"""The local channel's transports: a named pipe on Windows, a Unix socket elsewhere (spec 4).

**Not a network port.** The pipe refuses remote clients twice over (the
``PIPE_REJECT_REMOTE_CLIENTS`` flag and a deny entry for NETWORK in its
security descriptor); the socket is a file in the agent's 0700 state folder.

What each transport adds to `agent.localapi` is *who is calling*:

* **Windows.** After the client's first write the service impersonates it
  (``ImpersonateNamedPipeClient``), asks whether that token is a member of
  BUILTIN\\Administrators *with the group enabled* -- which is what an
  elevated token has and a filtered UAC token has not (``CheckTokenMembership``
  plus the group's own attributes) -- and reverts. Anything that fails on the
  way means "may only read".
* **Linux.** ``SO_PEERCRED``: uid 0 or the service's own uid may act.

The pipe's security descriptor lets Authenticated Users read and write data
but **not create instances** (``FILE_CREATE_PIPE_INSTANCE`` is the same bit as
``FILE_APPEND_DATA``, which ``GENERIC_WRITE`` would grant): otherwise any user
could open a second instance of this very pipe and receive an administrator's
requests. For the same reason the first instance is created with
``FILE_FLAG_FIRST_PIPE_INSTANCE`` -- if someone already holds the name, the
service does not serve -- and a client checks who owns the pipe before saying
anything, connecting at identification level so a fake server could not act
as it anyway.

**Each client has its own thread, its own deadlines and a slot out of a
capped number** (`agent.localapi.Admission`): a client that stops reading or
writing loses its connection; it never holds up the service or anyone else.

pywin32 is optional (`agent.winservice` already needs it). Without it the
channel is simply not served, and that is said once in the log.
"""

from __future__ import annotations

import os
import socket
import stat
import struct
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from agent import logs, store
from agent.i18n import _t
from agent.localapi import ANONYMOUS, Admission, Caller, Dispatcher, encode, error, posix_may_act, serve_connection, BUSY

PIPE_PREFIX = "\\\\.\\pipe\\"
DEFAULT_PIPE_NAME = PIPE_PREFIX + "CenyaAgent"
#: Para pruebas (y para un segundo agente en la misma máquina): otro nombre.
PIPE_ENV_VAR = "CENYA_PIPE_NAME"
SOCKET_NAME = "agent.sock"
#: Lo mismo para el socket: otra ruta (los tests usan una temporal).
SOCKET_ENV_VAR = "CENYA_SOCKET_PATH"

# --- Derechos del pipe ------------------------------------------------------------

#: FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES. Ni
#: FILE_APPEND_DATA (crear instancias), ni WRITE_DAC, ni WRITE_OWNER.
USER_PIPE_RIGHTS = 0x0012018B
#: Lo que pide el cliente al abrir (GENERIC_READ | FILE_WRITE_DATA): con
#: GENERIC_WRITE pediría también crear instancias y Windows se lo negaría.
CLIENT_ACCESS = 0x80000002

_WELL_KNOWN_SYSTEM = "S-1-5-18"
_WELL_KNOWN_ADMINS = "S-1-5-32-544"
#: SE_GROUP_ENABLED y SE_GROUP_USE_FOR_DENY_ONLY (los atributos de un grupo en un token).
_GROUP_ENABLED = 0x4
_GROUP_DENY_ONLY = 0x10


def pipe_name(environ: Mapping[str, str] | None = None) -> str:
    env = os.environ if environ is None else environ
    override = (env.get(PIPE_ENV_VAR) or "").strip()
    if not override:
        return DEFAULT_PIPE_NAME
    return override if override.startswith(PIPE_PREFIX) else PIPE_PREFIX + override


def socket_path(environ: Mapping[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    override = (env.get(SOCKET_ENV_VAR) or "").strip()
    return Path(override) if override else store.state_dir(environ) / SOCKET_NAME


def pipe_sddl(runner_sid: str = "") -> str:
    """Who may do what with the pipe: SYSTEM and Administrators everything, users read/write data.

    `runner_sid` is the account the agent runs as when it is neither (an agent
    run from a console): it needs to create the next instances.
    """
    runner = f"(A;;GA;;;{runner_sid})" if runner_sid and runner_sid not in (_WELL_KNOWN_SYSTEM, _WELL_KNOWN_ADMINS) else ""
    return f"D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA){runner}(A;;0x{USER_PIPE_RIGHTS:x};;;AU)"


def groups_grant_admin(groups: list[tuple[str, int]]) -> bool:
    """From a token's groups, whether it may act: Administrators, enabled and not deny-only. Pure.

    Un administrador sin elevar lleva el grupo, pero marcado «solo para
    denegar»: lo tiene y no le sirve. Es justo la diferencia que se busca.
    """
    for sid, attributes in groups:
        if sid == _WELL_KNOWN_ADMINS and attributes & _GROUP_ENABLED and not attributes & _GROUP_DENY_ONLY:
            return True
    return False


def trusted_pipe_owner(owner_sid: str, own_sid: str) -> bool:
    """Whether a client should talk to a pipe owned by `owner_sid`. Pure.

    El servicio corre como SYSTEM y el dueño del pipe sale SYSTEM o
    Administradores. Un agente lanzado a mano desde la consola de uno mismo es
    de uno mismo. Cualquier otro dueño es alguien que se ha quedado con el
    nombre antes que el servicio.
    """
    return bool(owner_sid) and owner_sid in (_WELL_KNOWN_SYSTEM, _WELL_KNOWN_ADMINS, own_sid)


class Unavailable(OSError):
    """There is no service to talk to (not running, no pywin32, someone else's pipe)."""

    def __init__(self, reason: str, message: str = "") -> None:
        super().__init__(message or reason)
        #: `not_running`, `no_pywin32`, `untrusted`, `denied`, `unsupported`.
        self.reason = reason


# =================================================================================
# Windows
# =================================================================================

_ERROR_FILE_NOT_FOUND = 2
_ERROR_ACCESS_DENIED = 5
_ERROR_BROKEN_PIPE = 109
_ERROR_PIPE_BUSY = 231
_ERROR_NO_DATA = 232
_ERROR_PIPE_NOT_CONNECTED = 233
_ERROR_PIPE_CONNECTED = 535
_ERROR_OPERATION_ABORTED = 995
_ERROR_IO_PENDING = 997
_CLOSED = {_ERROR_BROKEN_PIPE, _ERROR_NO_DATA, _ERROR_PIPE_NOT_CONNECTED}

_FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
_FILE_FLAG_OVERLAPPED = 0x40000000
_PIPE_ACCESS_DUPLEX = 0x3
_PIPE_REJECT_REMOTE_CLIENTS = 0x8
_SECURITY_SQOS_PRESENT = 0x00100000
_SECURITY_IDENTIFICATION = 0x00010000
_BUFFER = 64 * 1024
_READ_CHUNK = 64 * 1024


def _win32() -> Any:
    """The pywin32 modules, or raise `ImportError`."""
    import pywintypes
    import win32api
    import win32event
    import win32file
    import win32pipe
    import win32security

    class Modules:
        pass

    modules = Modules()
    for name, module in (
        ("pywintypes", pywintypes),
        ("win32api", win32api),
        ("win32event", win32event),
        ("win32file", win32file),
        ("win32pipe", win32pipe),
        ("win32security", win32security),
    ):
        setattr(modules, name, module)
    return modules


class PipeConnection:
    """One end of a pipe instance with overlapped I/O: every read and write has a deadline."""

    def __init__(self, handle: Any, w: Any) -> None:
        self.handle = handle
        self._w = w
        self._event = w.win32event.CreateEvent(None, True, False, None)
        self._closed = False

    def _overlapped(self) -> Any:
        w = self._w
        w.win32event.ResetEvent(self._event)
        overlapped = w.pywintypes.OVERLAPPED()
        overlapped.hEvent = self._event
        return overlapped

    def _finish(self, overlapped: Any, timeout: float) -> int:
        """Espera la operación en curso; si no acaba a tiempo, la cancela y lanza `TimeoutError`."""
        w = self._w
        waited = w.win32event.WaitForSingleObject(self._event, max(0, int(timeout * 1000)))
        if waited != w.win32event.WAIT_OBJECT_0:
            w.win32file.CancelIo(self.handle)
            try:
                # Pudo acabar justo entre la espera y la cancelación: entonces vale.
                return int(w.win32file.GetOverlappedResult(self.handle, overlapped, True))
            except w.pywintypes.error as exc:
                if exc.winerror == _ERROR_OPERATION_ABORTED:
                    raise TimeoutError from None
                if exc.winerror in _CLOSED:
                    return -1
                raise OSError(exc.winerror, str(exc)) from None
        try:
            return int(w.win32file.GetOverlappedResult(self.handle, overlapped, False))
        except w.pywintypes.error as exc:
            if exc.winerror in _CLOSED:
                return -1
            raise OSError(exc.winerror, str(exc)) from None

    def recv(self, timeout: float) -> bytes:
        w = self._w
        buffer = w.win32file.AllocateReadBuffer(_READ_CHUNK)
        overlapped = self._overlapped()
        try:
            w.win32file.ReadFile(self.handle, buffer, overlapped)
        except w.pywintypes.error as exc:
            if exc.winerror in _CLOSED:
                return b""
            raise OSError(exc.winerror, str(exc)) from None
        count = self._finish(overlapped, timeout)
        return b"" if count <= 0 else bytes(buffer[:count])

    def send(self, data: bytes, timeout: float) -> None:
        w = self._w
        view = memoryview(data)
        while view:
            overlapped = self._overlapped()
            try:
                w.win32file.WriteFile(self.handle, bytes(view), overlapped)
            except w.pywintypes.error as exc:
                raise OSError(exc.winerror, str(exc)) from None
            count = self._finish(overlapped, timeout)
            if count <= 0:
                raise OSError(_ERROR_BROKEN_PIPE, "pipe closed")
            view = view[count:]

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        w = self._w
        for target in (self.handle, self._event):
            try:
                w.win32file.CloseHandle(target)
            except Exception:  # noqa: BLE001
                pass


def _identify_pipe_client(handle: Any, w: Any) -> Caller:
    """Impersonate the client, look at its token, revert. Any failure: may only read."""
    sec = w.win32security
    try:
        sec.ImpersonateNamedPipeClient(handle)
    except Exception:  # noqa: BLE001
        return ANONYMOUS
    try:
        token = sec.OpenThreadToken(w.win32api.GetCurrentThread(), sec.TOKEN_QUERY, True)
        try:
            who = sec.ConvertSidToStringSid(sec.GetTokenInformation(token, sec.TokenUser)[0])
            admins = sec.CreateWellKnownSid(sec.WinBuiltinAdministratorsSid, None)
            member = bool(sec.CheckTokenMembership(token, admins))
            groups = [
                (sec.ConvertSidToStringSid(sid), int(attributes))
                for sid, attributes in sec.GetTokenInformation(token, sec.TokenGroups)
            ]
        finally:
            w.win32api.CloseHandle(token)
    except Exception:  # noqa: BLE001
        return ANONYMOUS
    finally:
        # Siempre, pase lo que pase: un hilo del servicio que se quedara con
        # la identidad del cliente haría lo siguiente con sus derechos.
        try:
            sec.RevertToSelf()
        except Exception:  # noqa: BLE001
            pass
    # Las dos tienen que estar de acuerdo: la llamada de Windows y la lectura
    # de los grupos que se prueba en cualquier sistema.
    return Caller(admin=member and groups_grant_admin(groups), who=who)


def _runner_sid(w: Any) -> str:
    sec = w.win32security
    try:
        token = sec.OpenProcessToken(w.win32api.GetCurrentProcess(), sec.TOKEN_QUERY)
        try:
            return sec.ConvertSidToStringSid(sec.GetTokenInformation(token, sec.TokenUser)[0])
        finally:
            w.win32api.CloseHandle(token)
    except Exception:  # noqa: BLE001
        return ""


class PipeServer:
    """Serves `dispatcher` on a named pipe until `close`."""

    def __init__(self, name: str, dispatcher: Dispatcher, *, admission: Admission | None = None) -> None:
        self.name = name
        self.dispatcher = dispatcher
        self.admission = admission or Admission()
        self._w = _win32()
        self._stop = threading.Event()
        self._stop_handle = self._w.win32event.CreateEvent(None, True, False, None)
        self._thread: threading.Thread | None = None
        self._sa: Any = None
        self.threads: list[threading.Thread] = []

    def _create(self, first: bool) -> Any:
        w = self._w
        if self._sa is None:
            sa = w.pywintypes.SECURITY_ATTRIBUTES()
            sa.SECURITY_DESCRIPTOR = w.win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                pipe_sddl(_runner_sid(w)), w.win32security.SDDL_REVISION_1
            )
            self._sa = sa
        open_mode = _PIPE_ACCESS_DUPLEX | _FILE_FLAG_OVERLAPPED | (_FILE_FLAG_FIRST_PIPE_INSTANCE if first else 0)
        pipe_mode = (
            w.win32pipe.PIPE_TYPE_BYTE | w.win32pipe.PIPE_READMODE_BYTE | w.win32pipe.PIPE_WAIT | _PIPE_REJECT_REMOTE_CLIENTS
        )
        return w.win32pipe.CreateNamedPipe(
            self.name, open_mode, pipe_mode, w.win32pipe.PIPE_UNLIMITED_INSTANCES, _BUFFER, _BUFFER, 0, self._sa
        )

    def start(self) -> bool:
        """Crea la primera instancia y empieza a escuchar. `False` si el nombre ya es de otro."""
        try:
            handle = self._create(first=True)
        except Exception as exc:  # noqa: BLE001
            logs.error(
                _t("[canal local] No se puede abrir %(name)s (%(error)s): la aplicación y los comandos locales no podrán hablar con el servicio.")
                % {"name": self.name, "error": exc}
            )
            return False
        self._thread = threading.Thread(target=self._accept, args=(handle,), name="cenya-local-pipe", daemon=True)
        self._thread.start()
        return True

    def _accept(self, handle: Any) -> None:
        w = self._w
        event = w.win32event.CreateEvent(None, True, False, None)
        try:
            while not self._stop.is_set():
                w.win32event.ResetEvent(event)
                overlapped = w.pywintypes.OVERLAPPED()
                overlapped.hEvent = event
                try:
                    result = w.win32pipe.ConnectNamedPipe(handle, overlapped)
                except w.pywintypes.error as exc:
                    result = exc.winerror
                if result == _ERROR_IO_PENDING:
                    which = w.win32event.WaitForMultipleObjects([event, self._stop_handle], False, w.win32event.INFINITE)
                    if which != w.win32event.WAIT_OBJECT_0:
                        w.win32file.CancelIo(handle)
                        break
                    try:
                        w.win32file.GetOverlappedResult(handle, overlapped, False)
                    except w.pywintypes.error:
                        self._recycle(handle)
                        handle = self._create(first=False)
                        continue
                elif result not in (0, _ERROR_PIPE_CONNECTED):
                    self._recycle(handle)
                    handle = self._create(first=False)
                    continue
                connected = handle
                # La siguiente instancia antes de atender a este: así el
                # nombre nunca queda libre para otro.
                handle = self._create(first=False)
                self._dispatch(connected)
        except Exception as exc:  # noqa: BLE001 - el canal se pierde; el servicio sigue
            logs.error(_t("[canal local] El canal local se ha cerrado por un error: %(error)s") % {"error": type(exc).__name__})
        finally:
            self._recycle(handle)
            try:
                w.win32file.CloseHandle(event)
            except Exception:  # noqa: BLE001
                pass

    def _recycle(self, handle: Any) -> None:
        try:
            self._w.win32file.CloseHandle(handle)
        except Exception:  # noqa: BLE001
            pass

    def _dispatch(self, handle: Any) -> None:
        conn = PipeConnection(handle, self._w)
        if not self.admission.enter():
            try:
                conn.send(encode(error(None, BUSY, _t("Hay demasiadas conexiones abiertas con el agente."))), 1.0)
            except Exception:  # noqa: BLE001
                pass
            conn.close()
            return

        def run() -> None:
            try:
                serve_connection(
                    conn,
                    self.dispatcher,
                    lambda: _identify_pipe_client(handle, self._w),
                    admission=self.admission,
                    stop=self._stop,
                )
            finally:
                self.admission.leave()

        thread = threading.Thread(target=run, name="cenya-local-client", daemon=True)
        self.threads = [t for t in self.threads if t.is_alive()] + [thread]
        thread.start()

    def close(self) -> None:
        self._stop.set()
        try:
            self._w.win32event.SetEvent(self._stop_handle)
        except Exception:  # noqa: BLE001
            pass
        if self._thread is not None:
            self._thread.join(timeout=2)


def _own_sid(w: Any) -> str:
    return _runner_sid(w)


def connect_pipe(name: str, timeout: float = 5.0) -> PipeConnection:
    """A client end of the pipe, after checking who owns it. Raises `Unavailable`."""
    try:
        w = _win32()
    except ImportError as exc:
        raise Unavailable("no_pywin32") from exc
    flags = _FILE_FLAG_OVERLAPPED | _SECURITY_SQOS_PRESENT | _SECURITY_IDENTIFICATION
    handle = None
    # El servicio deja una instancia esperando cada vez: con varios clientes
    # llegando a la vez, los demás esperan su turno (hasta `timeout`).
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            handle = w.win32file.CreateFile(name, CLIENT_ACCESS, 0, None, w.win32file.OPEN_EXISTING, flags, None)
            break
        except w.pywintypes.error as exc:
            if exc.winerror == _ERROR_PIPE_BUSY:
                try:
                    w.win32pipe.WaitNamedPipe(name, max(1, int((deadline - time.monotonic()) * 1000)))
                except w.pywintypes.error:
                    time.sleep(0.01)
                continue
            if exc.winerror == _ERROR_FILE_NOT_FOUND:
                raise Unavailable("not_running") from None
            if exc.winerror == _ERROR_ACCESS_DENIED:
                raise Unavailable("denied") from None
            raise Unavailable("not_running", str(exc)) from None
    if handle is None:
        raise Unavailable("busy")
    try:
        sd = w.win32security.GetSecurityInfo(
            handle, w.win32security.SE_KERNEL_OBJECT, w.win32security.OWNER_SECURITY_INFORMATION
        )
        owner = w.win32security.ConvertSidToStringSid(sd.GetSecurityDescriptorOwner())
    except Exception:  # noqa: BLE001
        owner = ""
    if not trusted_pipe_owner(owner, _own_sid(w)):
        w.win32file.CloseHandle(handle)
        raise Unavailable("untrusted")
    return PipeConnection(handle, w)


# =================================================================================
# Unix
# =================================================================================


def peer_uid(sock: socket.socket) -> int | None:
    """The uid of the process at the other end (`SO_PEERCRED`), or `None` if not knowable."""
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        return None
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, option, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
    except OSError:
        return None
    return uid


class SocketConnection:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock

    def recv(self, timeout: float) -> bytes:
        self.sock.settimeout(max(timeout, 0.001))
        try:
            return self.sock.recv(_READ_CHUNK)
        except socket.timeout as exc:
            raise TimeoutError from exc

    def send(self, data: bytes, timeout: float) -> None:
        self.sock.settimeout(max(timeout, 0.001))
        try:
            self.sock.sendall(data)
        except socket.timeout as exc:
            raise TimeoutError from exc

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class SocketServer:
    """Serves `dispatcher` on a Unix socket (0660, inside the 0700 state folder)."""

    def __init__(self, path: Path, dispatcher: Dispatcher, *, admission: Admission | None = None) -> None:
        self.path = Path(path)
        self.dispatcher = dispatcher
        self.admission = admission or Admission()
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self.threads: list[threading.Thread] = []
        self._service_uid = os.geteuid() if hasattr(os, "geteuid") else -1

    def start(self) -> bool:
        if self.path.exists() or self.path.is_symlink():
            try:
                mode = os.lstat(self.path).st_mode
            except OSError:
                mode = 0
            if not stat.S_ISSOCK(mode):
                logs.error(_t("[canal local] %(path)s existe y no es un socket: no se toca.") % {"path": self.path})
                return False
            # ¿Hay otro agente escuchando? Entonces no se le quita el sitio.
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.settimeout(1)
                probe.connect(str(self.path))
            except OSError:
                self.path.unlink(missing_ok=True)
            else:
                logs.error(_t("[canal local] Ya hay otro agente escuchando en %(path)s.") % {"path": self.path})
                return False
            finally:
                probe.close()
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(str(self.path))
            os.chmod(self.path, 0o660)
            sock.listen(16)
            sock.settimeout(0.5)
        except OSError as exc:
            logs.error(
                _t("[canal local] No se puede abrir %(name)s (%(error)s): la aplicación y los comandos locales no podrán hablar con el servicio.")
                % {"name": self.path, "error": exc}
            )
            return False
        self._sock = sock
        self._thread = threading.Thread(target=self._accept, name="cenya-local-socket", daemon=True)
        self._thread.start()
        return True

    def _accept(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                continue
            self._dispatch(client)

    def _identify(self, client: socket.socket) -> Caller:
        uid = peer_uid(client)
        return Caller(admin=posix_may_act(uid, self._service_uid), who=f"uid:{uid}")

    def _dispatch(self, client: socket.socket) -> None:
        conn = SocketConnection(client)
        if not self.admission.enter():
            try:
                conn.send(encode(error(None, BUSY, _t("Hay demasiadas conexiones abiertas con el agente."))), 1.0)
            except Exception:  # noqa: BLE001
                pass
            conn.close()
            return

        def run() -> None:
            try:
                serve_connection(conn, self.dispatcher, lambda: self._identify(client), admission=self.admission, stop=self._stop)
            finally:
                self.admission.leave()

        thread = threading.Thread(target=run, name="cenya-local-client", daemon=True)
        self.threads = [t for t in self.threads if t.is_alive()] + [thread]
        thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
        try:
            if stat.S_ISSOCK(os.lstat(self.path).st_mode):
                self.path.unlink()
        except OSError:
            pass


def connect_socket(path: Path, timeout: float = 5.0) -> SocketConnection:
    if not hasattr(socket, "AF_UNIX"):
        raise Unavailable("unsupported")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(path))
    except PermissionError as exc:
        sock.close()
        raise Unavailable("denied") from exc
    except OSError as exc:
        sock.close()
        raise Unavailable("not_running") from exc
    return SocketConnection(sock)


# =================================================================================
# Lo que usan el servicio y los clientes
# =================================================================================


def serve(
    dispatcher: Dispatcher, *, environ: Mapping[str, str] | None = None, admission: Admission | None = None
) -> PipeServer | SocketServer | None:
    """Start serving the channel on this platform's transport. `None` if it cannot (said once in the log)."""
    if sys.platform == "win32":
        try:
            server: PipeServer | SocketServer = PipeServer(pipe_name(environ), dispatcher, admission=admission)
        except ImportError:
            logs.error(
                _t("[canal local] Sin pywin32 no hay canal local: la aplicación y los comandos locales no podrán hablar con el servicio.")
            )
            return None
    else:
        if not hasattr(socket, "AF_UNIX"):
            return None
        server = SocketServer(socket_path(environ), dispatcher, admission=admission)
    return server if server.start() else None


def connect(*, environ: Mapping[str, str] | None = None, timeout: float = 5.0) -> PipeConnection | SocketConnection:
    """A client connection to the service on this machine. Raises `Unavailable`."""
    if sys.platform == "win32":
        return connect_pipe(pipe_name(environ), timeout)
    return connect_socket(socket_path(environ), timeout)
