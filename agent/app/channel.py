"""The client side of the local channel (spec section 4).

The desktop application and the tray icon talk to the service through this and
nothing else. One JSON message per line, UTF-8::

    -> {"id": 1, "op": "status", "args": {}}
    <- {"id": 1, "ok": true, "data": {...}}
    <- {"id": 1, "ok": false, "error": "forbidden", "message": "..."}

Windows: the named pipe ``\\\\.\\pipe\\CenyaAgent``. Elsewhere: the Unix socket
``<state folder>/agent.sock``. **The address is injectable** (``CENYA_PIPE_NAME``
/ ``CENYA_SOCKET_PATH``, the same variables the service reads, or the
``address`` argument): development and tests run against
``agent.app.fake_server`` on a random name and never reach a real service.

What this module promises:

* Every failure is a `ChannelError` with a stable ``code``: the view decides
  what to say from the code, never from a message.
  ``service_down`` (nothing is listening: the service is not running),
  ``busy``, ``timeout``, ``broken``, ``bad_response``, ``access_denied``, or
  whatever code the service sent (``forbidden`` above all).
* Every wait has a timeout. A long operation (``netbox.export``, ``probe``)
  gets a long one; ``status`` gets two seconds.
* Connections are reused (the window polls every second or two) and several
  requests can be in flight at once, each on its own connection: a NetBox
  export that takes minutes does not freeze the status polling.
* A request that only reads is retried once on a fresh connection when the old
  one turns out to be dead. One that acts is never retried after it may have
  been delivered: running a task twice is worse than saying it failed.
* The pipe is opened as the service expects (`agent/localpipe.py`): asking
  for ``GENERIC_READ | FILE_WRITE_DATA`` only, at identification level, and
  only after checking that the pipe belongs to SYSTEM, Administrators or this
  same account -- anything else is ``untrusted`` and is told nothing.
* Nothing here logs. The arguments of a request may carry a secret (the NetBox
  token): they go down the pipe and nowhere else.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

#: El canal de verdad. Solo se usa si nadie dice otra cosa.
PIPE_PREFIX = "\\\\.\\pipe\\"
DEFAULT_PIPE = PIPE_PREFIX + "CenyaAgent"
SOCKET_NAME = "agent.sock"
#: Para apuntar la aplicación (y el icono) a otro canal: el servidor falso. Las
#: mismas variables que lee el servicio (`agent/localpipe.py`): nombre del pipe
#: (con o sin el prefijo) en Windows, ruta del socket fuera.
ADDRESS_ENV_VAR = "CENYA_PIPE_NAME"
SOCKET_ENV_VAR = "CENYA_SOCKET_PATH"
#: Lo que se pide al abrir el pipe: GENERIC_READ | FILE_WRITE_DATA. Con
#: GENERIC_WRITE se pediría también FILE_APPEND_DATA (crear instancias), que el
#: servicio niega a propósito, y la apertura fallaría.
CLIENT_ACCESS = 0x80000002
_FILE_FLAG_OVERLAPPED = 0x40000000
#: Conectar a nivel de identificación: un servidor que no sea el servicio
#: podría saber quién es el cliente, pero no actuar en su nombre.
_SECURITY_SQOS_PRESENT = 0x00100000
_SECURITY_IDENTIFICATION = 0x00010000
#: Dueños de los que se fía el cliente: SYSTEM, Administradores (y uno mismo).
_TRUSTED_OWNERS = ("S-1-5-18", "S-1-5-32-544")

# Códigos que pone este cliente. Los del servicio llegan tal cual.
SERVICE_DOWN = "service_down"
BUSY = "busy"
TIMEOUT = "timeout"
BROKEN = "broken"
BAD_RESPONSE = "bad_response"
ACCESS_DENIED = "access_denied"
#: Alguien que no es el servicio tiene el nombre del pipe: no se le dice nada.
UNTRUSTED = "untrusted"
FORBIDDEN = "forbidden"
NOT_ENROLLED = "not_enrolled"
INVALID = "invalid"

#: Las operaciones que solo leen: se pueden repetir sin efecto.
READ_OPS = frozenset({"status", "log", "about", "settings.get"})

#: Cuánto puede tardar cada una en contestar. Las largas contestan al terminar
#: (spec 4) y su avance se lee con `status`.
OP_TIMEOUTS: dict[str, float] = {
    "status": 4.0,
    "log": 6.0,
    "about": 15.0,
    "settings.get": 6.0,
    "settings.set": 15.0,
    "run": 15.0,
    "pause": 10.0,
    "resume": 10.0,
    "probe": 180.0,
    "test_connection": 90.0,
    "connect": 90.0,
    "disconnect": 60.0,
    "netbox.export": 3600.0,
    "support_bundle": 300.0,
    "check_update": 60.0,
}
DEFAULT_TIMEOUT = 15.0
CONNECT_TIMEOUT = 2.0
#: Cuánto se insiste si el pipe no existe antes de decir que el servicio no corre.
NOT_FOUND_GRACE = 0.3
#: Una respuesta más grande que esto es un servicio roto, no una respuesta.
MAX_LINE_BYTES = 32 * 1024 * 1024
#: Conexiones libres que se guardan para reutilizar.
POOL_SIZE = 4


class ChannelError(Exception):
    """Lo que salió mal, con un código estable y, si lo hay, el texto del servicio."""

    def __init__(self, code: str, message: str = "", details: dict[str, Any] | None = None) -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message
        #: Lo que el servicio añade a un error (``fields`` en `settings.set`).
        self.details = details or {}


def default_address(environ: Mapping[str, str] | None = None) -> str:
    """El canal al que hablar: el de la variable o el del servicio de verdad."""
    env = os.environ if environ is None else environ
    if sys.platform == "win32":
        override = (env.get(ADDRESS_ENV_VAR) or "").strip()
        if not override:
            return DEFAULT_PIPE
        return override if override.startswith(PIPE_PREFIX) else PIPE_PREFIX + override
    override = (env.get(SOCKET_ENV_VAR) or "").strip()
    if override:
        return override
    from agent import store

    return str(store.state_dir(env) / SOCKET_NAME)


def address_overridden(environ: Mapping[str, str] | None = None) -> bool:
    """Si alguien ha apuntado el canal a otro sitio (desarrollo, pruebas)."""
    env = os.environ if environ is None else environ
    variable = ADDRESS_ENV_VAR if sys.platform == "win32" else SOCKET_ENV_VAR
    return bool((env.get(variable) or "").strip())


def is_default_address(address: str) -> bool:
    """Si es el canal del servicio de verdad (y no uno de desarrollo)."""
    return address.lower() == DEFAULT_PIPE.lower()


def trusted_pipe_owner(owner_sid: str, own_sid: str) -> bool:
    """Si se le habla a un pipe de ese dueño. Pura (la misma regla que `agent.localpipe`)."""
    return bool(owner_sid) and owner_sid in (*_TRUSTED_OWNERS, own_sid)


def random_pipe_name(prefix: str = "CenyaAgentDev") -> str:
    """Un nombre de canal que no es el del servicio, para desarrollo y tests."""
    token = os.urandom(6).hex()
    if sys.platform == "win32":
        return rf"\\.\pipe\{prefix}-{token}"
    import tempfile

    return str(Path(tempfile.gettempdir()) / f"{prefix.lower()}-{token}.sock")


# --- Transporte ------------------------------------------------------------------


class Connection(Protocol):
    def send(self, data: bytes, timeout: float) -> None: ...
    def read_line(self, timeout: float) -> bytes: ...
    def close(self) -> None: ...


class _LineBuffer:
    def __init__(self) -> None:
        self._buffer = b""

    def pop_line(self) -> bytes | None:
        index = self._buffer.find(b"\n")
        if index < 0:
            return None
        line, self._buffer = self._buffer[:index], self._buffer[index + 1 :]
        return line

    def feed(self, chunk: bytes) -> None:
        self._buffer += chunk
        if len(self._buffer) > MAX_LINE_BYTES:
            raise ChannelError(BAD_RESPONSE, "line too long")


def _own_sid() -> str:
    """El SID de la cuenta de este proceso (un servicio lanzado a mano por uno mismo es de fiar)."""
    try:
        import win32api
        import win32security

        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
        try:
            return win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
        finally:
            win32api.CloseHandle(token)
    except Exception:  # noqa: BLE001
        return ""


class PipeConnection:
    """Un extremo cliente del *named pipe*, con E/S solapada para poder esperar con tope."""

    READ_CHUNK = 64 * 1024

    def __init__(self, name: str, connect_timeout: float = CONNECT_TIMEOUT) -> None:
        import pywintypes
        import win32con
        import win32file
        import win32pipe
        import winerror

        self._w = (pywintypes, win32file)
        started = time.monotonic()
        deadline = started + connect_timeout
        flags = _FILE_FLAG_OVERLAPPED | _SECURITY_SQOS_PRESENT | _SECURITY_IDENTIFICATION
        while True:
            try:
                self._handle = win32file.CreateFile(name, CLIENT_ACCESS, 0, None, win32con.OPEN_EXISTING, flags, None)
                break
            except pywintypes.error as exc:
                if exc.winerror == winerror.ERROR_FILE_NOT_FOUND:
                    # Entre que un cliente se conecta y el servicio abre la
                    # siguiente instancia del pipe pasa un instante sin
                    # ninguna: eso no es «servicio parado». Se insiste un poco.
                    if time.monotonic() - started < NOT_FOUND_GRACE:
                        time.sleep(0.03)
                        continue
                    raise ChannelError(SERVICE_DOWN) from exc
                if exc.winerror == winerror.ERROR_ACCESS_DENIED:
                    raise ChannelError(ACCESS_DENIED) from exc
                if exc.winerror == winerror.ERROR_PIPE_BUSY:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ChannelError(BUSY) from exc
                    try:
                        win32pipe.WaitNamedPipe(name, max(1, int(remaining * 1000)))
                    except pywintypes.error:
                        pass
                    continue
                raise ChannelError(BROKEN, exc.strerror or "") from exc
        # Antes de decir nada: ¿es del servicio? Un pipe con ese nombre creado
        # por otro usuario recibiría las peticiones de un administrador.
        if not trusted_pipe_owner(self._owner(), _own_sid()):
            self.close()
            raise ChannelError(UNTRUSTED)
        self._lines = _LineBuffer()

    def _owner(self) -> str:
        try:
            import win32security

            descriptor = win32security.GetSecurityInfo(
                self._handle, win32security.SE_KERNEL_OBJECT, win32security.OWNER_SECURITY_INFORMATION
            )
            return win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
        except Exception:  # noqa: BLE001 - sin dueño conocido, no se fía
            return ""

    def _wait(self, overlapped: Any, timeout: float) -> int:
        import win32event

        pywintypes, win32file = self._w
        result = win32event.WaitForSingleObject(overlapped.hEvent, max(0, int(timeout * 1000)))
        if result != win32event.WAIT_OBJECT_0:
            try:
                win32file.CancelIo(self._handle)
                win32file.GetOverlappedResult(self._handle, overlapped, True)
            except pywintypes.error:
                pass
            raise ChannelError(TIMEOUT)
        try:
            return win32file.GetOverlappedResult(self._handle, overlapped, True)
        except pywintypes.error as exc:
            raise ChannelError(BROKEN, exc.strerror or "") from exc

    @staticmethod
    def _overlapped() -> Any:
        import pywintypes
        import win32event

        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
        return overlapped

    def send(self, data: bytes, timeout: float) -> None:
        pywintypes, win32file = self._w
        overlapped = self._overlapped()
        try:
            win32file.WriteFile(self._handle, data, overlapped)
        except pywintypes.error as exc:
            raise ChannelError(BROKEN, exc.strerror or "") from exc
        written = self._wait(overlapped, timeout)
        if written != len(data):
            raise ChannelError(BROKEN, "short write")

    def read_line(self, timeout: float) -> bytes:
        pywintypes, win32file = self._w
        deadline = time.monotonic() + timeout
        while True:
            line = self._lines.pop_line()
            if line is not None:
                return line
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ChannelError(TIMEOUT)
            overlapped = self._overlapped()
            buffer = win32file.AllocateReadBuffer(self.READ_CHUNK)
            try:
                win32file.ReadFile(self._handle, buffer, overlapped)
            except pywintypes.error as exc:
                raise ChannelError(BROKEN, exc.strerror or "") from exc
            count = self._wait(overlapped, remaining)
            if count == 0:
                raise ChannelError(BROKEN, "closed")
            self._lines.feed(bytes(buffer[:count]))

    def close(self) -> None:
        pywintypes, win32file = self._w
        try:
            win32file.CloseHandle(self._handle)
        except pywintypes.error:
            pass


class UnixConnection:
    """El mismo canal en Linux: un socket Unix, nunca uno de red."""

    def __init__(self, path: str, connect_timeout: float = CONNECT_TIMEOUT) -> None:
        import socket

        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.settimeout(connect_timeout)
        try:
            self._socket.connect(path)
        except (FileNotFoundError, ConnectionRefusedError) as exc:
            self._socket.close()
            raise ChannelError(SERVICE_DOWN) from exc
        except PermissionError as exc:
            self._socket.close()
            raise ChannelError(ACCESS_DENIED) from exc
        except TimeoutError as exc:
            self._socket.close()
            raise ChannelError(BUSY) from exc
        except OSError as exc:
            self._socket.close()
            raise ChannelError(BROKEN, str(exc)) from exc
        self._lines = _LineBuffer()

    def send(self, data: bytes, timeout: float) -> None:
        self._socket.settimeout(timeout)
        try:
            self._socket.sendall(data)
        except TimeoutError as exc:
            raise ChannelError(TIMEOUT) from exc
        except OSError as exc:
            raise ChannelError(BROKEN, str(exc)) from exc

    def read_line(self, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        while True:
            line = self._lines.pop_line()
            if line is not None:
                return line
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ChannelError(TIMEOUT)
            self._socket.settimeout(remaining)
            try:
                chunk = self._socket.recv(64 * 1024)
            except TimeoutError as exc:
                raise ChannelError(TIMEOUT) from exc
            except OSError as exc:
                raise ChannelError(BROKEN, str(exc)) from exc
            if not chunk:
                raise ChannelError(BROKEN, "closed")
            self._lines.feed(chunk)

    def close(self) -> None:
        try:
            self._socket.close()
        except OSError:
            pass


def open_connection(address: str, connect_timeout: float = CONNECT_TIMEOUT) -> Connection:
    if address.startswith("\\\\"):
        if sys.platform != "win32":
            raise ChannelError(SERVICE_DOWN)
        return PipeConnection(address, connect_timeout)
    return UnixConnection(address, connect_timeout)


# --- Cliente ---------------------------------------------------------------------


class ChannelClient:
    """Peticiones al servicio. Seguro entre hilos: cada petición usa su conexión."""

    def __init__(
        self,
        address: str | None = None,
        *,
        connect_timeout: float = CONNECT_TIMEOUT,
        opener: Any = None,
    ) -> None:
        self.address = address or default_address()
        self.connect_timeout = connect_timeout
        self._open = opener or open_connection
        self._lock = threading.Lock()
        self._idle: list[Connection] = []
        self._next_id = 0

    def _new_id(self) -> int:
        with self._lock:
            self._next_id += 1
            return self._next_id

    def _take(self) -> tuple[Connection, bool]:
        with self._lock:
            if self._idle:
                return self._idle.pop(), True
        return self._open(self.address, self.connect_timeout), False

    def _give_back(self, connection: Connection) -> None:
        with self._lock:
            if len(self._idle) < POOL_SIZE:
                self._idle.append(connection)
                return
        connection.close()

    def close(self) -> None:
        with self._lock:
            idle, self._idle = self._idle, []
        for connection in idle:
            connection.close()

    def request(self, op: str, args: Mapping[str, Any] | None = None, timeout: float | None = None) -> dict[str, Any]:
        """La respuesta (`data`) del servicio, o `ChannelError`."""
        wait = timeout if timeout is not None else OP_TIMEOUTS.get(op, DEFAULT_TIMEOUT)
        message_id = self._new_id()
        line = (
            json.dumps({"id": message_id, "op": op, "args": dict(args or {})}, ensure_ascii=False, separators=(",", ":"))
            + "\n"
        ).encode("utf-8")
        attempts = 2
        for attempt in range(attempts):
            connection, reused = self._take()
            delivered = False
            try:
                connection.send(line, wait)
                delivered = True
                reply = self._read_reply(connection, message_id, wait)
            except _Refused as refused:
                # El servicio contestó (que no): la conexión sigue buena.
                self._give_back(connection)
                raise ChannelError(refused.code, refused.message, refused.details) from None
            except ChannelError as exc:
                connection.close()
                # Una conexión guardada que resultó estar muerta: si no llegó
                # nada, o si solo se leía, se repite una vez con una nueva.
                retry = reused and exc.code == BROKEN and (not delivered or op in READ_OPS)
                if retry and attempt + 1 < attempts:
                    continue
                raise
            self._give_back(connection)
            return reply
        raise ChannelError(BROKEN)  # pragma: no cover - el bucle siempre vuelve o lanza

    @staticmethod
    def _read_reply(connection: Connection, message_id: int, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            raw = connection.read_line(max(0.0, deadline - time.monotonic()))
            if not raw.strip():
                continue
            try:
                reply = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise ChannelError(BAD_RESPONSE) from exc
            if not isinstance(reply, dict):
                raise ChannelError(BAD_RESPONSE)
            if reply.get("id") is None and reply.get("ok") is False:
                # Sin `id`: el servicio contesta a la conexión, no a la
                # petición (demasiadas conexiones, una línea que no entendió).
                raise ChannelError(str(reply.get("error") or BAD_RESPONSE), str(reply.get("message") or ""))
            if reply.get("id") != message_id:
                continue  # la respuesta tardía de otra petición: no es esta
            if reply.get("ok") is True:
                data = reply.get("data")
                return data if isinstance(data, dict) else {"value": data} if data is not None else {}
            details = reply.get("details") if isinstance(reply.get("details"), dict) else {}
            raise _Refused(str(reply.get("error") or BAD_RESPONSE), str(reply.get("message") or ""), details)


class _Refused(Exception):
    """Una respuesta `ok: false` bien formada: el servicio dice que no."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.message = message
        self.details = details or {}
