"""The agent's state folder: where it keeps its token, and how that folder is guarded.

The person never sees the token: the agent redeems a one-time code and writes
what it gets here. Next to it live the identity key, the local settings, the
memory, the outbox and the log (spec 2.6). **This module is the one place that
knows how that folder is protected**; everything else just writes into it.

The rules:

* **Readable only by whoever must read it.** On Windows the folder and the
  files that matter carry a *protected* DACL (nothing inherited from
  ``%ProgramData%``, where any user may create files): SYSTEM and the
  Administrators, plus the account running the agent when it is neither. The
  one exception is ``status.json`` and the folder's own listing, which
  BUILTIN\\Users may read because the tray icon runs as the logged-in user.
  ``0700``/``0600`` on POSIX. Everything by SID: group names are translated
  ("Administradores", "Administratoren"...).
* **What was already there is trusted only if the folder was already
  protected.** A folder that ordinary users could write into may hold a
  ``settings.json`` with a rogue proxy, an ``identity.key`` someone else owns, a
  forged outbox. Those are moved aside (renamed ``.untrusted-<timestamp>``,
  never deleted) before the agent reads anything, and the enrolment found
  there is not used: it has to be redone.
* **If it cannot be protected, nothing secret is written.** A token readable by
  every user of the machine is the failure this exists to avoid; better an
  agent that says why it will not start than one that quietly leaks.
* **Atomic.** A crash half-way never leaves a half-written file the service
  would read as an enrolment.
* **A broken file is "not enrolled", never a crash.**

Windows security is read and written as SDDL text, through pywin32 when it is
installed and through ``ctypes`` (standard library) when it is not: the
judgement of what is "protected" is a pure function of that text
(`sddl_is_protected`), so it is tested on any platform.
"""

from __future__ import annotations

import errno
import json
import os
import re
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from agent.i18n import _t

FILE_NAME = "enrollment.json"

#: Lo que el agente guarda en su carpeta y no puede leer nadie más.
IDENTITY_FILE = "identity.key"
SETTINGS_FILE = "settings.json"
MEMORY_FILE = "memory.json"
STATUS_FILE = "status.json"
#: La CA propia del portal, copiada aquí por `cenya-agent settings set ca_bundle`
#: (o el instalador con /CA=). No es un secreto, pero sí de confianza: una CA
#: puesta por otro usuario dejaría a cualquiera hacerse pasar por el portal.
CA_FILE = "ca.pem"
#: Las descargas del actualizador (`agent/update.py`): lo que se va a ejecutar
#: como administrador no puede haberlo dejado otro usuario.
UPDATES_FOLDER = "updates"
PRIVATE_FILES = (FILE_NAME, IDENTITY_FILE, SETTINGS_FILE, MEMORY_FILE, CA_FILE)
PRIVATE_FOLDERS = ("outbox", "logs", UPDATES_FOLDER)

#: Cómo se renombra lo que se aparta cuando la carpeta no estaba protegida:
#: todo lo que alguien pudo dejar para que el agente lo creyera suyo. El
#: registro también, aunque no se lea: un `agent.log` puesto por otro usuario
#: es un fichero suyo en el que el agente escribiría.
UNTRUSTED_SUFFIX = ".untrusted-"

#: SID de SYSTEM y del grupo Administradores, iguales en cualquier idioma.
_WINDOWS_SYSTEM_SID = "S-1-5-18"
_WINDOWS_ADMINS_SID = "S-1-5-32-544"

#: Lectura y recorrido (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE), sin escribir nada.
_READ = "0x1200a9"


class StoreError(RuntimeError):
    """The state folder or the enrolment could not be kept safe. Its text is for a person."""


@dataclass(frozen=True)
class Enrollment:
    url: str
    token: str
    name: str = ""


def state_dir(environ: Mapping[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    override = (env.get("CENYA_STATE_DIR") or "").strip()
    if override:
        return Path(override)
    if sys.platform == "win32":
        return Path(env.get("ProgramData") or r"C:\ProgramData") / "Cenya"
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/var/lib/cenya-agent")
    return Path.home() / ".config" / "cenya-agent"


def path(environ: Mapping[str, str] | None = None) -> Path:
    return state_dir(environ) / FILE_NAME


def load(environ: Mapping[str, str] | None = None) -> Enrollment | None:
    """The saved enrolment, or `None` if there is none or it cannot be read."""
    try:
        data = json.loads(path(environ).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    url, token = data.get("url"), data.get("token")
    if not isinstance(url, str) or not isinstance(token, str) or not url or not token:
        return None
    return Enrollment(url=url, token=token, name=str(data.get("name") or ""))


def untrusted_enrollment(environ: Mapping[str, str] | None = None) -> bool:
    """Whether an enrolment was set aside because its folder was not protected."""
    try:
        return any(state_dir(environ).glob(f"{FILE_NAME}{UNTRUSTED_SUFFIX}*"))
    except OSError:
        return False


# --- El juicio: ¿estaba protegida? ---------------------------------------------
#
# Funciones puras sobre texto SDDL (lo que devuelven GetNamedSecurityInfo +
# ConvertSecurityDescriptorToStringSecurityDescriptor, o `icacls /save`): así se
# prueban también en el Linux de CI, con cadenas de ejemplo.

#: Grupos «de todo el mundo»: si alguno puede crear o cambiar algo dentro, lo
#: que hay dentro puede haberlo dejado cualquiera.
_BROAD_SIDS = {
    "WD": "S-1-1-0",  # Everyone / Todos
    "AU": "S-1-5-11",  # Authenticated Users
    "BU": "S-1-5-32-545",  # Users
    "IU": "S-1-5-4",  # INTERACTIVE
    "AN": "S-1-5-7",  # ANONYMOUS LOGON
    "BG": "S-1-5-32-546",  # Guests
    "NU": "S-1-5-2",  # NETWORK
    "RU": "S-1-5-32-554",  # Pre-Windows 2000 Compatible Access
    "PU": "S-1-5-32-547",  # Power Users
    "RD": "S-1-5-32-555",  # Remote Desktop Users
    "AC": "S-1-15-2-1",  # ALL APPLICATION PACKAGES
}
_BROAD_EXTRA = {"S-1-2-0", "S-1-2-1", "S-1-5-1", "S-1-5-14", "S-1-15-2-2", "DU", "DG"}
_TRUSTED_OWNERS = {"SY", "BA", _WINDOWS_SYSTEM_SID, _WINDOWS_ADMINS_SID}

#: Los derechos que dejan crear, cambiar, borrar o reasignar algo. Leer no
#: está: la lectura por Usuarios de la disposición de 0.10.x es de fiar.
_WRITE_MASK = (
    0x2  # FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x4  # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x10  # FILE_WRITE_EA
    | 0x40  # FILE_DELETE_CHILD
    | 0x100  # FILE_WRITE_ATTRIBUTES
    | 0x10000  # DELETE
    | 0x40000  # WRITE_DAC
    | 0x80000  # WRITE_OWNER
    | 0x2000000  # MAXIMUM_ALLOWED
    | 0x10000000  # GENERIC_ALL
    | 0x40000000  # GENERIC_WRITE
)

_RIGHT_CODES = {
    "GA": 0x10000000, "GR": 0x80000000, "GW": 0x40000000, "GX": 0x20000000,
    "FA": 0x1F01FF, "FR": 0x120089, "FW": 0x120116, "FX": 0x1200A0,
    "RC": 0x20000, "SD": 0x10000, "WD": 0x40000, "WO": 0x80000,
    "CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "RP": 0x10, "WP": 0x20,
    "DT": 0x40, "LO": 0x80, "CR": 0x100,
}  # fmt: skip

_ALLOW_TYPES = {"A", "OA", "XA", "ZA"}
_ACE = re.compile(r"\(([^()]*)\)")
_OWNER = re.compile(r"O:(S-[0-9A-Fa-fx-]+|[A-Z]{2})")


def _rights(text: str) -> int:
    """Los derechos de un ACE, en número. Lo que no se entiende cuenta como todo."""
    text = text.strip()
    if not text:
        return 0
    try:
        return int(text, 0)
    except ValueError:
        pass
    mask = 0
    for start in range(0, len(text), 2):
        code = text[start : start + 2].upper()
        if code not in _RIGHT_CODES:
            return 0xFFFFFFFF  # ante la duda, peligroso
        mask |= _RIGHT_CODES[code]
    return mask


def _is_broad(sid: str) -> bool:
    sid = sid.strip()
    if sid.upper() in _BROAD_SIDS or sid in _BROAD_SIDS.values() or sid.upper() in _BROAD_EXTRA:
        return True
    # Domain Users / Domain Guests de cualquier dominio.
    return bool(re.fullmatch(r"S-1-5-21-\d+-\d+-\d+-51[34]", sid))


def sddl_is_protected(sddl: str, runner_sid: str = "") -> bool:
    """Whether a folder with this security descriptor was safe to trust.

    Protected means: a DACL that does not inherit from above (flag ``P``), no
    allow entry letting a broad group (Users, Authenticated Users, Everyone,
    INTERACTIVE...) create or change anything, and an owner that is SYSTEM,
    the Administrators or the account running the agent -- or else an OWNER
    RIGHTS entry, which takes away the owner's implicit right to rewrite the
    DACL. Anything that cannot be read is *not* protected.
    """
    if not isinstance(sddl, str) or "D:" not in sddl:
        return False
    dacl = sddl[sddl.index("D:") + 2 :]
    flags = dacl.split("(", 1)[0]
    if "NO_ACCESS_CONTROL" in flags or "P" not in flags.replace("AI", "").replace("AR", ""):
        return False
    aces = _ACE.findall(dacl)
    has_owner_rights = False
    for ace in aces:
        fields = ace.split(";")
        if len(fields) < 6:
            return False
        kind, rights, sid = fields[0].upper(), fields[2], fields[5].strip()
        if kind not in _ALLOW_TYPES:
            continue
        mask = _rights(rights)
        if sid.upper() in ("OW", "S-1-3-4"):
            has_owner_rights = True
        if _is_broad(sid) and mask & _WRITE_MASK:
            return False
    owner = _OWNER.search(sddl.split("D:", 1)[0])
    if owner is not None:
        trusted = set(_TRUSTED_OWNERS)
        if runner_sid:
            trusted.add(runner_sid)
        if owner.group(1) not in trusted and not has_owner_rights:
            return False
    return True


def posix_is_protected(mode: int, owner_uid: int, euid: int) -> bool:
    """Whether a POSIX folder was safe to trust: ours (or root's), no group/other write."""
    return owner_uid in (euid, 0) and not (mode & 0o022)


def _principals(runner_sid: str) -> list[str]:
    principals = ["SY", "BA"]
    if runner_sid and runner_sid not in (_WINDOWS_SYSTEM_SID, _WINDOWS_ADMINS_SID, "SY", "BA"):
        principals.append(runner_sid)
    return principals


def file_sddl(runner_sid: str = "", *, readers: bool = False, owner: bool = False) -> str:
    """A file only SYSTEM, the Administrators and `runner_sid` may touch.

    `readers` adds BUILTIN\\Users read: only for ``status.json``.
    """
    aces = "".join(f"(A;;FA;;;{sid})" for sid in _principals(runner_sid))
    if readers:
        aces += f"(A;;{_READ};;;BU)"
    return ("O:BA" if owner else "") + "D:P" + aces


def folder_sddl(runner_sid: str = "", *, top: bool = False, owner: bool = False) -> str:
    """A folder whose contents inherit the same few principals.

    `top` is the state folder itself: Users may list it (no inheritance: they
    read ``status.json`` and nothing else), and OWNER RIGHTS gets the same so
    whoever created it before the agent does not keep the right to rewrite it.
    """
    aces = "".join(f"(A;OICI;FA;;;{sid})" for sid in _principals(runner_sid))
    if top:
        aces += f"(A;;{_READ};;;BU)(A;;{_READ};;;OW)"
    return ("O:BA" if owner else "") + "D:P" + aces


# --- Leer y escribir permisos en Windows ---------------------------------------

_OWNER_INFO = 0x1
_DACL_INFO = 0x4
_PROTECTED_DACL_INFO = 0x80000000
_SE_FILE_OBJECT = 1
_SDDL_REVISION_1 = 1


class _Pywin32Backend:
    """pywin32, when installed (the service always has it)."""

    name = "pywin32"

    def __init__(self) -> None:
        import win32api
        import win32security

        for attr in (
            "GetNamedSecurityInfo",
            "SetNamedSecurityInfo",
            "ConvertSecurityDescriptorToStringSecurityDescriptor",
            "ConvertStringSecurityDescriptorToSecurityDescriptor",
            "OpenProcessToken",
            "GetTokenInformation",
            "ConvertSidToStringSid",
        ):
            if not hasattr(win32security, attr):
                raise ImportError(attr)
        self._api = win32api
        self._sec = win32security

    def read_sddl(self, target: Path) -> str:
        sec = self._sec
        try:
            sd = sec.GetNamedSecurityInfo(str(target), _SE_FILE_OBJECT, _OWNER_INFO | _DACL_INFO)
            return sec.ConvertSecurityDescriptorToStringSecurityDescriptor(
                sd, _SDDL_REVISION_1, _OWNER_INFO | _DACL_INFO
            )
        except Exception as exc:  # noqa: BLE001 - pywintypes.error
            raise OSError(str(exc)) from exc

    def write_sddl(self, target: Path, sddl: str) -> None:
        sec = self._sec
        try:
            sd = sec.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, _SDDL_REVISION_1)
            owner = sd.GetSecurityDescriptorOwner() if sddl.startswith("O:") else None
            # La constante del módulo y no 0x80000000: pywin32 la quiere con signo.
            info = sec.DACL_SECURITY_INFORMATION | sec.PROTECTED_DACL_SECURITY_INFORMATION
            if owner is not None:
                info |= sec.OWNER_SECURITY_INFORMATION
            sec.SetNamedSecurityInfo(
                str(target), _SE_FILE_OBJECT, info, owner, None, sd.GetSecurityDescriptorDacl(), None
            )
        except Exception as exc:  # noqa: BLE001
            raise OSError(str(exc)) from exc

    def runner_sid(self) -> str:
        sec = self._sec
        token = sec.OpenProcessToken(self._api.GetCurrentProcess(), 0x8)  # TOKEN_QUERY
        try:
            return sec.ConvertSidToStringSid(sec.GetTokenInformation(token, 1)[0])  # TokenUser
        finally:
            self._api.CloseHandle(token)


class _CtypesBackend:
    """The same through ``ctypes``: a plain ``pip install`` on Windows has no pywin32."""

    name = "ctypes"

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        self._ct = ctypes
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        void_p, dword, ptr = ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER
        advapi.GetNamedSecurityInfoW.argtypes = [
            wintypes.LPCWSTR, ctypes.c_int, dword, void_p, void_p, void_p, void_p, ptr(void_p)
        ]
        advapi.GetNamedSecurityInfoW.restype = dword
        advapi.SetNamedSecurityInfoW.argtypes = [
            wintypes.LPWSTR, ctypes.c_int, dword, void_p, void_p, void_p, void_p
        ]
        advapi.SetNamedSecurityInfoW.restype = dword
        advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [
            void_p, dword, dword, ptr(void_p), void_p
        ]
        advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = wintypes.BOOL
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            wintypes.LPCWSTR, dword, ptr(void_p), void_p
        ]
        advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
        advapi.GetSecurityDescriptorDacl.argtypes = [void_p, ptr(wintypes.BOOL), ptr(void_p), ptr(wintypes.BOOL)]
        advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
        advapi.GetSecurityDescriptorOwner.argtypes = [void_p, ptr(void_p), ptr(wintypes.BOOL)]
        advapi.GetSecurityDescriptorOwner.restype = wintypes.BOOL
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, dword, ptr(wintypes.HANDLE)]
        advapi.OpenProcessToken.restype = wintypes.BOOL
        advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, void_p, dword, ptr(dword)]
        advapi.GetTokenInformation.restype = wintypes.BOOL
        advapi.ConvertSidToStringSidW.argtypes = [void_p, ptr(void_p)]
        advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
        kernel.LocalFree.argtypes = [void_p]
        kernel.LocalFree.restype = void_p
        kernel.GetCurrentProcess.argtypes = []
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        self._advapi, self._kernel = advapi, kernel

    def _fail(self, code: int | None = None) -> OSError:
        code = self._ct.get_last_error() if code is None else code
        return OSError(code, self._ct.FormatError(code).strip())

    def read_sddl(self, target: Path) -> str:
        ct = self._ct
        sd = ct.c_void_p()
        error = self._advapi.GetNamedSecurityInfoW(
            str(target), _SE_FILE_OBJECT, _OWNER_INFO | _DACL_INFO, None, None, None, None, ct.byref(sd)
        )
        if error:
            raise self._fail(error)
        try:
            text = ct.c_void_p()
            if not self._advapi.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd, _SDDL_REVISION_1, _OWNER_INFO | _DACL_INFO, ct.byref(text), None
            ):
                raise self._fail()
            try:
                return ct.wstring_at(text.value)
            finally:
                self._kernel.LocalFree(text)
        finally:
            self._kernel.LocalFree(sd)

    def write_sddl(self, target: Path, sddl: str) -> None:
        ct = self._ct
        from ctypes import wintypes

        sd = ct.c_void_p()
        if not self._advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, _SDDL_REVISION_1, ct.byref(sd), None
        ):
            raise self._fail()
        try:
            present, defaulted = wintypes.BOOL(), wintypes.BOOL()
            dacl = ct.c_void_p()
            if not self._advapi.GetSecurityDescriptorDacl(sd, ct.byref(present), ct.byref(dacl), ct.byref(defaulted)):
                raise self._fail()
            owner = ct.c_void_p()
            info = _DACL_INFO | _PROTECTED_DACL_INFO
            if sddl.startswith("O:"):
                if not self._advapi.GetSecurityDescriptorOwner(sd, ct.byref(owner), ct.byref(defaulted)):
                    raise self._fail()
                info |= _OWNER_INFO
            error = self._advapi.SetNamedSecurityInfoW(
                str(target), _SE_FILE_OBJECT, info, owner if owner.value else None, None, dacl, None
            )
            if error:
                raise self._fail(error)
        finally:
            self._kernel.LocalFree(sd)

    def runner_sid(self) -> str:
        ct = self._ct
        from ctypes import wintypes

        token = wintypes.HANDLE()
        if not self._advapi.OpenProcessToken(self._kernel.GetCurrentProcess(), 0x8, ct.byref(token)):
            raise self._fail()
        try:
            size = wintypes.DWORD()
            self._advapi.GetTokenInformation(token, 1, None, 0, ct.byref(size))
            buffer = ct.create_string_buffer(size.value)
            if not self._advapi.GetTokenInformation(token, 1, buffer, size, ct.byref(size)):
                raise self._fail()
            sid = ct.c_void_p.from_buffer(buffer).value  # TOKEN_USER.User.Sid
            text = ct.c_void_p()
            if not self._advapi.ConvertSidToStringSidW(sid, ct.byref(text)):
                raise self._fail()
            try:
                return ct.wstring_at(text.value)
            finally:
                self._kernel.LocalFree(text)
        finally:
            self._kernel.CloseHandle(token)


@lru_cache(maxsize=1)
def _backend() -> _Pywin32Backend | _CtypesBackend:
    """pywin32 if it is importable and whole; else the standard library."""
    try:
        return _Pywin32Backend()
    except Exception:  # noqa: BLE001 - sin pywin32 (o con un doble de test): ctypes
        return _CtypesBackend()


@lru_cache(maxsize=1)
def _runner_sid() -> str:
    try:
        return _backend().runner_sid()
    except Exception:  # noqa: BLE001
        return ""


@lru_cache(maxsize=1)
def _is_admin() -> bool:
    """SYSTEM, or an elevated administrator: who may hand ownership to Administrators."""
    if sys.platform != "win32":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _acl_runner() -> str:
    """The account to name in the ACLs: none when it is SYSTEM or an Administrator."""
    return "" if _is_admin() else _runner_sid()


def _apply(target: Path, sddl: str) -> None:
    """Replace `target`'s owner (if `sddl` names one) and DACL. Raises `OSError`.

    Si no se puede poner a Administradores como dueño, se deja el que hay y se
    aplica igual la DACL: lo que protege es la DACL; el dueño solo la hace
    determinista.
    """
    try:
        _backend().write_sddl(target, sddl)
    except OSError:
        if not sddl.startswith("O:"):
            raise
        _backend().write_sddl(target, sddl[sddl.index("D:") :])


def _restrict_windows(target: Path) -> None:
    """Quita lo heredado y deja a SYSTEM, Administradores y a quien corre el agente."""
    _apply(target, file_sddl(_acl_runner(), owner=_is_admin()))


def protect_status_file(target: Path) -> None:
    """``status.json``: like the rest, plus BUILTIN\\Users read for the tray. Never raises."""
    if sys.platform != "win32":
        return
    try:
        _apply(target, file_sddl(_acl_runner(), readers=True, owner=_is_admin()))
    except Exception:  # noqa: BLE001 - el estado es una comodidad
        pass


def write_protected(target: Path, content: str | bytes) -> None:
    """Write `content` to `target` atomically, readable only by who must read it.

    The one way the agent writes anything secret or near-secret to disk: the
    token, the identity key (`agent/identity.py`), the local settings, the
    memory. Raises `OSError` when it cannot be protected -- and then nothing is
    left behind.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    # El temporal ya nace cerrado (mkstemp usa 0600) y se protege antes de
    # recibir el contenido, no después: ni un instante legible por otros.
    fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=f".{target.stem}-", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        data = content.encode("utf-8") if isinstance(content, str) else content
        with os.fdopen(fd, "wb") as handle:
            if sys.platform == "win32":
                handle.flush()
                _restrict_windows(tmp)
            handle.write(data)
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def private_folder(target: Path) -> Path:
    """Create `target` (if needed) closed like the rest: only SYSTEM, the Administrators
    and the account running the agent on Windows; ``0700`` on POSIX. Raises `OSError`.

    Lo que el actualizador descarga se guarda aquí y se ejecuta después: no
    basta con heredar de la carpeta de estado, se cierra explícitamente.
    """
    target.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        _apply(target, folder_sddl(_acl_runner(), owner=_is_admin()))
    else:
        os.chmod(target, 0o700)
    return target


def private_temp(folder: Path, *, prefix: str, suffix: str) -> tuple[int, Path]:
    """A new empty file in `folder`, already closed to others, open for writing.

    Como en `write_protected`: el temporal nace cerrado (``0600`` con
    `mkstemp`, y en Windows con la DACL protegida antes de escribir nada).
    Devuelve el descriptor y la ruta; quien llama lo cierra y lo borra si falla.
    """
    fd, name = tempfile.mkstemp(dir=folder, prefix=prefix, suffix=suffix)
    tmp = Path(name)
    if sys.platform == "win32":
        try:
            _restrict_windows(tmp)
        except BaseException:
            os.close(fd)
            tmp.unlink(missing_ok=True)
            raise
    return fd, tmp


def save(enrollment: Enrollment, environ: Mapping[str, str] | None = None) -> Path:
    """Write the enrolment, protected, replacing any previous one."""
    target = path(environ)
    try:
        write_protected(
            target, json.dumps({"url": enrollment.url, "token": enrollment.token, "name": enrollment.name})
        )
    except OSError as exc:
        raise StoreError(
            _t("No se pudo guardar el enrolamiento de forma segura en %(path)s: %(error)s")
            % {"path": target, "error": exc}
        ) from exc
    return target


def remove(environ: Mapping[str, str] | None = None) -> list[Path]:
    """Delete the enrolment and the identity key (`cenya-agent goodbye`). Returns what went.

    Nunca lanza: lo que no se pudo borrar simplemente no está en la lista.
    """
    removed: list[Path] = []
    for target in (path(environ), state_dir(environ) / IDENTITY_FILE):
        try:
            target.unlink()
        except OSError:
            continue
        removed.append(target)
    return removed


# --- Asegurar la carpeta al arrancar -------------------------------------------


@dataclass(frozen=True)
class Securing:
    """What `secure_state_dir` found and did."""

    folder: Path
    #: La carpeta ya estaba protegida (o no existía): lo de dentro es de fiar.
    trusted: bool
    #: Lo que se apartó por no ser de fiar, con su nombre nuevo.
    moved: tuple[str, ...] = ()
    suffix: str = ""
    #: Lo que no se pudo volver a proteger, sin que eso impida arrancar.
    warnings: tuple[str, ...] = field(default=())


def moved_line(securing: Securing) -> str:
    """The one line that says what was set aside, for a person. "" if nothing was."""
    if not securing.moved:
        return ""
    return _t(
        "[agente] La carpeta %(path)s no estaba protegida: se ha apartado sin usarlo lo que otro "
        "usuario pudo dejar en ella (%(names)s), y ya queda protegida."
    ) % {"path": securing.folder, "names": ", ".join(securing.moved)}


def _stamp(now: datetime | None) -> str:
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return UNTRUSTED_SUFFIX + moment.strftime("%Y%m%dT%H%M%SZ")


def _move_aside(base: Path, suffix: str) -> list[str]:
    """Renombra lo que alguien pudo dejar. Nunca borra. Lanza `StoreError` si
    algo que el agente leería no se puede apartar: entonces no arranca."""
    moved: list[str] = []
    for name in (*PRIVATE_FILES, *PRIVATE_FOLDERS):
        item = base / name
        if not item.exists() and not item.is_symlink():
            continue
        target = base / f"{name}{suffix}"
        counter = 1
        while target.exists():
            counter += 1
            target = base / f"{name}{suffix}-{counter}"
        try:
            item.rename(target)
        except OSError as exc:
            if name == "logs":
                continue  # el registro no se lee: que no impida arrancar
            raise StoreError(
                _t("No se pudo apartar %(path)s, que no es de fiar: %(error)s") % {"path": item, "error": exc}
            ) from exc
        moved.append(target.name)
    return moved


def secure_state_dir(
    environ: Mapping[str, str] | None = None, *, folder: Path | None = None, now: datetime | None = None
) -> Securing:
    """Protect the state folder before anything in it is read. Call it on every start.

    If the folder was not protected, what a stranger could have planted
    (`PRIVATE_FILES`, the outbox, the log) is renamed aside first. Raises
    `StoreError` when an unprotected folder cannot be protected (no rights):
    then the agent must not read or write its secrets there.
    """
    base = Path(folder) if folder is not None else state_dir(environ)
    if sys.platform == "win32":
        return _secure_windows(base, now)
    return _secure_posix(base, now)


def _cannot_protect(base: Path, error: object) -> StoreError:
    return StoreError(
        _t(
            "La carpeta %(path)s no está protegida y no se puede proteger (%(error)s): el agente no "
            "lee ni guarda en ella su token ni sus credenciales. Ejecútalo como administrador o como servicio."
        )
        % {"path": base, "error": error}
    )


def _created(base: Path) -> bool:
    """Crea la carpeta si no existe. `True` si la ha creado ahora."""
    if base.exists():
        return False
    base.mkdir(parents=True, exist_ok=True)
    return True


def _secure_windows(base: Path, now: datetime | None) -> Securing:
    runner = _runner_sid()
    admin = _is_admin()
    acl_runner = "" if admin else runner
    try:
        created = _created(base)
    except OSError as exc:
        raise _cannot_protect(base, exc) from exc
    if created:
        trusted = True
    else:
        try:
            trusted = sddl_is_protected(_backend().read_sddl(base), runner)
        except Exception:  # noqa: BLE001 - lo que no se puede leer no está protegido
            trusted = False
    warnings: list[str] = []
    try:
        _apply(base, folder_sddl(acl_runner, top=True, owner=admin))
    except OSError as exc:
        if not trusted:
            raise _cannot_protect(base, exc) from exc
        warnings.append(f"{base}: {exc}")
    # Recién creada y ya con algo dentro: alguien se coló en el instante entre
    # crearla y cerrarla. No es de fiar.
    if created and any(base.iterdir()):
        trusted = False
    suffix = _stamp(now)
    moved = [] if trusted else _move_aside(base, suffix)
    for name in PRIVATE_FILES:
        item = base / name
        if item.is_file():
            try:
                _apply(item, file_sddl(acl_runner, owner=admin))
            except OSError as exc:
                warnings.append(f"{item}: {exc}")
    for name in PRIVATE_FOLDERS:
        item = base / name
        if item.is_dir():
            try:
                _apply(item, folder_sddl(acl_runner, owner=admin))
            except OSError as exc:
                warnings.append(f"{item}: {exc}")
    status_file = base / STATUS_FILE
    if status_file.is_file():
        protect_status_file(status_file)
    return Securing(base, trusted, tuple(moved), suffix if moved else "", tuple(warnings))


def _secure_posix(base: Path, now: datetime | None) -> Securing:
    euid = os.geteuid() if hasattr(os, "geteuid") else -1
    try:
        created = not base.exists()
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.stat(base)
    except OSError as exc:
        raise _cannot_protect(base, exc) from exc
    trusted = created or posix_is_protected(info.st_mode, info.st_uid, euid)
    warnings: list[str] = []
    try:
        if euid == 0 and info.st_uid != 0:
            os.chown(base, 0, 0)
        elif info.st_uid not in (euid, 0):
            raise PermissionError(errno.EPERM, os.strerror(errno.EPERM))
        os.chmod(base, 0o700)
    except OSError as exc:
        if not trusted:
            raise _cannot_protect(base, exc) from exc
        warnings.append(f"{base}: {exc}")
    if created and any(base.iterdir()):
        trusted = False
    suffix = _stamp(now)
    moved = [] if trusted else _move_aside(base, suffix)

    def tighten(item: Path, mode: int) -> None:
        try:
            if not item.is_symlink():
                os.chmod(item, mode)
        except OSError as exc:
            warnings.append(f"{item}: {exc}")

    for name in PRIVATE_FILES:
        if (base / name).is_file():
            tighten(base / name, 0o600)
    for name in PRIVATE_FOLDERS:
        folder = base / name
        if folder.is_dir():
            tighten(folder, 0o700)
            for item in folder.iterdir():
                if item.is_file():
                    tighten(item, 0o600)
    return Securing(base, trusted, tuple(moved), suffix if moved else "", tuple(warnings))

