"""The agent updates itself (``docs/agente-v2-instalacion.md``, section 4).

The server says which version to go to in the check-in (``"update":
{"version": "0.11.1"}``); this module decides whether to, fetches the signed
manifest and the file for this platform, verifies both (`agent.release`), waits
until no task is running, and hands over to the installer:

* **Windows**: the downloaded ``.exe`` with ``/VERYSILENT /UPDATE``, detached
  from the service (the installer stops the service, replaces it, starts it,
  and leaves a watchdog that rolls back if the new version never checks in).
* **Linux**: the agent runs as an unprivileged user and cannot replace
  ``/opt`` or restart its own unit. It leaves a request
  (``updates/request.json``); a root-owned systemd path unit runs
  ``cenya-agent update apply-request``, which **verifies everything again with
  its own code and keys** before running the verified ``install.sh --update``.
  The unprivileged agent can ask; it can never make root run something.

The rules that do not bend:

* **Nothing runs unverified.** Signature of the manifest by a known key, then
  the hash and size of the file; the file is checked once more right before it
  is launched. What fails is deleted and reported with its code.
* **Never down, never sideways.** The manifest's version must be the one the
  server asked for and strictly newer than the running one.
* **Never in the middle of a task.** Once a file is ready, no new task starts
  and the update waits for the one in progress.
* **A version that was rolled back is never tried again** (its ``failed-``
  marker, left by the watchdog), even if the server keeps offering it.
* **The bearer token never follows a redirect.** GitHub's downloads redirect
  (no token is sent there); the agent's own server never does.

The decisions are pure functions (`decide`, `check_manifest`,
`startup_state`, `download_name`) and the `Updater` only strings them
together, so the tests drive every branch without threads, network or clock.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent import __version__, logs, release, store
from agent.config import setting
from agent.i18n import _t
from agent.notes import collector_note
from agent.release import (
    BAD_HASH,
    BAD_MANIFEST,
    BAD_SIGNATURE,
    NO_CRYPTO,
    NO_KEYS,
    VERSION_RE,
    ReleaseError,
)

# --- Estados y códigos (contrato, sección 4) -------------------------------------

STATE_IDLE = "idle"
STATE_DOWNLOADING = "downloading"
STATE_READY = "ready"
STATE_INSTALLING = "installing"
STATE_FAILED = "failed"

#: Además de los de `agent.release` (bad_signature, bad_hash, bad_manifest,
#: no_keys, no_crypto). Todos viajan como nota `update` / <código>.
NOT_NEWER = "not_newer"
WRONG_VERSION = "wrong_version"
DOWNLOAD_FAILED = "download_failed"
UPDATE_FAILED = "update_failed"
INSTALL_FAILED = "install_failed"
UNSUPPORTED = "unsupported"

#: Lo que no se vuelve a intentar nunca con esa versión: el vigilante la
#: devolvió atrás, o el instalador ni siquiera llegó a sustituirla.
PERMANENT = frozenset({UPDATE_FAILED, INSTALL_FAILED})

#: Cuando varias fuentes fallan, la que se cuenta es la más seria: una firma
#: mala dice más que una red caída.
_SERIOUSNESS = (BAD_SIGNATURE, BAD_HASH, BAD_MANIFEST, WRONG_VERSION, NOT_NEWER, NO_KEYS, NO_CRYPTO, DOWNLOAD_FAILED)

# --- Dónde --------------------------------------------------------------------------

FOLDER = store.UPDATES_FOLDER
PENDING_FILE = "pending.json"
REQUEST_FILE = "request.json"
RESULT_FILE = "result.json"
HEALTHY_PREFIX = "healthy-"
FAILED_PREFIX = "failed-"
#: Una versión cuyo instalador no llegó a sustituir nada se reintenta una vez
#: (casi siempre un fichero en uso en ese instante); esta marca dice que ya se hizo.
RETRIED_PREFIX = "retried-"
PARTIAL_PREFIX = ".dl-"

#: Las publicaciones de este repositorio. `CENYA_RELEASES_URL` lo cambia (la
#: prueba del instalador en CI sirve las suyas en 127.0.0.1): no abre nada,
#: porque lo que se baje de ahí tiene que venir firmado igual.
RELEASES_URL = "https://github.com/cenya-io/cenya-agent/releases/download"
SERVER_INSTALLER_PATH = "/api/agent/v2/installer/"

#: Tras un fallo que puede ser pasajero (red, firma, huella), cuánto se espera
#: antes de volver a intentarlo con la misma versión. Una orden explícita
#: («Actualizar» en la web) no espera.
RETRY_SECONDS = 30 * 60
#: Lanzado el instalador, si en este tiempo el agente sigue siendo el mismo, la
#: instalación no llegó a hacerse: se deja de esperar y se dice.
INSTALL_TIMEOUT_SECONDS = 20 * 60
#: Cada cuánto se mira si la tarea en curso terminó.
IDLE_POLL_SECONDS = 5.0
TIMEOUT_SECONDS = 30
CHUNK = 256 * 1024
#: El vigilante del instalador: lo que se acepta de `CENYA_UPDATE_WATCHDOG_SECONDS`.
MIN_WATCHDOG_SECONDS = 60
MAX_WATCHDOG_SECONDS = 24 * 60 * 60

#: El nombre local de cada fichero, que nunca sale del manifiesto ni de una URL.
_SUFFIXES = {
    "windows": ("cenya-agent-", ".exe"),
    "linux": ("cenya-agent-", ".tar.gz"),
    "install.sh": ("install-", ".sh"),
    "manifest": ("manifest-", ".json"),
    "signature": ("manifest-", ".json.sig"),
}


# --- Decisiones puras ------------------------------------------------------------------


def version_tuple(text: object) -> tuple[int, ...] | None:
    """`(0, 11, 1)` for ``"0.11.1"``; `None` for anything that is not a version."""
    if not isinstance(text, str) or not VERSION_RE.match(text):
        return None
    parts = tuple(int(part) for part in text.split("."))
    # 0.11 y 0.11.0 son la misma: se rellena a cuatro para comparar.
    return parts + (0,) * (4 - len(parts))


def is_newer(candidate: object, current: object) -> bool:
    """Whether `candidate` is strictly newer than `current`. Unknown versions are never newer."""
    new, old = version_tuple(candidate), version_tuple(current)
    return new is not None and old is not None and new > old


@dataclass(frozen=True)
class Offer:
    """What the server asked for in the check-in."""

    version: str
    #: Alguien pulsó «Actualizar»: vale aunque `auto_update` esté apagado aquí
    #: y no espera a que pase el tiempo de reintento. Nunca resucita una
    #: versión que ya se devolvió atrás.
    explicit: bool = False


def parse_offer(value: object) -> Offer | None:
    """`update` of the check-in answer (spec 1.2): `None`, or a version to go to."""
    if not isinstance(value, dict):
        return None
    version = value.get("version")
    if version_tuple(version) is None:
        return None
    return Offer(str(version), value.get("explicit") is True)


@dataclass(frozen=True)
class Decision:
    go: bool
    #: Por qué no, cuando no: `no_offer`, `in_progress`, `not_newer`,
    #: `failed_before`, `auto_update_off`, `waiting_retry`, `unsupported`.
    reason: str = ""


def decide(
    offer: Offer | None,
    *,
    current: str,
    auto_update: bool,
    failed: Iterable[str],
    retry_after: Mapping[str, float],
    now: float,
    in_progress: bool,
    platform: str | None,
) -> Decision:
    """Whether to start updating to `offer` now. Pure: no files, no network."""
    if offer is None:
        return Decision(False, "no_offer")
    if in_progress:
        return Decision(False, "in_progress")
    if platform is None:
        return Decision(False, UNSUPPORTED)
    if not is_newer(offer.version, current):
        return Decision(False, NOT_NEWER)
    if offer.version in set(failed):
        return Decision(False, "failed_before")
    if not (auto_update or offer.explicit):
        return Decision(False, "auto_update_off")
    if not offer.explicit and retry_after.get(offer.version, 0.0) > now:
        return Decision(False, "waiting_retry")
    return Decision(True)


def check_manifest(manifest: Mapping[str, Any], *, requested: str, current: str) -> None:
    """A verified manifest is acceptable only for exactly the requested, strictly newer version."""
    version = manifest.get("version")
    if version != requested:
        raise ReleaseError(WRONG_VERSION, f"el manifiesto es de la {version}, se pidió la {requested}")
    if not is_newer(version, current):
        raise ReleaseError(NOT_NEWER, f"la {version} no es más nueva que la {current}")


def platform_key(sys_platform: str = sys.platform) -> str | None:
    """Which file of the manifest this machine installs: `windows`, `linux`, or `None`."""
    if sys_platform == "win32":
        return "windows"
    if sys_platform.startswith("linux"):
        return "linux"
    return None


def download_name(version: str, kind: str) -> str:
    """The local name of a downloaded file. Built here, never taken from a URL.

    La versión ya pasó por `VERSION_RE` (cifras y puntos), así que el nombre no
    puede llevar una barra ni un ``..``; aun así se vuelve a comprobar.
    """
    if version_tuple(version) is None or kind not in _SUFFIXES:
        raise ReleaseError(BAD_MANIFEST, "versión o tipo de fichero no válidos")
    prefix, suffix = _SUFFIXES[kind]
    return f"{prefix}{version}{suffix}"


def inside(folder: Path, name: str) -> Path:
    """`folder / name`, refusing anything that would land outside `folder`."""
    if not name or name in (".", "..") or any(sep in name for sep in ("/", "\\", ":", "\0")):
        raise ReleaseError(BAD_MANIFEST, "nombre de fichero no válido")
    target = folder / name
    if target.resolve().parent != folder.resolve():
        raise ReleaseError(BAD_MANIFEST, "nombre de fichero fuera de la carpeta de descargas")
    return target


def most_serious(codes: Iterable[str]) -> str:
    """Of several failures, the one worth telling (a bad signature over a network error)."""
    seen = list(codes)
    for code in _SERIOUSNESS:
        if code in seen:
            return code
    return seen[0] if seen else DOWNLOAD_FAILED


def state(name: str, version: str = "", error: str = "") -> dict[str, str]:
    """The `update_state` of the check-in body (contract, section 4)."""
    return {"state": name, "version": version, "error": error}


def startup_state(
    *, current: str, pending: Mapping[str, Any] | None, failed: Iterable[str]
) -> tuple[dict[str, str], str | None]:
    """What the agent is when it starts, from what the last attempt left on disk.

    Returns the `update_state` and, when the last attempt must be written down
    as failed now, the version to mark (the installer never replaced anything:
    the agent that launched it is the one that started again).
    """
    failed = set(failed)
    if pending:
        target, origin = str(pending.get("to") or ""), str(pending.get("from") or "")
        if target == current:
            # La versión nueva, recién instalada: sana cuando haga su primer checkin.
            return state(STATE_INSTALLING, target), None
        if origin == current and version_tuple(target) is not None:
            if target in failed:
                # El vigilante la devolvió atrás y lo dejó escrito.
                return state(STATE_FAILED, target, UPDATE_FAILED), None
            return state(STATE_FAILED, target, INSTALL_FAILED), target
    newer = sorted((v for v in failed if is_newer(v, current)), key=lambda v: version_tuple(v) or ())
    if newer:
        return state(STATE_FAILED, newer[-1], UPDATE_FAILED), None
    return state(STATE_IDLE), None


def should_retry_install(
    *, current: str, pending: Mapping[str, Any] | None, failed: Iterable[str], retried: Iterable[str]
) -> str | None:
    """The version whose installer never replaced anything, if it deserves one more go.

    The same case `startup_state` calls `install_failed`, the first time only:
    a locked file or a service started by hand in the middle says nothing about
    the version itself. The second failure is final, as it always was.
    """
    if not pending:
        return None
    target, origin = str(pending.get("to") or ""), str(pending.get("from") or "")
    if target == current or origin != current or version_tuple(target) is None:
        return None
    if target in set(failed) or target in set(retried):
        return None
    return target


def watchdog_seconds(environ: Mapping[str, str]) -> int | None:
    """`CENYA_UPDATE_WATCHDOG_SECONDS`, bounded; `None` leaves the installer's own (600)."""
    raw = setting(environ, "UPDATE_WATCHDOG_SECONDS")
    if not raw:
        return None
    try:
        seconds = int(raw)
    except ValueError:
        return None
    return max(MIN_WATCHDOG_SECONDS, min(seconds, MAX_WATCHDOG_SECONDS))


def releases_url(environ: Mapping[str, str]) -> str:
    """Where the signed manifests are; only an allowed URL may replace the default."""
    override = setting(environ, "RELEASES_URL").rstrip("/")
    return override if override and release.allowed_url(override) else RELEASES_URL


def installer_arguments(installer: Path, *, log: Path, watchdog: int | None) -> list[str]:
    """The command line of the Windows installer in update mode (contract, section 4)."""
    arguments = [str(installer), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/UPDATE", f"/LOG={log}"]
    if watchdog is not None:
        arguments.append(f"/WATCHDOGSECONDS={watchdog}")
    return arguments


# --- Descargar -----------------------------------------------------------------------


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """For the agent's own server: a redirect is an error, never followed with the token."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, D102
        raise urllib.error.HTTPError(req.full_url, code, "redirección no seguida", headers, fp)


class _SafeRedirects(urllib.request.HTTPRedirectHandler):
    """For public downloads (GitHub redirects to its file storage): only to an allowed URL,
    and without any ``Authorization`` header -- none is ever sent there, and none can leak."""

    max_redirections = 5

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, D102
        if not release.allowed_url(newurl):
            raise urllib.error.HTTPError(req.full_url, code, "redirección a una URL no permitida", headers, fp)
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            new.remove_header("Authorization")
        return new


class Fetcher:
    """HTTP for the updater: the proxy and CA of the local settings, and its redirect rules."""

    def __init__(self, *, ca_bundle: str = "", proxy: tuple[str, str] | None = None) -> None:
        from agent.client import _proxy_handler

        self._proxy = _proxy_handler(proxy)
        self._ca_bundle = ca_bundle
        #: Un abridor por (redirecciones, CA): crear uno carga el almacén de
        #: certificados del sistema, que en Windows cuesta cerca de un segundo.
        self._openers: dict[tuple[type, str], Any] = {}

    def _opener(self, redirects: urllib.request.HTTPRedirectHandler, *, cafile: str = "") -> Any:
        import ssl

        key = (type(redirects), cafile)
        if key not in self._openers:
            handlers: list[Any] = [redirects]
            if self._proxy is not None:
                handlers.append(self._proxy)
            if cafile:
                handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=cafile)))
            self._openers[key] = urllib.request.build_opener(*handlers)
        return self._openers[key]

    def public(self, url: str) -> Any:
        """GET a public file (GitHub). Redirects allowed, to https only, never with a token.

        Si el certificado no verifica con el almacén del sistema, una segunda
        opinión con la lista de Mozilla, como hace el cliente
        (`agent.client.AgentClient._open`): el almacén de Windows guarda
        certificados caducados que a veces elige OpenSSL. Nunca sin verificar.
        """
        if not release.allowed_url(url):
            raise ReleaseError(BAD_MANIFEST, "URL no permitida")
        request = urllib.request.Request(url, headers={"User-Agent": f"cenya-agent/{__version__}"})
        return self._open(request, _SafeRedirects, cafile="")

    def server(self, base_url: str, token: str) -> Any:
        """GET the installer from the agent's own server, with its token. No redirects at all."""
        url = base_url.rstrip("/") + SERVER_INSTALLER_PATH
        if not release.allowed_url(url):
            raise ReleaseError(DOWNLOAD_FAILED, "el servidor no es https")
        request = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {token}", "User-Agent": f"cenya-agent/{__version__}"}
        )
        return self._open(request, _NoRedirects, cafile=self._ca_bundle)

    def _open(self, request: urllib.request.Request, redirects: type, *, cafile: str) -> Any:
        from agent.client import _is_certificate_failure, _mozilla_roots

        try:
            return self._opener(redirects(), cafile=cafile).open(request, timeout=TIMEOUT_SECONDS)
        except urllib.error.URLError as exc:
            # La CA propia de la empresa no se discute; sin ella, segunda opinión.
            roots = "" if cafile else _mozilla_roots()
            if not (roots and _is_certificate_failure(exc)):
                raise
            return self._opener(redirects(), cafile=roots).open(request, timeout=TIMEOUT_SECONDS)


_NETWORK_ERRORS = (urllib.error.URLError, TimeoutError, OSError, ValueError, binascii.Error)


def read_small(response: Any, max_bytes: int) -> bytes:
    """The body of a small answer (a manifest, a signature), refusing anything bigger."""
    data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ReleaseError(BAD_MANIFEST, "respuesta demasiado grande")
    return data


def stream_to(response: Any, folder: Path, name: str, entry: Mapping[str, Any]) -> Path:
    """Write `response` to `folder/name`, hashing on the way; nothing is left if it does not verify.

    Se escribe primero a un temporal ya cerrado a otros usuarios
    (`store.private_temp`), con el tope del tamaño que dice el manifiesto: un
    servidor que manda más de lo anunciado se corta ahí, sin llenar el disco.
    Solo con tamaño y huella exactos pasa a tener su nombre.
    """
    expected_size = int(entry["size"])
    announced = response.headers.get("Content-Length") if getattr(response, "headers", None) else None
    if announced and announced.isdigit() and int(announced) > expected_size:
        raise ReleaseError(BAD_HASH, "el servidor anuncia más bytes que el manifiesto")
    target = inside(folder, name)
    fd, tmp = store.private_temp(folder, prefix=PARTIAL_PREFIX, suffix=".part")
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(fd, "wb") as handle:
            while chunk := response.read(CHUNK):
                size += len(chunk)
                if size > expected_size:
                    raise ReleaseError(BAD_HASH, "el fichero es más grande que lo que dice el manifiesto")
                digest.update(chunk)
                handle.write(chunk)
        if size != expected_size or not hmac.compare_digest(digest.hexdigest(), str(entry["sha256"])):
            raise ReleaseError(BAD_HASH, "el fichero no coincide con el manifiesto")
        os.replace(tmp, target)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return target


# --- Lanzar ---------------------------------------------------------------------------

#: CreateProcess: sin consola, en su propio grupo y, si el trabajo lo permite,
#: fuera del objeto de trabajo del servicio. El instalador para el servicio:
#: no puede morir con él.
_DETACHED_PROCESS = 0x00000008
_CREATE_NEW_PROCESS_GROUP = 0x00000200
_CREATE_BREAKAWAY_FROM_JOB = 0x01000000


def launch_detached(arguments: list[str]) -> None:
    """Start the Windows installer so that stopping the service does not stop it."""
    common: dict[str, Any] = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
        "cwd": str(Path(arguments[0]).parent),
    }
    flags = _DETACHED_PROCESS | _CREATE_NEW_PROCESS_GROUP
    try:
        subprocess.Popen(arguments, creationflags=flags | _CREATE_BREAKAWAY_FROM_JOB, **common)  # noqa: S603
    except OSError:
        # Un objeto de trabajo que no deja salir: sin esa bandera. Un servicio
        # normal no está en ninguno, y el instalador sobrevive igual.
        subprocess.Popen(arguments, creationflags=flags, **common)  # noqa: S603


# --- El actualizador -----------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _reasons() -> dict[str, str]:
    """Why an update did not happen, for the agent's own log, in its language."""
    return {
        BAD_SIGNATURE: _t("la firma del manifiesto no es de ninguna clave conocida"),
        BAD_HASH: _t("el fichero descargado no coincide con el manifiesto firmado; se ha borrado"),
        BAD_MANIFEST: _t("el manifiesto no es válido"),
        NO_KEYS: _t("este agente no tiene ninguna clave de publicación configurada"),
        NO_CRYPTO: _t("falta la librería cryptography para verificar la firma"),
        NOT_NEWER: _t("no es más nueva que la instalada"),
        WRONG_VERSION: _t("el manifiesto es de otra versión"),
        DOWNLOAD_FAILED: _t("no se pudo descargar"),
        INSTALL_FAILED: _t("el instalador no llegó a sustituir el agente"),
        UPDATE_FAILED: _t("no consiguió conectar y se volvió a la versión anterior"),
        UNSUPPORTED: _t("este sistema no se actualiza solo"),
    }


#: El texto en castellano de la nota, para un servidor que no conozca el código.
_NOTE_TEXT = {
    BAD_SIGNATURE: "la firma del manifiesto no es de ninguna clave conocida",
    BAD_HASH: "el fichero descargado no coincide con el manifiesto",
    BAD_MANIFEST: "el manifiesto no es válido",
    NO_KEYS: "no hay ninguna clave de publicación configurada",
    NO_CRYPTO: "falta cryptography para verificar la firma",
    NOT_NEWER: "la versión pedida no es más nueva que la instalada",
    WRONG_VERSION: "el manifiesto es de otra versión",
    DOWNLOAD_FAILED: "no se pudo descargar la versión nueva",
    INSTALL_FAILED: "el instalador no llegó a sustituir el agente",
    UPDATE_FAILED: "la versión nueva no conectó y se volvió a la anterior",
    UNSUPPORTED: "este sistema no se actualiza solo",
}


class Updater:
    """Strings the decisions together. Never raises into the agent; never blocks the check-in."""

    def __init__(
        self,
        state_dir: Path,
        *,
        client: Any = None,
        fetcher: Fetcher | None = None,
        keys: Iterable[str] | None = None,
        current: str = __version__,
        platform: str | None = None,
        auto_update: Callable[[], bool] = lambda: True,
        busy: Callable[[], bool] = lambda: False,
        environ: Mapping[str, str] | None = None,
        launcher: Callable[[list[str]], None] | None = None,
        clock: Callable[[], float] = time.time,
        enabled: bool = True,
        say: Callable[[str], None] = logs.info,
    ) -> None:
        if keys is None:
            from agent.release_keys import PUBLIC_KEYS

            keys = PUBLIC_KEYS
        self.state_dir = Path(state_dir)
        self.folder = self.state_dir / FOLDER
        self.client = client
        self.fetcher = fetcher or Fetcher()
        self.keys = list(keys)
        self.current = current
        self.platform = platform_key() if platform is None else (platform or None)
        self._auto_update = auto_update
        self._busy = busy
        self._environ = os.environ if environ is None else environ
        self._launcher = launcher or launch_detached
        self._clock = clock
        self.enabled = enabled
        self._say = say
        self._lock = threading.Lock()
        self._state = state(STATE_IDLE)
        self._note: dict[str, Any] | None = None
        self._failed: set[str] = set()
        self._retry_after: dict[str, float] = {}
        self._hold = False
        self._thread: threading.Thread | None = None
        self._launched_at: float | None = None
        self._healthy_written = False
        self._last_said = ""
        #: Para que un test (o el servicio al parar) pueda despertar la espera.
        self.stop = threading.Event()

    # --- Lo que pide el resto del agente -------------------------------------------

    def state(self) -> dict[str, Any] | None:
        """`update_state` for the check-in body; `None` when disabled (``--once``)."""
        if not self.enabled:
            return None
        with self._lock:
            current = dict(self._state)
            if self._note is not None:
                current["note"] = dict(self._note)
            return current

    def holding(self) -> bool:
        """Whether tasks must not start: a verified update is waiting for the current one to end."""
        with self._lock:
            return self._hold

    def startup(self) -> None:
        """Read what the last attempt left (markers, the pending update). Never raises."""
        if not self.enabled:
            return
        try:
            self._startup()
        except Exception:  # noqa: BLE001 - un resto raro de una actualización no impide arrancar
            pass

    def offer(self, update: object) -> None:
        """Called after every successful check-in, with its `update` field. Never raises.

        Un checkin bueno es también la prueba de que esta versión funciona: la
        primera vez se deja la marca de «sana» que busca el vigilante.
        """
        if not self.enabled:
            return
        try:
            self._mark_healthy()
            self._check_installing()
            self._consider(parse_offer(update))
        except Exception as exc:  # noqa: BLE001
            self._say_once(_t("[agente] Error inesperado al actualizar: %(error)s") % {"error": f"{type(exc).__name__}: {exc}"})

    # --- Arrancar -------------------------------------------------------------------

    def _startup(self) -> None:
        if not self.folder.is_dir():
            return
        failed: set[str] = set()
        retried: set[str] = set()
        for item in list(self.folder.iterdir()):
            name = item.name
            if name.startswith(FAILED_PREFIX):
                version = name[len(FAILED_PREFIX) :]
                if is_newer(version, self.current):
                    failed.add(version)
                    continue
            elif name.startswith(RETRIED_PREFIX):
                version = name[len(RETRIED_PREFIX) :]
                if is_newer(version, self.current):
                    retried.add(version)
                    continue
            elif name.startswith(HEALTHY_PREFIX) and name == HEALTHY_PREFIX + self.current:
                continue
            elif name in (PENDING_FILE, RESULT_FILE, REQUEST_FILE) or name.endswith(".log"):
                continue
            # Lo demás es de una versión ya pasada o un trozo a medias: fuera.
            self._remove(item)
        pending = self._read_json(self.folder / PENDING_FILE)
        again = should_retry_install(current=self.current, pending=pending, failed=failed, retried=retried)
        if again:
            # Ni «falló» ni nada que contar: el servidor sigue ofreciéndola y la
            # siguiente vez, si vuelve a fallar, ya es definitivo.
            self._write_marker(RETRIED_PREFIX + again)
            (self.folder / PENDING_FILE).unlink(missing_ok=True)
            pending = None
            self._say_once(
                _t("[agente] El instalador de la versión %(version)s no llegó a sustituir el agente; se intentará una vez más.")
                % {"version": again}
            )
        current_state, mark = startup_state(current=self.current, pending=pending, failed=failed)
        if mark:
            failed.add(mark)
            self._write_marker(FAILED_PREFIX + mark)
        with self._lock:
            self._failed = failed
            self._state = current_state
            self._note = self._note_for(current_state)
            if current_state["state"] == STATE_INSTALLING:
                self._launched_at = self._clock()
        if pending and current_state["state"] != STATE_INSTALLING:
            (self.folder / PENDING_FILE).unlink(missing_ok=True)
        if current_state["error"] == UPDATE_FAILED:
            self._say_once(
                _t("[agente] La versión %(version)s no arrancó bien y se volvió a la anterior: no se intentará de nuevo.")
                % {"version": current_state["version"]}
            )

    # --- Cada checkin ---------------------------------------------------------------

    def _mark_healthy(self) -> None:
        if self._healthy_written:
            return
        store.private_folder(self.folder)
        store.write_protected(self.folder / (HEALTHY_PREFIX + self.current), _now_iso())
        self._healthy_written = True
        with self._lock:
            if self._state["state"] == STATE_INSTALLING and self._state["version"] == self.current:
                self._state, self._note, self._launched_at = state(STATE_IDLE, self.current), None, None
        (self.folder / PENDING_FILE).unlink(missing_ok=True)

    def _check_installing(self) -> None:
        """An installer launched by this same process that never replaced it: give up waiting."""
        with self._lock:
            installing = self._state["state"] == STATE_INSTALLING and self._state["version"] != self.current
            version, launched = self._state["version"], self._launched_at
        if not installing:
            return
        result = self._read_json(self.folder / RESULT_FILE)
        if result and result.get("version") == version:
            (self.folder / RESULT_FILE).unlink(missing_ok=True)
            code = str(result.get("error") or INSTALL_FAILED)
            self._fail(version, code if code in _NOTE_TEXT else INSTALL_FAILED)
            return
        if launched is not None and self._clock() - launched > INSTALL_TIMEOUT_SECONDS:
            self._fail(version, INSTALL_FAILED)

    def _consider(self, offer: Offer | None) -> None:
        with self._lock:
            in_progress = (self._thread is not None and self._thread.is_alive()) or self._state["state"] in (
                STATE_READY,
                STATE_INSTALLING,
            )
            failed = set(self._failed)
            retry = dict(self._retry_after)
        decision = decide(
            offer,
            current=self.current,
            auto_update=bool(self._auto_update()),
            failed=failed,
            retry_after=retry,
            now=self._clock(),
            in_progress=in_progress,
            platform=self.platform,
        )
        if decision.reason == "auto_update_off" and offer is not None:
            self._say_once(
                _t(
                    "[agente] Hay una versión nueva del agente (%(version)s), pero la actualización automática "
                    "está apagada en esta máquina."
                )
                % {"version": offer.version}
            )
        if not decision.go or offer is None:
            return
        thread = threading.Thread(target=self.run, args=(offer,), name="cenya-update", daemon=True)
        with self._lock:
            self._thread = thread
        thread.start()

    # --- La actualización, en su hilo ------------------------------------------------

    def run(self, offer: Offer) -> bool:
        """Fetch, verify, wait, launch. `True` if the installer was launched. Never raises."""
        version = offer.version
        try:
            return self._run(offer)
        except ReleaseError as exc:
            self._fail(version, exc.code)
        except Exception:  # noqa: BLE001 - lo inesperado tampoco deja a medias
            self._fail(version, DOWNLOAD_FAILED)
        return False

    def _run(self, offer: Offer) -> bool:
        version = offer.version
        if self.platform is None:
            raise ReleaseError(UNSUPPORTED)
        # Sin claves (o sin cryptography) no se baja nada: se dice y ya.
        release.load_public_keys(self.keys)
        self._set(state(STATE_DOWNLOADING, version))
        self._say_once(_t("[agente] Descargando la versión %(version)s del agente.") % {"version": version})
        store.private_folder(self.folder)
        if self.platform == "windows":
            files = self._fetch_windows(offer)
        else:
            files = self._fetch_linux(offer)
        self._set(state(STATE_READY, version))
        with self._lock:
            self._hold = True
        self._say_once(
            _t("[agente] Versión %(version)s verificada: se instalará en cuanto no haya ninguna tarea en curso.")
            % {"version": version}
        )
        while self._busy():
            if self.stop.wait(IDLE_POLL_SECONDS):
                with self._lock:
                    self._hold = False
                return False
        # Justo antes de lanzarlo, otra vez: entre la descarga y ahora ha
        # podido pasar una tarea entera.
        for path, entry in files:
            release.verify_file(path, entry)
        store.write_protected(
            self.folder / PENDING_FILE, json.dumps({"from": self.current, "to": version, "at": _now_iso()})
        )
        self._set(state(STATE_INSTALLING, version))
        with self._lock:
            self._launched_at = self._clock()
        self._say_once(_t("[agente] Instalando la versión %(version)s; el servicio se reiniciará.") % {"version": version})
        try:
            if self.platform == "windows":
                installer = files[0][0]
                log = self.folder / f"setup-{version}.log"
                self._launcher(installer_arguments(installer, log=log, watchdog=watchdog_seconds(self._environ)))
            else:
                store.write_protected(self.folder / REQUEST_FILE, json.dumps({"version": version, "at": _now_iso()}))
        except OSError as exc:
            (self.folder / PENDING_FILE).unlink(missing_ok=True)
            raise ReleaseError(INSTALL_FAILED, str(exc)) from exc
        return True

    def _accept(self, manifest_bytes: bytes, signature: str | bytes, offer: Offer) -> dict[str, Any]:
        manifest = release.verify_manifest(manifest_bytes, signature, self.keys)
        check_manifest(manifest, requested=offer.version, current=self.current)
        return manifest

    def _release_manifest(self, version: str) -> tuple[bytes, bytes]:
        base = f"{releases_url(self._environ)}/agent-v{version}/latest.json"
        with self.fetcher.public(base) as response:
            manifest_bytes = read_small(response, release.MAX_MANIFEST_BYTES)
        with self.fetcher.public(base + ".sig") as response:
            signature = read_small(response, release.MAX_SIGNATURE_BYTES)
        return manifest_bytes, signature

    def _fetch_windows(self, offer: Offer) -> list[tuple[Path, dict[str, Any]]]:
        version = offer.version
        name = download_name(version, "windows")
        codes: list[str] = []
        # 1. Las publicaciones del repositorio.
        try:
            manifest = self._accept(*self._release_manifest(version), offer)
            entry = release.file_entry(manifest, "windows")
            with self.fetcher.public(entry["url"]) as response:
                return [(stream_to(response, self.folder, name, entry), entry)]
        except ReleaseError as exc:
            codes.append(exc.code)
        except _NETWORK_ERRORS:
            codes.append(DOWNLOAD_FAILED)
        # 2. Su propio servidor, que lo sirve con el manifiesto en las cabeceras.
        if self.client is not None and getattr(self.client, "base_url", ""):
            try:
                with self.fetcher.server(self.client.base_url, self.client.token) as response:
                    manifest_bytes = base64.b64decode(response.headers.get("X-Cenya-Manifest") or "", validate=True)
                    signature = response.headers.get("X-Cenya-Manifest-Signature") or ""
                    manifest = self._accept(manifest_bytes, signature, offer)
                    entry = release.file_entry(manifest, "windows")
                    announced = (response.headers.get("X-Cenya-Sha256") or "").lower()
                    if announced and announced != entry["sha256"]:
                        raise ReleaseError(BAD_HASH, "la cabecera no coincide con el manifiesto")
                    return [(stream_to(response, self.folder, name, entry), entry)]
            except ReleaseError as exc:
                codes.append(exc.code)
            except _NETWORK_ERRORS:
                codes.append(DOWNLOAD_FAILED)
        raise ReleaseError(most_serious(codes))

    def _fetch_linux(self, offer: Offer) -> list[tuple[Path, dict[str, Any]]]:
        """The archive and install.sh, and the manifest and signature the root helper re-checks."""
        version = offer.version
        try:
            manifest_bytes, signature = self._release_manifest(version)
        except _NETWORK_ERRORS as exc:
            raise ReleaseError(DOWNLOAD_FAILED) from exc
        manifest = self._accept(manifest_bytes, signature, offer)
        files: list[tuple[Path, dict[str, Any]]] = []
        try:
            for kind in ("linux", "install.sh"):
                entry = release.file_entry(manifest, kind)
                with self.fetcher.public(entry["url"]) as response:
                    files.append((stream_to(response, self.folder, download_name(version, kind), entry), entry))
        except _NETWORK_ERRORS as exc:
            raise ReleaseError(DOWNLOAD_FAILED) from exc
        store.write_protected(inside(self.folder, download_name(version, "manifest")), manifest_bytes)
        store.write_protected(inside(self.folder, download_name(version, "signature")), signature)
        return files

    # --- Por dentro -----------------------------------------------------------------

    def _set(self, value: dict[str, str]) -> None:
        with self._lock:
            self._state, self._note = value, None

    def _note_for(self, value: Mapping[str, str]) -> dict[str, Any] | None:
        code = value.get("error") or ""
        if not code:
            return None
        return collector_note("update", code, _NOTE_TEXT.get(code, code), version=value.get("version") or "").as_json()

    def _fail(self, version: str, code: str) -> None:
        """Say it, write it down, clean up, and let tasks run again."""
        for kind in _SUFFIXES:
            try:
                self._remove(inside(self.folder, download_name(version, kind)))
            except ReleaseError:
                pass
        if code in PERMANENT:
            self._write_marker(FAILED_PREFIX + version)
        failed_state = state(STATE_FAILED, version, code)
        with self._lock:
            if code in PERMANENT:
                self._failed.add(version)
            else:
                self._retry_after[version] = self._clock() + RETRY_SECONDS
            self._state, self._note = failed_state, self._note_for(failed_state)
            self._hold = False
            self._launched_at = None
        (self.folder / PENDING_FILE).unlink(missing_ok=True)
        reason = _reasons().get(code, code)
        self._say_once(
            _t("[agente] No se actualiza a la versión %(version)s: %(reason)s.") % {"version": version, "reason": reason}
        )

    def _write_marker(self, name: str) -> None:
        try:
            store.private_folder(self.folder)
            store.write_protected(self.folder / name, _now_iso())
        except OSError:
            pass

    def _remove(self, item: Path) -> None:
        try:
            if item.is_dir() and not item.is_symlink():
                return
            item.unlink(missing_ok=True)
        except OSError:
            pass

    def _read_json(self, path: Path) -> dict[str, Any] | None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _say_once(self, text: str) -> None:
        if text != self._last_said:
            self._last_said = text
            self._say(text)


# --- Linux: el ayudante con privilegios ----------------------------------------------------


def _read_regular(path: Path, max_bytes: int) -> bytes:
    """Read a regular file without following a link; refuse anything else or anything bigger.

    Lo lee root, en una carpeta que escribe el usuario del agente: un enlace a
    `/etc/shadow` o una FIFO no pueden convertirse en algo que root lea o espere.
    """
    flags = (
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    )
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ReleaseError(BAD_MANIFEST, f"{path.name} no es un fichero normal")
        if info.st_size > max_bytes:
            raise ReleaseError(BAD_HASH, f"{path.name} es demasiado grande")
        chunks = []
        total = 0
        while chunk := os.read(fd, CHUNK):
            total += len(chunk)
            if total > max_bytes:
                raise ReleaseError(BAD_HASH, f"{path.name} es demasiado grande")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write_result(folder: Path, version: str, code: str) -> None:
    """Tell the unprivileged agent why its request was refused (it reads `result.json`)."""
    target = folder / RESULT_FILE
    try:
        # Root, en una carpeta que escribe el usuario del agente: nada por ruta
        # después de abrir. Un `chown` por nombre tras cerrar dejaba cambiar el
        # fichero por un enlace en medio y regalarle al agente otro fichero.
        # La carpeta se abre una vez, sin seguir enlaces, y todo va relativo a
        # ella: cambiarla por un enlace a mitad ya no lleva a ningún otro sitio.
        if hasattr(os, "fchown") and os.open in os.supports_dir_fd:
            folder_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                owner = os.fstat(folder_fd)
                try:
                    os.unlink(RESULT_FILE, dir_fd=folder_fd)
                except FileNotFoundError:
                    pass
                fd = os.open(
                    RESULT_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=folder_fd
                )
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    os.fchown(handle.fileno(), owner.st_uid, owner.st_gid)
                    json.dump({"version": version, "error": code}, handle)
            finally:
                os.close(folder_fd)
            return
        # Windows no tiene ayudante con privilegios: aquí escribe el propio agente.
        target.unlink(missing_ok=True)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"version": version, "error": code}, handle)
    except OSError:
        pass


def apply_request(
    state_dir: Path,
    *,
    keys: Iterable[str] | None = None,
    current: str = __version__,
    run: Callable[..., Any] = subprocess.run,
) -> int:
    """Linux, as root: verify the request the agent left and run the verified ``install.sh --update``.

    Todo se copia primero a una carpeta temporal solo de root y se verifica
    ahí, con el código y las claves de esta instalación (de root, en `/opt`):
    lo que dejó el usuario del agente no se cree, se comprueba. La petición se
    borra antes de nada, para que la unidad `.path` no la vuelva a disparar.
    """
    if keys is None:
        from agent.release_keys import PUBLIC_KEYS

        keys = PUBLIC_KEYS
    folder = Path(state_dir) / FOLDER
    request = folder / REQUEST_FILE
    try:
        raw = _read_regular(request, 4096)
    except FileNotFoundError:
        return 0
    except (OSError, ReleaseError):
        request.unlink(missing_ok=True)
        return 1
    request.unlink(missing_ok=True)
    version = ""
    try:
        data = json.loads(raw.decode("utf-8"))
        version = str(data.get("version") or "") if isinstance(data, dict) else ""
        if version_tuple(version) is None:
            raise ReleaseError(BAD_MANIFEST, "la petición no trae una versión válida")
        with tempfile.TemporaryDirectory(prefix="cenya-update-") as tmp:
            work = Path(tmp)
            copies: dict[str, Path] = {}
            for kind, limit in (
                ("manifest", release.MAX_MANIFEST_BYTES),
                ("signature", release.MAX_SIGNATURE_BYTES),
                ("linux", release.MAX_FILE_BYTES),
                ("install.sh", release.MAX_FILE_BYTES),
            ):
                name = download_name(version, kind)
                copies[kind] = work / name
                copies[kind].write_bytes(_read_regular(inside(folder, name), limit))
            manifest = release.verify_manifest(copies["manifest"].read_bytes(), copies["signature"].read_bytes(), keys)
            check_manifest(manifest, requested=version, current=current)
            release.verify_file(copies["linux"], release.file_entry(manifest, "linux"))
            release.verify_file(copies["install.sh"], release.file_entry(manifest, "install.sh"))
            result = run(
                ["/bin/sh", str(copies["install.sh"]), "--update", "--archive", str(copies["linux"]), "--version", version],
                check=False,
            )
            if getattr(result, "returncode", 1) != 0:
                raise ReleaseError(INSTALL_FAILED, f"install.sh terminó con {getattr(result, 'returncode', '?')}")
    except ReleaseError as exc:
        _write_result(folder, version, exc.code)
        return 1
    except FileNotFoundError:
        _write_result(folder, version, DOWNLOAD_FAILED)
        return 1
    except OSError:
        _write_result(folder, version, INSTALL_FAILED)
        return 1
    except ValueError:
        _write_result(folder, version, BAD_MANIFEST)
        return 1
    return 0


def run(args: list[str], environ: Mapping[str, str] | None = None) -> int:
    """`cenya-agent update apply-request <state dir>` (the Linux root helper)."""
    if args[:1] == ["apply-request"] and len(args) == 2:
        return apply_request(Path(args[1]))
    print(_t("Uso: cenya-agent update apply-request <carpeta de estado>"), file=sys.stderr)
    return 2
