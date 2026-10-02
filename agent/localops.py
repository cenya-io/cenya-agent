"""What the local channel can do: the handlers of spec 4, wired into the running agent.

`agent.localapi` decides what a request is and who may make it; this module is
what happens then. A `LocalService` lives as long as the service process and
follows its identity: `agent.__main__` tells it which `Runtime` is current
(`attach`), and asks it after each run whether someone changed the identity
from the channel (`connect`, `disconnect`).

Rules every handler keeps:

* **Short locks, nothing that waits on the loop.** A handler takes the
  runtime's locks for a copy and lets go; what takes time (a probe, a NetBox
  export, a goodbye) runs in the connection's own thread. The service loop
  never waits for a client.
* **No secret goes out.** Not in an answer, an error or the log: a proxy URL is
  shown with its credentials masked; the NetBox token that arrives in
  ``netbox.export`` is used and dropped; the support bundle is scrubbed of
  every secret the agent knows about before it is written.
* **Validate first, change after.** ``settings.set`` checks every field before
  saving any; ``connect`` redeems the code before touching the saved
  enrolment, so a code that fails leaves the agent as it was.
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import re
import socket
import sys
import ssl
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agent import __version__, about, enroll, logs, netbox_export, outbox, status, store
from agent import settings as local_settings
from agent.client import PushError, proxy_url_is_valid
from agent.config import Config, setting
from agent.i18n import _t
from agent.localapi import (
    BUSY,
    EXCLUDED,
    FAILED,
    INVALID,
    NOT_ENROLLED,
    UNAVAILABLE,
    Caller,
    Dispatcher,
    OpError,
)
from agent.scheduler import TASKS

CONNECTED = "connected"
DISCONNECTED = "disconnected"

#: Cuánto puede durar una pausa con hora puesta en esta máquina. Más es
#: olvidarse de que el agente está parado; quien lo quiere parado sin plazo lo
#: dice (`indefinite`), y entonces la ventana y el portal lo enseñan así.
MAX_PAUSE = timedelta(days=30)
#: Lo que espera `check_update` a su checkin antes de contestar con lo que haya.
CHECK_UPDATE_WAIT = 30.0
#: Dónde revisa una persona una lectura de NetBox subida (spec 3.4), si el
#: servidor no lo dice en `review_url`. SUPUESTO: lo tiene que confirmar el
#: servidor, o mandar siempre `review_url`; está en un solo sitio a propósito.
NETBOX_REVIEW_PATH = "/settings/import/pending/{import_id}/"

# Por qué un servicio no tiene identidad (`status.enrollment.state`).
ENROLLED = "enrolled"
NOT_ENROLLED_STATE = "not_enrolled"
UNTRUSTED_STATE = "untrusted"
INVALID_STATE = "invalid"
DEFAULT_LOG_LINES = 200
MAX_LOG_LINES = 2000
#: Lo más que se lee del final del registro de una vez.
LOG_TAIL_BYTES = 1024 * 1024

LANGUAGES = ("", "es", "en", "de", "fr", "pt_BR")
SETTINGS_FIELDS = ("language", "ca_bundle", "proxy", "excluded", "gentleness_cap", "auto_update", "notifications")
#: Qué variable de entorno fija cada ajuste (`agent/settings.py`): si está, manda ella.
_ENV_FOR_FIELD = {
    "ca_bundle": ("CA_BUNDLE",),
    "proxy": ("PROXY",),
    "excluded": ("EXCLUDED_SUBNETS", "EXCLUDED_ADDRESSES"),
    "gentleness_cap": ("GENTLENESS_CAP",),
    "auto_update": ("AUTO_UPDATE",),
    "notifications": ("NOTIFICATIONS",),
}

#: Los secretos más cortos que esto no se buscan en el paquete de soporte:
#: tapar cada «a» de un registro no protege nada y lo deja ilegible.
MIN_SECRET_LENGTH = 3
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S)


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- La parada de una sesión -----------------------------------------------------


class SessionStop:
    """The stop the loop sees: the service's own, or a change of identity from the channel.

    El bucle y el hilo de control esperan sobre esto en vez de sobre el
    `stop_event` del servicio. Se espera a sorbos de medio segundo sobre el de
    fuera (que sigue parando en el acto) mirando entre sorbo y sorbo el de
    dentro: así un `connect` corta la sesión en medio segundo como mucho.
    """

    SLICE = 0.5

    def __init__(self, outer: Any, inner: threading.Event) -> None:
        self._outer = outer
        self._inner = inner

    def is_set(self) -> bool:
        return self._inner.is_set() or (self._outer is not None and self._outer.is_set())

    def wait(self, timeout: float | None = None) -> bool:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if self.is_set():
                return True
            remaining = self.SLICE if deadline is None else deadline - time.monotonic()
            if remaining <= 0:
                return False
            piece = min(self.SLICE, remaining)
            waiter = self._outer if self._outer is not None else self._inner
            if waiter.wait(piece):
                return True


# --- Ajustes: lo que se enseña y lo que se acepta ---------------------------------


def mask_proxy_url(url: str) -> str:
    """The proxy URL with its ``user:password@`` replaced by ``***@``."""
    url = (url or "").strip()
    if "@" not in url:
        return url
    if "://" in url:
        scheme, rest = url.split("://", 1)
        return f"{scheme}://***@{rest.rsplit('@', 1)[1]}"
    return "***@" + url.rsplit("@", 1)[1]


def settings_view(current: local_settings.Settings, locked: list[str]) -> dict[str, Any]:
    """Los ajustes como los enseña el canal: sin secretos."""
    return {
        "language": current.language,
        "ca_bundle": current.ca_bundle,
        "proxy": {
            "mode": current.proxy_mode,
            "url": mask_proxy_url(current.proxy_url),
            "has_credentials": "@" in current.proxy_url,
        },
        "excluded": {"subnets": list(current.excluded_subnets), "addresses": list(current.excluded_addresses)},
        "gentleness_cap": current.gentleness_cap,
        "auto_update": current.auto_update,
        "notifications": current.notifications,
        "paused_until": None if local_settings.is_indefinite(current.paused_until) else (
            current.paused_until.isoformat() if current.paused_until else None
        ),
        "paused_indefinitely": local_settings.is_indefinite(current.paused_until),
        "locked": locked,
    }


def _ca_problem(path: str) -> str:
    if not os.path.isfile(path):
        return _t("No existe ese fichero.")
    try:
        ssl.create_default_context(cafile=path)
    except (OSError, ssl.SSLError, ValueError):
        return _t("No es un fichero de certificados que se pueda leer (PEM).")
    return ""


def validate_settings(args: Mapping[str, Any], current: local_settings.Settings) -> tuple[dict[str, Any], dict[str, str]]:
    """The changes `args` asks for, as `Settings` fields, and what is wrong field by field. Pure."""
    changes: dict[str, Any] = {}
    errors: dict[str, str] = {}
    for name, value in args.items():
        if name not in SETTINGS_FIELDS:
            errors[str(name)[:60]] = _t("Ajuste desconocido.")
            continue
        if name == "language":
            if value not in LANGUAGES:
                errors[name] = _t("Idioma no disponible: es, en, de, fr, pt_BR o vacío.")
            else:
                changes["language"] = value
        elif name == "ca_bundle":
            if not isinstance(value, str):
                errors[name] = _t("Tiene que ser una ruta.")
            elif value.strip() and (problem := _ca_problem(value.strip())):
                errors[name] = problem
            else:
                changes["ca_bundle"] = value.strip()
        elif name == "proxy":
            if not isinstance(value, dict):
                errors[name] = _t("Tiene que ser un objeto con «mode» y «url».")
                continue
            mode = value.get("mode", current.proxy_mode)
            url = value.get("url", current.proxy_url)
            if mode not in local_settings.PROXY_MODES or not isinstance(url, str):
                errors[name] = _t("Modo de proxy no válido: system, manual o none.")
                continue
            url = url.strip()
            # Lo que enseñó `settings.get` vuelve tal cual de un formulario: la
            # contraseña que no se enseñó sigue siendo la de antes.
            if url and url == mask_proxy_url(current.proxy_url):
                url = current.proxy_url
            if mode == "manual" and not proxy_url_is_valid(url):
                # Sin repetir la URL: puede llevar una contraseña.
                errors[name] = _t("La dirección del proxy no es válida.")
                continue
            if url and mode != "manual" and not proxy_url_is_valid(url):
                url = ""
            changes["proxy_mode"], changes["proxy_url"] = mode, url
        elif name == "excluded":
            if not isinstance(value, dict):
                errors[name] = _t("Tiene que ser un objeto con «subnets» y «addresses».")
                continue
            subnets, addresses = value.get("subnets", []), value.get("addresses", [])
            if not isinstance(subnets, list) or not isinstance(addresses, list):
                errors[name] = _t("Tiene que ser un objeto con «subnets» y «addresses».")
                continue
            bad: list[str] = []
            kept_subnets: list[str] = []
            kept_addresses: list[str] = []
            for item in subnets:
                try:
                    kept_subnets.append(str(ipaddress.ip_network(str(item).strip(), strict=False)))
                except ValueError:
                    bad.append(str(item)[:60])
            for item in addresses:
                try:
                    kept_addresses.append(str(ipaddress.ip_address(str(item).strip())))
                except ValueError:
                    bad.append(str(item)[:60])
            if bad:
                errors[name] = _t("No son redes ni direcciones válidas: %(values)s") % {"values": ", ".join(bad[:10])}
            else:
                changes["excluded_subnets"] = tuple(dict.fromkeys(kept_subnets))
                changes["excluded_addresses"] = tuple(dict.fromkeys(kept_addresses))
        elif name == "gentleness_cap":
            if value not in ("", *local_settings.GENTLENESS_LEVELS):
                errors[name] = _t("Valor no válido: gentle, normal, fast o vacío.")
            else:
                changes["gentleness_cap"] = value
        elif name in ("auto_update", "notifications"):
            if not isinstance(value, bool):
                errors[name] = _t("Tiene que ser verdadero o falso.")
            else:
                changes[name] = value
    return changes, errors


def parse_until(args: Mapping[str, Any], now: datetime) -> datetime:
    """`args.until` (ISO), `args.seconds` or `args.indefinite`, checked. Raises `OpError`.

    ``{"indefinite": true}`` (sin `until` ni `seconds`) es «hasta que la
    reanude»: devuelve `settings.PAUSE_INDEFINITE`. Es una decisión explícita,
    así que no tiene el tope de 30 días de una pausa con hora.
    """
    until_raw, seconds_raw, indefinite = args.get("until"), args.get("seconds"), args.get("indefinite")
    if indefinite is not None and not isinstance(indefinite, bool):
        raise OpError(INVALID, _t("«indefinite» tiene que ser verdadero o falso."))
    if indefinite:
        if until_raw is not None or seconds_raw is not None:
            raise OpError(INVALID, _t("Una pausa sin plazo no lleva «until» ni «seconds»."))
        return local_settings.PAUSE_INDEFINITE
    if until_raw is not None:
        if not isinstance(until_raw, str):
            raise OpError(INVALID, _t("«until» tiene que ser una fecha ISO 8601."))
        try:
            until = datetime.fromisoformat(until_raw.strip().replace("Z", "+00:00"))
        except ValueError:
            raise OpError(INVALID, _t("«until» tiene que ser una fecha ISO 8601.")) from None
        if until.tzinfo is None:
            until = until.replace(tzinfo=timezone.utc)
    elif seconds_raw is not None:
        if isinstance(seconds_raw, bool) or not isinstance(seconds_raw, (int, float)) or seconds_raw <= 0:
            raise OpError(INVALID, _t("«seconds» tiene que ser un número de segundos mayor que cero."))
        until = now + timedelta(seconds=float(seconds_raw))
    else:
        raise OpError(INVALID, _t("Falta «until» o «seconds»."))
    if until <= now:
        raise OpError(INVALID, _t("Esa hora ya ha pasado."))
    if until - now > MAX_PAUSE:
        raise OpError(
            INVALID,
            _t("Una pausa con hora no puede durar más de %(days)d días; para pararlo sin plazo, pausa hasta que lo reanudes.")
            % {"days": MAX_PAUSE.days},
        )
    return until


# --- El registro -------------------------------------------------------------------


def read_log(path: Path, lines: int, after: str | None = None) -> dict[str, Any]:
    """The last `lines` lines of the log, or those written since `after` (a cursor). Never raises.

    El cursor es «fichero:posición»: lo que devuelve cada respuesta, para
    pedir solo lo nuevo (``logs -f``). Si el registro rotó, el fichero es otro
    y se devuelve el final del nuevo.
    """
    try:
        info = os.stat(path)
    except OSError:
        return {"lines": [], "cursor": "", "missing": True}
    size, ident = info.st_size, f"{info.st_ino}"
    start = max(0, size - LOG_TAIL_BYTES)
    from_cursor = False
    if after:
        file_id, _, offset = str(after).partition(":")
        if file_id == ident and offset.isdigit() and int(offset) <= size:
            start = max(int(offset), size - LOG_TAIL_BYTES)
            from_cursor = True
    try:
        with open(path, "rb") as handle:
            handle.seek(start)
            raw = handle.read(size - start)
    except OSError:
        return {"lines": [], "cursor": "", "missing": True}
    text = raw.decode("utf-8", errors="replace")
    rows = text.split("\n")
    if rows and rows[-1] == "":
        rows.pop()
    if start > 0 and not from_cursor and rows:
        rows = rows[1:]  # la primera, cortada por la mitad
    rows = [logs.scrub(row.rstrip("\r")) for row in rows][-lines:]
    return {"lines": rows, "cursor": f"{ident}:{size}"}


# --- Probar la conexión -----------------------------------------------------------


def _step(name: str, ok: bool, code: str, message: str, **params: Any) -> dict[str, Any]:
    return {"step": name, "ok": ok, "code": code, "params": params, "message": message}


def _proxy_for(url: str, proxy: tuple[str, str] | None) -> str:
    """The proxy the client will go through for `url`, or "" if it goes direct."""
    if proxy is not None and proxy[0] == "none":
        return ""
    if proxy is not None and proxy[0] == "manual":
        return proxy[1]
    host = urllib.parse.urlsplit(url).hostname or ""
    try:
        if urllib.request.proxy_bypass(host):
            return ""
    except Exception:  # noqa: BLE001
        pass
    scheme = urllib.parse.urlsplit(url).scheme
    return urllib.request.getproxies().get(scheme, "")


def _tls_check(host: str, port: int, ca_bundle: str) -> tuple[bool, str, dict[str, Any]]:
    """El apretón de manos TLS, con la razón si el certificado no vale."""

    def handshake(cafile: str | None) -> None:
        context = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                pass

    if ca_bundle and _ca_problem(ca_bundle):
        return False, "ca_bundle_unreadable", {"path": ca_bundle}
    try:
        handshake(ca_bundle or None)
        return True, "ok", {}
    except ssl.SSLCertVerificationError as exc:
        reason = str(exc.verify_message or exc.reason or exc)
        if not ca_bundle:
            # La misma segunda opinión que da el cliente (agent/client.py).
            from agent.client import _mozilla_roots

            roots = _mozilla_roots()
            if roots:
                try:
                    handshake(roots)
                    return True, "ok_mozilla_roots", {"reason": reason}
                except Exception:  # noqa: BLE001
                    pass
        return False, "certificate", {"reason": reason}
    except (ssl.SSLError, OSError) as exc:
        return False, "handshake_failed", {"reason": type(exc).__name__}


def connection_test(
    url: str,
    *,
    ca_bundle: str,
    proxy: tuple[str, str] | None,
    checkin: Callable[[], tuple[bool, int | None, str]] | None,
    resolve: Callable[[str, int], Any] = socket.getaddrinfo,
    open_tcp: Callable[[tuple[str, int], float], Any] = socket.create_connection,
    tls: Callable[[str, int, str], tuple[bool, str, dict[str, Any]]] = _tls_check,
) -> list[dict[str, Any]]:
    """Name, port, certificate and token, step by step, each with its code. Stops at the first failure.

    Con un proxy en medio, el nombre y el puerto que se prueban son los del
    proxy, y el certificado se comprueba con el checkin (que va por él).
    """
    steps: list[dict[str, Any]] = []
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        port = 0
    if not host or not port:
        steps.append(_step("dns", False, "bad_url", _t("La dirección del portal no es válida.")))
        return steps
    via = _proxy_for(url, proxy)
    target_host, target_port = host, port
    if via:
        proxy_parts = urllib.parse.urlsplit(via if "://" in via else f"http://{via}")
        try:
            target_host, target_port = proxy_parts.hostname or "", proxy_parts.port or 8080
        except ValueError:
            target_host = ""
        if not target_host:
            steps.append(_step("dns", False, "bad_proxy", _t("La dirección del proxy no es válida.")))
            return steps
    shown = {"host": target_host, "port": target_port, "via_proxy": bool(via)}
    try:
        resolve(target_host, target_port)
    except (OSError, UnicodeError):
        steps.append(_step("dns", False, "not_found", _t("No se encuentra el nombre %(host)s.") % shown, **shown))
        return steps
    steps.append(_step("dns", True, "ok", _t("El nombre %(host)s se resuelve.") % shown, **shown))
    try:
        with open_tcp((target_host, target_port), 10):
            pass
    except TimeoutError:
        steps.append(_step("tcp", False, "timeout", _t("El puerto %(port)s de %(host)s no contesta.") % shown, **shown))
        return steps
    except ConnectionRefusedError:
        steps.append(_step("tcp", False, "refused", _t("%(host)s rechaza la conexión al puerto %(port)s.") % shown, **shown))
        return steps
    except OSError:
        steps.append(_step("tcp", False, "failed", _t("No se puede abrir una conexión con %(host)s:%(port)s.") % shown, **shown))
        return steps
    steps.append(_step("tcp", True, "ok", _t("El puerto %(port)s de %(host)s acepta conexiones.") % shown, **shown))
    if parts.scheme != "https":
        steps.append(_step("tls", True, "plain_http", _t("Sin TLS: la dirección es http://.")))
    elif via:
        steps.append(_step("tls", True, "via_proxy", _t("El certificado se comprueba a través del proxy, en el paso siguiente.")))
    else:
        ok, code, params = tls(host, port, ca_bundle)
        messages = {
            "ok": _t("El certificado del portal es válido."),
            "ok_mozilla_roots": _t("El certificado es válido con la lista de CA de Mozilla (no con la del sistema)."),
            "certificate": _t("El certificado del portal no es válido: %(reason)s"),
            "ca_bundle_unreadable": _t("No se puede leer el fichero de CA configurado (%(path)s)."),
            "handshake_failed": _t("Falló la negociación TLS (%(reason)s)."),
        }
        steps.append(_step("tls", ok, code, messages.get(code, code) % params if params else messages.get(code, code), **params))
        if not ok:
            return steps
    if checkin is None:
        steps.append(_step("checkin", False, "not_enrolled", _t("Este agente no está enrolado.")))
        return steps
    answered, status_code, detail = checkin()
    if answered:
        steps.append(_step("checkin", True, "ok", _t("El servidor acepta a este agente.")))
    elif status_code == 401:
        steps.append(_step("checkin", False, "unauthorized", _t("El servidor rechaza el token de este agente: hay que enrolarlo de nuevo."), status=401))
    elif status_code == 402:
        steps.append(_step("checkin", False, "read_only", _t("La instalación de Cenya está en solo lectura."), status=402))
    elif status_code is not None:
        steps.append(
            _step("checkin", False, "http_error", _t("El servidor respondió %(status)s: %(detail)s") % {"status": status_code, "detail": logs.scrub(detail)}, status=status_code)
        )
    else:
        steps.append(_step("checkin", False, "unreachable", _t("No se pudo hablar con el servidor: %(detail)s") % {"detail": logs.scrub(detail)}))
    return steps


# --- Secretos y el paquete de soporte ----------------------------------------------


def redact(text: str, secrets: list[str]) -> str:
    """`text` without any private key, any of `secrets`, any bearer token or URL password."""
    text = _PRIVATE_KEY.sub("[clave privada retirada]", text)
    for secret in sorted({s for s in secrets if len(s) >= MIN_SECRET_LENGTH}, key=len, reverse=True):
        text = text.replace(secret, "***")
    return logs.scrub(text)


def _credential_secrets(items: Any) -> list[str]:
    found: list[str] = []
    for item in items if isinstance(items, (list, tuple)) else []:
        if isinstance(item, dict):
            for key in ("secret", "priv_secret", "password", "token"):
                value = item.get(key)
                if isinstance(value, str) and value:
                    found.append(value)
        elif isinstance(item, str) and item:
            found.append(item)  # una comunidad
    return found


def _url_password(url: str) -> list[str]:
    if not url or "@" not in url:
        return []
    userinfo = url.split("://", 1)[-1].rsplit("@", 1)[0]
    _user, _, password = userinfo.partition(":")
    return [value for value in (password, userinfo, url) if value]


# --- El servicio ----------------------------------------------------------------------


class LocalService:
    """The handlers of spec 4 over the current runtime. One per service process."""

    def __init__(
        self,
        *,
        environ: Mapping[str, str] | None = None,
        language_locked: bool = False,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self._environ_override = environ
        self.language_locked = language_locked
        self._clock = clock
        #: Guarda `runtime`, `client`, `config`, `mode`, la sesión y el cambio pedido.
        self._lock = threading.Lock()
        self.runtime: Any = None
        self.client: Any = None
        self.config: Config | None = None
        self.mode: str | None = None
        self._session = threading.Event()
        self._change: str | None = None
        self._identity_changed = threading.Event()
        #: Los cambios de ajustes y de pausa leen, cambian y guardan el mismo fichero.
        self._settings_lock = threading.Lock()
        #: Una identidad cada vez: dos `connect` a la vez no se pisan.
        self._identity_lock = threading.Lock()
        self._export_lock = threading.Lock()
        #: Lo largo que corre desde el canal (exportación, sondeos), para `status`.
        self._jobs_lock = threading.Lock()
        self._jobs: dict[str, Any] = {}
        #: Lo que espera `check_update` (las pruebas lo acortan).
        self.check_update_wait = CHECK_UPDATE_WAIT
        #: Sin identidad, por qué: lo dice `status` (y la ventana lo enseña).
        self._enrollment: dict[str, str] = {"state": NOT_ENROLLED_STATE, "message": ""}

    # --- La sesión ------------------------------------------------------------------

    def env(self) -> Mapping[str, str]:
        return os.environ if self._environ_override is None else self._environ_override

    def attach(self, runtime: Any, client: Any, config: Config | None, mode: str | None = None) -> None:
        """El runtime vigente: lo que verán los manejadores a partir de ahora."""
        with self._lock:
            self.runtime, self.client, self.config, self.mode = runtime, client, config, mode
            self._session = threading.Event()
            self._change = None
            self._identity_changed.clear()
            self._enrollment = {"state": ENROLLED, "message": ""}

    def set_unenrolled(self, state: str, message: str) -> None:
        """Sin identidad usable: por qué (`not_enrolled`, `untrusted`, `invalid`) y la frase que lo dice."""
        with self._lock:
            self._enrollment = {"state": state, "message": logs.scrub(message)}

    def detach(self) -> None:
        with self._lock:
            self.runtime, self.client, self.config, self.mode = None, None, None, None

    def set_mode(self, mode: str | None) -> None:
        with self._lock:
            self.mode = mode

    def stop_signal(self, outer: Any) -> SessionStop:
        with self._lock:
            return SessionStop(outer, self._session)

    def take_change(self) -> str | None:
        with self._lock:
            change, self._change = self._change, None
            return change

    def _request_change(self, change: str) -> None:
        with self._lock:
            self._change = change
            self._session.set()
        if change == CONNECTED:
            self._identity_changed.set()

    def wait_for_connect(self, outer: Any) -> bool:
        """Desconectado: espera a un `connect` o a que paren el servicio. `True` si llegó el `connect`."""
        while not (outer is not None and outer.is_set()):
            if self._identity_changed.wait(0.5):
                with self._lock:
                    self._change = None
                return True
        return False

    def discard_outbox(self) -> None:
        """Lo pendiente era de la identidad de antes: no se manda con la nueva (ni a otro portal)."""
        folder = store.state_dir(self.env()) / outbox.FOLDER
        try:
            items = list(folder.iterdir())
        except OSError:
            return
        for item in items:
            try:
                if item.is_file():
                    item.unlink()
            except OSError:
                continue

    def _current(self) -> tuple[Any, Any, Config | None, str | None]:
        with self._lock:
            return self.runtime, self.client, self.config, self.mode

    def _need_runtime(self) -> Any:
        runtime, _client, _config, _mode = self._current()
        if runtime is None:
            raise OpError(NOT_ENROLLED, _t("Este agente no está enrolado: conéctalo con una cadena de Ajustes → Agentes."))
        return runtime

    def _job(self, name: str, **fields: Any) -> None:
        with self._jobs_lock:
            if fields.get("state") == "running" or name not in self._jobs:
                self._jobs[name] = {}
            self._jobs[name].update(fields)

    def jobs(self) -> dict[str, Any]:
        with self._jobs_lock:
            return json.loads(json.dumps(self._jobs, default=str))

    # --- La tabla ---------------------------------------------------------------------

    def dispatcher(self) -> Dispatcher:
        return Dispatcher(
            {
                "status": self.op_status,
                "log": self.op_log,
                "about": self.op_about,
                "settings.get": self.op_settings_get,
                "run": self.op_run,
                "pause": self.op_pause,
                "resume": self.op_resume,
                "settings.set": self.op_settings_set,
                "probe": self.op_probe,
                "test_connection": self.op_test_connection,
                "connect": self.op_connect,
                "disconnect": self.op_disconnect,
                "netbox.export": self.op_netbox_export,
                "support_bundle": self.op_support_bundle,
                "check_update": self.op_check_update,
            }
        )

    # --- Leer ---------------------------------------------------------------------------

    def op_status(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        runtime, _client, config, mode = self._current()
        env = self.env()
        enrollment = store.load(env)
        with self._lock:
            why = dict(self._enrollment)
        data: dict[str, Any] = {
            "version": __version__,
            "pid": os.getpid(),
            "enrolled": runtime is not None,
            # Sin identidad, por qué y qué hacer (spec 4): la ventana lo enseña tal cual.
            "enrollment": why if runtime is None else {"state": ENROLLED, "message": ""},
            "protocol": mode,
            "portal": status._safe_url(config.url) if config is not None else "",
            "name": enrollment.name if enrollment is not None and runtime is not None else "",
            "may_act": caller.admin,
            "local": self.jobs(),
            "log_folder": str(logs.path(env).parent),
        }
        if runtime is None:
            data["connection"] = {"state": "not_enrolled"}
            return data
        snapshot = runtime.snapshot()
        last = snapshot.get("last_checkin") or {}
        if snapshot.get("refusal"):
            state = "refused" if snapshot["refusal"] == "unauthorized" else "read_only"
        elif not last:
            state = "unknown"
        else:
            state = "ok" if last.get("ok") else "error"
        data["connection"] = {"state": state, **last, "last_ok_at": snapshot.get("last_ok_at")}
        data.update(snapshot)
        return data

    def op_log(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        lines = args.get("lines", DEFAULT_LOG_LINES)
        if isinstance(lines, bool) or not isinstance(lines, int) or lines < 1:
            raise OpError(INVALID, _t("«lines» tiene que ser un número entero positivo."))
        after = args.get("after")
        if after is not None and not isinstance(after, str):
            raise OpError(INVALID, _t("«after» tiene que ser el cursor de una respuesta anterior."))
        return read_log(logs.path(self.env()), min(lines, MAX_LOG_LINES), after)

    def op_about(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        runtime, *_ = self._current()
        if runtime is not None:
            return runtime.about()
        current = local_settings.load(self.env())
        return about.build(
            excluded_subnets=current.excluded_subnets,
            excluded_addresses=current.excluded_addresses,
            auto_update=current.auto_update,
        )

    def _locked_fields(self) -> list[str]:
        env = self.env()
        locked = [name for name, keys in _ENV_FOR_FIELD.items() if any(setting(env, key) for key in keys)]
        if self.language_locked:
            locked.insert(0, "language")
        return locked

    def op_settings_get(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        return settings_view(local_settings.load(self.env()), self._locked_fields())

    # --- Actuar ---------------------------------------------------------------------------

    def op_run(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        task = args.get("task")
        if task not in TASKS:
            raise OpError(INVALID, _t("Tarea desconocida. Las tareas son: %(tasks)s.") % {"tasks": ", ".join(TASKS)})
        runtime = self._need_runtime()
        _r, _c, _cfg, mode = self._current()
        if mode == "v1":
            raise OpError(UNAVAILABLE, _t("El servidor solo habla el protocolo 1: ahí no hay tareas sueltas, solo el barrido completo."))
        snapshot = runtime.snapshot()
        if snapshot.get("refusal") == "unauthorized":
            raise OpError(UNAVAILABLE, _t("El servidor ha rechazado a este agente: no se empieza ninguna tarea."))
        runtime.queue_local(str(task))
        waiting = ""
        if snapshot.get("refusal") == "read_only":
            waiting = "read_only"
        elif not snapshot.get("has_config"):
            waiting = "config"
        return {"queued": task, "waiting_for": waiting}

    def _save_settings(self, change: Callable[[local_settings.Settings], local_settings.Settings]) -> local_settings.Settings:
        """Lee el fichero (sin el entorno), cambia, guarda. Bajo un cerrojo: nadie pisa a nadie."""
        env = self.env()
        with self._settings_lock:
            updated = change(local_settings.load_file(env))
            if not local_settings.save(updated, env):
                raise OpError(FAILED, _t("No se pudieron guardar los ajustes en %(path)s.") % {"path": local_settings.path(env)})
        return updated

    def _server_pause(self) -> str | None:
        runtime, *_ = self._current()
        if runtime is None:
            return None
        return (runtime.snapshot().get("pause") or {}).get("server")

    def _wake(self) -> None:
        runtime, *_ = self._current()
        if runtime is not None:
            runtime.shared.wake.set()

    def op_pause(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        until = parse_until(args, self._clock())
        self._save_settings(lambda current: replace(current, paused_until=until))
        self._wake()
        indefinite = local_settings.is_indefinite(until)
        if indefinite:
            logs.info(_t("[agente] En pausa desde esta máquina hasta que se reanude."))
        else:
            logs.info(_t("[agente] En pausa desde esta máquina hasta %(until)s.") % {"until": until.isoformat()})
        return {
            "paused_until": None if indefinite else until.isoformat(),
            "indefinite": indefinite,
            "server_paused_until": self._server_pause(),
        }

    def op_resume(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        self._save_settings(lambda current: replace(current, paused_until=None))
        self._wake()
        logs.info(_t("[agente] Pausa local levantada desde esta máquina."))
        # La pausa puesta desde la web no se levanta aquí: se dice, para que
        # nadie piense que el agente debería estar trabajando ya.
        return {"paused_until": None, "indefinite": False, "server_paused_until": self._server_pause()}

    def op_settings_set(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        env = self.env()
        changes, problems = validate_settings(args, local_settings.load_file(env))
        if problems:
            raise OpError(INVALID, _t("Hay ajustes que no son válidos; no se ha cambiado nada."), fields=problems)
        if not changes:
            raise OpError(INVALID, _t("No hay nada que cambiar."))
        self._save_settings(lambda current: replace(current, **changes))
        effective = local_settings.load(env)
        locked = self._locked_fields()
        saved = sorted({name for name in args})
        applied: list[str] = []
        runtime, client, config, _mode = self._current()
        if runtime is not None:
            runtime.apply_settings(effective)
            applied += [name for name in ("excluded", "gentleness_cap", "auto_update") if name in saved]
        if client is not None and ({"proxy", "ca_bundle"} & set(saved)):
            ca_bundle = (config.ca_bundle if config is not None else "") or effective.ca_bundle
            try:
                client.reconfigure(ca_bundle=ca_bundle, proxy=effective.proxy)
            except Exception:  # noqa: BLE001 - validado antes; si aun así falla, se dice
                raise OpError(FAILED, _t("Los ajustes se guardaron, pero la conexión no se pudo rehacer con ellos.")) from None
            applied += [name for name in ("proxy", "ca_bundle") if name in saved]
        if "language" in saved and not self.language_locked:
            # Del fichero, no de `effective`: el entorno ya lleva el idioma de
            # antes (lo puso `main` desde estos mismos ajustes al arrancar).
            language = local_settings.load_file(env).language
            if language:
                os.environ["CENYA_LANGUAGE"] = language
            else:
                os.environ.pop("CENYA_LANGUAGE", None)
            applied.append("language")
        if "notifications" in saved:
            applied.append("notifications")  # lo lee la aplicación, no el servicio
        logs.info(_t("[agente] Ajustes locales cambiados desde esta máquina: %(fields)s.") % {"fields": ", ".join(saved)})
        return {
            "saved": saved,
            "applied": sorted(set(applied)),
            "overridden_by_environment": [name for name in saved if name in locked],
            "restart_required": [],
            "settings": settings_view(effective, locked),
        }

    def op_probe(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        try:
            ip = str(ipaddress.ip_address(str(args.get("ip") or "").strip()))
        except ValueError:
            raise OpError(INVALID, _t("La dirección no es válida.")) from None
        runtime = self._need_runtime()
        if runtime.excluded is not None and ip in runtime.excluded:
            raise OpError(EXCLUDED, _t("Esa dirección está excluida en este agente: no se sondea."))
        self._job("probe", state="running", ip=ip, started_at=self._clock().isoformat())
        try:
            report = runtime.probe_now(ip)
        except RuntimeError:
            self._job("probe", state="failed", finished_at=self._clock().isoformat())
            raise OpError(UNAVAILABLE, _t("El servidor ha rechazado a este agente: no se usa ninguna credencial.")) from None
        self._job("probe", state="done", finished_at=self._clock().isoformat())
        return {"ip": ip, "report": report}

    def _checkin_now(self) -> Callable[[], tuple[bool, int | None, str]] | None:
        runtime, client, _config, mode = self._current()
        if runtime is None:
            return None

        def legacy() -> tuple[bool, int | None, str]:
            try:
                client.heartbeat(version=__version__, hostname=socket.gethostname())
            except PushError as exc:
                return False, exc.status, str(exc)
            return True, None, ""

        def v2() -> tuple[bool, int | None, str]:
            answered = runtime.control.checkin_once()
            last = runtime.snapshot().get("last_checkin") or {}
            return answered, last.get("status"), str(last.get("error") or "")

        return legacy if mode == "v1" else v2

    def op_test_connection(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        runtime, _client, config, _mode = self._current()
        env = self.env()
        current = local_settings.load(env)
        if config is None:
            enrollment = store.load(env)
            if enrollment is None:
                raise OpError(NOT_ENROLLED, _t("Este agente no está enrolado: conéctalo con una cadena de Ajustes → Agentes."))
            url, ca_bundle = enrollment.url, current.ca_bundle
        else:
            url, ca_bundle = config.url, config.ca_bundle or current.ca_bundle
        steps = connection_test(url, ca_bundle=ca_bundle, proxy=current.proxy, checkin=self._checkin_now())
        return {"ok": all(step["ok"] for step in steps), "steps": steps, "portal": status._safe_url(url)}

    def op_connect(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        raw = args.get("connection")
        if not raw and args.get("code") and args.get("portal"):
            portal = str(args["portal"]).strip().rstrip("/")
            scheme = "cenya+http://" if portal.startswith("http://") else "cenya://"
            raw = scheme + portal.split("://", 1)[-1] + "/" + str(args["code"]).strip()
        if not isinstance(raw, str) or not raw.strip() or len(raw) > 500:
            raise OpError(INVALID, _t("Falta la cadena de conexión (la de Ajustes → Agentes)."))
        env = self.env()
        if setting(env, "AGENT_TOKEN"):
            raise OpError(UNAVAILABLE, _t("El token de este agente lo fija la variable CENYA_AGENT_TOKEN: cámbiala allí."))
        if not self._identity_lock.acquire(blocking=False):
            raise OpError(BUSY, _t("Ya se está cambiando la conexión de este agente."))
        try:
            current = local_settings.load(env)
            _r, _c, config, _m = self._current()
            ca_bundle = (config.ca_bundle if config is not None else "") or current.ca_bundle
            try:
                saved = enroll.redeem(raw, env, ca_bundle=ca_bundle, save=False)
            except SystemExit as exc:
                message = exc.code if isinstance(exc.code, str) and exc.code else _t("El enrolamiento ha fallado.")
                raise OpError(FAILED, logs.scrub(message)) from None
            try:
                store.save(saved, env)
            except store.StoreError as exc:
                raise OpError(FAILED, str(exc)) from None
        finally:
            self._identity_lock.release()
        logs.info(_t("[agente] Conectado desde esta máquina como «%(name)s» en %(url)s.") % {"name": saved.name, "url": saved.url})
        self._request_change(CONNECTED)
        return {"name": saved.name, "portal": status._safe_url(saved.url), "restarting": True}

    def op_disconnect(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        if not self._identity_lock.acquire(blocking=False):
            raise OpError(BUSY, _t("Ya se está cambiando la conexión de este agente."))
        try:
            _runtime, client, _config, _mode = self._current()
            told: bool | None = None
            detail = ""
            if client is not None:
                from agent.goodbye import REASON

                try:
                    client.goodbye(REASON)
                    told = True
                except PushError as exc:
                    told, detail = False, logs.scrub(str(exc))
            removed = store.remove(self.env())
        finally:
            self._identity_lock.release()
        logs.info(_t("[agente] Desconectado desde esta máquina."))
        self._request_change(DISCONNECTED)
        if told is False:
            message = _t(
                "No se pudo avisar al servidor (%(error)s). El enrolamiento de este equipo se borra igualmente; "
                "el agente seguirá apareciendo en Ajustes → Agentes hasta que se borre allí."
            ) % {"error": detail}
        elif told:
            message = _t("Se ha avisado al servidor: este agente queda dado de baja.")
        else:
            message = _t("Este agente no estaba conectado a ningún servidor.")
        return {"told_server": told, "removed": [item.name for item in removed], "message": message}

    def op_netbox_export(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        # El token sale de `args` ahora mismo: a partir de aquí solo vive en
        # esta variable, que no se registra, no se devuelve y muere al salir.
        token = args.pop("token", None)
        try:
            return self._netbox_export(token, args)
        except OpError as exc:
            # Última red: ningún mensaje de error sale con el token dentro,
            # lo traiga quien lo traiga (un servidor que lo repite, una URL).
            if isinstance(token, str) and token.strip():
                exc.message = redact(exc.message, [token, token.strip()])
            raise
        finally:
            token = None

    def _netbox_export(self, token: Any, args: dict[str, Any]) -> dict[str, Any]:
        url = args.get("url")
        verify_tls = args.get("verify_tls", True)
        send = args.get("send", False)
        target = args.get("path")
        if not isinstance(url, str) or not url.strip():
            raise OpError(INVALID, _t("Falta la URL de NetBox."))
        if not isinstance(token, str) or not token.strip() or len(token) > 1000:
            raise OpError(INVALID, _t("Falta el token de NetBox."))
        if not isinstance(verify_tls, bool) or not isinstance(send, bool):
            raise OpError(INVALID, _t("«verify_tls» y «send» tienen que ser verdadero o falso."))
        upload = None
        output: Path | None = None
        if send:
            runtime = self._need_runtime()
            upload = runtime.client.upload_netbox_bundle
        else:
            output = _output_path(target, netbox_export.DEFAULT_FILENAME)
        if not self._export_lock.acquire(blocking=False):
            raise OpError(BUSY, _t("Ya hay una exportación de NetBox en marcha."))
        total = len(netbox_export.ENDPOINTS)
        try:
            self._job("netbox_export", state="running", step="", done=0, total=total, started_at=self._clock().isoformat())
            done = [0]

            def progress(path: str) -> None:
                self._job("netbox_export", step=path, done=done[0], total=total)
                done[0] += 1

            try:
                bundle = netbox_export.fetch_bundle(url.strip(), token.strip(), verify_tls=verify_tls, progress=progress)
            except netbox_export.ExportError as exc:
                self._job("netbox_export", state="failed", finished_at=self._clock().isoformat())
                raise OpError(FAILED, str(exc)) from None
            except Exception as exc:  # noqa: BLE001 - sin el texto: podría llevar lo que se le pasó
                self._job("netbox_export", state="failed", finished_at=self._clock().isoformat())
                raise OpError(FAILED, _t("La exportación falló (%(type)s).") % {"type": type(exc).__name__}) from None
            finally:
                token = None  # noqa: F841 - olvidado en cuanto deja de hacer falta
            summary = {name: len(rows) for name, rows in bundle.items()}
            if upload is not None:
                try:
                    answer = upload(bundle, order_id=None)
                except PushError as exc:
                    self._job("netbox_export", state="failed", finished_at=self._clock().isoformat())
                    raise OpError(FAILED, logs.scrub(str(exc))) from None
                self._job("netbox_export", state="done", done=total, finished_at=self._clock().isoformat())
                answer = answer if isinstance(answer, dict) else {}
                _r, _c, config, _m = self._current()
                return {
                    "import": answer.get("import"),
                    "summary": summary,
                    "review_url": review_url(config.url if config is not None else "", answer),
                }
            assert output is not None
            try:
                _write_atomic(output, json.dumps(bundle, ensure_ascii=False).encode("utf-8"))
            except OSError as exc:
                self._job("netbox_export", state="failed", finished_at=self._clock().isoformat())
                raise OpError(FAILED, _t("No se pudo escribir %(path)s: %(error)s") % {"path": output, "error": exc.strerror or exc}) from None
            self._job("netbox_export", state="done", done=total, finished_at=self._clock().isoformat())
            return {"path": str(output), "summary": summary, "objects": sum(summary.values())}
        finally:
            self._export_lock.release()

    def secrets(self) -> list[str]:
        """Every secret this process knows about, to make sure none ends in a support bundle."""
        env = self.env()
        found: list[str] = []
        runtime, client, config, _mode = self._current()
        enrollment = store.load(env)
        for value in (enrollment.token if enrollment else "", getattr(client, "token", ""), config.token if config else ""):
            if isinstance(value, str) and value:
                found.append(value)
        for current in (local_settings.load_file(env), local_settings.load(env)):
            found += _url_password(current.proxy_url)
        found += _url_password(setting(env, "PROXY"))
        for name in ("AGENT_TOKEN", "CONNECTION"):
            if value := setting(env, name):
                found.append(value)
        if value := (env.get(netbox_export.TOKEN_ENV_VAR) or "").strip():
            found.append(value)
        # La clave privada del agente, línea a línea: si alguna vez acabó en un
        # registro sin sus marcas PEM, tampoco sale.
        try:
            key_text = (store.state_dir(env) / store.IDENTITY_FILE).read_text(encoding="utf-8")
        except (OSError, ValueError):
            key_text = ""
        found += [line.strip() for line in key_text.splitlines() if len(line.strip()) >= 16 and "-----" not in line]
        if config is not None:
            found += list(config.communities) + _credential_secrets(list(config.credentials))
        if runtime is not None:
            server_config, _etag = runtime.shared.config_snapshot()
            found += _credential_secrets(server_config.get("credentials"))
            found += _credential_secrets(server_config.get("communities"))
        return found

    def op_support_bundle(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        stamp = self._clock().strftime("%Y%m%d-%H%M%S")
        output = _output_path(args.get("path"), f"cenya-soporte-{stamp}.zip")
        secrets = self.secrets()
        admin = Caller(admin=True, who="support_bundle")
        parts: dict[str, Any] = {
            "version.json": {"version": __version__, "python": platform.python_version(), "platform": sys.platform},
            "about.json": self.op_about({}, admin),
            "settings.json": self.op_settings_get({}, admin),
            "status.json": self.op_status({}, admin),
        }
        base = logs.path(self.env())
        candidates = [base] + [base.with_name(f"{base.name}.{n}") for n in range(1, 5)]
        buffer_path = output.with_name(f".{output.name}.tmp")
        try:
            with zipfile.ZipFile(buffer_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                for name, value in parts.items():
                    text = json.dumps(value, ensure_ascii=False, indent=1, default=str)
                    bundle.writestr(name, redact(text, secrets))
                for log_file in candidates:
                    try:
                        text = log_file.read_bytes().decode("utf-8", errors="replace")
                    except OSError:
                        continue
                    bundle.writestr(f"logs/{log_file.name}", redact(text, secrets))
            os.replace(buffer_path, output)
        except OSError as exc:
            Path(buffer_path).unlink(missing_ok=True)
            raise OpError(FAILED, _t("No se pudo escribir %(path)s: %(error)s") % {"path": output, "error": exc.strerror or exc}) from None
        return {"path": str(output)}

    def op_check_update(self, args: dict[str, Any], caller: Caller) -> dict[str, Any]:
        """Pregunta de verdad: un checkin ahora y lo que trajo, con la espera acotada.

        El checkin es el mismo que el del hilo de control (no se cruzan: ver
        `Control.checkin_once`), y es él quien entrega a `Updater.offer` lo que
        ofrezca el servidor. Si no contesta en `CHECK_UPDATE_WAIT` segundos, se
        contesta con lo que se sabía y `pending`: el checkin sigue, y lo que
        traiga se verá en `status`.
        """
        runtime = self._need_runtime()
        checkin = self._checkin_now()
        _r, _c, _cfg, mode = self._current()
        outcome: dict[str, Any] = {}
        asked = checkin is not None and mode != "v1"
        if asked:
            done = threading.Event()

            def ask() -> None:
                try:
                    answered, status_code, detail = checkin()
                    outcome.update(answered=answered, status=status_code, error=detail)
                except Exception as exc:  # noqa: BLE001 - checkin_once no lanza; por si acaso
                    outcome.update(answered=False, status=None, error=type(exc).__name__)
                finally:
                    done.set()

            threading.Thread(target=ask, name="cenya-check-update", daemon=True).start()
            done.wait(self.check_update_wait)
        snapshot = runtime.snapshot()
        update = snapshot.get("update") or None
        offered = str(update.get("version") or "") if isinstance(update, dict) else ""
        last = snapshot.get("last_checkin") or {}
        answered = bool(outcome.get("answered"))
        return {
            "current": __version__,
            "offered": offered or None,
            "update": update,
            # Si este checkin contestó; `pending` si aún no ha vuelto.
            "checked": answered,
            "pending": asked and not outcome,
            "error": "" if answered or not outcome else logs.scrub(str(outcome.get("error") or "")),
            "checked_at": last.get("at"),
            "last_ok_at": snapshot.get("last_ok_at"),
            "updater": snapshot.get("updater"),
            "auto_update": local_settings.load(self.env()).auto_update,
        }


def review_url(portal: str, answer: Mapping[str, Any]) -> str:
    """Where a person reviews an uploaded NetBox reading (spec 3.4). Pure.

    El servidor puede decirlo (`review_url`, absoluta o una ruta); si lo dice,
    manda, siempre que sea del mismo portal: la ventana abre esto en el
    navegador, y una dirección de otro sitio no se abre. Si no lo dice, se
    construye con `NETBOX_REVIEW_PATH`, que es un supuesto.
    """
    base = urllib.parse.urlsplit(portal or "")
    if base.scheme not in ("http", "https") or not base.netloc:
        return ""
    root = f"{base.scheme}://{base.netloc}{base.path.rstrip('/')}"
    given = answer.get("review_url")
    if isinstance(given, str) and given.strip():
        given = given.strip()
        if given.startswith("/") and not given.startswith("//"):
            return f"{base.scheme}://{base.netloc}{given}"
        parts = urllib.parse.urlsplit(given)
        if parts.scheme in ("http", "https") and parts.netloc.lower() == base.netloc.lower():
            return given
    import_id = answer.get("import")
    if not isinstance(import_id, str) or not re.fullmatch(r"[0-9A-Za-z-]{1,64}", import_id):
        return ""
    return root + NETBOX_REVIEW_PATH.format(import_id=import_id)


def _output_path(raw: Any, default_name: str) -> Path:
    """Where to write what was asked for: an absolute path, or a folder that exists."""
    if not isinstance(raw, str) or not raw.strip():
        raise OpError(INVALID, _t("Falta «path»: la ruta completa donde dejar el fichero."))
    target = Path(raw.strip())
    if not target.is_absolute():
        raise OpError(INVALID, _t("«path» tiene que ser una ruta completa (absoluta)."))
    if target.is_dir():
        return target / default_name
    if not target.parent.is_dir():
        raise OpError(INVALID, _t("No existe la carpeta %(path)s.") % {"path": target.parent})
    return target


def _write_atomic(target: Path, data: bytes) -> None:
    fd, temporary = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.replace(temporary, target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


__all__ = ["LocalService", "SessionStop", "connection_test", "redact", "read_log", "validate_settings"]
