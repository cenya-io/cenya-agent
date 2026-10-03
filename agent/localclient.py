"""The client side of the local channel (spec 4), and the console commands built on it.

Everything on this machine that talks to the service goes through
`ChannelClient`: the desktop application (`agent.app`), the tray icon
(`agent.tray`) and ``cenya-agent status``, ``pause``, ``logs``... There is no
second client. The bytes travel over `agent.localpipe` (the pipe opened with
``GENERIC_READ | FILE_WRITE_DATA``, at identification level, after checking
who owns it; or the Unix socket) and are cut into lines by
`agent.localapi.LineBuffer`, the same code the service uses.

What the client promises:

* **Every failure is a `ChannelError` with a stable ``code``**: whoever shows
  it decides what to say from the code, never from a message.
  ``service_down`` (nothing listens: the service is not running),
  ``access_denied``, ``untrusted`` (someone else holds the pipe's name and is
  told nothing), ``no_pywin32``, ``busy``, ``timeout``, ``broken``,
  ``bad_response``, or whatever code the service sent (``forbidden`` above all).
* **Every wait has a deadline**, per operation (`OP_TIMEOUTS`): the long ones
  answer when they finish (spec 4) and their progress is read with ``status``.
* **Connections are reused** and several requests can be in flight at once,
  each on its own connection: a NetBox export that takes minutes does not
  freeze the window's status polling.
* **A read is retried once** on a fresh connection when a pooled one turns out
  to be dead. **An action never is** once it may have been delivered: running a
  task twice is worse than saying it failed.
* **Nothing here logs.** The arguments of a request may carry a secret (the
  NetBox token): they go down the channel and nowhere else.

The console commands are thin: one request, an answer printed for a person
in the session's language. The service does the work; the console never reads
the agent's files or its token, so these commands work from an ordinary
account for everything that only reads. When the service is not running they
say so plainly; ``connect`` then falls back to ``enroll`` and ``logs`` to
reading the log file, if this account may.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from agent import __version__, localpipe, logs
from agent.i18n import _t, _tn
from agent.localapi import (
    FORBIDDEN,
    INVALID,
    MAX_RESPONSE_BYTES,
    NOT_ENROLLED,
    OPERATIONS,
    READ,
    LineBuffer,
    TooLong,
    encode,
)

# --- Dónde está el servicio ---------------------------------------------------------

PIPE_PREFIX = localpipe.PIPE_PREFIX
DEFAULT_PIPE = localpipe.DEFAULT_PIPE_NAME
#: Las mismas variables que lee el servicio (`agent.localpipe`): el nombre del
#: pipe (con o sin prefijo) en Windows, la ruta del socket fuera. Desarrollo y
#: pruebas apuntan aquí el servidor falso (`agent.app.fake_server`).
ADDRESS_ENV_VAR = localpipe.PIPE_ENV_VAR
SOCKET_ENV_VAR = localpipe.SOCKET_ENV_VAR
#: Lo que se pide al abrir el pipe (lo decide `agent.localpipe`, aquí solo se nombra).
CLIENT_ACCESS = localpipe.CLIENT_ACCESS

# --- Los códigos que pone el cliente (los del servicio llegan tal cual) ---------------

SERVICE_DOWN = "service_down"
BUSY = "busy"
TIMEOUT = "timeout"
BROKEN = "broken"
BAD_RESPONSE = "bad_response"
ACCESS_DENIED = "access_denied"
#: Alguien que no es el servicio tiene el nombre del pipe: no se le dice nada.
UNTRUSTED = "untrusted"
NO_PYWIN32 = "no_pywin32"
# FORBIDDEN, INVALID y NOT_ENROLLED (los del servicio) se importan de
# `agent.localapi` arriba: quien solo usa este módulo los tiene aquí también.

#: Por qué no se pudo abrir el canal (`localpipe.Unavailable.reason`) -> código.
_UNAVAILABLE = {
    "not_running": SERVICE_DOWN,
    "unsupported": SERVICE_DOWN,
    "denied": ACCESS_DENIED,
    "untrusted": UNTRUSTED,
    "busy": BUSY,
    "no_pywin32": NO_PYWIN32,
}
#: Los códigos que quieren decir «no hay con quién hablar»: ni llegó la petición.
NO_SERVICE_CODES = frozenset({SERVICE_DOWN, ACCESS_DENIED, UNTRUSTED, NO_PYWIN32})

#: Las operaciones que solo leen: se pueden repetir sin efecto.
READ_OPS = frozenset(op for op, kind in OPERATIONS.items() if kind == READ)

#: Cuánto puede tardar cada una en contestar. Las largas contestan al terminar
#: (spec 4): un sondeo prueba cada protocolo con cada credencial, una
#: exportación de NetBox lee miles de objetos.
OP_TIMEOUTS: dict[str, float] = {
    "status": 4.0,
    "log": 6.0,
    "about": 15.0,
    "settings.get": 6.0,
    "settings.set": 15.0,
    "run": 15.0,
    "pause": 10.0,
    "resume": 10.0,
    "probe": 900.0,
    "test_connection": 120.0,
    "connect": 120.0,
    "disconnect": 60.0,
    "netbox.export": 3600.0,
    "support_bundle": 300.0,
    # El servicio espera su checkin como mucho `localops.CHECK_UPDATE_WAIT`.
    "check_update": 60.0,
}
DEFAULT_TIMEOUT = 15.0
CONNECT_TIMEOUT = 2.0
#: Conexiones libres que se guardan. Pocas: el servicio admite cuatro por
#: usuario (`localapi.Admission`), y la ventana y el icono son el mismo usuario.
POOL_SIZE = 2


class ChannelError(Exception):
    """What went wrong, with a stable code and, if there is one, the service's sentence."""

    def __init__(self, code: str, message: str = "", details: dict[str, Any] | None = None) -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message
        #: Lo que el servicio añade a un error (``fields`` en `settings.set`).
        self.details = details or {}


def default_address(environ: Mapping[str, str] | None = None) -> str:
    """El canal al que hablar: el de la variable o el del servicio de verdad."""
    if sys.platform == "win32":
        return localpipe.pipe_name(environ)
    return str(localpipe.socket_path(environ))


def address_overridden(environ: Mapping[str, str] | None = None) -> bool:
    """Si alguien ha apuntado el canal a otro sitio (desarrollo, pruebas)."""
    env = os.environ if environ is None else environ
    variable = ADDRESS_ENV_VAR if sys.platform == "win32" else SOCKET_ENV_VAR
    return bool((env.get(variable) or "").strip())


def is_default_address(address: str) -> bool:
    """Si es el canal del servicio de verdad (y no uno de desarrollo)."""
    return address.lower() == DEFAULT_PIPE.lower()


def trusted_pipe_owner(owner_sid: str, own_sid: str, *, allow_own: bool = True) -> bool:
    """Si se le habla a un pipe de ese dueño (la regla es la de `agent.localpipe`)."""
    return localpipe.trusted_pipe_owner(owner_sid, own_sid, allow_own=allow_own)


def random_pipe_name(prefix: str = "CenyaAgentDev") -> str:
    """Un nombre de canal que no es el del servicio, para desarrollo y pruebas."""
    token = os.urandom(6).hex()
    if sys.platform == "win32":
        return rf"{PIPE_PREFIX}{prefix}-{token}"
    import tempfile

    return str(Path(tempfile.gettempdir()) / f"{prefix.lower()}-{token}.sock")


def open_connection(address: str, timeout: float = CONNECT_TIMEOUT) -> Any:
    """A connection to `address` over this platform's transport. Raises `ChannelError`."""
    try:
        if address.startswith("\\\\"):
            if sys.platform != "win32":
                raise ChannelError(SERVICE_DOWN)
            return localpipe.connect_pipe(address, timeout)
        return localpipe.connect_socket(Path(address), timeout)
    except localpipe.Unavailable as exc:
        raise ChannelError(_UNAVAILABLE.get(exc.reason, SERVICE_DOWN)) from None


class _Wire:
    """Una conexión del transporte y lo que ya llegó de ella sin leer."""

    def __init__(self, conn: Any) -> None:
        self.conn = conn
        self.buffer = LineBuffer(MAX_RESPONSE_BYTES)
        self.lines: list[bytes] = []

    def read_line(self, deadline: float) -> bytes:
        while not self.lines:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ChannelError(TIMEOUT)
            try:
                # A sorbos: el transporte devuelve lo que haya o `TimeoutError`.
                data = self.conn.recv(min(remaining, 1.0))
            except TimeoutError:
                continue
            except ChannelError:
                raise
            except OSError as exc:
                raise ChannelError(BROKEN, type(exc).__name__) from None
            if not data:
                raise ChannelError(BROKEN, "closed")
            for line in self.buffer.feed(data):
                if isinstance(line, TooLong):
                    raise ChannelError(BAD_RESPONSE, "too_large")
                self.lines.append(line)
        return self.lines.pop(0)

    def send(self, data: bytes, timeout: float) -> None:
        try:
            self.conn.send(data, timeout)
        except TimeoutError:
            raise ChannelError(TIMEOUT) from None
        except ChannelError:
            raise
        except OSError as exc:
            raise ChannelError(BROKEN, type(exc).__name__) from None

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:  # noqa: BLE001
            pass


class _Refused(Exception):
    """Una respuesta `ok: false` bien formada: el servicio dice que no (la conexión sigue buena)."""

    def __init__(self, code: str, message: str, details: dict[str, Any]) -> None:
        super().__init__(code)
        self.code, self.message, self.details = code, message, details


class ChannelClient:
    """Requests to the service. Thread-safe: each request in flight has its own connection.

    `opener(address, timeout)` gives a transport connection (``send``,
    ``recv``, ``close``, as in `agent.localpipe`); the default opens the real
    one. Tests and the console pass their own.
    """

    def __init__(
        self,
        address: str | None = None,
        *,
        environ: Mapping[str, str] | None = None,
        connect_timeout: float = CONNECT_TIMEOUT,
        opener: Callable[[str, float], Any] | None = None,
    ) -> None:
        self.address = address or default_address(environ)
        self.connect_timeout = connect_timeout
        self._open = opener or open_connection
        self._lock = threading.Lock()
        self._idle: list[_Wire] = []
        self._next_id = 0

    def __enter__(self) -> ChannelClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _new_id(self) -> int:
        with self._lock:
            self._next_id += 1
            return self._next_id

    def _take(self) -> tuple[_Wire, bool]:
        with self._lock:
            if self._idle:
                return self._idle.pop(), True
        try:
            return _Wire(self._open(self.address, self.connect_timeout)), False
        except localpipe.Unavailable as exc:  # un `opener` que no traduce
            raise ChannelError(_UNAVAILABLE.get(exc.reason, SERVICE_DOWN)) from None

    def _give_back(self, wire: _Wire) -> None:
        with self._lock:
            if len(self._idle) < POOL_SIZE:
                self._idle.append(wire)
                return
        wire.close()

    def close(self) -> None:
        with self._lock:
            idle, self._idle = self._idle, []
        for wire in idle:
            wire.close()

    def connect_now(self) -> None:
        """Open a connection now (and keep it), to know at once whether there is a service."""
        wire, _ = self._take()
        self._give_back(wire)

    def call(self, op: str, args: Mapping[str, Any] | None = None, *, timeout: float | None = None) -> Any:
        """The service's `data` for this request, as it came. Raises `ChannelError`."""
        wait = timeout if timeout is not None else OP_TIMEOUTS.get(op, DEFAULT_TIMEOUT)
        message_id = self._new_id()
        line = encode({"id": message_id, "op": op, "args": dict(args or {})})
        attempts = 2
        for attempt in range(attempts):
            wire, reused = self._take()
            delivered = False
            try:
                wire.send(line, wait)
                delivered = True
                data = self._read_reply(wire, message_id, time.monotonic() + wait)
            except _Refused as refused:
                self._give_back(wire)
                raise ChannelError(refused.code, refused.message, refused.details) from None
            except ChannelError as exc:
                wire.close()
                # Una conexión guardada que resultó estar muerta: si no llegó
                # nada, o si solo se leía, se repite una vez con una nueva.
                retry = reused and exc.code == BROKEN and (not delivered or op in READ_OPS)
                if retry and attempt + 1 < attempts:
                    continue
                raise
            self._give_back(wire)
            return data
        raise ChannelError(BROKEN)  # pragma: no cover - el bucle siempre vuelve o lanza

    def request(self, op: str, args: Mapping[str, Any] | None = None, timeout: float | None = None) -> dict[str, Any]:
        """Like `call`, with the answer always a dict (what the window's views read)."""
        data = self.call(op, args, timeout=timeout)
        return data if isinstance(data, dict) else {"value": data} if data is not None else {}

    @staticmethod
    def _read_reply(wire: _Wire, message_id: int, deadline: float) -> Any:
        while True:
            raw = wire.read_line(deadline)
            try:
                reply = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise ChannelError(BAD_RESPONSE) from None
            if not isinstance(reply, dict):
                raise ChannelError(BAD_RESPONSE)
            if reply.get("id") is None and reply.get("ok") is False:
                # Sin `id`: el servicio contesta a la conexión, no a la
                # petición (demasiadas conexiones, una línea que no entendió).
                raise ChannelError(str(reply.get("error") or BAD_RESPONSE), str(reply.get("message") or ""))
            if reply.get("id") != message_id:
                continue  # la respuesta tardía de otra petición: no es esta
            if reply.get("ok") is True:
                return reply.get("data")
            details = reply.get("details") if isinstance(reply.get("details"), dict) else {}
            raise _Refused(str(reply.get("error") or BAD_RESPONSE), str(reply.get("message") or ""), details)


class Channel(ChannelClient):
    """One client that connects at once: for a script, or a test, that wants to know now.

    Raises `ChannelError` (``service_down``...) on construction if there is no
    service to talk to.
    """

    def __init__(self, *, environ: Mapping[str, str] | None = None, timeout: float = 5.0, **kwargs: Any) -> None:
        super().__init__(environ=environ, connect_timeout=timeout, **kwargs)
        self.connect_now()


# --- Frases -----------------------------------------------------------------------


def _clock(value: Any) -> str:
    """Una fecha ISO como hora local corta, o "" si no se entiende."""
    if not isinstance(value, str) or not value:
        return ""
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return ""
    local = moment.astimezone()
    today = datetime.now().astimezone().date()
    return local.strftime("%H:%M") if local.date() == today else local.strftime("%d/%m %H:%M")


def no_service_line(code: str) -> str:
    """What to tell a person when there is nobody to talk to, from the client's code."""
    if code == NO_PYWIN32:
        return _t("Esta instalación no puede hablar con el servicio: falta pywin32.")
    if code == UNTRUSTED:
        return _t(
            "El canal del agente lo ha abierto otro programa, no el servicio de Cenya: no se le envía nada. "
            "Reinicia el servicio y avisa a quien administre este equipo."
        )
    if code == ACCESS_DENIED:
        return _t("Esta cuenta no tiene permiso para hablar con el servicio del agente.")
    return _t("El servicio del agente no está en marcha en este equipo.")


def forbidden_line() -> str:
    if sys.platform == "win32":
        return _t("Esto solo lo puede hacer un administrador: abre la consola con «Ejecutar como administrador».")
    return _t("Esto solo lo puede hacer root o la cuenta con la que corre el agente.")


def status_lines(data: dict[str, Any]) -> list[str]:
    """Lo que `status` cuenta, para una persona."""
    lines = [_t("Cenya Agent %(version)s") % {"version": data.get("version") or __version__}]
    if not data.get("enrolled"):
        enrollment = data.get("enrollment") if isinstance(data.get("enrollment"), dict) else {}
        if enrollment.get("message"):
            lines.append(str(enrollment["message"]))
        lines.append(_t("No está conectado a ningún portal: cenya-agent connect <cadena>"))
        return lines
    protocol = {"v2": "2", "v1": "1"}.get(str(data.get("protocol") or ""), "?")
    lines.append(
        _t("Conectado como «%(name)s» a %(portal)s (protocolo %(protocol)s).")
        % {"name": data.get("name") or "?", "portal": data.get("portal") or "?", "protocol": protocol}
    )
    connection = data.get("connection") or {}
    state = connection.get("state")
    if state == "ok":
        lines.append(_t("Conexión: correcta (último contacto a las %(clock)s).") % {"clock": _clock(connection.get("at"))})
    elif state == "error":
        lines.append(_t("Conexión: falla (%(error)s).") % {"error": logs.scrub(str(connection.get("error") or ""))})
    elif state == "refused":
        lines.append(_t("Conexión: el servidor ha rechazado a este agente; hay que conectarlo de nuevo."))
    elif state == "read_only":
        lines.append(_t("Conexión: la instalación de Cenya está en solo lectura."))
    else:
        lines.append(_t("Conexión: todavía sin noticias del servidor."))
    activity = data.get("activity") or {}
    pause = data.get("pause") or {}
    if activity:
        progress = ""
        if activity.get("total"):
            progress = f" ({activity.get('step') or ''} {activity.get('done')}/{activity.get('total')})"
        elif activity.get("step"):
            progress = f" ({activity.get('step')})"
        lines.append(_t("Ahora: trabajando en %(task)s%(progress)s.") % {"task": activity.get("task"), "progress": progress})
    elif pause.get("indefinite"):
        lines.append(_t("Ahora: en pausa hasta que se reanude (cenya-agent resume)."))
    elif pause.get("until"):
        lines.append(_t("Ahora: en pausa hasta las %(clock)s.") % {"clock": _clock(pause.get("until"))})
    else:
        lines.append(_t("Ahora: esperando a la siguiente tarea."))
    schedule = [row for row in data.get("schedule") or [] if row.get("every_seconds")]
    if schedule:
        lines.append(_t("Tareas:"))
        for row in schedule:
            lines.append(
                "  "
                + _t("%(task)s: cada %(every)s, última %(last)s (%(status)s), próxima %(next)s")
                % {
                    "task": row.get("task"),
                    "every": _every(int(row.get("every_seconds") or 0)),
                    "last": _clock(row.get("last_finished_at")) or "-",
                    "status": row.get("last_status") or "-",
                    "next": _clock(row.get("next_at")) or "-",
                }
            )
    pending = int(data.get("outbox") or 0)
    if pending:
        lines.append(_tn("%(n)d envío pendiente en la cola local.", "%(n)d envíos pendientes en la cola local.", pending) % {"n": pending})
    update = data.get("update") or {}
    if isinstance(update, dict) and update.get("version"):
        lines.append(_t("Hay una versión nueva del agente: %(version)s.") % {"version": update["version"]})
    export = (data.get("local") or {}).get("netbox_export") or {}
    if export.get("state") == "running":
        lines.append(
            _t("Exportando NetBox: %(step)s (%(done)s de %(total)s).")
            % {"step": export.get("step") or "", "done": export.get("done"), "total": export.get("total")}
        )
    return lines


def _every(seconds: int) -> str:
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return _tn("%(n)d hora", "%(n)d horas", hours) % {"n": hours}
    if seconds % 60 == 0:
        minutes = seconds // 60
        return _tn("%(n)d minuto", "%(n)d minutos", minutes) % {"n": minutes}
    return _tn("%(n)d segundo", "%(n)d segundos", seconds) % {"n": seconds}


def step_lines(steps: list[dict[str, Any]]) -> list[str]:
    marks = {True: _t("[bien]"), False: _t("[falla]")}
    return [f"{marks[bool(step.get('ok'))]} {step.get('step')}: {step.get('message')}" for step in steps]


# --- Los comandos -------------------------------------------------------------------

#: Los subcomandos que son clientes del canal.
COMMANDS = ("status", "run", "pause", "resume", "logs", "doctor", "connect", "disconnect")

OK = 0
FAILED = 1
USAGE = 2
NO_SERVICE = 3
NOT_ALLOWED = 4


def _usage() -> str:
    return _t(
        "Uso: cenya-agent status | run <tarea> | pause [--hours N] | resume | logs [-n N] [-f] | "
        "doctor | connect <cadena> | disconnect"
    )


class _Console:
    def __init__(self, out: Callable[[str], None], err: Callable[[str], None]) -> None:
        self.out, self.err = out, err


def _client(environ: Mapping[str, str] | None, connect: Callable[..., Any]) -> ChannelClient:
    """Un cliente para un comando: `connect(environ=, timeout=)` da la conexión (la de verdad o la de una prueba)."""
    return ChannelClient(
        default_address(environ),
        connect_timeout=5.0,
        opener=lambda _address, timeout: connect(environ=environ, timeout=timeout),
    )


def run(
    args: list[str],
    *,
    environ: Mapping[str, str] | None = None,
    connect: Callable[..., Any] = localpipe.connect,
    out: Callable[[str], None] | None = None,
    err: Callable[[str], None] | None = None,
) -> int:
    """One console command. Returns the exit code."""
    console = _Console(out or (lambda text: print(text, flush=True)), err or (lambda text: print(text, file=sys.stderr, flush=True)))
    if not args or args[0] not in COMMANDS:
        console.err(_usage())
        return USAGE
    command, rest = args[0], args[1:]
    handler = {
        "status": _status,
        "run": _run_task,
        "pause": _pause,
        "resume": _resume,
        "logs": _logs,
        "doctor": _doctor,
        "connect": _connect,
        "disconnect": _disconnect,
    }[command]
    try:
        return handler(rest, console, environ, connect)
    except ChannelError as exc:
        if exc.code in NO_SERVICE_CODES:
            console.err(no_service_line(exc.code))
            return NO_SERVICE
        if exc.code == FORBIDDEN:
            console.err(forbidden_line())
            return NOT_ALLOWED
        if exc.code == TIMEOUT:
            console.err(_t("El servicio no ha contestado a tiempo."))
            return FAILED
        if exc.code in (BROKEN, BAD_RESPONSE):
            console.err(_t("Se ha perdido la conexión con el servicio."))
            return FAILED
        console.err(exc.message or exc.code)
        for field, problem in (exc.details.get("fields") or {}).items():
            console.err(f"  {field}: {problem}")
        return FAILED


def _one(op: str, args: dict[str, Any], environ: Mapping[str, str] | None, connect: Callable[..., Any]) -> Any:
    with _client(environ, connect) as client:
        return client.call(op, args)


def _status(rest: list[str], console: _Console, environ: Any, connect: Any) -> int:
    if rest:
        console.err(_usage())
        return USAGE
    for line in status_lines(_one("status", {}, environ, connect)):
        console.out(line)
    return OK


def _run_task(rest: list[str], console: _Console, environ: Any, connect: Any) -> int:
    if len(rest) != 1:
        console.err(_usage())
        return USAGE
    data = _one("run", {"task": rest[0]}, environ, connect)
    console.out(_t("Tarea %(task)s en cola: empieza en cuanto termine la que está en curso.") % {"task": data.get("queued")})
    if data.get("waiting_for") == "config":
        console.out(_t("Antes tiene que llegar la configuración del servidor."))
    elif data.get("waiting_for") == "read_only":
        console.out(_t("La instalación de Cenya está en solo lectura: la tarea espera a que vuelva a aceptar resultados."))
    return OK


def _pause(rest: list[str], console: _Console, environ: Any, connect: Any) -> int:
    hours = 1.0
    if rest:
        if len(rest) != 2 or rest[0] != "--hours":
            console.err(_usage())
            return USAGE
        try:
            hours = float(rest[1].replace(",", "."))
        except ValueError:
            console.err(_usage())
            return USAGE
        if hours <= 0:
            console.err(_usage())
            return USAGE
    data = _one("pause", {"seconds": int(hours * 3600)}, environ, connect)
    console.out(_t("Agente en pausa hasta las %(clock)s. La tarea en curso, si hay una, termina.") % {"clock": _clock(data.get("paused_until"))})
    return OK


def _resume(rest: list[str], console: _Console, environ: Any, connect: Any) -> int:
    if rest:
        console.err(_usage())
        return USAGE
    data = _one("resume", {}, environ, connect)
    console.out(_t("Pausa local levantada."))
    if data.get("server_paused_until"):
        console.out(
            _t("Sigue en pausa hasta las %(clock)s: esa pausa se puso desde la web y se quita allí.")
            % {"clock": _clock(data["server_paused_until"])}
        )
    return OK


def _logs(rest: list[str], console: _Console, environ: Any, connect: Any) -> int:
    lines, follow = 50, False
    items = iter(rest)
    for item in items:
        if item == "-f":
            follow = True
        elif item == "-n":
            try:
                lines = int(next(items, ""))
            except ValueError:
                console.err(_usage())
                return USAGE
            if lines < 1:
                console.err(_usage())
                return USAGE
        else:
            console.err(_usage())
            return USAGE
    with _client(environ, connect) as client:
        try:
            data = client.call("log", {"lines": lines})
        except ChannelError as exc:
            if exc.code not in NO_SERVICE_CODES:
                raise
            console.err(no_service_line(exc.code))
            return _logs_from_file(lines, console, environ)
        for line in data.get("lines") or []:
            console.out(line)
        if not follow:
            return OK
        cursor = data.get("cursor")
        try:
            while True:
                time.sleep(1.0)
                data = client.call("log", {"lines": 2000, "after": cursor})
                for line in data.get("lines") or []:
                    console.out(line)
                cursor = data.get("cursor") or cursor
        except KeyboardInterrupt:
            return OK


def _logs_from_file(lines: int, console: _Console, environ: Any) -> int:
    from agent.localops import read_log

    path = logs.path(environ)
    data = read_log(path, lines)
    if data.get("missing"):
        console.err(_t("Tampoco se puede leer el registro (%(path)s) desde esta cuenta.") % {"path": path})
        return NO_SERVICE
    console.err(_t("Registro leído directamente de %(path)s:") % {"path": path})
    for line in data.get("lines") or []:
        console.out(line)
    return OK


def _doctor(rest: list[str], console: _Console, environ: Any, connect: Any) -> int:
    if rest:
        console.err(_usage())
        return USAGE
    from agent import selftest

    try:
        result = _one("test_connection", {}, environ, connect)
        steps = result.get("steps") or []
        connection_ok = bool(result.get("ok"))
    except ChannelError as exc:
        if exc.code not in NO_SERVICE_CODES:
            raise
        console.err(no_service_line(exc.code))
        console.err(_t("Se prueba la conexión desde esta consola, sin el servicio."))
        steps, connection_ok = _local_connection_test(console, environ)
    console.out(_t("Conexión con el portal:"))
    for line in step_lines(steps):
        console.out("  " + line)
    report = selftest.report()
    complete = selftest.complete(report)
    console.out(_t("Esta instalación:"))
    console.out("  " + (_t("[bien]") if complete else _t("[falla]")) + " " + (
        _t("completa (colectores, librerías y traducciones).") if complete else _t("incompleta: detalle con cenya-agent selftest.")
    ))
    return OK if connection_ok and complete else FAILED


def _local_connection_test(console: _Console, environ: Any) -> tuple[list[dict[str, Any]], bool]:
    """Sin servicio: la misma prueba, con el enrolamiento que esta cuenta pueda leer."""
    import socket as _socket

    from agent import settings as local_settings
    from agent.client import PROTOCOL, AgentClient, PushError
    from agent.config import from_env
    from agent.localops import connection_test

    env = os.environ if environ is None else environ
    try:
        config = from_env(dict(env))
    except SystemExit as exc:
        console.err(str(exc.code))
        return [], False
    local = local_settings.load(env)
    client = AgentClient(config.url, config.token, ca_bundle=config.ca_bundle or local.ca_bundle, proxy=local.proxy)

    def checkin() -> tuple[bool, int | None, str]:
        try:
            client.checkin({"protocol": PROTOCOL, "agent_version": __version__, "state": "idle", "hostname": _socket.gethostname()})
        except PushError as exc:
            return False, exc.status, str(exc)
        return True, None, ""

    steps = connection_test(config.url, ca_bundle=config.ca_bundle or local.ca_bundle, proxy=local.proxy, checkin=checkin)
    return steps, all(step["ok"] for step in steps)


def _connect(rest: list[str], console: _Console, environ: Any, connect: Any) -> int:
    positional = [item for item in rest if not item.startswith("--")]
    if len(positional) != 1:
        console.err(_t("Falta la cadena de conexión: cenya-agent connect cenya://portal.midominio.com/XXXX-XXXX-XXXX"))
        return USAGE
    try:
        data = _one("connect", {"connection": positional[0]}, environ, connect)
    except ChannelError as exc:
        # Sin servicio con quien hablar se enrola desde aquí. Nunca si el
        # canal lo tiene otro programa: eso se dice, no se esquiva.
        if exc.code not in NO_SERVICE_CODES or exc.code == UNTRUSTED:
            raise
        console.err(no_service_line(exc.code))
        console.err(_t("Se enrola desde esta consola; después arranca el servicio."))
        from agent import enroll

        return enroll.run(rest, environ)
    console.out(_t("Conectado como «%(name)s» a %(portal)s. El agente se reinicia con la conexión nueva.") % data)
    return OK


def _disconnect(rest: list[str], console: _Console, environ: Any, connect: Any) -> int:
    if rest:
        console.err(_usage())
        return USAGE
    try:
        data = _one("disconnect", {}, environ, connect)
    except ChannelError as exc:
        if exc.code not in NO_SERVICE_CODES:
            raise
        console.err(no_service_line(exc.code))
        console.err(_t("Para borrar el enrolamiento sin el servicio: cenya-agent goodbye"))
        return NO_SERVICE
    console.out(str(data.get("message") or ""))
    return OK
