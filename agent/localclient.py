"""The console side of the local channel: ``cenya-agent status``, ``pause``, ``logs``...

Each command is a thin client: it connects to the service on this machine
(`agent.localpipe`), sends one request (spec 4) and prints the answer for a
person, in the session's language. The service does the work; the console
never reads the agent's files or its token, so these commands work from an
ordinary account for everything that only reads.

When the service is not running they say so plainly. Two of them still have
something useful to do on their own: ``connect`` falls back to ``enroll``
(redeeming the code from this console), and ``logs`` to reading the log file
directly if this account may.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable, Mapping
from datetime import datetime
from itertools import count
from typing import Any

from agent import __version__, localpipe, logs
from agent.i18n import _t, _tn
from agent.localapi import FORBIDDEN, MAX_RESPONSE_BYTES, LineBuffer, TooLong, encode

#: Los subcomandos que son clientes del canal.
COMMANDS = ("status", "run", "pause", "resume", "logs", "doctor", "connect", "disconnect")

OK = 0
FAILED = 1
USAGE = 2
NO_SERVICE = 3
NOT_ALLOWED = 4

#: Cuánto se espera la respuesta de cada operación: las largas contestan al terminar.
TIMEOUTS = {"probe": 900.0, "test_connection": 120.0, "connect": 120.0, "disconnect": 60.0, "netbox.export": 3600.0}
DEFAULT_TIMEOUT = 30.0


class ChannelError(Exception):
    """The service answered no. `code` is the spec's error code; `message` the service's sentence."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


class Channel:
    """One connection to the service, for one or several requests."""

    def __init__(
        self,
        *,
        environ: Mapping[str, str] | None = None,
        connect: Callable[..., Any] = localpipe.connect,
        timeout: float = 5.0,
    ) -> None:
        self._conn = connect(environ=environ, timeout=timeout)
        self._buffer = LineBuffer(MAX_RESPONSE_BYTES)
        self._lines: list[bytes] = []
        self._ids = count(1)

    def __enter__(self) -> Channel:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:  # noqa: BLE001
            pass

    def call(self, op: str, args: dict[str, Any] | None = None, *, timeout: float | None = None) -> Any:
        """Send one request and wait for its answer. Returns `data`; raises `ChannelError` on a refusal."""
        wait = TIMEOUTS.get(op, DEFAULT_TIMEOUT) if timeout is None else timeout
        request_id = next(self._ids)
        self._conn.send(encode({"id": request_id, "op": op, "args": args or {}}), wait)
        deadline = time.monotonic() + wait
        while True:
            line = self._next_line(deadline)
            try:
                answer = json.loads(line.decode("utf-8"))
            except ValueError:
                raise ChannelError("bad_answer", _t("El servicio contestó algo que no se entiende.")) from None
            if not isinstance(answer, dict):
                continue
            if answer.get("id") not in (request_id, None):
                continue  # una respuesta atrasada de otra petición
            if answer.get("ok"):
                return answer.get("data")
            raise ChannelError(str(answer.get("error") or ""), str(answer.get("message") or ""), answer.get("details"))

    def _next_line(self, deadline: float) -> bytes:
        while not self._lines:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            try:
                data = self._conn.recv(min(remaining, 1.0))
            except TimeoutError:
                continue
            if not data:
                raise ConnectionError(_t("El servicio cerró la conexión."))
            for line in self._buffer.feed(data):
                if isinstance(line, TooLong):
                    raise ChannelError("too_large", _t("La respuesta del servicio es demasiado grande."))
                self._lines.append(line)
        return self._lines.pop(0)


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


def no_service_line(error: localpipe.Unavailable) -> str:
    if error.reason == "no_pywin32":
        return _t("Esta instalación no puede hablar con el servicio: falta pywin32.")
    if error.reason == "untrusted":
        return _t(
            "El canal del agente lo ha abierto otro programa, no el servicio de Cenya: no se le envía nada. "
            "Reinicia el servicio y avisa a quien administre este equipo."
        )
    if error.reason == "denied":
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


def _usage() -> str:
    return _t(
        "Uso: cenya-agent status | run <tarea> | pause [--hours N] | resume | logs [-n N] [-f] | "
        "doctor | connect <cadena> | disconnect"
    )


class _Console:
    def __init__(self, out: Callable[[str], None], err: Callable[[str], None]) -> None:
        self.out, self.err = out, err


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
    except localpipe.Unavailable as exc:
        console.err(no_service_line(exc))
        return NO_SERVICE
    except ChannelError as exc:
        if exc.code == FORBIDDEN:
            console.err(forbidden_line())
            return NOT_ALLOWED
        console.err(exc.message or exc.code)
        for field, problem in (exc.details.get("fields") or {}).items():
            console.err(f"  {field}: {problem}")
        return FAILED
    except TimeoutError:
        console.err(_t("El servicio no ha contestado a tiempo."))
        return FAILED
    except (ConnectionError, OSError):
        console.err(_t("Se ha perdido la conexión con el servicio."))
        return FAILED


def _one(op: str, args: dict[str, Any], environ: Mapping[str, str] | None, connect: Callable[..., Any]) -> Any:
    with Channel(environ=environ, connect=connect) as channel:
        return channel.call(op, args)


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
    try:
        channel = Channel(environ=environ, connect=connect)
    except localpipe.Unavailable as exc:
        console.err(no_service_line(exc))
        return _logs_from_file(lines, console, environ)
    with channel:
        data = channel.call("log", {"lines": lines})
        for line in data.get("lines") or []:
            console.out(line)
        if not follow:
            return OK
        cursor = data.get("cursor")
        try:
            while True:
                time.sleep(1.0)
                data = channel.call("log", {"lines": 2000, "after": cursor})
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
    except localpipe.Unavailable as exc:
        console.err(no_service_line(exc))
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
    import os
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
    except localpipe.Unavailable as exc:
        if exc.reason == "untrusted":
            raise
        console.err(no_service_line(exc))
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
    except localpipe.Unavailable as exc:
        console.err(no_service_line(exc))
        console.err(_t("Para borrar el enrolamiento sin el servicio: cenya-agent goodbye"))
        return NO_SERVICE
    console.out(str(data.get("message") or ""))
    return OK
