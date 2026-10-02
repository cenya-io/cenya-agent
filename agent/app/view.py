"""What the window shows, decided in Python: from the service's answers to view models.

Every function here is pure -- data and ``now`` in, a dictionary of texts,
tones and flags out -- so every case is tested without a window, a pipe or
Windows, the same way `agent.status` decides what the tray says. The page
(``ui/app.js``) only lays these out: it never decides a label, a tone, whether
a button is enabled or why not.

Tones are the design system's: ``success``, ``warning``, ``danger``, ``info``,
``accent`` and ``neutral`` (grey is "I don't know", never "off").

The shapes read here are the ones listed in `agent.app.fake_server`; anything
missing or of the wrong type is treated as unknown, never as a crash: the real
service is written in parallel and a field it does not send yet must cost a
dash on the screen, not the screen.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any

from agent import localclient as channel
from agent.i18n import _t, _tn
from agent.status import _ago

SUCCESS, WARNING, DANGER, INFO, ACCENT, NEUTRAL = "success", "warning", "danger", "info", "accent", "neutral"

TASK_ORDER = ("presence", "inventory", "configs", "ups", "hypervisors")
NETBOX_TASK = "netbox_export"
#: La pausa más larga que acepta el servicio (`agent/localops.py::MAX_PAUSE`).
#: «Hasta que se reanude» es eso, y la etiqueta lo dice: una pausa olvidada no
#: puede dejar un agente parado para siempre.
MAX_PAUSE = timedelta(days=30)
#: A partir de cuánto una pausa se lee como «hasta que se reanude».
INDEFINITE_AFTER = timedelta(days=7)
#: «Hasta mañana» es hasta mañana a esta hora (la de quien mira).
TOMORROW_HOUR = 8

LANGUAGES = (("es", "Español"), ("en", "English"), ("de", "Deutsch"), ("fr", "Français"), ("pt_BR", "Português (Brasil)"))
GENTLENESS_CAPS = ("", "gentle", "normal")


# --- Pequeñas piezas -------------------------------------------------------------


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _local(moment: datetime) -> datetime:
    try:
        return moment.astimezone()
    except (OverflowError, ValueError, OSError):
        return moment


def clock(moment: datetime) -> str:
    return _local(moment).strftime("%H:%M")


def full_time(moment: datetime) -> str:
    """Fecha y hora completas, para el texto emergente de una celda."""
    return _local(moment).strftime("%d/%m/%Y %H:%M:%S")


def ago(value: Any, now: datetime) -> str:
    moment = parse_time(value)
    return _ago(moment, now) if moment else ""


def upcoming(moment: datetime, now: datetime) -> str:
    """Cuándo va a pasar algo: «hoy, 14:35», «mañana, 08:00» o la fecha."""
    local, today = _local(moment), _local(now)
    if moment <= now:
        return _t("ahora")
    if local.date() == today.date():
        return _t("hoy, %(clock)s") % {"clock": local.strftime("%H:%M")}
    if local.date() == (today + timedelta(days=1)).date():
        return _t("mañana, %(clock)s") % {"clock": local.strftime("%H:%M")}
    return local.strftime("%d/%m %H:%M")


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    return None


def task_label(task: str) -> str:
    labels = {
        "presence": _t("Presencia"),
        "inventory": _t("Inventario"),
        "configs": _t("Copias de configuración"),
        "ups": _t("SAI"),
        "hypervisors": _t("Hipervisores"),
        NETBOX_TASK: _t("Lectura de NetBox"),
        "": _t("General"),
    }
    return labels.get(task, task)


def step_label(step: str) -> str:
    """El paso de una tarea: el colector que corre, con nombre para una persona."""
    labels = {
        "local": _t("Este equipo"),
        "sweep": _t("Ping y ARP"),
        "snmp": "SNMP",
        "ssh": "SSH",
        "winrm": "WinRM",
        "hypervisors": _t("Hipervisores"),
    }
    return labels.get(step, step)


def error_message(code: str, message: str = "") -> str:
    """Lo que se le dice a una persona cuando el canal falla."""
    if code == channel.SERVICE_DOWN:
        return _t("El servicio del agente no está en marcha.")
    if code == channel.TIMEOUT:
        return _t("El servicio no ha contestado a tiempo.")
    if code in (channel.BROKEN, channel.BAD_RESPONSE):
        return _t("Se ha perdido la comunicación con el servicio. Vuelve a intentarlo.")
    if code == channel.BUSY:
        return _t("El servicio está ocupado. Vuelve a intentarlo en unos segundos.")
    if code == channel.ACCESS_DENIED:
        return _t("Windows no deja a esta cuenta hablar con el servicio del agente.")
    if code == channel.FORBIDDEN:
        return _t("Hace falta abrir Cenya Agent como administrador para hacer cambios.")
    # El servicio ya lo dice en palabras de persona; si no, el código.
    return message or _t("El servicio no ha podido hacerlo (%(code)s).") % {"code": code}


# --- Lo que contesta el servicio, en una forma ------------------------------------


#: Los estados de conexión del servicio (`agent/localops.py::op_status`) a los de la ventana.
_CONNECTION_STATES = {"refused": "rejected", "unknown": "connecting", "not_enrolled": "connecting"}


def normalize_status(raw: Any) -> dict[str, Any]:
    """La respuesta de `status` del servicio en la forma que leen las vistas.

    El servicio (`agent/localops.py`) dice ``name``, ``pause.until``,
    ``connection`` con los datos del último checkin (``at``, ``ok``,
    ``error``) y el avance de lo largo en ``local``; las vistas leen
    ``agent_name``, ``paused_until``, ``connection.last_ok_at`` /
    ``last_error`` y la exportación de NetBox como ``activity``. Lo que ya
    venga en la forma de las vistas se respeta. Nunca lanza.
    """
    status = dict(raw) if isinstance(raw, dict) else {}
    status.setdefault("agent_name", status.get("name") or "")
    pause = status.get("pause") if isinstance(status.get("pause"), dict) else {}
    if "paused_until" not in status:
        status["paused_until"] = pause.get("until")
    status.setdefault("paused_indefinitely", bool(pause.get("indefinite")))
    connection = dict(status["connection"]) if isinstance(status.get("connection"), dict) else {}
    state = str(connection.get("state") or "")
    connection["state"] = _CONNECTION_STATES.get(state, state)
    last = status.get("last_checkin") if isinstance(status.get("last_checkin"), dict) else {}
    at = connection.get("at") or last.get("at")
    # El último contacto BUENO lo guarda el servicio (spec 4, `last_ok_at`) y
    # se conserva mientras fallan los siguientes.
    last_ok = connection.get("last_ok_at") or status.get("last_ok_at") or (at if connection.get("ok") is True else None)
    if last_ok:
        connection["last_ok_at"] = last_ok
    if connection.get("ok") is False and not connection.get("last_error"):
        connection["last_error"] = str(connection.get("error") or "")
        connection.setdefault("last_error_at", at)
    status["connection"] = connection
    local = status.get("local") if isinstance(status.get("local"), dict) else {}
    export = local.get("netbox_export") if isinstance(local.get("netbox_export"), dict) else {}
    if not status.get("activity") and export.get("state") == "running":
        status["activity"] = {
            "task": NETBOX_TASK,
            "step": export.get("step") or "",
            "done": export.get("done"),
            "total": export.get("total"),
            "started_at": export.get("started_at"),
        }
    return status


# --- Permisos y el armazón de la ventana ------------------------------------------


def permissions(elevated: bool, forbidden_seen: bool, may_act: bool | None = None) -> dict[str, Any]:
    """Si se puede actuar. Lo dice el servicio (``may_act`` de `status`) y, si no lo dice, Windows.

    Un administrador elevado al que el servicio contesta `forbidden` sigue sin
    poder: manda el servicio, que es quien comprueba.
    """
    can_act = (elevated if may_act is None else bool(may_act)) and not forbidden_seen
    return {
        "can_act": can_act,
        "readonly": not can_act,
        "why": "" if can_act else _t("Hace falta abrir Cenya Agent como administrador para hacer cambios."),
        # Reiniciar elevado solo sirve si no lo está ya.
        "can_elevate": not can_act and not elevated,
    }


def shell_view(
    status: dict[str, Any] | None,
    error_code: str | None,
    service_state: str,
    *,
    elevated: bool,
    forbidden_seen: bool,
    dev: bool,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Qué cara pone la ventana entera: lista, servicio parado, sin enrolar...

    ``mode``: ``ready`` | ``not_enrolled`` | ``down`` | ``not_installed`` |
    ``unreachable``. Un servicio sin enrolar está en marcha y contesta
    (``not_enrolled``, con el porqué en ``enrollment``): conectarlo es un
    ``connect`` por el canal. ``down`` es solo eso, el servicio parado.
    ``tone`` es el del punto junto al nombre del equipo en la barra lateral.
    """
    may_act = status.get("may_act") if isinstance(status, dict) and isinstance(status.get("may_act"), bool) else None
    perms = permissions(elevated, forbidden_seen, may_act)
    view: dict[str, Any] = {
        "mode": "ready",
        "perms": perms,
        "dev": dev,
        "message": "",
        "agent_name": "",
        "portal": "",
        "tone": NEUTRAL,
        "start_why": "",
        "enrollment": "",
    }
    if error_code is not None:
        if service_state == "not_installed":
            view["mode"] = "not_installed"
        elif error_code == channel.SERVICE_DOWN:
            view["mode"] = "down"
        else:
            view["mode"] = "unreachable"
            view["message"] = error_message(error_code)
        view["tone"] = WARNING
        # Arrancar el servicio lo hace Windows, no el canal: pide estar elevado,
        # no que el servicio lo permita (no hay servicio al que preguntar).
        if dev:
            view["start_why"] = _t("Con el canal de desarrollo, el servicio de Windows no se toca desde aquí.")
        elif not elevated:
            view["start_why"] = _t("Hace falta abrir Cenya Agent como administrador para hacer cambios.")
        return view
    status = status or {}
    view["agent_name"] = str(status.get("agent_name") or "")
    view["portal"] = str(status.get("portal") or "")
    if status.get("enrolled") is False:
        view["mode"] = "not_enrolled"
        view["tone"] = WARNING
        view["enrollment"] = enrollment_text(status)
    else:
        view["tone"] = connection_view(status, now or datetime.now(timezone.utc))["tone"]
    return view


def enrollment_text(status: dict[str, Any]) -> str:
    """Por qué el servicio no tiene identidad, para una persona (spec 4, `status.enrollment`)."""
    enrollment = status.get("enrollment") if isinstance(status.get("enrollment"), dict) else {}
    state = str(enrollment.get("state") or "not_enrolled")
    if state == "untrusted":
        return _t(
            "La conexión anterior de este equipo estaba guardada en una carpeta sin proteger y se ha apartado "
            "por seguridad. Vuelve a conectarlo con una cadena nueva."
        )
    if state == "invalid":
        # La frase del servicio dice qué falla (una dirección http:// sin permiso...).
        return str(enrollment.get("message") or "") or _t("La configuración de este agente no es válida.")
    return _t("El servicio está en marcha y esperando: pega una cadena de conexión para conectarlo a tu portal.")


# --- Estado -----------------------------------------------------------------------


def connection_view(status: dict[str, Any], now: datetime) -> dict[str, Any]:
    connection = status.get("connection") if isinstance(status.get("connection"), dict) else {}
    state = str(connection.get("state") or "")
    portal = str(status.get("portal") or "")
    host = re.sub(r"^https?://", "", portal).rstrip("/")
    last_ok = ago(connection.get("last_ok_at"), now)
    since = _t("Último contacto %(ago)s") % {"ago": last_ok} if last_ok else ""
    if not since and (tried := ago(connection.get("last_error_at"), now)):
        since = _t("Último intento %(ago)s") % {"ago": tried}
    detail = str(connection.get("last_error") or "")
    if state == "ok":
        return {"tone": SUCCESS, "title": _t("Conectado a %(portal)s") % {"portal": host or "—"}, "detail": "", "since": since}
    if state == "rejected":
        return {
            "tone": DANGER,
            "title": _t("El portal ha rechazado este agente"),
            "detail": detail or _t("No barre ni usa ninguna credencial hasta que el portal lo acepte de nuevo. Si se revocó, hay que conectarlo otra vez."),
            "since": since,
        }
    if state == "read_only":
        return {
            "tone": WARNING,
            "title": _t("La instalación de Cenya está en solo lectura"),
            "detail": detail or _t("El agente no empieza ninguna tarea hasta que el portal vuelva a aceptar resultados."),
            "since": since,
        }
    if state == "error":
        return {"tone": WARNING, "title": _t("Sin conexión con el portal"), "detail": detail, "since": since}
    return {"tone": NEUTRAL, "title": _t("Conectando con el portal…"), "detail": "", "since": since}


def activity_view(status: dict[str, Any], now: datetime) -> dict[str, Any] | None:
    activity = status.get("activity")
    if not isinstance(activity, dict) or not activity.get("task"):
        return None
    task = str(activity["task"])
    done, total = _as_int(activity.get("done")), _as_int(activity.get("total"))
    percent: int | None = None
    if done is not None and total:
        percent = max(0, min(100, round(100 * done / total)))
    step = str(activity.get("step") or "")
    started = ago(activity.get("started_at"), now)
    return {
        "task": task,
        "label": task_label(task),
        "step": _t("Paso actual: %(step)s") % {"step": step_label(step)} if step else "",
        "percent": percent,
        "count": _t("%(done)d de %(total)d") % {"done": done, "total": total} if percent is not None else "",
        "started": _t("Empezó %(ago)s") % {"ago": started} if started else "",
    }


def is_paused(status: dict[str, Any], now: datetime) -> bool:
    until = parse_time(status.get("paused_until"))
    return bool(until and until > now) or status.get("state") == "paused"


def pause_view(status: dict[str, Any], now: datetime) -> dict[str, Any]:
    until = parse_time(status.get("paused_until"))
    if not is_paused(status, now):
        return {"paused": False, "text": "", "detail": ""}
    if status.get("paused_indefinitely"):
        text = _t("En pausa hasta que se reanude")
    elif until is None or until - now > INDEFINITE_AFTER:
        text = _t("En pausa hasta que se reanude")
        if until is not None:
            text = _t("En pausa hasta que se reanude (como mucho, hasta el %(date)s)") % {"date": _local(until).strftime("%d/%m")}
    else:
        local, today = _local(until), _local(now)
        if local.date() == today.date():
            text = _t("En pausa hasta las %(clock)s") % {"clock": local.strftime("%H:%M")}
        elif local.date() == (today + timedelta(days=1)).date():
            text = _t("En pausa hasta mañana a las %(clock)s") % {"clock": local.strftime("%H:%M")}
        else:
            text = _t("En pausa hasta el %(date)s") % {"date": local.strftime("%d/%m %H:%M")}
    return {
        "paused": True,
        "text": text,
        "detail": _t("No empieza ninguna tarea programada. Lo que se pida desde el portal sí se atiende."),
    }


def pause_options(now: datetime) -> list[dict[str, Any]]:
    """Las tres pausas, con lo que hay que mandar al canal para cada una."""
    local = _local(now)
    tomorrow = (local + timedelta(days=1)).replace(hour=TOMORROW_HOUR, minute=0, second=0, microsecond=0)
    return [
        {"id": "hour", "label": _t("Una hora"), "args": {"seconds": 3600}},
        {
            "id": "tomorrow",
            "label": _t("Hasta mañana a las %(clock)s") % {"clock": tomorrow.strftime("%H:%M")},
            "args": {"until": tomorrow.isoformat()},
        },
        # Sin plazo de verdad (spec 4, `pause` con `indefinite`): el servicio
        # lo guarda como tal y el portal lo enseña así.
        {"id": "indefinite", "label": _t("Hasta que se reanude"), "args": {"indefinite": True}},
    ]


def result_view(last_status: Any, *, running: bool = False) -> dict[str, str]:
    if running:
        return {"tone": ACCENT, "label": _t("En curso")}
    return {
        "ok": {"tone": SUCCESS, "label": _t("Correcta")},
        "partial": {"tone": WARNING, "label": _t("Parcial")},
        "error": {"tone": DANGER, "label": _t("Con errores")},
    }.get(str(last_status or ""), {"tone": NEUTRAL, "label": _t("Sin ejecutar")})


def run_blocker(status: dict[str, Any], can_act: bool, why: str) -> str:
    """Por qué no se puede pedir una tarea ahora, o vacío si se puede."""
    if not can_act:
        return why
    if status.get("enrolled") is False:
        return _t("Este equipo no está conectado a ningún portal.")
    connection = status.get("connection") if isinstance(status.get("connection"), dict) else {}
    if connection.get("state") == "rejected":
        return _t("El portal ha rechazado este agente: conéctalo de nuevo.")
    if connection.get("state") == "read_only":
        return _t("La instalación de Cenya está en solo lectura: no se guardaría nada.")
    return ""


def tasks_view(status: dict[str, Any], now: datetime, can_act: bool, why: str = "") -> list[dict[str, Any]]:
    schedule = status.get("schedule") if isinstance(status.get("schedule"), list) else []
    by_task = {str(row.get("task")): row for row in schedule if isinstance(row, dict) and row.get("task")}
    activity = status.get("activity") if isinstance(status.get("activity"), dict) else {}
    running = str(activity.get("task") or "")
    paused = is_paused(status, now)
    blocker = run_blocker(status, can_act, why)
    order = [task for task in TASK_ORDER if task in by_task] + sorted(t for t in by_task if t not in TASK_ORDER)
    rows: list[dict[str, Any]] = []
    for task in order:
        row = by_task[task]
        finished = parse_time(row.get("last_finished_at"))
        upcoming_at = parse_time(row.get("next_at"))
        every = _as_int(row.get("every_seconds"))
        if every == 0:
            next_text = _t("Desactivada")
        elif paused:
            next_text = _t("En pausa")
        elif upcoming_at:
            next_text = upcoming(upcoming_at, now)
        else:
            next_text = "—"
        rows.append(
            {
                "task": task,
                "label": task_label(task),
                "last": _ago(finished, now) if finished else _t("Nunca"),
                "last_title": full_time(finished) if finished else "",
                "result": result_view(row.get("last_status"), running=task == running),
                "next": next_text,
                "next_title": full_time(upcoming_at) if upcoming_at and every != 0 else "",
                "can_run": not blocker,
                "why": blocker,
            }
        )
    return rows


COUNTER_KEYS = ("hosts_alive", "new_hosts", "sent", "created", "refreshed")


def last_runs(status: dict[str, Any]) -> list[dict[str, Any]]:
    """Las últimas ejecuciones (spec 4, `status.last_run`: una por tarea), la más reciente primero."""
    runs = status.get("last_run") if isinstance(status.get("last_run"), dict) else {}
    rows = [dict(run, task=str(run.get("task") or task)) for task, run in runs.items() if isinstance(run, dict)]
    return sorted(rows, key=lambda run: parse_time(run.get("finished_at")) or datetime.min.replace(tzinfo=timezone.utc), reverse=True)


def counters_view(status: dict[str, Any], now: datetime) -> dict[str, Any]:
    """Las cifras de la última tarea que terminó, y la cola."""
    runs = last_runs(status)
    last = runs[0] if runs else None
    labels = {
        "hosts_alive": _t("Equipos vivos"),
        "new_hosts": _t("Equipos nuevos"),
        "sent": _t("Hallazgos enviados"),
        "created": _t("Nuevos en la bandeja"),
        "refreshed": _t("Ya conocidos"),
        "outbox": _t("Envíos pendientes"),
    }
    items: list[dict[str, Any]] = []
    if last:
        for key in COUNTER_KEYS:
            value = _as_int(last.get(key))
            if value is not None:
                items.append({"key": key, "label": labels[key], "value": value, "tone": NEUTRAL})
    outbox = _as_int(status.get("outbox"))
    if outbox is not None:
        items.append({"key": "outbox", "label": labels["outbox"], "value": outbox, "tone": WARNING if outbox else NEUTRAL})
    caption = ""
    note = ""
    if last:
        when = ago(last.get("finished_at"), now)
        caption = " · ".join(part for part in (task_label(str(last.get("task") or "")), when) if part)
        if last.get("delivered") is False:
            note = _t("El resultado espera en la cola local: el portal aún no ha dicho qué había de nuevo.")
        elif (notes := _as_int(last.get("notes"))):
            note = _tn("%(n)d aviso: los detalles, en Actividad.", "%(n)d avisos: los detalles, en Actividad.", notes) % {"n": notes}
    return {"caption": caption, "items": items, "note": note, "result": result_view(last.get("status")) if last else None}


def status_view(status: dict[str, Any], now: datetime, perms: dict[str, Any]) -> dict[str, Any]:
    can_act = bool(perms.get("can_act"))
    why = str(perms.get("why") or "")
    paused = pause_view(status, now)
    blocker = "" if can_act else why
    update = status.get("update") if isinstance(status.get("update"), dict) else None
    return {
        "connection": connection_view(status, now),
        "activity": activity_view(status, now),
        "pause": paused,
        "pause_options": pause_options(now),
        "can_pause": can_act and not paused["paused"],
        "can_resume": can_act and paused["paused"],
        "pause_why": blocker,
        "tasks": tasks_view(status, now, can_act, why),
        "counters": counters_view(status, now),
        "next_text": _next_task_text(status, now),
        "update": _t("Hay una versión nueva del agente: %(version)s") % {"version": update.get("version")}
        if update and update.get("version")
        else "",
    }


def _next_task_text(status: dict[str, Any], now: datetime) -> str:
    """La frase del estado de reposo: qué toca y cuándo."""
    if is_paused(status, now):
        return ""
    schedule = status.get("schedule") if isinstance(status.get("schedule"), list) else []
    candidates = []
    for row in schedule:
        if not isinstance(row, dict) or _as_int(row.get("every_seconds")) == 0:
            continue
        moment = parse_time(row.get("next_at"))
        if moment:
            candidates.append((moment, str(row.get("task") or "")))
    if not candidates:
        return ""
    moment, task = min(candidates)
    return _t("La siguiente es %(task)s: %(when)s.") % {"task": task_label(task), "when": upcoming(moment, now)}


# --- Actividad (el registro) --------------------------------------------------------

_LOG_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})(?:[,.]\d+)?\s+([A-Z]+)\s+(.*)$")
_TASK_IN_TEXT = re.compile(r"\b(?:[Tt]area|task)\s+(" + "|".join(TASK_ORDER) + r")\b")
LEVELS = ("info", "warning", "error")


def _level(raw: str) -> str:
    raw = raw.lower()
    if raw in ("error", "critical", "fatal"):
        return "error"
    if raw in ("warning", "warn"):
        return "warning"
    return "info"


def log_row(line: Any, fallback_n: int = 0) -> dict[str, Any] | None:
    """Una línea del registro, venga como objeto o como el texto del fichero."""
    if isinstance(line, dict):
        n = _as_int(line.get("n")) or fallback_n
        at = parse_time(line.get("at"))
        level = _level(str(line.get("level") or "info"))
        text = str(line.get("text") or "")
        task = str(line.get("task") or "")
    elif isinstance(line, str):
        n = fallback_n
        match = _LOG_LINE.match(line.strip())
        if match:
            at = parse_time(match.group(1).replace(" ", "T"))
            level, text = _level(match.group(2)), match.group(3)
        else:
            at, level, text = None, "info", line.rstrip()
        task = ""
    else:
        return None
    # Todo lo que escribe el agente empieza por «[agente] »: en su propia
    # ventana no dice nada y ocupa la columna que más se lee.
    text = text.removeprefix("[agente] ")
    if not task:
        found = _TASK_IN_TEXT.search(text)
        task = found.group(1) if found else ""
    tones = {"info": NEUTRAL, "warning": WARNING, "error": DANGER}
    return {
        "n": n,
        "clock": _local(at).strftime("%H:%M:%S") if at else "",
        "title": full_time(at) if at else "",
        "level": level,
        "tone": tones[level],
        "task": task,
        "task_label": task_label(task),
        "text": text,
    }


def log_view(data: dict[str, Any], after: str, first_n: int = 0) -> dict[str, Any]:
    """Las líneas nuevas del registro. El cursor del servicio es opaco: se guarda y se devuelve.

    `first_n` numera las filas (para que la página las distinga), seguido de
    las que ya tenía.
    """
    lines = data.get("lines") if isinstance(data.get("lines"), list) else []
    rows = []
    for index, line in enumerate(lines, 1):
        row = log_row(line, first_n + index)
        if row is not None:
            rows.append(row)
    cursor = data.get("cursor", data.get("next"))
    return {"rows": rows, "cursor": str(cursor) if cursor not in (None, "") else after, "missing": bool(data.get("missing"))}


def log_filters() -> dict[str, list[dict[str, str]]]:
    return {
        "tasks": [{"id": "", "label": _t("Todas las tareas")}]
        + [{"id": task, "label": task_label(task)} for task in (*TASK_ORDER, NETBOX_TASK)]
        + [{"id": "-", "label": task_label("")}],
        "levels": [
            {"id": "", "label": _t("Todos los niveles")},
            {"id": "info", "label": _t("Información")},
            {"id": "warning", "label": _t("Avisos")},
            {"id": "error", "label": _t("Errores")},
        ],
    }


# --- Importar de NetBox ---------------------------------------------------------------


def netbox_form_error(url: str, token: str) -> str:
    """Lo que falta en el formulario antes de mandar nada, o vacío."""
    url = url.strip()
    if not url:
        return _t("Escribe la dirección de NetBox.")
    if not url.lower().startswith(("http://", "https://")):
        return _t("La URL tiene que empezar por http:// o https://.")
    if not token.strip():
        return _t("Pega el token de NetBox.")
    return ""


def netbox_progress(activity: dict[str, Any] | None, seen: list[str]) -> dict[str, Any]:
    """El avance por colección, con lo que se ha ido viendo en `status`.

    El servicio dice la colección que lee ahora (``activity.step``) y cuántas
    lleva de cuántas; las anteriores se dan por leídas. `seen` es la lista de
    colecciones vistas hasta ahora, en orden, y se devuelve ampliada.
    """
    seen = list(seen)
    step = ""
    percent = None
    if isinstance(activity, dict) and activity.get("task") == NETBOX_TASK:
        step = str(activity.get("step") or "")
        done, total = _as_int(activity.get("done")), _as_int(activity.get("total"))
        if done is not None and total:
            percent = max(0, min(100, round(100 * done / total)))
    if step and step not in seen:
        seen.append(step)
    rows = [{"name": name, "state": "reading" if name == step else "done"} for name in seen]
    return {"seen": seen, "rows": rows, "percent": percent}


def netbox_summary(data: dict[str, Any], mode: str) -> dict[str, Any]:
    summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
    rows = [{"name": str(name).replace("_", " "), "count": count} for name, count in summary.items() if _as_int(count) is not None]
    total = sum(int(row["count"]) for row in rows)
    view: dict[str, Any] = {
        "rows": rows,
        "total": _tn("%(n)d objeto leído", "%(n)d objetos leídos", total) % {"n": total},
        "review_url": "",
        "path": "",
        "message": "",
    }
    if mode == "send":
        # Dónde se revisa lo dice el servicio (spec 4, `review_url`), que ya
        # comprobó que es del mismo portal; aquí solo se mira que se pueda abrir.
        view["review_url"] = safe_url(str(data.get("review_url") or ""))
        view["message"] = _t("Enviado al portal. La revisión se abre en el navegador: nada se importa hasta que lo confirmes allí.")
    else:
        view["path"] = str(data.get("path") or "")
        view["message"] = _t("Guardado en %(path)s") % {"path": view["path"]}
    return view


def safe_url(url: str) -> str:
    """Solo `http`/`https` con un servidor y sin usuario: se abre en un navegador."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(url.strip())
        parts.port  # noqa: B018 - un puerto que no es número lanza aquí
    except ValueError:
        return ""
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return ""
    return url.strip()


# --- Herramientas -----------------------------------------------------------------------


def probe_view(report: dict[str, Any]) -> dict[str, Any]:
    # El servicio contesta {"ip", "report"}; el informe es el de agent/probe.py.
    if isinstance(report.get("report"), dict):
        report = report["report"]
    rows = []
    for protocol, name in (("snmp", "SNMP"), ("ssh", "SSH"), ("winrm", "WinRM")):
        if protocol in report:
            rows.append({"protocol": name, "text": str(report[protocol])})
    return {"rows": rows}


def connection_test_view(data: dict[str, Any]) -> dict[str, Any]:
    # Los pasos del servicio (agent/localops.py::connection_test), en orden.
    # Se para en el primero que falla: los de detrás salen «sin comprobar».
    labels = {
        "dns": _t("Nombre del portal"),
        "tcp": _t("Puerto"),
        "tls": _t("Certificado"),
        "checkin": _t("Token del agente"),
    }
    steps = []
    seen: set[str] = set()
    for step in data.get("steps") or []:
        if not isinstance(step, dict):
            continue
        ok = step.get("ok")
        state = "ok" if ok is True else "fail" if ok is False else "skip"
        name = str(step.get("step") or "")
        seen.add(name)
        detail = str(step.get("message") or step.get("detail") or "")
        if state == "skip" and not detail:
            detail = _t("No se llegó a comprobar.")
        steps.append({"label": labels.get(name, name), "state": state, "detail": detail})
    if steps and steps[-1]["state"] == "fail":
        for name in labels:
            if name not in seen:
                steps.append({"label": labels[name], "state": "skip", "detail": _t("No se llegó a comprobar.")})
    passed = bool(steps) and all(step["state"] == "ok" for step in steps)
    return {
        "ok": passed,
        "steps": steps,
        "summary": _t("Todo en orden: el agente llega al portal y el portal lo acepta.") if passed else _t("Algo falla: el primer paso en rojo dice qué."),
    }


def selftest_view(report: dict[str, Any], complete: bool) -> dict[str, Any]:
    rows = []

    def row(label: str, values: dict[str, Any] | None) -> None:
        if not isinstance(values, dict):
            return
        missing = sorted(name for name, ok in values.items() if not ok)
        rows.append(
            {
                "label": label,
                "ok": not missing,
                "detail": _t("Falta: %(names)s") % {"names": ", ".join(missing)} if missing else ", ".join(sorted(values)),
            }
        )

    collectors = report.get("collectors") or []
    rows.append({"label": _t("Colectores"), "ok": len(collectors) >= 6, "detail": ", ".join(map(str, collectors))})
    row(_t("Librerías opcionales"), report.get("modules"))
    row(_t("Idiomas"), report.get("languages"))
    row(_t("Librerías de Windows"), report.get("windows_modules"))
    ssh = report.get("ssh") if isinstance(report.get("ssh"), dict) else {}
    if ssh:
        rows.append(
            {
                "label": "OpenSSH",
                "ok": bool(ssh.get("binary")) and bool(ssh.get("password_auth")),
                "detail": " · ".join(str(part) for part in (ssh.get("version"), ssh.get("binary")) if part) or _t("No encontrado"),
            }
        )
    return {
        "complete": complete,
        "title": _t("Instalación completa") if complete else _t("Falta algo en esta instalación"),
        "rows": rows,
        "version": str(report.get("version") or ""),
    }


# --- Conexión y ajustes ------------------------------------------------------------------


def validate_exclusion(text: str, existing: list[str]) -> dict[str, Any]:
    """Una red o una dirección para la lista de exclusiones, ya normalizada."""
    value = text.strip()
    if not value:
        return {"ok": False, "message": _t("Escribe una red (10.0.5.0/24) o una dirección (10.0.5.7).")}
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
            if network.num_addresses == 1:
                normalized, kind = str(network.network_address), "address"
            else:
                normalized, kind = str(network), "network"
        else:
            normalized, kind = str(ipaddress.ip_address(value)), "address"
    except ValueError:
        return {"ok": False, "message": _t("Escribe una red (10.0.5.0/24) o una dirección (10.0.5.7).")}
    if normalized in existing:
        return {"ok": False, "message": _t("Ya está en la lista.")}
    return {"ok": True, "value": normalized, "kind": kind}


def exclusions_view(settings: dict[str, Any], about: dict[str, Any] | None) -> dict[str, Any]:
    excluded = settings.get("excluded") if isinstance(settings.get("excluded"), dict) else {}
    subnets = [str(v) for v in excluded.get("subnets") or []]
    addresses = [str(v) for v in excluded.get("addresses") or []]
    items = [{"value": v, "kind": "network", "kind_label": _t("Red")} for v in subnets]
    items += [{"value": v, "kind": "address", "kind_label": _t("Dirección")} for v in addresses]
    present = set(subnets) | set(addresses)
    suggestions = []
    for network in (about or {}).get("networks") or []:
        if not isinstance(network, dict):
            continue
        for value, kind in ((network.get("cidr"), "network"), (network.get("address"), "address")):
            if value and str(value) not in present and all(s["value"] != value for s in suggestions):
                suggestions.append({"value": str(value), "kind": kind, "interface": str(network.get("interface") or "")})
    return {"items": items, "suggestions": suggestions}


def settings_error(message: str, details: dict[str, Any]) -> str:
    """El «no» de `settings.set` con lo que dijo de cada campo (``details.fields``)."""
    fields = details.get("fields") if isinstance(details.get("fields"), dict) else {}
    reasons = [str(reason) for reason in fields.values() if reason]
    return " ".join([message, *reasons]).strip()


def exclusions_payload(items: list[str]) -> dict[str, Any]:
    """Lo que se manda en `settings.set` a partir de la lista (redes y direcciones)."""
    subnets, addresses = [], []
    for value in items:
        (subnets if "/" in value else addresses).append(value)
    return {"excluded": {"subnets": subnets, "addresses": addresses}}


def gentleness_label(level: str) -> str:
    return {"gentle": _t("Suave"), "normal": _t("Normal"), "fast": _t("Rápida"), "": _t("Sin tope")}.get(level, level)


def gentleness_view(settings: dict[str, Any], status: dict[str, Any] | None) -> dict[str, Any]:
    cap = str(settings.get("gentleness_cap") or "")
    effective = str((status or {}).get("gentleness") or "")
    return {
        "value": cap if cap in GENTLENESS_CAPS else "",
        "options": [{"id": level, "label": gentleness_label(level)} for level in GENTLENESS_CAPS],
        "effective": _t("Ahora trabaja en modo %(level)s.") % {"level": gentleness_label(effective).lower()} if effective else "",
    }


#: Lo que está haciendo el actualizador (`agent/update.py`), para una persona.
def _updater_text(updater: dict[str, Any] | None) -> str:
    state = str((updater or {}).get("state") or "")
    version = str((updater or {}).get("version") or "")
    return {
        "downloading": _t("Descargando la versión %(version)s…"),
        "ready": _t("La versión %(version)s está verificada: se instala en cuanto termine la tarea en curso."),
        "installing": _t("Instalando la versión %(version)s…"),
        "failed": _t("La actualización a %(version)s no se pudo completar; se sigue con la versión instalada."),
    }.get(state, "") % {"version": version} if state in ("downloading", "ready", "installing", "failed") else ""


def updates_view(settings: dict[str, Any], status: dict[str, Any] | None, check: dict[str, Any] | None) -> dict[str, Any]:
    """El bloque de actualizaciones: lo instalado, lo ofrecido y, tras «Buscar», lo que contestó el portal ahora.

    `check` es la respuesta de `check_update` (spec 4): un checkin de verdad,
    con ``checked`` (contestó), ``pending`` (no contestó a tiempo), ``error``
    y el estado del actualizador.
    """
    installed = str((status or {}).get("version") or (check or {}).get("current") or "")
    latest = str((check or {}).get("offered") or "")
    update = (status or {}).get("update") if isinstance((status or {}).get("update"), dict) else None
    if not latest and update:
        latest = str(update.get("version") or "")
    available = bool(latest and installed and latest != installed)
    updater = (check or {}).get("updater") if isinstance((check or {}).get("updater"), dict) else None
    if updater is None and isinstance((status or {}).get("updater"), dict):
        updater = (status or {})["updater"]
    auto = bool(settings.get("auto_update", True))
    tone = NEUTRAL
    if check is not None and check.get("pending"):
        message, tone = _t("El portal tarda en contestar; el resultado aparecerá aquí en cuanto llegue."), INFO
    elif check is not None and not check.get("checked") and check.get("error"):
        message, tone = _t("No se pudo preguntar al portal: %(error)s") % {"error": check.get("error")}, WARNING
    elif available:
        message, tone = _t("Hay una versión nueva: %(version)s") % {"version": latest}, INFO
        if auto:
            message += " " + _t("Se instalará sola, sin cortar ninguna tarea.")
        else:
            message += " " + _t("Las actualizaciones automáticas están desactivadas en este equipo.")
    elif check is not None:
        message, tone = _t("Está al día."), SUCCESS
    else:
        message = ""
    progress = _updater_text(updater)
    if progress:
        tone = DANGER if (updater or {}).get("state") == "failed" else INFO
    checked = ago((check or {}).get("checked_at"), datetime.now(timezone.utc)) if check and check.get("checked") else ""
    return {
        "auto": auto,
        "installed": installed or "—",
        "latest": latest or "—",
        "available": available,
        "message": message,
        "progress": progress,
        "checked": _t("Comprobado %(ago)s") % {"ago": checked} if checked else "",
        "tone": tone,
    }


def service_view(state: str, start_type: str, can_act: bool, why: str, *, dev: bool) -> dict[str, Any]:
    labels = {
        "running": (_t("En marcha"), SUCCESS),
        "stopped": (_t("Detenido"), WARNING),
        "starting": (_t("Arrancando…"), INFO),
        "stopping": (_t("Deteniéndose…"), INFO),
        "not_installed": (_t("No instalado"), DANGER),
    }
    label, tone = labels.get(state, (_t("Desconocido"), NEUTRAL))
    blocker = why if not can_act else ""
    if dev:
        blocker = _t("Con el canal de desarrollo, el servicio de Windows no se toca desde aquí.")
    installed = state != "not_installed"
    return {
        "label": label,
        "tone": tone,
        "can_start": not blocker and installed and state == "stopped",
        "can_stop": not blocker and state == "running",
        "can_restart": not blocker and state == "running",
        "autostart": start_type in ("auto", "delayed"),
        "can_autostart": not blocker and installed,
        "why": blocker,
    }


def language_options(current: str) -> dict[str, Any]:
    options = [{"id": "", "label": _t("El de Windows")}] + [{"id": code, "label": name} for code, name in LANGUAGES]
    return {"value": current if current in {code for code, _ in LANGUAGES} else "", "options": options}


def proxy_view(settings: dict[str, Any]) -> dict[str, Any]:
    proxy = settings.get("proxy") if isinstance(settings.get("proxy"), dict) else {}
    mode = str(proxy.get("mode") or "system")
    return {"mode": mode if mode in ("system", "manual", "none") else "system", "url": str(proxy.get("url") or "")}


# --- El icono de bandeja -------------------------------------------------------------------


def tray_menu(status: dict[str, Any] | None, now: datetime, headline: str, portal_url: str | None) -> list[dict[str, Any]]:
    """Las entradas del menú del icono, en orden. `None` en `status`: sin canal."""
    reachable = status is not None
    enrolled = reachable and status.get("enrolled") is not False
    paused = reachable and is_paused(status, now)
    items: list[dict[str, Any]] = [
        {"id": "open", "label": _t("Abrir"), "enabled": True, "default": True},
        {"id": "status", "label": headline, "enabled": False},
        {"id": "-"},
        # También en pausa: la pausa para lo programado, no lo que pide una persona (2.1).
        {"id": "run_presence", "label": _t("Ejecutar Presencia ahora"), "enabled": enrolled},
        {"id": "resume" if paused else "pause", "label": _t("Reanudar") if paused else _t("Pausar una hora"), "enabled": enrolled},
        {"id": "-"},
        {"id": "portal", "label": _t("Abrir Cenya en el navegador"), "enabled": bool(portal_url)},
        {"id": "check_update", "label": _t("Buscar actualizaciones"), "enabled": reachable},
        {"id": "-"},
        {"id": "close", "label": _t("Cerrar este icono"), "enabled": True},
    ]
    return items
