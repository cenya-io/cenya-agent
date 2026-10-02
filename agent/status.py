"""What the agent is doing right now, in a small file the tray icon reads.

The agent keeps no state it needs -- that stays true. This file is not state
the agent reads back; it is a window for the person at the machine: the
service runs as SYSTEM in its own session and the tray runs as whoever is
logged in, and a file both can reach is the simplest bridge between them that
opens no port.

Two halves:

* **Writing**, from the agent's loop (`started`, `sweep_started`, ...). Every
  write merges into what was there, lands atomically (temporary file +
  ``os.replace``) and **never raises**: a status file is a convenience, and an
  agent that dies because it could not write one would be the worst trade.
* **Reading and judging**, from the tray (`read`, `describe`). `describe` is a
  pure function from the file and the service's state to what the icon says,
  so every case can be tested without Windows. Its rule is to be honest about
  what it does not know: no news is grey, "I don't know", never red or green.

Never a secret in here: the URL is stored without any user:password part, and
the token is never written.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
# La función y no el módulo: los tests del bucle sustituyen `time.sleep` para
# contar sorbos de siesta, y un reintento de escritura aquí (Windows bloquea un
# instante el fichero recién escrito) se colaba en esa cuenta.
from time import sleep as _sleep
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from agent.i18n import _t, _tn

ENV_VAR = "CENYA_STATUS_FILE"
#: El nombre de antes de llamarse Cenya.
LEGACY_ENV_VAR = "NETINVENTORY_STATUS_FILE"

#: Cada cuánto se reescribe como mínimo mientras el agente duerme: tras cada
#: sorbo de la siesta (`agent.__main__.POLL_SECONDS`). Se repite aquí en vez de
#: importarse para que el icono no cargue el bucle entero del agente.
NAP_WRITE_SECONDS = 60

#: Cuánto silencio es normal antes de decir «no sé». Durmiendo, el fichero se
#: toca cada minuto: cuatro sin noticias ya no es casualidad. Barriendo, un
#: colector puede tardar mucho (un ping a una /16), así que se espera más.
STALE_WHILE_IDLE = timedelta(seconds=NAP_WRITE_SECONDS * 4)
STALE_WHILE_SWEEPING = timedelta(minutes=60)


def path() -> Path | None:
    """Dónde vive el fichero, o `None` si en esta plataforma no hace falta.

    En Windows, `%ProgramData%\\Cenya\\status.json`: el servicio escribe
    como SYSTEM y el icono lee como el usuario de la sesión, y esa carpeta la
    alcanzan los dos (el instalador del servicio la deja cerrada a escritura).
    En Linux no hay icono que lo lea: solo se escribe si alguien pide una ruta.
    """
    override = (os.environ.get(ENV_VAR) or os.environ.get(LEGACY_ENV_VAR) or "").strip()
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = os.environ.get("ProgramData") or r"C:\ProgramData"
        return Path(base) / "Cenya" / "status.json"
    return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def read() -> dict[str, Any] | None:
    """Lo último escrito, o `None` si no hay fichero o no se puede leer."""
    target = path()
    if target is None:
        return None
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


#: Con el protocolo 2 escriben dos hilos (el de control y el de las tareas):
#: leer, fundir y reemplazar tiene que ir de una vez o uno pisa al otro.
_WRITE_LOCK = threading.Lock()


def write(**fields: Any) -> None:
    """Funde `fields` con lo que había y lo guarda de golpe. Nunca lanza."""
    target = path()
    if target is None:
        return
    with _WRITE_LOCK:
        _write(target, fields)


def _write(target: Path, fields: dict[str, Any]) -> None:
    try:
        current = read() or {}
        current.update(fields)
        current["updated_at"] = _now().isoformat()
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=target.parent, prefix=".status-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(current, handle, ensure_ascii=False, indent=1)
            # En Windows, reemplazar un fichero que el icono tiene abierto en
            # ese mismo instante falla: se reintenta un momento antes de
            # rendirse, y rendirse solo cuesta una actualización.
            for attempt in range(3):
                try:
                    os.replace(temporary, target)
                    break
                except PermissionError:
                    if attempt == 2:
                        raise
                    _sleep(0.05)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    except Exception:  # noqa: BLE001 - el estado es una comodidad, nunca tumba el agente
        pass


def _safe_url(url: str) -> str:
    """La URL sin `usuario:contraseña@`, por si alguien la escribió así."""
    parts = urlsplit(url)
    if parts.username is None and parts.password is None:
        return url
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


# --- Lo que escribe el bucle ---------------------------------------------------
#
# Con nombre y no `write(...)` suelto por el bucle: así los campos del fichero
# están en un solo sitio, y el que lo lee (`describe`) no depende de adivinar.


def started(*, version: str, url: str, interval_seconds: int) -> None:
    write(
        state="iniciando",
        version=version,
        url=_safe_url(url),
        pid=os.getpid(),
        started_at=_now().isoformat(),
        interval_seconds=interval_seconds,
        step="",
        stop_reason="",
    )


def sweep_started() -> None:
    write(state="barriendo", step="", last_sweep_started_at=_now().isoformat())


def sweep_step(name: str) -> None:
    write(state="barriendo", step=name)


def sweep_finished(*, created: int, refreshed: int, errors: list[str], next_in: int) -> None:
    now = _now()
    write(
        state="durmiendo",
        step="",
        last_sweep_finished_at=now.isoformat(),
        last_sweep_created=created,
        last_sweep_refreshed=refreshed,
        last_sweep_notes=list(errors),
        last_contact_ok_at=now.isoformat(),
        last_error="",
        next_sweep_at=(now + timedelta(seconds=next_in)).isoformat(),
    )


def nap_tick(*, next_in: int, error: str = "") -> None:
    """Un sorbo de siesta: sigue vivo, y cómo fue el latido de ese sorbo."""
    now = _now()
    fields: dict[str, Any] = {
        "state": "durmiendo",
        "step": "",
        "next_sweep_at": (now + timedelta(seconds=next_in)).isoformat(),
    }
    if error:
        fields.update(last_error=error, last_error_at=now.isoformat())
    else:
        fields["last_contact_ok_at"] = now.isoformat()
    write(**fields)


# --- Protocolo 2: tareas con su propio ritmo ----------------------------------
#
# Los mismos campos que lee `describe`, para que el icono de hoy siga
# funcionando: una tarea en marcha es «barriendo» con su paso, y al terminar
# cuenta como el último barrido. `task` dice cuál fue.


def task_started(task: str) -> None:
    write(state="barriendo", task=task, step="", last_sweep_started_at=_now().isoformat())


def task_step(task: str, step: str) -> None:
    write(state="barriendo", task=task, step=step)


def task_finished(*, task: str, created: int, refreshed: int, errors: list[str], next_in: int | None) -> None:
    now = _now()
    fields: dict[str, Any] = {
        "state": "durmiendo",
        "task": "",
        "step": "",
        "last_task": task,
        "last_sweep_finished_at": now.isoformat(),
        "last_sweep_created": created,
        "last_sweep_refreshed": refreshed,
        "last_sweep_notes": list(errors),
    }
    if next_in is not None:
        fields["next_sweep_at"] = (now + timedelta(seconds=next_in)).isoformat()
    write(**fields)


def contact(error: str = "") -> None:
    """Cómo fue el último checkin, sin tocar lo que esté haciendo el agente."""
    now = _now()
    if error:
        write(last_error=error, last_error_at=now.isoformat())
    else:
        write(last_contact_ok_at=now.isoformat(), last_error="")


def idle(*, next_in: int | None, paused_until: str | None = None) -> None:
    """Esperando a la siguiente tarea (o en pausa hasta `paused_until`)."""
    fields: dict[str, Any] = {"state": "durmiendo", "task": "", "step": "", "paused_until": paused_until}
    if next_in is not None:
        fields["next_sweep_at"] = (_now() + timedelta(seconds=next_in)).isoformat()
    write(**fields)


def failed(message: str) -> None:
    """Un barrido que no llegó al servidor, o un fallo inesperado del bucle.

    Lo siguiente que hace el bucle es dormir, así que eso es lo que se dice.
    """
    write(state="durmiendo", step="", last_error=message, last_error_at=_now().isoformat())


def stopped(reason: str = "") -> None:
    write(state="detenido", step="", stopped_at=_now().isoformat(), stop_reason=reason)


# --- Lo que dice el icono ------------------------------------------------------

OK = "ok"
WARNING = "warning"
UNKNOWN = "unknown"

#: Lo que el icono sabe del servicio de Windows, además del fichero.
SERVICE_RUNNING = "running"
SERVICE_STOPPED = "stopped"
SERVICE_NOT_INSTALLED = "not_installed"


@dataclass(frozen=True)
class Health:
    """Lo que el icono enseña: un tono, una frase corta y el detalle."""

    tone: str
    headline: str
    details: list[str] = field(default_factory=list)


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _ago(moment: datetime, now: datetime) -> str:
    seconds = max(0, int((now - moment).total_seconds()))
    if seconds < 60:
        return _t("hace menos de un minuto")
    minutes = seconds // 60
    if minutes < 60:
        return _tn("hace %(n)d minuto", "hace %(n)d minutos", minutes) % {"n": minutes}
    hours = minutes // 60
    if hours < 48:
        return _tn("hace %(n)d hora", "hace %(n)d horas", hours) % {"n": hours}
    days = hours // 24
    return _tn("hace %(n)d día", "hace %(n)d días", days) % {"n": days}


def _clock(moment: datetime) -> str:
    return moment.astimezone().strftime("%H:%M")


def describe(data: dict[str, Any] | None, now: datetime, service: str | None = None) -> Health:
    """Del fichero de estado y del servicio, lo que el icono tiene que decir.

    `service` es lo que dice Windows del servicio (`SERVICE_*`), o `None` si
    no se pudo preguntar (el agente puede estar corriendo en una consola).
    Gris es «no lo sé»; naranja, «sé que algo va mal»; verde, «funciona».
    """
    if not data:
        if service == SERVICE_STOPPED:
            return Health(UNKNOWN, _t("Agente detenido"), [_t("El servicio está detenido y no hay datos de su última ejecución.")])
        if service == SERVICE_NOT_INSTALLED:
            return Health(UNKNOWN, _t("Servicio no instalado"), [_t("El servicio del agente no está instalado en este equipo.")])
        return Health(UNKNOWN, _t("Sin datos del agente"), [_t("No se encuentra el fichero de estado: el agente no ha arrancado nunca aquí, o no se puede leer.")])

    details = _last_sweep_lines(data, now)
    updated = _parse(data.get("updated_at"))
    state = data.get("state")

    # «No instalado» no significa detenido: el agente puede estar corriendo en
    # una consola, y entonces lo que manda es si el fichero está al día.
    if state == "detenido" or service == SERVICE_STOPPED:
        reason = str(data.get("stop_reason") or "")
        if reason:
            return Health(WARNING, _t("Agente detenido por un error"), [reason, *details])
        return Health(UNKNOWN, _t("Agente detenido"), details)

    limit = STALE_WHILE_SWEEPING if state == "barriendo" else STALE_WHILE_IDLE
    if updated is None or now - updated > limit:
        since = _ago(updated, now) if updated else _t("hace un tiempo desconocido")
        return Health(
            UNKNOWN,
            _t("Sin noticias del agente"),
            [
                _t("La última noticia del agente es de %(ago)s: puede haberse detenido, o el fichero de estado ya no se actualiza.") % {"ago": since},
                *details,
            ],
        )

    failed_at = _parse(data.get("last_error_at"))
    ok_at = _parse(data.get("last_contact_ok_at"))
    if data.get("last_error") and failed_at and (ok_at is None or failed_at > ok_at):
        return Health(
            WARNING,
            _t("No puede hablar con el servidor"),
            [str(data["last_error"]), *details],
        )

    if state == "barriendo":
        step = str(data.get("step") or "")
        headline = _t("Barriendo la red")
        lines = [_t("Paso actual: %(step)s") % {"step": step}] if step else []
        return Health(OK, headline, [*lines, *details])
    if state == "iniciando":
        return Health(OK, _t("Arrancando"), details)
    return Health(OK, _t("En marcha"), details)


#: Lo que cabe en el texto emergente de un icono de bandeja (szTip, 128 con el nulo).
TOOLTIP_MAX = 127


def tooltip(health: Health) -> str:
    text = _t("Cenya Agent: %(headline)s") % {"headline": health.headline}
    return text if len(text) <= TOOLTIP_MAX else text[: TOOLTIP_MAX - 1] + "…"


def should_notify(previous_tone: str | None, tone: str) -> bool:
    """Avisar con un globo solo al *pasar* a «algo va mal».

    También al abrir sesión si ya estaba mal (`previous_tone` es `None`): es
    justo cuando conviene saberlo. Nunca por «no lo sé»: un aviso que salta
    cada vez que se reinicia el servicio deja de leerse.
    """
    return tone == WARNING and previous_tone != WARNING


def settings_url(data: dict[str, Any] | None) -> str | None:
    """La página de Ajustes → Agentes del servidor, si la URL guardada es de fiar.

    Solo `http` o `https` con un servidor: el icono va a abrirla en el
    navegador de quien lo pulse, y el fichero de estado es algo que se lee de
    disco. Cualquier otra cosa (`file:`, `javascript:`, vacío) no se abre.
    """
    url = str((data or {}).get("url") or "").strip()
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    try:
        port = parts.port
    except ValueError:  # un puerto que no es un número
        return None
    netloc = f"{host}:{port}" if port else host  # sin usuario:contraseña, nunca
    base = urlunsplit((parts.scheme, netloc, parts.path.rstrip("/"), "", ""))
    return f"{base}/settings/agents/"


def _last_sweep_lines(data: dict[str, Any], now: datetime) -> list[str]:
    lines: list[str] = []
    finished = _parse(data.get("last_sweep_finished_at"))
    if finished:
        created = int(data.get("last_sweep_created") or 0)
        refreshed = int(data.get("last_sweep_refreshed") or 0)
        lines.append(
            _t("Último barrido: %(clock)s (%(ago)s).") % {"clock": _clock(finished), "ago": _ago(finished, now)}
        )
        lines.append(
            _tn("%(n)d hallazgo nuevo", "%(n)d hallazgos nuevos", created) % {"n": created}
            + ", "
            + _tn("%(n)d ya conocido.", "%(n)d ya conocidos.", refreshed) % {"n": refreshed}
        )
        notes = [str(note) for note in data.get("last_sweep_notes") or []]
        if notes:
            # Un barrido parcial es lo normal sin credenciales: se cuenta, pero
            # no pone el icono en naranja -- un aviso permanente ya no avisa.
            lines.append(
                _tn(
                    "Salió parcial, con %(n)d aviso (detalle en Ajustes → Agentes).",
                    "Salió parcial, con %(n)d avisos (detalle en Ajustes → Agentes).",
                    len(notes),
                )
                % {"n": len(notes)}
            )
    else:
        lines.append(_t("Todavía no ha terminado ningún barrido."))
    upcoming = _parse(data.get("next_sweep_at"))
    if upcoming and upcoming > now and data.get("state") == "durmiendo":
        lines.append(_t("Próximo barrido hacia las %(clock)s.") % {"clock": _clock(upcoming)})
    return lines
