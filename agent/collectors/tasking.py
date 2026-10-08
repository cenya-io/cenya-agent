"""What every collector reads from ``ctx`` when it runs inside a task.

The agent 0.11 runs collectors per task (presence, inventory, configs, ups,
hypervisors) and hands them more than the config: which hosts to touch
(``targets``), which never to touch (``excluded``), how many at once
(``workers``), whom to tell how far it got (``progress``) and what it learnt
last time (``memory``). All of it optional.

**Regla de oro: una clave ausente es el comportamiento de la 0.10.x.** El
bucle del protocolo 1 no pone ninguna, y con eso cada función de aquí devuelve
lo de siempre: todas las IP valen, las constantes de cada colector mandan,
nadie recibe avisos y todas las credenciales se prueban en su orden. Por eso
los tests de siempre siguen pasando sin tocarlos.

Este módulo no lleva ``@register``: no es un colector.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any

from agent import credentials as creds
from agent import net
from agent.notes import collector_note


def task(ctx: dict) -> str | None:
    """La tarea en curso, o ``None`` en el bucle del protocolo 1."""
    value = ctx.get("task")
    return str(value) if value else None


def memory(ctx: dict) -> Any:
    """La `Memory` del agente, o ``None``."""
    return ctx.get("memory")


def now() -> datetime:
    return datetime.now(timezone.utc)


def workers(ctx: dict, kind: str, default: int) -> int:
    """Cuántas conexiones a la vez (`ping`, `login`, `snmp`). Sin `workers`
    en el contexto, o con un valor que no sirve, la constante de siempre."""
    table = ctx.get("workers")
    if not isinstance(table, dict) or kind not in table:
        return default
    try:
        value = int(table[kind])
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def excluded(ctx: dict, ip: str) -> bool:
    """¿Está fuera de límites? Una exclusión que falla al mirarla excluye:
    ante la duda, no se toca."""
    rules = ctx.get("excluded")
    if rules is None:
        return False
    try:
        return ip in rules
    except Exception:  # noqa: BLE001
        return True


def wanted(ctx: dict, ip: str) -> bool:
    """¿Toca este equipo en esta pasada? Ni excluido ni fuera de `targets`."""
    if not ip:
        return False
    targets = ctx.get("targets")
    if targets is not None and ip not in set(targets):
        return False
    return not excluded(ctx, ip)


def listen_options(ctx: dict) -> dict[str, int]:
    """Los argumentos extra de `net.hosts_listening`: la suavidad de la tarea.

    Sin `workers` no hay ninguno y la llamada es exactamente la de antes (dos
    argumentos), que es lo que esperan los dobles de los tests de siempre.
    """
    if "workers" not in ctx:
        return {}
    return {"workers": workers(ctx, "ping", net.PORT_WORKERS)}


class Progress:
    """El aviso de avance de un colector: `progress(step, done, total)`.

    Llamarlo nunca lanza, aunque lo que haya detrás lance: el aviso es para el
    icono de bandeja y el checkin, y un fallo ahí no puede costar una tarea. Se
    llama desde los hilos de un `ThreadPoolExecutor`, así que cuenta con candado.
    """

    def __init__(self, ctx: dict, step: str, total: int) -> None:
        self._callback = ctx.get("progress")
        self._step = step
        self._total = max(0, int(total))
        self._done = 0
        self._lock = threading.Lock()
        self._emit(0)

    def tick(self) -> None:
        with self._lock:
            self._done += 1
            self._emit(self._done)

    def _emit(self, done: int) -> None:
        if not callable(self._callback):
            return
        try:
            self._callback(self._step, done, self._total)
        except Exception:  # noqa: BLE001 - avisar nunca rompe nada
            pass


def _guarded(call, *args, default=None, **kwargs):
    """Una llamada a la memoria que, si falla, no se lleva el colector.

    La memoria está escrita para no lanzar, pero la pone otro y es
    prescindible: perderla una pasada cuesta una ronda de credenciales, no un
    inventario.
    """
    try:
        return call(*args, **kwargs)
    except Exception:  # noqa: BLE001
        return default


def host_key(ctx: dict, ip: str, mac: str) -> str:
    mem = memory(ctx)
    if mem is not None and hasattr(mem, "key_for"):
        key = _guarded(mem.key_for, ip, mac)
        if key:
            return key
    return (mac or "").lower() or ip


def plan(
    ctx: dict, ip: str, mac: str, protocol: str, candidates: list[creds.Credential]
) -> tuple[list[creds.Credential], bool]:
    """Qué credenciales probar contra ese equipo, y si eso es la ronda entera.

    Primero el alcance (`scope`): eso vale también sin memoria. Con memoria,
    además, su orden y su veto de 24 h (`Memory.order_for`). El segundo valor
    dice si la lista es todo lo que había en alcance: solo una ronda **entera**
    fallida cuenta como tal. Si se apuntara también la de «solo la recordada»,
    la ventana de 24 h se renovaría sola mientras esa siga fallando y las
    demás no se volverían a probar nunca.
    """
    in_scope = [credential for credential in candidates if credential.covers(ip)]
    if not in_scope:
        # Un equipo que escucha y ninguna credencial lo cubre: se dice, que si
        # no ese equipo se queda en «solo responde» sin explicación.
        record(ctx, ip, protocol, NO_CREDENTIALS)
    mem = memory(ctx)
    if mem is None:
        return in_scope, True
    moment = now()
    # Apuntar el equipo antes de pedir el orden: la memoria necesita su IP para
    # comprobar el alcance cuando la clave es una MAC.
    _guarded(mem.note_host, ip, mac, moment)
    key = host_key(ctx, ip, mac)
    order = _guarded(mem.order_for, key, protocol, in_scope, moment, default=None)
    if order is None:
        return in_scope, True
    if in_scope and not order:
        # Falló una ronda entera hace menos de 24 h: hoy no se insiste.
        record(ctx, ip, protocol, RESTING)
    return list(order), len(order) == len(in_scope)


# --- Qué se intentó con cada equipo (08-10-2026) ------------------------------------------
#
# Un equipo que contesta al ping y en el que nada entra se quedaba en la bandeja
# sin un porqué: el colector solo devuelve hallazgos de lo que funcionó, y lo
# que falló contra un equipo concreto no se anotaba (sería ruido en el
# historial). Ahora se apunta por IP y protocolo, con un código y el `id` de la
# credencial, **nunca un secreto**, y viaja en `stats.attempts`; el servidor lo
# pega al hallazgo de esa IP y la web dice qué pasó con cada protocolo. Que un
# equipo no conteste a SSH no quita que conteste a SNMP: cada protocolo cuenta
# lo suyo.

#: La clave de `ctx` y la de `stats`.
ATTEMPTS = "attempts"
#: Un barrido de un /16 no puede convertir el resultado en megas.
MAX_ATTEMPTS = 4000

#: Entró (y, si es un inventario, se presentó).
LOGGED_IN = "ok"
#: Entró pero no dijo qué equipo es: ninguna orden conocida le sirvió.
UNRECOGNISED = "ok_unknown"
#: Esa credencial no le valió.
REJECTED = "auth_failed"
#: No se llegó a mandar la credencial: no contestó, cerró, o el saludo falló.
NOT_REACHED = "unreachable"
#: Solo habla un SSH antiguo que este equipo no admite.
OLD_SSH = "old_ssh"
#: El certificado no es de confianza (hipervisores).
UNTRUSTED = "tls_untrusted"
#: La credencial está suspendida por fallar demasiado (límite global).
SUSPENDED = "suspended"
#: Falló una ronda entera hace menos de 24 h; hoy no se insiste.
RESTING = "resting"
#: Escucha, pero ninguna credencial de ese protocolo lo cubre.
NO_CREDENTIALS = "no_credentials"
#: SNMP: no contestó con ninguna comunidad ni usuario.
SILENT = "silent"


def record(ctx: dict, ip: str, protocol: str, code: str, credential: creds.Credential | None = None) -> None:
    """Apunta un intento. Nunca lanza: una cifra no tumba un colector."""
    if not ip:
        return
    entry: dict[str, str] = {"ip": str(ip), "protocol": protocol, "code": code}
    if credential is not None and credential.from_server:
        entry["credential"] = credential.ident
    try:
        bucket = ctx.setdefault(ATTEMPTS, [])
        if len(bucket) < MAX_ATTEMPTS:
            bucket.append(entry)  # `append` es atómico con el GIL
    except Exception:  # noqa: BLE001
        pass


def attempts(ctx: dict) -> list[dict[str, str]]:
    found = ctx.get(ATTEMPTS)
    return list(found) if isinstance(found, list) else []


def _verdict_code(verdict: str, result: Any) -> str:
    """El código de un intento a partir de su veredicto y de lo que devolvió."""
    if verdict == OK:
        return LOGGED_IN
    error = str(getattr(result, "error", "") or "").lower()
    if "unable to negotiate" in error:
        return OLD_SSH
    if getattr(result, "certificate", None):
        return UNTRUSTED
    return REJECTED if verdict == AUTH_FAILED else NOT_REACHED


def settle(
    ctx: dict,
    ip: str,
    mac: str,
    protocol: str,
    credential: creds.Credential | None,
    *,
    attempted: bool,
    full: bool,
) -> None:
    """Apunta cómo fue: la credencial que entró, o una ronda entera fallida."""
    if credential is not None:
        note_ok(ctx, credential, ip or mac)
    mem = memory(ctx)
    if mem is None:
        return
    key = host_key(ctx, ip, mac)
    if credential is not None:
        _guarded(mem.record_success, key, protocol, credential, now())
    elif attempted and full:
        _guarded(mem.record_round_failed, key, protocol, now())


#: Lo que devuelve `Logins.run` cuando el cortacircuitos dice que no se pruebe.
SKIPPED = object()

#: Los veredictos de un intento (los mismos que `agent.memory`).
OK = "ok"
AUTH_FAILED = "auth_failed"
UNREACHABLE = "unreachable"


class Logins:
    """The logins of one collector against one host, through the credential breaker.

    Cada intento se reserva antes (`Memory.reserve`) y se cierra después con
    su veredicto (`outcome(resultado)`: `OK`, `AUTH_FAILED` o `UNREACHABLE`).
    Sin memoria en el contexto (o una que no sabe de esto), se intenta sin
    más, como siempre. Una credencial suspendida no se prueba y se anota una
    vez por ejecución (`credential_suspended`); `skipped` dice si eso pasó, y
    entonces la ronda contra ese equipo no fue entera.
    """

    def __init__(self, ctx: dict, collector: str, protocol: str, ip: str, mac: str = "", *, explicit: bool = False) -> None:
        self.ctx = ctx
        self.collector = collector
        self.protocol = protocol
        self.ip = ip
        self.explicit = explicit
        self.skipped = False
        mem = memory(ctx)
        self._memory = mem if mem is not None and hasattr(mem, "reserve") else None
        self._key = host_key(ctx, ip, mac) if self._memory is not None and (ip or mac) else ""

    def run(self, credential: creds.Credential, call: Any, outcome: Any) -> Any:
        mem = self._memory
        if mem is None:
            result = call()
            self._record(credential, outcome, result)
            return result
        remembered = bool(self._key) and _guarded(mem.remembered, self._key, self.protocol, default="") == credential.ident
        attempt = _guarded(
            mem.reserve,
            credential.ident,
            now(),
            host_key=self._key,
            remembered=remembered,
            explicit=self.explicit,
            default=False,
        )
        if attempt is False:
            result = call()  # la memoria falló: es prescindible, se intenta como siempre
            self._record(credential, outcome, result)
            return result
        if attempt is None:
            self.skipped = True
            note_suspended(self.ctx, self.collector, credential)
            record(self.ctx, self.ip, self.protocol, SUSPENDED, credential)
            return SKIPPED
        verdict = AUTH_FAILED  # ante la duda, un fallo de autenticación: es lo prudente
        result: Any = None
        try:
            result = call()
            verdict = outcome(result)
            return result
        finally:
            record(self.ctx, self.ip, self.protocol, _verdict_code(verdict, result), credential)
            if _guarded(mem.finish, attempt, verdict, now(), default=False):
                note_suspended(self.ctx, self.collector, credential)

    def _record(self, credential: creds.Credential, outcome: Any, result: Any) -> None:
        verdict = _guarded(outcome, result, default=AUTH_FAILED)
        record(self.ctx, self.ip, self.protocol, _verdict_code(verdict, result), credential)


_NOTED_LOCK = threading.Lock()


def note_suspended(ctx: dict, collector: str, credential: creds.Credential) -> None:
    """La nota `credential_suspended`, una sola vez por credencial y ejecución."""
    with _NOTED_LOCK:
        noted = ctx.setdefault("_suspended_noted", set())
        if credential.ident in noted:
            return
        noted.add(credential.ident)
    mem = memory(ctx)
    failures = _guarded(mem.failures, credential.ident, default=0) if mem is not None else 0
    name = credential.label or credential.username
    ctx.setdefault("errors", []).append(
        collector_note(
            collector,
            "credential_suspended",
            f"la credencial «{name}» ha fallado {failures} veces y no se volverá a probar hasta que "
            "se cambie en Ajustes -> Agentes o pasen 24 horas",
            name=name,
            failures=failures,
        )
    )


#: La clave de `ctx` con lo que entró en esta ejecución: ``{id: {equipos}}``.
CREDENTIALS_OK = "credentials_ok"


def note_ok(ctx: dict, credential: creds.Credential, host: str) -> None:
    """Esa credencial entró en ese equipo: para `stats.credentials_ok` (spec 3.2).

    Solo las que traen `id` del servidor: de una derivada (o de una comunidad
    de la lista vieja) el servidor no sabría qué hacer. Un equipo cuenta una
    vez aunque dos colectores entren con la misma. Se llama desde los hilos de
    un colector: `setdefault` y `set.add` son atómicos con el GIL.
    """
    if not credential.from_server or not host:
        return
    try:
        ctx.setdefault(CREDENTIALS_OK, {}).setdefault(credential.ident, set()).add(host)
    except Exception:  # noqa: BLE001 - una cifra no tumba un colector
        pass


def credentials_ok(ctx: dict) -> dict[str, int]:
    """``{id: nº de equipos}`` de esta ejecución."""
    found = ctx.get(CREDENTIALS_OK)
    if not isinstance(found, dict):
        return {}
    return {ident: len(hosts) for ident, hosts in found.items() if hosts}


def flag(ctx: dict, ip: str, mac: str, **flags: Any) -> None:
    """`Memory.flag` sobre el equipo de esa IP, si hay memoria."""
    mem = memory(ctx)
    if mem is None:
        return
    _guarded(mem.note_host, ip, mac, now())
    _guarded(mem.flag, host_key(ctx, ip, mac), **flags)


def alive_from_memory(ctx: dict, remembered: list[dict]) -> list[tuple[str, str, dict]]:
    """Los equipos que la memoria señala y que **siguen vivos** en esta pasada.

    Se casan por MAC primero (un equipo que cambió de IP sigue siendo él) y
    por IP después. La IP que se usa es la de ahora, no la que se apuntó.
    Devuelve ``(ip, mac, entrada)`` sin excluidos ni fuera de `targets`.
    """
    hosts = ctx.get("hosts") or []
    by_mac = {str(host.get("mac") or "").lower(): host for host in hosts if host.get("mac")}
    by_ip = {host["ip"]: host for host in hosts if host.get("ip")}
    found: list[tuple[str, str, dict]] = []
    seen: set[str] = set()
    for entry in remembered:
        host = by_mac.get(str(entry.get("mac") or "").lower()) if entry.get("mac") else None
        if host is None:
            host = by_ip.get(entry.get("ip", ""))
        if host is None:
            continue
        ip = host["ip"]
        if ip in seen or not wanted(ctx, ip):
            continue
        seen.add(ip)
        found.append((ip, str(host.get("mac") or ""), entry))
    return found
