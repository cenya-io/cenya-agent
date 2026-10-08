"""The tasks of protocol 2 and the collectors each one runs (spec 2.1 and 2.5).

A task is a named subset of the collectors that always existed, run with
``ctx["task"]`` set so each collector knows which part of its job is wanted
(``ssh`` in ``configs`` only copies; ``snmp`` in ``ups`` only asks the
UPS-MIB). The collectors themselves do not change shape: ``collect(ctx)``.

What ran before is kept: a collector that raises does not kill the task, it
leaves a ``crashed`` note exactly as the protocol-1 loop does, and the rest of
the findings still go up.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agent import credentials as creds
from agent.collectors import all_collectors, tasking
from agent.notes import Note, collector_note
from agent.scheduler import CONFIGS, HYPERVISORS, INVENTORY, PRESENCE, UPS

#: Tarea → colectores (spec 2.1). El orden lo sigue mandando `RUN_ORDER`.
TASK_COLLECTORS: dict[str, tuple[str, ...]] = {
    PRESENCE: ("local", "sweep"),
    INVENTORY: ("fingerprint", "snmp", "ssh", "winrm"),
    CONFIGS: ("ssh",),
    UPS: ("snmp",),
    HYPERVISORS: ("hypervisors",),
}

#: Cuántas conexiones a la vez según la suavidad (spec 2.5).
GENTLENESS: dict[str, dict[str, int]] = {
    "gentle": {"ping": 8, "login": 2, "snmp": 5},
    "normal": {"ping": 50, "login": 10, "snmp": 20},
    "fast": {"ping": 100, "login": 20, "snmp": 40},
}
GENTLENESS_ORDER = ("gentle", "normal", "fast")
DEFAULT_GENTLENESS = "normal"


def gentleness(server: object, cap: str = "") -> str:
    """La suavidad que vale: la del servidor, bajada al tope local si lo hay.

    El ajuste local puede bajarla, nunca subirla: quien está en la máquina
    sabe que la red de la planta no aguanta cien pings a la vez, pero no puede
    convertir un «suave» decidido en la web en un «rápido».
    """
    level = server if isinstance(server, str) and server in GENTLENESS else DEFAULT_GENTLENESS
    if cap in GENTLENESS and GENTLENESS_ORDER.index(cap) < GENTLENESS_ORDER.index(level):
        return cap
    return level


def workers_for(server: object, cap: str = "") -> dict[str, int]:
    """`ctx["workers"]` para esa suavidad."""
    return dict(GENTLENESS[gentleness(server, cap)])


def _safe_progress(ctx: dict) -> Callable[[str, int, int], None]:
    """El aviso de avance del bucle, con la promesa de 2.2: llamarlo nunca lanza."""
    report = ctx.get("progress")

    def progress(step: str, done: int, total: int) -> None:
        if report is None:
            return
        try:
            report(step, done, total)
        except Exception:  # noqa: BLE001 - un aviso roto no para un colector
            pass

    return progress


def run_task(name: str, ctx: dict) -> tuple[list[dict[str, Any]], list[Note | str], dict[str, Any]]:
    """Corre los colectores de la tarea `name` sobre `ctx`.

    Devuelve los hallazgos (ya en JSON), las notas (`ctx["errors"]`) y las
    cifras de la ejecución. `stats["crashed"]` cuenta los colectores que
    lanzaron: si son todos, la ejecución no sirvió de nada y el bucle la da por
    fallida, no por parcial.
    """
    wanted = TASK_COLLECTORS.get(name, ())
    ctx["task"] = name
    ctx.setdefault("errors", [])
    progress = _safe_progress(ctx)
    ctx["progress"] = progress
    collectors = [collector for collector in all_collectors() if collector.name in wanted]
    items: list[dict[str, Any]] = []
    crashed = 0
    for index, collector in enumerate(collectors):
        progress(collector.name, index, len(collectors))
        try:
            items.extend(finding.as_json() for finding in collector.collect(ctx))
        except Exception as exc:  # noqa: BLE001 - un colector roto, no una tarea muerta
            crashed += 1
            ctx["errors"].append(
                collector_note(collector.name, "crashed", str(exc), detail=f"{type(exc).__name__}: {exc}")
            )
    progress("", len(collectors), len(collectors))
    sealed_note(ctx)
    stats: dict[str, Any] = {"collectors": len(collectors), "items": len(items), "crashed": crashed}
    if name == PRESENCE:
        stats["hosts_alive"] = len(ctx.get("hosts") or [])
    worked = tasking.credentials_ok(ctx)
    if worked:
        stats["credentials_ok"] = worked
    tried = tasking.attempts(ctx)
    if tried:
        # Qué se intentó con cada equipo y qué pasó (`tasking.record`); el
        # servidor lo pega al hallazgo de cada IP.
        stats[tasking.ATTEMPTS] = tried
    return items, list(ctx["errors"]), stats


def sealed_note(ctx: dict) -> None:
    """Una sola nota por ejecución con las credenciales selladas que no se pudieron usar.

    Un sobre que no abre no es un error del barrido (spec 3.1): esa credencial
    no se usa y se dice cuántas fueron, sin nombrarlas -- el servidor sabe
    cuáles mandó y la web puede ofrecer volver a teclearlas.
    """
    opener = ctx.get(creds.CTX_KEY)
    if not isinstance(opener, creds.Unsealer):
        return
    count = opener.unreadable
    if count:
        ctx.setdefault("errors", []).append(
            collector_note(
                "credentials",
                "sealed_unreadable",
                f"{count} credencial(es) sellada(s) no se pueden abrir en este agente; no se usan",
                count=count,
            )
        )
