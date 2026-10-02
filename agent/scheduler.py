"""What runs next, and when: the agent's task queue (spec 1.4 and 2.1).

Pure logic, on purpose: no clock of its own, no threads, no I/O. Whoever calls
it says what time it is, whether the agent is paused and what happened; it
answers with the next job. That is what lets every rule below be tested in a
millisecond, including the ones that would take a week to see happen.

The rules:

* **One task at a time**, in a queue. Orders from a person (``run_task``) go
  first, before anything scheduled; among themselves, in arrival order.
* **Each task has its own cadence** (``config.tasks.<task>.every_seconds``),
  bounded to [60, 604800] for ``presence`` and ``ups`` and [300, 604800] for
  the rest; ``0`` switches the task off.
* **``inventory``, ``configs`` and ``ups`` need fresh presence**: the live hosts
  of a presence that finished less than two presence periods ago. If there is
  none, a presence runs first -- and pushes its own result -- and the task
  that needed it stays where it was.
* **New hosts trigger an inventory of just them** (``trigger: "new_host"``),
  unless a full inventory is about to run anyway.
* **A pause stops scheduled work, not orders**: an order is a person asking.
  The task in progress always finishes; that is the caller's business.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

PRESENCE = "presence"
INVENTORY = "inventory"
CONFIGS = "configs"
UPS = "ups"
HYPERVISORS = "hypervisors"

#: Todas las tareas, en el orden en que se desempatan: a igualdad de retraso,
#: primero la presencia, que es de la que dependen las demás.
TASKS: tuple[str, ...] = (PRESENCE, INVENTORY, CONFIGS, UPS, HYPERVISORS)

#: Los valores del ejemplo de la especificación (1.4): los que valen mientras
#: el servidor no diga otra cosa.
DEFAULT_EVERY: dict[str, int] = {
    PRESENCE: 300,
    INVENTORY: 21600,
    CONFIGS: 86400,
    UPS: 300,
    HYPERVISORS: 3600,
}

#: Las tareas ligeras, que pueden ir cada minuto; las demás, como poco cada cinco.
FREQUENT_TASKS = frozenset({PRESENCE, UPS})
MIN_FREQUENT_SECONDS = 60
MIN_SECONDS = 300
MAX_SECONDS = 604800

#: Las que trabajan sobre los vivos de una presencia.
NEEDS_PRESENCE = frozenset({INVENTORY, CONFIGS, UPS})
#: «Fresca» es de hace menos de este número de periodos de presencia.
PRESENCE_FRESH_PERIODS = 2

TRIGGER_SCHEDULE = "schedule"
TRIGGER_ORDER = "order"
TRIGGER_NEW_HOST = "new_host"


def every_seconds(tasks_config: Any, task: str) -> int:
    """La cadencia de `task` en segundos, acotada; `0` si está desactivada.

    Un valor que no se entiende (texto, negativo, ausente) es el de por
    defecto: un dato raro del servidor no puede dejar al agente sin tareas,
    ni martillear la red cada segundo.
    """
    default = DEFAULT_EVERY[task]
    entry = tasks_config.get(task) if isinstance(tasks_config, dict) else None
    raw = entry.get("every_seconds") if isinstance(entry, dict) else None
    if isinstance(raw, bool):
        return default
    try:
        seconds = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    if seconds == 0:
        return 0
    if seconds < 0:
        return default
    floor = MIN_FREQUENT_SECONDS if task in FREQUENT_TASKS else MIN_SECONDS
    return max(floor, min(seconds, MAX_SECONDS))


def effective_pause(local: datetime | None, server: datetime | None) -> datetime | None:
    """La más tardía de las dos pausas (spec 1.2), o `None` sin ninguna."""
    moments = [moment for moment in (local, server) if moment is not None]
    return max(moments) if moments else None


def is_paused(now: datetime, until: datetime | None) -> bool:
    return until is not None and now < until


@dataclass(frozen=True)
class Job:
    """Una tarea que correr y por qué."""

    task: str
    trigger: str = TRIGGER_SCHEDULE
    order_id: str | None = None
    #: Solo esas IP (`ctx["targets"]`); `None` es «todas».
    targets: tuple[str, ...] | None = None

    @property
    def is_order(self) -> bool:
        return self.trigger == TRIGGER_ORDER


@dataclass
class _Record:
    last_finished_at: datetime | None = None
    last_status: str | None = None


class Scheduler:
    """La cola. No es segura entre hilos: quien la comparte pone el cerrojo."""

    def __init__(self, tasks_config: Any = None) -> None:
        self._every: dict[str, int] = {}
        self._records = {task: _Record() for task in TASKS}
        self._queue: list[Job] = []
        self._presence_at: datetime | None = None
        self.configure(tasks_config)

    # --- Configuración y cola ----------------------------------------------------

    def configure(self, tasks_config: Any) -> None:
        self._every = {task: every_seconds(tasks_config, task) for task in TASKS}

    def every(self, task: str) -> int:
        return self._every.get(task, 0)

    @property
    def queued(self) -> tuple[Job, ...]:
        return tuple(self._queue)

    def add_order(self, job: Job) -> None:
        """Un encargo entra el primero, pero detrás de los encargos que ya esperan."""
        position = 0
        while position < len(self._queue) and self._queue[position].is_order:
            position += 1
        self._queue.insert(position, job)

    def clear_queue(self) -> None:
        """Olvida lo que esperaba: encargos y equipos nuevos (un token revocado)."""
        self._queue.clear()

    def add_new_hosts(self, ips: list[str], now: datetime) -> Job | None:
        """Tras una presencia, un inventario solo de los nuevos. Devuelve el que queda en cola.

        No hace falta cuando el inventario está apagado (la persona no lo
        quiere), ni cuando uno completo va a correr de todas formas: ya les toca
        o hay un encargo de inventario esperando. Si ya había uno de nuevos en
        la cola, los suma a ese en vez de abrir otro.
        """
        ips = [ip for ip in dict.fromkeys(ips) if ip]
        if not ips or not self.every(INVENTORY):
            return None
        if self.due(INVENTORY, now) or any(j.task == INVENTORY and j.targets is None for j in self._queue):
            return None
        for index, job in enumerate(self._queue):
            if job.trigger == TRIGGER_NEW_HOST:
                merged = Job(INVENTORY, TRIGGER_NEW_HOST, targets=tuple(dict.fromkeys([*(job.targets or ()), *ips])))
                self._queue[index] = merged
                return merged
        job = Job(INVENTORY, TRIGGER_NEW_HOST, targets=tuple(ips))
        self._queue.append(job)
        return job

    def finished(self, job: Job, at: datetime, status: str) -> None:
        """Anota que `job` terminó. Un inventario de solo unos pocos no mueve la cadencia."""
        if job.task == PRESENCE:
            # Con cualquier estado: una presencia fallida tampoco se repite
            # en bucle delante de cada inventario.
            self._presence_at = at
        if job.targets is not None:
            return
        record = self._records[job.task]
        record.last_finished_at = at
        record.last_status = status

    # --- Cuándo ------------------------------------------------------------------

    def next_at(self, task: str, now: datetime) -> datetime | None:
        """Cuándo le toca a `task` por calendario; `None` si está apagada."""
        every = self.every(task)
        if not every:
            return None
        last = self._records[task].last_finished_at
        return now if last is None else last + timedelta(seconds=every)

    def due(self, task: str, now: datetime) -> bool:
        moment = self.next_at(task, now)
        return moment is not None and moment <= now

    def presence_fresh(self, now: datetime) -> bool:
        """Si los vivos de la última presencia valen todavía.

        Con la presencia apagada, el periodo de referencia es el suyo por
        defecto: las tareas que necesitan vivos los siguen necesitando, y
        sacarlos de una presencia de hace un mes sería inventariar fantasmas.
        """
        if self._presence_at is None:
            return False
        period = self.every(PRESENCE) or DEFAULT_EVERY[PRESENCE]
        return now - self._presence_at < timedelta(seconds=period * PRESENCE_FRESH_PERIODS)

    def next_job(self, now: datetime, *, paused: bool = False) -> Job | None:
        """La siguiente tarea que correr ahora, o `None` si no toca nada.

        Lo que sale de la cola se quita de ella; lo que solo «toca» por
        calendario no está en ninguna cola y no hace falta quitarlo: deja de
        tocar cuando se anota con `finished`.
        """
        picked: Job | None = None
        from_queue = False
        for job in self._queue:
            if job.is_order or not paused:
                picked, from_queue = job, True
                break
        if picked is None and not paused:
            due = [task for task in TASKS if self.due(task, now)]
            if due:
                # El más atrasado primero; a igualdad, el orden de `TASKS`.
                task = min(due, key=lambda t: (self.next_at(t, now), TASKS.index(t)))
                picked = Job(task)
        if picked is None:
            return None
        if picked.task in NEEDS_PRESENCE and picked.targets is None and not self.presence_fresh(now):
            # La tarea espera donde estaba; antes, la presencia que necesita,
            # con el mismo motivo (un encargo sigue siendo un encargo).
            return Job(PRESENCE, picked.trigger, order_id=picked.order_id)
        if from_queue:
            self._queue.remove(picked)
        return picked

    def seconds_until_next(self, now: datetime, *, paused: bool = False) -> float | None:
        """Cuánto falta para la siguiente tarea; `None` si nada tiene hora."""
        if any(job.is_order or not paused for job in self._queue):
            return 0.0
        if paused:
            return None
        moments = [m for m in (self.next_at(task, now) for task in TASKS) if m is not None]
        if not moments:
            return None
        return max(0.0, (min(moments) - now).total_seconds())

    def view(self, now: datetime) -> list[dict[str, Any]]:
        """El calendario tal como lo pide el checkin (spec 1.2)."""
        rows: list[dict[str, Any]] = []
        for task in TASKS:
            record = self._records[task]
            upcoming = self.next_at(task, now)
            rows.append(
                {
                    "task": task,
                    "every_seconds": self.every(task),
                    "last_finished_at": record.last_finished_at.isoformat() if record.last_finished_at else None,
                    "last_status": record.last_status,
                    "next_at": upcoming.isoformat() if upcoming else None,
                }
            )
        return rows
