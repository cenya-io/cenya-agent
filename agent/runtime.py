"""The protocol-2 agent: a service with tasks (``docs/agente-v2-nucleo.md``, 2).

Two threads and a queue:

* **The control thread** (`agent.control`) checks in every ~30 s, also while a
  task runs: it brings the configuration, the orders and the pause, and
  empties the outbox.
* **The task thread** (this module's `Runtime.run`, which is the caller's
  thread) takes the next job from the scheduler (`agent.scheduler`), runs it
  (`agent.tasks`) and pushes *its* result at once. If the push fails, the
  result goes to the outbox and the next task does not wait.

Stopping keeps the promise of the protocol-1 loop: the task in progress
finishes (cutting an SNMP walk in half saves nothing), nothing new starts, and
waiting stops at once.

What the agent learns between tasks -- the live hosts of the last presence --
lives here, in memory; what must survive a restart is in `agent.memory` and in
the outbox.
"""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from agent import __version__, about, logs, notes, outbox, probe, status, store, tasks
from agent import settings as local_settings
from agent.client import AgentClient, PushError, result_parts
from agent.config import Config
from agent.control import REFUSED_UNAUTHORIZED, Control, Hooks, Shared
from agent.i18n import _t, _tn
from agent.memory import Excluded, Memory
from agent.notes import collector_note
from agent.scheduler import PRESENCE, Job, Scheduler, effective_pause, is_paused

MEMORY_FILE = "memory.json"

#: Cada cuánto se recalcula el `about`: las redes de una máquina cambian poco,
#: y leerlas en cada checkin sería trabajo para nada.
ABOUT_TTL_SECONDS = 300

#: El mayor sorbo de espera entre tareas, y cada cuánto se mira si hay que
#: parar mientras tanto. Un segundo es «en el acto» para quien pulsa Detener.
MAX_IDLE_SECONDS = 60
TICK_SECONDS = 1.0

#: Cada cuánto, como mucho, se reescribe el paso en el fichero de estado: un
#: colector puede avisar de su avance por cada equipo.
STEP_WRITE_SECONDS = 2.0

V2 = "v2"
V1 = "v1"
UNKNOWN = "unknown"

STOPPED = "stopped"
FALLBACK = "fallback"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load_memory(path: Any) -> Memory | None:
    """La memoria del agente (spec 2.3). `Memory.load` no lanza: un fichero
    roto es una memoria vacía. El `None` queda para lo que no se puede prever:
    prescindible por diseño, sin ella el agente funciona como sin pasado."""
    try:
        return Memory.load(path)
    except Exception:  # noqa: BLE001
        return None


def _excluded_for(settings: local_settings.Settings) -> Excluded | None:
    if not settings.excluded_subnets and not settings.excluded_addresses:
        return None
    return Excluded(list(settings.excluded_subnets), list(settings.excluded_addresses))


def task_line(task: str, created: int, refreshed: int) -> str:
    """«[agente] presence enviado: 3 hallazgos nuevos, 10 ya conocidos.», en su idioma."""
    return _t("[agente] Tarea %(task)s enviada: %(created)s, %(refreshed)s") % {
        "task": task,
        "created": _tn("%(n)d hallazgo nuevo", "%(n)d hallazgos nuevos", created) % {"n": created},
        "refreshed": _tn("%(n)d ya conocido.", "%(n)d ya conocidos.", refreshed) % {"n": refreshed},
    }


class _NeverSet:
    """Un `stop_event` para la consola, donde nadie para el bucle desde fuera."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def is_set(self) -> bool:
        return self._event.is_set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)


class Runtime:
    def __init__(
        self,
        client: AgentClient,
        env: Config,
        *,
        environ: Mapping[str, str] | None = None,
        clock: Callable[[], datetime] = _now,
        report: bool = True,
        say: Callable[[str], None] | None = None,
        once: bool = False,
    ) -> None:
        self.client = client
        self.env = env
        self._environ = environ
        self._clock = clock
        self._report = report
        self._say = say or logs.info
        base = store.state_dir(environ)
        self.settings = local_settings.load(environ)
        self.shared = Shared()
        self.scheduler = Scheduler()
        #: Guarda la cola y los vivos: los tocan los dos hilos.
        self._lock = threading.Lock()
        self._hosts: list[dict[str, Any]] = []
        # `--once` (`once`) puede correr con el servicio en marcha en la misma
        # máquina: ni su cola de envíos (que vaciaría y cuyos temporales
        # borraría) ni su memoria en disco (que pisaría) son suyas. Lee la
        # memoria, pero trabaja sobre una copia que no guarda.
        self.outbox: outbox.Outbox | outbox.NullOutbox = (
            outbox.NullOutbox() if once else outbox.Outbox(base / outbox.FOLDER)
        )
        self.memory = _load_memory(base / MEMORY_FILE)
        if once and self.memory is not None:
            self.memory.detach()
        self.excluded = _excluded_for(self.settings)
        self._about: tuple[float, dict[str, Any]] | None = None
        self._step_written = 0.0
        self.tick = TICK_SECONDS
        self.control = Control(
            client,
            self.shared,
            self.outbox,
            Hooks(
                about=self.about,
                schedule=self._schedule,
                local_pause=self._local_pause,
                run_task=self._queue_order,
                config_changed=self._config_changed,
                probe=self._probe,
                excluded=self._is_excluded,
                rejected=self._rejected,
            ),
            clock=clock,
            report=report,
            take_orders=not once,
        )

    # --- Lo que pide el canal de control --------------------------------------------

    def about(self) -> dict[str, Any]:
        cached = self._about
        if cached is not None and time.monotonic() - cached[0] < ABOUT_TTL_SECONDS:
            return cached[1]
        data = about.build(
            excluded_subnets=self.settings.excluded_subnets,
            excluded_addresses=self.settings.excluded_addresses,
            auto_update=self.settings.auto_update,
        )
        self._about = (time.monotonic(), data)
        return data

    def _schedule(self, now: datetime) -> list[dict[str, Any]]:
        with self._lock:
            return self.scheduler.view(now)

    def _local_pause(self) -> datetime | None:
        # Se relee cada vez: quien pausa en esta máquina escribe el fichero
        # (el icono, en la fase 5) y no tiene otra forma de avisar al servicio.
        return local_settings.load(self._environ).paused_until

    def _queue_order(self, job: Job) -> None:
        with self._lock:
            self.scheduler.add_order(job)

    def _config_changed(self, etag: str) -> None:
        config, _ = self.shared.config_snapshot()
        with self._lock:
            self.scheduler.configure(config.get("tasks"))
        if self.memory is not None:
            try:
                self.memory.credentials_changed(etag)
            except Exception:  # noqa: BLE001 - la memoria es prescindible
                pass

    def _is_excluded(self, ip: str) -> bool:
        return self.excluded is not None and ip in self.excluded

    def _rejected(self) -> None:
        """El servidor ya no quiere a este agente: lo que esperaba en la cola, fuera."""
        with self._lock:
            self.scheduler.clear_queue()

    def _probe(self, ip: str) -> dict[str, Any]:
        if self.shared.refused() == REFUSED_UNAUTHORIZED:
            raise RuntimeError("el servidor ha rechazado a este agente")
        config, _ = self.shared.config_snapshot()
        return probe.report_for(ip, self._base_ctx(config))

    # --- Negociar ------------------------------------------------------------------

    def negotiate(self) -> str:
        """Un primer checkin para saber qué habla el servidor: `v2`, `v1` o `unknown`.

        Un 404 es un servidor del protocolo 1 (spec 1.8) si su latido del
        protocolo 1 contesta; si no, es un servidor que no está bien y no se
        sabe. Una respuesta que no dice `protocol` ≥ 2 también se toma por
        protocolo 1: un servidor 2 siempre lo dice. Sin respuesta (la red
        caída) no se sabe: quien llama arranca el protocolo 2, y el primer 404
        confirmado lo devolverá al 1.
        """
        try:
            body, about_hash = self.control.body(self._clock())
            answer = self.client.checkin(body)
        except PushError as exc:
            if exc.status == 404 and self.control.speaks_only_protocol_1():
                return V1
            return UNKNOWN
        except Exception:  # noqa: BLE001
            return UNKNOWN
        if not isinstance(answer, dict):
            return V1
        try:
            protocol = int(answer.get("protocol") or 1)
        except (TypeError, ValueError):
            protocol = 1
        if protocol < 2:
            return V1
        self.control.gone = False
        self.control.accept(answer, body, about_hash)
        return V2

    # --- El bucle ------------------------------------------------------------------

    def run(self, stop_event: Any = None) -> str:
        """Corre hasta que paren (`stopped`) o el servidor resulte ser del protocolo 1 (`fallback`)."""
        stop = stop_event if stop_event is not None else _NeverSet()
        thread = threading.Thread(target=self.control.run, args=(stop,), name="cenya-control", daemon=True)
        thread.start()
        try:
            while not stop.is_set() and not self.control.gone:
                job = self.next_job()
                if job is None:
                    self._idle(stop)
                    continue
                try:
                    self.run_job(job)
                except Exception as exc:  # noqa: BLE001 - una tarea rota no tumba el bucle
                    self._say(_t("[agente] %(error)s") % {"error": _unexpected(exc)})
        finally:
            # Sin esperar a un checkin a medias: el hilo es de fondo y lo que
            # tenga pendiente se repite en el próximo arranque.
            thread.join(timeout=0.1)
        return FALLBACK if self.control.gone and not stop.is_set() else STOPPED

    def next_job(self) -> Job | None:
        with self.shared.lock:
            if not self.shared.has_config:
                return None  # sin configuración no hay qué barrer ni con qué
            if self.shared.refusal:
                # 401 o 402: ni lo programado ni los encargos. Con un 402 lo
                # que espera en la cola se queda para cuando vuelva a aceptar.
                return None
            server_pause = self.shared.server_paused_until
        now = self._clock()
        paused = is_paused(now, effective_pause(self._local_pause(), server_pause))
        with self._lock:
            return self.scheduler.next_job(now, paused=paused)

    def _idle(self, stop: Any) -> None:
        """Espera a la siguiente tarea, a sorbos, despertando si llega algo."""
        now = self._clock()
        with self.shared.lock:
            # Rechazado, nada puede empezar: se espera al próximo checkin bueno
            # (que despierta este hilo), no a la hora de la siguiente tarea.
            has_config = self.shared.has_config and not self.shared.refusal
            server_pause = self.shared.server_paused_until
        until = effective_pause(self._local_pause(), server_pause)
        paused = is_paused(now, until)
        with self._lock:
            seconds = self.scheduler.seconds_until_next(now, paused=paused) if has_config else None
        if seconds is None:
            seconds = MAX_IDLE_SECONDS
        seconds = min(max(seconds, 0.0), MAX_IDLE_SECONDS)
        if self._report:
            status.idle(next_in=int(seconds) if has_config and not paused else None,
                        paused_until=until.isoformat() if paused and until else None)
        waited = 0.0
        while waited < seconds and not stop.is_set() and not self.control.gone:
            chunk = min(self.tick, seconds - waited)
            if self.shared.wake.wait(chunk):
                self.shared.wake.clear()
                return
            waited += chunk

    # --- Una tarea -------------------------------------------------------------------

    def _base_ctx(self, config: dict[str, Any]) -> dict[str, Any]:
        return {
            "config": config,
            "env": self.env,
            "memory": self.memory,
            "workers": tasks.workers_for(config.get("gentleness"), self.settings.gentleness_cap),
            "excluded": self.excluded,
            "errors": [],
        }

    def build_ctx(self, job: Job, config: dict[str, Any]) -> dict[str, Any]:
        """El `ctx` de spec 2.2 para esa tarea."""
        ctx = self._base_ctx(config)
        ctx["task"] = job.task
        ctx["targets"] = list(job.targets) if job.targets is not None else None
        ctx["progress"] = self._progress
        if job.task != PRESENCE:
            # Los vivos de la última presencia (la presencia los pone ella).
            with self._lock:
                hosts = [dict(host) for host in self._hosts]
            if self.excluded is not None:
                hosts = [host for host in hosts if host.get("ip") not in self.excluded]
            if job.targets is not None:
                wanted = set(job.targets)
                hosts = [host for host in hosts if host.get("ip") in wanted]
            ctx["hosts"] = hosts
        return ctx

    def _progress(self, step: str, done: int, total: int) -> None:
        self.shared.update_activity(step=step, done=done, total=total)
        if not self._report:
            return
        moment = time.monotonic()
        if moment - self._step_written >= STEP_WRITE_SECONDS or not step:
            self._step_written = moment
            activity = self.shared.activity_snapshot() or {}
            status.task_step(str(activity.get("task") or ""), step)

    def _note_hosts(self, hosts: list[dict[str, Any]], now: datetime) -> list[str]:
        """Anota los vivos en la memoria. Devuelve las IP de los que no conocía."""
        if self.memory is None:
            return []
        new: list[str] = []
        for host in hosts:
            ip = str(host.get("ip") or "")
            if not ip:
                continue
            try:
                if self.memory.note_host(ip, str(host.get("mac") or ""), now):
                    new.append(ip)
            except Exception:  # noqa: BLE001
                continue
        return new

    def run_job(self, job: Job, *, strict: bool = False) -> dict[str, Any]:
        """Corre una tarea y empuja su resultado. Devuelve el `run`.

        Con `strict` (`--once`) el envío no pasa por la cola: si falla, lanza.
        """
        started = self._clock()
        run_id = str(uuid.uuid4())
        self.shared.set_activity(
            {"task": job.task, "run_id": run_id, "step": "", "done": 0, "total": 0, "started_at": started.isoformat()}
        )
        if self._report:
            status.task_started(job.task)
        config, _ = self.shared.config_snapshot()
        ctx = self.build_ctx(job, config)
        try:
            items, entries, stats = tasks.run_task(job.task, ctx)
            crashed_all = stats.get("collectors", 0) > 0 and stats.get("crashed") == stats.get("collectors")
        except Exception as exc:  # noqa: BLE001 - run_task no debería lanzar; si lo hace, error y sigue
            items, stats, crashed_all = [], {}, True
            entries = [collector_note(job.task, "crashed", str(exc), detail=f"{type(exc).__name__}: {exc}")]
        finished = self._clock()
        new: list[str] = []
        if job.task == PRESENCE:
            hosts = [h for h in (ctx.get("hosts") or []) if isinstance(h, dict)]
            with self._lock:
                self._hosts = hosts
            new = self._note_hosts(hosts, finished)
            stats["new_hosts"] = len(new)
        if self.memory is not None:
            try:
                self.memory.save()
            except Exception:  # noqa: BLE001
                pass
        entries = [*entries, *self.outbox.take_notes()]
        outcome = "error" if crashed_all else ("partial" if entries else "ok")
        with self._lock:
            self.scheduler.finished(job, finished, outcome)
            # Después de anotar la presencia: el inventario de los nuevos se
            # decide sabiendo que los vivos ya están frescos.
            self.scheduler.add_new_hosts(new, finished)
        run = {
            "id": run_id,
            "task": job.task,
            "trigger": job.trigger,
            "order_id": job.order_id,
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "status": outcome,
            # Como en el protocolo 1: el texto en castellano para un servidor
            # que no conozca un código, y las notas para que la web las traduzca.
            "notes": [notes.to_json(entry) for entry in entries],
            "error": "; ".join(str(entry) for entry in entries),
            "stats": stats,
            "agent_version": __version__,
        }
        self.shared.set_activity(None)
        answer = self._deliver(run, items, strict=strict)
        if self._report:
            with self._lock:
                wait = self.scheduler.seconds_until_next(self._clock())
            status.task_finished(
                task=job.task,
                created=int((answer or {}).get("created") or 0),
                refreshed=int((answer or {}).get("refreshed") or 0),
                errors=[str(entry) for entry in entries],
                next_in=int(wait) if wait is not None else None,
            )
        return run

    def _deliver(self, run: dict[str, Any], items: list[dict[str, Any]], *, strict: bool) -> dict[str, Any] | None:
        """Empuja el resultado; lo que no sale va a la cola local."""
        if strict:
            answer = self.client.push_results(run=run, items=items)
            self._say(task_line(run["task"], int(answer.get("created") or 0), int(answer.get("refreshed") or 0)))
            return answer
        if self.outbox.count():
            # Lo de antes sale antes: esta va detrás, y la cola se vacía en el
            # próximo checkin que salga bien.
            pending = result_parts(run, items)
        else:
            try:
                answer = self.client.push_results(run=run, items=items)
            except Exception as exc:  # noqa: BLE001
                pending = getattr(exc, "remaining", None) or result_parts(run, items)
            else:
                self._say(task_line(run["task"], int(answer.get("created") or 0), int(answer.get("refreshed") or 0)))
                return answer
        for body in pending:
            self.outbox.put_result(body)
        self._say(_t("[agente] Tarea %(task)s guardada en la cola local: se enviará cuando el servidor conteste.") % {"task": run["task"]})
        return None

    # --- `--once` --------------------------------------------------------------------

    def once(self) -> None:
        """Una presencia y un inventario, empujados al momento. Para probar a mano."""
        for task in (PRESENCE, "inventory"):
            self.run_job(Job(task), strict=True)


def _unexpected(exc: BaseException) -> str:
    return _t("Error inesperado: %(error)s") % {"error": f"{type(exc).__name__}: {exc}"}
