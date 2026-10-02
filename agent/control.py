"""The control channel of protocol 2: the check-in and the orders (spec 1.2, 1.3).

Every ``checkin_seconds`` (30 by default) the agent says what it is doing and
the server answers with what changed: a new configuration (only when its etag
differs), orders, a pause set from the web, a newer version. It runs in its own
thread, **also in the middle of a task**: that is what lets a person see a long
inventory advance, pause the agent or ask for an analysis without waiting for
the end of a sweep.

The rules that matter:

* **An order runs once.** The server repeats it in every answer until the
  agent answers it; the agent remembers what it took (and what is waiting in
  the outbox, across a restart) and does not take it twice.
* **Every order gets an answer.** An unknown kind is ``unsupported``, so a
  server newer than the agent never waits for nothing. ``run_task`` is answered
  ``done`` when accepted; the task's findings arrive as its result. An answer
  that cannot be sent goes to the outbox and is retried.
* **Nothing kills the thread.** A failed check-in is a line in the log and
  another try at the next tick. The one answer that changes course is a 404
  from ``v2/checkin`` *confirmed* by a protocol-1 heartbeat that works: the
  server only speaks protocol 1 (spec 1.8). A 404 with a failing heartbeat is
  a server that is unwell, not an old one.

The logic is in methods that can be called one at a time (``checkin_once``,
``handle_order``), so the tests drive it without threads or clocks.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from agent import __version__, logs, notes, status
from agent.client import PROTOCOL, AgentClient, PushError
from agent.i18n import _t
from agent.notes import Note, collector_note
from agent.outbox import KIND_ORDER, Entry, Outbox
from agent.scheduler import TASKS, TRIGGER_ORDER, Job, effective_pause, is_paused

CHECKIN_SECONDS = 30
MIN_CHECKIN_SECONDS = 10
MAX_CHECKIN_SECONDS = 300

#: Cuántos encargos atendidos se recuerdan. El servidor los caduca en 24 h:
#: mil son muchos más de los que una persona encarga en un día.
REMEMBERED_ORDERS = 1000

#: Lo que el servidor nunca va a aceptar aunque se reintente: se tira de la
#: cola (con su nota) en vez de taparla para siempre. Un 401 o un 402 no: el
#: token puede volver a valer y la instalación salir de solo lectura.
PERMANENT_STATUSES = frozenset({400, 404, 409, 410, 413, 422})

#: Lo que el servidor dice cuando no quiere al agente (spec 1, códigos).
REFUSED_UNAUTHORIZED = "unauthorized"
REFUSED_READ_ONLY = "read_only"
_REFUSALS = {401: REFUSED_UNAUTHORIZED, 402: REFUSED_READ_ONLY}

#: Con el token rechazado se sigue preguntando, pero despacio: si alguien lo
#: arregla en la web el agente vuelve solo, y mientras tanto no martillea.
REJECTED_CHECKIN_SECONDS = 300

#: El viaje de ida y vuelta más largo con el que todavía se fía de la medida
#: de la diferencia de relojes (`Control.exchange`).
MAX_SKEW_TRIP_SECONDS = 5.0

#: «Analizar» a la vez, como mucho. Los demás esperan su turno (y se contestan).
MAX_PROBES = 2

KIND_RUN_TASK = "run_task"
KIND_PROBE = "probe"
#: Los encargos de las credenciales selladas (spec 3.3).
KIND_TEST_CREDENTIAL = "test_credential"
KIND_RESEAL = "reseal"
KIND_NETBOX_EXPORT = "netbox_export"

DONE = "done"
FAILED = "failed"
UNSUPPORTED = "unsupported"

STATE_IDLE = "idle"
STATE_RUNNING = "running"
STATE_PAUSED = "paused"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def bound_checkin(value: object, fallback: int = CHECKIN_SECONDS) -> int:
    """`checkin_seconds` acotado a [10, 300]; lo que no se entiende, `fallback`."""
    if isinstance(value, bool):
        return fallback
    try:
        seconds = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return fallback
    return max(MIN_CHECKIN_SECONDS, min(seconds, MAX_CHECKIN_SECONDS))


def parse_moment(value: object) -> datetime | None:
    """Una fecha ISO 8601 del servidor, o `None` si no hay o no se entiende."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


#: Para un resultado, un 404 no es «nunca»: es la misma puerta que contesta
#: 404 a mitad de un despliegue (spec 1.8), y tirar el resultado de una tarea
#: por eso perdía un inventario. Para la respuesta a un encargo sí lo es: el
#: encargo caducó o no es de este agente (spec 1.3).
RESULT_PERMANENT_STATUSES = PERMANENT_STATUSES - {404}


def is_permanent(exc: Exception, kind: str = KIND_ORDER) -> bool:
    """Si el servidor nunca aceptará ese envío (`kind`: resultado o encargo)."""
    statuses = PERMANENT_STATUSES if kind == KIND_ORDER else RESULT_PERMANENT_STATUSES
    return isinstance(exc, PushError) and exc.status in statuses


class Shared:
    """Lo que comparten el hilo de control y el de las tareas, tras un cerrojo.

    Nada de esto se lee ni se escribe sin `lock`: el hilo de control cambia la
    configuración mientras el de tareas la copia para la siguiente, y el de
    tareas cambia la actividad mientras el de control la cuenta.
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.config: dict[str, Any] = {}
        self.config_etag = ""
        self.has_config = False
        self.server_paused_until: datetime | None = None
        self.checkin_seconds = CHECKIN_SECONDS
        self.update: dict[str, Any] | None = None
        self.activity: dict[str, Any] | None = None
        #: Cómo fue el último checkin que el servidor contestó con un «no»
        #: rotundo: `REFUSED_UNAUTHORIZED` (401, token revocado o no válido),
        #: `REFUSED_READ_ONLY` (402, instalación en solo lectura), o "".
        self.refusal = ""
        #: El `uuid` de este agente en el servidor: la mitad de la AAD de las
        #: credenciales selladas (spec 3.1). Lo pone el enrolamiento y, si
        #: llega, el campo `agent` de cada respuesta del checkin.
        self.agent_uuid = ""
        #: Hora del servidor menos hora de esta máquina (`Control.exchange`).
        #: Solo para traducir su `paused_until`; la cola caduca con el reloj local.
        self.clock_offset = timedelta(0)
        #: Despierta al hilo de tareas: llegó un encargo, una configuración o
        #: un cambio de pausa, y no tiene sentido esperar al siguiente minuto.
        self.wake = threading.Event()

    def refused(self) -> str:
        with self.lock:
            return self.refusal

    def config_snapshot(self) -> tuple[dict[str, Any], str]:
        with self.lock:
            return dict(self.config), self.config_etag

    def set_activity(self, activity: dict[str, Any] | None) -> None:
        with self.lock:
            self.activity = dict(activity) if activity is not None else None

    def update_activity(self, **fields: Any) -> None:
        with self.lock:
            if self.activity is not None:
                self.activity.update(fields)

    def activity_snapshot(self) -> dict[str, Any] | None:
        with self.lock:
            return dict(self.activity) if self.activity is not None else None


@dataclass
class Hooks:
    """Lo que el canal de control necesita del resto del agente."""

    #: El `about` de ahora (1.5); quien lo da decide cada cuánto lo recalcula.
    about: Callable[[], dict[str, Any]]
    #: El calendario para el checkin (`Scheduler.view`).
    schedule: Callable[[datetime], list[dict[str, Any]]]
    #: La pausa local (`settings.json`), o `None`.
    local_pause: Callable[[], datetime | None]
    #: Mete un `run_task` en la cola de tareas.
    run_task: Callable[[Job], None]
    #: Llegó una configuración con otro etag (ya guardada en `Shared`).
    config_changed: Callable[[str], None]
    #: El informe de «Analizar» de una IP (`agent.probe.report_for`).
    probe: Callable[[str], dict[str, Any]]
    #: Si una IP está excluida en los ajustes locales.
    excluded: Callable[[str], bool]
    #: El servidor ha rechazado al agente (401): vaciar la cola de tareas.
    rejected: Callable[[], None] = lambda: None
    #: Los encargos de la fase 3 (`agent/orders.py`): reciben `(id, params)` y
    #: devuelven `(status, result, notas)`. Sin ellos, el encargo es `unsupported`.
    test_credential: Callable[[str, dict[str, Any]], tuple[str, dict[str, Any], list[Note]]] | None = None
    reseal: Callable[[str, dict[str, Any]], tuple[str, dict[str, Any], list[Note]]] | None = None
    netbox_export: Callable[[str, dict[str, Any]], tuple[str, dict[str, Any], list[Note]]] | None = None
    #: Un checkin bueno, con su `update` (o `None`): decide `agent/update.py`.
    update_offered: Callable[[Any], None] = lambda _update: None
    #: El `update_state` del checkin (docs/agente-v2-instalacion.md, 4), o `None`.
    update_state: Callable[[], dict[str, Any] | None] = lambda: None


class Control:
    def __init__(
        self,
        client: AgentClient,
        shared: Shared,
        outbox: Outbox,
        hooks: Hooks,
        *,
        clock: Callable[[], datetime] = _now,
        report: bool = True,
        take_orders: bool = True,
    ) -> None:
        self.client = client
        self.shared = shared
        self.outbox = outbox
        self.hooks = hooks
        self._clock = clock
        self._report = report
        #: `--once` no atiende encargos ni los contesta: son del servicio, que
        #: los recibirá en su próximo checkin y los hará de verdad.
        self._take_orders = take_orders
        self._handled: OrderedDict[str, None] = OrderedDict()
        self._handled_lock = threading.Lock()
        for order_id in outbox.order_ids():
            self._remember(order_id)
        self._about_sent: str | None = None
        self._need_about = False
        self._announced_update = ""
        self._last_error = ""
        #: El servidor contestó 404 al checkin: solo habla el protocolo 1.
        self.gone = False
        #: Los hilos de «Analizar» en curso (para que los tests puedan esperarlos).
        self.probe_threads: list[threading.Thread] = []
        #: Cuántos sondeos a la vez, y uno solo por IP: cada sondeo prueba todas
        #: las credenciales contra su equipo, y diez a la vez (o dos contra el
        #: mismo) son justo los intentos de más que la memoria evita.
        self._probe_slots = threading.BoundedSemaphore(MAX_PROBES)
        self._probe_ip_locks: dict[str, list] = {}
        self._probe_ip_guard = threading.Lock()

    # --- El checkin ----------------------------------------------------------------

    def body(self, now: datetime) -> tuple[dict[str, Any], str]:
        """El cuerpo del checkin y el hash del `about` que lleva."""
        about = self.hooks.about()
        about_hash = _about_hash(about)
        activity = self.shared.activity_snapshot()
        with self.shared.lock:
            etag = self.shared.config_etag
            server_pause = self.shared.server_paused_until
        local_pause = self.hooks.local_pause()
        if activity is not None:
            state = STATE_RUNNING
        elif is_paused(now, effective_pause(local_pause, server_pause)):
            state = STATE_PAUSED
        else:
            state = STATE_IDLE
        body: dict[str, Any] = {
            "protocol": PROTOCOL,
            "agent_version": __version__,
            "state": state,
            "activity": activity,
            "schedule": self.hooks.schedule(now),
            "paused_until": local_pause.isoformat() if local_pause else None,
            "config_etag": etag,
            "about_hash": about_hash,
            "outbox": self.outbox.count(),
        }
        if (update_state := self._safely(self.hooks.update_state)) is not None:
            body["update_state"] = update_state
        # El `about` entero solo si cambió desde el último que llegó, o si el
        # servidor lo pidió; el primero de cada arranque siempre va.
        if self._need_about or about_hash != self._about_sent:
            body["about"] = about
        return body, about_hash

    def checkin_once(self) -> bool:
        """Un checkin entero: preguntar, aplicar, atender y vaciar la cola. Nunca lanza.

        Devuelve si el servidor contestó. Un 404 pone `gone`: quien corre el
        bucle vuelve al protocolo 1.
        """
        try:
            body, about_hash = self.body(self._clock())
            answer = self.exchange(body)
        except PushError as exc:
            if exc.status == 404 and self.speaks_only_protocol_1():
                self.gone = True
            elif exc.status in _REFUSALS:
                self._refused(_REFUSALS[exc.status], str(exc))
            else:
                self._say_error(str(exc))
            return False
        except Exception as exc:  # noqa: BLE001 - el hilo de control no muere
            self._say_error(_unexpected(exc))
            return False
        if not isinstance(answer, dict):
            return False
        self.accept(answer, body, about_hash)
        return True

    def exchange(self, body: dict[str, Any]) -> Any:
        """The check-in itself, timed: a quick answer also says how far the clocks are apart.

        `server_time` y el reloj de esta máquina pueden no coincidir (un
        servidor sin NTP, una máquina con la hora mal): la pausa puesta desde
        la web (`paused_until`) está en la hora del servidor, y aplicarla tal
        cual con otra hora alargaba o acortaba la pausa. Solo se fía de la
        medida si el viaje fue corto: con uno largo, la mitad del viaje ya es
        más error que la diferencia que se quiere medir.
        """
        before_wall = self._clock()
        before = time.monotonic()
        answer = self.client.checkin(body)
        trip = time.monotonic() - before
        if isinstance(answer, dict) and trip <= MAX_SKEW_TRIP_SECONDS:
            server_time = parse_moment(answer.get("server_time"))
            if server_time is not None:
                local_then = before_wall + timedelta(seconds=trip / 2)
                with self.shared.lock:
                    self.shared.clock_offset = server_time - local_then
        return answer

    def speaks_only_protocol_1(self) -> bool:
        """After a 404 on ``v2/checkin``: is this a protocol-1 server? Never raises.

        Solo si su latido del protocolo 1 contesta bien. Un 404 suelto puede
        ser un proxy inverso a mitad de un despliegue, y tomarlo por un
        servidor viejo dejaba al agente una hora con barridos completos del
        protocolo 1; un servidor viejo de verdad contesta al latido. Con el
        latido fallando también, el servidor está mal: se sigue en el 2 y se
        reintenta.
        """
        try:
            answer = self.client.heartbeat(version=__version__, hostname=socket.gethostname())
        except Exception:  # noqa: BLE001
            return False
        return isinstance(answer, dict)

    def _refused(self, refusal: str, detail: str) -> None:
        """El servidor dice que no: 401 (token rechazado) o 402 (solo lectura).

        Con un 401 el agente deja de ser de nadie: no se empieza ninguna tarea
        ni encargo, y la configuración --con las credenciales dentro-- se
        olvida, para no seguir entrando en los equipos con las de alguien que
        ya no lo quiere. Se sigue preguntando, despacio, por si se arregla.
        Con un 402 nada de lo que se descubra podría guardarse: no se empieza
        ninguna tarea, pero la configuración se queda y se sigue preguntando
        como siempre. Las dos se levantan solas con el primer checkin bueno.
        """
        with self.shared.lock:
            self.shared.refusal = refusal
            if refusal == REFUSED_UNAUTHORIZED:
                self.shared.config, self.shared.config_etag, self.shared.has_config = {}, "", False
        if refusal == REFUSED_UNAUTHORIZED:
            self._safely(self.hooks.rejected)
            text = _t(
                "El servidor ha rechazado este agente (%(error)s): no barre ni usa ninguna credencial hasta "
                "que lo acepte de nuevo, y le pregunta cada %(minutes)d minutos. Si se revocó, hay que "
                "enrolarlo otra vez."
            ) % {"error": detail, "minutes": REJECTED_CHECKIN_SECONDS // 60}
        else:
            text = _t(
                "La instalación de Cenya está en solo lectura (%(error)s): el agente no empieza ninguna tarea "
                "hasta que el servidor vuelva a aceptar resultados."
            ) % {"error": detail}
        self._say_error(text)

    def accept(self, answer: dict[str, Any], body: dict[str, Any], about_hash: str) -> None:
        """Lo que se hace con una respuesta buena: aplicarla y vaciar la cola. Nunca lanza."""
        self._last_error = ""
        with self.shared.lock:
            was_refused, self.shared.refusal = bool(self.shared.refusal), ""
        if was_refused:
            self._say(_t("[agente] El servidor vuelve a aceptar a este agente."))
            self.shared.wake.set()
        if "about" in body:
            self._about_sent = about_hash
        try:
            self.apply(answer)
            self.drain()
        except Exception as exc:  # noqa: BLE001
            self._say_error(_unexpected(exc))
        if self._report:
            status.contact()

    def apply(self, answer: dict[str, Any]) -> None:
        """Aplica la respuesta de un checkin (spec 1.2)."""
        self._need_about = bool(answer.get("need_about"))
        etag = answer.get("config_etag")
        config = answer.get("config")
        changed = False
        etag = etag if isinstance(etag, str) else ""
        with self.shared.lock:
            # Con el mismo etag la configuración no viaja, y si viaja se
            # ignora: es la misma. La primera vez vale cualquiera (un servidor
            # que no mande etag también deja trabajar).
            if isinstance(config, dict) and (etag != self.shared.config_etag or not self.shared.has_config):
                self.shared.config, self.shared.config_etag = dict(config), etag
                self.shared.has_config = changed = True
            previous_pause = self.shared.server_paused_until
            server_pause = parse_moment(answer.get("paused_until"))
            # A la hora de esta máquina: el servidor la dice en la suya.
            self.shared.server_paused_until = (
                server_pause - self.shared.clock_offset if server_pause is not None else None
            )
            pause_changed = previous_pause != self.shared.server_paused_until
            self.shared.checkin_seconds = bound_checkin(answer.get("checkin_seconds"), self.shared.checkin_seconds)
            update = answer.get("update")
            self.shared.update = dict(update) if isinstance(update, dict) else None
            agent_uuid = _agent_uuid(answer.get("agent"))
            if agent_uuid:
                self.shared.agent_uuid = agent_uuid
        if changed:
            self._say(_t("[agente] Configuración nueva recibida."))
            self._safely(lambda: self.hooks.config_changed(etag))
        offered = str(update.get("version") or "") if isinstance(update, dict) else ""
        if offered and offered != self._announced_update:
            # Se anota aquí; si se actualiza o no lo decide `agent/update.py`.
            self._announced_update = offered
            self._say(_t("[agente] Hay una versión nueva del agente: %(version)s.") % {"version": offered})
        self._safely(lambda: self.hooks.update_offered(dict(update) if isinstance(update, dict) else None))
        orders = answer.get("orders") if self._take_orders else None
        for order in orders if isinstance(orders, list) else []:
            self.handle_order(order)
        if changed or pause_changed:
            self.shared.wake.set()

    # --- Encargos ------------------------------------------------------------------

    def _remember(self, order_id: str) -> bool:
        """Lo anota como atendido. `False` si ya lo estaba."""
        with self._handled_lock:
            if order_id in self._handled:
                return False
            self._handled[order_id] = None
            while len(self._handled) > REMEMBERED_ORDERS:
                self._handled.popitem(last=False)
            return True

    def handle_order(self, order: object) -> None:
        """Atiende un encargo, una sola vez por `id`. Nunca lanza."""
        if not isinstance(order, dict):
            return
        order_id = str(order.get("id") or "").strip()
        if not order_id or not self._remember(order_id):
            return
        kind = order.get("kind")
        params = order.get("params") if isinstance(order.get("params"), dict) else {}
        self._say(_t("[agente] Encargo recibido: %(kind)s.") % {"kind": str(kind)[:40]})
        if kind == KIND_RUN_TASK:
            task = params.get("task")
            if task not in TASKS:
                # Una tarea que este agente no conoce: un servidor más nuevo.
                self.answer(order_id, UNSUPPORTED)
                return
            self._safely(lambda: self.hooks.run_task(Job(str(task), TRIGGER_ORDER, order_id=order_id)))
            self.shared.wake.set()
            self.answer(order_id, DONE, {})
            return
        if kind == KIND_PROBE:
            self._start_probe(order_id, params.get("ip"))
            return
        if kind in (KIND_TEST_CREDENTIAL, KIND_RESEAL, KIND_NETBOX_EXPORT):
            self._start_sealed(order_id, str(kind), params)
            return
        self.answer(order_id, UNSUPPORTED)

    def _start_sealed(self, order_id: str, kind: str, params: dict[str, Any]) -> None:
        """Un encargo de la fase 3 en su propio hilo, con el mismo turno que «Analizar».

        `test_credential` entra en un equipo como un sondeo: espera el turno de
        su IP (o de su credencial, si es un hipervisor) y uno de los
        `MAX_PROBES` huecos. `netbox_export` va de uno en uno y sin ocupar
        hueco (puede tardar minutos y no tiene por qué parar los sondeos);
        `reseal` solo hace cuentas.
        """
        hook = {
            KIND_TEST_CREDENTIAL: self.hooks.test_credential,
            KIND_RESEAL: self.hooks.reseal,
            KIND_NETBOX_EXPORT: self.hooks.netbox_export,
        }[kind]
        if hook is None:
            self.answer(order_id, UNSUPPORTED)
            return
        if kind == KIND_TEST_CREDENTIAL:
            # La misma clave que usa «Analizar» (la IP normalizada): una prueba
            # y un sondeo contra el mismo equipo tampoco van a la vez.
            try:
                turn = str(ipaddress.ip_address(str(params.get("ip") or "").strip()))
            except ValueError:
                turn = f"credential:{params.get('credential_id')}"
            slot = True
        else:
            turn, slot = f"order:{kind}", False

        def work() -> None:
            try:
                outcome, result, entries = hook(order_id, params)
            except Exception as exc:  # noqa: BLE001
                # Solo el tipo: el texto de una excepción de estos encargos
                # pudo pasar cerca de un secreto abierto.
                name = type(exc).__name__
                outcome, result, entries = FAILED, {}, [
                    collector_note(kind, "crashed", f"error inesperado ({name})", error=name)
                ]
            self.answer(order_id, outcome, result, entries)

        thread = threading.Thread(
            target=self._in_turn, args=(turn, slot, work), name=f"{kind}-{order_id[:8]}", daemon=True
        )
        self.probe_threads = [t for t in self.probe_threads if t.is_alive()] + [thread]
        thread.start()

    def _start_probe(self, order_id: str, raw_ip: object) -> None:
        try:
            ip = str(ipaddress.ip_address(str(raw_ip or "").strip()))
        except ValueError:
            self.answer(order_id, FAILED, {}, [collector_note("probe", "bad_address", "la dirección no es válida")])
            return
        if self._safely(lambda: self.hooks.excluded(ip)):
            # Excluida en esta máquina: ni un `probe` la toca (spec 2.4).
            self.answer(
                order_id, FAILED, {}, [collector_note("probe", "excluded", "la dirección está excluida en este agente")]
            )
            return
        thread = threading.Thread(target=self._probe, args=(order_id, ip), name=f"probe-{ip}", daemon=True)
        self.probe_threads = [t for t in self.probe_threads if t.is_alive()] + [thread]
        thread.start()

    def _ip_lock(self, ip: str, take: bool) -> threading.Lock:
        """El cerrojo de esa IP, con su cuenta de quién lo espera: se olvida al soltarlo el último."""
        with self._probe_ip_guard:
            entry = self._probe_ip_locks.get(ip)
            if take:
                if entry is None:
                    entry = self._probe_ip_locks[ip] = [threading.Lock(), 0]
                entry[1] += 1
            else:
                entry[1] -= 1
                if entry[1] == 0:
                    del self._probe_ip_locks[ip]
            return entry[0]

    def _probe(self, order_id: str, ip: str) -> None:
        """«Analizar», en su propio hilo: sin esperar a la cola de tareas.

        Espera su turno: primero el de su IP (nunca dos contra el mismo
        equipo), luego uno de los `MAX_PROBES` huecos. Siempre en ese orden,
        así que no hay abrazo mortal.
        """
        self._in_turn(ip, True, lambda: self._probe_now(order_id, ip))

    def _in_turn(self, turn: str, slot: bool, work: Callable[[], None]) -> None:
        """`work` con el cerrojo de `turn` y, si `slot`, uno de los `MAX_PROBES` huecos."""
        ip_lock = self._ip_lock(turn, take=True)
        try:
            if slot:
                with ip_lock, self._probe_slots:
                    work()
            else:
                with ip_lock:
                    work()
        finally:
            self._ip_lock(turn, take=False)

    def _probe_now(self, order_id: str, ip: str) -> None:
        try:
            report = self.hooks.probe(ip)
        except Exception as exc:  # noqa: BLE001
            self.answer(
                order_id,
                FAILED,
                {},
                [collector_note("probe", "crashed", str(exc), detail=f"{type(exc).__name__}: {exc}")],
            )
            return
        self.answer(order_id, DONE, {"probe_report": report})

    def answer(
        self, order_id: str, outcome: str, result: dict[str, Any] | None = None, entries: list[Note] | None = None
    ) -> None:
        """Contesta un encargo; si no sale, a la cola local. Nunca lanza."""
        body = {"status": outcome, "result": result or {}, "notes": [notes.to_json(e) for e in entries or []]}
        if self.outbox.count():
            # Hay cosas esperando: esta va detrás, en orden.
            self.outbox.put_order_answer(order_id, body)
            return
        try:
            self.client.answer_order(order_id, body)
        except Exception as exc:  # noqa: BLE001
            if is_permanent(exc):
                return  # el encargo ya no existe (caducó, o no es de este agente)
            self.outbox.put_order_answer(order_id, body)

    # --- La cola local -----------------------------------------------------------

    def drain(self) -> int:
        """Lo pendiente, en orden, tras un checkin que salió bien."""

        def send(entry: Entry) -> None:
            if entry.kind == KIND_ORDER:
                self.client.answer_order(entry.order_id, entry.body)
            else:
                self.client.post_result_part(entry.body)

        return self.outbox.drain(send, is_permanent=is_permanent)

    # --- El hilo ---------------------------------------------------------------------

    def run(self, stop_event: Any) -> None:
        """El bucle del hilo de control: hasta que paren o el servidor sea del protocolo 1."""
        while not stop_event.is_set() and not self.gone:
            try:
                self.checkin_once()
            except Exception as exc:  # noqa: BLE001 - checkin_once no lanza; esto es por si acaso
                self._say_error(_unexpected(exc))
            if self.gone:
                break
            with self.shared.lock:
                seconds = self.shared.checkin_seconds
                if self.shared.refusal == REFUSED_UNAUTHORIZED:
                    seconds = max(seconds, REJECTED_CHECKIN_SECONDS)
            if stop_event.wait(seconds):
                break
        # Quien espera en la cola de tareas se entera en el acto.
        self.shared.wake.set()

    # --- Por dentro --------------------------------------------------------------------

    def _safely(self, call: Callable[[], Any]) -> Any:
        try:
            return call()
        except Exception as exc:  # noqa: BLE001
            self._say_error(_unexpected(exc))
            return None

    def _say(self, text: str) -> None:
        logs.info(text)

    def _say_error(self, text: str) -> None:
        # Una vez por error distinto: con el servidor caído, una línea cada
        # treinta segundos llenaría el registro sin decir nada nuevo.
        if text != self._last_error:
            self._last_error = text
            logs.error(_t("[agente] %(error)s") % {"error": text})
        if self._report:
            status.contact(error=text)


def _agent_uuid(value: object) -> str:
    """El uuid del agente que manda el checkin (`"agent": "<uuid>"` o `{"uuid": ...}`), o ""."""
    if isinstance(value, dict):
        value = value.get("uuid")
    if not isinstance(value, str):
        return ""
    try:
        return str(uuid.UUID(value.strip()))
    except ValueError:
        return ""


def _about_hash(about: dict[str, Any]) -> str:
    from agent.about import digest

    return digest(about)


def _unexpected(exc: BaseException) -> str:
    return _t("Error inesperado: %(error)s") % {"error": f"{type(exc).__name__}: {exc}"}
