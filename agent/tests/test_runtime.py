"""The protocol-2 runtime end to end, against a throwaway server on 127.0.0.1.

No collector touches the network here: the registry is replaced by fakes that
say who is alive. What is real is the HTTP (client, batching, outbox), the
threads and the stop semantics.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado y la carpeta del agente

import contextlib
import http.server
import json
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from agent import __main__ as loop
from agent import runtime as rt
from agent.client import MAX_BATCH_ITEMS, AgentClient, PushError
from agent.collectors.base import Finding
from agent.config import Config
from agent.runtime import Runtime
from agent.scheduler import Job

ALL_OFF_BUT = {"presence": {"every_seconds": 300}, "inventory": {"every_seconds": 0}, "configs": {"every_seconds": 0},
               "ups": {"every_seconds": 0}, "hypervisors": {"every_seconds": 0}}


class Server:
    """Un servidor de mentira que habla los protocolos 1 y 2 (o solo el 1)."""

    def __init__(self, *, v2: bool = True, config: dict | None = None, heartbeat: bool = True) -> None:
        self.v2 = v2
        #: Sin latido: un servidor que no está bien (un proxy en pleno despliegue).
        self.heartbeat = heartbeat
        self.config = config if config is not None else {"subnets": ["192.0.2.0/30"], "tasks": ALL_OFF_BUT}
        self.requests: list[tuple[str, dict]] = []
        self.orders: list[dict] = []
        self.fail_results = 0
        self.lock = threading.Lock()

    def bodies(self, path: str) -> list[dict]:
        with self.lock:
            return [body for p, body in self.requests if p == path]

    def answer(self, path: str, body: dict) -> tuple[int, dict]:
        with self.lock:
            self.requests.append((path, body))
        if path.startswith("/api/agent/v2/") and not self.v2:
            return 404, {"error": "No existe."}
        if path == "/api/agent/v2/checkin/":
            answer: dict[str, Any] = {"ok": True, "protocol": 2, "checkin_seconds": 10, "config_etag": "e1",
                                      "orders": list(self.orders), "need_about": False}
            if body.get("config_etag") != "e1":
                answer["config"] = self.config
            return 200, answer
        if path == "/api/agent/v2/results/":
            if self.fail_results:
                self.fail_results -= 1
                return 503, {"error": "Mantenimiento."}
            return 200, {"ok": True, "created": len(body.get("items") or []), "refreshed": 0}
        if path.startswith("/api/agent/v2/orders/"):
            return 200, {"ok": True}
        if path == "/api/agent/heartbeat/":
            if not self.heartbeat:
                return 502, {"error": "Bad gateway."}
            return 200, {"ok": True, "interval_seconds": 900, "config": self.config}
        if path == "/api/agent/findings/":
            return 200, {"ok": True, "run": "r1", "created": len(body.get("items") or []), "refreshed": 0}
        return 404, {"error": "No existe."}


@contextlib.contextmanager
def serving(server: Server):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(length) or b"{}")
            code, answer = server.answer(self.path, body)
            data = json.dumps(answer).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args: object) -> None:
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


class FakeCollector:
    def __init__(self, name: str, behaviour) -> None:  # noqa: ANN001
        self.name = name
        self.behaviour = behaviour
        self.contexts: list[dict] = []

    def collect(self, ctx: dict) -> list[Finding]:
        self.contexts.append(dict(ctx))
        return self.behaviour(ctx)


def sweep_finding(alive: list[tuple[str, str]]):  # noqa: ANN201
    def behaviour(ctx: dict) -> list[Finding]:
        ctx["hosts"] = [{"ip": ip, "mac": mac} for ip, mac in alive]
        return [Finding("host", {"mac": mac}, {"ip": ip, "mac": mac}) for ip, mac in alive]

    return behaviour


class FakeMemory:
    """La memoria de la especificación (2.3), lo justo que usa el bucle."""

    def __init__(self, known: set[str] | None = None) -> None:
        self.known = set(known or ())
        self.saved = 0
        self.etags: list[str] = []

    def note_host(self, ip: str, mac: str, now: datetime) -> bool:
        key = mac or ip
        new = key not in self.known
        self.known.add(key)
        return new

    def save(self) -> None:
        self.saved += 1

    def credentials_changed(self, etag: str) -> None:
        self.etags.append(etag)


class RuntimeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.state = tempfile.mkdtemp(prefix="cenya-runtime-")
        patcher = mock.patch.dict(os.environ, {"CENYA_STATE_DIR": self.state})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.alive = [("192.0.2.1", "aa:aa:aa:aa:aa:01")]
        self.collectors = {
            "local": FakeCollector("local", lambda ctx: [Finding("host", {"ip": "192.0.2.99"}, {"local": True})]),
            "sweep": FakeCollector("sweep", lambda ctx: sweep_finding(self.alive)(ctx)),
            "snmp": FakeCollector("snmp", lambda ctx: []),
            "ssh": FakeCollector("ssh", lambda ctx: []),
            "winrm": FakeCollector("winrm", lambda ctx: []),
            "hypervisors": FakeCollector("hypervisors", lambda ctx: []),
        }
        patcher = mock.patch("agent.tasks.all_collectors", side_effect=lambda: list(self.collectors.values()))
        patcher.start()
        self.addCleanup(patcher.stop)
        # El `about` de verdad lee las redes de esta máquina: aquí, uno fijo.
        patcher = mock.patch("agent.runtime.about.build", return_value={"hostname": "PRUEBA", "networks": []})
        patcher.start()
        self.addCleanup(patcher.stop)

    def runtime(self, url: str, **kwargs: Any) -> Runtime:
        client = AgentClient(url, "cya_token")
        runtime = Runtime(client, Config(url=url, token="cya_token"), report=False, **kwargs)
        runtime.tick = 0.02
        return runtime


class NegotiationTests(RuntimeTestCase):
    def test_a_protocol_2_server_is_recognised_and_its_config_applied(self) -> None:
        server = Server()
        with serving(server) as url:
            runtime = self.runtime(url)
            self.assertEqual(runtime.negotiate(), rt.V2)
        self.assertEqual(runtime.shared.config_etag, "e1")
        self.assertEqual(server.bodies("/api/agent/v2/checkin/")[0]["about"], {"hostname": "PRUEBA", "networks": []})

    def test_a_404_is_protocol_1(self) -> None:
        with serving(Server(v2=False)) as url:
            self.assertEqual(self.runtime(url).negotiate(), rt.V1)

    def test_a_404_with_a_failing_heartbeat_is_not_protocol_1(self) -> None:
        with serving(Server(v2=False, heartbeat=False)) as url:
            self.assertEqual(self.runtime(url).negotiate(), rt.UNKNOWN)

    def test_no_answer_is_unknown(self) -> None:
        self.assertEqual(self.runtime("http://127.0.0.1:9").negotiate(), rt.UNKNOWN)

    def test_an_answer_without_protocol_2_is_protocol_1(self) -> None:
        runtime = self.runtime("http://127.0.0.1:9")
        with mock.patch.object(runtime.client, "checkin", return_value={"ok": True}):
            self.assertEqual(runtime.negotiate(), rt.V1)
        with mock.patch.object(runtime.client, "checkin", return_value=mock.Mock()):
            self.assertEqual(runtime.negotiate(), rt.V1)


class RunJobTests(RuntimeTestCase):
    def test_a_presence_pushes_its_own_result(self) -> None:
        server = Server()
        with serving(server) as url:
            runtime = self.runtime(url)
            runtime.negotiate()
            run = runtime.run_job(Job("presence"))
        bodies = server.bodies("/api/agent/v2/results/")
        self.assertEqual(len(bodies), 1)
        body = bodies[0]
        self.assertEqual((body["part"], body["final"]), (1, True))
        self.assertEqual(body["run"]["id"], run["id"])
        self.assertEqual(body["run"]["task"], "presence")
        self.assertEqual(body["run"]["trigger"], "schedule")
        self.assertEqual(body["run"]["status"], "ok")
        self.assertEqual(body["run"]["stats"]["hosts_alive"], 1)
        self.assertEqual(len(body["items"]), 2)
        self.assertEqual(self.collectors["snmp"].contexts, [])  # solo local y sweep

    def test_a_big_result_is_split_and_every_piece_shares_the_run_id(self) -> None:
        self.alive = [(f"10.0.{n // 250}.{n % 250 + 1}", f"02:00:00:00:{n // 256:02x}:{n % 256:02x}") for n in range(MAX_BATCH_ITEMS + 20)]
        server = Server()
        with serving(server) as url:
            runtime = self.runtime(url)
            runtime.negotiate()
            run = runtime.run_job(Job("presence"))
        bodies = server.bodies("/api/agent/v2/results/")
        self.assertEqual([(b["part"], b["final"]) for b in bodies], [(1, False), (2, True)])
        self.assertEqual({b["run"]["id"] for b in bodies}, {run["id"]})
        self.assertEqual(sum(len(b["items"]) for b in bodies), MAX_BATCH_ITEMS + 21)

    def test_a_failed_push_goes_to_the_outbox_and_the_next_checkin_sends_it(self) -> None:
        server = Server()
        with serving(server) as url:
            runtime = self.runtime(url)
            runtime.negotiate()
            server.fail_results = 1
            run = runtime.run_job(Job("presence"))
            self.assertEqual(runtime.outbox.count(), 1)
            # La siguiente tarea no espera a la cola, pero sale detrás de ella.
            second = runtime.run_job(Job("hypervisors"))
            self.assertEqual(runtime.outbox.count(), 2)
            self.assertTrue(runtime.control.checkin_once())
            self.assertEqual(runtime.outbox.count(), 0)
        ids = [b["run"]["id"] for b in server.bodies("/api/agent/v2/results/")]
        self.assertEqual(ids, [run["id"], run["id"], second["id"]])  # el fallido, y la cola en orden

    def test_a_crashing_collector_is_a_note_and_the_rest_still_goes_up(self) -> None:
        self.collectors["local"].behaviour = lambda ctx: 1 / 0
        server = Server()
        with serving(server) as url:
            runtime = self.runtime(url)
            runtime.negotiate()
            run = runtime.run_job(Job("presence"))
        self.assertEqual(run["status"], "partial")
        self.assertEqual(run["notes"][0]["code"], "crashed")
        self.assertEqual(run["notes"][0]["collector"], "local")
        self.assertEqual(len(server.bodies("/api/agent/v2/results/")[0]["items"]), 1)

    def test_when_every_collector_crashes_the_run_is_an_error(self) -> None:
        self.collectors["hypervisors"].behaviour = lambda ctx: 1 / 0
        with serving(Server()) as url:
            runtime = self.runtime(url)
            runtime.negotiate()
            self.assertEqual(runtime.run_job(Job("hypervisors"))["status"], "error")

    def test_the_ctx_has_the_keys_of_the_spec(self) -> None:
        server = Server(config={"subnets": [], "gentleness": "gentle", "tasks": ALL_OFF_BUT})
        with serving(server) as url:
            runtime = self.runtime(url)
            runtime.memory = FakeMemory()
            runtime.negotiate()
            runtime.run_job(Job("presence"))
            runtime.run_job(Job("inventory"))
        ctx = self.collectors["snmp"].contexts[0]
        self.assertEqual(ctx["task"], "inventory")
        self.assertEqual(ctx["hosts"], [{"ip": "192.0.2.1", "mac": "aa:aa:aa:aa:aa:01"}])
        self.assertIsNone(ctx["targets"])
        self.assertIs(ctx["memory"], runtime.memory)
        self.assertEqual(ctx["workers"], {"ping": 8, "login": 2, "snmp": 5})
        self.assertIsInstance(ctx["env"], Config)
        self.assertEqual(ctx["config"]["gentleness"], "gentle")
        self.assertIn("excluded", ctx)
        ctx["progress"]("x", 1, 2)  # nunca lanza
        self.assertNotIn("hosts", self.collectors["sweep"].contexts[0])

    def test_new_hosts_after_a_presence_trigger_an_inventory_of_just_them(self) -> None:
        self.alive = [("192.0.2.1", "aa:aa:aa:aa:aa:01"), ("192.0.2.2", "aa:aa:aa:aa:aa:02")]
        tasks = {**ALL_OFF_BUT, "inventory": {"every_seconds": 21600}}
        with serving(Server(config={"subnets": [], "tasks": tasks})) as url:
            runtime = self.runtime(url)
            runtime.memory = FakeMemory(known={"aa:aa:aa:aa:aa:01"})
            runtime.negotiate()
            now = datetime.now(timezone.utc)
            runtime.scheduler.finished(Job("inventory"), now, "ok")  # el completo ya pasó hace nada
            run = runtime.run_job(Job("presence"))
            self.assertEqual(run["stats"]["new_hosts"], 1)
            job = runtime.next_job()
            self.assertEqual(job, Job("inventory", "new_host", targets=("192.0.2.2",)))
            runtime.run_job(job)
        ctx = self.collectors["snmp"].contexts[0]
        self.assertEqual(ctx["targets"], ["192.0.2.2"])
        self.assertEqual(ctx["hosts"], [{"ip": "192.0.2.2", "mac": "aa:aa:aa:aa:aa:02"}])
        self.assertGreaterEqual(runtime.memory.saved, 2)

    def test_excluded_hosts_never_reach_the_inventory(self) -> None:
        self.alive = [("192.0.2.1", "aa:aa:aa:aa:aa:01"), ("192.0.2.2", "aa:aa:aa:aa:aa:02")]
        with serving(Server()) as url:
            runtime = self.runtime(url)
            runtime.excluded = rt.Excluded([], ["192.0.2.2"])
            runtime.negotiate()
            runtime.run_job(Job("presence"))
            runtime.run_job(Job("inventory"))
        self.assertEqual([h["ip"] for h in self.collectors["snmp"].contexts[0]["hosts"]], ["192.0.2.1"])

    def test_a_new_configuration_tells_the_memory(self) -> None:
        with serving(Server()) as url:
            runtime = self.runtime(url)
            runtime.memory = FakeMemory()
            runtime.negotiate()
        self.assertEqual(runtime.memory.etags, ["e1"])
        self.assertEqual(runtime.scheduler.every("inventory"), 0)


class LoopTests(RuntimeTestCase):
    def test_the_loop_runs_tasks_and_stops_at_once_when_idle(self) -> None:
        server = Server()
        stop = threading.Event()
        with serving(server) as url:
            runtime = self.runtime(url)
            runtime.negotiate()
            thread = threading.Thread(target=lambda: setattr(self, "outcome", runtime.run(stop)), daemon=True)
            thread.start()
            deadline = time.monotonic() + 10
            while not server.bodies("/api/agent/v2/results/") and time.monotonic() < deadline:
                time.sleep(0.02)
            started = time.monotonic()
            stop.set()
            thread.join(timeout=5)
            self.assertLess(time.monotonic() - started, 2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.outcome, rt.STOPPED)
        self.assertEqual(server.bodies("/api/agent/v2/results/")[0]["run"]["task"], "presence")

    def test_a_stop_during_a_task_lets_it_finish_and_starts_no_other(self) -> None:
        server = Server(config={"subnets": [], "tasks": {"presence": {"every_seconds": 60}, "hypervisors": {"every_seconds": 300},
                                                          "inventory": {"every_seconds": 0}, "configs": {"every_seconds": 0},
                                                          "ups": {"every_seconds": 0}}})
        stop = threading.Event()
        ran: list[str] = []

        def slow_sweep(ctx: dict) -> list[Finding]:
            ran.append("sweep")
            stop.set()  # «Detener» a mitad de la presencia
            time.sleep(0.2)
            return sweep_finding(self.alive)(ctx)

        self.collectors["sweep"].behaviour = slow_sweep
        with serving(server) as url:
            runtime = self.runtime(url)
            runtime.negotiate()
            self.assertEqual(runtime.run(stop), rt.STOPPED)
        self.assertEqual(ran, ["sweep"])
        results = server.bodies("/api/agent/v2/results/")
        self.assertEqual([b["run"]["task"] for b in results], ["presence"])  # terminó y la empujó
        self.assertEqual(self.collectors["hypervisors"].contexts, [])  # y no empezó otra

    def test_an_order_wakes_the_loop_and_runs_first(self) -> None:
        server = Server()
        server.orders = [{"id": "o-1", "kind": "run_task", "params": {"task": "hypervisors"}}]
        stop = threading.Event()
        with serving(server) as url:
            runtime = self.runtime(url)
            runtime.negotiate()
            thread = threading.Thread(target=runtime.run, args=(stop,), daemon=True)
            thread.start()
            deadline = time.monotonic() + 10
            while len(server.bodies("/api/agent/v2/results/")) < 1 and time.monotonic() < deadline:
                time.sleep(0.02)
            stop.set()
            thread.join(timeout=5)
        first = server.bodies("/api/agent/v2/results/")[0]["run"]
        self.assertEqual((first["task"], first["trigger"], first["order_id"]), ("hypervisors", "order", "o-1"))
        answers = [p for p, _ in server.requests if p.startswith("/api/agent/v2/orders/")]
        self.assertEqual(answers, ["/api/agent/v2/orders/o-1/result/"])  # una vez, aunque se repita

    def test_a_server_pause_blocks_scheduled_tasks(self) -> None:
        server = Server()
        stop = threading.Event()
        with serving(server) as url:
            runtime = self.runtime(url)
            runtime.negotiate()
            runtime.shared.server_paused_until = datetime(2999, 1, 1, tzinfo=timezone.utc)
            self.assertIsNone(runtime.next_job())
            runtime.shared.server_paused_until = None
            self.assertEqual(runtime.next_job(), Job("presence"))
        stop.set()

    def test_no_task_before_the_first_configuration(self) -> None:
        runtime = self.runtime("http://127.0.0.1:9")
        self.assertIsNone(runtime.next_job())

    def test_a_404_mid_run_falls_back_to_protocol_1(self) -> None:
        server = Server()
        with serving(server) as url:
            runtime = self.runtime(url)
            runtime.negotiate()
            server.v2 = False  # el servidor «se desactualiza»
            with runtime.shared.lock:
                runtime.shared.checkin_seconds = 0
            self.assertEqual(runtime.run(threading.Event()), rt.FALLBACK)

    def test_once_runs_a_presence_and_an_inventory_and_raises_on_failure(self) -> None:
        server = Server()
        with serving(server) as url:
            runtime = self.runtime(url)
            runtime.negotiate()
            runtime.once()
            self.assertEqual([b["run"]["task"] for b in server.bodies("/api/agent/v2/results/")], ["presence", "inventory"])
            server.fail_results = 5
            with self.assertRaises(PushError):
                runtime.once()
        self.assertEqual(runtime.outbox.count(), 0)


class StopAfterOneWait:
    """Un `stop_event` que apunta cuánto le piden esperar y para en la primera espera."""

    def __init__(self) -> None:
        self.waits: list[float] = []

    def is_set(self) -> bool:
        return bool(self.waits)

    def wait(self, timeout: float | None = None) -> bool:
        self.waits.append(timeout or 0)
        return True


class RefusalTests(RuntimeTestCase):
    """A revoked token (401) or a read-only installation (402) stops the scanning."""

    def setUp(self) -> None:
        super().setUp()
        self.server = Server()
        self.serving = serving(self.server)
        url = self.serving.__enter__()
        self.addCleanup(self.serving.__exit__, None, None, None)
        self.rt = self.runtime(url)
        self.assertEqual(self.rt.negotiate(), rt.V2)
        self.rt._queue_order(Job("presence", "order", order_id="o-1"))
        self.said: list[str] = []
        patcher = mock.patch("agent.control.logs.error", side_effect=self.said.append)
        patcher.start()
        self.addCleanup(patcher.stop)

    def refuse(self, status: int) -> None:
        with mock.patch.object(self.rt.client, "checkin", side_effect=PushError(f"{status}", status=status)):
            self.assertFalse(self.rt.control.checkin_once())

    def checkin_seconds_while_refused(self) -> float:
        stop = StopAfterOneWait()
        with mock.patch.object(self.rt.control, "checkin_once", return_value=False):
            self.rt.control.run(stop)
        return stop.waits[0]

    def test_a_401_drops_the_credentials_starts_nothing_and_checks_in_slowly(self) -> None:
        self.server.config = {**self.server.config, "credentials": [{"kind": "ssh", "username": "a", "secret": "s"}]}
        self.rt.shared.config_etag = "viejo"  # que el siguiente checkin la traiga
        self.assertTrue(self.rt.control.checkin_once())
        self.assertTrue(self.rt.shared.config_snapshot()[0]["credentials"])

        self.refuse(401)

        self.assertIsNone(self.rt.next_job())
        self.assertEqual(self.rt.shared.config_snapshot(), ({}, ""))
        self.assertFalse(self.rt.shared.has_config)
        self.assertEqual(self.rt.scheduler.queued, ())  # el encargo pendiente, fuera
        with self.assertRaises(RuntimeError):
            self.rt._probe("10.0.0.5")
        self.assertEqual(self.checkin_seconds_while_refused(), 300)
        self.assertTrue(any("rechazado" in line for line in self.said), self.said)

    def test_after_a_401_the_agent_comes_back_by_itself(self) -> None:
        self.refuse(401)

        self.assertTrue(self.rt.control.checkin_once())

        self.assertTrue(self.rt.shared.has_config)
        self.assertEqual(self.rt.shared.refused(), "")
        self.assertEqual(self.rt.next_job().task, "presence")  # la programada, de nuevo
        self.assertEqual(self.checkin_seconds_while_refused(), 10)

    def test_a_402_starts_nothing_but_keeps_the_config_and_the_queue(self) -> None:
        config = self.rt.shared.config_snapshot()

        self.refuse(402)

        self.assertIsNone(self.rt.next_job())
        self.assertEqual(self.rt.shared.config_snapshot(), config)
        self.assertEqual(len(self.rt.scheduler.queued), 1)
        self.assertEqual(self.checkin_seconds_while_refused(), 10)  # el ritmo de siempre
        self.assertTrue(any("solo lectura" in line for line in self.said), self.said)

        self.assertTrue(self.rt.control.checkin_once())

        job = self.rt.next_job()
        self.assertEqual((job.task, job.order_id), ("presence", "o-1"))


class MainTests(RuntimeTestCase):
    """`main` elige protocolo, y vuelve al 1 si el servidor no sabe del 2."""

    def run_main(self, url: str, stop: threading.Event, argv: list[str] | None = None) -> list[str]:
        printed: list[str] = []
        with mock.patch.object(loop, "from_env", return_value=Config(url=url, token="cya_token")), mock.patch(
            "builtins.print", side_effect=lambda text, **kwargs: printed.append(text)
        ):
            loop.main(argv or [], stop_event=stop)
        return printed

    def test_against_a_protocol_1_server_the_old_loop_runs(self) -> None:
        server = Server(v2=False)
        stop = threading.Event()

        def stop_after_sweep(*args: Any, **kwargs: Any) -> int:
            stop.set()
            return 900

        with serving(server) as url, mock.patch.object(loop, "_nap", return_value=900), mock.patch.object(
            loop, "sweep", side_effect=stop_after_sweep
        ) as sweep:
            printed = self.run_main(url, stop)
        self.assertEqual(sweep.call_count, 1)
        self.assertTrue(printed[0].startswith("[agente] Empujando a"))
        # El 404 del checkin se confirma con un latido del protocolo 1 (spec 1.8).
        self.assertEqual([p for p, _ in server.requests], ["/api/agent/v2/checkin/", "/api/agent/heartbeat/"])

    def test_the_old_loop_tries_protocol_2_again_every_hour(self) -> None:
        server = Server(v2=False)
        stop = threading.Event()
        sweeps = []

        def sweep(*args: Any, **kwargs: Any) -> int:
            sweeps.append(1)
            if len(sweeps) == 2:
                server.v2 = True  # el servidor se actualiza entre barridos
            return 900

        def runtime_run(self_runtime: Runtime, stop_event: Any) -> str:
            stop.set()
            return rt.STOPPED

        with serving(server) as url, mock.patch.object(loop, "_nap", return_value=900), mock.patch.object(
            loop, "sweep", side_effect=sweep
        ), mock.patch.object(loop, "V2_RETRY_SECONDS", 0), mock.patch.object(Runtime, "run", runtime_run):
            printed = self.run_main(url, stop)
        self.assertEqual(len(sweeps), 2)
        self.assertEqual(len(server.bodies("/api/agent/v2/checkin/")), 3)  # al arrancar y tras cada barrido
        self.assertTrue(any("protocolo 2" in line for line in printed))

    def test_the_retry_waits_an_hour(self) -> None:
        self.assertEqual(loop.V2_RETRY_SECONDS, 3600)

    def test_against_a_protocol_2_server_the_runtime_runs(self) -> None:
        server = Server()
        stop = threading.Event()
        with serving(server) as url, mock.patch.object(Runtime, "run", side_effect=lambda s: stop.set() or rt.STOPPED) as run, \
                mock.patch.object(loop, "sweep") as sweep:
            printed = self.run_main(url, stop)
        run.assert_called_once()
        sweep.assert_not_called()
        self.assertEqual(printed[0], f"[agente] Conectado a {url} con el protocolo 2.")
        self.assertEqual(printed[-1], "[agente] Detenido.")

    def test_a_fallback_mid_run_goes_to_the_old_loop(self) -> None:
        server = Server()
        stop = threading.Event()
        with serving(server) as url, mock.patch.object(Runtime, "run", return_value=rt.FALLBACK), mock.patch.object(
            loop, "sweep", side_effect=lambda *a, **k: stop.set() or 900
        ) as sweep, mock.patch.object(loop, "_nap", return_value=900):
            self.run_main(url, stop)
        sweep.assert_called_once()

    def test_once_with_protocol_2_pushes_two_results(self) -> None:
        server = Server()
        with serving(server) as url:
            self.run_main(url, threading.Event(), ["--once"])
        self.assertEqual([b["run"]["task"] for b in server.bodies("/api/agent/v2/results/")], ["presence", "inventory"])

    def test_once_leaves_the_services_orders_outbox_and_memory_alone(self) -> None:
        """`--once` puede correr con el servicio en marcha: antes contestaba
        `done` a sus encargos sin hacerlos, borraba sus temporales, vaciaba su
        cola y pisaba su memoria."""
        from agent import outbox as outbox_module

        state = Path(self.state)
        queue = outbox_module.Outbox(state / "outbox")
        queue.put_result({"run": {"id": "del-servicio"}, "items": [], "part": 1, "final": True})
        in_flight = state / "outbox" / ".out-del-servicio.tmp"
        in_flight.write_text("a medio escribir", encoding="utf-8")
        memory_file = state / "memory.json"
        memory_file.write_text('{"version": 1, "etag": "x", "hosts": {}}', encoding="utf-8")
        before = memory_file.read_bytes()
        server = Server()
        server.orders = [
            {"id": "o-run", "kind": "run_task", "params": {"task": "presence"}},
            {"id": "o-probe", "kind": "probe", "params": {"ip": "192.0.2.1"}},
        ]

        with serving(server) as url:
            self.run_main(url, threading.Event(), ["--once"])

        paths = [p for p, _ in server.requests]
        self.assertFalse([p for p in paths if p.startswith("/api/agent/v2/orders/")])
        self.assertEqual([b["run"]["id"] for b in server.bodies("/api/agent/v2/results/")].count("del-servicio"), 0)
        self.assertEqual([b["run"]["trigger"] for b in server.bodies("/api/agent/v2/results/")], ["schedule", "schedule"])
        self.assertTrue(in_flight.exists())
        self.assertEqual(outbox_module.Outbox(state / "outbox").count(), 1)
        self.assertEqual(memory_file.read_bytes(), before)

    def test_once_with_protocol_1_still_sweeps(self) -> None:
        server = Server(v2=False)
        with serving(server) as url:
            self.run_main(url, threading.Event(), ["--once"])
        self.assertEqual(len(server.bodies("/api/agent/findings/")), 1)

    def test_what_the_loop_says_also_lands_in_the_log(self) -> None:
        from agent import logs

        server = Server()
        stop = threading.Event()
        with serving(server) as url, mock.patch.object(Runtime, "run", side_effect=lambda s: stop.set() or rt.STOPPED):
            self.run_main(url, stop)
        logs.close()
        text = logs.path().read_text(encoding="utf-8")
        self.assertIn("Conectado a", text)
        self.assertIn("Detenido.", text)
        self.assertNotIn("cya_token", text)


if __name__ == "__main__":
    unittest.main()
