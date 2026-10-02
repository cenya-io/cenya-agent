"""The control channel of protocol 2, driven one check-in at a time."""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado y la carpeta del agente

import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from agent import control
from agent.client import PushError
from agent.control import Control, Hooks, Shared
from agent.outbox import Outbox
from agent.scheduler import Job

NOW = datetime(2026, 10, 2, 9, 0, tzinfo=timezone.utc)
ABOUT = {"hostname": "SRV", "networks": []}


class FakeClient:
    """Un servidor con guion: lo que contesta cada checkin y lo que recibe."""

    def __init__(self, answers: list[Any] | None = None) -> None:
        self.answers = list(answers or [])
        self.checkins: list[dict] = []
        self.order_answers: list[tuple[str, dict]] = []
        self.parts: list[dict] = []
        self.fail_orders: list[Exception] = []
        self.fail_parts: list[Exception] = []
        #: El latido del protocolo 1: lo que contesta un servidor viejo de verdad.
        self.heartbeat_answer: Any = PushError("no hay nadie", status=None)
        self.heartbeats = 0

    def heartbeat(self, *, version: str, hostname: str) -> Any:
        self.heartbeats += 1
        if isinstance(self.heartbeat_answer, Exception):
            raise self.heartbeat_answer
        return self.heartbeat_answer

    def checkin(self, body: dict) -> Any:
        self.checkins.append(body)
        answer = self.answers.pop(0) if self.answers else {"ok": True, "protocol": 2}
        if isinstance(answer, Exception):
            raise answer
        return answer

    def answer_order(self, order_id: str, body: dict) -> dict:
        if self.fail_orders:
            raise self.fail_orders.pop(0)
        self.order_answers.append((order_id, body))
        return {"ok": True}

    def post_result_part(self, body: dict) -> dict:
        if self.fail_parts:
            raise self.fail_parts.pop(0)
        self.parts.append(body)
        return {"ok": True}


class ControlTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="cenya-control-"))
        self.outbox = Outbox(self.dir / "outbox")
        self.shared = Shared()
        self.queued: list[Job] = []
        self.etags: list[str] = []
        self.probed: list[str] = []
        self.client = FakeClient()
        self.about = dict(ABOUT)
        self.hooks = Hooks(
            about=lambda: self.about,
            schedule=lambda now: [],
            local_pause=lambda: None,
            run_task=self.queued.append,
            config_changed=self.etags.append,
            probe=lambda ip: self.probed.append(ip) or {"ssh": "puerto 22 cerrado"},
            excluded=lambda ip: ip == "10.0.0.66",
        )

    def control(self, **kwargs: Any) -> Control:
        return Control(self.client, self.shared, self.outbox, self.hooks, clock=lambda: NOW, report=False, **kwargs)

    def wait_probes(self, ctl: Control) -> None:
        for thread in ctl.probe_threads:
            thread.join(timeout=5)


class CheckinBodyTests(ControlTestCase):
    def test_the_body_follows_the_spec(self) -> None:
        ctl = self.control()
        body, about_hash = ctl.body(NOW)
        self.assertEqual(body["protocol"], 2)
        self.assertEqual(body["state"], "idle")
        self.assertIsNone(body["activity"])
        self.assertIsNone(body["paused_until"])
        self.assertEqual(body["config_etag"], "")
        self.assertEqual(body["about_hash"], about_hash)
        self.assertEqual(body["outbox"], 0)
        self.assertEqual(body["about"], ABOUT)

    def test_running_and_paused_states(self) -> None:
        ctl = self.control()
        self.shared.set_activity({"task": "presence"})
        self.assertEqual(ctl.body(NOW)[0]["state"], "running")
        self.shared.set_activity(None)
        self.shared.server_paused_until = NOW + timedelta(hours=1)
        self.assertEqual(ctl.body(NOW)[0]["state"], "paused")

    def test_the_about_travels_only_when_it_changed_or_was_asked_for(self) -> None:
        ctl = self.control()
        ctl.checkin_once()
        ctl.checkin_once()
        self.assertIn("about", self.client.checkins[0])
        self.assertNotIn("about", self.client.checkins[1])
        self.about = {**ABOUT, "hostname": "OTRO"}
        ctl.checkin_once()
        self.assertIn("about", self.client.checkins[2])
        self.client.answers = [{"ok": True, "protocol": 2, "need_about": True}]
        ctl.checkin_once()
        ctl.checkin_once()
        self.assertIn("about", self.client.checkins[4])


class ApplyTests(ControlTestCase):
    def test_config_is_applied_only_when_the_etag_changes(self) -> None:
        ctl = self.control()
        ctl.apply({"config_etag": "e1", "config": {"subnets": ["10.0.0.0/24"]}})
        ctl.apply({"config_etag": "e1", "config": {"subnets": ["otra cosa"]}})
        self.assertEqual(self.shared.config, {"subnets": ["10.0.0.0/24"]})
        self.assertEqual(self.etags, ["e1"])
        ctl.apply({"config_etag": "e2"})  # otro etag sin config: se queda la de antes
        self.assertEqual(self.shared.config_etag, "e1")
        ctl.apply({"config_etag": "e2", "config": {"subnets": []}})
        self.assertEqual((self.shared.config, self.etags), ({"subnets": []}, ["e1", "e2"]))
        self.assertEqual(ctl.body(NOW)[0]["config_etag"], "e2")

    def test_checkin_seconds_is_bounded(self) -> None:
        ctl = self.control()
        for raw, expected in ((1, 10), (9999, 300), (45, 45), ("x", 45), (None, 45), (True, 45)):
            ctl.apply({"checkin_seconds": raw})
            self.assertEqual(self.shared.checkin_seconds, expected, raw)

    def test_server_pause_and_update_are_recorded(self) -> None:
        ctl = self.control()
        ctl.apply({"paused_until": "2026-10-02T10:00:00+00:00", "update": {"version": "0.11.1"}})
        self.assertEqual(self.shared.server_paused_until, NOW + timedelta(hours=1))
        self.assertEqual(self.shared.update, {"version": "0.11.1"})
        self.assertTrue(self.shared.wake.is_set())
        ctl.apply({"paused_until": None, "update": None})
        self.assertIsNone(self.shared.server_paused_until)
        self.assertIsNone(self.shared.update)


class ServerTimeTests(ControlTestCase):
    """The server's `paused_until` is in the server's clock; this machine's may differ."""

    def answer_two_hours_behind(self) -> dict:
        server_now = NOW - timedelta(hours=2)
        return {"ok": True, "protocol": 2, "server_time": server_now.isoformat(),
                "paused_until": (server_now + timedelta(minutes=30)).isoformat()}

    def test_a_server_pause_is_applied_in_this_machines_clock(self) -> None:
        self.client.answers = [self.answer_two_hours_behind()]
        ctl = self.control()

        self.assertTrue(ctl.checkin_once())

        until = self.shared.server_paused_until
        self.assertLess(abs((until - (NOW + timedelta(minutes=30))).total_seconds()), 1)
        # Sin corregir, la pausa ya habría «caducado» hace hora y media.
        self.assertEqual(ctl.body(NOW)[0]["state"], "paused")

    def test_a_slow_round_trip_is_not_trusted_to_measure_the_clocks(self) -> None:
        self.client.answers = [self.answer_two_hours_behind()]
        ctl = self.control()

        with mock.patch("agent.control.time.monotonic", side_effect=[0.0, 30.0]):
            self.assertTrue(ctl.checkin_once())

        self.assertEqual(self.shared.clock_offset, timedelta(0))
        self.assertEqual(self.shared.server_paused_until, NOW - timedelta(hours=1, minutes=30))


class OrderTests(ControlTestCase):
    def test_an_order_runs_once_even_if_delivered_three_times(self) -> None:
        ctl = self.control()
        order = {"id": "o-1", "kind": "run_task", "params": {"task": "presence"}}
        for _ in range(3):
            ctl.apply({"orders": [order]})
        self.assertEqual(self.queued, [Job("presence", "order", order_id="o-1")])
        self.assertEqual(self.client.order_answers, [("o-1", {"status": "done", "result": {}, "notes": []})])

    def test_an_unknown_kind_is_answered_unsupported(self) -> None:
        ctl = self.control()
        ctl.apply({"orders": [{"id": "o-2", "kind": "reboot", "params": {}}]})
        self.assertEqual(self.client.order_answers[0][1]["status"], "unsupported")
        ctl.apply({"orders": [{"id": "o-3", "kind": "run_task", "params": {"task": "backup"}}]})
        self.assertEqual(self.client.order_answers[1][1]["status"], "unsupported")
        self.assertEqual(self.queued, [])

    def test_rubbish_orders_are_ignored(self) -> None:
        ctl = self.control()
        ctl.apply({"orders": ["x", {"kind": "probe"}, None]})
        ctl.apply({"orders": "no es una lista"})
        self.assertEqual(self.client.order_answers, [])

    def test_a_probe_runs_in_its_own_thread_and_answers_with_the_report(self) -> None:
        ctl = self.control()
        ctl.apply({"orders": [{"id": "p-1", "kind": "probe", "params": {"ip": "10.0.0.5"}}]})
        self.wait_probes(ctl)
        self.assertEqual(self.probed, ["10.0.0.5"])
        self.assertEqual(
            self.client.order_answers,
            [("p-1", {"status": "done", "result": {"probe_report": {"ssh": "puerto 22 cerrado"}}, "notes": []})],
        )
        self.assertEqual(self.queued, [])  # sin tocar la cola de tareas

    def test_a_probe_never_touches_an_excluded_or_invalid_address(self) -> None:
        ctl = self.control()
        ctl.apply({"orders": [
            {"id": "p-2", "kind": "probe", "params": {"ip": "10.0.0.66"}},
            {"id": "p-3", "kind": "probe", "params": {"ip": "no-es-ip"}},
        ]})
        self.wait_probes(ctl)
        self.assertEqual(self.probed, [])
        answers = dict(self.client.order_answers)
        self.assertEqual(answers["p-2"]["status"], "failed")
        self.assertEqual(answers["p-2"]["notes"][0]["code"], "excluded")
        self.assertEqual(answers["p-3"]["notes"][0]["code"], "bad_address")

    def test_at_most_two_probes_at_once_and_never_two_on_the_same_ip(self) -> None:
        guard = threading.Lock()
        running: list[str] = []
        peak = [0]
        same_ip_overlap: list[str] = []

        def slow_probe(ip: str) -> dict:
            with guard:
                if ip in running:
                    same_ip_overlap.append(ip)
                running.append(ip)
                peak[0] = max(peak[0], len(running))
            time.sleep(0.05)
            with guard:
                running.remove(ip)
            return {"ip": ip}

        self.hooks.probe = slow_probe
        ctl = self.control()
        ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.5", "10.0.0.5"]
        ctl.apply({"orders": [{"id": f"p-{n}", "kind": "probe", "params": {"ip": ip}} for n, ip in enumerate(ips)]})
        self.wait_probes(ctl)

        self.assertLessEqual(peak[0], 2)
        self.assertEqual(control.MAX_PROBES, 2)
        self.assertEqual(same_ip_overlap, [])
        # Todos esperan su turno y todos se contestan.
        self.assertEqual(sorted(order_id for order_id, _ in self.client.order_answers), sorted(f"p-{n}" for n in range(7)))
        self.assertEqual(ctl._probe_ip_locks, {})

    def test_a_probe_that_crashes_is_answered_failed(self) -> None:
        self.hooks.probe = lambda ip: 1 / 0
        ctl = self.control()
        ctl.apply({"orders": [{"id": "p-4", "kind": "probe", "params": {"ip": "10.0.0.5"}}]})
        self.wait_probes(ctl)
        body = self.client.order_answers[0][1]
        self.assertEqual(body["status"], "failed")
        self.assertEqual(body["notes"][0]["code"], "crashed")

    def test_a_failed_answer_goes_to_the_outbox_and_is_retried(self) -> None:
        ctl = self.control()
        self.client.fail_orders = [PushError("caído")]
        ctl.apply({"orders": [{"id": "o-9", "kind": "run_task", "params": {"task": "ups"}}]})
        self.assertEqual(self.outbox.count(), 1)
        self.assertEqual(ctl.body(NOW)[0]["outbox"], 1)
        ctl.checkin_once()  # un checkin que sale bien vacía la cola
        self.assertEqual(self.outbox.count(), 0)
        self.assertEqual(self.client.order_answers, [("o-9", {"status": "done", "result": {}, "notes": []})])
        self.assertEqual(len(self.queued), 1)

    def test_an_order_waiting_in_the_outbox_is_not_run_again_after_a_restart(self) -> None:
        self.outbox.put_order_answer("o-7", {"status": "done", "result": {}, "notes": []})
        ctl = self.control()  # un arranque nuevo, con la respuesta aún en la cola
        ctl.apply({"orders": [{"id": "o-7", "kind": "run_task", "params": {"task": "presence"}}]})
        self.assertEqual(self.queued, [])

    def test_an_answer_the_server_will_never_take_is_not_queued(self) -> None:
        ctl = self.control()
        self.client.fail_orders = [PushError("no existe", status=404)]
        ctl.apply({"orders": [{"id": "o-x", "kind": "run_task", "params": {"task": "ups"}}]})
        self.assertEqual(self.outbox.count(), 0)


class CheckinTests(ControlTestCase):
    def test_a_404_with_a_working_heartbeat_means_the_server_only_speaks_protocol_1(self) -> None:
        self.client.answers = [PushError("no", status=404)]
        self.client.heartbeat_answer = {"interval_seconds": 900, "config": {}}
        ctl = self.control()
        self.assertFalse(ctl.checkin_once())
        self.assertTrue(ctl.gone)

    def test_a_404_with_a_failing_heartbeat_is_a_server_unwell_and_protocol_2_stays(self) -> None:
        """Un proxy inverso a mitad de un despliegue: antes, una hora entera de
        barridos completos del protocolo 1 por un solo 404."""
        for heartbeat in (PushError("caído"), PushError("no", status=404), PushError("502", status=502)):
            with self.subTest(heartbeat=str(heartbeat)):
                self.client.answers = [PushError("no", status=404), {"ok": True, "protocol": 2}]
                self.client.heartbeat_answer = heartbeat
                ctl = self.control()
                self.assertFalse(ctl.checkin_once())
                self.assertFalse(ctl.gone)
                self.assertTrue(ctl.checkin_once())  # y en cuanto vuelve, sigue en el 2

    def test_a_network_failure_is_not_a_404(self) -> None:
        self.client.answers = [PushError("caído"), PushError("401", status=401)]
        ctl = self.control()
        self.assertFalse(ctl.checkin_once())
        self.assertFalse(ctl.checkin_once())
        self.assertFalse(ctl.gone)

    def test_the_outbox_drains_in_order_after_a_good_checkin(self) -> None:
        for part in (1, 2, 3):
            self.outbox.put_result({"run": {"id": "r"}, "items": [], "part": part, "final": part == 3})
        ctl = self.control()
        self.client.answers = [PushError("caído")]
        ctl.checkin_once()
        self.assertEqual(self.outbox.count(), 3)  # un checkin fallido no vacía nada
        ctl.checkin_once()
        self.assertEqual([p["part"] for p in self.client.parts], [1, 2, 3])
        self.assertEqual(self.outbox.count(), 0)

    def test_exceptions_do_not_kill_the_thread(self) -> None:
        calls = []

        def broken_about() -> dict:
            calls.append(1)
            if len(calls) < 3:
                raise RuntimeError("roto")
            return ABOUT

        self.hooks.about = broken_about
        self.client.answers = [ValueError("raro")]
        self.shared.checkin_seconds = 0  # sin esperar entre vueltas
        ctl = self.control()
        stop = threading.Event()

        original = ctl.checkin_once

        def counting() -> bool:
            result = original()
            if len(self.client.checkins) >= 2:
                stop.set()
            return result

        ctl.checkin_once = counting  # type: ignore[method-assign]
        thread = threading.Thread(target=ctl.run, args=(stop,), daemon=True)
        thread.start()
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertGreaterEqual(len(calls), 3)
        self.assertGreaterEqual(len(self.client.checkins), 2)

    def test_the_thread_stops_at_once_and_wakes_the_task_thread(self) -> None:
        ctl = self.control()
        stop = threading.Event()
        thread = threading.Thread(target=ctl.run, args=(stop,), daemon=True)
        thread.start()
        stop.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertTrue(self.shared.wake.is_set())


class HelperTests(unittest.TestCase):
    def test_bound_checkin(self) -> None:
        self.assertEqual(control.bound_checkin(None), 30)
        self.assertEqual(control.bound_checkin(0), 10)
        self.assertEqual(control.bound_checkin(301), 300)

    def test_parse_moment(self) -> None:
        self.assertEqual(control.parse_moment("2026-10-02T09:00:00Z"), NOW)
        self.assertEqual(control.parse_moment("2026-10-02T09:00:00"), NOW)
        self.assertIsNone(control.parse_moment("mañana"))
        self.assertIsNone(control.parse_moment(5))


if __name__ == "__main__":
    unittest.main()
