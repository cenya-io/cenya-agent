"""The fake service's answers have the real service's shapes, key by key.

The window is reviewed against `agent.app.fake_server`; if its answers drifted
from `agent.localops`, a screen could look right in review and break against
the real service. The fake already goes through the real dispatcher and
transport; this checks the scripted part: for the same request, every key the
real service answers is in the fake's answer and the other way round, down
through the nested objects the window reads.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from agent import logs, netbox_export, store
from agent.app import fake_server
from agent.client import AgentClient
from agent.config import Config
from agent.localapi import Caller
from agent.localops import LocalService
from agent.runtime import Runtime
from agent.scheduler import Job

ADMIN = Caller(admin=True, who="admin")
TOKEN = "cya_FORMAS_0123456789"
ANSWER = {"ok": True, "protocol": 2, "checkin_seconds": 30, "config_etag": "e1",
          "config": {"tasks": {t: {"every_seconds": 300} for t in ("presence", "inventory", "configs", "ups", "hypervisors")}}}


def keys(value: Any, path: str = "") -> set[str]:
    """Every key path of a JSON value; a list contributes the keys of its items, a dict of tasks those of one task."""
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            here = f"{path}.{key}" if path else str(key)
            found.add(here)
            found |= keys(item, here)
    elif isinstance(value, list):
        for item in value:
            found |= keys(item, path + "[]")
    return found


def by_task(answer: dict) -> dict:
    """`last_run` y `schedule` llevan una entrada por tarea: se compara la forma de una, no cuáles hay."""
    answer = json.loads(json.dumps(answer))
    if isinstance(answer.get("last_run"), dict):
        answer["last_run"] = {"<task>": next(iter(answer["last_run"].values()))} if answer["last_run"] else {}
    return answer


class FakeAnswersHaveTheRealShapesTests(unittest.TestCase):
    def setUp(self) -> None:
        state = Path(tempfile.mkdtemp(prefix="cenya-shapes-"))
        for patcher in (
            mock.patch.dict(os.environ, {"CENYA_STATE_DIR": str(state)}),
            mock.patch("agent.runtime.about.build", return_value={"hostname": "PRUEBA", "networks": []}),
            mock.patch("agent.identity.available", return_value=False),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        logs.setup()
        self.addCleanup(logs.close)
        store.save(store.Enrollment("https://portal.example", TOKEN, "CPD"))
        self.client = AgentClient("https://portal.example", TOKEN)
        self.runtime = Runtime(self.client, Config(url="https://portal.example", token=TOKEN), report=False)
        self.service = LocalService()
        self.service.attach(self.runtime, self.client, Config(url="https://portal.example", token=TOKEN), "v2")
        with mock.patch.object(self.client, "checkin", return_value=ANSWER):
            self.runtime.control.checkin_once()
        with mock.patch("agent.runtime.tasks.run_task", return_value=([], [], {"collectors": 1, "items": 0, "crashed": 0})), \
                mock.patch.object(self.client, "push_results", return_value={"created": 0, "refreshed": 0}):
            self.runtime.run_job(Job("presence"))
        self.state = state
        self.real = self.service.dispatcher()
        self.fake = fake_server.FakeAgent("idle", speed=500).dispatcher()

    def both(self, op: str, args: dict | None = None) -> tuple[dict, dict]:
        line = json.dumps({"id": 1, "op": op, "args": args or {}}).encode()
        real = self.real.handle_line(line, ADMIN)
        fake = self.fake.handle_line(line, ADMIN)
        self.assertTrue(real["ok"], real)
        self.assertTrue(fake["ok"], fake)
        return real["data"], fake["data"]

    def assert_same_shape(self, op: str, args: dict | None = None, ignore: set[str] = frozenset()) -> None:
        real, fake = self.both(op, args)
        real_keys, fake_keys = keys(by_task(real)), keys(by_task(fake))
        self.assertEqual(real_keys - fake_keys - ignore, set(), f"{op}: el servicio contesta esto y el falso no")
        self.assertEqual(fake_keys - real_keys - ignore, set(), f"{op}: el falso contesta esto y el servicio no")

    def test_status(self) -> None:
        # `activity` es null sin tarea en curso, en los dos; `refusal` también.
        self.assert_same_shape("status")

    def test_the_read_operations(self) -> None:
        for op, args in (("settings.get", {}), ("log", {"lines": 5})):
            with self.subTest(op=op):
                self.assert_same_shape(op, args)

    def test_pause_resume_and_an_indefinite_pause(self) -> None:
        for args in ({"seconds": 600}, {"indefinite": True}):
            with self.subTest(args=args):
                self.assert_same_shape("pause", args)
                self.assert_same_shape("status")
        self.assert_same_shape("resume")

    def test_run_and_settings_set(self) -> None:
        self.assert_same_shape("run", {"task": "presence"})
        self.assert_same_shape("settings.set", {"gentleness_cap": "gentle"})

    def test_check_update(self) -> None:
        self.fake = fake_server.FakeAgent("update", speed=500).dispatcher()
        with mock.patch.object(self.client, "checkin", return_value={**ANSWER, "update": {"version": "0.11.1"}}):
            self.assert_same_shape("check_update")

    def test_netbox_export_with_send(self) -> None:
        self.client.upload_netbox_bundle = lambda bundle, order_id=None: {"ok": True, "import": "imp-1"}  # type: ignore[attr-defined]
        with mock.patch.object(netbox_export, "fetch_bundle", return_value={"devices": [{"id": 1}]}):
            # El resumen lleva las colecciones que haya: se compara el resto.
            real, fake = self.both("netbox.export", {"url": "https://nb", "token": "t", "send": True})
        self.assertEqual(set(real), set(fake))
        self.assertTrue(real["review_url"].startswith("https://portal.example/"))

    def test_test_connection_steps(self) -> None:
        with mock.patch("agent.localops.connection_test", return_value=[
            {"step": "dns", "ok": True, "code": "ok", "params": {}, "message": "bien"}
        ]):
            self.assert_same_shape("test_connection")

    def test_an_unenrolled_status(self) -> None:
        self.service.detach()
        self.service.set_unenrolled("not_enrolled", "x")
        self.fake = fake_server.FakeAgent("not_enrolled").dispatcher()
        self.assert_same_shape("status")


if __name__ == "__main__":
    unittest.main()
