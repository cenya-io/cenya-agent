"""Where the updater plugs into the agent: the check-in (`agent.control`) and the task loop (`agent.runtime`).

The updater itself is tested in `test_update.py`; these only check the seams:
the check-in carries `update_state`, its answer's `update` reaches the updater
after every good check-in, and no task starts while a verified update waits.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado y la carpeta del agente

import dataclasses
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent.client import AgentClient
from agent.config import Config
from agent.control import Control, Hooks, Shared
from agent.outbox import Outbox
from agent.runtime import Runtime
from agent.tests.test_control import ABOUT, NOW, FakeClient
from agent.tests.test_runtime import Server, serving


class ControlSeamTests(unittest.TestCase):
    def setUp(self) -> None:
        folder = Path(tempfile.mkdtemp(prefix="cenya-hooks-"))
        self.offered: list[object] = []
        self.client = FakeClient()
        self.hooks = Hooks(
            about=lambda: dict(ABOUT),
            schedule=lambda now: [],
            local_pause=lambda: None,
            run_task=lambda job: None,
            config_changed=lambda etag: None,
            probe=lambda ip: {},
            excluded=lambda ip: False,
            update_offered=self.offered.append,
            update_state=lambda: {"state": "ready", "version": "0.11.1", "error": ""},
        )
        self.control = Control(self.client, Shared(), Outbox(folder / "outbox"), self.hooks, clock=lambda: NOW, report=False)

    def test_the_checkin_carries_the_update_state(self) -> None:
        body, _hash = self.control.body(NOW)

        self.assertEqual(body["update_state"], {"state": "ready", "version": "0.11.1", "error": ""})

    def test_without_an_updater_the_body_is_as_before(self) -> None:
        hooks = dataclasses.replace(self.hooks, update_state=lambda: None)
        control = Control(self.client, Shared(), self.control.outbox, hooks, clock=lambda: NOW, report=False)

        self.assertNotIn("update_state", control.body(NOW)[0])

    def test_every_good_checkin_hands_its_update_field_to_the_updater(self) -> None:
        self.client.answers = [
            {"ok": True, "protocol": 2, "update": {"version": "0.11.1", "explicit": True}},
            {"ok": True, "protocol": 2, "update": None},
        ]

        self.control.checkin_once()
        self.control.checkin_once()

        self.assertEqual(self.offered, [{"version": "0.11.1", "explicit": True}, None])

    def test_a_failed_checkin_offers_nothing(self) -> None:
        self.client.answers = [ConnectionError("caído")]

        self.control.checkin_once()

        self.assertEqual(self.offered, [])

    def test_an_updater_that_blows_up_does_not_take_the_checkin_with_it(self) -> None:
        hooks = dataclasses.replace(self.hooks, update_offered=mock.Mock(side_effect=RuntimeError("x")),
                                    update_state=mock.Mock(side_effect=RuntimeError("y")))
        control = Control(self.client, Shared(), self.control.outbox, hooks, clock=lambda: NOW, report=False)

        self.assertTrue(control.checkin_once())
        self.assertNotIn("update_state", self.client.checkins[-1])


class RuntimeSeamTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = tempfile.mkdtemp(prefix="cenya-hooks-runtime-")
        patcher = mock.patch.dict(os.environ, {"CENYA_STATE_DIR": self.state})
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = mock.patch("agent.runtime.about.build", return_value={"hostname": "PRUEBA", "networks": []})
        patcher.start()
        self.addCleanup(patcher.stop)

    def runtime(self, url: str, **kwargs) -> Runtime:  # noqa: ANN003
        return Runtime(AgentClient(url, "cya_token"), Config(url=url, token="cya_token"), report=False, **kwargs)

    def test_no_task_starts_while_a_verified_update_waits(self) -> None:
        server = Server()
        with serving(server) as url:
            runtime = self.runtime(url)
            self.assertEqual(runtime.negotiate(), "v2")
        self.assertIsNotNone(runtime.next_job(), "with a configuration, presence is due")

        with mock.patch.object(runtime.updater, "holding", return_value=True):
            self.assertIsNone(runtime.next_job())

    def test_the_server_offer_reaches_the_updater_and_its_state_goes_back_in_the_checkin(self) -> None:
        server = Server()
        original = server.answer

        def with_update(path: str, body: dict):  # noqa: ANN202
            code, answer = original(path, body)
            if path == "/api/agent/v2/checkin/":
                answer["update"] = {"version": "99.0.0"}
            return code, answer

        server.answer = with_update  # type: ignore[method-assign]
        with serving(server) as url:
            runtime = self.runtime(url)
            self.assertEqual(runtime.control.hooks.update_offered, runtime.updater.offer)
            with mock.patch.object(runtime.control.hooks, "update_offered") as offer:
                runtime.negotiate()
            offer.assert_called_once_with({"version": "99.0.0"})
            body = server.bodies("/api/agent/v2/checkin/")[0]
        self.assertEqual(body["update_state"]["state"], "idle")

    def test_the_first_good_checkin_marks_this_version_healthy(self) -> None:
        from agent import __version__

        with serving(Server()) as url:
            self.runtime(url).negotiate()

        self.assertTrue((Path(self.state) / "updates" / f"healthy-{__version__}").is_file())

    def test_once_never_updates(self) -> None:
        with serving(Server()) as url:
            runtime = self.runtime(url, once=True)
            runtime.negotiate()

        self.assertFalse(runtime.updater.enabled)
        self.assertFalse((Path(self.state) / "updates").exists())


if __name__ == "__main__":
    unittest.main()
