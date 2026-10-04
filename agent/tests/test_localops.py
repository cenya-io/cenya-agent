"""The local channel's handlers (spec 4) over a real `Runtime`, with no server and no pipe.

Every request goes through the dispatcher as a JSON line, the way a client's
would: what is tested is what a client gets back. The properties that matter
most: who may only read cannot act, a setting changes the running agent
without a restart, a failed ``connect`` leaves the old enrolment, and no
secret -- the agent's token, a proxy password, a community, the NetBox token
-- ever comes out in an answer, an error, the log or the support bundle.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import json
import os
import tempfile
import threading
import time
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from agent import __version__, localops, logs, netbox_export, store
from agent import settings as local_settings
from agent.client import AgentClient, PushError
from agent.config import Config
from agent.localapi import Caller, encode
from agent.localops import CONNECTED, DISCONNECTED, LocalService, SessionStop, connection_test, read_log
from agent.runtime import Runtime
from agent.scheduler import Job

TOKEN = "cya_TOKEN_DEL_AGENTE_1234"
ADMIN = Caller(admin=True, who="S-1-5-21-1-2-3-500")
USER = Caller(admin=False, who="S-1-5-21-1-2-3-1001")
CODE = "K7QF-9M2X-4TQN"
TASKS_ON = {"presence": {"every_seconds": 300}, "inventory": {"every_seconds": 0}, "configs": {"every_seconds": 0},
            "ups": {"every_seconds": 0}, "hypervisors": {"every_seconds": 0}}


class LocalServiceCase(unittest.TestCase):
    def setUp(self) -> None:
        self.state = Path(tempfile.mkdtemp(prefix="cenya-local-"))
        for patcher in (
            mock.patch.dict(os.environ, {"CENYA_STATE_DIR": str(self.state)}),
            mock.patch("agent.runtime.about.build", return_value={"hostname": "PRUEBA", "networks": []}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        for name in ("CENYA_PROXY", "CENYA_AGENT_TOKEN", "CENYA_CA_BUNDLE", "CENYA_EXCLUDED_ADDRESSES"):
            os.environ.pop(name, None)
        logs.setup()
        self.addCleanup(logs.close)
        store.save(store.Enrollment("https://portal.example", TOKEN, "CPD"))
        self.client = AgentClient("https://portal.example", TOKEN)
        self.config = Config(url="https://portal.example", token=TOKEN)
        self.runtime = Runtime(self.client, self.config, report=False)
        self.service = LocalService()
        self.service.attach(self.runtime, self.client, self.config, "v2")
        self.dispatcher = self.service.dispatcher()

    def call(self, op: str, args: dict[str, Any] | None = None, caller: Caller = ADMIN) -> dict[str, Any]:
        line = json.dumps({"id": 1, "op": op, "args": args or {}}).encode()
        answer = self.dispatcher.handle_line(line, caller)
        encode(answer)  # siempre se puede mandar
        return answer

    def data(self, op: str, args: dict[str, Any] | None = None) -> Any:
        answer = self.call(op, args)
        self.assertTrue(answer["ok"], answer)
        return answer["data"]

    def give_config(self, config: dict[str, Any]) -> None:
        with self.runtime.shared.lock:
            self.runtime.shared.config, self.runtime.shared.has_config = dict(config), True
        self.runtime.scheduler.configure(config.get("tasks"))

    def log_text(self) -> str:
        logs.close()
        try:
            return logs.path().read_text(encoding="utf-8") if logs.path().exists() else ""
        finally:
            logs.setup()


class ReadTests(LocalServiceCase):
    def test_status_is_for_anyone_and_says_what_the_agent_is_doing(self) -> None:
        self.give_config({"tasks": TASKS_ON})
        answer = self.call("status", caller=USER)
        self.assertTrue(answer["ok"])
        data = answer["data"]
        self.assertEqual((data["enrolled"], data["name"], data["protocol"]), (True, "CPD", "v2"))
        self.assertEqual(data["portal"], "https://portal.example")
        self.assertEqual(data["state"], "idle")
        self.assertEqual(data["connection"]["state"], "unknown")
        self.assertEqual([row["task"] for row in data["schedule"]][0], "presence")
        self.assertEqual(data["outbox"], 0)
        self.assertFalse(data["may_act"])
        self.assertNotIn(TOKEN, json.dumps(data))

    def test_status_shows_the_last_checkin_and_a_running_task(self) -> None:
        with mock.patch.object(self.client, "checkin", side_effect=PushError("El servidor respondió 503: caído", status=503)):
            self.runtime.control.checkin_once()
        self.runtime.shared.set_activity({"task": "inventory", "step": "ssh", "done": 3, "total": 9})
        data = self.data("status")
        self.assertEqual(data["connection"]["state"], "error")
        self.assertEqual(data["connection"]["status"], 503)
        self.assertEqual(data["state"], "running")
        self.assertEqual(data["activity"]["step"], "ssh")

    def test_status_without_an_identity(self) -> None:
        self.service.detach()
        data = self.data("status")
        self.assertEqual((data["enrolled"], data["connection"]["state"]), (False, "not_enrolled"))

    def test_log_returns_the_tail_and_then_only_what_is_new(self) -> None:
        for n in range(5):
            logs.info(f"linea {n}")
        data = self.data("log", {"lines": 2})
        self.assertEqual([line.split(" ", 3)[-1] for line in data["lines"]], ["linea 3", "linea 4"])
        logs.info("linea nueva con Bearer abc.def")
        later = self.data("log", {"after": data["cursor"]})
        self.assertEqual(len(later["lines"]), 1)
        self.assertIn("linea nueva", later["lines"][0])
        self.assertNotIn("abc.def", later["lines"][0])
        self.assertEqual(self.call("log", {"lines": 0})["error"], "invalid")

    def test_log_reads_a_rotated_file_from_its_end(self) -> None:
        path = self.state / "otro.log"
        path.write_text("".join(f"l{n}\n" for n in range(10)), encoding="utf-8")
        first = read_log(path, 3)
        self.assertEqual(first["lines"], ["l7", "l8", "l9"])
        path.unlink()
        path.write_text("nuevo\n", encoding="utf-8")
        self.assertEqual(read_log(path, 3, first["cursor"])["lines"], ["nuevo"])
        self.assertTrue(read_log(self.state / "no-existe.log", 3)["missing"])

    def test_about_is_the_presentation(self) -> None:
        self.assertEqual(self.data("about")["hostname"], "PRUEBA")

    def test_settings_get_masks_the_proxy_password(self) -> None:
        local_settings.save(local_settings.Settings(proxy_mode="manual", proxy_url="http://ana:S3cr3tPx@proxy:8080"))
        answer = self.call("settings.get", caller=USER)
        self.assertEqual(answer["data"]["proxy"], {"mode": "manual", "url": "http://***@proxy:8080", "has_credentials": True})
        self.assertNotIn("S3cr3tPx", json.dumps(answer))
        self.assertNotIn("ana", answer["data"]["proxy"]["url"])

    def test_settings_get_says_what_the_environment_fixes(self) -> None:
        with mock.patch.dict(os.environ, {"CENYA_EXCLUDED_ADDRESSES": "10.0.0.1"}):
            data = self.data("settings.get")
        self.assertIn("excluded", data["locked"])
        self.assertEqual(data["excluded"]["addresses"], ["10.0.0.1"])


class ActRefusedTests(LocalServiceCase):
    def test_every_act_is_forbidden_to_who_may_only_read(self) -> None:
        from agent.localapi import OPERATIONS

        before = store.load()
        for op, kind in OPERATIONS.items():
            if kind != "act":
                continue
            with self.subTest(op=op):
                answer = self.call(op, {"task": "presence", "seconds": 60, "ip": "192.0.2.1", "connection": f"cenya://x/{CODE}",
                                        "url": "https://nb", "token": "t", "path": str(self.state)}, caller=USER)
                self.assertEqual(answer["error"], "forbidden")
        self.assertEqual(store.load(), before)
        self.assertIsNone(local_settings.load_file().paused_until)
        self.assertEqual(self.runtime.scheduler.queued, ())


class RunAndPauseTests(LocalServiceCase):
    def test_run_puts_the_task_first_in_the_queue(self) -> None:
        self.give_config({"tasks": TASKS_ON})
        self.assertEqual(self.data("run", {"task": "hypervisors"}), {"queued": "hypervisors", "waiting_for": ""})
        self.assertEqual(self.runtime.next_job(), Job("hypervisors", "order"))
        self.assertEqual(self.call("run", {"task": "everything"})["error"], "invalid")

    def test_run_says_when_it_will_have_to_wait(self) -> None:
        self.assertEqual(self.data("run", {"task": "presence"})["waiting_for"], "config")
        self.service.set_mode("v1")
        self.assertEqual(self.call("run", {"task": "presence"})["error"], "unavailable")

    def test_pause_stops_scheduled_work_at_once_and_resume_brings_it_back(self) -> None:
        self.give_config({"tasks": TASKS_ON})
        self.assertEqual(self.runtime.next_job(), Job("presence"))
        data = self.data("pause", {"seconds": 3600})
        self.assertIsNone(self.runtime.next_job())
        self.assertTrue(self.runtime.shared.wake.is_set())
        saved = local_settings.load_file().paused_until
        self.assertEqual(saved.isoformat(), data["paused_until"])
        self.assertEqual(self.data("status")["state"], "paused")
        self.assertIsNone(self.data("resume")["paused_until"])
        self.assertEqual(self.runtime.next_job(), Job("presence"))

    def test_resume_does_not_hide_a_pause_from_the_web(self) -> None:
        later = datetime.now(timezone.utc) + timedelta(hours=2)
        with self.runtime.shared.lock:
            self.runtime.shared.server_paused_until = later
        self.assertEqual(self.data("resume")["server_paused_until"], later.isoformat())

    def test_pause_until_and_its_limits(self) -> None:
        until = (datetime.now(timezone.utc) + timedelta(hours=3)).replace(microsecond=0)
        self.assertEqual(self.data("pause", {"until": until.isoformat()})["paused_until"], until.isoformat())
        for args in ({}, {"seconds": -5}, {"seconds": True}, {"until": "mañana"},
                     {"until": "2001-01-01T00:00:00+00:00"}, {"seconds": 40 * 86400}):
            with self.subTest(args=args):
                self.assertEqual(self.call("pause", args)["error"], "invalid")

    def test_pause_keeps_the_other_settings(self) -> None:
        local_settings.save(local_settings.Settings(excluded_addresses=("10.0.0.9",), extra={"futuro": 1}))
        self.data("pause", {"seconds": 60})
        kept = local_settings.load_file()
        self.assertEqual(kept.excluded_addresses, ("10.0.0.9",))
        self.assertEqual(kept.extra, {"futuro": 1})


class SettingsSetTests(LocalServiceCase):
    def test_one_bad_field_changes_nothing(self) -> None:
        answer = self.call("settings.set", {"excluded": {"subnets": ["10.0.0.0/8", "no-es-red"], "addresses": []},
                                            "gentleness_cap": "gentle", "colour": "red"})
        self.assertEqual(answer["error"], "invalid")
        self.assertEqual(set(answer["details"]["fields"]), {"excluded", "colour"})
        self.assertIn("no-es-red", answer["details"]["fields"]["excluded"])
        self.assertFalse(local_settings.path().exists())

    def test_each_field_is_validated(self) -> None:
        cases = [
            {"language": "klingon"},
            {"ca_bundle": str(self.state / "no-existe.pem")},
            {"ca_bundle": 3},
            {"proxy": {"mode": "manual", "url": "https:/ana:S3cret@proxy:8080"}},
            {"proxy": {"mode": "pac"}},
            {"proxy": "http://proxy:8080"},
            {"excluded": ["10.0.0.0/8"]},
            {"gentleness_cap": "brutal"},
            {"auto_update": "yes"},
            {"notifications": 1},
        ]
        for args in cases:
            with self.subTest(args=args):
                answer = self.call("settings.set", args)
                self.assertEqual(answer["error"], "invalid")
                self.assertNotIn("S3cret", json.dumps(answer))
        bad_pem = self.state / "malo.pem"
        bad_pem.write_text("no es un certificado", encoding="utf-8")
        self.assertEqual(self.call("settings.set", {"ca_bundle": str(bad_pem)})["error"], "invalid")
        self.assertEqual(self.call("settings.set", {})["error"], "invalid")

    def test_exclusions_and_gentleness_apply_without_a_restart(self) -> None:
        data = self.data("settings.set", {"excluded": {"subnets": ["10.9.0.0/16"], "addresses": ["192.0.2.7"]},
                                          "gentleness_cap": "gentle", "auto_update": False})
        self.assertEqual(data["restart_required"], [])
        self.assertEqual(set(data["applied"]), {"excluded", "gentleness_cap", "auto_update"})
        self.assertIn("192.0.2.7", self.runtime.excluded)
        self.assertIn("10.9.1.1", self.runtime.excluded)
        self.assertEqual(self.runtime._base_ctx({"gentleness": "fast"})["workers"], {"ping": 8, "login": 2, "snmp": 5})
        self.assertFalse(self.runtime.settings.auto_update)
        self.assertIsNone(self.runtime._about)  # el `about` se recalcula y viaja en el próximo checkin
        self.assertEqual(self.call("probe", {"ip": "192.0.2.7"})["error"], "excluded")

    def test_the_proxy_applies_at_once_and_a_masked_url_keeps_its_password(self) -> None:
        self.data("settings.set", {"proxy": {"mode": "manual", "url": "http://ana:S3cr3tPx@proxy.lan:3128"}})
        self.assertEqual(self.client._proxy, ("manual", "http://ana:S3cr3tPx@proxy.lan:3128"))
        shown = self.data("settings.get")["proxy"]["url"]
        self.assertEqual(shown, "http://***@proxy.lan:3128")
        # El formulario devuelve lo que vio: la contraseña no se pierde.
        self.data("settings.set", {"proxy": {"mode": "manual", "url": shown}})
        self.assertEqual(local_settings.load_file().proxy_url, "http://ana:S3cr3tPx@proxy.lan:3128")
        self.data("settings.set", {"proxy": {"mode": "none", "url": ""}})
        self.assertEqual(self.client._proxy, ("none", ""))
        self.assertNotIn("S3cr3tPx", self.log_text())

    def test_the_language_applies_at_once(self) -> None:
        with mock.patch.dict(os.environ, {}):
            self.data("settings.set", {"language": "en"})
            self.assertEqual(os.environ.get("CENYA_LANGUAGE"), "en")
            self.data("settings.set", {"language": ""})
            self.assertIsNone(os.environ.get("CENYA_LANGUAGE"))

    def test_a_value_fixed_by_the_environment_is_saved_but_said(self) -> None:
        with mock.patch.dict(os.environ, {"CENYA_EXCLUDED_ADDRESSES": "10.0.0.1"}):
            data = self.data("settings.set", {"excluded": {"subnets": [], "addresses": ["10.0.0.2"]}})
        self.assertEqual(data["overridden_by_environment"], ["excluded"])


class ProbeTests(LocalServiceCase):
    def test_probe_returns_the_report(self) -> None:
        with mock.patch("agent.runtime.probe.report_for", return_value={"ssh": "puerto 22 cerrado"}) as report:
            data = self.data("probe", {"ip": "192.0.2.5"})
        self.assertEqual(data, {"ip": "192.0.2.5", "report": {"ssh": "puerto 22 cerrado"}})
        self.assertEqual(report.call_args.args[0], "192.0.2.5")
        self.assertEqual(self.data("status")["local"]["probe"]["state"], "done")

    def test_probe_refuses_nonsense_and_a_rejected_agent(self) -> None:
        self.assertEqual(self.call("probe", {"ip": "999.1.1.1"})["error"], "invalid")
        with self.runtime.shared.lock:
            self.runtime.shared.refusal = "unauthorized"
        self.assertEqual(self.call("probe", {"ip": "192.0.2.5"})["error"], "unavailable")


class ConnectionTestTests(unittest.TestCase):
    URL = "https://portal.example:8443"

    def run_test(self, **overrides: Any) -> list[dict[str, Any]]:
        def resolve(host: str, port: int) -> list:
            return [("ok",)]

        class Socket:
            def __enter__(self):  # noqa: ANN204
                return self

            def __exit__(self, *exc: object) -> None:
                pass

        kwargs: dict[str, Any] = {
            "ca_bundle": "",
            "proxy": ("none", ""),
            "checkin": lambda: (True, None, ""),
            "resolve": resolve,
            "open_tcp": lambda address, timeout: Socket(),
            "tls": lambda host, port, ca: (True, "ok", {}),
        }
        kwargs.update(overrides)
        return connection_test(self.URL, **kwargs)

    def codes(self, steps: list[dict[str, Any]]) -> list[tuple[str, str]]:
        return [(step["step"], step["code"]) for step in steps]

    def test_all_good(self) -> None:
        steps = self.run_test()
        self.assertEqual(self.codes(steps), [("dns", "ok"), ("tcp", "ok"), ("tls", "ok"), ("checkin", "ok")])
        self.assertTrue(all(step["ok"] and step["message"] for step in steps))

    def test_each_failure_stops_there_with_its_code(self) -> None:
        def no_name(host: str, port: int) -> None:
            raise OSError("getaddrinfo failed")

        def refused(address: tuple, timeout: float) -> None:
            raise ConnectionRefusedError

        def slow(address: tuple, timeout: float) -> None:
            raise TimeoutError

        self.assertEqual(self.codes(self.run_test(resolve=no_name)), [("dns", "not_found")])
        self.assertEqual(self.codes(self.run_test(open_tcp=refused))[-1], ("tcp", "refused"))
        self.assertEqual(self.codes(self.run_test(open_tcp=slow))[-1], ("tcp", "timeout"))
        steps = self.run_test(tls=lambda h, p, c: (False, "certificate", {"reason": "certificate has expired"}))
        self.assertEqual(self.codes(steps)[-1], ("tls", "certificate"))
        self.assertIn("certificate has expired", steps[-1]["message"])
        self.assertEqual(steps[-1]["params"]["reason"], "certificate has expired")
        self.assertEqual(self.codes(self.run_test(checkin=lambda: (False, 401, "x")))[-1], ("checkin", "unauthorized"))
        self.assertEqual(self.codes(self.run_test(checkin=lambda: (False, 402, "x")))[-1], ("checkin", "read_only"))
        self.assertEqual(self.codes(self.run_test(checkin=lambda: (False, 500, "x")))[-1], ("checkin", "http_error"))
        self.assertEqual(self.codes(self.run_test(checkin=lambda: (False, None, "timed out")))[-1], ("checkin", "unreachable"))
        self.assertEqual(self.codes(self.run_test(checkin=None))[-1], ("checkin", "not_enrolled"))

    def test_through_a_proxy_the_proxy_is_what_is_tried(self) -> None:
        tried: list[tuple[str, int]] = []

        def resolve(host: str, port: int) -> list:
            tried.append((host, port))
            return []

        steps = self.run_test(proxy=("manual", "http://ana:S3cret@proxy.lan:3128"), resolve=resolve)
        self.assertEqual(tried, [("proxy.lan", 3128)])
        self.assertEqual(self.codes(steps)[2], ("tls", "via_proxy"))
        self.assertNotIn("S3cret", json.dumps(steps))

    def test_the_real_tls_check_names_the_certificate_problem(self) -> None:
        import ssl

        error = ssl.SSLCertVerificationError(1, "certificate verify failed")
        error.verify_message = "self-signed certificate"
        with mock.patch("agent.localops.socket.create_connection") as connect, mock.patch(
            "agent.localops.ssl.SSLContext.wrap_socket", side_effect=error
        ), mock.patch("agent.client._mozilla_roots", return_value=""):
            connect.return_value.__enter__.return_value = object()
            self.assertEqual(localops._tls_check("portal", 443, ""), (False, "certificate", {"reason": "self-signed certificate"}))

    def test_the_service_uses_a_real_checkin_and_reads_its_outcome(self) -> None:
        state = tempfile.mkdtemp(prefix="cenya-local-")
        with mock.patch.dict(os.environ, {"CENYA_STATE_DIR": state}), mock.patch(
            "agent.runtime.about.build", return_value={"hostname": "PRUEBA"}
        ):
            client = AgentClient("https://portal.example", TOKEN)
            runtime = Runtime(client, Config(url="https://portal.example", token=TOKEN), report=False)
            service = LocalService()
            service.attach(runtime, client, runtime.env, "v2")
            with mock.patch.object(client, "checkin", side_effect=PushError("El servidor respondió 401: no", status=401)):
                outcome = service._checkin_now()()
            self.assertEqual(outcome[:2], (False, 401))
            self.assertEqual(runtime.shared.refused(), "unauthorized")
            service.set_mode("v1")
            with mock.patch.object(client, "heartbeat", return_value={"ok": True}):
                self.assertEqual(service._checkin_now()(), (True, None, ""))


class FakeEnrollClient:
    answer: dict[str, Any] | Exception = {}

    def __init__(self, base_url: str, token: str, **kwargs: Any) -> None:
        self.base_url = base_url

    def enroll(self, **kwargs: Any) -> dict[str, Any]:
        if isinstance(FakeEnrollClient.answer, Exception):
            raise FakeEnrollClient.answer
        return dict(FakeEnrollClient.answer)


class IdentityTests(LocalServiceCase):
    def setUp(self) -> None:
        super().setUp()
        for patcher in (
            mock.patch("agent.enroll.AgentClient", FakeEnrollClient),
            mock.patch("agent.enroll.identity.ensure", return_value=""),
            mock.patch("agent.enroll.about.build", return_value={}),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_connect_saves_the_new_identity_and_restarts_the_session(self) -> None:
        FakeEnrollClient.answer = {"ok": True, "token": "cya_NUEVO_TOKEN_5678", "name": "Oficina", "uuid": "u"}
        stop = self.service.stop_signal(None)
        data = self.data("connect", {"connection": f"cenya://otro.example/{CODE}"})
        self.assertEqual(data, {"name": "Oficina", "portal": "https://otro.example", "restarting": True})
        self.assertEqual(store.load(), store.Enrollment("https://otro.example", "cya_NUEVO_TOKEN_5678", "Oficina", "u"))
        self.assertTrue(stop.is_set())
        self.assertEqual(self.service.take_change(), CONNECTED)
        self.assertNotIn("cya_NUEVO_TOKEN_5678", json.dumps(data) + self.log_text())

    def test_connect_with_code_and_portal(self) -> None:
        FakeEnrollClient.answer = {"ok": True, "token": "cya_N", "name": "Oficina"}
        self.data("connect", {"code": CODE, "portal": "https://otro.example"})
        self.assertEqual(store.load().url, "https://otro.example")

    def test_a_failed_redeem_keeps_the_old_enrolment_and_the_session(self) -> None:
        FakeEnrollClient.answer = PushError("El servidor respondió 400: Código caducado.", status=400)
        stop = self.service.stop_signal(None)
        answer = self.call("connect", {"connection": f"cenya://otro.example/{CODE}"})
        self.assertEqual(answer["error"], "failed")
        self.assertIn("Código caducado", answer["message"])
        self.assertEqual(store.load(), store.Enrollment("https://portal.example", TOKEN, "CPD"))
        self.assertFalse(stop.is_set())
        self.assertIsNone(self.service.take_change())

    def test_a_bad_string_never_reaches_the_server(self) -> None:
        FakeEnrollClient.answer = AssertionError("no debería llamarse")
        for args in ({}, {"connection": "cenya://portal/corto"}, {"connection": 3}):
            with self.subTest(args=args):
                self.assertIn(self.call("connect", args)["error"], ("invalid", "failed"))
        self.assertEqual(store.load().token, TOKEN)

    def test_a_token_fixed_by_the_environment_cannot_be_replaced_from_here(self) -> None:
        with mock.patch.dict(os.environ, {"CENYA_AGENT_TOKEN": "cya_env"}):
            self.assertEqual(self.call("connect", {"connection": f"cenya://otro.example/{CODE}"})["error"], "unavailable")

    def test_disconnect_with_the_server_unreachable_still_leaves(self) -> None:
        store.write_protected(self.state / store.IDENTITY_FILE, "-----BEGIN PRIVATE KEY-----\n")
        stop = self.service.stop_signal(None)
        with mock.patch.object(self.client, "goodbye", side_effect=PushError("No se pudo hablar con el servidor: timed out")) as goodbye:
            data = self.data("disconnect")
        goodbye.assert_called_once_with("uninstall")
        self.assertIs(data["told_server"], False)
        self.assertIn("No se pudo avisar al servidor", data["message"])
        self.assertEqual(sorted(data["removed"]), sorted([store.FILE_NAME, store.IDENTITY_FILE]))
        self.assertIsNone(store.load())
        self.assertTrue(stop.is_set())
        self.assertEqual(self.service.take_change(), DISCONNECTED)

    def test_disconnect_tells_the_server_when_it_can(self) -> None:
        with mock.patch.object(self.client, "goodbye", return_value={"ok": True}):
            self.assertIs(self.data("disconnect")["told_server"], True)

    def test_after_a_change_the_old_outbox_is_discarded(self) -> None:
        self.runtime.outbox.put_result({"run": {"id": "r1"}, "items": [], "part": 1, "final": True})
        self.assertEqual(self.runtime.outbox.count(), 1)
        self.service.discard_outbox()
        self.assertEqual(self.runtime.outbox.count(), 0)

    def test_waiting_for_a_connect_ends_with_it_or_with_the_service(self) -> None:
        stop = threading.Event()
        threading.Timer(0.2, lambda: self.service._request_change(CONNECTED)).start()
        self.assertTrue(self.service.wait_for_connect(stop))
        stop.set()
        self.assertFalse(self.service.wait_for_connect(stop))


class NetboxExportTests(LocalServiceCase):
    NB_TOKEN = "nbt_0123456789abcdef_SECRETO"

    def export(self, **args: Any) -> dict[str, Any]:
        payload = {"url": "https://netbox.lan", "token": self.NB_TOKEN, **args}
        answer = self.call("netbox.export", payload)
        self.assertNotIn(self.NB_TOKEN, encode(answer).decode("utf-8"))
        return answer

    def assert_no_token_anywhere(self) -> None:
        self.assertNotIn(self.NB_TOKEN, self.log_text())
        self.assertNotIn(self.NB_TOKEN, json.dumps(self.data("status")))

    def test_without_send_the_bundle_is_written_to_path_and_progress_is_visible(self) -> None:
        seen: list[dict] = []

        def fetch(url: str, token: str, verify_tls: bool = True, progress: Any = None) -> dict:
            self.assertEqual(token, self.NB_TOKEN)
            for path in ("/api/dcim/sites/", "/api/dcim/devices/"):
                progress(path)
                seen.append(self.service.jobs()["netbox_export"])
            return {"sites": [{"id": 1}], "devices": [{"id": 1}, {"id": 2}]}

        target = self.state / "nb.json"
        with mock.patch.object(netbox_export, "fetch_bundle", side_effect=fetch):
            answer = self.export(path=str(target))
        self.assertTrue(answer["ok"], answer)
        self.assertEqual(answer["data"]["summary"], {"sites": 1, "devices": 2})
        self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["devices"][1], {"id": 2})
        self.assertNotIn(self.NB_TOKEN, target.read_text(encoding="utf-8"))
        self.assertEqual(seen[1]["step"], "/api/dcim/devices/")
        self.assertEqual(seen[1]["state"], "running")
        # Las ya leídas, todas, para que la ventana no enseñe huecos.
        self.assertEqual((seen[0]["finished"], seen[1]["finished"]), ([], ["/api/dcim/sites/"]))
        self.assertEqual(self.service.jobs()["netbox_export"]["state"], "done")
        self.assert_no_token_anywhere()

    def test_with_send_it_goes_through_the_upload_and_no_file_is_needed(self) -> None:
        uploads: list[tuple] = []
        self.client.upload_netbox_bundle = lambda bundle, order_id=None: uploads.append((bundle, order_id)) or {"ok": True, "import": "imp-1"}  # type: ignore[attr-defined]
        with mock.patch.object(netbox_export, "fetch_bundle", return_value={"sites": []}):
            answer = self.export(send=True)
        self.assertEqual(
            answer["data"],
            {"import": "imp-1", "summary": {"sites": 0}, "review_url": "https://portal.example/settings/import/pending/imp-1/"},
        )
        self.assertEqual(uploads, [({"sites": []}, None)])

    def test_with_send_the_server_may_say_where_to_review(self) -> None:
        for given, expected in (
            ("/importar/revisar/imp-2/", "https://portal.example/importar/revisar/imp-2/"),
            ("https://portal.example/x/imp-2/", "https://portal.example/x/imp-2/"),
            # De otro sitio no: la ventana lo abriría en el navegador.
            ("https://otro.example/x/", "https://portal.example/settings/import/pending/imp-2/"),
            ("//otro.example/x/", "https://portal.example/settings/import/pending/imp-2/"),
        ):
            with self.subTest(given=given):
                self.client.upload_netbox_bundle = lambda bundle, order_id=None: {"ok": True, "import": "imp-2", "review_url": given}  # type: ignore[attr-defined]
                with mock.patch.object(netbox_export, "fetch_bundle", return_value={}):
                    self.assertEqual(self.export(send=True)["data"]["review_url"], expected)

    def test_failures_never_carry_the_token(self) -> None:
        failures = [
            netbox_export.ExportError("NetBox rechazó el token."),
            RuntimeError(f"algo con {self.NB_TOKEN} dentro"),
            ValueError(self.NB_TOKEN),
        ]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with mock.patch.object(netbox_export, "fetch_bundle", side_effect=failure):
                    answer = self.export(path=str(self.state / "x.json"))
                self.assertEqual(answer["error"], "failed")
        self.client.upload_netbox_bundle = mock.Mock(side_effect=PushError(f"El servidor respondió 413: {self.NB_TOKEN}"))  # type: ignore[attr-defined]
        with mock.patch.object(netbox_export, "fetch_bundle", return_value={}):
            self.export(send=True)
        self.assert_no_token_anywhere()

    def test_bad_arguments(self) -> None:
        for args in ({"path": "relativo.json"}, {"path": str(self.state / "no" / "x.json")}, {"verify_tls": "no", "path": str(self.state)}, {}):
            with self.subTest(args=args):
                self.assertEqual(self.export(**args)["error"], "invalid")
        self.assertEqual(self.call("netbox.export", {"url": "https://nb", "path": str(self.state)})["error"], "invalid")

    def test_one_export_at_a_time(self) -> None:
        release = threading.Event()
        started = threading.Event()

        def slow(*args: Any, **kwargs: Any) -> dict:
            started.set()
            release.wait(5)
            return {}

        with mock.patch.object(netbox_export, "fetch_bundle", side_effect=slow):
            first = threading.Thread(target=self.export, kwargs={"path": str(self.state)}, daemon=True)
            first.start()
            started.wait(5)
            self.assertEqual(self.export(path=str(self.state))["error"], "busy")
            release.set()
            first.join(5)


class SupportBundleTests(LocalServiceCase):
    def test_the_bundle_has_what_support_needs_and_no_secret(self) -> None:
        secrets = {
            "token": TOKEN,
            "proxy": "Pr0xyPa55",
            "ssh": "SshS3cret!",
            "priv": "V3PrivPass",
            "community": "c0mmun1ty",
            "key": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
        }
        local_settings.save(local_settings.Settings(proxy_mode="manual", proxy_url=f"http://ana:{secrets['proxy']}@proxy:3128"))
        self.give_config({
            "tasks": TASKS_ON,
            "communities": [secrets["community"]],
            "credentials": [{"kind": "ssh", "username": "admin", "secret": secrets["ssh"]},
                            {"kind": "snmpv3", "username": "lector", "secret": "x" * 8, "priv_secret": secrets["priv"]}],
        })
        store.write_protected(
            self.state / store.IDENTITY_FILE, f"-----BEGIN PRIVATE KEY-----\n{secrets['key']}\n-----END PRIVATE KEY-----\n"
        )
        # Lo peor que podría haber en un registro: todo lo anterior, escrito tal cual.
        for value in secrets.values():
            logs.info(f"filtrado: {value}")
        logs.info(f"-----BEGIN PRIVATE KEY-----\n{secrets['key']}\n-----END PRIVATE KEY-----")
        logs.info(f"Authorization: Bearer {TOKEN}")
        logs.close()
        rotated = logs.path().with_name("agent.log.1")
        rotated.write_text(f"antiguo {secrets['ssh']} y {secrets['community']}\n", encoding="utf-8")
        logs.setup()

        data = self.data("support_bundle", {"path": str(self.state)})
        target = Path(data["path"])
        self.assertTrue(target.name.startswith("cenya-soporte-") and target.suffix == ".zip")
        with zipfile.ZipFile(target) as bundle:
            names = set(bundle.namelist())
            contents = "\n".join(bundle.read(name).decode("utf-8") for name in names)
        self.assertTrue({"version.json", "about.json", "settings.json", "status.json", "logs/agent.log", "logs/agent.log.1"} <= names)
        self.assertIn("filtrado", contents)  # el registro está…
        for name, value in secrets.items():
            with self.subTest(secret=name):
                self.assertNotIn(value, contents)  # …pero sin ningún secreto
        self.assertNotIn("PRIVATE KEY-----\n", contents)
        self.assertNotIn(TOKEN[:12], contents)

    def test_a_path_that_cannot_be_used(self) -> None:
        self.assertEqual(self.call("support_bundle", {"path": "relativo.zip"})["error"], "invalid")
        self.assertEqual(self.call("support_bundle", {})["error"], "invalid")


class CheckUpdateTests(LocalServiceCase):
    ANSWER = {"ok": True, "protocol": 2, "checkin_seconds": 30, "config_etag": "e1", "config": {"tasks": TASKS_ON}}

    def test_it_asks_the_server_now_and_answers_with_what_it_brought(self) -> None:
        asked: list[dict] = []
        answer = {**self.ANSWER, "update": {"version": "9.0.0", "url": "https://x/latest.json"}}
        with mock.patch.object(self.client, "checkin", side_effect=lambda body: asked.append(body) or answer):
            data = self.data("check_update")
        self.assertEqual(len(asked), 1)  # un checkin de verdad, ahora
        self.assertEqual((data["current"], data["offered"], data["checked"], data["pending"]), (__version__, "9.0.0", True, False))
        self.assertEqual(data["error"], "")
        self.assertIsNotNone(data["checked_at"])
        self.assertEqual(data["last_ok_at"], data["checked_at"])
        self.assertIn("state", data["updater"])
        self.assertTrue(data["auto_update"])
        self.assertEqual(self.data("status")["update"]["version"], "9.0.0")

    def test_a_checkin_that_fails_says_so(self) -> None:
        with mock.patch.object(self.client, "checkin", side_effect=PushError("No se pudo hablar con el servidor", status=None)):
            data = self.data("check_update")
        self.assertFalse(data["checked"])
        self.assertIn("No se pudo hablar", data["error"])
        self.assertIsNone(data["offered"])

    def test_a_server_that_does_not_answer_in_time_leaves_it_pending(self) -> None:
        release = threading.Event()
        self.service.check_update_wait = 0.2
        with mock.patch.object(self.client, "checkin", side_effect=lambda body: release.wait(5) and self.ANSWER):
            started = time.monotonic()
            data = self.data("check_update")
            self.assertLess(time.monotonic() - started, 3)
            release.set()
        self.assertTrue(data["pending"])
        self.assertFalse(data["checked"])

    def test_it_never_runs_alongside_the_control_threads_checkin(self) -> None:
        inside = threading.Semaphore(0)
        overlap: list[int] = []
        running = [0]

        def slow(body: dict) -> dict:
            running[0] += 1
            overlap.append(running[0])
            time.sleep(0.2)
            running[0] -= 1
            return self.ANSWER

        with mock.patch.object(self.client, "checkin", side_effect=slow):
            other = threading.Thread(target=self.runtime.control.checkin_once)
            other.start()
            self.data("check_update")
            other.join(5)
        self.assertEqual(max(overlap), 1)


class StatusForTheWindowTests(LocalServiceCase):
    """What the desktop application asked the service for (spec 4, `status`)."""

    def test_the_last_run_of_each_task_with_its_figures(self) -> None:
        self.give_config({"tasks": TASKS_ON})
        hosts = [{"ip": "10.0.0.1", "mac": "aa"}, {"ip": "10.0.0.2", "mac": "bb"}]

        def presence(task: str, ctx: dict) -> tuple:
            ctx["hosts"] = hosts
            return [{"kind": "host", "ip": h["ip"]} for h in hosts], [], {"collectors": 2, "items": 2, "crashed": 0, "hosts_alive": 2}

        with mock.patch("agent.runtime.tasks.run_task", side_effect=presence), mock.patch.object(
            self.client, "push_results", return_value={"created": 1, "refreshed": 1}
        ):
            self.runtime.run_job(Job("presence"))
        run = self.data("status")["last_run"]["presence"]
        self.assertEqual(
            {k: run[k] for k in ("task", "status", "hosts_alive", "new_hosts", "sent", "delivered", "created", "refreshed", "notes")},
            {"task": "presence", "status": "ok", "hosts_alive": 2, "new_hosts": 2, "sent": 2, "delivered": True,
             "created": 1, "refreshed": 1, "notes": 0},
        )
        self.assertTrue(run["finished_at"])

    def test_a_result_left_in_the_queue_has_no_server_figures_yet(self) -> None:
        self.give_config({"tasks": TASKS_ON})
        with mock.patch("agent.runtime.tasks.run_task", return_value=([{"kind": "host"}], [], {"collectors": 1, "items": 1, "crashed": 0})), \
                mock.patch.object(self.client, "push_results", side_effect=PushError("caído", status=503)):
            self.runtime.run_job(Job("inventory", "order"))
        run = self.data("status")["last_run"]["inventory"]
        self.assertEqual((run["delivered"], run["created"], run["refreshed"], run["sent"]), (False, None, None, 1))

    def test_the_last_good_contact_is_kept_while_the_checkins_fail(self) -> None:
        with mock.patch.object(self.client, "checkin", return_value=CheckUpdateTests.ANSWER):
            self.runtime.control.checkin_once()
        good = self.data("status")["last_ok_at"]
        self.assertIsNotNone(good)
        with mock.patch.object(self.client, "checkin", side_effect=PushError("caído", status=503)):
            self.runtime.control.checkin_once()
        data = self.data("status")
        self.assertEqual(data["connection"]["state"], "error")
        self.assertEqual((data["last_ok_at"], data["connection"]["last_ok_at"]), (good, good))

    def test_the_effective_gentleness_after_the_local_cap(self) -> None:
        self.give_config({"tasks": TASKS_ON, "gentleness": "fast"})
        self.assertEqual(self.data("status")["gentleness"], "fast")
        self.data("settings.set", {"gentleness_cap": "gentle"})
        self.assertEqual(self.data("status")["gentleness"], "gentle")

    def test_where_the_log_is_and_why_there_is_no_identity(self) -> None:
        data = self.data("status")
        self.assertEqual(data["log_folder"], str(logs.path().parent))
        self.assertEqual(data["enrollment"], {"state": "enrolled", "message": ""})
        self.service.detach()
        self.service.set_unenrolled(localops.UNTRUSTED_STATE, "apartado")
        data = self.data("status")
        self.assertEqual(data["enrollment"], {"state": "untrusted", "message": "apartado"})
        self.assertEqual(data["log_folder"], str(logs.path().parent))
        self.assertEqual(data["name"], "")


class IndefinitePauseTests(LocalServiceCase):
    def test_a_pause_until_resumed_has_no_end_and_resume_ends_it(self) -> None:
        self.give_config({"tasks": TASKS_ON})
        data = self.data("pause", {"indefinite": True})
        self.assertEqual((data["paused_until"], data["indefinite"]), (None, True))
        self.assertIsNone(self.runtime.next_job())
        status = self.data("status")
        self.assertEqual(status["state"], "paused")
        self.assertEqual(status["pause"], {"local": None, "server": None, "until": None, "indefinite": True})
        self.assertEqual(json.loads(local_settings.path().read_text(encoding="utf-8"))["paused_until"], "indefinite")
        settings = self.data("settings.get")
        self.assertEqual((settings["paused_until"], settings["paused_indefinitely"]), (None, True))
        # Y al servidor se le dice como lo que es, no como el año 9999.
        body, _ = self.runtime.control.body(datetime.now(timezone.utc))
        self.assertEqual((body["state"], body["paused_until"], body["paused_indefinitely"]), ("paused", None, True))
        self.data("resume")
        self.assertEqual(self.runtime.next_job(), Job("presence"))
        body, _ = self.runtime.control.body(datetime.now(timezone.utc))
        self.assertNotIn("paused_indefinitely", body)

    def test_a_dated_pause_still_has_its_limit_and_indefinite_takes_no_date(self) -> None:
        for args in ({"seconds": 40 * 86400}, {"indefinite": True, "seconds": 60}, {"indefinite": "yes"},
                     {"indefinite": True, "until": "2030-01-01T00:00:00+00:00"}):
            with self.subTest(args=args):
                self.assertEqual(self.call("pause", args)["error"], "invalid")
        self.assertIn("hasta que lo reanudes", self.call("pause", {"seconds": 40 * 86400})["message"])


class ReviewUrlTests(unittest.TestCase):
    def test_built_from_the_portal_when_the_server_does_not_say(self) -> None:
        self.assertEqual(
            localops.review_url("https://cenya.example/sub", {"import": "0f3c-9"}),
            "https://cenya.example/sub" + localops.NETBOX_REVIEW_PATH.format(import_id="0f3c-9"),
        )

    def test_nothing_to_open_without_a_portal_or_a_clean_id(self) -> None:
        self.assertEqual(localops.review_url("", {"import": "x"}), "")
        self.assertEqual(localops.review_url("https://p", {"import": "../../x"}), "")
        self.assertEqual(localops.review_url("https://p", {}), "")


class SessionStopTests(unittest.TestCase):
    def test_either_side_stops_it(self) -> None:
        outer, inner = threading.Event(), threading.Event()
        stop = SessionStop(outer, inner)
        self.assertFalse(stop.is_set())
        self.assertFalse(stop.wait(0.05))
        threading.Timer(0.1, inner.set).start()
        started = time.monotonic()
        self.assertTrue(stop.wait(10))
        self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(SessionStop(None, inner).is_set())
        outer2 = threading.Event()
        outer2.set()
        self.assertTrue(SessionStop(outer2, threading.Event()).wait(5))


if __name__ == "__main__":
    unittest.main()
