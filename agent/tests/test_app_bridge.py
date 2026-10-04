"""The object the page calls (agent/app/bridge.py), against the fake service in memory.

No pipe, no window: the channel client is given an opener that hands each
request straight to `FakeAgent.handle`, so these run on any platform.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - entorno de pruebas

import json
import os
import time
import unittest
from datetime import datetime, timezone
from unittest import mock

from agent import i18n
from agent import localclient as channel
from agent.app import bridge, fake_server, winsys


class MemoryConnection:
    """A transport connection in memory: each line goes through the real dispatcher with the fake handlers."""

    def __init__(self, agent: fake_server.FakeAgent, admin: bool, wire: list) -> None:
        self.agent, self.admin, self.wire = agent, admin, wire
        self.pending: list[bytes] = []

    def send(self, data: bytes, timeout: float) -> None:
        self.wire.append(data)
        reply = self.agent.handle(json.loads(data), admin=self.admin)
        self.pending.append(json.dumps(reply).encode() + b"\n")

    def recv(self, timeout: float) -> bytes:
        if not self.pending:
            raise TimeoutError
        return self.pending.pop(0)

    def close(self) -> None:
        pass


class FakeService:
    dev = False

    def __init__(self) -> None:
        self.calls: list[str] = []

    def query(self) -> dict:
        return {"state": "running", "start_type": "delayed"}

    def start(self) -> None:
        self.calls.append("start")

    def stop(self) -> None:
        self.calls.append("stop")

    def restart(self) -> None:
        self.calls.append("restart")

    def set_autostart(self, enabled: bool) -> None:
        self.calls.append(f"autostart={enabled}")


class FakeTray:
    dev = False

    def __init__(self) -> None:
        self.value = True

    def enabled(self) -> bool:
        return self.value

    def set(self, enabled: bool) -> None:
        self.value = enabled


class FakeDialogs:
    def __init__(self, path: str | None) -> None:
        self.path = path

    def save(self, filename: str, types: tuple) -> str | None:
        return self.path

    def open(self, types: tuple) -> str | None:
        return self.path


def make(scenario: str = "idle", *, elevated: bool = True, admin: bool = True, dev: bool = False, dialogs=None, opened=None):
    agent = fake_server.FakeAgent(scenario, speed=200)
    wire: list[bytes] = []
    client = channel.ChannelClient("memory", opener=lambda a, t: MemoryConnection(agent, admin, wire))
    service = FakeService()
    api = bridge.Api(
        client,
        elevated=elevated,
        dev=dev,
        service=service,
        tray_startup=FakeTray(),
        dialogs=dialogs or FakeDialogs(None),
        opener=(opened.append if opened is not None else (lambda url: True)),
        clock=lambda: datetime.now(timezone.utc),
    )
    return api, agent, wire, service


class BridgeTests(unittest.TestCase):
    def test_nothing_but_the_api_is_reachable_from_the_page(self) -> None:
        api, *_ = make()
        public = [name for name in vars(api) if not name.startswith("_")]
        self.assertEqual(public, [], "pywebview expone también los atributos públicos")

    def test_init_hands_the_page_its_texts(self) -> None:
        api, *_ = make()
        result = api.init()
        self.assertTrue(result["ok"])
        self.assertEqual(result["strings"]["nav_status"], "Estado")

    def test_shell_and_status(self) -> None:
        api, *_ = make("running")
        self.assertEqual(api.shell()["view"]["mode"], "ready")
        view = api.status()["view"]
        self.assertEqual(view["activity"]["task"], "inventory")

    def test_a_reader_is_refused_before_anything_is_sent(self) -> None:
        api, agent, wire, _ = make(elevated=False)
        before = len(wire)
        result = api.run_task("presence")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], channel.FORBIDDEN)
        self.assertEqual(len(wire), before)

    def test_forbidden_from_the_service_turns_the_window_read_only(self) -> None:
        api, *_ = make(admin=False)
        self.assertFalse(api.run_task("presence")["ok"])
        self.assertTrue(api.shell()["view"]["perms"]["readonly"])

    def test_run_pause_resume(self) -> None:
        api, agent, *_ = make()
        self.assertTrue(api.run_task("presence")["ok"])
        self.assertIsNotNone(agent.activity)
        self.assertTrue(api.pause("hour")["view"]["pause"]["paused"])
        self.assertFalse(api.resume()["view"]["pause"]["paused"])
        self.assertFalse(api.pause("forever-and-ever")["ok"])

    def test_log_pages_by_cursor(self) -> None:
        api, *_ = make()
        first = api.log(0)["view"]
        self.assertTrue(first["rows"])
        self.assertEqual(api.log(first["cursor"])["view"]["rows"], [])

    def test_exclusions_round_trip(self) -> None:
        api, agent, *_ = make()
        result = api.add_exclusion("10.9.9.0/24")
        self.assertTrue(result["ok"])
        self.assertIn("10.9.9.0/24", agent.settings["excluded"]["subnets"])
        self.assertFalse(api.add_exclusion("10.9.9.0/24")["ok"])
        self.assertFalse(api.add_exclusion("nope")["ok"])
        api.remove_exclusion("10.9.9.0/24")
        self.assertNotIn("10.9.9.0/24", agent.settings["excluded"]["subnets"])

    def test_only_known_settings_can_be_set(self) -> None:
        api, agent, *_ = make()
        self.assertTrue(api.set_setting("notifications", False)["ok"])
        self.assertFalse(agent.settings["notifications"])
        self.assertFalse(api.set_setting("notifications", "no")["ok"])
        self.assertFalse(api.set_setting("token", "x")["ok"])
        self.assertFalse(api.set_setting("gentleness_cap", "fast")["ok"])

    def test_proxy_kept_hidden_is_not_overwritten(self) -> None:
        api, agent, *_ = make()
        api.set_proxy("manual", "http://user:pw@proxy:8080")
        self.assertEqual(agent.settings["proxy"]["url"], "http://user:pw@proxy:8080")
        shown = api.connection()["view"]["proxy"]["url"]
        self.assertNotIn("pw", shown)
        api.set_proxy("manual", shown)  # guardar lo tapado no pisa la contraseña
        self.assertEqual(agent.settings["proxy"]["url"], "http://user:pw@proxy:8080")
        self.assertFalse(api.set_proxy("manual", "proxy:8080")["ok"])

    def test_connect_and_disconnect(self) -> None:
        api, agent, *_ = make("not_enrolled")
        self.assertEqual(api.shell()["view"]["mode"], "not_enrolled")
        self.assertFalse(api.connect("")["ok"])
        self.assertFalse(api.connect("garbage")["ok"])
        view = api.connect("cenya://acme.cenya.cloud/ABCD-EFGH-JKLM")["view"]
        self.assertTrue(view["enrolled"])
        self.assertEqual(view["portal"], "https://acme.cenya.cloud")
        self.assertFalse(api.disconnect()["view"]["enrolled"])

    def test_probe_validates_the_address(self) -> None:
        api, *_ = make()
        self.assertFalse(api.probe("10.0.0.0/24")["ok"])
        rows = api.probe("192.168.1.20")["view"]["rows"]
        self.assertEqual([r["protocol"] for r in rows], ["SNMP", "SSH", "WinRM"])

    def test_support_bundle_cancelled_and_saved(self, ) -> None:
        api, *_ = make()
        self.assertEqual(api.support_bundle()["error"], "cancelled")
        path = os.path.join(fake_server.FakeAgent("idle").workdir, "b.zip")
        api, *_ = make(dialogs=FakeDialogs(path))
        result = api.support_bundle()
        self.assertTrue(result["ok"])
        self.assertTrue(os.path.isfile(path))

    def test_service_control_needs_elevation_and_is_off_in_development(self) -> None:
        api, _, _, service = make(elevated=False)
        self.assertFalse(api.service_action("restart")["ok"])
        api, _, _, service = make(dev=True)
        self.assertEqual(api.service_action("restart")["error"], "dev")
        self.assertEqual(service.calls, [])
        api, _, _, service = make()
        self.assertTrue(api.service_action("restart")["ok"])
        self.assertFalse(api.service_action("format c:")["ok"])
        api.set_autostart(False)
        self.assertEqual(service.calls, ["restart", "autostart=False"])

    def test_language_changes_the_texts(self) -> None:
        api, agent, *_ = make()
        try:
            result = api.set_language("en")
            self.assertTrue(result["ok"])
            self.assertEqual(agent.settings["language"], "en")
            self.assertEqual(os.environ[i18n.LANGUAGE_ENV_VAR], "en")
            self.assertFalse(api.set_language("klingon")["ok"])
        finally:
            api.set_language("")
        self.assertEqual(os.environ.get(i18n.LANGUAGE_ENV_VAR), "es")

    def test_only_safe_links_are_opened(self) -> None:
        opened: list[str] = []
        api, *_ = make(opened=opened)
        api.status()
        api.open_link("portal")
        api.open_link("repo")
        self.assertEqual(opened, ["https://demo.cenya.cloud", bridge.REPO_URL])
        self.assertFalse(api.open_link("file:///c:/windows")["ok"])


class NetboxSecretTests(unittest.TestCase):
    TOKEN = "nbt_0123456789abcdef-very-secret"

    def wait(self, api: bridge.Api) -> dict:
        for _ in range(200):
            result = api.netbox_poll()
            if result["state"] != "running":
                return result
            time.sleep(0.02)
        self.fail("la lectura de NetBox no terminó")

    def test_send_then_review_and_the_token_is_gone(self) -> None:
        opened: list[str] = []
        api, agent, wire, _ = make(opened=opened)
        api.status()
        self.assertTrue(api.netbox_start("https://netbox.local", self.TOKEN, False, "send")["ok"])
        result = self.wait(api)
        self.assertEqual(result["state"], "done")
        self.assertTrue(opened and opened[0].startswith("https://demo.cenya.cloud/settings/import/pending/"))
        # El token viajó una vez por el canal y no está en ningún otro sitio.
        self.assertEqual(sum(self.TOKEN.encode() in line for line in wire), 1)
        self.assertNotIn(self.TOKEN, json.dumps(result))
        self.assertNotIn(self.TOKEN, json.dumps(agent._log))
        self.assertNotIn(self.TOKEN, repr(vars(api)))

    def test_save_needs_a_path(self) -> None:
        api, *_ = make()
        self.assertFalse(api.netbox_start("https://netbox.local", self.TOKEN, False, "save", "")["ok"])

    def test_a_refused_token_is_an_error_to_show(self) -> None:
        api, *_ = make()
        api.netbox_start("https://netbox.local", "bad", False, "send")
        result = self.wait(api)
        self.assertEqual(result["state"], "error")
        self.assertIn("token", result["message"])

    def test_readers_cannot_export(self) -> None:
        api, _, wire, _ = make(elevated=False)
        self.assertFalse(api.netbox_start("https://netbox.local", self.TOKEN, False, "send")["ok"])
        self.assertFalse(any(self.TOKEN.encode() in line for line in wire))

    def test_testing_netbox_reports_without_echoing_the_token(self) -> None:
        api, *_ = make()
        with mock.patch("agent.netbox_export._get_page", side_effect=__import__("agent.netbox_export").netbox_export.ExportError("NetBox rechazó el token.")):
            result = api.netbox_test("https://netbox.local", self.TOKEN, False)
        self.assertFalse(result["ok"])
        self.assertNotIn(self.TOKEN, json.dumps(result))
        with mock.patch("agent.netbox_export._get_page", return_value={}):
            self.assertTrue(api.netbox_test("https://netbox.local", self.TOKEN, True)["ok"])


class NetboxPhotosTests(unittest.TestCase):
    TOKEN = NetboxSecretTests.TOKEN
    PASSWORD = "la-contraseña-de-las-fotos"

    wait = NetboxSecretTests.wait

    def test_the_password_travels_once_and_the_summary_tells_the_photos(self) -> None:
        api, agent, wire, _ = make()
        api.status()
        self.assertTrue(api.netbox_start("https://netbox.local", self.TOKEN, False, "send", "", "eduardo", self.PASSWORD)["ok"])
        result = self.wait(api)
        self.assertEqual(result["state"], "done")
        self.assertEqual(sum(self.PASSWORD.encode() in line for line in wire), 1)
        self.assertNotIn(self.PASSWORD, json.dumps(result))
        self.assertNotIn(self.PASSWORD, json.dumps(agent._log))
        self.assertNotIn(self.PASSWORD, repr(vars(api)))
        self.assertFalse(result["summary"]["photos_missing"])
        self.assertTrue(result["summary"]["photos"])

    def test_without_a_user_the_summary_warns_about_the_photos(self) -> None:
        api, *_ = make()
        api.status()
        api.netbox_start("https://netbox.local", self.TOKEN, False, "send")
        summary = self.wait(api)["summary"]
        self.assertTrue(summary["photos_missing"])
        self.assertIn("Bajar también las fotos", " ".join(summary["photos"]))

    def test_a_user_without_a_password_is_stopped_in_the_window(self) -> None:
        api, _, wire, _ = make()
        result = api.netbox_start("https://netbox.local", self.TOKEN, False, "send", "", "eduardo", "")
        self.assertEqual(result["error"], "invalid")
        self.assertFalse(any(self.TOKEN.encode() in line for line in wire))

    def test_testing_also_signs_in_and_out(self) -> None:
        api, *_ = make()
        session = object()
        with mock.patch("agent.netbox_export._get_page", return_value={}), mock.patch(
            "agent.netbox_export.login_session", return_value=session
        ) as login, mock.patch("agent.netbox_export.logout") as logout:
            result = api.netbox_test("https://netbox.local", self.TOKEN, False, "eduardo", self.PASSWORD)
        self.assertTrue(result["ok"])
        login.assert_called_once_with("https://netbox.local", "eduardo", self.PASSWORD, verify_tls=True)
        logout.assert_called_once_with("https://netbox.local", session)
        failure = __import__("agent.netbox_export").netbox_export.ExportError("NetBox no aceptó ese usuario y contraseña.")
        with mock.patch("agent.netbox_export._get_page", return_value={}), mock.patch("agent.netbox_export.login_session", side_effect=failure):
            result = api.netbox_test("https://netbox.local", self.TOKEN, False, "eduardo", self.PASSWORD)
        self.assertFalse(result["ok"])
        self.assertNotIn(self.PASSWORD, json.dumps(result))


class NotEnrolledTests(unittest.TestCase):
    """Un equipo sin enrolar: el servicio está en marcha y se conecta por el canal (spec 4, 2.7 de la integración)."""

    def test_the_window_says_why_and_connects_through_the_channel(self) -> None:
        api, agent, wire, service = make("not_enrolled")
        shell = api.shell()["view"]
        self.assertEqual(shell["mode"], "not_enrolled")
        self.assertIn("en marcha y esperando", shell["enrollment"])
        result = api.connect("  cenya://acme.cenya.cloud/ABCD-EFGH-JKLM ")
        self.assertTrue(result["ok"], result)
        self.assertTrue(agent.enrolled)
        self.assertEqual(service.calls, [])  # nada de arrancar servicios: ya estaba en marcha
        self.assertEqual(api.shell()["view"]["mode"], "ready")
        self.assertTrue(any(b'"op":"connect"' in line for line in wire))

    def test_a_set_aside_enrolment_is_explained(self) -> None:
        api, *_ = make("untrusted")
        self.assertIn("sin proteger", api.shell()["view"]["enrollment"])

    def test_with_the_service_down_only_starting_it_is_offered(self) -> None:
        client = channel.ChannelClient(channel.random_pipe_name())  # nadie escucha
        api = bridge.Api(client, elevated=True, dev=False, service=FakeService(), tray_startup=FakeTray())
        self.assertEqual(api.shell()["view"]["mode"], "down")
        self.assertFalse(hasattr(api, "enroll_offline"))

class DevControlsTests(unittest.TestCase):
    def test_development_never_gets_the_real_controls(self) -> None:
        service, tray = winsys.controls_for(True, lambda: True)
        self.assertTrue(service.dev and tray.dev)
        self.assertEqual(service.query()["state"], "running")
        with self.assertRaises(winsys.ServiceControlError):
            service.restart()
        with self.assertRaises(winsys.ServiceControlError):
            tray.set(True)


if __name__ == "__main__":
    unittest.main()
