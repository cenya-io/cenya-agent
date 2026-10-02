"""What the window decides to show (agent/app/view.py): pure functions, no window."""

from __future__ import annotations

import agent.tests  # noqa: F401 - castellano y entorno de pruebas

import unittest
from datetime import datetime, timedelta, timezone

from agent.app import channel, view

NOW = datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc)


def iso(delta: timedelta) -> str:
    return (NOW + delta).isoformat()


def status(**changes: object) -> dict:
    base = {
        "version": "0.11.0",
        "enrolled": True,
        "portal": "https://acme.cenya.cloud",
        "agent_name": "SRV",
        "connection": {"state": "ok", "last_ok_at": iso(timedelta(minutes=-2))},
        "state": "idle",
        "activity": None,
        "schedule": [
            {"task": "inventory", "every_seconds": 21600, "last_status": "partial", "last_finished_at": iso(timedelta(hours=-1)), "next_at": iso(timedelta(hours=5))},
            {"task": "presence", "every_seconds": 300, "last_status": "ok", "last_finished_at": iso(timedelta(minutes=-3)), "next_at": iso(timedelta(minutes=2))},
            {"task": "configs", "every_seconds": 0, "last_status": None},
        ],
        "last_run": {"task": "presence", "finished_at": iso(timedelta(minutes=-3)), "status": "ok", "stats": {"hosts_alive": 41, "new_hosts": 1}, "created": 1, "refreshed": 40},
        "paused_until": None,
        "outbox": 0,
    }
    base.update(changes)
    return base


ADMIN = view.permissions(elevated=True, forbidden_seen=False)
READER = view.permissions(elevated=False, forbidden_seen=False)


class PermissionTests(unittest.TestCase):
    def test_an_elevated_administrator_can_act(self) -> None:
        self.assertTrue(ADMIN["can_act"])
        self.assertFalse(ADMIN["readonly"])
        self.assertFalse(ADMIN["can_elevate"])

    def test_anyone_else_reads_and_is_told_why_not(self) -> None:
        self.assertFalse(READER["can_act"])
        self.assertIn("administrador", READER["why"])
        self.assertTrue(READER["can_elevate"])

    def test_the_service_has_the_last_word(self) -> None:
        perms = view.permissions(elevated=True, forbidden_seen=True)
        self.assertFalse(perms["can_act"])
        self.assertFalse(perms["can_elevate"])  # ya lo está: reiniciar no arreglaría nada


class RealServiceShapeTests(unittest.TestCase):
    """Lo que contesta `status` el servicio de verdad (agent/localops.py), leído por las vistas."""

    REAL = {
        "version": "0.11.0",
        "enrolled": True,
        "portal": "https://acme.cenya.cloud",
        "name": "SRV",
        "may_act": False,
        "local": {"netbox_export": {"state": "running", "step": "dcim/devices", "done": 3, "total": 17}},
        "connection": {"state": "refused", "at": iso(timedelta(minutes=-1)), "ok": False, "status": 401, "error": "Token no válido."},
        "state": "paused",
        "activity": None,
        "pause": {"local": iso(timedelta(hours=1)), "server": None, "until": iso(timedelta(hours=1))},
        "refusal": "unauthorized",
        "last_checkin": {"at": iso(timedelta(minutes=-1)), "ok": False},
        "outbox": 0,
    }

    def test_normalized(self) -> None:
        s = view.normalize_status(self.REAL)
        self.assertEqual(s["agent_name"], "SRV")
        self.assertEqual(s["paused_until"], self.REAL["pause"]["until"])
        self.assertEqual(s["connection"]["state"], "rejected")
        self.assertEqual(s["connection"]["last_error"], "Token no válido.")
        self.assertEqual(s["activity"]["task"], view.NETBOX_TASK)
        self.assertEqual(s["activity"]["step"], "dcim/devices")

    def test_views_read_it(self) -> None:
        s = view.normalize_status(self.REAL)
        c = view.connection_view(s, NOW)
        self.assertEqual(c["tone"], view.DANGER)
        self.assertEqual(c["detail"], "Token no válido.")
        self.assertIn("Último intento", c["since"])
        self.assertTrue(view.pause_view(s, NOW)["paused"])

    def test_the_service_decides_who_may_act(self) -> None:
        shell = view.shell_view(view.normalize_status(self.REAL), None, "running", elevated=True, forbidden_seen=False, dev=False, now=NOW)
        self.assertFalse(shell["perms"]["can_act"])
        shell = view.shell_view(view.normalize_status({**self.REAL, "may_act": True}), None, "running", elevated=False, forbidden_seen=False, dev=False, now=NOW)
        self.assertTrue(shell["perms"]["can_act"])

    def test_unknown_and_not_enrolled_connection_states_are_grey(self) -> None:
        for state in ("unknown", "not_enrolled"):
            s = view.normalize_status({"connection": {"state": state}})
            self.assertEqual(view.connection_view(s, NOW)["tone"], view.NEUTRAL)

    def test_garbage_is_empty(self) -> None:
        self.assertEqual(view.normalize_status(None)["connection"], {"state": ""})

    def test_settings_errors_name_each_field(self) -> None:
        text = view.settings_error("No válido.", {"fields": {"proxy": "La dirección del proxy no es válida."}})
        self.assertIn("proxy no es válida", text)


class ShellTests(unittest.TestCase):
    def shell(self, st, code=None, service="running", elevated=True, dev=False):
        return view.shell_view(st, code, service, elevated=elevated, forbidden_seen=False, dev=dev, now=NOW)

    def test_ready(self) -> None:
        v = self.shell(status())
        self.assertEqual(v["mode"], "ready")
        self.assertEqual(v["tone"], view.SUCCESS)
        self.assertEqual(v["agent_name"], "SRV")

    def test_not_enrolled(self) -> None:
        self.assertEqual(self.shell(status(enrolled=False))["mode"], "not_enrolled")

    def test_nothing_listening_is_the_service_down(self) -> None:
        v = self.shell(None, channel.SERVICE_DOWN, "stopped")
        self.assertEqual(v["mode"], "down")
        self.assertEqual(v["start_why"], "")

    def test_starting_the_service_needs_elevation_and_never_in_development(self) -> None:
        self.assertIn("administrador", self.shell(None, channel.SERVICE_DOWN, "stopped", elevated=False)["start_why"])
        self.assertIn("desarrollo", self.shell(None, channel.SERVICE_DOWN, "stopped", dev=True)["start_why"])

    def test_down_without_enrolment_is_its_own_state(self) -> None:
        # Hoy un servicio sin enrolar sale al arrancar: sin canal y sin fichero.
        v = view.shell_view(None, channel.SERVICE_DOWN, "stopped", elevated=True, forbidden_seen=False, dev=False, now=NOW, enrolled_on_disk=False)
        self.assertEqual(v["mode"], "down_not_enrolled")
        v = view.shell_view(None, channel.SERVICE_DOWN, "stopped", elevated=True, forbidden_seen=False, dev=False, now=NOW, enrolled_on_disk=None)
        self.assertEqual(v["mode"], "down")

    def test_not_installed_wins_over_down(self) -> None:
        self.assertEqual(self.shell(None, channel.SERVICE_DOWN, "not_installed")["mode"], "not_installed")

    def test_other_failures_say_what_happened(self) -> None:
        v = self.shell(None, channel.TIMEOUT)
        self.assertEqual(v["mode"], "unreachable")
        self.assertTrue(v["message"])


class ConnectionTests(unittest.TestCase):
    def test_connected(self) -> None:
        v = view.connection_view(status(), NOW)
        self.assertEqual(v["tone"], view.SUCCESS)
        self.assertIn("acme.cenya.cloud", v["title"])
        self.assertIn("hace 2 minutos", v["since"])

    def test_an_error_carries_its_reason(self) -> None:
        v = view.connection_view(status(connection={"state": "error", "last_error": "timed out"}), NOW)
        self.assertEqual(v["tone"], view.WARNING)
        self.assertEqual(v["detail"], "timed out")

    def test_rejected_is_red_and_explains(self) -> None:
        v = view.connection_view(status(connection={"state": "rejected"}), NOW)
        self.assertEqual(v["tone"], view.DANGER)
        self.assertTrue(v["detail"])

    def test_unknown_is_grey_never_green(self) -> None:
        self.assertEqual(view.connection_view(status(connection={}), NOW)["tone"], view.NEUTRAL)
        self.assertEqual(view.connection_view({}, NOW)["tone"], view.NEUTRAL)


class ActivityTests(unittest.TestCase):
    def test_progress_and_step(self) -> None:
        a = view.activity_view(status(activity={"task": "inventory", "step": "ssh", "done": 14, "total": 37, "started_at": iso(timedelta(minutes=-5))}), NOW)
        self.assertEqual(a["percent"], 38)
        self.assertEqual(a["label"], "Inventario")
        self.assertIn("SSH", a["step"])
        self.assertEqual(a["count"], "14 de 37")

    def test_unknown_total_is_an_indeterminate_bar(self) -> None:
        a = view.activity_view(status(activity={"task": "presence", "step": "sweep"}), NOW)
        self.assertIsNone(a["percent"])
        self.assertEqual(a["count"], "")

    def test_no_activity(self) -> None:
        self.assertIsNone(view.activity_view(status(), NOW))
        self.assertIsNone(view.activity_view(status(activity="nonsense"), NOW))


class PauseTests(unittest.TestCase):
    def test_not_paused(self) -> None:
        self.assertFalse(view.pause_view(status(), NOW)["paused"])

    def test_a_pause_that_already_ended_is_not_a_pause(self) -> None:
        self.assertFalse(view.pause_view(status(paused_until=iso(timedelta(minutes=-1))), NOW)["paused"])

    def test_paused_until_a_time(self) -> None:
        v = view.pause_view(status(paused_until=iso(timedelta(minutes=30))), NOW)
        self.assertTrue(v["paused"])
        self.assertIn(view.clock(NOW + timedelta(minutes=30)), v["text"])

    def test_a_long_pause_reads_as_until_resumed_and_says_its_limit(self) -> None:
        v = view.pause_view(status(paused_until=iso(timedelta(days=29))), NOW)
        self.assertTrue(v["text"].startswith("En pausa hasta que se reanude"))
        self.assertIn("como mucho", v["text"])

    def test_the_three_options_and_what_they_send(self) -> None:
        options = {o["id"]: o for o in view.pause_options(NOW)}
        self.assertEqual(options["hour"]["args"], {"seconds": 3600})
        tomorrow = datetime.fromisoformat(options["tomorrow"]["args"]["until"])
        self.assertEqual(tomorrow.hour, view.TOMORROW_HOUR)
        self.assertEqual(tomorrow.date(), (NOW.astimezone() + timedelta(days=1)).date())
        indefinite = datetime.fromisoformat(options["indefinite"]["args"]["until"])
        # Dentro del tope del servicio (localops.MAX_PAUSE, 30 días): si no, lo rechazaría.
        self.assertLess(indefinite - NOW, view.MAX_PAUSE)
        self.assertGreater(indefinite - NOW, view.MAX_PAUSE - timedelta(hours=1))
        self.assertIn("30", options["indefinite"]["label"])


class TasksTests(unittest.TestCase):
    def test_rows_in_the_agents_order_with_results(self) -> None:
        rows = view.tasks_view(status(), NOW, True)
        self.assertEqual([r["task"] for r in rows], ["presence", "inventory", "configs"])
        self.assertEqual(rows[0]["result"]["tone"], view.SUCCESS)
        self.assertEqual(rows[1]["result"]["tone"], view.WARNING)
        self.assertEqual(rows[2]["result"]["label"], "Sin ejecutar")
        self.assertEqual(rows[2]["last"], "Nunca")

    def test_a_disabled_task_says_so(self) -> None:
        self.assertEqual(view.tasks_view(status(), NOW, True)[2]["next"], "Desactivada")

    def test_paused_tasks_wait(self) -> None:
        rows = view.tasks_view(status(paused_until=iso(timedelta(hours=1))), NOW, True)
        self.assertEqual(rows[0]["next"], "En pausa")
        self.assertTrue(rows[0]["can_run"])  # lo que pide una persona sí se atiende

    def test_the_running_task_is_marked(self) -> None:
        rows = view.tasks_view(status(activity={"task": "inventory"}), NOW, True)
        self.assertEqual(rows[1]["result"]["label"], "En curso")

    def test_running_needs_permission_and_says_why(self) -> None:
        rows = view.tasks_view(status(), NOW, False, READER["why"])
        self.assertFalse(rows[0]["can_run"])
        self.assertEqual(rows[0]["why"], READER["why"])

    def test_a_rejected_agent_cannot_be_asked_to_run(self) -> None:
        rows = view.tasks_view(status(connection={"state": "rejected"}), NOW, True)
        self.assertFalse(rows[0]["can_run"])
        self.assertIn("rechazado", rows[0]["why"])

    def test_next_time_reads_as_today_or_tomorrow(self) -> None:
        self.assertTrue(view.upcoming(NOW + timedelta(days=1, hours=1), NOW).startswith(("mañana", "hoy")))
        self.assertEqual(view.upcoming(NOW - timedelta(seconds=1), NOW), "ahora")

    def test_garbage_does_not_break_the_table(self) -> None:
        self.assertEqual(view.tasks_view(status(schedule="nope"), NOW, True), [])
        self.assertEqual(view.tasks_view(status(schedule=[None, {"task": "x"}]), NOW, True)[0]["next"], "—")


class CountersTests(unittest.TestCase):
    def test_last_run_counters_and_outbox(self) -> None:
        c = view.counters_view(status(outbox=3), NOW)
        values = {item["key"]: item["value"] for item in c["items"]}
        self.assertEqual(values, {"hosts_alive": 41, "new_hosts": 1, "created": 1, "refreshed": 40, "outbox": 3})
        self.assertEqual([i for i in c["items"] if i["key"] == "outbox"][0]["tone"], view.WARNING)
        self.assertIn("Presencia", c["caption"])

    def test_nothing_run_yet(self) -> None:
        c = view.counters_view(status(last_run=None, outbox=None), NOW)
        self.assertEqual(c["items"], [])
        self.assertIsNone(c["result"])


class StatusViewTests(unittest.TestCase):
    def test_pause_and_resume_follow_the_state_and_the_permissions(self) -> None:
        v = view.status_view(status(), NOW, ADMIN)
        self.assertTrue(v["can_pause"])
        self.assertFalse(v["can_resume"])
        v = view.status_view(status(paused_until=iso(timedelta(hours=1))), NOW, ADMIN)
        self.assertTrue(v["can_resume"])
        v = view.status_view(status(), NOW, READER)
        self.assertFalse(v["can_pause"])
        self.assertTrue(v["pause_why"])

    def test_idle_says_what_comes_next(self) -> None:
        self.assertIn("Presencia", view.status_view(status(), NOW, ADMIN)["next_text"])

    def test_a_new_version_is_mentioned(self) -> None:
        self.assertIn("0.11.1", view.status_view(status(update={"version": "0.11.1"}), NOW, ADMIN)["update"])


class LogTests(unittest.TestCase):
    def test_structured_lines(self) -> None:
        v = view.log_view({"lines": [{"n": 7, "at": iso(timedelta()), "level": "WARNING", "task": "", "text": "[agente] Tarea inventory: algo"}], "next": 7}, "")
        row = v["rows"][0]
        self.assertEqual(row["level"], "warning")
        self.assertEqual(row["task"], "inventory")  # sacada del texto
        self.assertEqual(row["text"], "Tarea inventory: algo")  # sin «[agente] »
        self.assertEqual(v["cursor"], "7")

    def test_raw_lines_of_the_log_file_and_the_opaque_cursor(self) -> None:
        # Lo que contesta el servicio de verdad (agent/localops.py::read_log).
        v = view.log_view({"lines": ["2026-10-02 10:00:01,123 ERROR [agente] boom", "no format"], "cursor": "1234:5678"}, "1234:100", 10)
        self.assertEqual(v["rows"][0]["level"], "error")
        self.assertEqual(v["rows"][0]["text"], "boom")
        self.assertEqual(v["rows"][1]["text"], "no format")
        self.assertEqual([r["n"] for r in v["rows"]], [11, 12])
        self.assertEqual(v["cursor"], "1234:5678")

    def test_a_missing_log_keeps_the_cursor(self) -> None:
        v = view.log_view({"lines": [], "cursor": "", "missing": True}, "1:2")
        self.assertEqual(v["cursor"], "1:2")
        self.assertTrue(v["missing"])

    def test_filters_cover_every_task_and_general(self) -> None:
        ids = [t["id"] for t in view.log_filters()["tasks"]]
        self.assertEqual(ids[0], "")
        self.assertIn("-", ids)
        self.assertIn("netbox_export", ids)


class NetboxTests(unittest.TestCase):
    def test_form_errors(self) -> None:
        self.assertTrue(view.netbox_form_error("", "t"))
        self.assertTrue(view.netbox_form_error("netbox.local", "t"))
        self.assertTrue(view.netbox_form_error("https://netbox.local", " "))
        self.assertEqual(view.netbox_form_error("https://netbox.local", "t"), "")

    def test_progress_remembers_collections_already_read(self) -> None:
        p = view.netbox_progress({"task": "netbox_export", "step": "dcim/sites", "done": 0, "total": 9}, [])
        p = view.netbox_progress({"task": "netbox_export", "step": "dcim/racks", "done": 1, "total": 9}, p["seen"])
        self.assertEqual([r["state"] for r in p["rows"]], ["done", "reading"])
        self.assertEqual(p["percent"], 11)

    def test_another_task_is_not_netbox_progress(self) -> None:
        p = view.netbox_progress({"task": "presence", "step": "sweep"}, ["dcim/sites"])
        self.assertEqual(p["rows"], [{"name": "dcim/sites", "state": "done"}])
        self.assertIsNone(p["percent"])

    def test_summary_when_sent(self) -> None:
        s = view.netbox_summary({"summary": {"devices": 2, "sites": 1}, "review_url": "https://acme/x/"}, "send")
        self.assertEqual(s["total"], "3 objetos leídos")
        self.assertEqual(s["review_url"], "https://acme/x/")

    def test_a_dangerous_review_url_is_not_opened(self) -> None:
        s = view.netbox_summary({"summary": {}, "review_url": "javascript:alert(1)"}, "send", "https://acme.cenya.cloud")
        self.assertEqual(s["review_url"], "https://acme.cenya.cloud/settings/import/")

    def test_summary_when_saved(self) -> None:
        s = view.netbox_summary({"summary": {"devices": 1}, "path": "C:\\x.json"}, "save")
        self.assertEqual(s["total"], "1 objeto leído")
        self.assertIn("C:\\x.json", s["message"])

    def test_safe_url(self) -> None:
        self.assertEqual(view.safe_url("https://a.b/c"), "https://a.b/c")
        for bad in ("file:///c:/x", "https://u:p@a.b/", "javascript:x", "https://a.b:port/", ""):
            self.assertEqual(view.safe_url(bad), "", bad)


class ToolsTests(unittest.TestCase):
    def test_probe_rows_in_protocol_order(self) -> None:
        rows = view.probe_view({"ssh": "b", "snmp": "a", "at": "x", "codes": {}})["rows"]
        self.assertEqual([r["protocol"] for r in rows], ["SNMP", "SSH"])

    def test_connection_steps_stop_at_the_first_failure(self) -> None:
        # Como los da agent/localops.py::connection_test: se para en el que falla.
        v = view.connection_test_view(
            {"steps": [{"step": "dns", "ok": True, "code": "ok", "message": "a"}, {"step": "tcp", "ok": False, "code": "timeout", "message": "x"}]}
        )
        self.assertEqual([s["state"] for s in v["steps"]], ["ok", "fail", "skip", "skip"])
        self.assertEqual([s["label"] for s in v["steps"]], ["Nombre del portal", "Puerto", "Certificado", "Token del agente"])
        self.assertEqual(v["steps"][1]["detail"], "x")
        self.assertFalse(v["ok"])

    def test_probe_answer_of_the_service_is_unwrapped(self) -> None:
        rows = view.probe_view({"ip": "10.0.0.1", "report": {"snmp": "a", "ssh": "b", "winrm": "c"}})["rows"]
        self.assertEqual([r["text"] for r in rows], ["a", "b", "c"])

    def test_update_check_of_the_service(self) -> None:
        u = view.updates_view({}, {"version": "0.11.0"}, {"current": "0.11.0", "offered": "0.11.1", "update": {"version": "0.11.1"}})
        self.assertTrue(u["available"])
        u = view.updates_view({}, {"version": "0.11.0"}, {"current": "0.11.0", "offered": None, "update": None})
        self.assertFalse(u["available"])
        self.assertEqual(u["message"], "Está al día.")

    def test_selftest_names_what_is_missing(self) -> None:
        v = view.selftest_view({"collectors": ["a"] * 6, "modules": {"snmp": False, "winrm": True}, "languages": {"es": True}}, False)
        rows = {r["label"]: r for r in v["rows"]}
        self.assertFalse(rows["Librerías opcionales"]["ok"])
        self.assertIn("snmp", rows["Librerías opcionales"]["detail"])
        self.assertEqual(v["title"], "Falta algo en esta instalación")


class SettingsTests(unittest.TestCase):
    def test_exclusions_are_validated_and_normalised(self) -> None:
        self.assertEqual(view.validate_exclusion(" 10.0.5.7 ", []), {"ok": True, "value": "10.0.5.7", "kind": "address"})
        self.assertEqual(view.validate_exclusion("10.0.5.9/24", [])["value"], "10.0.5.0/24")
        self.assertEqual(view.validate_exclusion("10.0.5.7/32", [])["kind"], "address")
        self.assertFalse(view.validate_exclusion("10.0.5.300", [])["ok"])
        self.assertFalse(view.validate_exclusion("router", [])["ok"])
        self.assertFalse(view.validate_exclusion("10.0.5.7", ["10.0.5.7"])["ok"])

    def test_suggestions_are_this_machines_networks_not_already_listed(self) -> None:
        about = {"networks": [{"interface": "Ethernet", "address": "192.168.1.10", "cidr": "192.168.1.0/24"}]}
        v = view.exclusions_view({"excluded": {"subnets": ["192.168.1.0/24"], "addresses": []}}, about)
        self.assertEqual([s["value"] for s in v["suggestions"]], ["192.168.1.10"])

    def test_payload_splits_networks_and_addresses(self) -> None:
        self.assertEqual(
            view.exclusions_payload(["10.0.0.0/8", "10.1.1.1"]),
            {"excluded": {"subnets": ["10.0.0.0/8"], "addresses": ["10.1.1.1"]}},
        )

    def test_gentleness_cap_never_offers_fast(self) -> None:
        g = view.gentleness_view({"gentleness_cap": "fast"}, {"gentleness": "normal"})
        self.assertEqual([o["id"] for o in g["options"]], ["", "gentle", "normal"])
        self.assertEqual(g["value"], "")
        self.assertIn("normal", g["effective"])

    def test_updates(self) -> None:
        u = view.updates_view({"auto_update": False}, {"version": "0.11.0"}, {"installed": "0.11.0", "latest": "0.11.1", "available": True})
        self.assertFalse(u["auto"])
        self.assertTrue(u["available"])
        self.assertIn("0.11.1", u["message"])
        self.assertEqual(view.updates_view({}, {"version": "0.11.1"}, {"latest": "0.11.1", "available": False})["message"], "Está al día.")

    def test_service_buttons(self) -> None:
        running = view.service_view("running", "delayed", True, "", dev=False)
        self.assertTrue(running["can_stop"] and running["can_restart"] and running["autostart"])
        self.assertFalse(running["can_start"])
        stopped = view.service_view("stopped", "manual", True, "", dev=False)
        self.assertTrue(stopped["can_start"])
        self.assertFalse(stopped["autostart"])
        reader = view.service_view("running", "auto", False, "why", dev=False)
        self.assertFalse(reader["can_stop"])
        self.assertEqual(reader["why"], "why")
        dev = view.service_view("running", "auto", True, "", dev=True)
        self.assertFalse(dev["can_stop"])
        self.assertIn("desarrollo", dev["why"])

    def test_languages(self) -> None:
        options = view.language_options("de")
        self.assertEqual(options["value"], "de")
        self.assertEqual(options["options"][0]["id"], "")
        self.assertEqual(view.language_options("xx")["value"], "")

    def test_proxy(self) -> None:
        self.assertEqual(view.proxy_view({}), {"mode": "system", "url": ""})
        self.assertEqual(view.proxy_view({"proxy": {"mode": "weird"}})["mode"], "system")


class TrayMenuTests(unittest.TestCase):
    def ids(self, items):
        return [item["id"] for item in items if item["id"] != "-"]

    def test_the_agreed_entries_in_order(self) -> None:
        items = view.tray_menu(status(), NOW, "En marcha", "https://acme")
        self.assertEqual(self.ids(items), ["open", "status", "run_presence", "pause", "portal", "check_update", "close"])
        self.assertTrue(items[0]["default"])
        self.assertFalse(items[1]["enabled"])

    def test_paused_offers_resume(self) -> None:
        items = view.tray_menu(status(paused_until=iso(timedelta(hours=1))), NOW, "x", None)
        self.assertIn("resume", self.ids(items))
        portal = [i for i in items if i["id"] == "portal"][0]
        self.assertFalse(portal["enabled"])

    def test_without_the_service_only_what_does_not_need_it(self) -> None:
        enabled = {i["id"] for i in view.tray_menu(None, NOW, "x", None) if i.get("enabled")}
        self.assertEqual(enabled, {"open", "close"})


if __name__ == "__main__":
    unittest.main()
