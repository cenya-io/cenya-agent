"""A credential refused three times on one device stops being tried there (12-10-2026).

Before, a credential that never got in was paused on every device after three
refusals in total: three switches without that account kept a good SSH user
out of the other fifty for a day. Now the count is per device and credential:

* at the third refusal on a device it is not tried there any more, and each
  run says so in its attempts with the code ``discarded``;
* the other devices keep trying it;
* getting in resets the count; «Analizar» and «Probar» try it anyway and do
  not add to it;
* the order ``forget_rejection`` («Reintentar» in the web) makes it count
  from zero on that device, or on all of them without an IP;
* the count survives a restart.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import tempfile
import threading
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
import unittest

from agent import ssh
from agent.collectors import tasking
from agent.collectors.ssh import SshCollector
from agent.memory import AUTH_FAILED, HOST_REJECTIONS, OK, Memory
from agent.tests.test_control import ControlTestCase

T0 = datetime(2026, 10, 12, 9, 0, tzinfo=timezone.utc)


class MemoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mem = Memory.load(None)
        self.mem.note_host("10.0.0.5", "", T0)

    def refuse(self, host: str = "10.0.0.5", ident: str = "ssh-1", *, explicit: bool = False) -> None:
        attempt = self.mem.reserve(ident, T0, host_key=host, explicit=explicit, brake=False, per_host=True, wait=0)
        self.assertIsNotNone(attempt)
        self.mem.finish(attempt, AUTH_FAILED, T0)

    def test_the_third_refusal_on_a_device_discards_it_there(self) -> None:
        for _ in range(HOST_REJECTIONS - 1):
            self.refuse()
        self.assertFalse(self.mem.discarded("10.0.0.5", "ssh-1"))
        self.refuse()
        self.assertTrue(self.mem.discarded("10.0.0.5", "ssh-1"))
        # Ni en otro equipo ni con otra credencial.
        self.assertFalse(self.mem.discarded("10.0.0.6", "ssh-1"))
        self.assertFalse(self.mem.discarded("10.0.0.5", "ssh-2"))

    def test_without_the_global_brake_nothing_is_suspended(self) -> None:
        for n in range(10):
            self.refuse(host=f"10.0.0.{n}")
        self.assertFalse(self.mem.suspended("ssh-1", T0))

    def test_getting_in_resets_the_count(self) -> None:
        self.refuse()
        self.refuse()
        attempt = self.mem.reserve("ssh-1", T0, host_key="10.0.0.5", brake=False, per_host=True, wait=0)
        self.mem.finish(attempt, OK, T0)
        self.refuse()
        self.refuse()
        self.assertFalse(self.mem.discarded("10.0.0.5", "ssh-1"))

    def test_what_a_person_asks_for_does_not_count(self) -> None:
        for _ in range(HOST_REJECTIONS):
            self.refuse(explicit=True)
        self.assertFalse(self.mem.discarded("10.0.0.5", "ssh-1"))

    def test_forget_rejection_on_one_device_or_on_all(self) -> None:
        self.mem.note_host("10.0.0.6", "", T0)
        for host in ("10.0.0.5", "10.0.0.6"):
            for _ in range(HOST_REJECTIONS):
                self.refuse(host=host)

        self.assertEqual(self.mem.forget_rejection("ssh-1", "10.0.0.5"), 1)
        self.assertFalse(self.mem.discarded("10.0.0.5", "ssh-1"))
        self.assertTrue(self.mem.discarded("10.0.0.6", "ssh-1"))

        self.assertEqual(self.mem.forget_rejection("ssh-1"), 1)
        self.assertFalse(self.mem.discarded("10.0.0.6", "ssh-1"))

    def test_a_device_known_by_its_mac_is_found_by_its_ip(self) -> None:
        self.mem.note_host("10.0.0.7", "02:00:00:00:00:07", T0)
        key = self.mem.key_for("10.0.0.7", "02:00:00:00:00:07")
        for _ in range(HOST_REJECTIONS):
            self.refuse(host=key)

        self.assertEqual(self.mem.forget_rejection("ssh-1", "10.0.0.7"), 1)
        self.assertFalse(self.mem.discarded(key, "ssh-1"))

    def test_it_survives_a_restart_and_rubbish_is_dropped(self) -> None:
        path = Path(tempfile.mkdtemp(prefix="cenya-rejections-")) / "memory.json"
        mem = Memory.load(path)
        mem.note_host("10.0.0.5", "", T0)
        for _ in range(HOST_REJECTIONS):
            attempt = mem.reserve("ssh-1", T0, host_key="10.0.0.5", brake=False, per_host=True, wait=0)
            mem.finish(attempt, AUTH_FAILED, T0)
        mem.save()

        self.assertTrue(Memory.load(path).discarded("10.0.0.5", "ssh-1"))

        text = path.read_text(encoding="utf-8").replace('"ssh-1": 3', '"ssh-1": "tres"')
        path.write_text(text, encoding="utf-8")
        self.assertFalse(Memory.load(path).discarded("10.0.0.5", "ssh-1"))


HOSTS = [{"ip": f"10.1.0.{n}", "mac": f"02:00:00:00:00:{n:02x}"} for n in range(1, 11)]


class SshCollectorTests(unittest.TestCase):
    """Tres switches sin la cuenta y siete con ella: los siete entran siempre."""

    def setUp(self) -> None:
        self.mem = Memory.load(None)
        self.good = {h["ip"] for h in HOSTS[3:]}
        self.attempts: Counter = Counter()
        self.lock = threading.Lock()

    def fake_run(self, *, host: str, username: str, secret: str = "", port: int = 0, key_file: str = "", command: str) -> ssh.Answer:
        with self.lock:
            self.attempts[host] += 1
        if host in self.good:
            return ssh.Answer(True, output="Cisco IOS Software, Version 15.2")
        return ssh.Answer(False, error=f"{username}@{host}: Permission denied (password).")

    def run_once(self, day: int) -> dict:
        ctx = {
            "config": {"credentials": [{"id": "ssh-1", "kind": "ssh", "username": "sistemas", "secret": "x", "label": "SSH · sistemas"}]},
            "task": "inventory",
            "hosts": [dict(h) for h in HOSTS],
            "memory": self.mem,
            "workers": {"login": 4, "ping": 4},
            "errors": [],
        }
        # Un día más cada vez: tras una ronda fallida, el equipo descansa 24 h.
        moment = T0 + timedelta(days=day, hours=1)
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", lambda ips, port, **kw: list(ips)), \
             mock.patch("agent.collectors.ssh.ssh.run", self.fake_run), \
             mock.patch("agent.collectors.tasking.now", return_value=moment):
            SshCollector().collect(ctx)
        return ctx

    def codes(self, ctx: dict, ip: str) -> list[str]:
        return [entry["code"] for entry in tasking.attempts(ctx) if entry["ip"] == ip]

    def test_three_refusals_discard_it_on_those_devices_only(self) -> None:
        bad = HOSTS[0]["ip"]
        for day in range(HOST_REJECTIONS):
            ctx = self.run_once(day)
            self.assertNotIn("credential_suspended", [n.code for n in ctx["errors"]])
        tried_on_bad = self.attempts[bad]

        ctx = self.run_once(HOST_REJECTIONS)

        self.assertEqual(self.attempts[bad], tried_on_bad)  # ya no se prueba allí
        self.assertIn(tasking.DISCARDED, self.codes(ctx, bad))
        self.assertEqual(self.codes(ctx, HOSTS[5]["ip"]).count(tasking.LOGGED_IN) >= 1, True)
        discarded = [e for e in tasking.attempts(ctx) if e["code"] == tasking.DISCARDED]
        self.assertEqual(sorted({e["ip"] for e in discarded}), sorted(h["ip"] for h in HOSTS[:3]))
        self.assertTrue(all(e["credential"] == "ssh-1" for e in discarded))

    def test_after_forget_rejection_it_is_tried_again(self) -> None:
        bad = HOSTS[0]["ip"]
        for day in range(HOST_REJECTIONS):
            self.run_once(day)
        self.mem.forget_rejection("ssh-1", bad)
        before = self.attempts[bad]

        ctx = self.run_once(HOST_REJECTIONS)

        self.assertEqual(self.attempts[bad], before + 1)
        self.assertNotIn(tasking.DISCARDED, self.codes(ctx, bad))


class ForgetRejectionOrderTests(ControlTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.forgotten: list[tuple[str, str]] = []

        def forget(credential: str, ip: str) -> int:
            self.forgotten.append((credential, ip))
            return 1

        self.hooks.forget_rejection = forget

    def test_it_forgets_and_answers_done(self) -> None:
        ctl = self.control()
        ctl.apply({"orders": [{"id": "o-1", "kind": "forget_rejection", "params": {"credential": "c-1", "ip": "10.0.0.5"}}]})

        self.assertEqual(self.forgotten, [("c-1", "10.0.0.5")])
        self.assertEqual(self.client.order_answers[0][1]["status"], "done")
        self.assertEqual(self.client.order_answers[0][1]["result"], {"forgotten": 1})

    def test_without_an_ip_it_forgets_everywhere(self) -> None:
        ctl = self.control()
        ctl.apply({"orders": [{"id": "o-1", "kind": "forget_rejection", "params": {"credential": "c-1"}}]})

        self.assertEqual(self.forgotten, [("c-1", "")])

    def test_bad_params_fail_with_a_note(self) -> None:
        ctl = self.control()
        ctl.apply({"orders": [{"id": "o-1", "kind": "forget_rejection", "params": {"credential": "c-1", "ip": "no"}}]})
        ctl.apply({"orders": [{"id": "o-2", "kind": "forget_rejection", "params": {}}]})

        self.assertEqual(self.forgotten, [])
        self.assertEqual([a[1]["status"] for a in self.client.order_answers], ["failed", "failed"])
        self.assertEqual(self.client.order_answers[0][1]["notes"][0]["code"], "bad_params")

    def test_an_agent_without_the_hook_says_unsupported(self) -> None:
        self.hooks.forget_rejection = None
        ctl = self.control()
        ctl.apply({"orders": [{"id": "o-1", "kind": "forget_rejection", "params": {"credential": "c-1"}}]})

        self.assertEqual(self.client.order_answers[0][1]["status"], "unsupported")


if __name__ == "__main__":
    unittest.main()
