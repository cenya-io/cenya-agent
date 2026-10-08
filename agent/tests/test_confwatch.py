"""`agent.confwatch`: noticing a configuration change without waiting for the night.

The network is fake: no SNMP packet and no `ssh`. What is checked is the
decision (when a stamp counts as a change) and the manners: the first sighting
does not copy, a change copies only that device, a reboot copies once, a device
that does not publish the stamp or does not answer is left alone, and one that
changes all the time is not logged into every cycle.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - isolates the state file under `unittest discover` too

import unittest
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest import mock

from agent import confwatch, snmp, ssh, tasks
from agent import credentials as creds
from agent.collectors.base import Finding
from agent.memory import Memory
from agent.tests.test_tasks import HOSTS, SWITCH_MAC, ssh_credentials

SWITCH_2_MAC = "aa:bb:cc:dd:ee:03"
SWITCH_2 = {"ip": "192.168.1.4", "mac": SWITCH_2_MAC}
START = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)


def cisco_answer(running: int, startup: int = 10, uptime: int = 500_000) -> dict[str, str]:
    return {"uptime": str(uptime), "running": str(running), "startup": str(startup)}


class Clock:
    """The time `tasking.now()` gives, moved by hand."""

    def __init__(self) -> None:
        self.moment = START

    def __call__(self) -> datetime:
        return self.moment

    def advance(self, **kwargs: int) -> None:
        self.moment += timedelta(**kwargs)


class ChangedTests(unittest.TestCase):
    """The pure decision."""

    ticks = confwatch.WATCHES["huawei"]
    date = confwatch.WATCHES["junos"]

    def test_no_previous_value_is_never_a_change(self) -> None:
        self.assertFalse(confwatch.changed(self.ticks, {}, ["100"], 5000))

    def test_ticks_that_moved_are_a_change_and_equal_ones_are_not(self) -> None:
        before = {"stamp": ["100"], "uptime": 5000}
        self.assertTrue(confwatch.changed(self.ticks, before, ["900"], 9000))
        self.assertFalse(confwatch.changed(self.ticks, before, ["100"], 9000))

    def test_a_change_newer_than_the_last_poll_is_a_change(self) -> None:
        self.assertTrue(confwatch.changed(self.ticks, {"stamp": ["6000"], "uptime": 5000}, ["6000"], 9000))

    def test_uptime_going_backwards_is_a_reboot_and_counts_once_out_of_prudence(self) -> None:
        before = {"stamp": ["100"], "uptime": 900_000}
        self.assertTrue(confwatch.changed(self.ticks, before, ["100"], 300))

    def test_a_date_is_compared_as_a_value_whatever_the_uptime(self) -> None:
        before = {"stamp": ["2026-10-8,10:0:0.0,+0:0"], "uptime": 900_000}
        self.assertTrue(confwatch.changed(self.date, before, ["2026-10-8,11:0:0.0,+0:0"], 10))
        self.assertFalse(confwatch.changed(self.date, before, ["2026-10-8,10:0:0.0,+0:0"], 10))

    def test_an_empty_reading_is_no_information(self) -> None:
        self.assertEqual(confwatch.current_stamp(confwatch.WATCHES["cisco"], {"uptime": "5"}), [])
        self.assertFalse(confwatch.changed(self.date, {"stamp": ["x"], "uptime": 1}, [], 5))


class WatchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = Clock()
        patches = [
            mock.patch("agent.collectors.tasking.now", self.clock),
            mock.patch("agent.confwatch.snmp.AVAILABLE", True),
            mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True),
            mock.patch("agent.collectors.ssh.ssh.SSHPASS_AVAILABLE", True),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.memory = Memory.load(None)
        self.answers: dict[str, dict[str, str]] = {}
        self.queried: list[list[str]] = []
        self.ssh_calls: list[dict] = []
        self.know(SWITCH_MAC, "192.168.1.2")

    def ctx(self, **extra: Any) -> dict:
        ctx: dict[str, Any] = {
            "config": {"credentials": ssh_credentials("admin"), "communities": ["public"]},
            "env": None,
            "hosts": [dict(HOSTS[0]), dict(HOSTS[1]), dict(SWITCH_2)],
            "task": "presence",
            "memory": self.memory,
        }
        ctx.update(extra)
        return ctx

    def know(self, mac: str, ip: str, family: str = "cisco") -> None:
        """What the inventory leaves in the memory: family, identity and the SSH credential that got in."""
        self.memory.note_host(ip, mac, self.clock())
        self.memory.flag(mac, config_family=family, identity_mac=mac)
        credential = creds.for_kind({"config": {"credentials": ssh_credentials("admin")}}, creds.SSH)[0]
        self.memory.record_success(mac, "ssh", credential, self.clock())

    def watch(self, ctx: dict | None = None) -> list[Finding]:
        def fake_stamps(plan, **kwargs):
            self.queried.append(sorted(plan))
            return {ip: (0, self.answers[ip]) for ip in plan if ip in self.answers}

        def fake_run(**kwargs: Any) -> ssh.Answer:
            self.ssh_calls.append(kwargs)
            output = "hostname sw\ninterface Gi1/0/1\n" if "running" in kwargs["command"] else ""
            return ssh.Answer(connected=True, output=output)

        with mock.patch("agent.confwatch.snmp.query_stamps", side_effect=fake_stamps), \
             mock.patch("agent.collectors.ssh.ssh.run", fake_run):
            return confwatch.run(ctx if ctx is not None else self.ctx())

    def test_the_first_sighting_keeps_the_stamp_and_copies_nothing(self) -> None:
        self.answers["192.168.1.2"] = cisco_answer(running=100)

        self.assertEqual(self.watch(), [])

        self.assertEqual(self.ssh_calls, [])
        self.assertEqual(self.memory.confwatch_state(SWITCH_MAC)["stamp"], ["100", "10"])

    def test_a_change_copies_only_that_device(self) -> None:
        self.know(SWITCH_2_MAC, "192.168.1.4")
        self.answers = {"192.168.1.2": cisco_answer(100), "192.168.1.4": cisco_answer(100)}
        self.watch()
        self.clock.advance(minutes=6)
        self.answers = {"192.168.1.2": cisco_answer(100), "192.168.1.4": cisco_answer(777)}

        findings = self.watch()

        self.assertEqual([f.kind for f in findings], ["config"])
        self.assertEqual(findings[0].payload["ip"], "192.168.1.4")
        self.assertEqual(findings[0].identity, {"mac": SWITCH_2_MAC})
        self.assertEqual({call["host"] for call in self.ssh_calls}, {"192.168.1.4"})
        # With the same credential that got in, nobody else's.
        self.assertEqual({call["username"] for call in self.ssh_calls}, {"admin"})

    def test_no_change_does_nothing(self) -> None:
        self.answers["192.168.1.2"] = cisco_answer(100)
        self.watch()
        self.clock.advance(minutes=6)

        self.assertEqual(self.watch(), [])
        self.assertEqual(self.ssh_calls, [])

    def test_a_reboot_copies_once_and_then_settles(self) -> None:
        self.answers["192.168.1.2"] = cisco_answer(100, uptime=900_000)
        self.watch()
        self.clock.advance(minutes=6)
        self.answers["192.168.1.2"] = cisco_answer(100, uptime=2_000)  # the uptime went backwards

        self.assertEqual(len(self.watch()), 1)

        self.clock.advance(minutes=6)
        self.answers["192.168.1.2"] = cisco_answer(100, uptime=40_000)
        self.assertEqual(self.watch(), [])

    def test_a_device_that_does_not_publish_the_stamp_is_left_alone_without_errors(self) -> None:
        self.answers["192.168.1.2"] = {"uptime": "500000", "running": "", "startup": ""}
        ctx = self.ctx()

        self.assertEqual(self.watch(ctx), [])

        self.assertEqual(self.ssh_calls, [])
        self.assertEqual(ctx.get("errors", []), [])
        self.assertEqual(self.memory.confwatch_state(SWITCH_MAC), {})

    def test_a_device_is_not_asked_again_within_the_minimum_poll_time(self) -> None:
        self.answers["192.168.1.2"] = cisco_answer(100)
        self.watch()
        self.clock.advance(minutes=1)
        self.watch()

        self.assertEqual(len(self.queried), 1)

    def test_a_device_that_changes_all_the_time_is_copied_at_most_every_five_minutes(self) -> None:
        self.answers["192.168.1.2"] = cisco_answer(100)
        self.watch()
        self.clock.advance(minutes=4, seconds=30)
        self.answers["192.168.1.2"] = cisco_answer(200)
        self.assertEqual(len(self.watch()), 1)
        self.assertEqual(len(self.ssh_calls), 2)  # running and saved, once

        self.clock.advance(minutes=4, seconds=30)  # polled again, but copied 4.5 min ago
        self.answers["192.168.1.2"] = cisco_answer(300)
        self.assertEqual(self.watch(), [])
        self.assertEqual(len(self.ssh_calls), 2)

        self.clock.advance(minutes=4, seconds=30)  # the gap has passed: the change is still pending
        self.assertEqual(len(self.watch()), 1)

    def test_at_most_ten_copies_per_cycle_and_the_rest_wait(self) -> None:
        hosts = []
        for n in range(12):
            mac, ip = f"aa:bb:cc:00:00:{n:02x}", f"10.0.0.{n + 1}"
            self.know(mac, ip)
            hosts.append({"ip": ip, "mac": mac})
        ctx = self.ctx(hosts=hosts)
        self.answers = {host["ip"]: cisco_answer(1) for host in hosts}
        self.watch(ctx)
        self.clock.advance(minutes=6)
        self.answers = {host["ip"]: cisco_answer(2) for host in hosts}

        self.assertEqual(len(self.watch(ctx)), confwatch.MAX_CAPTURES)
        self.clock.advance(minutes=6)
        self.assertEqual(len(self.watch(ctx)), len(hosts) - confwatch.MAX_CAPTURES)

    def test_erased_memory_costs_nothing_but_the_first_sighting(self) -> None:
        self.answers["192.168.1.2"] = cisco_answer(100)
        self.watch()
        self.memory = Memory.load(None)  # the file was deleted
        self.know(SWITCH_MAC, "192.168.1.2")
        self.clock.advance(minutes=6)
        self.answers["192.168.1.2"] = cisco_answer(999)  # it did change meanwhile

        ctx = self.ctx(memory=self.memory)
        self.assertEqual(self.watch(ctx), [])
        self.assertEqual(ctx.get("errors", []), [])
        self.assertEqual(self.memory.confwatch_state(SWITCH_MAC)["stamp"], ["999", "10"])

    def test_no_memory_at_all_is_not_an_error(self) -> None:
        ctx = self.ctx(memory=None)

        self.assertEqual(self.watch(ctx), [])
        self.assertEqual((self.queried, ctx.get("errors", [])), ([], []))

    def test_a_device_that_does_not_answer_snmp_is_not_asked_every_cycle(self) -> None:
        self.answers = {}  # silence
        self.watch()
        self.clock.advance(minutes=6)
        self.watch()
        self.clock.advance(minutes=6)
        self.watch()

        # One failed whole round, and the memory's 24 h rest does the rest.
        self.assertEqual(len(self.queried), 1)

    def test_a_family_without_a_verified_stamp_is_never_asked(self) -> None:
        self.memory = Memory.load(None)
        self.know(SWITCH_MAC, "192.168.1.2", family="mikrotik")
        self.answers["192.168.1.2"] = cisco_answer(100)

        self.assertEqual(self.watch(self.ctx(memory=self.memory)), [])
        self.assertEqual(self.queried, [])

    def test_it_stays_off_with_copies_switched_off_or_the_configs_task_off(self) -> None:
        self.answers["192.168.1.2"] = cisco_answer(100)
        off = self.ctx()
        off["config"]["capture_configs"] = False
        self.assertEqual(self.watch(off), [])
        no_task = self.ctx()
        no_task["config"]["tasks"] = {"configs": {"every_seconds": 0}}
        self.assertEqual(self.watch(no_task), [])
        self.assertEqual(self.queried, [])

    def test_a_failure_inside_is_a_note_and_not_an_exception(self) -> None:
        ctx = self.ctx()
        with mock.patch("agent.confwatch._run", side_effect=RuntimeError("boom")):
            self.assertEqual(confwatch.run(ctx), [])

        self.assertEqual([note.code for note in ctx["errors"]], ["crashed"])


class StampQueryTests(unittest.TestCase):
    """`snmp.query_stamps`: one `get` per device with sysUpTime and its own leaves."""

    def test_asks_uptime_plus_the_family_leaves_and_reports_which_auth_answered(self) -> None:
        asked: list[dict[str, str]] = []

        async def fake_get(engine, host, auth, oids, context_name="", fast=False):
            asked.append(dict(oids))
            if auth != "buena":
                raise TimeoutError
            return {"uptime": "5000", "running": "123"}

        plan = {
            "10.0.0.5": (["mala", "buena"], confwatch.WATCHES["huawei"].oids),
            "10.0.0.6": (["mala"], confwatch.WATCHES["junos"].oids),
        }
        with mock.patch.object(snmp, "AVAILABLE", True),              mock.patch.object(snmp, "SnmpEngine", mock.Mock(), create=True),              mock.patch.object(snmp, "_get", fake_get):
            found = snmp.query_stamps(plan)

        self.assertEqual(list(found), ["10.0.0.5"])
        self.assertEqual(found["10.0.0.5"], (1, {"uptime": "5000", "running": "123"}))
        self.assertIn({"uptime": snmp.SYSTEM_OIDS["uptime"], "running": "1.3.6.1.4.1.2011.6.10.1.1.1.0"}, asked)

    def test_an_answer_without_uptime_is_not_an_answer(self) -> None:
        async def fake_get(engine, host, auth, oids, context_name="", fast=False):
            return {"uptime": "", "running": ""}

        with mock.patch.object(snmp, "AVAILABLE", True),              mock.patch.object(snmp, "SnmpEngine", mock.Mock(), create=True),              mock.patch.object(snmp, "_get", fake_get):
            self.assertEqual(snmp.query_stamps({"10.0.0.5": (["public"], confwatch.WATCHES["cisco"].oids)}), {})


class PresenceTaskTests(unittest.TestCase):
    def test_presence_carries_the_copies_it_triggered_and_counts_them(self) -> None:
        finding = Finding(kind="config", identity={"mac": SWITCH_MAC}, payload={"ip": "192.168.1.2", "config": "x"})

        def fake_run(ctx: dict) -> list[Finding]:
            ctx["confwatch_copies"] = 1
            return [finding]

        with mock.patch("agent.tasks.all_collectors", return_value=[]), \
             mock.patch("agent.tasks.confwatch.run", side_effect=fake_run):
            items, _notes, stats = tasks.run_task("presence", {"config": {}, "env": None})

        self.assertEqual([item["kind"] for item in items], ["config"])
        self.assertEqual(stats["config_changes"], 1)

    def test_other_tasks_do_not_watch(self) -> None:
        with mock.patch("agent.tasks.all_collectors", return_value=[]), \
             mock.patch("agent.tasks.confwatch.run", side_effect=AssertionError("only presence")):
            for name in ("inventory", "configs", "ups", "hypervisors"):
                tasks.run_task(name, {"config": {}, "env": None})


if __name__ == "__main__":
    unittest.main()
