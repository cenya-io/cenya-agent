"""What was tried with each device and what happened (08-10-2026).

A device that answers the ping and that nothing gets into used to stay in the
tray with no reason given. Each protocol now writes down its own outcome per
IP -- a device can refuse SSH and still answer SNMP -- with a code and the
credential's id, never a secret, and it travels in ``stats.attempts``.
"""

from __future__ import annotations

import unittest
from unittest import mock

from agent import credentials as creds
from agent import ssh
from agent.collectors import tasking
from agent.collectors.snmp import SnmpCollector
from agent.collectors.ssh import SshCollector
from agent.memory import Memory

IP = "172.20.5.28"
SECRET = "Sistemas13$"


def server_credential(kind: str, ident: str, **extra: str) -> creds.Credential:
    return creds._one({"kind": kind, "username": "sistemas", "secret": SECRET, "id": ident, **extra}, 0)


class RecordTests(unittest.TestCase):
    def test_a_login_writes_its_code_and_the_credential_id_never_the_secret(self) -> None:
        ctx: dict = {}
        credential = server_credential("ssh", "cred-ssh")
        logins = tasking.Logins(ctx, "ssh", "ssh", IP)

        logins.run(credential, lambda: ssh.Answer(connected=False, error="Permission denied (password)."), ssh.outcome)

        self.assertEqual(tasking.attempts(ctx), [{"ip": IP, "protocol": "ssh", "code": "auth_failed", "credential": "cred-ssh"}])
        self.assertNotIn(SECRET, repr(tasking.attempts(ctx)))

    def test_an_old_ssh_is_told_apart_from_a_wrong_password(self) -> None:
        ctx: dict = {}
        old = ssh.Answer(connected=False, error="Unable to negotiate with 172.20.5.21 port 22", unreachable=True)

        tasking.Logins(ctx, "ssh", "ssh", IP).run(server_credential("ssh", "c"), lambda: old, ssh.outcome)

        self.assertEqual(tasking.attempts(ctx)[0]["code"], "old_ssh")

    def test_with_memory_the_verdict_is_recorded_too(self) -> None:
        ctx: dict = {"memory": Memory.load(None)}

        tasking.Logins(ctx, "ssh", "ssh", IP).run(
            server_credential("ssh", "c"), lambda: ssh.Answer(connected=True, output="x"), ssh.outcome
        )

        self.assertEqual(tasking.attempts(ctx)[0]["code"], "ok")

    def test_no_credential_covering_the_device_is_said(self) -> None:
        ctx: dict = {}
        out_of_scope = server_credential("ssh", "c", scope={"subnets": ["10.0.0.0/24"]})  # type: ignore[arg-type]

        order, _full = tasking.plan(ctx, IP, "", "ssh", [out_of_scope])

        self.assertEqual(order, [])
        self.assertEqual(tasking.attempts(ctx), [{"ip": IP, "protocol": "ssh", "code": "no_credentials"}])

    def test_the_list_has_a_ceiling(self) -> None:
        ctx: dict = {}
        for index in range(tasking.MAX_ATTEMPTS + 10):
            tasking.record(ctx, f"10.0.{index // 250}.{index % 250}", "snmp", "silent")
        self.assertEqual(len(tasking.attempts(ctx)), tasking.MAX_ATTEMPTS)


class SnmpAttemptTests(unittest.TestCase):
    def test_each_device_says_whether_it_answered(self) -> None:
        ctx = {
            "config": {"communities": ["public"]},
            "env": None,
            "task": "inventory",
            "hosts": [{"ip": "10.0.0.2", "mac": ""}, {"ip": IP, "mac": ""}],
        }
        data = {"name": "sw", "description": "", "interfaces": [], "addresses": {}}

        def query_plan(plan: dict, **kwargs: object) -> dict:
            return {"10.0.0.2": (0, data)}

        with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True), mock.patch(
            "agent.collectors.snmp.snmp.query_plan", side_effect=query_plan
        ):
            SnmpCollector().collect(ctx)

        codes = {entry["ip"]: entry["code"] for entry in tasking.attempts(ctx)}
        self.assertEqual(codes, {"10.0.0.2": "ok", IP: "silent"})


class SshAttemptTests(unittest.TestCase):
    def test_logged_in_but_unrecognised_is_said_instead_of_vanishing(self) -> None:
        credential = server_credential("ssh", "cred-ssh")
        ctx = {"config": {"credentials": []}, "env": None, "task": "inventory", "hosts": [{"ip": IP, "mac": ""}]}

        with mock.patch.object(ssh, "AVAILABLE", True), mock.patch.object(
            creds, "for_kind", return_value=[credential]
        ), mock.patch(
            "agent.collectors.ssh.net.hosts_listening", return_value=[IP]
        ), mock.patch(
            "agent.collectors.ssh.interrogate", return_value=({}, credential)
        ):
            findings = SshCollector().collect(ctx)

        self.assertEqual(findings, [])
        self.assertIn(
            {"ip": IP, "protocol": "ssh", "code": "ok_unknown", "credential": "cred-ssh"}, tasking.attempts(ctx)
        )


class StatsTests(unittest.TestCase):
    def test_the_attempts_travel_in_the_stats(self) -> None:
        from agent import tasks

        def collect(ctx: dict) -> list:
            tasking.record(ctx, IP, "snmp", "silent")
            return []

        collector = mock.Mock()
        collector.name = "snmp"
        collector.collect.side_effect = collect
        with mock.patch("agent.tasks.all_collectors", return_value=[collector]):
            _items, _notes, stats = tasks.run_task("inventory", {"config": {}, "env": None, "hosts": []})

        self.assertEqual(stats["attempts"], [{"ip": IP, "protocol": "snmp", "code": "silent"}])


if __name__ == "__main__":
    unittest.main()
