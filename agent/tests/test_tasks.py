"""Los colectores dentro de una tarea (agente 0.11, `ctx["task"]`).

Sin `task` todo es como en la 0.10.x, y eso lo prueban los tests de siempre,
que no se han tocado. Aquí, lo nuevo: cada tarea hace solo lo suyo, la
memoria decide qué credenciales se prueban, lo excluido no se toca nunca, y
los avisos de avance no pueden romper nada.

La red entera es de mentira: ni un ping, ni un `ssh`, ni un paquete SNMP.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado también bajo `unittest discover`

import json
import subprocess
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest import mock

from agent import credentials as creds
from agent import hypervisor, net, probe, snmp, ssh, winrm
from agent.collectors.hypervisors import HypervisorCollector
from agent.collectors.snmp import SnmpCollector
from agent.collectors.ssh import SshCollector
from agent.collectors.sweep import SweepCollector
from agent.collectors.winrm import WinrmCollector
from agent.memory import Excluded, Memory
from agent.tests.test_ssh import CISCO_SHOW_VERSION, IOS_RECHAZA_EL_COMANDO_DE_LINUX, LINUX_UBUNTU
from agent.tests.test_winrm import DC_2019

SWITCH_MAC = "aa:bb:cc:dd:ee:01"
SERVER_MAC = "aa:bb:cc:dd:ee:02"
HOSTS = [{"ip": "192.168.1.2", "mac": SWITCH_MAC}, {"ip": "192.168.1.3", "mac": SERVER_MAC}]


def boom(*args: Any, **kwargs: Any) -> None:
    raise RuntimeError("el icono de bandeja se ha caído")


class Recorder:
    """Un `progress` que apunta lo que le dicen."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, int, int]] = []

    def __call__(self, step: str, done: int, total: int) -> None:
        self.calls.append((step, done, total))


# --- Presencia: el barrido -----------------------------------------------------------


class SweepTaskTests(unittest.TestCase):
    def _ctx(self, **extra: Any) -> dict:
        ctx: dict[str, Any] = {"config": {"subnets": ["192.168.1.0/29"]}, "env": None, "task": "presence"}
        ctx.update(extra)
        return ctx

    def _collect(self, ctx: dict, pinged: list[str]) -> list:
        def fake_ping(ip: str) -> bool:
            pinged.append(ip)
            return ip in {"192.168.1.1", "192.168.1.2"}

        with mock.patch("agent.net.ping", fake_ping), \
             mock.patch("agent.collectors.sweep.net.arp_table", return_value={}), \
             mock.patch("agent.collectors.sweep.net.reverse_dns", return_value=""):
            return SweepCollector().collect(ctx)

    def test_an_excluded_address_is_never_pinged(self) -> None:
        pinged: list[str] = []
        ctx = self._ctx(excluded=Excluded(subnets=["192.168.1.4/31"], addresses=["192.168.1.2"]))

        findings = self._collect(ctx, pinged)

        self.assertEqual(sorted(pinged), ["192.168.1.1", "192.168.1.3", "192.168.1.6"])
        self.assertEqual([host["ip"] for host in ctx["hosts"]], ["192.168.1.1"])
        self.assertEqual(len(findings), 1)

    def test_the_ping_workers_come_from_the_task(self) -> None:
        ctx = self._ctx(workers={"ping": 8, "login": 2, "snmp": 5})
        with mock.patch("agent.collectors.sweep.net.sweep", return_value=[]) as sweep, \
             mock.patch("agent.collectors.sweep.net.arp_table", return_value={}):
            SweepCollector().collect(ctx)

        self.assertEqual(sweep.call_args.kwargs["workers"], 8)

    def test_progress_is_reported_and_its_failures_are_swallowed(self) -> None:
        recorder = Recorder()
        self._collect(self._ctx(progress=recorder), [])
        self.assertEqual(recorder.calls[0], ("sweep", 0, 6))
        self.assertEqual(max(done for _step, done, _total in recorder.calls), 6)

        findings = self._collect(self._ctx(progress=boom), [])
        self.assertEqual(len(findings), 2)

    def test_net_sweep_survives_a_progress_callback_that_raises(self) -> None:
        completed = subprocess.CompletedProcess(args=["ping"], returncode=0, stdout="TTL=64")
        with mock.patch("agent.net.subprocess.run", return_value=completed):
            alive = net.sweep(["10.0.0.1", "10.0.0.2"], workers=1, on_done=boom)

        self.assertEqual(alive, ["10.0.0.1", "10.0.0.2"])


# --- SNMP: inventario y SAI -----------------------------------------------------------

SWITCH_ANSWER = {
    "name": "sw-planta-1",
    "description": "Cisco IOS Software, C1000",
    "object_id": "1.3.6.1.4.1.9.1.3245",
    "interfaces": [
        {"index": "1", "name": "Gi1/0/1", "mac": "aa:bb:cc:00:00:01", "status": "up", "speed_mbps": "1000"},
    ],
    "addresses": {"192.168.1.2": "1"},
}
UPS_READING = {"runtime_minutes": 42, "charge_percent": 100, "load_percent": 31, "on_battery": False}
UPS_ANSWER = {
    "name": "sai-cpd",
    "description": "APC Smart-UPS",
    "object_id": "1.3.6.1.4.1.318",
    # La MAC que el SAI da por SNMP no es la del barrido: es la que manda en
    # la identidad del inventario, y la que la tarea `ups` tiene que repetir.
    "interfaces": [{"index": "1", "name": "eth0", "mac": "00:c0:b7:aa:aa:aa", "status": "up", "speed_mbps": "100"}],
    "addresses": {"192.168.1.3": "1"},
    "ups": UPS_READING,
}


class SnmpTaskTests(unittest.TestCase):
    def _ctx(self, task: str, **extra: Any) -> dict:
        ctx: dict[str, Any] = {
            "config": {"communities": ["comunidad-secreta"]},
            "env": None,
            "hosts": [dict(host) for host in HOSTS],
            "task": task,
        }
        ctx.update(extra)
        return ctx

    def _collect(self, ctx: dict, answers: dict[str, dict]) -> tuple[list, mock.Mock]:
        def fake_plan(plan, **kwargs):
            for _ in plan:
                kwargs["on_done"]()
            return {ip: (0, answers[ip]) for ip in plan if ip in answers}

        with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True), \
             mock.patch("agent.collectors.snmp.snmp.query_plan", side_effect=fake_plan) as query_plan, \
             mock.patch("agent.collectors.snmp.snmp.query_hosts", side_effect=AssertionError("protocolo 1")):
            return SnmpCollector().collect(ctx), query_plan

    def test_inventory_flags_the_ups_with_the_identity_it_presented(self) -> None:
        memory = Memory.load(None)
        ctx = self._ctx("inventory", memory=memory)

        findings, query_plan = self._collect(ctx, {"192.168.1.2": SWITCH_ANSWER, "192.168.1.3": UPS_ANSWER})

        hosts = {f.payload["ip"]: f for f in findings if f.kind == "host"}
        self.assertEqual(hosts["192.168.1.3"].identity, {"mac": "00:c0:b7:aa:aa:aa"})
        self.assertEqual(hosts["192.168.1.3"].payload["ups"], UPS_READING)
        self.assertEqual(
            memory.ups_hosts(), [{"ip": "192.168.1.3", "mac": SERVER_MAC, "identity_mac": "00:c0:b7:aa:aa:aa"}]
        )
        self.assertFalse(query_plan.call_args.kwargs["ups_only"])
        # Y quedó apuntado con qué se entró: la comunidad nº 1, por su número.
        self.assertEqual(memory.remembered(SERVER_MAC, "snmp"), "community-1")

    def test_the_ups_task_asks_only_the_ups_and_only_ups_hosts_with_the_same_identity(self) -> None:
        memory = Memory.load(None)
        inventory, _ = self._collect(
            self._ctx("inventory", memory=memory), {"192.168.1.2": SWITCH_ANSWER, "192.168.1.3": UPS_ANSWER}
        )
        ups_row = next(f for f in inventory if f.kind == "host" and f.payload["ip"] == "192.168.1.3")

        findings, query_plan = self._collect(
            self._ctx("ups", memory=memory), {"192.168.1.3": {"ups": {**UPS_READING, "runtime_minutes": 12}}}
        )

        self.assertEqual(list(query_plan.call_args.args[0]), ["192.168.1.3"])
        self.assertTrue(query_plan.call_args.kwargs["ups_only"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "host")
        self.assertEqual(findings[0].identity, ups_row.identity)
        self.assertEqual(findings[0].payload["ups"]["runtime_minutes"], 12)
        # Solo lo que sabe: ni nombre ni interfaces vacíos que pisen el inventario.
        self.assertNotIn("hostname", findings[0].payload)
        self.assertNotIn("interfaces", findings[0].payload)

    def test_the_ups_task_follows_a_ups_that_changed_address(self) -> None:
        memory = Memory.load(None)
        memory.note_host("192.168.1.3", SERVER_MAC, datetime.now(timezone.utc))
        memory.flag(SERVER_MAC, ups=True, identity_mac="00:c0:b7:aa:aa:aa")
        ctx = self._ctx("ups", memory=memory, hosts=[{"ip": "192.168.1.30", "mac": SERVER_MAC}])

        findings, query_plan = self._collect(ctx, {"192.168.1.30": {"ups": UPS_READING}})

        self.assertEqual(list(query_plan.call_args.args[0]), ["192.168.1.30"])
        self.assertEqual(findings[0].payload["ip"], "192.168.1.30")

    def test_the_ups_task_without_memory_has_nobody_to_ask(self) -> None:
        findings, query_plan = self._collect(self._ctx("ups", memory=None), {})

        self.assertEqual(findings, [])
        query_plan.assert_not_called()

    def test_inventory_without_memory_still_works(self) -> None:
        findings, _ = self._collect(self._ctx("inventory", memory=None), {"192.168.1.2": SWITCH_ANSWER})

        self.assertEqual([f.payload["hostname"] for f in findings if f.kind == "host"], ["sw-planta-1"])

    def test_targets_and_exclusions_decide_who_is_asked(self) -> None:
        ctx = self._ctx(
            "inventory",
            memory=Memory.load(None),
            targets=["192.168.1.2", "192.168.1.3"],
            excluded=Excluded(addresses=["192.168.1.3"]),
        )

        _findings, query_plan = self._collect(ctx, {})

        self.assertEqual(list(query_plan.call_args.args[0]), ["192.168.1.2"])

    def test_the_snmp_workers_come_from_the_task(self) -> None:
        ctx = self._ctx("inventory", workers={"ping": 8, "login": 2, "snmp": 5})

        _findings, query_plan = self._collect(ctx, {})

        self.assertEqual(query_plan.call_args.kwargs["concurrency"], 5)

    def test_a_silent_host_is_not_asked_again_for_a_day(self) -> None:
        memory = Memory.load(None)
        self._collect(self._ctx("inventory", memory=memory), {})

        _findings, query_plan = self._collect(self._ctx("inventory", memory=memory), {})

        query_plan.assert_not_called()

    def test_progress_failures_do_not_cost_the_findings(self) -> None:
        findings, _ = self._collect(self._ctx("inventory", progress=boom), {"192.168.1.2": SWITCH_ANSWER})

        self.assertTrue(findings)


class UpsQueryTests(unittest.TestCase):
    """`agent.snmp` en la tarea `ups`: cuatro OIDs de hoja y ni uno más."""

    def test_only_the_ups_mib_is_asked(self) -> None:
        asked: list[dict[str, str]] = []

        async def fake_get(engine, host, auth, oids, context_name=""):
            asked.append(dict(oids))
            return {"runtime_minutes": "17", "charge_percent": "90", "output_source": "5", "load_percent": "40"}

        async def no_walks(*args, **kwargs):
            raise AssertionError("la tarea ups no recorre tablas")

        with mock.patch.object(snmp, "AVAILABLE", True), \
             mock.patch.object(snmp, "SnmpEngine", mock.Mock(), create=True), \
             mock.patch.object(snmp, "_get", fake_get), \
             mock.patch.object(snmp, "_walk", no_walks):
            found = snmp.query_plan({"10.0.0.5": ["public"]}, ups_only=True)

        self.assertEqual(asked, [snmp.UPS_OIDS])
        self.assertEqual(found["10.0.0.5"][0], 0)
        self.assertEqual(found["10.0.0.5"][1]["ups"]["runtime_minutes"], 17)
        self.assertTrue(found["10.0.0.5"][1]["ups"]["on_battery"])

    def test_the_index_says_which_auth_answered(self) -> None:
        async def fake_get(engine, host, auth, oids, context_name=""):
            if auth != "buena":
                raise TimeoutError
            return {"runtime_minutes": "17"}

        with mock.patch.object(snmp, "AVAILABLE", True), \
             mock.patch.object(snmp, "SnmpEngine", mock.Mock(), create=True), \
             mock.patch.object(snmp, "_get", fake_get):
            found = snmp.query_plan({"10.0.0.5": ["mala", "buena"], "10.0.0.6": ["mala"]}, ups_only=True)

        self.assertEqual(list(found), ["10.0.0.5"])
        self.assertEqual(found["10.0.0.5"][0], 1)


# --- SSH: inventario y copias ------------------------------------------------------


def ssh_credentials(*names: str) -> list[dict]:
    return [{"id": f"id-{name}", "kind": "ssh", "username": name, "key_file": "/k"} for name in names]


class SshTaskTests(unittest.TestCase):
    RUNNING_CONFIG = "hostname sw-core-01\ninterface Gi1/0/1\n switchport access vlan 10"

    def _ctx(self, task: str, **extra: Any) -> dict:
        ctx: dict[str, Any] = {
            "config": {"credentials": ssh_credentials("admin")},
            "env": None,
            "hosts": [dict(host) for host in HOSTS],
            "task": task,
        }
        ctx.update(extra)
        return ctx

    def _collect(
        self,
        ctx: dict,
        *,
        calls: list[dict] | None = None,
        accept: set[str] | None = None,
        listening: Any = None,
    ) -> list:
        """`accept`: los usuarios que entran. El switch es un IOS; el otro, un Ubuntu."""
        accepted = {"admin"} if accept is None else accept

        def fake_run(**kwargs: Any) -> ssh.Answer:
            if calls is not None:
                calls.append(kwargs)
            if kwargs["username"] not in accepted:
                return ssh.Answer(connected=False, error="Permission denied")
            command = kwargs["command"]
            if kwargs["host"] == "192.168.1.3":
                return ssh.Answer(connected=True, output=LINUX_UBUNTU)
            if command == "show version":
                return ssh.Answer(connected=True, output=CISCO_SHOW_VERSION)
            if command == "show running-config":
                return ssh.Answer(connected=True, output=self.RUNNING_CONFIG)
            return ssh.Answer(connected=True, output=IOS_RECHAZA_EL_COMANDO_DE_LINUX)

        def fake_listening(ips: list[str], port: int, **kwargs: Any) -> list[str]:
            return list(ips)

        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.SSHPASS_AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", listening or fake_listening), \
             mock.patch("agent.collectors.ssh.ssh.run", fake_run):
            return SshCollector().collect(ctx)

    def test_inventory_interrogates_but_never_copies_and_remembers_the_family(self) -> None:
        memory = Memory.load(None)
        calls: list[dict] = []

        findings = self._collect(self._ctx("inventory", memory=memory), calls=calls)

        self.assertEqual(sorted(f.kind for f in findings), ["host", "host"])
        self.assertNotIn("show running-config", [call["command"] for call in calls])
        self.assertEqual(
            memory.config_hosts(),
            [{"ip": "192.168.1.2", "mac": SWITCH_MAC, "family": "cisco", "identity_mac": SWITCH_MAC}],
        )
        self.assertEqual(memory.remembered(SWITCH_MAC, "ssh"), "id-admin")

    def test_configs_only_copies_config_hosts_with_the_remembered_credential(self) -> None:
        memory = Memory.load(None)
        ctx = self._ctx("inventory", memory=memory)
        ctx["config"]["credentials"] = ssh_credentials("lector", "admin")
        self._collect(ctx, accept={"admin"})

        calls: list[dict] = []
        ctx = self._ctx("configs", memory=memory)
        ctx["config"]["credentials"] = ssh_credentials("lector", "admin")
        findings = self._collect(ctx, calls=calls, accept={"admin"}, listening=mock.Mock(side_effect=AssertionError))

        self.assertEqual(
            [(call["host"], call["username"], call["command"]) for call in calls],
            [("192.168.1.2", "admin", "show running-config")],
        )
        self.assertEqual([f.kind for f in findings], ["config"])
        self.assertEqual(findings[0].identity, {"mac": SWITCH_MAC})
        self.assertEqual(findings[0].payload["config"], self.RUNNING_CONFIG)
        self.assertEqual(findings[0].payload["family"], "cisco")

    def test_configs_skips_a_host_whose_credential_is_gone(self) -> None:
        memory = Memory.load(None)
        self._collect(self._ctx("inventory", memory=memory))
        calls: list[dict] = []
        ctx = self._ctx("configs", memory=memory)
        ctx["config"]["credentials"] = ssh_credentials("otro")

        self.assertEqual(self._collect(ctx, calls=calls, accept={"otro"}), [])
        self.assertEqual(calls, [])

    def test_configs_skips_a_device_that_is_not_alive_now(self) -> None:
        memory = Memory.load(None)
        self._collect(self._ctx("inventory", memory=memory))
        calls: list[dict] = []

        findings = self._collect(self._ctx("configs", memory=memory, hosts=[HOSTS[1]]), calls=calls)

        self.assertEqual((findings, calls), ([], []))

    def test_configs_respects_the_capture_switch(self) -> None:
        memory = Memory.load(None)
        self._collect(self._ctx("inventory", memory=memory))
        ctx = self._ctx("configs", memory=memory)
        ctx["config"]["capture_configs"] = False

        self.assertEqual(self._collect(ctx), [])

    def test_three_wrong_credentials_are_not_tried_again_on_the_next_run(self) -> None:
        """El motivo de la memoria: un barrido cada pocos minutos con tres
        credenciales malas contra un dominio bloquea la cuenta."""
        memory = Memory.load(None)
        attempts: list[list[dict]] = []
        for _run in range(2):
            calls: list[dict] = []
            ctx = self._ctx("inventory", memory=memory, hosts=[HOSTS[0]])
            ctx["config"]["credentials"] = ssh_credentials("uno", "dos", "tres")
            self._collect(ctx, calls=calls, accept=set())
            attempts.append(calls)

        self.assertEqual(len(attempts[0]), 3)
        self.assertEqual(attempts[1], [])

    def test_a_credential_change_earns_a_new_round(self) -> None:
        memory = Memory.load(None)
        memory.credentials_changed("etag-1")
        ctx = self._ctx("inventory", memory=memory, hosts=[HOSTS[0]])
        self._collect(ctx, accept=set())

        memory.credentials_changed("etag-2")
        calls: list[dict] = []
        self._collect(self._ctx("inventory", memory=memory, hosts=[HOSTS[0]]), calls=calls)

        self.assertTrue(calls)

    def test_out_of_scope_credentials_are_never_tried(self) -> None:
        calls: list[dict] = []
        ctx = self._ctx("inventory", memory=Memory.load(None), hosts=[HOSTS[0]])
        ctx["config"]["credentials"] = [
            {"id": "x", "kind": "ssh", "username": "ajena", "key_file": "/k", "scope": {"subnets": ["10.0.0.0/8"]}},
            *ssh_credentials("admin"),
        ]

        self._collect(ctx, calls=calls)

        self.assertNotIn("ajena", {call["username"] for call in calls})

    def test_targets_and_exclusions_decide_who_is_touched(self) -> None:
        probed: list[list[str]] = []
        calls: list[dict] = []

        def listening(ips: list[str], port: int, **kwargs: Any) -> list[str]:
            probed.append(list(ips))
            return list(ips)

        ctx = self._ctx(
            "inventory", targets=["192.168.1.2", "192.168.1.3"], excluded=Excluded(addresses=["192.168.1.3"])
        )
        self._collect(ctx, calls=calls, listening=listening)

        self.assertEqual(probed, [["192.168.1.2"]])
        self.assertEqual({call["host"] for call in calls}, {"192.168.1.2"})

    def test_workers_come_from_the_task(self) -> None:
        sizes: list[int] = []

        def pool(max_workers: int) -> ThreadPoolExecutor:
            sizes.append(max_workers)
            return ThreadPoolExecutor(max_workers=max_workers)

        probes: list[dict] = []

        def listening(ips: list[str], port: int, **kwargs: Any) -> list[str]:
            probes.append(kwargs)
            return list(ips)

        with mock.patch("agent.collectors.ssh.ThreadPoolExecutor", pool):
            self._collect(self._ctx("inventory", workers={"ping": 8, "login": 2, "snmp": 5}), listening=listening)

        self.assertEqual(sizes, [2])
        self.assertEqual(probes, [{"workers": 8}])

    def test_progress_and_its_failures(self) -> None:
        recorder = Recorder()
        self._collect(self._ctx("inventory", progress=recorder))
        self.assertEqual(recorder.calls[0], ("ssh", 0, 2))
        self.assertEqual(recorder.calls[-1][1:], (2, 2))

        self.assertTrue(self._collect(self._ctx("inventory", progress=boom)))

    def test_inventory_without_memory_tries_everything_as_today(self) -> None:
        calls: list[dict] = []
        ctx = self._ctx("inventory", memory=None, hosts=[HOSTS[0]])
        ctx["config"]["credentials"] = ssh_credentials("uno", "dos")

        for _run in range(2):
            self._collect(ctx, calls=calls, accept=set())

        self.assertEqual(len(calls), 4)


# --- WinRM -----------------------------------------------------------------------------


class WinrmTaskTests(unittest.TestCase):
    def _collect(self, ctx: dict, calls: list[tuple[str, str]], accept: set[str]) -> list:
        def fake_query(*, host: str, username: str, secret: str, port: int = 0, ca_file: str = "") -> winrm.Answer:
            calls.append((host, username))
            if username in accept:
                return winrm.Answer(True, DC_2019)
            return winrm.Answer(False, None, "401")

        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", True), \
             mock.patch("agent.collectors.winrm.net.hosts_listening", lambda ips, port, **kw: list(ips)), \
             mock.patch("agent.collectors.winrm.winrm.query", fake_query):
            return WinrmCollector().collect(ctx)

    def _ctx(self, memory: Memory | None, **extra: Any) -> dict:
        ctx: dict[str, Any] = {
            "config": {
                "credentials": [
                    {"id": f"w{n}", "kind": "winrm", "username": f"ACME\\u{n}", "secret": "s"} for n in (1, 2, 3)
                ]
            },
            "env": None,
            "hosts": [{"ip": "192.168.1.10", "mac": "b0:83:fe:11:22:33"}],
            "task": "inventory",
            "memory": memory,
        }
        ctx.update(extra)
        return ctx

    def test_three_wrong_credentials_are_not_tried_again_on_the_next_run(self) -> None:
        memory = Memory.load(None)
        first: list[tuple[str, str]] = []
        second: list[tuple[str, str]] = []

        self._collect(self._ctx(memory), first, accept=set())
        self._collect(self._ctx(memory), second, accept=set())

        self.assertEqual(len(first), 3)
        self.assertEqual(second, [])

    def test_the_one_that_worked_is_tried_first_next_time(self) -> None:
        memory = Memory.load(None)
        self._collect(self._ctx(memory), [], accept={"ACME\\u3"})
        calls: list[tuple[str, str]] = []

        findings = self._collect(self._ctx(memory), calls, accept={"ACME\\u3"})

        self.assertEqual(calls, [("192.168.1.10", "ACME\\u3")])
        self.assertEqual(findings[0].payload["hostname"], "SRV-DC01")

    def test_an_excluded_host_is_never_asked(self) -> None:
        calls: list[tuple[str, str]] = []

        self._collect(self._ctx(None, excluded=Excluded(subnets=["192.168.1.0/24"])), calls, accept={"ACME\\u1"})

        self.assertEqual(calls, [])


# --- Hipervisores ------------------------------------------------------------------------


class _Client:
    logins: list[str] = []

    def __init__(self, host: str, username: str, secret: str, *, port: int = 0, ca_file: str = "") -> None:
        self.host = host
        self.secret = secret

    def login(self) -> None:
        _Client.logins.append(self.host)
        if self.secret != "buena":
            raise hypervisor.HypervisorError("401")

    def hosts(self) -> list[dict]:
        return []

    def virtual_machines(self) -> list[dict]:
        return [{"id": "vm-1", "name": "srv-ficheros"}]


class HypervisorTaskTests(unittest.TestCase):
    def setUp(self) -> None:
        _Client.logins = []

    def _collect(self, ctx: dict) -> list:
        with mock.patch.dict("agent.collectors.hypervisors.CLIENTS", {"vmware": _Client}, clear=True), \
             mock.patch("agent.collectors.hypervisors.net.resolve", lambda name: "10.0.0.50"):
            return HypervisorCollector().collect(ctx)

    def _ctx(self, secret: str, **extra: Any) -> dict:
        ctx: dict[str, Any] = {
            "config": {"credentials": [{"id": "vc", "kind": "vmware", "username": "u", "secret": secret, "host": "vc.acme.local"}]},
            "env": None,
            "task": "hypervisors",
        }
        ctx.update(extra)
        return ctx

    def test_an_excluded_server_is_not_touched_and_it_is_said(self) -> None:
        ctx = self._ctx("buena", excluded=Excluded(addresses=["10.0.0.50"]))

        self.assertEqual(self._collect(ctx), [])
        self.assertEqual(_Client.logins, [])
        self.assertEqual([(n.collector, n.code) for n in ctx["errors"]], [("hypervisors", "excluded")])

    def test_a_password_that_never_worked_waits_a_day(self) -> None:
        memory = Memory.load(None)
        self._collect(self._ctx("mala", memory=memory))
        self._collect(self._ctx("mala", memory=memory))

        self.assertEqual(_Client.logins, ["vc.acme.local"])

    def test_one_that_worked_once_is_always_retried(self) -> None:
        memory = Memory.load(None)
        self._collect(self._ctx("buena", memory=memory))
        memory.record_round_failed("10.0.0.50", "vmware", datetime.now(timezone.utc))

        findings = self._collect(self._ctx("buena", memory=memory))

        self.assertEqual(len(_Client.logins), 2)
        self.assertEqual([f.kind for f in findings], ["vm"])

    def test_progress_and_no_memory(self) -> None:
        recorder = Recorder()

        findings = self._collect(self._ctx("buena", memory=None, progress=recorder))

        self.assertEqual([f.kind for f in findings], ["vm"])
        self.assertEqual(recorder.calls, [("hypervisors", 0, 1), ("hypervisors", 1, 1)])


# --- «Analizar» ----------------------------------------------------------------------------


class ProbeTaskTests(unittest.TestCase):
    def test_an_excluded_address_is_refused_without_touching_it(self) -> None:
        ctx = {"config": {"communities": ["x"]}, "env": None, "excluded": Excluded(addresses=["10.0.0.9"])}
        with mock.patch.object(probe, "_port_open", side_effect=AssertionError("ni un puerto")), \
             mock.patch.object(probe.snmp, "AVAILABLE", True), \
             mock.patch.object(probe.snmp, "query_hosts", side_effect=AssertionError("ni un paquete")):
            report = probe.report_for("10.0.0.9", ctx)

        self.assertEqual({entry["code"] for entry in report["codes"].values()}, {"excluded"})
        self.assertIn("excluida", report["ssh"])

    def test_a_probe_ignores_the_daily_limit_and_remembers_what_worked(self) -> None:
        """Lo pide una persona: prueba todo lo que está en alcance, aunque el
        agente hoy ya hubiera desistido con ese equipo."""
        memory = Memory.load(None)
        memory.note_host("10.0.0.9", "", datetime.now(timezone.utc))
        memory.record_round_failed("10.0.0.9", "ssh", datetime.now(timezone.utc))
        ctx = {
            "config": {"credentials": ssh_credentials("malo", "bueno")},
            "env": None,
            "memory": memory,
        }
        answers = [ssh.Answer(connected=False), ssh.Answer(connected=True)]
        with mock.patch.object(probe, "_port_open", return_value=True), \
             mock.patch.object(probe.ssh, "run", side_effect=answers) as run:
            line = probe._ssh_line("10.0.0.9", ctx)

        self.assertIn("«bueno»", line)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(memory.remembered("10.0.0.9", "ssh"), "id-bueno")
        # La ronda fallida sigue donde estaba: el sondeo no la toca. El agente
        # probará la que entró y, hasta mañana, ninguna más.
        malo, bueno = creds.all_from(ctx)
        later = datetime.now(timezone.utc) + timedelta(minutes=1)
        self.assertEqual(memory.order_for("10.0.0.9", "ssh", [malo, bueno], later), [bueno])

    def test_a_probe_remembers_a_community_by_number_and_never_says_it(self) -> None:
        memory = Memory.load(None)
        ctx = {"config": {"communities": ["super-secreta", "otra"]}, "env": None, "memory": memory}
        with mock.patch.object(probe.snmp, "AVAILABLE", True), \
             mock.patch.object(probe.snmp, "query_hosts", side_effect=[{}, {"10.0.0.9": {}}]):
            line = probe._snmp_line("10.0.0.9", ctx)

        self.assertEqual(line, "contesta con la comunidad nº 2")
        self.assertEqual(memory.remembered("10.0.0.9", "snmp"), "community-2")
        self.assertNotIn("super-secreta", json.dumps(memory._snapshot()))

    def test_out_of_scope_credentials_are_not_probed(self) -> None:
        ctx = {
            "config": {
                "credentials": [
                    {"kind": "ssh", "username": "ajena", "key_file": "/k", "scope": {"hosts": ["10.9.9.9"]}},
                    {"kind": "ssh", "username": "propia", "key_file": "/k"},
                ]
            },
            "env": None,
        }
        with mock.patch.object(probe, "_port_open", return_value=True), \
             mock.patch.object(probe.ssh, "run", return_value=ssh.Answer(connected=True)) as run:
            probe._ssh_line("10.0.0.9", ctx)

        self.assertEqual([call.kwargs["username"] for call in run.call_args_list], ["propia"])


if __name__ == "__main__":
    unittest.main()
