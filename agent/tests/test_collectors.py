"""The sweep and SNMP collectors, tested without a network: ARP fixtures from
real Windows (EN/ES) and Linux outputs, and a fake SNMP layer."""

from __future__ import annotations

import subprocess
import time
import unittest
from unittest import mock

from agent import net
from agent.collectors import RUN_ORDER, all_collectors
from agent.collectors.snmp import SnmpCollector, _communities
from agent.collectors.sweep import SweepCollector, _subnets
from agent.config import Config

ARP_WINDOWS_EN = """
Interface: 192.168.1.50 --- 0x8
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
  192.168.1.20          aa-bb-cc-dd-ee-02     dynamic
  224.0.0.22            01-00-5e-00-00-16     static
"""

ARP_WINDOWS_ES = """
Interfaz: 192.168.1.50 --- 0x8
  Dirección Internet    Dirección física      Tipo
  192.168.1.1           aa-bb-cc-dd-ee-01     dinámica
"""

ARP_LINUX = """
? (192.168.1.1) en aa:bb:cc:dd:ee:01 [ether] en eth0
? (192.168.1.20) en aa:bb:cc:dd:ee:02 [ether] en eth0
"""


class NetTests(unittest.TestCase):
    def test_expand_subnets_skips_garbage_and_caps_giants(self) -> None:
        self.assertEqual(net.expand_subnets(["192.168.1.0/30"]), ["192.168.1.1", "192.168.1.2"])
        self.assertEqual(net.expand_subnets(["no-es-una-red"]), [])
        self.assertEqual(len(net.expand_subnets(["10.0.0.0/16"])), net.MAX_SWEEP_HOSTS)

    def test_ping_command_follows_the_os(self) -> None:
        with mock.patch("platform.system", return_value="Windows"):
            self.assertEqual(net.ping_command("1.1.1.1"), ["ping", "-n", "1", "-w", "500", "1.1.1.1"])
        with mock.patch("platform.system", return_value="Linux"):
            self.assertEqual(net.ping_command("1.1.1.1"), ["ping", "-c", "1", "-W", "1", "1.1.1.1"])

    def _arp(self, output: str) -> dict[str, str]:
        completed = subprocess.CompletedProcess(args=["arp", "-a"], returncode=0, stdout=output)
        with mock.patch("subprocess.run", return_value=completed):
            return net.arp_table()

    def test_arp_table_parses_windows_english(self) -> None:
        table = self._arp(ARP_WINDOWS_EN)
        self.assertEqual(table["192.168.1.1"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(table["192.168.1.20"], "aa:bb:cc:dd:ee:02")

    def test_arp_table_parses_windows_spanish(self) -> None:
        """The OS language must not matter: regexes, not column headers."""
        self.assertEqual(self._arp(ARP_WINDOWS_ES)["192.168.1.1"], "aa:bb:cc:dd:ee:01")

    def test_arp_table_parses_linux(self) -> None:
        table = self._arp(ARP_LINUX)
        self.assertEqual(table["192.168.1.20"], "aa:bb:cc:dd:ee:02")

    def test_without_arp_the_table_comes_from_ip_neigh(self) -> None:
        """A minimal Debian/Ubuntu server ships no net-tools: without the
        fallback every host came back MAC-less there and identity degraded
        to the IP."""
        neigh = "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"

        def run(command, **kwargs):
            if command[0] == "arp":
                raise FileNotFoundError("arp: not found")
            return subprocess.CompletedProcess(args=command, returncode=0, stdout=neigh)

        with mock.patch("subprocess.run", side_effect=run):
            table = net.arp_table()

        self.assertEqual(table["192.168.1.1"], "aa:bb:cc:dd:ee:01")

    def test_an_empty_arp_output_also_falls_back(self) -> None:
        """busybox ships an `arp` that exists and prints nothing useful."""
        neigh = "10.0.0.7 dev eth0 lladdr aa:bb:cc:dd:ee:07 STALE\n"

        def run(command, **kwargs):
            output = "" if command[0] == "arp" else neigh
            return subprocess.CompletedProcess(args=command, returncode=0, stdout=output)

        with mock.patch("subprocess.run", side_effect=run):
            self.assertEqual(net.arp_table()["10.0.0.7"], "aa:bb:cc:dd:ee:07")

    def test_ping_on_windows_needs_a_ttl_not_just_exit_zero(self) -> None:
        """ping.exe returns 0 for «Destination host unreachable» too: the
        router answered, the host did not. A real reply carries TTL=,
        whatever the system language."""
        unreachable = subprocess.CompletedProcess(
            args=["ping"], returncode=0,
            stdout="Respuesta desde 10.0.0.1: Host de destino inaccesible.\n",
        )
        alive = subprocess.CompletedProcess(
            args=["ping"], returncode=0,
            stdout="Respuesta desde 10.0.0.5: bytes=32 tiempo<1m TTL=128\n",
        )
        with mock.patch("platform.system", return_value="Windows"):
            with mock.patch("subprocess.run", return_value=unreachable):
                self.assertFalse(net.ping("10.0.0.5"))
            with mock.patch("subprocess.run", return_value=alive):
                self.assertTrue(net.ping("10.0.0.5"))

    def test_ping_on_linux_still_trusts_the_exit_code(self) -> None:
        silent = subprocess.CompletedProcess(args=["ping"], returncode=0, stdout="")
        with mock.patch("platform.system", return_value="Linux"), \
             mock.patch("subprocess.run", return_value=silent):
            self.assertTrue(net.ping("10.0.0.5"))

    def test_reverse_dns_never_waits_longer_than_its_budget(self) -> None:
        """The one sweep operation that had no ceiling: a hung resolver held
        its thread for as long as it pleased."""
        import time as time_module

        def hang(ip):
            time_module.sleep(5)
            return ("nunca-llega", [], [])

        with mock.patch("socket.gethostbyaddr", side_effect=hang):
            started = time_module.perf_counter()
            name = net.reverse_dns("10.0.0.5", timeout=0.2)
            elapsed = time_module.perf_counter() - started

        self.assertEqual(name, "")
        self.assertLess(elapsed, 2)


class SweepCollectorTests(unittest.TestCase):
    def _ctx(self, **config) -> dict:
        return {"config": config, "env": None}

    def test_subnets_come_from_the_server_first(self) -> None:
        env = Config(url="http://x", token="t", subnets=("10.9.0.0/24",))
        self.assertEqual(_subnets({"config": {"subnets": ["192.168.1.0/24"]}, "env": env}), ["192.168.1.0/24"])
        self.assertEqual(_subnets({"config": {}, "env": env}), ["10.9.0.0/24"])

    def test_without_config_the_agent_sweeps_its_own_24(self) -> None:
        with mock.patch("agent.collectors.sweep.net.own_subnet", return_value="192.168.7.0/24"):
            self.assertEqual(_subnets(self._ctx()), ["192.168.7.0/24"])

    def test_alive_hosts_become_findings_and_land_in_the_context(self) -> None:
        ctx = self._ctx(subnets=["192.168.1.0/30"])
        with mock.patch("agent.collectors.sweep.net.sweep", return_value=["192.168.1.1", "192.168.1.2"]), \
             mock.patch("agent.collectors.sweep.net.arp_table", return_value={"192.168.1.1": "aa:bb:cc:dd:ee:01"}), \
             mock.patch("agent.collectors.sweep.net.reverse_dns", side_effect=["router.local", ""]):
            findings = SweepCollector().collect(ctx)

        self.assertEqual(len(findings), 2)
        by_ip = {f.payload["ip"]: f for f in findings}
        # Identity prefers the MAC; without one, the IP.
        self.assertEqual(by_ip["192.168.1.1"].identity, {"mac": "aa:bb:cc:dd:ee:01"})
        self.assertEqual(by_ip["192.168.1.2"].identity, {"ip": "192.168.1.2"})
        self.assertEqual(by_ip["192.168.1.1"].payload["hostname"], "router.local")
        self.assertEqual(len(ctx["hosts"]), 2)


class SnmpCollectorTests(unittest.TestCase):
    SNMP_ANSWER = {
        "name": "sw-planta-1",
        "description": "Cisco IOS Software, C1000",
        "object_id": "1.3.6.1.4.1.9.1.3245",
        "interfaces": [
            {"index": "1", "name": "Gi1/0/1", "mac": "aa:bb:cc:00:00:01", "status": "up", "speed_mbps": "1000"},
            {"index": "2", "name": "Gi1/0/2", "mac": "", "status": "down", "speed_mbps": "1000"},
        ],
        "addresses": {"192.168.1.2": "1"},
    }

    def test_communities_come_from_the_server_first(self) -> None:
        env = Config(url="http://x", token="t", communities=("entorno",))
        self.assertEqual(_communities({"config": {"communities": ["servidor"]}, "env": env}), ["servidor"])
        self.assertEqual(_communities({"config": {}, "env": env}), ["entorno"])
        self.assertEqual(_communities({"config": {}, "env": None}), ["public"])

    def test_v3_users_are_tried_before_the_communities(self) -> None:
        """Un equipo configurado con v3 suele tener v2c apagado; al revés, el
        que tiene los dos contestaría siempre a la comunidad y el usuario v3
        que alguien escribió a propósito no se usaría nunca."""
        from agent.collectors.snmp import _auths

        ctx = {
            "config": {
                "communities": ["publica"],
                "credentials": [{"kind": "snmpv3", "username": "lector"}],
            },
            "env": None,
        }

        auths = _auths(ctx)

        self.assertEqual(auths[0].username, "lector")
        self.assertEqual(auths[1], "publica")

    def test_without_v3_users_the_communities_alone_remain(self) -> None:
        from agent.collectors.snmp import _auths

        self.assertEqual(_auths({"config": {}, "env": None}), ["public"])

    def test_an_answering_host_is_enriched_not_duplicated(self) -> None:
        ctx = {"config": {"communities": ["public"]}, "env": None, "hosts": [{"ip": "192.168.1.2", "mac": ""}]}
        with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True), \
             mock.patch("agent.collectors.snmp.snmp.query_hosts", return_value={"192.168.1.2": self.SNMP_ANSWER}):
            findings = SnmpCollector().collect(ctx)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        # The identity is the device's own MAC: the same host the sweep filed.
        self.assertEqual(finding.identity, {"mac": "aa:bb:cc:00:00:01"})
        self.assertEqual(finding.payload["hostname"], "sw-planta-1")
        self.assertEqual(finding.payload["management_interface"], "Gi1/0/1")
        self.assertEqual(len(finding.payload["interfaces"]), 2)

    def test_without_pysnmp_the_collector_reports_and_returns_nothing(self) -> None:
        ctx: dict = {"config": {}, "env": None, "hosts": [{"ip": "192.168.1.2", "mac": ""}]}
        with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", False):
            findings = SnmpCollector().collect(ctx)

        self.assertEqual(findings, [])
        self.assertTrue(any("pysnmp" in error for error in ctx["errors"]))

    def test_a_sweep_that_found_nobody_is_not_an_error(self) -> None:
        ctx = {"config": {}, "env": None, "hosts": []}
        with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True):
            self.assertEqual(SnmpCollector().collect(ctx), [])
        self.assertIsNone(ctx.get("errors"))

    def test_running_before_the_sweep_complains_instead_of_going_quiet(self) -> None:
        """El fallo que dejó SNMP mudo en producción sin que nadie se enterara.

        Sin la queja, la ejecución se marcaba «ok» y no salía ni un hallazgo por
        SNMP: el síntoma era «esto no encuentra nada», que no se parece en nada
        a la causa.
        """
        ctx = {"config": {}, "env": None}  # sin «hosts»: el barrido no ha corrido
        with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True):
            self.assertEqual(SnmpCollector().collect(ctx), [])

        self.assertTrue(any("barrido no ha corrido" in line for line in ctx["errors"]))


class LinkTests(unittest.TestCase):
    """Link findings from LLDP neighbours and the forwarding table."""

    SWITCH = {
        "name": "sw-planta-1",
        "description": "Cisco IOS Software",
        "object_id": "1.3.6.1.4.1.9.1.3245",
        "interfaces": [
            {"index": "1", "name": "Gi1/0/1", "mac": "aa:bb:cc:00:00:01", "status": "up", "speed_mbps": "1000"},
            {"index": "2", "name": "Gi1/0/2", "mac": "", "status": "up", "speed_mbps": "1000"},
        ],
        "addresses": {"192.168.1.2": "1"},
        "neighbors": [
            {"protocol": "lldp", "local_port": "Gi1/0/2", "remote_mac": "aa:bb:cc:00:00:09",
             "remote_port": "Gi0/1", "remote_name": "sw-nave"},
        ],
        "fdb": [
            {"mac": "aa:bb:cc:dd:ee:10", "ifindex": "1"},   # host conocido
            {"mac": "aa:bb:cc:dd:ee:99", "ifindex": "2"},   # desconocida: se ignora
            {"mac": "aa:bb:cc:00:00:01", "ifindex": "1"},   # la propia del switch: se ignora
        ],
    }

    def _collect(self):
        ctx = {
            "config": {"communities": ["public"]},
            "env": None,
            "hosts": [
                {"ip": "192.168.1.2", "mac": "aa:bb:cc:00:00:01"},
                {"ip": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:10"},
            ],
        }
        with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True), \
             mock.patch("agent.collectors.snmp.snmp.query_hosts",
                        return_value={"192.168.1.2": self.SWITCH}):
            return SnmpCollector().collect(ctx)

    def test_lldp_neighbours_become_link_findings(self) -> None:
        links = [f for f in self._collect() if f.kind == "link" and f.payload["protocol"] == "lldp"]

        self.assertEqual(len(links), 1)
        link = links[0]
        self.assertEqual(link.payload["local"]["port"], "Gi1/0/2")
        self.assertEqual(link.payload["remote"]["device_name"], "sw-nave")
        self.assertEqual(link.payload["remote"]["port"], "Gi0/1")

    def test_the_fdb_only_proposes_links_for_known_macs(self) -> None:
        links = [f for f in self._collect() if f.kind == "link" and f.payload["protocol"] == "fdb"]

        self.assertEqual(len(links), 1)
        link = links[0]
        self.assertEqual(link.payload["local"]["port"], "Gi1/0/1")
        self.assertEqual(link.payload["remote"]["device_ip"], "192.168.1.10")
        self.assertEqual(link.payload["remote"]["port"], "")

    def test_snmp_index_suffixes(self) -> None:
        from agent.snmp import fdb_mac_from_suffix, lldp_local_port_from_suffix

        self.assertEqual(fdb_mac_from_suffix("1.170.187.204.0.0.16"), "aa:bb:cc:00:00:10")
        self.assertEqual(fdb_mac_from_suffix("sin-formato"), "")
        self.assertEqual(lldp_local_port_from_suffix("1569366927.5.1"), "5")
        self.assertEqual(lldp_local_port_from_suffix("mal"), "")


class AuthDataTests(unittest.TestCase):
    """De la credencial al objeto de pysnmp: el nivel de seguridad lo dicen las
    contraseñas presentes, nunca un interruptor aparte.

    Saltados donde no hay pysnmp (el entorno de desarrollo en Windows); corren
    en la imagen Docker del agente, que sí lo trae.
    """

    def _credential(self, **fields) -> object:
        from agent import credentials as creds

        return creds._one({"kind": "snmpv3", "username": "lector", **fields})

    def setUp(self) -> None:
        from agent import snmp

        if not snmp.AVAILABLE:
            self.skipTest("sin pysnmp instalado")
        self.snmp = snmp

    def test_a_plain_string_is_still_a_v2c_community(self) -> None:
        self.assertEqual(type(self.snmp._auth_data("publica")).__name__, "CommunityData")

    def test_the_security_level_follows_the_passwords(self) -> None:
        self.assertEqual(self._level(), "noAuthNoPriv")
        self.assertEqual(self._level(secret="a" * 8), "authNoPriv")
        self.assertEqual(self._level(secret="a" * 8, priv_secret="p" * 8), "authPriv")

    def test_an_unknown_protocol_falls_back_instead_of_failing_the_host(self) -> None:
        data = self.snmp._auth_data(self._credential(secret="a" * 8, auth_protocol="sha512"))

        # SHA-1, el conservador: 1.3.6.1.6.3.10.1.1.3.
        self.assertEqual(tuple(data.authentication_protocol)[-1], 3)

    def _level(self, **fields) -> str:
        return str(self.snmp._auth_data(self._credential(**fields)).security_level)


class RunOrderTests(unittest.TestCase):
    """Quién corre antes que quién, que resultó no ser un detalle.

    El barrido llena `ctx["hosts"]` y SNMP solo llama a las puertas que
    contestaron. Con SNMP delante, encontraba la lista vacía y devolvía nada:
    el hito de SNMP y el de enlaces quedaron inertes por el orden en que estaba
    escrita una línea de importación.
    """

    def test_the_sweep_runs_before_snmp(self) -> None:
        order = [collector.name for collector in all_collectors()]

        self.assertLess(order.index("sweep"), order.index("snmp"))

    def test_the_sweep_runs_before_everyone_who_needs_its_hosts(self) -> None:
        """SSH y WinRM llaman a las puertas que contestaron, igual que SNMP.

        Con ellos delante del barrido encontrarían la lista vacía y no dirían
        nada: el mismo fallo mudo, multiplicado por tres.
        """
        order = [collector.name for collector in all_collectors()]

        for name in ("snmp", "ssh", "winrm"):
            self.assertLess(order.index("sweep"), order.index(name), name)

    def test_the_order_is_the_declared_one(self) -> None:
        self.assertEqual([collector.name for collector in all_collectors()], list(RUN_ORDER))

    def test_every_registered_collector_comes_out(self) -> None:
        """Nadie se queda fuera por no estar nombrado en `RUN_ORDER`."""
        names = {collector.name for collector in all_collectors()}

        self.assertEqual(names, {"local", "sweep", "snmp", "ssh", "winrm", "hypervisors"})


class SubnetExpansionTests(unittest.TestCase):
    """Lo que se acota, se acota antes de construirlo.

    Materializar la red entera para quedarse con las primeras mil no era una
    ineficiencia: una /12 son más de un millón de direcciones y un giga de
    memoria en la máquina del cliente, y la /64 de IPv6 no termina nunca.
    """

    def test_a_normal_subnet_comes_out_whole(self) -> None:
        self.assertEqual(len(net.expand_subnets(["192.168.1.0/24"])), 254)

    def test_a_huge_subnet_is_capped_without_building_it(self) -> None:
        started = time.monotonic()
        found = net.expand_subnets(["10.0.0.0/8"])
        elapsed = time.monotonic() - started

        self.assertEqual(len(found), net.MAX_SWEEP_HOSTS)
        # Construirla entera son dieciséis millones de cadenas y medio minuto.
        self.assertLess(elapsed, 1.0)

    def test_ipv6_is_left_alone_instead_of_hanging(self) -> None:
        """`hosts()` de una /64 es un generador de 1,8·10¹⁹ elementos."""
        self.assertEqual(net.expand_subnets(["2001:db8::/64"]), [])

    def test_rubbish_is_skipped_and_the_rest_survives(self) -> None:
        found = net.expand_subnets(["no-es-una-red", "192.168.5.0/30"])

        self.assertEqual(found, ["192.168.5.1", "192.168.5.2"])


class ArpDecodingTests(unittest.TestCase):
    def test_output_the_console_cannot_decode_does_not_kill_the_sweep(self) -> None:
        """En un Windows en español `arp -a` llega en otra página de códigos.

        Decodificar en estricto lanzaba `UnicodeDecodeError`, que no es de los
        que se capturan, y se llevaba por delante el barrido entero.
        """
        captured = {}

        def fake_run(*args, **kwargs):
            captured.update(kwargs)
            return subprocess.CompletedProcess(args, 0, stdout=ARP_WINDOWS_ES, stderr="")

        with mock.patch("agent.net.subprocess.run", fake_run):
            table = net.arp_table()

        self.assertEqual(captured.get("errors"), "replace")
        self.assertEqual(table["192.168.1.1"], "aa:bb:cc:dd:ee:01")


if __name__ == "__main__":
    unittest.main()


class StackMembersSnmpTests(unittest.TestCase):
    """ENTITY-MIB: two or more chassis are a stack and go as `members`; one
    chassis, or a device that does not answer, is a host without the key."""

    @staticmethod
    def _fake_walk(tables: dict[str, dict[str, str]], calls: list[str] | None = None, fail: bool = False):
        async def walk(engine, host, auth, oid, context_name=""):  # noqa: ANN001 - mirrors snmp._walk
            if calls is not None:
                calls.append(oid)
            if fail and oid.startswith("1.3.6.1.2.1.47."):
                raise RuntimeError("noSuchObject")
            return dict(tables.get(oid, {}))

        return walk

    @staticmethod
    def _tables(entity: dict) -> dict[str, dict[str, str]]:
        from agent import snmp

        return {
            snmp.ENTITY_CLASS_OID: entity["classes"],
            snmp.ENTITY_POSITION_OID: entity["positions"],
            snmp.ENTITY_SERIAL_OID: entity["serials"],
            snmp.ENTITY_MODEL_OID: entity["models"],
        }

    def test_two_chassis_become_members(self) -> None:
        import asyncio

        from agent import snmp
        from agent.tests.test_stacks import ENTITY_TWO_CHASSIS

        with mock.patch("agent.snmp._walk", self._fake_walk(self._tables(ENTITY_TWO_CHASSIS))):
            members = asyncio.run(snmp._query_members(None, "192.168.1.2", "public"))

        self.assertEqual([(m["unit"], m["serial"]) for m in members], [(1, "FOC2231X0AA"), (2, "FOC2231X0BB")])

    def test_one_chassis_asks_only_the_class_column(self) -> None:
        import asyncio

        from agent import snmp
        from agent.tests.test_stacks import ENTITY_ONE_CHASSIS

        calls: list[str] = []
        with mock.patch("agent.snmp._walk", self._fake_walk(self._tables(ENTITY_ONE_CHASSIS), calls)):
            members = asyncio.run(snmp._query_members(None, "192.168.1.2", "public"))

        self.assertEqual(members, [])
        self.assertEqual(calls, [snmp.ENTITY_CLASS_OID])

    def test_a_device_without_entity_mib_is_still_inventoried(self) -> None:
        import asyncio

        from agent import snmp

        async def no_get(*args, **kwargs):  # noqa: ANN002,ANN003
            return None

        with mock.patch("agent.snmp._walk", self._fake_walk({}, fail=True)), \
             mock.patch("agent.snmp._get", no_get):
            data = asyncio.run(snmp._inventory(None, "192.168.1.2", "public", {"name": "sw"}))

        self.assertEqual(data["members"], [])
        self.assertEqual(data["name"], "sw")

    def test_the_host_finding_carries_members_only_for_a_stack(self) -> None:
        members = [
            {"unit": 1, "serial": "FOC2231X0AA", "model": "C9300-48P", "role": ""},
            {"unit": 2, "serial": "FOC2231X0BB", "model": "C9300-24T", "role": ""},
        ]
        for answer, expected in (
            ({**SnmpCollectorTests.SNMP_ANSWER, "members": members}, members),
            ({**SnmpCollectorTests.SNMP_ANSWER, "members": []}, None),
            (SnmpCollectorTests.SNMP_ANSWER, None),
        ):
            ctx = {"config": {"communities": ["public"]}, "env": None, "hosts": [{"ip": "192.168.1.2", "mac": ""}]}
            with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True), \
                 mock.patch("agent.collectors.snmp.snmp.query_hosts", return_value={"192.168.1.2": answer}):
                payload = SnmpCollector().collect(ctx)[0].payload
            self.assertEqual(payload.get("members"), expected)
            if expected is None:
                self.assertNotIn("members", payload)
