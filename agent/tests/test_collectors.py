"""The sweep and SNMP collectors, tested without a network: ARP fixtures from
real Windows (EN/ES) and Linux outputs, and a fake SNMP layer."""

from __future__ import annotations

import subprocess
import time
import unittest
from unittest import mock

from agent import net, profiles, snmp
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

        self.assertEqual(names, {"local", "sweep", "fingerprint", "snmp", "ssh", "winrm", "hypervisors"})


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

    def test_the_host_finding_carries_power_supplies_only_when_there_are_any(self) -> None:
        supplies = [{"index": "1000", "name": "PSU1", "description": "", "model": "", "serial": "", "status": "ok"}]
        for answer, expected in (
            ({**SnmpCollectorTests.SNMP_ANSWER, "power_supplies": supplies}, supplies),
            ({**SnmpCollectorTests.SNMP_ANSWER, "power_supplies": []}, None),
            (SnmpCollectorTests.SNMP_ANSWER, None),
        ):
            ctx = {"config": {"communities": ["public"]}, "env": None, "hosts": [{"ip": "192.168.1.2", "mac": ""}]}
            with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True),                  mock.patch("agent.collectors.snmp.snmp.query_hosts", return_value={"192.168.1.2": answer}):
                payload = SnmpCollector().collect(ctx)[0].payload
            self.assertEqual(payload.get("power_supplies"), expected)
            if expected is None:
                self.assertNotIn("power_supplies", payload)

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


class IdentitySnmpTests(unittest.TestCase):
    """What the device is: the vendor profile's OIDs, then ENTITY-MIB, then
    nothing -- and whatever happens, the same inventory as before."""

    from agent.tests.test_profiles import CISCO_DESCR, TABLE

    @staticmethod
    def _fake_get(answers: dict[str, object], calls: list[list[str]] | None = None, fail_on: str = ""):
        """`snmp._get` over a dict {oid: value}; a missing OID answers like a
        real v2c device: a NoSuchObject bind, not an error. `fail_on` makes
        the whole get raise when it asks that OID."""
        from pysnmp.proto.rfc1905 import NoSuchObject

        async def get(engine, host, auth, oids, context_name=""):  # noqa: ANN001 - mirrors snmp._get
            if calls is not None:
                calls.append(list(oids.values()))
            if fail_on and fail_on in oids.values():
                raise RuntimeError("timeout")
            return {name: snmp._text(answers.get(oid, NoSuchObject())) for name, oid in oids.items()}

        return get

    @staticmethod
    def _fake_walk(tables: dict[str, dict[str, str]], calls: list[str] | None = None):
        async def walk(engine, host, auth, oid, context_name=""):  # noqa: ANN001 - mirrors snmp._walk
            if calls is not None:
                calls.append(oid)
            return dict(tables.get(oid, {}))

        return walk

    def _inventory(self, system: dict, get, walk) -> dict:
        import asyncio

        with mock.patch("agent.profiles.PROFILES", self.TABLE), \
             mock.patch("agent.snmp._get", get), \
             mock.patch("agent.snmp._walk", walk):
            return asyncio.run(snmp._inventory(None, "192.168.1.2", "public", system))

    def test_the_profile_oids_are_asked_in_one_get(self) -> None:
        get_calls: list[list[str]] = []
        system = {"name": "rb", "description": "RouterOS CCR1009-7G-1C-1S+", "object_id": "1.3.6.1.4.1.14988.1"}
        get = self._fake_get(
            {"1.3.6.1.4.1.14988.1.1.7.3.0": "ABC123", "1.3.6.1.4.1.14988.1.1.4.4.0": "7.15.3"}, get_calls
        )
        data = self._inventory(system, get, self._fake_walk({}))

        identity = data["identity"]
        self.assertEqual(identity.serial, "ABC123")
        self.assertEqual(identity.os_version, "7.15.3")
        self.assertEqual(identity.model, "CCR1009-7G-1C-1S+")
        self.assertEqual(identity.payload_fields()["os"], "RouterOS 7.15.3")
        profile_gets = [c for c in get_calls if "1.3.6.1.4.1.14988.1.1.7.3.0" in c]
        self.assertEqual(len(profile_gets), 1)
        self.assertEqual(sorted(profile_gets[0]), ["1.3.6.1.4.1.14988.1.1.4.4.0", "1.3.6.1.4.1.14988.1.1.7.3.0"])

    def test_no_such_object_is_empty_not_a_sentence(self) -> None:
        """A v2c get of a missing OID answers with a NoSuchObject bind whose
        text is "No Such Object currently exists at this OID". That must
        never become a serial number."""
        system = {"name": "rb", "description": "RouterOS hAP ac2", "object_id": "1.3.6.1.4.1.14988.1"}
        data = self._inventory(system, self._fake_get({}), self._fake_walk({}))

        self.assertEqual(data["identity"].serial, "")
        self.assertEqual(data["identity"].os_version, "")
        self.assertEqual(
            data["identity"].payload_fields(), {"manufacturer": "MikroTik", "model": "hAP ac2", "os": "RouterOS"}
        )

    def test_entity_mib_fills_what_the_profile_could_not(self) -> None:
        """Cisco IOS: no serial or model OID in the profile, so the chassis
        row of ENTITY-MIB is asked -- one get of its four leaf instances, on
        the index the class column marks as chassis -- and the class column
        is walked once for identity and stack together."""
        from agent.tests.test_stacks import ENTITY_ONE_CHASSIS

        get_calls: list[list[str]] = []
        walk_calls: list[str] = []
        system = {"name": "sw", "description": self.CISCO_DESCR, "object_id": "1.3.6.1.4.1.9.1.3245"}
        get = self._fake_get(
            {
                snmp.ENTITY_MODEL_OID + ".1": "WS-C2960X-48FPD-L",
                snmp.ENTITY_SERIAL_OID + ".1": "FOC2001X0AB",
                snmp.ENTITY_SOFTWARE_OID + ".1": "15.2(7)E8",
                snmp.ENTITY_MFG_OID + ".1": "Cisco Systems, Inc.",
            },
            get_calls,
        )
        walk = self._fake_walk({snmp.ENTITY_CLASS_OID: ENTITY_ONE_CHASSIS["classes"]}, walk_calls)
        data = self._inventory(system, get, walk)

        identity = data["identity"]
        self.assertEqual(identity.model, "WS-C2960X-48FPD-L")
        self.assertEqual(identity.serial, "FOC2001X0AB")
        self.assertEqual(identity.os_version, "15.2(7)E8")  # the sysDescr regex, before ENTITY's
        self.assertEqual(identity.manufacturer, "Cisco")  # the profile's, not entPhysicalMfgName
        self.assertEqual(walk_calls.count(snmp.ENTITY_CLASS_OID), 1)
        self.assertNotIn(snmp.ENTITY_MODEL_OID, walk_calls)
        self.assertNotIn(snmp.ENTITY_SERIAL_OID, walk_calls)
        self.assertEqual(data["members"], [])

    def test_a_profile_without_fallback_never_asks_entity(self) -> None:
        get_calls: list[list[str]] = []
        system = {"name": "sg", "description": "SG350-28", "object_id": "1.3.6.1.4.1.9.6.1.1004"}
        walk = self._fake_walk({snmp.ENTITY_CLASS_OID: {"1": "3"}})
        data = self._inventory(system, self._fake_get({}, get_calls), walk)

        self.assertEqual(data["identity"].profile, "cisco-sb")
        self.assertFalse(any(snmp.ENTITY_MODEL_OID in oid for call in get_calls for oid in call))

    def test_without_a_profile_entity_alone_identifies(self) -> None:
        system = {"name": "x", "description": "Unknown box", "object_id": "1.3.6.1.4.1.99999.1"}
        get = self._fake_get({snmp.ENTITY_MODEL_OID + ".1": "Box-1", snmp.ENTITY_MFG_OID + ".1": "Acme"})
        data = self._inventory(system, get, self._fake_walk({snmp.ENTITY_CLASS_OID: {"1": "3", "2": "10"}}))

        self.assertEqual(data["identity"].payload_fields(), {"manufacturer": "Acme", "model": "Box-1"})
        self.assertEqual(data["identity"].profile, "")

    def test_a_profile_get_that_blows_up_does_not_cost_the_inventory(self) -> None:
        system = {"name": "rb", "description": "RouterOS hAP ac2", "object_id": "1.3.6.1.4.1.14988.1"}
        get = self._fake_get({}, fail_on="1.3.6.1.4.1.14988.1.1.7.3.0")
        data = self._inventory(system, get, self._fake_walk({}))

        self.assertEqual(data["name"], "rb")
        self.assertEqual(data["identity"].manufacturer, "MikroTik")
        self.assertEqual(data["identity"].serial, "")

    def test_the_host_payload_is_unchanged_without_identity(self) -> None:
        """A device nobody recognises -- or an answer without the key -- gives
        exactly the payload it gave before this existed: no empty keys (the raw
        sysObjectID/sysDescr are the only additions, and only because the
        answer carries them)."""
        answers = (
            SnmpCollectorTests.SNMP_ANSWER,
            {**SnmpCollectorTests.SNMP_ANSWER, "identity": profiles.Identity()},
        )
        for answer in answers:
            ctx = {"config": {"communities": ["public"]}, "env": None, "hosts": [{"ip": "192.168.1.2", "mac": ""}]}
            with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True), \
                 mock.patch("agent.collectors.snmp.snmp.query_hosts", return_value={"192.168.1.2": answer}):
                payload = SnmpCollector().collect(ctx)[0].payload
            self.assertEqual(
                sorted(payload),
                [
                    "description", "hostname", "interfaces", "ip", "mac", "management_interface",
                    "seen_by", "sys_descr", "sys_object_id",
                ],
            )

    def test_the_host_payload_carries_the_identity(self) -> None:
        identity = profiles.Identity(
            manufacturer="Cisco", model="C1000-24T-4G-L", serial="FOC2341", os="IOS", os_version="15.2(7)E8", profile="cisco"
        )
        answer = {**SnmpCollectorTests.SNMP_ANSWER, "identity": identity}
        ctx = {"config": {"communities": ["public"]}, "env": None, "hosts": [{"ip": "192.168.1.2", "mac": ""}]}
        with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True), \
             mock.patch("agent.collectors.snmp.snmp.query_hosts", return_value={"192.168.1.2": answer}):
            payload = SnmpCollector().collect(ctx)[0].payload

        self.assertEqual(payload["manufacturer"], "Cisco")
        self.assertEqual(payload["model"], "C1000-24T-4G-L")
        self.assertEqual(payload["serial"], "FOC2341")
        self.assertEqual(payload["os"], "IOS 15.2(7)E8")
        self.assertEqual(payload["os_version"], "15.2(7)E8")
        self.assertNotIn("profile", payload)
        # Nothing that was there has moved.
        self.assertEqual(payload["hostname"], "sw-planta-1")
        self.assertEqual(payload["description"], "Cisco IOS Software, C1000")


class KindIdentitySnmpTests(unittest.TestCase):
    """Model and serial of printers, UPSs and PDUs when ENTITY-MIB gives
    nothing: read-only, tolerant, and only for the kind of device that has them."""

    PRINTER_TYPE = "1.3.6.1.2.1.25.3.1.5"
    OTHER_TYPE = "1.3.6.1.2.1.25.3.1.3"  # hrDeviceProcessor
    RICOH = {"name": "ricoh", "description": "RICOH Network Printer", "object_id": "1.3.6.1.4.1.367.1.1"}

    @staticmethod
    def _inventory(system: dict, answers: dict, tables: dict, get_calls=None, walk_calls=None, broken=()):
        import asyncio

        from agent import profiles_data

        get = IdentitySnmpTests._fake_get(answers, get_calls)
        plain_walk = IdentitySnmpTests._fake_walk(tables, walk_calls)

        async def walk(engine, host, auth, oid, context_name=""):  # noqa: ANN001 - mirrors snmp._walk
            if oid in broken:
                raise RuntimeError("timeout")
            return await plain_walk(engine, host, auth, oid, context_name)

        with mock.patch("agent.profiles.PROFILES", profiles_data.PROFILES), \
             mock.patch("agent.snmp._get", get), \
             mock.patch("agent.snmp._walk", walk):
            return asyncio.run(snmp._inventory(None, "192.168.1.9", "public", system))

    def _printer_tables(self) -> dict:
        return {
            snmp.HR_DEVICE_TYPE_OID: {"1": self.OTHER_TYPE, "2": self.PRINTER_TYPE},
            snmp.PRT_SERIAL_OID: {"2": "VNB3K12345"},
            snmp.PRT_MARKER_UNIT_OID: {"2.1": "8"},
            snmp.PRT_MARKER_LIFE_OID: {"2.1": "48213"},
        }

    def test_a_printer_without_profile_gets_model_serial_and_page_count(self) -> None:
        answers = {f"{snmp.HR_DEVICE_DESCR_OID}.2": "HP LaserJet Pro M404dn"}
        data = self._inventory(self.RICOH, answers, self._printer_tables())

        self.assertEqual(data["identity"].model, "HP LaserJet Pro M404dn")
        self.assertEqual(data["identity"].serial, "VNB3K12345")
        self.assertEqual(data["page_count"], 48213)

    def test_a_counter_that_is_not_in_pages_is_not_a_page_count(self) -> None:
        tables = self._printer_tables()
        tables[snmp.PRT_MARKER_UNIT_OID] = {"2.1": "16"}  # feet
        data = self._inventory(self.RICOH, {}, tables)

        self.assertNotIn("page_count", data)
        self.assertEqual(data["identity"].serial, "VNB3K12345")

    def test_the_profile_wins_and_the_printer_only_fills_the_gaps(self) -> None:
        system = {
            "name": "hp",
            "description": "HP ETHERNET MULTI-ENVIRONMENT,SN:X,PID:HP LaserJet MFP M130nw",
            "object_id": "1.3.6.1.4.1.11.2.3.9.1",
        }
        answers = {f"{snmp.HR_DEVICE_DESCR_OID}.2": "something else"}
        data = self._inventory(system, answers, self._printer_tables())

        self.assertEqual(data["identity"].model, "HP LaserJet MFP M130nw")  # the profile's
        self.assertEqual(data["identity"].serial, "VNB3K12345")  # was empty
        self.assertEqual(data["identity"].manufacturer, "HP")

    def test_a_device_with_no_printer_row_is_left_alone(self) -> None:
        tables = {snmp.HR_DEVICE_TYPE_OID: {"1": self.OTHER_TYPE}}
        walk_calls: list[str] = []
        data = self._inventory(self.RICOH, {}, tables, walk_calls=walk_calls)

        self.assertEqual(data["identity"].serial, "")
        self.assertNotIn("page_count", data)
        self.assertNotIn(snmp.PRT_SERIAL_OID, walk_calls)

    def test_a_switch_with_a_profile_is_never_asked_printer_oids(self) -> None:
        system = {
            "name": "sw",
            "description": "Cisco IOS Software, C1000 Software, Version 15.2(7)E8, RELEASE",
            "object_id": "1.3.6.1.4.1.9.1.3245",
        }
        get_calls: list[list[str]] = []
        walk_calls: list[str] = []
        data = self._inventory(system, {}, {}, get_calls, walk_calls)

        self.assertEqual(data["identity"].manufacturer, "Cisco")
        asked = [oid for call in get_calls for oid in call] + walk_calls
        self.assertFalse([oid for oid in asked if oid.startswith(("1.3.6.1.2.1.25.3.", "1.3.6.1.2.1.43."))])

    def test_printer_oids_that_fail_are_one_key_less_not_an_error(self) -> None:
        broken = (snmp.PRT_SERIAL_OID, snmp.PRT_MARKER_LIFE_OID)
        answers = {f"{snmp.HR_DEVICE_DESCR_OID}.2": "Ricoh SP 330"}
        data = self._inventory(self.RICOH, answers, self._printer_tables(), broken=broken)

        self.assertEqual(data["identity"].model, "Ricoh SP 330")
        self.assertEqual(data["identity"].serial, "")
        self.assertNotIn("page_count", data)
        # And when even the type table fails the device is simply not a printer.
        data = self._inventory(self.RICOH, {}, self._printer_tables(), broken=(snmp.HR_DEVICE_TYPE_OID,))
        self.assertEqual(data["identity"].model, "")

    def test_an_apc_ups_keeps_the_serial_its_profile_read(self) -> None:
        system = {"name": "sai", "description": "APC Web/SNMP Management Card", "object_id": "1.3.6.1.4.1.318.1.3.27"}
        answers = {
            "1.3.6.1.4.1.318.1.1.1.1.1.1.0": "Smart-UPS 1500",
            "1.3.6.1.4.1.318.1.1.1.1.2.3.0": "AS1234567890",
            "1.3.6.1.2.1.33.1.2.3.0": "42",
            "1.3.6.1.2.1.33.1.1.2.0": "SMART-UPS 1500 RM",
        }
        get_calls: list[list[str]] = []
        data = self._inventory(system, answers, {}, get_calls)

        self.assertEqual(data["identity"].model, "Smart-UPS 1500")
        self.assertEqual(data["identity"].serial, "AS1234567890")
        self.assertEqual(data["ups"]["runtime_minutes"], 42)
        # Nothing was asked of a PDU, and the UPS identity rode along with the reading.
        self.assertFalse([c for c in get_calls if "1.3.6.1.4.1.318.1.1.12.1.6.0" in c])
        self.assertTrue(any(snmp.UPS_OIDS["ident_model"] in c for c in get_calls))

    def test_a_generic_ups_mib_device_gets_manufacturer_and_model_without_serial(self) -> None:
        system = {"name": "sai", "description": "UPS card", "object_id": "1.3.6.1.4.1.12345.1"}
        answers = {
            "1.3.6.1.2.1.33.1.1.1.0": "Riello UPS",
            "1.3.6.1.2.1.33.1.1.2.0": "Sentinel Dual SDL 3000",
            "1.3.6.1.2.1.33.1.2.3.0": "30",
        }
        walk_calls: list[str] = []
        data = self._inventory(system, answers, {}, walk_calls=walk_calls)

        self.assertEqual(
            data["identity"].payload_fields(), {"manufacturer": "Riello UPS", "model": "Sentinel Dual SDL 3000"}
        )
        self.assertNotIn(snmp.HR_DEVICE_TYPE_OID, walk_calls)  # a UPS is not asked as a printer

    def test_a_raritan_pdu_gets_model_and_serial(self) -> None:
        system = {"name": "pdu", "description": "Raritan PX3", "object_id": "1.3.6.1.4.1.13742.6"}
        answers = {snmp.RARITAN_PDU_OIDS["model"]: "PX3-5190R", snmp.RARITAN_PDU_OIDS["serial"]: "2EA1234567"}
        data = self._inventory(system, answers, {})

        self.assertEqual(
            data["identity"].payload_fields(),
            {"manufacturer": "Raritan", "model": "PX3-5190R", "serial": "2EA1234567"},
        )

    def test_an_apc_rack_pdu_gets_its_ident_oids(self) -> None:
        system = {
            "name": "pdu",
            "description": "APC Web/SNMP Management Card",
            "object_id": "1.3.6.1.4.1.318.1.3.4.5",
        }
        answers = {snmp.APC_PDU_OIDS["model"]: "AP7921", snmp.APC_PDU_OIDS["serial"]: "ZA0123456789"}
        data = self._inventory(system, answers, {})

        self.assertEqual(data["identity"].model, "AP7921")
        self.assertEqual(data["identity"].serial, "ZA0123456789")
        self.assertEqual(data["identity"].manufacturer, "APC")

    def test_a_pdu_whose_oids_fail_is_still_inventoried(self) -> None:
        system = {"name": "pdu", "description": "Raritan PX3", "object_id": "1.3.6.1.4.1.13742.6"}
        data = self._inventory(system, {}, {})

        self.assertEqual(data["identity"].model, "")
        self.assertEqual(data["identity"].serial, "")

    def test_the_host_payload_carries_page_count_only_when_there_is_one(self) -> None:
        identity = profiles.Identity(manufacturer="HP", model="LaserJet", serial="X1")
        ctx = {"config": {"communities": ["public"]}, "env": None, "hosts": [{"ip": "192.168.1.2", "mac": ""}]}
        for extra, expected in (({"page_count": 120}, 120), ({}, None)):
            answer = {**SnmpCollectorTests.SNMP_ANSWER, "identity": identity, **extra}
            with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True), \
                 mock.patch("agent.collectors.snmp.snmp.query_hosts", return_value={"192.168.1.2": answer}):
                payload = SnmpCollector().collect(ctx)[0].payload
            self.assertEqual(payload.get("page_count"), expected)
