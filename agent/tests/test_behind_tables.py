"""«Ve detrás», formato 2: lo que el agente lee para que el servidor sepa qué
equipo hay detrás de cada boca (contrato `hito-ve-detras-contrato.md` del
servidor, §6).

* La tabla ARP de **todos** los equipos SNMP: un equipo de otra VLAN, que el
  barrido de esta subred no ve, tiene IP y enlace.
* La VLAN de cada MAC de la tabla, en el payload del enlace y nunca en su
  identidad (la huella no puede cambiar con la versión).
* La tabla antigua (`dot1dTpFdbTable`) cuando la de VLAN viene vacía.
* La tabla completa por boca (`fdb_ports`), con su recuento y 64 MAC como mucho.
"""

from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from agent import snmp
from agent.collectors import snmp as collector
from agent.collectors.snmp import SnmpCollector

SWITCH_MAC = "aa:bb:cc:00:00:01"


def switch(**extra) -> dict:
    return {
        "name": "sw-core",
        "description": "Cisco IOS Software",
        "object_id": "1.3.6.1.4.1.9.1.3245",
        "interfaces": [
            {"index": "1", "name": "Gi1/0/1", "mac": SWITCH_MAC, "status": "up", "speed_mbps": "1000"},
            {"index": "2", "name": "Gi1/0/2", "mac": "", "status": "up", "speed_mbps": "1000"},
            {"index": "24", "name": "Gi1/0/24", "mac": "", "status": "up", "speed_mbps": "1000"},
        ],
        "addresses": {"192.168.1.2": "1"},
        "neighbors": [],
        "fdb": [],
        "arp": [],
        **extra,
    }


def collect(answers: dict, hosts: list[dict] | None = None):
    ctx = {
        "config": {"communities": ["public"]},
        "env": None,
        "hosts": hosts if hosts is not None else [{"ip": "192.168.1.2", "mac": SWITCH_MAC}],
    }
    with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True), \
         mock.patch("agent.collectors.snmp.snmp.query_hosts", return_value=answers):
        return SnmpCollector().collect(ctx)


def fdb_links(findings) -> list:
    return [f for f in findings if f.kind == "link" and f.payload["protocol"] == "fdb"]


def host_payload(findings, ip: str = "192.168.1.2") -> dict:
    return next(f.payload for f in findings if f.kind == "host" and f.payload["ip"] == ip)


class ArpMakesKnownTests(unittest.TestCase):
    def test_a_device_in_another_vlan_gets_its_ip_from_the_arp_table(self) -> None:
        camera = "00:00:00:00:20:33"
        found = collect(
            {
                "192.168.1.2": switch(
                    fdb=[{"mac": camera, "ifindex": "2", "vlan": "20"}],
                    arp=[{"ip": "10.0.20.33", "mac": camera}],
                )
            }
        )

        (link,) = fdb_links(found)
        self.assertEqual(link.payload["remote"]["device_mac"], camera)
        self.assertEqual(link.payload["remote"]["device_ip"], "10.0.20.33")
        self.assertEqual(link.payload["local"]["port"], "Gi1/0/2")

    def test_what_the_sweep_saw_wins_over_the_arp_table(self) -> None:
        pc = "00:00:00:00:00:10"
        found = collect(
            {
                "192.168.1.2": switch(
                    fdb=[{"mac": pc, "ifindex": "2", "vlan": "1"}],
                    arp=[{"ip": "192.168.1.99", "mac": pc}],
                )
            },
            hosts=[{"ip": "192.168.1.2", "mac": SWITCH_MAC}, {"ip": "192.168.1.10", "mac": pc}],
        )

        (link,) = fdb_links(found)
        self.assertEqual(link.payload["remote"]["device_ip"], "192.168.1.10")

    def test_a_proxy_arp_mac_is_known_but_without_an_ip(self) -> None:
        firewall = "f0:f0:f0:00:00:01"
        found = collect(
            {
                "192.168.1.2": switch(
                    fdb=[{"mac": firewall, "ifindex": "24", "vlan": "1"}],
                    arp=[{"ip": f"192.168.50.{n}", "mac": firewall} for n in range(1, collector.ROUTER_MIN_IPS + 1)],
                )
            }
        )

        (link,) = fdb_links(found)
        self.assertEqual(link.payload["remote"]["device_ip"], "")

    def test_a_mac_nobody_knows_still_proposes_nothing(self) -> None:
        found = collect({"192.168.1.2": switch(fdb=[{"mac": "00:00:00:00:99:99", "ifindex": "2", "vlan": "1"}])})

        self.assertEqual(fdb_links(found), [])


class VlanTests(unittest.TestCase):
    def test_the_vlan_travels_in_the_payload_not_in_the_identity(self) -> None:
        pc = "00:00:00:00:00:10"
        found = collect(
            {"192.168.1.2": switch(fdb=[{"mac": pc, "ifindex": "2", "vlan": "20"}])},
            hosts=[{"ip": "192.168.1.2", "mac": SWITCH_MAC}, {"ip": "192.168.1.10", "mac": pc}],
        )

        (link,) = fdb_links(found)
        self.assertEqual(link.payload["vlan"], 20)
        self.assertNotIn("vlan", link.identity)
        self.assertNotIn("vlan", link.identity["local"])
        self.assertNotIn("vlan", link.identity["remote"])

    def test_the_same_mac_on_the_same_port_in_two_vlans_is_one_link(self) -> None:
        pc = "00:00:00:00:00:10"
        found = collect(
            {
                "192.168.1.2": switch(
                    fdb=[{"mac": pc, "ifindex": "2", "vlan": "10"}, {"mac": pc, "ifindex": "2", "vlan": "20"}]
                )
            },
            hosts=[{"ip": "192.168.1.2", "mac": SWITCH_MAC}, {"ip": "192.168.1.10", "mac": pc}],
        )

        self.assertEqual(len(fdb_links(found)), 1)

    def test_an_entry_without_vlan_has_no_vlan_key(self) -> None:
        """Lo que mandaba el agente de antes: el payload sigue igual."""
        pc = "00:00:00:00:00:10"
        found = collect(
            {"192.168.1.2": switch(fdb=[{"mac": pc, "ifindex": "2"}])},
            hosts=[{"ip": "192.168.1.2", "mac": SWITCH_MAC}, {"ip": "192.168.1.10", "mac": pc}],
        )

        (link,) = fdb_links(found)
        self.assertNotIn("vlan", link.payload)


class HostTablesTests(unittest.TestCase):
    def test_the_switch_finding_carries_its_tables(self) -> None:
        macs = [f"02:00:00:00:{n // 256:02x}:{n % 256:02x}" for n in range(100)]
        found = collect(
            {
                "192.168.1.2": switch(
                    fdb=[{"mac": mac, "ifindex": "24", "vlan": "1"} for mac in macs]
                    + [{"mac": "00:00:00:00:00:10", "ifindex": "2", "vlan": "1"}]
                    + [{"mac": "00:00:00:00:00:10", "ifindex": "2", "vlan": "20"}]
                    + [{"mac": "00:00:00:00:00:11", "ifindex": "99", "vlan": "1"}],  # boca sin nombre
                    arp=[{"ip": "10.0.20.33", "mac": "00:00:00:00:20:33"}],
                )
            }
        )

        payload = host_payload(found)
        ports = {entry["port"]: entry for entry in payload["fdb_ports"]}
        self.assertEqual(set(ports), {"Gi1/0/24", "Gi1/0/2"})
        self.assertEqual(ports["Gi1/0/24"]["count"], 100)
        self.assertEqual(len(ports["Gi1/0/24"]["macs"]), collector.MAX_MACS_PER_PORT)
        self.assertEqual(ports["Gi1/0/2"], {"port": "Gi1/0/2", "count": 1, "macs": ["00:00:00:00:00:10"]})
        self.assertEqual(payload["arp"], [{"ip": "10.0.20.33", "mac": "00:00:00:00:20:33"}])

    def test_without_tables_the_finding_is_as_before(self) -> None:
        payload = host_payload(collect({"192.168.1.2": switch()}))

        self.assertNotIn("arp", payload)
        self.assertNotIn("fdb_ports", payload)


class SuffixTests(unittest.TestCase):
    def test_the_vlan_of_a_q_bridge_entry(self) -> None:
        self.assertEqual(snmp.fdb_vlan_from_suffix("20.170.187.204.0.0.16"), "20")
        self.assertEqual(snmp.fdb_vlan_from_suffix("170.187.204.0.0.16"), "")

    def test_the_mac_of_an_old_bridge_entry(self) -> None:
        self.assertEqual(snmp.legacy_fdb_mac_from_suffix("170.187.204.0.0.16"), "aa:bb:cc:00:00:10")
        self.assertEqual(snmp.legacy_fdb_mac_from_suffix("1.170.187.204.0.0.16"), "")
        self.assertEqual(snmp.legacy_fdb_mac_from_suffix("a.b.c.d.e.f"), "")

    def test_the_ip_of_an_arp_entry(self) -> None:
        self.assertEqual(snmp.arp_ip_from_media_suffix("12.10.0.20.33"), "10.0.20.33")
        self.assertEqual(snmp.arp_ip_from_media_suffix("12.10.0.20"), "")
        self.assertEqual(snmp.arp_ip_from_physical_suffix("12.1.4.10.0.20.33"), "10.0.20.33")
        ipv6 = "12.2.16." + ".".join(["254", "128"] + ["0"] * 13 + ["1"])
        self.assertEqual(snmp.arp_ip_from_physical_suffix(ipv6), "fe80::1")
        self.assertEqual(snmp.arp_ip_from_physical_suffix("12.1.5.10.0.20.33"), "")  # longitud que miente
        self.assertEqual(snmp.arp_ip_from_physical_suffix("12.3.4.10.0.20.33"), "")  # tipo desconocido


class QueryTests(unittest.TestCase):
    """Las consultas, con un SNMP de mentira: qué tabla se pide y qué sale."""

    def _run(self, coroutine):
        return asyncio.run(coroutine)

    def test_the_old_table_answers_when_the_vlan_one_is_empty(self) -> None:
        async def fake_walk(engine, host, auth, oid, context_name=""):
            if oid == snmp.FDB_PORT_OID:
                return {}
            if oid == snmp.FDB_LEGACY_PORT_OID:
                return {"170.187.204.0.0.16": "3"}
            if oid == snmp.BRIDGE_PORT_IFINDEX_OID:
                return {"3": "7"}
            return {}

        with mock.patch.object(snmp, "_walk", fake_walk):
            found = self._run(snmp._query_fdb(None, "10.0.0.2", "public", "1.3.6.1.4.1.11"))

        self.assertEqual(found, [{"mac": "aa:bb:cc:00:00:10", "ifindex": "7", "vlan": ""}])

    def test_a_mac_in_two_vlans_is_two_entries(self) -> None:
        async def fake_walk(engine, host, auth, oid, context_name=""):
            if oid == snmp.FDB_PORT_OID:
                return {"10.170.187.204.0.0.16": "3", "20.170.187.204.0.0.16": "4"}
            if oid == snmp.BRIDGE_PORT_IFINDEX_OID:
                return {"3": "7", "4": "8"}
            return {}

        with mock.patch.object(snmp, "_walk", fake_walk):
            found = self._run(snmp._query_fdb(None, "10.0.0.2", "public", "1.3.6.1.4.1.11"))

        self.assertEqual(
            sorted((entry["vlan"], entry["ifindex"]) for entry in found), [("10", "7"), ("20", "8")]
        )

    def test_the_arp_table_falls_back_to_the_old_one(self) -> None:
        asked: list[str] = []

        async def fake_walk(engine, host, auth, oid, context_name=""):
            asked.append(oid)
            if oid == snmp.ARP_MEDIA_OID:
                return {"12.10.0.20.33": "00:00:00:00:20:33", "12.10.0.20.34": "no-es-una-mac"}
            return {}

        with mock.patch.object(snmp, "_walk", fake_walk):
            found = self._run(snmp._query_arp(None, "10.0.0.1", "public"))

        self.assertEqual(asked, [snmp.ARP_PHYSICAL_OID, snmp.ARP_MEDIA_OID])
        self.assertEqual(found, [{"ip": "10.0.20.33", "mac": "00:00:00:00:20:33"}])

    def test_the_arp_table_is_capped(self) -> None:
        async def fake_walk(engine, host, auth, oid, context_name=""):
            if oid == snmp.ARP_PHYSICAL_OID:
                return {
                    f"1.1.4.10.{n // 65536}.{n // 256 % 256}.{n % 256}": f"02:00:00:{n // 65536:02x}:{n // 256 % 256:02x}:{n % 256:02x}"
                    for n in range(snmp.MAX_ARP_ENTRIES + 50)
                }
            return {}

        with mock.patch.object(snmp, "_walk", fake_walk):
            found = self._run(snmp._query_arp(None, "10.0.0.1", "public"))

        self.assertEqual(len(found), snmp.MAX_ARP_ENTRIES)


if __name__ == "__main__":
    unittest.main()
