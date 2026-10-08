"""La IP de gestión que anuncia un vecino (LLDP lldpRemManAddr, CDP
cdpCacheAddress): viaja en la carga del enlace para que el servidor tenga a
quién sondear, y nunca en la huella, que no puede cambiar por leerla."""

from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from agent import snmp
from agent.collectors.snmp import SnmpCollector, _link


class _Octets:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def asOctets(self) -> bytes:  # noqa: N802 - mirrors pysnmp
        return self.raw

    def prettyPrint(self) -> str:  # noqa: N802 - mirrors pysnmp
        return self.raw.hex()


class SuffixTests(unittest.TestCase):
    def test_an_ipv4_management_address_inside_the_index(self) -> None:
        # timeMark 0, local port 5, remote index 1, subtype 1 (IPv4), 4 octets
        self.assertEqual(snmp.lldp_man_addr_from_suffix("0.5.1.1.4.10.0.0.254"), ("0.5.1", "10.0.0.254"))

    def test_an_ipv6_management_address(self) -> None:
        suffix = "0.5.1.2.16." + ".".join(["254", "128"] + ["0"] * 13 + ["1"])
        self.assertEqual(snmp.lldp_man_addr_from_suffix(suffix), ("0.5.1", "fe80::1"))

    def test_a_mac_or_a_short_index_is_nothing(self) -> None:
        self.assertEqual(snmp.lldp_man_addr_from_suffix("0.5.1.6.6.0.17.34.51.68.85"), ("", ""))
        self.assertEqual(snmp.lldp_man_addr_from_suffix("0.5.1.1.4.10.0.0"), ("", ""))
        self.assertEqual(snmp.lldp_man_addr_from_suffix("mal"), ("", ""))

    def test_cdp_addresses_come_as_raw_octets(self) -> None:
        self.assertEqual(snmp._ip_from_value(_Octets(b"\x0a\x00\x00\xfe")), "10.0.0.254")
        self.assertEqual(snmp._ip_from_value(_Octets(b"\x01\x02")), "")
        self.assertEqual(snmp._ip_from_value("192.168.1.1"), "192.168.1.1")
        self.assertEqual(snmp._ip_from_value("basura"), "")
        self.assertEqual(snmp._ip_from_value(object()), "")


class NeighborQueryTests(unittest.TestCase):
    def _neighbors(self, tables: dict) -> list[dict]:
        async def walk(engine, host, auth, oid, context_name=""):  # noqa: ANN001
            return dict(tables.get(oid, {}))

        with mock.patch("agent.snmp._walk", walk):
            return asyncio.run(snmp._query_neighbors(None, "10.0.0.1", "public"))

    def test_the_lldp_neighbour_carries_its_management_ip(self) -> None:
        tables = {
            snmp.LLDP_LOCAL_PORT_OID: {"5": "Gi1/0/5"},
            snmp.LLDP_REM_CHASSIS_OID: {"0.5.1": "aa:bb:cc:00:00:09"},
            snmp.LLDP_REM_PORT_OID: {"0.5.1": "Gi0/1"},
            snmp.LLDP_REM_NAME_OID: {"0.5.1": "sw-nave"},
            snmp.LLDP_REM_MAN_ADDR_OID: {
                "0.5.1.2.16." + ".".join(["254", "128"] + ["0"] * 13 + ["1"]): "1",
                "0.5.1.1.4.10.0.0.254": "1",
            },
        }
        neighbors = self._neighbors(tables)
        self.assertEqual(len(neighbors), 1)
        # IPv4 wins over IPv6 whatever the order the table came in.
        self.assertEqual(neighbors[0]["remote_ip"], "10.0.0.254")

    def test_a_neighbour_without_management_address_has_none(self) -> None:
        tables = {
            snmp.LLDP_LOCAL_PORT_OID: {"5": "Gi1/0/5"},
            snmp.LLDP_REM_NAME_OID: {"0.5.1": "phone"},
            snmp.LLDP_REM_PORT_OID: {"0.5.1": "1"},
        }
        self.assertEqual(self._neighbors(tables)[0]["remote_ip"], "")

    def test_the_cdp_neighbour_carries_its_ip(self) -> None:
        tables = {
            snmp.CDP_DEVICE_OID: {"3.1": "sw-core.local"},
            snmp.CDP_PORT_OID: {"3.1": "GigabitEthernet0/1"},
            snmp.CDP_IFINDEX_OID: {"3.1": "3"},
            snmp.IF_OIDS["name"]: {"3": "Gi1/0/3"},
            snmp.CDP_ADDRESS_TYPE_OID: {"3.1": "1"},
            snmp.CDP_ADDRESS_OID: {"3.1": _Octets(b"\xc0\xa8\x01\x01")},
        }
        neighbors = self._neighbors(tables)
        self.assertEqual(neighbors[0]["protocol"], "cdp")
        self.assertEqual(neighbors[0]["remote_ip"], "192.168.1.1")

    def test_a_cdp_address_that_is_not_ip_is_ignored(self) -> None:
        tables = {
            snmp.CDP_DEVICE_OID: {"3.1": "old"},
            snmp.CDP_PORT_OID: {"3.1": "1"},
            snmp.CDP_IFINDEX_OID: {"3.1": "3"},
            snmp.IF_OIDS["name"]: {"3": "Gi1/0/3"},
            snmp.CDP_ADDRESS_TYPE_OID: {"3.1": "2"},  # CLNS
            snmp.CDP_ADDRESS_OID: {"3.1": _Octets(b"\x01\x02\x03\x04")},
        }
        self.assertEqual(self._neighbors(tables)[0]["remote_ip"], "")


class LinkFindingTests(unittest.TestCase):
    SWITCH = {
        "name": "sw-planta-1",
        "description": "x",
        "object_id": "",
        "interfaces": [{"index": "1", "name": "Gi1/0/1", "mac": "aa:bb:cc:00:00:01", "status": "up", "speed_mbps": "1000"}],
        "addresses": {"192.168.1.2": "1"},
        "neighbors": [
            {"protocol": "lldp", "local_port": "Gi1/0/1", "remote_mac": "aa:bb:cc:00:00:09",
             "remote_port": "Gi0/1", "remote_name": "sw-nave", "remote_ip": "10.0.0.254"},
        ],
    }

    def _links(self):
        ctx = {"config": {"communities": ["public"]}, "env": None, "hosts": [{"ip": "192.168.1.2", "mac": ""}]}
        with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True), \
             mock.patch("agent.collectors.snmp.snmp.query_hosts", return_value={"192.168.1.2": self.SWITCH}):
            return [f for f in SnmpCollector().collect(ctx) if f.kind == "link"]

    def test_the_ip_goes_in_the_payload_and_not_in_the_identity(self) -> None:
        link = self._links()[0]
        self.assertEqual(link.payload["remote"]["device_ip"], "10.0.0.254")
        self.assertEqual(link.identity["remote"]["device_ip"], "")
        # Everything else in the identity is what it always was.
        self.assertEqual(link.identity["remote"]["device_mac"], "aa:bb:cc:00:00:09")
        self.assertEqual(link.identity["remote"]["port"], "Gi0/1")

    def test_a_neighbour_from_an_older_shape_has_no_remote_ip_key(self) -> None:
        """An answer whose neighbours carry no `remote_ip` (a test double,
        an older inventory) produces the same link as before."""
        local = {"device_mac": "", "device_name": "a", "device_ip": "1.1.1.1", "port": "1"}
        remote = {"device_mac": "", "device_name": "b", "device_ip": "", "port": "2"}
        self.assertEqual(_link("lldp", local, remote).payload["remote"], remote)

    def test_an_fdb_remote_keeps_its_own_ip(self) -> None:
        local = {"device_mac": "", "device_name": "a", "device_ip": "1.1.1.1", "port": "1"}
        remote = {"device_mac": "m", "device_name": "b", "device_ip": "2.2.2.2", "port": ""}
        self.assertEqual(_link("fdb", local, remote, remote_ip="9.9.9.9").payload["remote"]["device_ip"], "2.2.2.2")


if __name__ == "__main__":
    unittest.main()
