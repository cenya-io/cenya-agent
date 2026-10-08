"""Raw sysObjectID/sysDescr on the host finding and what a neighbour announces
about itself (LLDP description, capabilities, LLDP-MED inventory, CDP platform)
on the link finding. All of it is additive: absent when the device said
nothing, so an older server and an older answer shape see the same payloads."""

from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from agent import snmp
from agent.collectors.snmp import SYS_DESCR_MAX, SnmpCollector


class _Octets:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def asOctets(self) -> bytes:  # noqa: N802 - mirrors pysnmp
        return self.raw

    def prettyPrint(self) -> str:  # noqa: N802 - mirrors pysnmp
        return self.raw.hex()


def _collect(answer: dict) -> list:
    ctx = {"config": {"communities": ["public"]}, "env": None, "hosts": [{"ip": "192.168.1.2", "mac": ""}]}
    with mock.patch("agent.collectors.snmp.snmp.AVAILABLE", True), \
         mock.patch("agent.collectors.snmp.snmp.query_hosts", return_value={"192.168.1.2": answer}):
        return SnmpCollector().collect(ctx)


def _answer(**extra) -> dict:
    return {
        "name": "sw",
        "description": "Cisco IOS Software, C1000",
        "object_id": "1.3.6.1.4.1.9.1.2504",
        "interfaces": [{"index": "1", "name": "Gi1/0/1", "mac": "aa:bb:cc:00:00:01", "status": "up", "speed_mbps": "1000"}],
        "addresses": {"192.168.1.2": "1"},
        **extra,
    }


class RawSystemTests(unittest.TestCase):
    def test_host_payload_carries_raw_sys_object_id_and_descr(self) -> None:
        host = next(f for f in _collect(_answer()) if f.kind == "host")
        self.assertEqual(host.payload["sys_object_id"], "1.3.6.1.4.1.9.1.2504")
        self.assertEqual(host.payload["sys_descr"], "Cisco IOS Software, C1000")

    def test_sys_descr_is_cut_to_512(self) -> None:
        host = next(f for f in _collect(_answer(description="x" * 2000)) if f.kind == "host")
        self.assertEqual(len(host.payload["sys_descr"]), SYS_DESCR_MAX)

    def test_a_device_that_said_nothing_adds_no_keys(self) -> None:
        host = next(f for f in _collect(_answer(description="", object_id="")) if f.kind == "host")
        self.assertNotIn("sys_object_id", host.payload)
        self.assertNotIn("sys_descr", host.payload)


class NeighborDetailTests(unittest.TestCase):
    def _neighbors(self, tables: dict) -> list[dict]:
        async def walk(engine, host, auth, oid, context_name=""):  # noqa: ANN001
            return dict(tables.get(oid, {}))

        with mock.patch("agent.snmp._walk", walk):
            return asyncio.run(snmp._query_neighbors(None, "10.0.0.1", "public"))

    BASE = {
        snmp.LLDP_LOCAL_PORT_OID: {"5": "Gi1/0/5"},
        snmp.LLDP_REM_PORT_OID: {"0.5.1": "1"},
        snmp.LLDP_REM_NAME_OID: {"0.5.1": "phone-1"},
    }

    def test_lldp_med_inventory_reaches_the_neighbour(self) -> None:
        tables = {
            **self.BASE,
            snmp.LLDP_REM_SYS_DESC_OID: {"0.5.1": "Acme IP Phone 8800"},
            snmp.LLDP_REM_CAPS_ENABLED_OID: {"0.5.1": _Octets(b"\x24")},
            snmp.LLDP_MED_REM_MODEL_OID: {"0.5.1": "CP-8851"},
            snmp.LLDP_MED_REM_SERIAL_OID: {"0.5.1": "FCH1234ABCD"},
            snmp.LLDP_MED_REM_MFG_OID: {"0.5.1": "Acme"},
        }
        neighbor = self._neighbors(tables)[0]
        self.assertEqual(neighbor["remote_sys_descr"], "Acme IP Phone 8800")
        self.assertEqual(neighbor["remote_capabilities"], ["bridge", "telephone"])
        self.assertEqual(neighbor["remote_model"], "CP-8851")
        self.assertEqual(neighbor["remote_serial"], "FCH1234ABCD")
        self.assertEqual(neighbor["remote_manufacturer"], "Acme")

    def test_a_neighbour_that_announced_nothing_adds_no_keys(self) -> None:
        neighbor = self._neighbors(dict(self.BASE))[0]
        for key in ("remote_sys_descr", "remote_capabilities", "remote_model",
                    "remote_serial", "remote_manufacturer", "remote_platform"):
            self.assertNotIn(key, neighbor)

    def test_a_failing_optional_table_is_not_an_error(self) -> None:
        async def walk(engine, host, auth, oid, context_name=""):  # noqa: ANN001
            if oid in (snmp.LLDP_REM_SYS_DESC_OID, snmp.LLDP_MED_REM_SERIAL_OID):
                raise RuntimeError("noSuchObject")
            return dict(self.BASE.get(oid, {}))

        with mock.patch("agent.snmp._walk", walk):
            neighbors = asyncio.run(snmp._query_neighbors(None, "10.0.0.1", "public"))
        self.assertEqual(len(neighbors), 1)
        self.assertNotIn("remote_serial", neighbors[0])

    def test_cdp_platform(self) -> None:
        tables = {
            snmp.CDP_DEVICE_OID: {"3.1": "sw-core"},
            snmp.CDP_PORT_OID: {"3.1": "Gi0/1"},
            snmp.CDP_IFINDEX_OID: {"3.1": "3"},
            snmp.IF_OIDS["name"]: {"3": "Gi1/0/3"},
            snmp.CDP_PLATFORM_OID: {"3.1": "cisco WS-C2960X-24TS-L"},
        }
        self.assertEqual(self._neighbors(tables)[0]["remote_platform"], "cisco WS-C2960X-24TS-L")

    def test_capability_bits(self) -> None:
        self.assertEqual(snmp.lldp_capabilities(_Octets(b"\x80")), ["other"])
        self.assertEqual(snmp.lldp_capabilities(_Octets(b"\x24")), ["bridge", "telephone"])
        self.assertEqual(snmp.lldp_capabilities(_Octets(b"\x28")), ["bridge", "router"])
        self.assertEqual(snmp.lldp_capabilities(_Octets(b"\x01")), ["stationOnly"])
        self.assertEqual(snmp.lldp_capabilities(_Octets(b"\x00")), [])
        self.assertEqual(snmp.lldp_capabilities(_Octets(b"")), [])
        self.assertEqual(snmp.lldp_capabilities(None), [])
        self.assertEqual(snmp.lldp_capabilities(object()), [])


class LinkPayloadTests(unittest.TestCase):
    def _link(self, **neighbor_extra):
        neighbor = {"protocol": "lldp", "local_port": "Gi1/0/1", "remote_mac": "aa:bb:cc:00:00:09",
                    "remote_port": "1", "remote_name": "phone-1", "remote_ip": "", **neighbor_extra}
        return next(f for f in _collect(_answer(neighbors=[neighbor])) if f.kind == "link")

    def test_med_details_reach_the_link_payload_but_not_the_identity(self) -> None:
        link = self._link(remote_model="CP-8851", remote_serial="FCH1", remote_manufacturer="Acme",
                          remote_sys_descr="Acme IP Phone", remote_capabilities=["telephone"])
        self.assertEqual(link.payload["remote_model"], "CP-8851")
        self.assertEqual(link.payload["remote_serial"], "FCH1")
        self.assertEqual(link.payload["remote_manufacturer"], "Acme")
        self.assertEqual(link.payload["remote_sys_descr"], "Acme IP Phone")
        self.assertEqual(link.payload["remote_capabilities"], ["telephone"])
        self.assertNotIn("remote_model", str(link.identity))

    def test_a_neighbour_without_them_has_the_same_payload_as_before(self) -> None:
        link = self._link()
        self.assertEqual(set(link.payload), {"protocol", "local", "remote"})


if __name__ == "__main__":
    unittest.main()
