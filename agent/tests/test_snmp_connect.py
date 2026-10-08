"""Cómo llama el agente a la puerta de un equipo por SNMP (fase 2 del plan
Netdisco): pasada rápida y pasada lenta, qué cuenta como sesión, y lo que
trae de cada interfaz (tipo, estado administrativo, agregado)."""

from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from agent import snmp
from agent.collectors import tasking
from agent.collectors.snmp import _interface_payload


class _Device:
    """Un equipo simulado detrás de `snmp._get`: contesta a una comunidad,
    y solo si la llamada es paciente cuando `slow_only`."""

    def __init__(self, community: str = "ok", slow_only: bool = False, blank: bool = False) -> None:
        self.community = community
        self.slow_only = slow_only
        self.blank = blank
        self.calls: list[tuple[str, bool]] = []  # (auth, fast)

    def get(self):
        async def _get(engine, host, auth, oids, context_name="", fast=False):  # noqa: ANN001
            if oids is snmp.SYSTEM_OIDS:
                self.calls.append((auth, fast))
                if auth != self.community or (self.slow_only and fast):
                    raise RuntimeError("timeout")
                if self.blank:
                    return {name: "" for name in oids}
                return {"description": "RouterOS hAP", "object_id": "1.3.6.1.4.1.14988.1", "uptime": "1234", "name": "r"}
            return {name: "" for name in oids}

        return _get


async def _empty_walk(engine, host, auth, oid, context_name=""):  # noqa: ANN001
    return {}


def _query(device: _Device, auths: list, slow: bool = True):
    with mock.patch("agent.snmp._get", device.get()), \
         mock.patch("agent.snmp._walk", _empty_walk), \
         mock.patch("agent.snmp.SnmpEngine", lambda: None):
        return asyncio.run(snmp._query_host_indexed("10.0.0.1", auths, slow=slow))


class KnockTests(unittest.TestCase):
    def test_fast_pass_over_every_auth_before_any_slow_call(self) -> None:
        """Netdisco: todas las credenciales deprisa, y solo después, despacio."""
        device = _Device(community="tercera", slow_only=True)
        found = _query(device, ["primera", "segunda", "tercera"])

        self.assertIsNotNone(found)
        self.assertEqual(found[0], 2)
        fast_then_slow = [fast for _auth, fast in device.calls]
        self.assertEqual(fast_then_slow, [True, True, True, False, False, False])

    def test_a_device_that_answers_fast_never_waits(self) -> None:
        device = _Device(community="ok")
        found = _query(device, ["mala", "ok"])

        self.assertEqual(found[0], 1)
        self.assertEqual(device.calls, [("mala", True), ("ok", True)])

    def test_a_known_device_gets_the_fast_pass_only(self) -> None:
        """El que contestó ayer en milisegundos y hoy calla está apagado:
        seis segundos más por credencial no lo despiertan."""
        device = _Device(community="ok", slow_only=True)
        self.assertIsNone(_query(device, ["ok"], slow=False))
        self.assertEqual(device.calls, [("ok", True)])

    def test_nobody_answers_in_either_pass(self) -> None:
        device = _Device(community="otra")
        self.assertIsNone(_query(device, ["ok"]))
        self.assertEqual(device.calls, [("ok", True), ("ok", False)])


class SessionTests(unittest.TestCase):
    def test_a_session_needs_a_description_or_an_uptime(self) -> None:
        self.assertTrue(snmp._answered({"description": "x", "uptime": ""}))
        self.assertTrue(snmp._answered({"description": "", "uptime": "99"}))
        self.assertFalse(snmp._answered({"description": "", "uptime": "", "name": "sw"}))
        self.assertFalse(snmp._answered(None))
        self.assertFalse(snmp._answered({}))

    def test_four_empty_binds_are_not_a_device(self) -> None:
        """Un proxy o un agente roto que contesta sin decir nada no se
        inventaría, y su comunidad no se recuerda como la buena."""
        device = _Device(community="ok", blank=True)
        self.assertIsNone(_query(device, ["ok"]))


class InterfaceColumnsTests(unittest.TestCase):
    TABLES = {
        snmp.IF_OIDS["name"]: {"1": "Gi1/0/1", "2": "Gi1/0/2", "3": "Po1", "4": "Vlan10", "5": "Lo0"},
        snmp.IF_OIDS["type"]: {"1": "6", "2": "6", "3": "161", "4": "53", "5": "24"},
        snmp.IF_OIDS["admin"]: {"1": "1", "2": "2", "3": "1", "4": "1"},
        snmp.IF_OIDS["status"]: {"1": "1", "2": "2", "3": "1", "4": "1", "5": "1"},
        snmp.LAG_MEMBER_OID: {"1": "3", "2": "3", "3": "0", "4": "0"},
    }

    def _inventory(self, tables: dict) -> list[dict]:
        async def walk(engine, host, auth, oid, context_name=""):  # noqa: ANN001
            return dict(tables.get(oid, {}))

        async def get(engine, host, auth, oids, context_name="", fast=False):  # noqa: ANN001
            return {name: "" for name in oids}

        system = {"name": "sw", "description": "x", "object_id": "", "uptime": "1"}
        with mock.patch("agent.snmp._get", get), mock.patch("agent.snmp._walk", walk):
            return asyncio.run(snmp._inventory(None, "10.0.0.1", "public", system))["interfaces"]

    def test_type_admin_and_aggregator_come_with_each_interface(self) -> None:
        by_name = {iface["name"]: iface for iface in self._inventory(self.TABLES)}

        self.assertEqual(by_name["Gi1/0/1"]["type"], "ethernet")
        self.assertEqual(by_name["Po1"]["type"], "lag")
        self.assertEqual(by_name["Vlan10"]["type"], "virtual")
        self.assertEqual(by_name["Lo0"]["type"], "loopback")
        self.assertEqual(by_name["Gi1/0/2"]["admin"], "down")
        self.assertEqual(by_name["Lo0"]["admin"], "unknown")
        # Members point at their aggregator by name; the aggregator itself
        # and the ports in none carry nothing.
        self.assertEqual(by_name["Gi1/0/1"]["lag"], "Po1")
        self.assertEqual(by_name["Gi1/0/2"]["lag"], "Po1")
        self.assertEqual(by_name["Po1"]["lag"], "")
        self.assertEqual(by_name["Vlan10"]["lag"], "")

    def test_a_port_that_points_at_itself_is_in_no_lag(self) -> None:
        tables = {**self.TABLES, snmp.LAG_MEMBER_OID: {"1": "1", "2": "0"}}
        by_name = {iface["name"]: iface for iface in self._inventory(tables)}
        self.assertEqual(by_name["Gi1/0/1"]["lag"], "")

    def test_without_the_ieee_mib_nothing_breaks(self) -> None:
        tables = {key: value for key, value in self.TABLES.items() if key != snmp.LAG_MEMBER_OID}
        self.assertTrue(all(iface["lag"] == "" for iface in self._inventory(tables)))

    def test_an_unknown_iftype_is_other(self) -> None:
        tables = {**self.TABLES, snmp.IF_OIDS["type"]: {"1": "999"}}
        by_name = {iface["name"]: iface for iface in self._inventory(tables)}
        self.assertEqual(by_name["Gi1/0/1"]["type"], "other")

    def test_the_payload_carries_the_new_keys_only_when_present(self) -> None:
        old_shape = {"name": "Gi1", "mac": "", "status": "up", "speed_mbps": "1000"}
        self.assertEqual(_interface_payload(old_shape), old_shape)
        full = {**old_shape, "type": "ethernet", "admin": "up", "lag": "Po1"}
        self.assertEqual(_interface_payload(full), full)
        member_of_none = {**old_shape, "type": "ethernet", "admin": "up", "lag": ""}
        self.assertNotIn("lag", _interface_payload(member_of_none))


class KnownHostsTests(unittest.TestCase):
    def test_answered_before_reads_the_memory(self) -> None:
        memory = mock.Mock()
        memory.key_for.return_value = "aa:bb"
        memory.remembered.return_value = "cred-1"
        self.assertTrue(tasking.answered_before({"memory": memory}, "10.0.0.1", "aa:bb", "snmp"))
        memory.remembered.assert_called_with("aa:bb", "snmp")
        memory.remembered.return_value = ""
        self.assertFalse(tasking.answered_before({"memory": memory}, "10.0.0.1", "aa:bb", "snmp"))

    def test_without_memory_nobody_is_known(self) -> None:
        self.assertFalse(tasking.answered_before({}, "10.0.0.1", "", "snmp"))

    def test_query_plan_marks_known_hosts_as_fast_only(self) -> None:
        seen: dict[str, bool] = {}

        async def fake(host, auths, slow=True):  # noqa: ANN001
            seen[host] = slow
            return None

        with mock.patch("agent.snmp.AVAILABLE", True), mock.patch("agent.snmp._query_host_indexed", fake):
            snmp.query_plan({"10.0.0.1": ["a"], "10.0.0.2": ["a"]}, known=["10.0.0.2"])

        self.assertEqual(seen, {"10.0.0.1": True, "10.0.0.2": False})


if __name__ == "__main__":
    unittest.main()
