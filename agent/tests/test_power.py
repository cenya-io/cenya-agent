"""The power supplies of a device, from ENTITY-MIB and the vendor's status
column (``agent/power.py``): pure, and the SNMP reading over fakes."""

from __future__ import annotations

import asyncio
import unittest
from unittest import mock

from agent import power, snmp

CISCO_9300 = "1.3.6.1.4.1.9.1.2494"
HUAWEI = "1.3.6.1.4.1.2011.2.23.606"
JUNIPER = "1.3.6.1.4.1.2636.1.1.1.2.31"

#: A Catalyst 9300 with bay A fitted and live, bay B empty: both listed.
CLASSES_TWO_BAYS = {"1": "3", "2": "9", "1000": "6", "1001": "6", "1500": "7"}


class SupplyRowsTests(unittest.TestCase):
    def test_only_rows_of_class_power_supply_count_in_index_order(self) -> None:
        classes = {"1001": "6", "1": "3", "1000": "6", "2": "9", "10": "6"}
        self.assertEqual(power.supply_indexes(classes), ["10", "1000", "1001"])

    def test_no_entity_mib_means_no_supplies(self) -> None:
        self.assertEqual(power.supply_indexes({}), [])

    def test_a_chassis_with_too_many_bays_is_cut(self) -> None:
        classes = {str(index): "6" for index in range(1, 40)}
        self.assertEqual(len(power.supply_indexes(classes)), power.MAX_POWER_SUPPLIES)

    def test_the_name_falls_back_to_description_then_position(self) -> None:
        self.assertEqual(power.supply("9", 2, {"name": "Switch 1 - Power Supply B"}, "")["name"], "Switch 1 - Power Supply B")
        self.assertEqual(power.supply("9", 2, {"name": "", "description": "Power Supply"}, "")["name"], "Power Supply")
        self.assertEqual(power.supply("9", 2, {}, "")["name"], "PSU2")

    def test_a_no_such_instance_that_leaked_as_text_is_not_a_name(self) -> None:
        self.assertEqual(power.supply("9", 1, {"name": "NoSuchInstance", "description": "No Such Object"}, "")["name"], "PSU1")

    def test_an_unknown_status_word_is_left_empty(self) -> None:
        self.assertEqual(power.supply("9", 1, {}, "melting")["status"], "")
        self.assertEqual(power.supply("9", 1, {}, power.NO_INPUT)["status"], "no_input")


class StatusColumnTests(unittest.TestCase):
    def test_cisco_reads_the_fru_power_column(self) -> None:
        oid, states = power.status_column(CISCO_9300)
        self.assertEqual(oid, power.CISCO_FRU_POWER_OID)
        self.assertEqual(power.status_of("2", states), power.OK)
        self.assertEqual(power.status_of("5", states), power.NO_INPUT)
        self.assertEqual(power.status_of("8", states), power.FAILED)
        self.assertEqual(power.status_of("9", states), power.FAILED)
        self.assertEqual(power.status_of("3", states), power.OFF)

    def test_huawei_reads_its_entity_extent_column(self) -> None:
        oid, states = power.status_column(HUAWEI)
        self.assertEqual(oid, power.HUAWEI_ENTITY_STATUS_OID)
        self.assertEqual(power.status_of("3", states), power.OK)
        self.assertEqual(power.status_of("4", states), power.ABSENT)

    def test_everybody_else_gets_the_generic_entity_state_column(self) -> None:
        oid, states = power.status_column(JUNIPER)
        self.assertEqual(oid, power.ENTITY_STATE_OPER_OID)
        self.assertEqual(power.status_of("3", states), power.OK)
        self.assertEqual(power.status_of("1", states), power.UNKNOWN)

    def test_a_prefix_never_matches_a_longer_enterprise_number(self) -> None:
        """9 is Cisco; 90, 99 and 9999 are not."""
        self.assertEqual(power.status_column("1.3.6.1.4.1.99.1.1")[0], power.ENTITY_STATE_OPER_OID)
        self.assertEqual(power.status_column("1.3.6.1.4.1.9")[0], power.CISCO_FRU_POWER_OID)

    def test_a_value_nobody_mapped_is_unknown(self) -> None:
        self.assertEqual(power.status_of("", power.CISCO_FRU_POWER_STATES), power.UNKNOWN)
        self.assertEqual(power.status_of("NoSuchInstance", power.CISCO_FRU_POWER_STATES), power.UNKNOWN)
        self.assertEqual(power.status_of("99", power.CISCO_FRU_POWER_STATES), power.UNKNOWN)


def fake_get(answers: dict[str, str], calls: list[list[str]] | None = None, fail_on: str = ""):
    """`snmp._get` over {oid: text}; a missing OID answers empty like a
    NoSuchInstance bind does once `_text` has seen it."""

    async def get(engine, host, auth, oids, context_name="", fast=False):  # noqa: ANN001 - mirrors snmp._get
        if calls is not None:
            calls.append(list(oids.values()))
        if fail_on and any(oid.startswith(fail_on) for oid in oids.values()):
            raise RuntimeError("timeout")
        return {name: answers.get(oid, "") for name, oid in oids.items()}

    return get


class ReadingTests(unittest.TestCase):
    """`snmp._query_power_supplies`: one name row and one status instance per
    bay, never a walk."""

    ANSWERS = {
        f"{snmp.ENTITY_NAME_OID}.1000": "Switch 1 - Power Supply A",
        f"{snmp.ENTITY_DESCR_OID}.1000": "Switch 1 - Power Supply A",
        f"{snmp.ENTITY_MODEL_OID}.1000": "PWR-C1-715WAC",
        f"{snmp.ENTITY_SERIAL_OID}.1000": "DTN2301X0AA",
        f"{power.CISCO_FRU_POWER_OID}.1000": "2",
        f"{snmp.ENTITY_NAME_OID}.1001": "Switch 1 - Power Supply B",
        f"{snmp.ENTITY_DESCR_OID}.1001": "Switch 1 - Power Supply B",
        f"{power.CISCO_FRU_POWER_OID}.1001": "5",
    }

    def read(self, classes: dict[str, str], object_id: str = CISCO_9300, **kwargs) -> tuple[list, list]:
        calls: list[list[str]] = []
        with mock.patch("agent.snmp._get", fake_get(self.ANSWERS, calls, **kwargs)):
            supplies = asyncio.run(snmp._query_power_supplies(None, "192.168.1.2", "public", classes, object_id))
        return supplies, calls

    def test_each_bay_comes_named_with_its_state(self) -> None:
        supplies, calls = self.read(CLASSES_TWO_BAYS)

        self.assertEqual(
            supplies,
            [
                {
                    "index": "1000",
                    "name": "Switch 1 - Power Supply A",
                    "description": "Switch 1 - Power Supply A",
                    "model": "PWR-C1-715WAC",
                    "serial": "DTN2301X0AA",
                    "status": "ok",
                },
                {
                    "index": "1001",
                    "name": "Switch 1 - Power Supply B",
                    "description": "Switch 1 - Power Supply B",
                    "model": "",
                    "serial": "",
                    "status": "no_input",
                },
            ],
        )
        # Two gets per bay, every one a leaf instance of that bay's index.
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(oid.endswith((".1000", ".1001")) for call in calls for oid in call))

    def test_a_device_without_supplies_asks_nothing(self) -> None:
        supplies, calls = self.read({"1": "3", "2": "9"})
        self.assertEqual(supplies, [])
        self.assertEqual(calls, [])

    def test_a_vendor_without_a_status_column_reports_unknown(self) -> None:
        supplies, _ = self.read(CLASSES_TWO_BAYS, object_id=JUNIPER)
        self.assertEqual([supply["status"] for supply in supplies], ["", ""])
        self.assertEqual(supplies[0]["name"], "Switch 1 - Power Supply A")

    def test_a_bay_whose_get_fails_is_still_counted(self) -> None:
        supplies, _ = self.read(CLASSES_TWO_BAYS, fail_on=snmp.ENTITY_NAME_OID)
        self.assertEqual([supply["name"] for supply in supplies], ["PSU1", "PSU2"])
        # The status column answered even though the name row did not.
        self.assertEqual([supply["status"] for supply in supplies], ["ok", "no_input"])

    def test_a_status_column_that_fails_leaves_the_state_unknown(self) -> None:
        supplies, _ = self.read(CLASSES_TWO_BAYS, fail_on=power.CISCO_FRU_POWER_OID)
        self.assertEqual([supply["status"] for supply in supplies], ["", ""])
        self.assertEqual(supplies[0]["name"], "Switch 1 - Power Supply A")


if __name__ == "__main__":
    unittest.main()
