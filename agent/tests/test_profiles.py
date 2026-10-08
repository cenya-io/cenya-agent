"""The vendor-profile engine, with three minimal profiles of its own: the
real table (`profiles_data`) has its own tests and is not needed here."""

from __future__ import annotations

import unittest

from agent import profiles
from agent.profiles import Identity, Profile

#: Enterprise only: any sysObjectID under 1.3.6.1.4.1.9.
CISCO = Profile(
    key="cisco",
    vendor="Cisco",
    enterprise=9,
    os="IOS",
    version_from_description=r"Version ([^,\s]+)",
)
#: A longer prefix under the same enterprise, with its own OIDs.
CISCO_SB = Profile(
    key="cisco-sb",
    vendor="Cisco",
    object_id_prefix="1.3.6.1.4.1.9.6.1",
    serial_oid="1.3.6.1.4.1.9.6.1.101.53.14.1.5.1",
    model_oid="1.3.6.1.4.1.9.6.1.101.53.14.1.1.1",
    version_oid="1.3.6.1.4.1.9.6.1.101.2.16.1.1.1",
    os="SB-OS",
    entity_fallback=False,
)
#: A regex over sysDescr, which beats everything, and OS from the description.
MIKROTIK = Profile(
    key="mikrotik",
    vendor="MikroTik",
    enterprise=14988,
    description_match=r"^RouterOS",
    serial_oid="1.3.6.1.4.1.14988.1.1.7.3.0",
    version_oid="1.3.6.1.4.1.14988.1.1.4.4.0",
    model_from_description=r"^RouterOS\s+(.+)$",
    os_from_description=r"^(RouterOS)\b",
)
TABLE = (CISCO, CISCO_SB, MIKROTIK)

CISCO_DESCR = "Cisco IOS Software, C1000 Software (C1000-UNIVERSALK9-M), Version 15.2(7)E8, RELEASE SOFTWARE"


class ResolveTests(unittest.TestCase):
    def test_enterprise_number_picks_the_profile(self) -> None:
        self.assertIs(profiles.resolve("1.3.6.1.4.1.9.1.3245", CISCO_DESCR, TABLE), CISCO)

    def test_the_longest_prefix_beats_the_enterprise(self) -> None:
        self.assertIs(profiles.resolve("1.3.6.1.4.1.9.6.1.1004", "SG350-28", TABLE), CISCO_SB)
        # 1.3.6.1.4.1.9.6.10 is not under the 9.6.1 prefix: whole arcs only.
        self.assertIs(profiles.resolve("1.3.6.1.4.1.9.6.10", "", TABLE), CISCO)

    def test_the_description_regex_beats_the_object_id(self) -> None:
        # A MikroTik answering with a Cisco-looking sysObjectID still matches on sysDescr.
        self.assertIs(profiles.resolve("1.3.6.1.4.1.9.1.1", "RouterOS CCR1009-7G-1C-1S+", TABLE), MIKROTIK)
        self.assertIs(profiles.resolve("1.3.6.1.4.1.14988.1", "routeros hAP ac2", TABLE), MIKROTIK)

    def test_nobody_known_is_none(self) -> None:
        self.assertIsNone(profiles.resolve("1.3.6.1.4.1.99999.1", "Something else", TABLE))
        self.assertIsNone(profiles.resolve("", "", TABLE))
        self.assertIsNone(profiles.resolve("garbage", "", TABLE))

    def test_a_leading_dot_does_not_matter(self) -> None:
        self.assertIs(profiles.resolve(".1.3.6.1.4.1.9.6.1.1004", "", TABLE), CISCO_SB)

    def test_a_broken_regex_matches_nothing_instead_of_raising(self) -> None:
        broken = Profile(key="x", vendor="X", description_match=r"(unclosed")
        self.assertIsNone(profiles.resolve("", "(unclosed", (broken,)))

    def test_enterprise_of(self) -> None:
        self.assertEqual(profiles.enterprise_of("1.3.6.1.4.1.14988.1"), 14988)
        self.assertIsNone(profiles.enterprise_of("1.3.6.1.2.1.1.1.0"))
        self.assertIsNone(profiles.enterprise_of("1.3.6.1.4.1"))


class ExtraOidsTests(unittest.TestCase):
    def test_only_the_oids_the_profile_has(self) -> None:
        self.assertEqual(
            profiles.extra_oids(MIKROTIK),
            {"serial": "1.3.6.1.4.1.14988.1.1.7.3.0", "version": "1.3.6.1.4.1.14988.1.1.4.4.0"},
        )
        self.assertEqual(profiles.extra_oids(CISCO), {})
        self.assertEqual(profiles.extra_oids(None), {})


class IdentifyTests(unittest.TestCase):
    ENTITY = {"model": "ENT-MODEL", "serial": "ENT-SERIAL", "version": "ENT-VER", "manufacturer": "Ent Inc"}

    def test_the_profile_oid_wins_over_the_regex_and_the_entity(self) -> None:
        identity = profiles.identify(
            MIKROTIK,
            "RouterOS CCR1009-7G-1C-1S+",
            {"serial": "ABC123", "version": "7.15.3"},
            self.ENTITY,
        )
        self.assertEqual(identity.serial, "ABC123")
        self.assertEqual(identity.os_version, "7.15.3")
        # No model OID: the regex over sysDescr comes next, before ENTITY-MIB.
        self.assertEqual(identity.model, "CCR1009-7G-1C-1S+")
        self.assertEqual(identity.os, "RouterOS")
        self.assertEqual(identity.manufacturer, "MikroTik")
        self.assertEqual(identity.profile, "mikrotik")

    def test_without_oid_answers_the_regex_then_the_entity_fill_in(self) -> None:
        identity = profiles.identify(CISCO, CISCO_DESCR, {}, self.ENTITY)
        self.assertEqual(identity.os_version, "15.2(7)E8")  # regex
        self.assertEqual(identity.model, "ENT-MODEL")  # no regex for the model: ENTITY
        self.assertEqual(identity.serial, "ENT-SERIAL")
        self.assertEqual(identity.os, "IOS")  # fixed by the profile
        self.assertEqual(identity.manufacturer, "Cisco")  # always the profile's, never ENTITY's

    def test_an_unanswered_oid_is_an_empty_string_and_falls_through(self) -> None:
        identity = profiles.identify(MIKROTIK, "RouterOS hAP ac2", {"serial": "", "version": "  "}, {})
        self.assertEqual(identity.serial, "")
        self.assertEqual(identity.os_version, "")
        self.assertEqual(identity.model, "hAP ac2")

    def test_everything_missing_is_empty_not_an_error(self) -> None:
        identity = profiles.identify(CISCO, "", {}, {})
        self.assertEqual(identity, Identity(manufacturer="Cisco", os="IOS", profile="cisco"))

    def test_without_a_profile_only_the_entity_speaks(self) -> None:
        identity = profiles.identify(None, "Whatever 1.0", {}, self.ENTITY)
        self.assertEqual(identity.manufacturer, "Ent Inc")
        self.assertEqual(identity.model, "ENT-MODEL")
        self.assertEqual(identity.serial, "ENT-SERIAL")
        self.assertEqual(identity.os_version, "ENT-VER")
        self.assertEqual(identity.os, "")
        self.assertEqual(identity.profile, "")
        self.assertEqual(profiles.identify(None, "Whatever", {}, {}), Identity())

    def test_needs_entity_only_when_something_is_missing_and_allowed(self) -> None:
        full = Identity(model="m", serial="s")
        self.assertFalse(profiles.needs_entity(CISCO, full))
        self.assertTrue(profiles.needs_entity(CISCO, Identity(model="m")))
        self.assertTrue(profiles.needs_entity(None, Identity()))
        # CISCO_SB switched the fallback off.
        self.assertFalse(profiles.needs_entity(CISCO_SB, Identity()))


class ChassisFromEntityTests(unittest.TestCase):
    def test_the_first_chassis_row_by_index_wins(self) -> None:
        classes = {"1": "11", "2000": "3", "2001": "9", "1000": "3", "1001": "10"}
        chassis = profiles.chassis_from_entity(
            classes,
            {"1000": "C9300-48P", "2000": "C9300-24T"},
            {"1000": "FOC2231X0AA", "2000": "FOC2231X0BB"},
            {"1000": "16.12.4", "2000": "16.12.4"},
            {"1000": "Cisco Systems, Inc.", "2000": "Cisco Systems, Inc."},
        )
        self.assertEqual(
            chassis,
            {"model": "C9300-48P", "serial": "FOC2231X0AA", "version": "16.12.4", "manufacturer": "Cisco Systems, Inc."},
        )

    def test_a_missing_column_leaves_that_field_empty(self) -> None:
        chassis = profiles.chassis_from_entity({"1": "3"}, {"1": " WS-C2960X "}, {}, {}, {})
        self.assertEqual(chassis, {"model": "WS-C2960X", "serial": "", "version": "", "manufacturer": ""})

    def test_no_chassis_row_is_nothing(self) -> None:
        self.assertEqual(profiles.chassis_from_entity({"1": "9", "2": "10"}, {}, {}, {}, {}), {})
        self.assertEqual(profiles.chassis_from_entity({}, {}, {}, {}, {}), {})
        self.assertEqual(profiles.chassis_index({"7": "3", "10": "3"}), "7")


class PayloadFieldsTests(unittest.TestCase):
    def test_os_is_name_and_version_together(self) -> None:
        identity = Identity(manufacturer="Cisco", model="C1000-24T", serial="FOC1", os="IOS", os_version="15.2(7)E8")
        self.assertEqual(
            identity.payload_fields(),
            {"manufacturer": "Cisco", "model": "C1000-24T", "serial": "FOC1", "os": "IOS 15.2(7)E8", "os_version": "15.2(7)E8"},
        )

    def test_os_alone_or_version_alone(self) -> None:
        self.assertEqual(Identity(os="RouterOS").payload_fields(), {"os": "RouterOS"})
        self.assertEqual(Identity(os_version="7.15.3").payload_fields(), {"os": "7.15.3", "os_version": "7.15.3"})

    def test_nothing_known_is_an_empty_payload(self) -> None:
        self.assertEqual(Identity().payload_fields(), {})
        # The profile key is internal: it never travels.
        self.assertEqual(Identity(profile="cisco").payload_fields(), {})


if __name__ == "__main__":
    unittest.main()
