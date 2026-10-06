"""Stack members (`agent.stacks`): one parser per vendor, fed with captures
shaped like the real CLI output, with two or more units and with one.

The contract under test: ``members`` only exists with two or more units, one
entry per physical unit, sorted, and the master's serial is the main one.
"""

from __future__ import annotations

import unittest

from agent import stacks

#: A Catalyst 9200 stack of three, IOS-XE 17.9. The top section is the active
#: unit (switch 1); switches 2 and 3 each get their "Switch 0N" block.
CISCO_STACK_OF_THREE = """Cisco IOS XE Software, Version 17.09.04
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 17.9.4, RELEASE SOFTWARE (fc5)
sw-core uptime is 2 weeks, 3 days, 4 hours, 12 minutes
System image file is "flash:packages.conf"

cisco C9200-48P (ARM64) processor with 600404K/3071K bytes of memory.
3 Virtual Ethernet interfaces
156 Gigabit Ethernet interfaces
12 Ten Gigabit Ethernet interfaces

Base Ethernet MAC Address          : 70:d3:79:aa:10:00
Motherboard Assembly Number        : 73-18785-04
Motherboard Serial Number          : JAE24350111
Model Revision Number              : B0
Motherboard Revision Number        : A0
Model Number                       : C9200-48P
System Serial Number               : JAE24350ABC
CLEI Code Number                   : INM6Q00ARA


Switch Ports Model              SW Version        SW Image              Mode
------ ----- -----              ----------        ----------            ----
*    1 52    C9200-48P          17.9.4            CAT9K_LITE_IOSXE      INSTALL
     2 52    C9200-48P          17.9.4            CAT9K_LITE_IOSXE      INSTALL
     3 28    C9200-24P          17.9.4            CAT9K_LITE_IOSXE      INSTALL


Switch 02
---------
Switch uptime                      : 2 weeks, 3 days, 4 hours, 10 minutes
Base Ethernet MAC Address          : 70:d3:79:aa:20:00
Motherboard Assembly Number        : 73-18785-04
Motherboard Serial Number          : JAE24350222
Model Revision Number              : B0
Motherboard Revision Number        : A0
Model Number                       : C9200-48P
System Serial Number               : JAE24350DEF
CLEI Code Number                   : INM6Q00ARA

Switch 03
---------
Switch uptime                      : 2 weeks, 3 days, 4 hours, 11 minutes
Base Ethernet MAC Address          : 70:d3:79:aa:30:00
Motherboard Assembly Number        : 73-18786-03
Motherboard Serial Number          : JAE24350333
Model Revision Number              : B0
Motherboard Revision Number        : A0
Model Number                       : C9200-24P
System Serial Number               : JAE24350GHI
CLEI Code Number                   : INM6P00ARA

Configuration register is 0x102
"""

#: The same family, one unit: the table has a single row and no blocks.
CISCO_SINGLE = """Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(4)E7, RELEASE SOFTWARE (fc2)
sw-planta uptime is 1 year, 2 weeks, 3 days
Model number                    : WS-C2960X-48FPD-L
System serial number            : FOC2001X0AB

Switch Ports Model                     SW Version            SW Image
------ ----- -----                     ----------            ----------
*    1 52    WS-C2960X-48FPD-L         15.2(4)E7             C2960X-UNIVERSALK9-M

Configuration register is 0xF
"""


class CiscoTests(unittest.TestCase):
    def test_a_stack_of_three_lists_every_unit_with_its_own_serial(self) -> None:
        members = stacks.cisco_members(CISCO_STACK_OF_THREE)

        self.assertEqual(
            members,
            [
                {"unit": 1, "serial": "JAE24350ABC", "model": "C9200-48P", "role": "master"},
                {"unit": 2, "serial": "JAE24350DEF", "model": "C9200-48P", "role": "member"},
                {"unit": 3, "serial": "JAE24350GHI", "model": "C9200-24P", "role": "member"},
            ],
        )
        self.assertEqual(stacks.master_serial(members), "JAE24350ABC")

    def test_a_single_switch_is_not_a_stack(self) -> None:
        self.assertEqual(stacks.cisco_members(CISCO_SINGLE), [])

    def test_output_without_the_table_gives_nothing(self) -> None:
        self.assertEqual(stacks.cisco_members("Cisco IOS Software, C800\nrouter uptime is 3 days\n"), [])


#: Dell N3048P, OS6: `show version` on a stack of two prints one section per
#: unit, each with its own serial.
DELL_VERSION_STACK_OF_TWO = """
Switch: 1

System Description............................. Dell Networking N3048P, 6.6.3.10, Linux 4.14.138
Machine Description............................ Dell Networking Switch
System Model ID................................ N3048P
Machine Type................................... Dell Networking N3048P
Serial Number.................................. CN0K9F1P2829831A0012A00
Manufacturer................................... 0xbc00
Burned In MAC Address.......................... F8B1.5655.3D1C

Switch: 2

System Description............................. Dell Networking N3048P, 6.6.3.10, Linux 4.14.138
Machine Description............................ Dell Networking Switch
System Model ID................................ N3048P
Machine Type................................... Dell Networking N3048P
Serial Number.................................. CN0K9F1P2829831A0034A00
Manufacturer................................... 0xbc00
Burned In MAC Address.......................... F8B1.5655.4E2D
"""

#: The firmware that only describes the management unit: one section, so
#: the agent asks `show switch` too.
DELL_VERSION_MANAGEMENT_ONLY = """
Switch: 1

System Description............................. Dell Networking N2048P, 6.3.3.10, Linux 3.6.5
System Model ID................................ N2048P
Serial Number.................................. CN0D4T5D2829832K0042A00

unit active      backup      current-active next-active
---- ----------- ----------- -------------- --------------
1    6.3.3.10    6.3.2.4     6.3.3.10       6.3.3.10
2    6.3.3.10    6.3.2.4     6.3.3.10       6.3.3.10
"""

DELL_SHOW_SWITCH = """
    Management Standby   Preconfig     Plugged-in    Switch        Code
SW  Status     Status    Model ID      Model ID      Status        Version
--- ---------- --------- ------------- ------------- ------------- -----------
1   Mgmt Sw              N2048P        N2048P        OK            6.3.3.10
2   Stack Mbr  Oper Stby N2048P        N2024P        OK            6.3.3.10
3   Unassigned           N2048P                      Not Present   0.0.0.0
"""

DELL_SHOW_SWITCH_ALONE = """
    Management Standby   Preconfig     Plugged-in    Switch        Code
SW  Status     Status    Model ID      Model ID      Status        Version
--- ---------- --------- ------------- ------------- ------------- -----------
1   Mgmt Sw              N2048P        N2048P        OK            6.3.3.10
"""


class DellTests(unittest.TestCase):
    def test_show_version_with_a_section_per_unit_is_enough(self) -> None:
        self.assertEqual(
            stacks.dell_members_from_version(DELL_VERSION_STACK_OF_TWO),
            [
                {"unit": 1, "serial": "CN0K9F1P2829831A0012A00", "model": "N3048P", "role": "master"},
                {"unit": 2, "serial": "CN0K9F1P2829831A0034A00", "model": "N3048P", "role": "member"},
            ],
        )

    def test_a_version_describing_one_unit_needs_show_switch(self) -> None:
        self.assertEqual(stacks.dell_members_from_version(DELL_VERSION_MANAGEMENT_ONLY), [])
        serial, model = stacks.dell_identity(DELL_VERSION_MANAGEMENT_ONLY)
        self.assertEqual((serial, model), ("CN0D4T5D2829832K0042A00", "N2048P"))

        members = stacks.dell_members_from_switch(DELL_SHOW_SWITCH, serial)

        # The absent, preconfigured unit 3 is not a physical unit; the
        # plugged-in model wins over the preconfigured one.
        self.assertEqual(
            members,
            [
                {"unit": 1, "serial": "CN0D4T5D2829832K0042A00", "model": "N2048P", "role": "master"},
                {"unit": 2, "serial": "", "model": "N2024P", "role": "standby"},
            ],
        )

    def test_a_lone_dell_is_not_a_stack(self) -> None:
        self.assertEqual(stacks.dell_members_from_switch(DELL_SHOW_SWITCH_ALONE, "X"), [])


#: ArubaOS-Switch 3810M, backplane stacking of four (KB.16.10). The model
#: column has spaces and, in unit 3, a bare number ("2920 48G"-style names
#: exist) that must not be read as the priority.
ARUBA_STACK_OF_FOUR = """
 Stack ID         : 00013863-bbc1d900

 MAC Address      : 3863bb-c1d93f
 Stack Topology   : Ring
 Stack Status     : Active
 Split Policy     : One-Fragment-Up
 Uptime           : 21d 2h 35m
 Software Version : KB.16.10.0009

 Mbr
 ID  Mac Address       Model                                 Pri Status
 --- ----------------- ------------------------------------- --- ---------------
 1   3863bb-c1d900     HP JL075A 3810M-16SFP+-2-slot Switch  250 Commander
 2   3863bb-c1e400     HP JL076A 3810M-40G-8SR-PoE+-1-slot   230 Standby
 3   3863bb-c1f800     Aruba JL071A 3810M 24G 1-slot Switch  128 Member
 4   3863bb-c20c00     HP JL073A 3810M-24G-PoE+-1-slot       128 Member
 5                                                           128 Missing
"""

ARUBA_ALONE = """
 Mbr
 ID  Mac Address       Model                                 Pri Status
 --- ----------------- ------------------------------------- --- ---------------
 1   3863bb-c1d900     HP JL075A 3810M-16SFP+-2-slot Switch  128 Commander
"""

#: An EX4300 Virtual Chassis of two, plus a provisioned member not present.
JUNOS_VC_OF_TWO = """
fpc0:
--------------------------------------------------------------------------
Preprovisioned Virtual Chassis
Virtual Chassis ID: 5a1b.0c2d.3e4f
Virtual Chassis Mode: Enabled
                                                Mstr           Mixed Route Neighbor List
Member ID  Status   Serial No    Model          prio  Role      Mode  Mode ID  Interface
0 (FPC 0)  Prsnt    PE3714100218 ex4300-48p     129   Master*      N  VC   1  vcp-255/1/0
                                                                           1  vcp-255/1/1
1 (FPC 1)  Prsnt    PE3714100759 ex4300-48t     129   Backup       N  VC   0  vcp-255/1/0
                                                                           0  vcp-255/1/1
2 (FPC 2)  NotPrsnt PE3714100999 ex4300-48t

Member ID for next new member: 3 (FPC 3)
"""

JUNOS_VC_ALONE = """
Virtual Chassis ID: 1c2d.3e4f.5a6b
Virtual Chassis Mode: Enabled
                                                Mstr           Mixed Route Neighbor List
Member ID  Status   Serial No    Model          prio  Role      Mode  Mode ID  Interface
0 (FPC 0)  Prsnt    NV0217290101 ex2300-24p     128   Master*      N  VC
"""


class ArubaTests(unittest.TestCase):
    def test_a_stack_of_four_with_its_roles_and_without_the_missing_unit(self) -> None:
        members = stacks.aruba_members(ARUBA_STACK_OF_FOUR)

        self.assertEqual([m["unit"] for m in members], [1, 2, 3, 4])
        self.assertEqual([m["role"] for m in members], ["master", "standby", "member", "member"])
        self.assertEqual(members[0]["model"], "HP JL075A 3810M-16SFP+-2-slot Switch")
        self.assertEqual(members[2]["model"], "Aruba JL071A 3810M 24G 1-slot Switch")
        self.assertTrue(all(m["serial"] == "" for m in members))

    def test_a_lone_aruba_is_not_a_stack(self) -> None:
        self.assertEqual(stacks.aruba_members(ARUBA_ALONE), [])
        self.assertEqual(stacks.aruba_members("Invalid input: stacking"), [])


class JunosTests(unittest.TestCase):
    def test_a_virtual_chassis_of_two_keeps_juniper_numbering(self) -> None:
        self.assertEqual(
            stacks.junos_members(JUNOS_VC_OF_TWO),
            [
                {"unit": 0, "serial": "PE3714100218", "model": "ex4300-48p", "role": "master"},
                {"unit": 1, "serial": "PE3714100759", "model": "ex4300-48t", "role": "standby"},
            ],
        )

    def test_a_standalone_ex_gives_its_serial_but_no_members(self) -> None:
        self.assertEqual(stacks.junos_members(JUNOS_VC_ALONE), [])
        self.assertEqual(stacks.junos_master_serial(JUNOS_VC_ALONE), "NV0217290101")
        self.assertEqual(stacks.junos_master_serial("error: syntax error"), "")


#: HPE 5130 EI, Comware 7: an IRF fabric of three.
IRF_OF_THREE = """MemberID    Slot  Role    Priority  CPU-Mac         Description
 *+1        1     Master  32        3822-d6c2-1802  ---
   2        1     Standby 1         3822-d6c2-1a02  ---
   3        1     Standby 1         3822-d6c2-1c02  ---
--------------------------------------------------
 * indicates the device is the master.
 + indicates the device through which the user logs in.

 The bridge MAC of the IRF is: 3822-d6c2-1800
 Auto upgrade                : yes
 Mac persistent              : 6 min
 Domain ID                   : 0
"""

#: Comware 5 (an older H3C 5120): no Slot column, subordinates are "Slave".
IRF_COMWARE5_OF_TWO = """Switch  Role   Priority  CPU-Mac         Description
 *+1    Master 31        0023-8912-3456  -----
   2    Slave  1         0023-8912-3457  -----
"""

IRF_ALONE = """MemberID    Slot  Role    Priority  CPU-Mac         Description
 *+1        1     Master  1         3822-d6c2-1802  ---
"""

MANUINFO_OF_THREE = """Slot 1 CPU 0:
DEVICE_NAME          : 5130-48G-PoE+-4SFP+
DEVICE_SERIAL_NUMBER : CN64GPV0AA
MAC_ADDRESS          : 3822-D6C2-1800
MANUFACTURING_DATE   : 2016-07-20
VENDOR_NAME          : HPE

Fan 1:
DEVICE_NAME          : LSWM1FANSC
DEVICE_SERIAL_NUMBER : 210231A1FANX01

Slot 2 CPU 0:
DEVICE_NAME          : 5130-48G-PoE+-4SFP+
DEVICE_SERIAL_NUMBER : CN64GPV0BB
MAC_ADDRESS          : 3822-D6C2-1A00

Slot 3 CPU 0:
DEVICE_NAME          : 5130-24G-4SFP+
DEVICE_SERIAL_NUMBER : CN64GPV0CC
MAC_ADDRESS          : 3822-D6C2-1C00
"""


class ComwareTests(unittest.TestCase):
    def test_irf_gives_units_and_roles_and_manuinfo_fills_serials(self) -> None:
        members = stacks.irf_members(IRF_OF_THREE)

        self.assertEqual([(m["unit"], m["role"]) for m in members], [(1, "master"), (2, "standby"), (3, "standby")])
        stacks.add_manuinfo(members, MANUINFO_OF_THREE)
        self.assertEqual(
            [(m["serial"], m["model"]) for m in members],
            [("CN64GPV0AA", "5130-48G-PoE+-4SFP+"), ("CN64GPV0BB", "5130-48G-PoE+-4SFP+"), ("CN64GPV0CC", "5130-24G-4SFP+")],
        )

    def test_a_fan_section_is_never_taken_for_a_member(self) -> None:
        self.assertEqual(set(stacks.manuinfo_by_slot(MANUINFO_OF_THREE)), {1, 2, 3})

    def test_comware5_layout(self) -> None:
        self.assertEqual(
            [(m["unit"], m["role"]) for m in stacks.irf_members(IRF_COMWARE5_OF_TWO)],
            [(1, "master"), (2, "standby")],
        )

    def test_a_lone_member_is_not_a_fabric(self) -> None:
        self.assertEqual(stacks.irf_members(IRF_ALONE), [])
        self.assertEqual(stacks.irf_members("% Unrecognized command found at '^' position."), [])


class FinishTests(unittest.TestCase):
    def test_duplicates_collapse_and_order_is_by_unit(self) -> None:
        members = stacks.finish(
            [
                {"unit": 2, "serial": "B", "model": "m", "role": "member"},
                {"unit": 1, "serial": "A", "model": "m", "role": "master"},
                {"unit": 2, "serial": "C", "model": "m", "role": "member"},
            ]
        )
        self.assertEqual([(m["unit"], m["serial"]) for m in members], [(1, "A"), (2, "B")])

    def test_one_unit_is_never_a_list(self) -> None:
        self.assertEqual(stacks.finish([{"unit": 1, "serial": "A", "model": "", "role": ""}]), [])


#: entPhysicalTable of a Catalyst 9300 stack of two, as walked: the "stack"
#: entity (class 11) holds one chassis (class 3) per switch at its number;
#: modules, ports and power supplies (9, 10, 6) are not units.
ENTITY_TWO_CHASSIS = {
    "classes": {"1": "11", "1000": "3", "1001": "9", "1010": "10", "2000": "3", "2001": "9", "1015": "6"},
    "positions": {"1": "-1", "1000": "1", "1001": "0", "2000": "2", "2001": "0"},
    "serials": {"1000": "FOC2231X0AA", "1001": "", "2000": "FOC2231X0BB"},
    "models": {"1000": "C9300-48P", "2000": "C9300-24T", "1001": ""},
}

ENTITY_ONE_CHASSIS = {
    "classes": {"1": "3", "2": "9", "3": "10"},
    "positions": {"1": "-1"},
    "serials": {"1": "FOC2001X0AB"},
    "models": {"1": "WS-C2960X-48FPD-L"},
}


class EntityMibTests(unittest.TestCase):
    def test_two_chassis_are_a_stack_numbered_by_position(self) -> None:
        self.assertEqual(
            stacks.entity_members(**ENTITY_TWO_CHASSIS),
            [
                {"unit": 1, "serial": "FOC2231X0AA", "model": "C9300-48P", "role": ""},
                {"unit": 2, "serial": "FOC2231X0BB", "model": "C9300-24T", "role": ""},
            ],
        )

    def test_one_chassis_is_not_a_stack(self) -> None:
        self.assertEqual(stacks.entity_members(**ENTITY_ONE_CHASSIS), [])

    def test_without_usable_positions_the_chassis_are_numbered_in_order(self) -> None:
        members = stacks.entity_members(
            {"20": "3", "3": "3"}, {"20": "0", "3": "0"}, {"3": "A", "20": "B"}, {}
        )
        self.assertEqual([(m["unit"], m["serial"]) for m in members], [(1, "A"), (2, "B")])
