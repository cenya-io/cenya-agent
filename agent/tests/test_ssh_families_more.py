"""The families added on 09-10-2026 (analisis-captura-configuracion-2026-10-09.md).

Every sample output here comes from the vendors' public documentation or
from public forum captures, never from a device in front of us: the parsers
are tolerant (several clues each) and these tests pin that tolerance. What a
real device prints can still differ, and each parser's docstring says so.
"""

from __future__ import annotations

import unittest
from typing import Any
from unittest import mock

from agent import ssh, sshshell
from agent.collectors.ssh import (
    CAPTURE_COMMANDS,
    CAPTURE_FALLBACKS,
    ENABLE_FAMILIES,
    MARK,
    SAVED_CONFIG_COMMANDS,
    fetch_configs,
    parse_aos,
    parse_asa,
    parse_cisco,
    parse_ciscosb,
    parse_dell,
    parse_dlink,
    parse_eos,
    parse_fireware,
    parse_lancom,
    parse_linux,
    parse_panos,
    parse_session,
    parse_show_version,
    parse_sonicos,
    parse_tplink,
    parse_zyxel,
)
from agent.credentials import Credential
from agent.tests.test_ssh import CISCO_SHOW_VERSION, DELL_SHOW_VERSION

ASA_SHOW_VERSION = """Cisco Adaptive Security Appliance Software Version 9.12(4)
Firepower Extensible Operating System Version 2.6(1.254)
Device Manager Version 7.12(2)

Compiled on Tue 25-Feb-20 13:21 PST by builders
System image file is "disk0:/asa9-12-4-smp-k8.bin"
Config file at boot was "startup-config"

fw-oficina up 45 days 3 hours

Hardware:   ASA5516, 8192 MB RAM, CPU Atom C2000 series 2416 MHz, 1 CPU (8 cores)
Internal ATA Compact Flash, 8000MB
BIOS Flash M25P64 @ 0xfed01000, 16384KB

Serial Number: JAD12345678
"""

EOS_SHOW_VERSION = """Arista DCS-7050TX-48-R
Hardware version: 02.00
Serial number: JPE15200519
Hardware MAC address: 001c.7350.0d2d
System MAC address: 001c.7350.0d2d

Software image version: 4.31.5M
Architecture: x86_64
Internal build version: 4.31.5M-37234853.4315M
"""

CISCOSB_SHOW_VERSION = """Active-image: flash://system/images/image_tesla_hybrid_2.5.0.83.bin
  Version: 2.5.0.83
  MD5 Digest: 0d4e4f7c2c1b3a9e8f6d5c4b3a291807
  Date: 11-Jul-2019
  Time: 15:44:00
Inactive-image: flash://system/images/image_tesla_hybrid_2.4.5.71.bin
  Version: 2.4.5.71
Unit  SW version   Boot version   HW version
---- ----------- ------------- -----------
   1  2.5.0.83    1.0.0.3        V02
"""

ZYXEL_SHOW_VERSION = """Current ZyNOS version: V4.70(ABMM.1) | 11/18/2021
ZyNOS F/W Version: V4.70(ABMM.1) | 11/18/2021
Bootbase Version: V1.00 | 03/08/2019
System Name: GS1920
Product Model: GS1920-24HP
Serial Number: S190Y12345678
"""

SONICOS_SHOW_VERSION = """firmware-version "SonicOS Enhanced 6.5.4.4-44n"
rom-version "SonicROM 6.5.0.0"
model "NSA 2650"
serial-number C0EAE4ABCDEF
"""

PANOS_SYSTEM_INFO = """hostname: fw-pa220
ip-address: 192.168.1.1
public-ip-address: unknown
netmask: 255.255.255.0
default-gateway: 192.168.1.254
mac-address: 00:1b:17:00:00:01
time: Thu Oct  9 10:00:00 2026
uptime: 12 days, 3:20:15
family: 220
model: PA-220
serial: 012345678901
sw-version: 10.1.9
app-version: 8700-7900
"""

TPLINK_SYSTEM_INFO = """ System Description      - JetStream 24-Port Gigabit L2 Managed Switch with 4 SFP Slots
 Device Name             - T1600G-28TS
 Device Location         - SHENZHEN
 System Contact          - www.tp-link.com
 Hardware Version        - T1600G-28TS 3.0
 Firmware Version        - 3.0.1 Build 20200324 Rel.46771(s)
 Serial Number           - 2212345000123
 System Time             - 2026-10-09 10:00:00
 Running Time            - 12 day - 3 hour - 20 min - 15 sec
"""

DLINK_SHOW_SWITCH = """Device Type        : DGS-1210-28/ME Gigabit Ethernet Switch
MAC Address        : 00-11-22-33-44-55
IP Address         : 192.168.1.10 (Manual)
VLAN Name          : default
Subnet Mask        : 255.255.255.0
Default Gateway    : 192.168.1.1
Boot PROM Version  : Build 1.00.B006
Firmware Version   : Build 7.00.B018
Hardware Version   : B1
Serial Number      : QA2B1C3000123
System Name        : sw-dlink
System Uptime      : 12 days, 3 hours, 20 minutes, 15 seconds
"""

FIREWARE_SYSINFO = """Fireware OS Version: 12.7.2.B657832
Model: M270
Serial Number: 80B1234567890
Hostname: fw-wg
System Time: 10:00:00
System Date: 10/09/2026
"""

LANCOM_SYSINFO = """DEVICE: LANCOM 1781EF+
HW-RELEASE: B
VERSION: 10.32.0176 / 27.04.2020
SERIAL-NUMBER: 4001234567890123
MAC-ADDRESS: 00a057001122
NAME: router-lancom
"""

AOS_SHOW_SYSTEM = """System:
  Description:  Alcatel-Lucent Enterprise OS6860E-P48 8.9.221.R03 GA, December 05, 2023.,
  Object ID:    1.3.6.1.4.1.6486.801.1.1.2.1.11.1.4,
  Up Time:      12 days 3 hours 20 minutes and 15 seconds,
  Contact:      Alcatel-Lucent Enterprise, https://www.al-enterprise.com,
  Name:         sw-ale-1,
  Location:     CPD,
  Services:     78,
"""


def linux_output(**sections: str) -> str:
    base = {
        "uname": "FreeBSD 14.0-CURRENT",
        "os": "",
        "host": "fw-pf",
        "link": "",
        "addr": "",
        "vendor": "",
        "model": "",
        "serial": "",
        "vyatta": "",
        "ubnt": "",
        "platform": "",
        "opnsense": "",
        "openwrt": "",
    }
    base.update(sections)
    return "\n".join(f"{MARK}{name}\n{value}" for name, value in base.items())


class DetectionTests(unittest.TestCase):
    def test_asa_before_ios(self) -> None:
        data = parse_show_version(ASA_SHOW_VERSION)

        self.assertEqual(data["family"], "asa")
        self.assertEqual((data["hostname"], data["model"], data["serial"]), ("fw-oficina", "ASA5516", "JAD12345678"))
        self.assertEqual(parse_cisco(ASA_SHOW_VERSION)["family"], "cisco", "the IOS parser would have taken it")

    def test_arista(self) -> None:
        data = parse_show_version(EOS_SHOW_VERSION)

        self.assertEqual(data["family"], "eos")
        self.assertEqual((data["model"], data["serial"]), ("DCS-7050TX-48-R", "JPE15200519"))
        self.assertEqual(data["description"], "Arista EOS 4.31.5M")

    def test_cisco_small_business(self) -> None:
        data = parse_show_version(CISCOSB_SHOW_VERSION)

        self.assertEqual(data["family"], "ciscosb")
        self.assertIn("2.5.0.83", data["description"])

    def test_zyxel_switch(self) -> None:
        data = parse_show_version(ZYXEL_SHOW_VERSION)

        self.assertEqual(data["family"], "zyxel")
        self.assertEqual((data["model"], data["serial"]), ("GS1920-24HP", "S190Y12345678"))

    def test_sonicos(self) -> None:
        data = parse_show_version(SONICOS_SHOW_VERSION)

        self.assertEqual(data["family"], "sonicos")
        self.assertEqual((data["model"], data["serial"]), ("NSA 2650", "C0EAE4ABCDEF"))

    def test_the_session_only_families(self) -> None:
        cases = {
            "panos": (parse_panos, PANOS_SYSTEM_INFO, "PA-220", "012345678901"),
            "tplink": (parse_tplink, TPLINK_SYSTEM_INFO, "T1600G-28TS", "2212345000123"),
            "dlink": (parse_dlink, DLINK_SHOW_SWITCH, "DGS-1210-28/ME", "QA2B1C3000123"),
            "fireware": (parse_fireware, FIREWARE_SYSINFO, "M270", "80B1234567890"),
            "lancom": (parse_lancom, LANCOM_SYSINFO, "1781EF+", "4001234567890123"),
        }
        for family, (parse, sample, model, serial) in cases.items():
            data = parse(sample)
            self.assertEqual(data["family"], family, family)
            self.assertEqual((data["model"], data["serial"]), (model, serial), family)
            self.assertEqual(parse_session(sample + "\nsw-x# ")["family"], family, family)

    def test_alcatel(self) -> None:
        data = parse_aos(AOS_SHOW_SYSTEM)

        self.assertEqual(data["family"], "aos")
        self.assertEqual((data["hostname"], data["model"]), ("sw-ale-1", "OS6860E-P48"))

    def test_pfsense_opnsense_and_openwrt_by_exec(self) -> None:
        pf = parse_linux(linux_output(platform="pfSense", ubnt="2.7.2-RELEASE"))
        self.assertEqual((pf["family"], pf["description"], pf["manufacturer"]), ("pfsense", "pfSense 2.7.2-RELEASE", "Netgate"))

        opn = parse_linux(linux_output(opnsense="OPNsense 24.7.1"))
        self.assertEqual((opn["family"], opn["description"]), ("opnsense", "OPNsense 24.7.1"))

        wrt = parse_linux(
            linux_output(uname="Linux 5.15.150", openwrt="DISTRIB_ID='OpenWrt'\nDISTRIB_DESCRIPTION='OpenWrt 23.05.3'")
        )
        self.assertEqual((wrt["family"], wrt["description"]), ("openwrt", "OpenWrt 23.05.3"))

        plain = parse_linux(linux_output(uname="Linux 6.1.0", os='PRETTY_NAME="Debian GNU/Linux 12"'))
        self.assertNotIn("family", plain)

    def test_each_new_parser_stays_mute_with_the_others_output(self) -> None:
        parsers = (parse_asa, parse_eos, parse_ciscosb, parse_zyxel, parse_sonicos, parse_panos, parse_tplink,
                   parse_dlink, parse_fireware, parse_lancom, parse_aos)
        samples = (CISCO_SHOW_VERSION, DELL_SHOW_VERSION, ASA_SHOW_VERSION, EOS_SHOW_VERSION, CISCOSB_SHOW_VERSION,
                   ZYXEL_SHOW_VERSION, SONICOS_SHOW_VERSION, PANOS_SYSTEM_INFO, TPLINK_SYSTEM_INFO, DLINK_SHOW_SWITCH,
                   FIREWARE_SYSINFO, LANCOM_SYSINFO, AOS_SHOW_SYSTEM)
        for parse in parsers:
            signed = [sample for sample in samples if parse(sample)]
            self.assertEqual(len(signed), 1, f"{parse.__name__} signed {len(signed)} samples")

    def test_the_old_families_keep_their_equipment(self) -> None:
        self.assertEqual(parse_show_version(CISCO_SHOW_VERSION)["family"], "cisco")
        self.assertEqual(parse_show_version(DELL_SHOW_VERSION)["family"], "dell")
        self.assertEqual(parse_dell(CISCOSB_SHOW_VERSION), {})


class CaptureTests(unittest.TestCase):
    def test_commands_and_privilege(self) -> None:
        self.assertEqual(CAPTURE_COMMANDS["asa"], "more system:running-config")
        self.assertEqual(CAPTURE_COMMANDS["panos"], "show config running")
        self.assertEqual(CAPTURE_COMMANDS["fortinet"], "show full-configuration | grep .")
        self.assertEqual(CAPTURE_COMMANDS["pfsense"], "cat /cf/conf/config.xml")
        self.assertEqual(CAPTURE_COMMANDS["openwrt"], "uci export")
        for family in ("asa", "eos", "ciscosb", "zyxel", "tplink"):
            self.assertIn(family, ENABLE_FAMILIES)
        for family in ("panos", "sonicos", "pfsense", "lancom", "aos"):
            self.assertNotIn(family, ENABLE_FAMILIES)
        self.assertEqual(SAVED_CONFIG_COMMANDS["asa"], "show startup-config")

    def test_the_session_setup_speaks_every_dialect(self) -> None:
        for command in ("terminal pager 0", "no cli pager session", "set cli pager off", "set cli config-output-format set"):
            self.assertIn(command, sshshell.PAGING_OFF)
        for command in ("show system info", "show system-info", "show switch", "show sysinfo", "sysinfo"):
            self.assertIn(command, sshshell.IDENTIFY)

    def test_a_dlink_with_the_new_cli_gets_the_second_dialect(self) -> None:
        """The classic command is refused, the new one answers: the copy is the
        new one, and nobody is asked again who they are."""
        answers = {
            "show config current_config": "Command: show config current_config\n\n% Unrecognized command\n",
            "show running-config": "!DGS-1510-28X Gigabit Ethernet Switch\n!Firmware: Build 1.31.B005\nconfigure terminal\nvlan 10\n",
        }

        def fake(host: str, credential: Any, command: str, logins: Any = None, enable: bool = False) -> str:
            return answers.get(command, "")

        with mock.patch("agent.collectors.ssh.fetch_config", side_effect=fake), mock.patch(
            "agent.collectors.ssh.interrogate", side_effect=AssertionError("asked again")
        ):
            copies = fetch_configs("10.0.0.9", Credential(kind="ssh", username="u", secret="s"), "dlink", None, [])

        self.assertIn("vlan 10", copies["config"])
        self.assertEqual(CAPTURE_FALLBACKS["dlink"], ("show running-config",))

    def test_a_refusal_in_every_dialect_is_still_a_refusal(self) -> None:
        errors: list = []
        refusal = "show config current_config : Command Is Not Authorized\n"

        def fake(host: str, credential: Any, command: str, logins: Any = None, enable: bool = False) -> str:
            return refusal

        with mock.patch("agent.collectors.ssh.fetch_config", side_effect=fake), mock.patch(
            "agent.collectors.ssh.interrogate", return_value=({"family": "dlink"}, None)
        ):
            copies = fetch_configs("10.0.0.9", Credential(kind="ssh", username="u", secret="s"), "dlink", None, errors)

        self.assertEqual(copies, {})
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
