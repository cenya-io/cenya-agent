"""Configuration copies for Extreme EXOS, Ruckus ICX, AlliedWare Plus and EdgeOS.

The sample outputs follow the vendors' public documentation. They have not
been checked against real hardware: the parsers are tolerant (several clues)
and these tests pin that tolerance, not a certainty about the exact bytes.
"""

from __future__ import annotations

import unittest
from typing import Any
from unittest import mock

from agent import ssh
from agent.collectors.ssh import (
    CAPTURE_COMMANDS,
    LINUX_COMMAND,
    MARK,
    SshCollector,
    fetch_configs,
    parse_awplus,
    parse_edgeos,
    parse_exos,
    parse_icx,
    parse_linux,
    parse_session,
    parse_show_version,
)
from agent.credentials import Credential
from agent.tests.test_ssh import (
    ARUBA_SHOW_VERSION,
    CISCO_SHOW_VERSION,
    DELL_SHOW_VERSION,
    JUNOS_SHOW_VERSION,
    LINUX_UBUNTU,
)

EXOS_SHOW_VERSION = """Switch      : 800554-00-04 1550G-00184 Rev 4.0 BootROM: 2.0.1.1    IMG: 22.7.1.4
Image   : ExtremeXOS version 22.7.1.4 by release-manager
          on Wed Mar 28 15:08:54 EDT 2018
BootROM : 2.0.1.1
Diagnostics : 6.3
"""

EXOS_CONFIG = """#### Module devmgr configuration.
#
configure snmp sysName "sw-ext-1"
configure vlan Default tag 1
"""

ICX_SHOW_VERSION = """Copyright (c) Ruckus Networks, Inc. All rights reserved.
  UNIT 1: compiled on Mar  9 2020 at 17:55:21 labeled as SPR08092
        (31455610 bytes) from Primary SPR08092.bin
        SW: Version 08.0.92T213
  Boot-Monitor Image size = 786944, Version:10.1.06T215 (kxz10106)
HW: Stackable ICX7150-24-POE
==========================================================================
UNIT 1: SL 1: ICX7150-24-POE 24-port Management Module
      Serial  #:CYP3213N00A
      License: ICX7150_L3_SOFT_PACKAGE   (LID: eayHHIJmFFu)
"""

ICX_BROCADE_SHOW_VERSION = """Copyright (c) 1996-2012 Brocade Communications Systems, Inc.
  UNIT 1: compiled on Dec  8 2017 at 18:25:01 labeled as FCXR08030
        SW: Version 08.0.30
HW: Stackable FCX648S-HPOE (FastIron)
"""

ICX_CONFIG = """Current configuration:
!
ver 08.0.92T213
!
stack unit 1
  module 1 icx7150-24-poe-port-management-module
!
hostname sw-icx
"""

AWPLUS_SHOW_VERSION = """AlliedWare Plus (TM) 5.4.9 19/10/18 12:00:00

Build date: Fri Oct 19 12:00:00 NZDT 2018
Build type: RELEASE
Allied Telesis x510-28GTX
"""

AWPLUS_CONFIG = """!
! Allied Telesis Software
!
no service password-encryption
!
hostname sw-at-1
"""

EDGEOS_SHOW_VERSION = """Version:      v2.0.9-hotfix.2
Build ID:     5574651
Build on:     01/12/21 06:22
Copyright:    2012-2021 Ubiquiti Networks, Inc.
HW model:     EdgeRouter X 5-Port
HW S/N:       F09FC2123456
Uptime:       10:20:30 up 5 days
"""

EDGEOS_CONFIG = """firewall {
    all-ping enable
}
interfaces {
    ethernet eth0 {
        address dhcp
    }
}
system {
    host-name er-oficina
}
"""

#: EdgeRouter reached by exec: a Linux whose `uname` answers.
EDGEOS_LINUX = f"""{MARK}uname
Linux 4.9.79-UBNT
{MARK}os
PRETTY_NAME="Debian GNU/Linux 7 (wheezy)"
{MARK}host
er-oficina
{MARK}link
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\\    link/ether f0:9f:c2:12:34:56 brd ff:ff:ff:ff:ff:ff
{MARK}addr
2: eth0    inet 192.168.1.1/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever preferred_lft forever
{MARK}vendor
{MARK}model
{MARK}serial
{MARK}vyatta
yes
{MARK}ubnt
EdgeRouter.ER-e50.v2.0.9-hotfix.2.5574651.210112.0622
"""

#: Same wrapper, no Ubiquiti: a VyOS stays a plain Linux.
VYOS_LINUX = EDGEOS_LINUX.replace("4.9.79-UBNT", "4.19.0-9-amd64").replace(
    "EdgeRouter.ER-e50.v2.0.9-hotfix.2.5574651.210112.0622", "VyOS 1.2.9"
)

EDGESWITCH_IOSLIKE = """System Description............................. EdgeSwitch 24-Port 250W, 1.9.0, Linux 3.6.5
Machine Model.................................. ES-24-250W
Serial Number.................................. F09FC2AABBCC
"""

UNKNOWN_COMMAND_OUTPUTS = (
    "% Invalid input detected at '^' marker.\n",
    "%% Invalid input detected at '^' marker.\n",
    "% Unrecognized command\n",
    "Invalid input -> show configuration\nType ? for a list\n",
    "Unknown command\n",
    "bash: show: command not found\n",
)


class DetectionTests(unittest.TestCase):
    def test_exos(self) -> None:
        data = parse_show_version(EXOS_SHOW_VERSION)
        self.assertEqual(data["family"], "exos")
        self.assertEqual(data["manufacturer"], "Extreme Networks")
        self.assertEqual(data["description"], "ExtremeXOS version 22.7.1.4 by release-manager")
        self.assertEqual(data["serial"], "1550G-00184")

    def test_icx_ruckus_and_brocade(self) -> None:
        data = parse_show_version(ICX_SHOW_VERSION)
        self.assertEqual(data["family"], "icx")
        self.assertEqual(data["manufacturer"], "Ruckus")
        self.assertEqual(data["model"], "ICX7150-24-POE")
        self.assertEqual(data["serial"], "CYP3213N00A")
        self.assertIn("08.0.92T213", data["description"])
        brocade = parse_show_version(ICX_BROCADE_SHOW_VERSION)
        self.assertEqual(brocade["family"], "icx")
        self.assertEqual(brocade["manufacturer"], "Brocade")

    def test_awplus(self) -> None:
        data = parse_show_version(AWPLUS_SHOW_VERSION)
        self.assertEqual(data["family"], "awplus")
        self.assertEqual(data["manufacturer"], "Allied Telesis")
        self.assertEqual(data["model"], "x510-28GTX")
        self.assertEqual(data["description"], "AlliedWare Plus 5.4.9")

    def test_edgeos_by_show_version(self) -> None:
        data = parse_show_version(EDGEOS_SHOW_VERSION)
        self.assertEqual(data["family"], "edgeos")
        self.assertEqual(data["model"], "EdgeRouter X 5-Port")
        self.assertEqual(data["serial"], "F09FC2123456")

    def test_edgeos_by_exec_is_told_apart_from_a_plain_linux(self) -> None:
        data = parse_linux(EDGEOS_LINUX)
        self.assertEqual(data["family"], "edgeos")
        self.assertEqual(data["manufacturer"], "Ubiquiti")
        self.assertEqual(data["hostname"], "er-oficina")
        self.assertEqual(data["interfaces"][0]["mac"], "f0:9f:c2:12:34:56")
        self.assertIn("test -x /opt/vyatta/bin/vyatta-op-cmd-wrapper", LINUX_COMMAND)

    def test_a_vyos_and_an_ordinary_linux_are_not_edgeos(self) -> None:
        self.assertNotIn("family", parse_linux(VYOS_LINUX))
        self.assertNotIn("family", parse_linux(LINUX_UBUNTU))

    def test_the_session_fallback_signs_the_new_families(self) -> None:
        for output, family in (
            (EXOS_SHOW_VERSION, "exos"),
            (ICX_SHOW_VERSION, "icx"),
            (AWPLUS_SHOW_VERSION, "awplus"),
            (EDGEOS_SHOW_VERSION, "edgeos"),
        ):
            self.assertEqual(parse_session(output)["family"], family)

    def test_each_parser_stays_mute_with_the_others_output(self) -> None:
        samples = {
            "exos": (parse_exos, EXOS_SHOW_VERSION),
            "icx": (parse_icx, ICX_SHOW_VERSION),
            "awplus": (parse_awplus, AWPLUS_SHOW_VERSION),
            "edgeos": (parse_edgeos, EDGEOS_SHOW_VERSION),
        }
        for name, (parse, _own) in samples.items():
            for other, (_p, output) in samples.items():
                if other != name:
                    self.assertEqual(parse(output), {}, f"{name} claimed {other}")

    def test_the_existing_show_version_families_keep_their_equipment(self) -> None:
        aruba_aos_s = (
            "Image stamp:    /ws/swbuildm/rel_yakima_qaoff/code/build/btm(swbuildm_rel_yakima_qaoff_rel_yakima)\n"
            "                Jan 29 2020 12:34:56\n"
            "                WB.16.10.0009\n"
            "ProCurve J9772A 2530-48G-PoEP\n"
        )
        dell_os6 = (
            "Machine Description............... Dell EMC Networking N1548P\n"
            "System Model ID................... N1548P\n"
            "Serial Number..................... CN0ABC123\n"
        )
        cases = (
            (CISCO_SHOW_VERSION, "cisco"),
            (JUNOS_SHOW_VERSION, "junos"),
            (ARUBA_SHOW_VERSION, "aruba"),
            (aruba_aos_s, "aruba"),
            (DELL_SHOW_VERSION, "dell"),
            (dell_os6, "dell"),
        )
        for output, family in cases:
            self.assertEqual(parse_show_version(output)["family"], family)

    def test_an_edgeswitch_ioslike_and_a_fortigate_are_not_edgeos(self) -> None:
        self.assertEqual(parse_edgeos(EDGESWITCH_IOSLIKE), {})
        self.assertEqual(parse_edgeos("Version: FortiGate-60F v7.2.5,build1517\nSerial-Number: X\n"), {})
        self.assertNotEqual(parse_show_version(EDGESWITCH_IOSLIKE).get("family"), "edgeos")

    def test_a_cisco_mentioning_extreme_is_still_a_cisco(self) -> None:
        output = CISCO_SHOW_VERSION + "interface to Extreme Networks switch\n"
        self.assertEqual(parse_show_version(output)["family"], "cisco")


class CaptureCommandTests(unittest.TestCase):
    def test_commands(self) -> None:
        self.assertEqual(CAPTURE_COMMANDS["exos"], "show configuration")
        self.assertEqual(CAPTURE_COMMANDS["icx"], "show running-config")
        self.assertEqual(CAPTURE_COMMANDS["awplus"], "show running-config")
        self.assertTrue(CAPTURE_COMMANDS["edgeos"].endswith("vyatta-op-cmd-wrapper show configuration"))

    def test_paging_is_switched_off_in_the_session_fallback(self) -> None:
        from agent import sshshell

        for command in ("disable clipaging", "skip-page-display", "set terminal length 0"):
            self.assertIn(command, sshshell.PAGING_OFF)


class CollectTests(unittest.TestCase):
    HOSTS = [{"ip": "192.168.1.9", "mac": "aa:bb:cc:dd:ee:09"}]

    def _collect(self, version_command: str, version_output: str, capture_output: str, family: str):
        capture = CAPTURE_COMMANDS[family]

        def fake_run(**kwargs: Any) -> ssh.Answer:
            command = kwargs["command"]
            if command == version_command:
                return ssh.Answer(connected=True, output=version_output)
            if command == capture:
                return ssh.Answer(connected=True, output=capture_output)
            # The Linux order and anything else: a CLI that refuses it.
            return ssh.Answer(connected=True, output="% Invalid input detected at '^' marker.\n")

        ctx = {
            "config": {"credentials": [{"kind": "ssh", "username": "admin", "key_file": "/k"}]},
            "env": None,
            "hosts": list(self.HOSTS),
            "errors": [],
        }
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", return_value=["192.168.1.9"]), \
             mock.patch("agent.collectors.ssh.ssh.run", fake_run):
            return SshCollector().collect(ctx), ctx

    def _check(self, version_command: str, version_output: str, config: str, family: str) -> None:
        findings, _ctx = self._collect(version_command, version_output, config, family)
        self.assertEqual([f.kind for f in findings], ["host", "config"])
        self.assertEqual(findings[0].payload["family"], family)
        copy = findings[1].payload
        self.assertEqual(copy["family"], family)
        self.assertEqual(copy["config"], config)
        self.assertNotIn("saved_config", copy)
        self.assertEqual(findings[1].identity, findings[0].identity)

    def test_exos(self) -> None:
        self._check("show version", EXOS_SHOW_VERSION, EXOS_CONFIG, "exos")

    def test_icx(self) -> None:
        self._check("show version", ICX_SHOW_VERSION, ICX_CONFIG, "icx")

    def test_awplus(self) -> None:
        self._check("show version", AWPLUS_SHOW_VERSION, AWPLUS_CONFIG, "awplus")

    def test_edgeos_reached_by_exec_as_a_linux(self) -> None:
        self._check(LINUX_COMMAND, EDGEOS_LINUX, EDGEOS_CONFIG, "edgeos")

    def test_an_empty_configuration_saves_nothing(self) -> None:
        for version_command, version_output, family in (
            ("show version", EXOS_SHOW_VERSION, "exos"),
            ("show version", ICX_SHOW_VERSION, "icx"),
            ("show version", AWPLUS_SHOW_VERSION, "awplus"),
            (LINUX_COMMAND, EDGEOS_LINUX, "edgeos"),
        ):
            findings, _ctx = self._collect(version_command, version_output, "  \n", family)
            self.assertEqual([f.kind for f in findings], ["host"], family)

    def test_a_refused_command_is_not_a_copy(self) -> None:
        for version_command, version_output, family in (
            ("show version", EXOS_SHOW_VERSION, "exos"),
            ("show version", ICX_SHOW_VERSION, "icx"),
            ("show version", AWPLUS_SHOW_VERSION, "awplus"),
            (LINUX_COMMAND, EDGEOS_LINUX, "edgeos"),
        ):
            for refusal in UNKNOWN_COMMAND_OUTPUTS:
                findings, _ctx = self._collect(version_command, version_output, refusal, family)
                self.assertEqual([f.kind for f in findings], ["host"], f"{family}: {refusal!r}")

    def test_a_refusal_explains_the_privilege_without_new_note_codes(self) -> None:
        findings, ctx = self._collect("show version", ICX_SHOW_VERSION, "Invalid input -> show running-config\n", "icx")
        self.assertEqual([f.kind for f in findings], ["host"])
        codes = {getattr(note, "code", None) or (note.get("code") if isinstance(note, dict) else None) for note in ctx["errors"]}
        self.assertEqual(codes - {None}, {"config_needs_privilege"})

    def test_a_dump_over_the_cap_is_dropped(self) -> None:
        big = "x" * (256 * 1024 + 1)
        findings, _ctx = self._collect("show version", EXOS_SHOW_VERSION, big, "exos")
        self.assertEqual([f.kind for f in findings], ["host"])

    def test_fetch_configs_needs_nothing_else(self) -> None:
        credential = Credential(kind="ssh", username="admin", key_file="/k")
        answer = ssh.Answer(connected=True, output=EXOS_CONFIG)
        with mock.patch("agent.collectors.ssh.ssh.run", return_value=answer):
            self.assertEqual(fetch_configs("10.0.0.1", credential, "exos"), {"config": EXOS_CONFIG})


if __name__ == "__main__":
    unittest.main()
