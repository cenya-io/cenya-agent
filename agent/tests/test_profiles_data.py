"""La tabla de perfiles (`agent.profiles_data`) contra muestras reales.

Un test por perfil con un ``sysDescr`` y un ``sysObjectID`` capturados de
equipos de verdad (las capturas de LibreNMS en ``tests/snmpsim/<os>.snmprec``,
que guardan sysDescr en 1.3.6.1.2.1.1.1.0 y sysObjectID en 1.3.6.1.2.1.1.2.0,
salvo donde se indica otra fuente): ``resolve`` tiene que elegir ese perfil y,
cuando el perfil promete modelo, versión o sistema por regex, ``identify`` los
saca de la descripción. Después, las reglas de forma de toda la tabla.
"""

from __future__ import annotations

import re
import unittest

from agent.profiles import Profile, identify, resolve
from agent.profiles_data import PROFILES

BY_KEY: dict[str, Profile] = {profile.key: profile for profile in PROFILES}

#: One real (sysObjectID, sysDescr) per profile, the same ones the per-profile
#: tests use, so the ambiguity test can cross every description_match with
#: every other profile's sample.
SAMPLES: dict[str, tuple[str, str]] = {
    # LibreNMS tests/snmpsim/ios_2960x.snmprec
    "cisco-ios": (
        "1.3.6.1.4.1.9.1.1208",
        "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.0(2a)EX5, "
        "RELEASE SOFTWARE (fc3)\nTechnical Support: http://www.cisco.com/techsupport\r\n"
        "Copyright (c) 1986-2015 by Cisco Systems, Inc.",
    ),
    # LibreNMS tests/snmpsim/nxos_lag-mib.snmprec
    "cisco-nxos": (
        "1.3.6.1.4.1.9.12.3.1.3.1955",
        "Cisco NX-OS(tm) Nexus9000 C9336C-FX2, Software (NXOS 64-bit), Version 10.2(3), "
        "RELEASE SOFTWARE Copyright (c) 2002-2022 by Cisco Systems, Inc. Compiled 4/24/2022 3:00:00",
    ),
    # LibreNMS tests/snmpsim/ciscosb_cbs250-24p-4x-v3.snmprec
    "cisco-sb": (
        "1.3.6.1.4.1.9.6.1.1005.24.5",
        "CBS250-24P-4X 24-Port Gigabit PoE Smart Switch with 10G Uplinks",
    ),
    # LibreNMS tests/snmpsim/merakimx.snmprec
    "meraki": ("1.3.6.1.4.1.29671.2.111", "Meraki MX65W Cloud Managed Router"),
    # LibreNMS tests/snmpsim/procurve_131.snmprec
    "hp-procurve": (
        "1.3.6.1.4.1.11.2.3.7.11.131",
        "HP J9625A 2620-24-PoEP Switch, revision RA.16.02.0012, ROM RA.15.13 "
        "(/ws/swbuildm/rel_spokane_qaoff/code/build/xform(swbuildm_rel_spokane_qaoff_rel_spokane))",
    ),
    # LibreNMS tests/snmpsim/arubaos-cx_10.07.snmprec
    "aruba-cx": (
        "1.3.6.1.4.1.47196.4.1.1.1.303",
        "Aruba JL727A 6200F 48G CL4 4SFP+370W Swch ML.10.07.0005",
    ),
    # LibreNMS tests/snmpsim/comware.snmprec
    "hpe-comware": (
        "1.3.6.1.4.1.25506.11.1.172",
        "HP Comware Platform Software, Software Version 7.1.045, Release 2416 HP FF 5700-40XG-2QSFP  "
        "Switch Copyright (c) 2010-2014 Hewlett-Packard Development Company, L.P.",
    ),
    # LibreNMS tests/snmpsim/powerconnect_2824.snmprec (sysObjectID) and the
    # Dell-Vendor-MIB display name it answers, "PowerConnect 2824", which N-series
    # firmware also prints at the head of sysDescr.
    "dell-os6": ("1.3.6.1.4.1.674.10895.3000", "PowerConnect 2824"),
    # LibreNMS tests/snmpsim/dell-os10_s4128ton-psu.snmprec
    "dell-os10": (
        "1.3.6.1.4.1.674.11000.5000.100.2.1.9",
        "Dell SmartFabric OS10 Enterprise.\nCopyright (c) 1999-2025 by Dell Inc. All Rights Reserved.\r\n"
        "System Description: OS10 Enterprise.\r\nOS Version: 10.6.1.0.\r\nSystem Type: S4128T-ON",
    ),
    # LibreNMS tests/snmpsim/netgear.snmprec
    "netgear": (
        "1.3.6.1.4.1.4526.100.4.32",
        "GS724Tv4 ProSafe 24-port Gigabit Ethernet Smart Switch, 6.3.1.11, B1.0.0.4",
    ),
    # LibreNMS tests/snmpsim/jetstream.snmprec
    "tp-link": ("1.3.6.1.4.1.11863.5.34", "JetStream 48-Port Gigabit L2 Managed Switch with 4 SFP Slots"),
    # LibreNMS tests/snmpsim/edgeswitch.snmprec
    "ubiquiti-edgeswitch": ("1.3.6.1.4.1.4413", "EdgeSwitch 24-Port 250W, 1.0.1.4720839, Linux 3.6.5-f4a26ed5"),
    # LibreNMS tests/snmpsim/edgeos.snmprec
    "ubiquiti-edgeos": ("1.3.6.1.4.1.41112.1.5", "EdgeOS v1.8.0.4853089.160219.1607"),
    # LibreNMS tests/snmpsim/unifi_560.snmprec
    "ubiquiti-unifi": ("1.3.6.1.4.1.41112", "UAP-nanoHD 5.60.3.12934"),
    # LibreNMS tests/snmpsim/airos.snmprec
    "ubiquiti-airos": ("1.3.6.1.4.1.10002.1", "Linux 2.6.32.68 #1 Fri Dec 16 15:44:21 EET 2016 mips"),
    # LibreNMS tests/snmpsim/routeros_ccr2004-7.24.snmprec
    "mikrotik": ("1.3.6.1.4.1.14988.1", "RouterOS CCR2004-1G-12S+2XS 7.24.2 (stable)"),
    # LibreNMS tests/snmpsim/junos_ex.snmprec
    "juniper": (
        "1.3.6.1.4.1.2636.1.1.1.4.131.2",
        "Juniper Networks, Inc. ex3400-48t Ethernet Switch, kernel JUNOS 15.1X53-D59.4, "
        "Build date: 2018-09-14 21:00:55 UTC Copyright (c) 1996-2018 Juniper Networks, Inc.",
    ),
    # LibreNMS tests/snmpsim/fortigate_1.snmprec
    "fortinet": ("1.3.6.1.4.1.12356.101.1.2003", "FORTIGATE 200B"),
    # LibreNMS tests/snmpsim/panos_440.snmprec
    "paloalto": ("1.3.6.1.4.1.25461.2.3.54", "Palo Alto Networks PA-400 series firewall"),
    # LibreNMS tests/snmpsim/gaia_1.snmprec
    "checkpoint": (
        "1.3.6.1.4.1.2620.1.6.123.1.49",
        "Linux gw1-ckp-gaia 2.6.18-92cpx86_64 #1 SMP Tue Sep 4 13:46:30 IDT 2018 x86_64",
    ),
    # LibreNMS tests/snmpsim/sophos-xg_xgs2100.snmprec
    "sophos": ("1.3.6.1.4.1.2604.5", "Linux localhost 6.6.116 #1 SMP Wed Jun  3 08:00:50 CDT 2026 x86_64"),
    # LibreNMS tests/snmpsim/vrp.snmprec
    "huawei": (
        "1.3.6.1.4.1.2011.2.224.1",
        "Huawei AR1220 Huawei Versatile Routing Platform Software  VRP (R) software,Version 5.120 "
        "(AR1220 V200R003C01SPC900) Copyright (C) 2011-2013 Huawei Technologies Co., Ltd",
    ),
    # LibreNMS tests/snmpsim/dlink.snmprec
    "dlink": ("1.3.6.1.4.1.171.10.153.7.1", "WS6-DGS-1210-52/F1 6.10.007"),
    # LibreNMS tests/snmpsim/awplus_5.4.8-2.snmprec
    "allied-telesis": (
        "1.3.6.1.4.1.207.1.14.120",
        "Allied Telesis router/switch, Software (AlliedWare Plus) Version 5.4.8-2.1",
    ),
    # LibreNMS tests/snmpsim/apc_ap7900b.snmprec
    "apc": (
        "1.3.6.1.4.1.318.1.3.4.8",
        "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.8.2 PN:apc_hw05_aos_682.bin AF1:v6.8.0 "
        "AN1:apc_hw05_rpdu2g_680.bin MN:AP7900B HR:B2 SN: ZA1732000177 MD:08/07/2017) ",
    ),
    # LibreNMS tests/snmpsim/eatonups.snmprec
    "eaton": ("1.3.6.1.4.1.534.1", "ConnectUPS Web/SNMP Card V4.38"),
    # LibreNMS tests/snmpsim/qnap.snmprec
    "qnap": ("1.3.6.1.4.1.24681", "Linux hostname 4.2.2"),
    # LibreNMS tests/snmpsim/vmware-esxi.snmprec
    "vmware": ("1.3.6.1.4.1.6876.4.1", "VMware ESXi 7.0.0 build-15843807 VMware, Inc. x86_64"),
    # LibreNMS tests/snmpsim/linux_asterisk-v1.snmprec
    "linux": (
        "1.3.6.1.4.1.8072.3.2.10",
        "Linux joseph.tingiris 3.10.0-693.17.1.el7.x86_64 #1 SMP Thu Jan 25 20:13:58 UTC 2018 x86_64",
    ),
    # LibreNMS tests/snmpsim/windows.snmprec
    "windows": (
        "1.3.6.1.4.1.311.1.1.3.1.2",
        "Hardware: Intel64 Family 6 Model 26 Stepping 4 AT/AT COMPATIBLE - Software: Windows Version 6.1 "
        "(Build 7601 Multiprocessor Free)",
    ),
    # LibreNMS tests/snmpsim/zywall_usg20-vpn.snmprec
    "zyxel": ("1.3.6.1.4.1.890.1.15", "USG20-VPN"),
    # LibreNMS tests/snmpsim/brother.snmprec
    "brother": ("1.3.6.1.4.1.2435.2.3.9.1", "Brother NC-8300h, Firmware Ver.1.14  (14.11.06),MID 8C5-F01,FID 2"),
    # LibreNMS tests/snmpsim/jetdirect_m130nw.snmprec
    "hp-printer": (
        "1.3.6.1.4.1.11.2.3.9.1",
        "HP ETHERNET MULTI-ENVIRONMENT,SN:VNCRC48198,FN:4Q817L4,SVCID:31339,PID:HP LaserJet MFP M130nw",
    ),
    # LibreNMS tests/snmpsim/canonprinter_ir-adv.snmprec
    "canon": ("1.3.6.1.4.1.1602.4.7", "Canon iR-ADV C5235 /P"),
    # LibreNMS tests/snmpsim/epson.snmprec
    "epson": ("1.3.6.1.4.1.1248.1.1.2.1.3.5.69.69.80.83.50", "EPSON Built-in"),
    # LibreNMS tests/snmpsim/hikvision-nvr.snmprec (the NVR's sysObjectID is not Hikvision's)
    "hikvision": ("1.3.6.1.4.1.50001", "Hikvision company products"),
    # LibreNMS tests/snmpsim/dahua-nvr.snmprec
    "dahua": ("1.3.6.1.4.1.1004849.3.2.10", "DH-NVR4108HS-8P-4KS2"),
    # LibreNMS tests/snmpsim/axiscam.snmprec
    "axis": ("1.3.6.1.4.1.368", "; AXIS P5534-E; PTZ Dome Network Camera; 5.40.9.2; May 15 2012 09:50; 188.1; 1;"),
}


class ProfileTestCase(unittest.TestCase):
    def resolved(self, key: str) -> Profile:
        """The profile `resolve` picks for the sample of *key*, asserted to be *key*."""
        object_id, description = SAMPLES[key]
        profile = resolve(object_id, description)
        self.assertIsNotNone(profile, f"{key}: nobody resolved the sample")
        assert profile is not None
        self.assertEqual(profile.key, key)
        return profile

    def identity(self, key: str):
        profile = self.resolved(key)
        return identify(profile, SAMPLES[key][1], {}, {})


class CiscoTests(ProfileTestCase):
    def test_cisco_ios(self) -> None:
        identity = self.identity("cisco-ios")
        self.assertEqual(identity.manufacturer, "Cisco")
        self.assertEqual(identity.os, "IOS")
        self.assertEqual(identity.os_version, "15.0(2a)EX5")

    def test_cisco_ios_xe_names_itself(self) -> None:
        # Capture of a Catalyst 9200 on IOS-XE 17.9 (agent/tests/test_stacks.py).
        description = (
            "Cisco IOS XE Software, Version 17.09.04\n"
            "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), "
            "Version 17.9.4, RELEASE SOFTWARE (fc5)"
        )
        profile = resolve("1.3.6.1.4.1.9.1.2695", description)
        assert profile is not None
        self.assertEqual(profile.key, "cisco-ios")
        identity = identify(profile, description, {}, {})
        self.assertEqual(identity.os, "IOS XE")
        self.assertEqual(identity.os_version, "17.09.04")

    def test_cisco_nxos(self) -> None:
        identity = self.identity("cisco-nxos")
        self.assertEqual(identity.os, "NX-OS")
        self.assertEqual(identity.os_version, "10.2(3)")

    def test_cisco_sb(self) -> None:
        identity = self.identity("cisco-sb")
        self.assertEqual(identity.model, "CBS250-24P-4X")
        self.assertEqual(identity.os_version, "")

    def test_cisco_sb_catalyst_1200_lives_under_the_classic_arc(self) -> None:
        # LibreNMS tests/snmpsim/ciscosb_c1200-8t-e-2g.snmprec
        description = "Catalyst 1200 Series Smart Switch, 8-port GE, Ext PS, 2x1G Combo (C1200-8T-E-2G)"
        profile = resolve("1.3.6.1.4.1.9.1.3211", description)
        assert profile is not None
        self.assertEqual(profile.key, "cisco-sb")
        self.assertEqual(identify(profile, description, {}, {}).model, "C1200-8T-E-2G")

    def test_cisco_sb_sg_series(self) -> None:
        # LibreNMS tests/snmpsim/ciscosb_sf20048.snmprec
        description = "SG550XG-24F 24-Port 10G SFP  Stackable Managed Switch"
        profile = resolve("1.3.6.1.4.1.9.6.1.90.24.8", description)
        assert profile is not None
        self.assertEqual(profile.key, "cisco-sb")
        self.assertEqual(identify(profile, description, {}, {}).model, "SG550XG-24F")

    def test_meraki(self) -> None:
        identity = self.identity("meraki")
        self.assertEqual(identity.manufacturer, "Cisco Meraki")
        self.assertEqual(identity.model, "MX65W")


class HpeTests(ProfileTestCase):
    def test_hp_procurve(self) -> None:
        identity = self.identity("hp-procurve")
        self.assertEqual(identity.model, "2620-24-PoEP")
        self.assertEqual(identity.os_version, "RA.16.02.0012")
        self.assertEqual(identity.os, "ArubaOS-Switch")

    def test_hp_procurve_stack_arc(self) -> None:
        # LibreNMS tests/snmpsim/procurve.snmprec
        profile = resolve("1.3.6.1.4.1.11.2.3.7.8.5.2", "HP Stack, revision KA.00.00.0000")
        assert profile is not None
        self.assertEqual(profile.key, "hp-procurve")

    def test_aruba_cx(self) -> None:
        identity = self.identity("aruba-cx")
        self.assertEqual(identity.model, "6200F 48G CL4 4SFP+370W")
        self.assertEqual(identity.os_version, "ML.10.07.0005")

    def test_aruba_cx_short_description(self) -> None:
        # LibreNMS tests/snmpsim/arubaos-cx.snmprec
        description = "Aruba JL635A 8325 GL.10.04.2000"
        profile = resolve("1.3.6.1.4.1.47196.4.1.1.1.50", description)
        assert profile is not None
        identity = identify(profile, description, {}, {})
        self.assertEqual(identity.model, "8325")
        self.assertEqual(identity.os_version, "GL.10.04.2000")

    def test_hpe_comware(self) -> None:
        identity = self.identity("hpe-comware")
        self.assertEqual(identity.model, "5700-40XG-2QSFP")
        self.assertEqual(identity.os_version, "7.1.045")
        self.assertEqual(identity.os, "Comware")


class DellTests(ProfileTestCase):
    def test_dell_os6(self) -> None:
        identity = self.identity("dell-os6")
        self.assertEqual(identity.manufacturer, "Dell")
        self.assertEqual(identity.model, "2824")

    def test_dell_os10(self) -> None:
        identity = self.identity("dell-os10")
        self.assertEqual(identity.model, "S4128T-ON")
        self.assertEqual(identity.os_version, "10.6.1.0")
        self.assertEqual(identity.os, "OS10")


class SmallVendorSwitchTests(ProfileTestCase):
    def test_netgear(self) -> None:
        identity = self.identity("netgear")
        self.assertEqual(identity.model, "GS724Tv4")
        self.assertEqual(identity.os_version, "6.3.1.11")

    def test_tp_link(self) -> None:
        identity = self.identity("tp-link")
        self.assertEqual(identity.manufacturer, "TP-Link")

    def test_ubiquiti_edgeswitch(self) -> None:
        identity = self.identity("ubiquiti-edgeswitch")
        self.assertEqual(identity.model, "EdgeSwitch 24-Port 250W")
        self.assertEqual(identity.os_version, "1.0.1.4720839")

    def test_ubiquiti_edgeos(self) -> None:
        identity = self.identity("ubiquiti-edgeos")
        self.assertEqual(identity.os, "EdgeOS")
        self.assertEqual(identity.os_version, "1.8.0")

    def test_ubiquiti_unifi(self) -> None:
        identity = self.identity("ubiquiti-unifi")
        self.assertEqual(identity.model, "UAP-nanoHD")
        self.assertEqual(identity.os_version, "5.60.3.12934")

    def test_ubiquiti_airos(self) -> None:
        identity = self.identity("ubiquiti-airos")
        self.assertEqual(identity.manufacturer, "Ubiquiti")
        self.assertEqual(identity.os, "airOS")

    def test_mikrotik(self) -> None:
        identity = self.identity("mikrotik")
        self.assertEqual(identity.model, "CCR2004-1G-12S+2XS")
        self.assertEqual(identity.os, "RouterOS")

    def test_mikrotik_model_without_version(self) -> None:
        # LibreNMS tests/snmpsim/routeros_1.snmprec
        profile = BY_KEY["mikrotik"]
        self.assertEqual(identify(profile, "RouterOS RB951G-2HnD", {}, {}).model, "RB951G-2HnD")
        # LibreNMS tests/snmpsim/routeros.snmprec: a sysDescr somebody typed
        self.assertEqual(identify(profile, "router", {}, {}).model, "")

    def test_juniper(self) -> None:
        identity = self.identity("juniper")
        self.assertEqual(identity.model, "ex3400-48t")
        self.assertEqual(identity.os_version, "15.1X53-D59.4")
        self.assertEqual(identity.os, "JunOS")


class FirewallTests(ProfileTestCase):
    def test_fortinet(self) -> None:
        identity = self.identity("fortinet")
        self.assertEqual(identity.manufacturer, "Fortinet")
        self.assertEqual(identity.os, "FortiOS")

    def test_paloalto(self) -> None:
        identity = self.identity("paloalto")
        self.assertEqual(identity.manufacturer, "Palo Alto Networks")
        self.assertEqual(identity.os, "PAN-OS")

    def test_checkpoint(self) -> None:
        identity = self.identity("checkpoint")
        self.assertEqual(identity.manufacturer, "Check Point")
        # The OS name is an OID answer, never the "Linux ..." description.
        self.assertEqual(identity.os, "")

    def test_sophos(self) -> None:
        identity = self.identity("sophos")
        self.assertEqual(identity.manufacturer, "Sophos")
        self.assertEqual(identity.os, "SFOS")


class OtherNetworkTests(ProfileTestCase):
    def test_huawei(self) -> None:
        identity = self.identity("huawei")
        self.assertEqual(identity.model, "AR1220")
        self.assertEqual(identity.os_version, "V200R003C01SPC900")
        self.assertEqual(identity.os, "VRP")

    def test_huawei_banner_that_starts_with_the_model(self) -> None:
        # LibreNMS tests/snmpsim/vrp_4.snmprec: the full model comes first,
        # and the old «word after Huawei» regex returned «Versatile».
        profile = BY_KEY["huawei"]
        description = (
            "S2700-9TP-EI-AC Huawei Versatile Routing Platform Software VRP (R) software,"
            "Version 5.70 (S2700 V100R006C05) Copyright (C) 2003-2013 Huawei Technologies Co., Ltd."
        )
        identity = identify(profile, description, {}, {})
        self.assertEqual(identity.model, "S2700-9TP-EI-AC")
        self.assertEqual(identity.os_version, "V100R006C05")

    def test_huawei_banner_with_line_breaks(self) -> None:
        # What a switch answers verbatim: CRLF between the lines.
        profile = BY_KEY["huawei"]
        description = (
            "S5720-28X-SI-AC\r\nHuawei Versatile Routing Platform Software\r\n"
            "VRP (R) software, Version 5.170 (S5720 V200R019C10SPC500)\r\n"
            "Copyright (C) 2000-2020 HUAWEI TECH CO., LTD"
        )
        identity = identify(profile, description, {}, {})
        self.assertEqual(identity.model, "S5720-28X-SI-AC")
        self.assertEqual(identity.os_version, "V200R019C10SPC500")

    def test_huawei_banner_without_a_model_line_falls_back_to_the_family(self) -> None:
        # CloudEngine / AR: only the family inside the parentheses, never «Versatile».
        profile = BY_KEY["huawei"]
        description = (
            "Huawei Versatile Routing Platform Software\r\nVRP (R) software, Version 8.180 "
            "(CE6850EI V200R005C10SPC800)\r\nCopyright (C) 2012-2018 Huawei Technologies Co., Ltd."
        )
        identity = identify(profile, description, {}, {})
        self.assertEqual(identity.model, "CE6850EI")
        self.assertEqual(identity.os_version, "V200R005C10SPC800")

    def test_huawei_oids_and_entity_beat_the_banner(self) -> None:
        # hwEntitySystemModel / hwDeviceEsn first; the ENTITY-MIB chassis fills
        # what the OIDs and the banner left empty.
        profile = BY_KEY["huawei"]
        description = (
            "Huawei Versatile Routing Platform Software VRP (R) software, "
            "Version 5.170 (S5720 V200R019C10SPC500)"
        )
        identity = identify(
            profile, description, {"model": "S5720-28X-SI-AC", "serial": "2102350DLE10J4000123"}, {}
        )
        self.assertEqual((identity.model, identity.serial), ("S5720-28X-SI-AC", "2102350DLE10J4000123"))
        identity = identify(profile, description, {}, {"serial": "2102350DLE10J4000123"})
        self.assertEqual((identity.model, identity.serial), ("S5720", "2102350DLE10J4000123"))

    def test_dlink(self) -> None:
        identity = self.identity("dlink")
        self.assertEqual(identity.model, "WS6-DGS-1210-52/F1")
        self.assertEqual(identity.os_version, "6.10.007")

    def test_allied_telesis(self) -> None:
        identity = self.identity("allied-telesis")
        self.assertEqual(identity.os_version, "5.4.8-2.1")
        # LibreNMS tests/snmpsim/awplus.snmprec, the older wording
        self.assertEqual(
            identify(BY_KEY["allied-telesis"], "Allied Telesis router/switch, AW+ v5.4.7-2.1", {}, {}).os_version,
            "5.4.7-2.1",
        )


class PowerTests(ProfileTestCase):
    def test_apc(self) -> None:
        identity = self.identity("apc")
        self.assertEqual(identity.model, "AP7900B")

    def test_eaton(self) -> None:
        identity = self.identity("eaton")
        self.assertEqual(identity.manufacturer, "Eaton")


class HostTests(ProfileTestCase):
    def test_qnap(self) -> None:
        identity = self.identity("qnap")
        self.assertEqual(identity.manufacturer, "QNAP")

    def test_vmware(self) -> None:
        identity = self.identity("vmware")
        self.assertEqual(identity.os, "VMware ESXi")
        self.assertEqual(identity.os_version, "7.0.0")

    def test_linux(self) -> None:
        identity = self.identity("linux")
        self.assertEqual(identity.manufacturer, "")
        self.assertEqual(identity.os, "Linux")
        self.assertEqual(identity.os_version, "3.10.0-693.17.1.el7.x86_64")

    def test_windows(self) -> None:
        identity = self.identity("windows")
        self.assertEqual(identity.manufacturer, "")
        self.assertEqual(identity.os, "Windows")
        self.assertEqual(identity.os_version, "6.1")

    def test_zyxel(self) -> None:
        identity = self.identity("zyxel")
        self.assertEqual(identity.model, "USG20-VPN")


class PrinterTests(ProfileTestCase):
    def test_brother(self) -> None:
        identity = self.identity("brother")
        self.assertEqual(identity.os_version, "1.14")

    def test_hp_printer(self) -> None:
        identity = self.identity("hp-printer")
        self.assertEqual(identity.manufacturer, "HP")
        self.assertEqual(identity.model, "HP LaserJet MFP M130nw")

    def test_canon(self) -> None:
        identity = self.identity("canon")
        self.assertEqual(identity.model, "iR-ADV C5235")

    def test_epson(self) -> None:
        identity = self.identity("epson")
        self.assertEqual(identity.manufacturer, "Epson")


class CameraTests(ProfileTestCase):
    def test_hikvision(self) -> None:
        identity = self.identity("hikvision")
        self.assertEqual(identity.manufacturer, "Hikvision")

    def test_dahua(self) -> None:
        identity = self.identity("dahua")
        self.assertEqual(identity.model, "DH-NVR4108HS-8P-4KS2")

    def test_axis(self) -> None:
        identity = self.identity("axis")
        self.assertEqual(identity.model, "AXIS P5534-E")
        self.assertEqual(identity.os_version, "5.40.9.2")


class TableShapeTests(unittest.TestCase):
    """Rules every row of the table keeps."""

    def test_every_profile_has_a_sample_and_every_sample_a_profile(self) -> None:
        self.assertEqual(set(SAMPLES), set(BY_KEY))

    def test_keys_are_unique_and_lowercase(self) -> None:
        keys = [profile.key for profile in PROFILES]
        self.assertEqual(len(keys), len(set(keys)))
        for key in keys:
            self.assertEqual(key, key.lower())
            self.assertRegex(key, r"^[a-z0-9-]+$")

    def test_vendor_or_os_is_always_there(self) -> None:
        # A profile that names neither a vendor nor an OS would identify nothing.
        for profile in PROFILES:
            with self.subTest(profile.key):
                self.assertTrue(profile.vendor or profile.os or profile.os_oid or profile.os_from_description)

    def test_enterprise_is_a_positive_integer(self) -> None:
        for profile in PROFILES:
            with self.subTest(profile.key):
                if profile.enterprise is not None:
                    self.assertIsInstance(profile.enterprise, int)
                    self.assertGreater(profile.enterprise, 0)
                self.assertTrue(
                    profile.enterprise or profile.object_id_prefix or profile.description_match,
                    "a profile with no way to be chosen",
                )

    def test_object_id_prefixes_are_bare_arcs(self) -> None:
        for profile in PROFILES:
            with self.subTest(profile.key):
                if profile.object_id_prefix:
                    self.assertRegex(profile.object_id_prefix, r"^1\.3\.6\.1\.4\.1(\.\d+)+$")

    def test_profile_oids_are_leaves(self) -> None:
        for profile in PROFILES:
            for name in ("serial_oid", "model_oid", "version_oid", "os_oid"):
                oid = getattr(profile, name)
                if not oid:
                    continue
                with self.subTest(f"{profile.key}.{name}"):
                    self.assertRegex(oid, r"^1\.3\.6\.1(\.\d+)+\.0$")

    def test_regexes_compile_and_extractors_have_a_group(self) -> None:
        # At least one: `_extract` takes the first group that matched, so a
        # pattern with alternatives carries one group per alternative.
        for profile in PROFILES:
            with self.subTest(profile.key):
                if profile.description_match:
                    re.compile(profile.description_match)
                for name in ("model_from_description", "version_from_description", "os_from_description"):
                    pattern = getattr(profile, name)
                    if pattern:
                        self.assertGreaterEqual(re.compile(pattern).groups, 1, f"{profile.key}.{name}")

    def test_description_matches_do_not_cross_samples(self) -> None:
        """No profile's description_match fires on another profile's real sysDescr."""
        for profile in PROFILES:
            if not profile.description_match:
                continue
            pattern = re.compile(profile.description_match, re.IGNORECASE)
            for key, (_, description) in SAMPLES.items():
                if key == profile.key:
                    continue
                with self.subTest(f"{profile.key} vs {key}"):
                    self.assertIsNone(pattern.search(description))

    def test_each_sample_resolves_to_its_own_profile(self) -> None:
        for key, (object_id, description) in SAMPLES.items():
            with self.subTest(key):
                profile = resolve(object_id, description)
                self.assertIsNotNone(profile)
                assert profile is not None
                self.assertEqual(profile.key, key)

    def test_identify_never_leaks_sysdescr_as_os(self) -> None:
        for key, (object_id, description) in SAMPLES.items():
            with self.subTest(key):
                identity = identify(resolve(object_id, description), description, {}, {})
                self.assertNotEqual(identity.os, description)
                self.assertLess(len(identity.os), 40)


if __name__ == "__main__":
    unittest.main()
