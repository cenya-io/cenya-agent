"""La tabla de perfiles de fabricante (`agent.profiles.PROFILES`).

Un perfil por fabricante, en el orden de importancia del contrato
(``docs/perfiles-snmp-contrato.md``): el orden manda en ``description_match``
(el primero que casa gana), así que no se reordena a la ligera.

Cada perfil lleva un comentario con la fuente de sus OIDs: la clase de
SNMP::Info (github.com/netdisco/snmp-info, BSD), la definición de LibreNMS
(``resources/definitions/os_discovery/<os>.yaml``) o la captura de LibreNMS
(``tests/snmpsim/<os>.snmprec``) donde ese OID contesta con un valor real.
Solo OIDs de hoja (``.0``): identificar cuesta un ``get`` más, nunca un ``walk``.
Los objetos tabulares que usan las referencias (``entPhysical*.1``,
``rlPhdUnitGenParam*.1``, ``hrDeviceDescr.1``, ``prtGeneralSerialNumber.1``)
quedan fuera a propósito; el chasis de ENTITY-MIB lo pide el motor.

Los perfiles que no se pudieron documentar con un ``sysDescr`` y un
``sysObjectID`` reales no están: Synology (sus NAS contestan con el
sysObjectID de Net-SNMP, ``8072.3.2.10``, y solo se distinguen con un ``get``
a su MIB) y QNAP ``55062`` (sin muestra). Las cámaras Hikvision entran por
``sysDescr`` porque unas dejan ``sysObjectID`` vacío y otras ponen un número
que no es suyo.
"""

from __future__ import annotations

from agent.profiles import Profile

PROFILES: tuple[Profile, ...] = (
    # --- Cisco -----------------------------------------------------------
    # SNMP::Info Layer3::Cisco (os_ver from sysDescr); model and serial from
    # ENTITY-MIB, as LibreNMS ios/iosxe do. The OS name comes from sysDescr:
    # "Cisco IOS Software" -> IOS, "Cisco IOS XE Software" -> IOS XE.
    Profile(
        key="cisco-ios",
        vendor="Cisco",
        enterprise=9,
        object_id_prefix="1.3.6.1.4.1.9.1",
        version_from_description=r"Version ([^,\s]+)",
        os_from_description=r"\b(IOS[ -]XE|IOS)\b",
    ),
    # SNMP::Info Layer3::Nexus (os_ver: "..., Version X,"); LibreNMS nxos
    # detects by "NX-OS" in sysDescr; model/serial from ENTITY-MIB.
    Profile(
        key="cisco-nxos",
        vendor="Cisco",
        description_match=r"NX-OS",
        os="NX-OS",
        version_from_description=r"Version ([^,\s]+)",
    ),
    # LibreNMS ciscosb: sysObjectID under 1.3.6.1.4.1.9.6.1 (SG/SF/SX/CBS),
    # Catalyst 1200/1300 under the classic 9.1 arc but "Catalyst 1x00 Series"
    # in sysDescr. Model from sysDescr (rlPhdUnitGenParamModelName is tabular).
    Profile(
        key="cisco-sb",
        vendor="Cisco",
        object_id_prefix="1.3.6.1.4.1.9.6.1",
        description_match=r"^Catalyst 1[23]00X? Series|^Linksys SLM",
        model_from_description=r"\b((?:S[GFX]\d{3}\w*|CBS\d{3}\w*|C1[23]00X?)-[\w-]+)",
        version_from_description=r"Version (\S+)",
    ),
    # LibreNMS merakims/merakimx/merakimr: "Meraki MX65W Cloud Managed Router",
    # "Meraki CW9166I Cloud Managed AP"; serial from ENTITY-MIB.
    Profile(
        key="meraki",
        vendor="Cisco Meraki",
        enterprise=29671,
        model_from_description=r"^(?:Meraki|Cisco Wireless) (\S+)",
    ),
    # --- HPE / Aruba -----------------------------------------------------
    # SNMP::Info Layer2::HP: serial2 hpHttpMgSerialNumber.0 (SEMI-MIB),
    # os_version hpSwitchOsVersion.0 (NETSWITCH-MIB); values in LibreNMS
    # procurve_e2910.snmprec. Model/revision regex from LibreNMS procurve.yaml.
    Profile(
        key="hp-procurve",
        vendor="HPE Aruba",
        object_id_prefix="1.3.6.1.4.1.11.2.3.7",
        os="ArubaOS-Switch",
        serial_oid="1.3.6.1.4.1.11.2.36.1.1.2.9.0",
        version_oid="1.3.6.1.4.1.11.2.14.11.5.1.1.3.0",
        model_from_description=r"^(?:HPE OfficeConnect Switch|HP ProCurve|Aruba|ProCurve|HPE|HP) (?:J\w{4}[AB] )?([^,\s]+)",
        version_from_description=r"revision ([^\s,]+)",
    ),
    # SNMP::Info Layer3::ArubaCX and LibreNMS arubaos-cx: everything from
    # ENTITY-MIB; the version is also in sysDescr ("... 8325 GL.10.04.2000").
    Profile(
        key="aruba-cx",
        vendor="HPE Aruba",
        enterprise=47196,
        os="AOS-CX",
        model_from_description=r"^Aruba \w+ (.+?) (?:Swch )?[A-Z]{2}\.\d{2}\.\d{2}\.\d{4}",
        version_from_description=r"\b([A-Z]{2}\.\d{2}\.\d{2}\.\d{4})\b",
    ),
    # SNMP::Info Layer3::H3C (os_ver "Software Version X, ... Release Y") and
    # LibreNMS comware.yaml; model/serial from ENTITY-MIB when sysDescr lacks it.
    Profile(
        key="hpe-comware",
        vendor="HPE",
        enterprise=25506,
        description_match=r"Comware",
        os="Comware",
        model_from_description=r"\b(?:HPE|HP|H3C) (?:FF )?([A-Z]?\d{4}\S*(?: [A-Z]{2})?) +Switch",
        version_from_description=r"Software Version ([\d.]+)",
    ),
    # --- Dell ------------------------------------------------------------
    # SNMP::Info Layer3::Dell: productIdentificationDisplayName.0 and
    # productIdentificationVersion.0 (Dell-Vendor-MIB); values in LibreNMS
    # powerconnect_2824.snmprec. Serial is tabular (.8.1.1): ENTITY-MIB.
    Profile(
        key="dell-os6",
        vendor="Dell",
        enterprise=674,
        object_id_prefix="1.3.6.1.4.1.674.10895",
        model_oid="1.3.6.1.4.1.674.10895.3000.1.2.100.1.0",
        version_oid="1.3.6.1.4.1.674.10895.3000.1.2.100.4.0",
        model_from_description=r"^(?:Dell (?:EMC )?Networking |PowerConnect )?([A-Z]?\d{4}[A-Z\d-]*)",
    ),
    # LibreNMS dell-os10: os10Chassis* are tabular (.1), so the newer sysDescr
    # ("OS Version: 10.6.1.0. System Type: S4128T-ON") and ENTITY-MIB do it.
    Profile(
        key="dell-os10",
        vendor="Dell",
        object_id_prefix="1.3.6.1.4.1.674.11000.5000.100",
        os="OS10",
        model_from_description=r"System Type: ([\w-]+)",
        version_from_description=r"OS Version: (\d[\d.]*?)\.?(?:\s|$)",
    ),
    # --- Netgear, TP-Link, Ubiquiti ---------------------------------------
    # SNMP::Info Layer2::Netgear: ng_gsmserial .10.1.1.1.4.0 and ng_gsmosver
    # .10.1.1.1.13.0 (GSM/FSM only); LibreNMS netgear.yaml regex
    # "GS724Tv4 ProSafe ..., 6.3.1.11, B1.0.0.4"; else ENTITY-MIB.
    Profile(
        key="netgear",
        vendor="Netgear",
        enterprise=4526,
        serial_oid="1.3.6.1.4.1.4526.10.1.1.1.4.0",
        version_oid="1.3.6.1.4.1.4526.10.1.1.1.13.0",
        model_from_description=r"^([A-Z]{2,3}\d{3,4}\S*) ",
        version_from_description=r", (\d[\d.]*), ",
    ),
    # LibreNMS jetstream.yaml: TPLINK-SYSINFO-MIB tpSysInfoHwVersion.0,
    # tpSysInfoSwVersion.0, tpSysInfoSerialNum.0; values in
    # jetstream_sg2218p.snmprec.
    Profile(
        key="tp-link",
        vendor="TP-Link",
        enterprise=11863,
        model_oid="1.3.6.1.4.1.11863.6.1.1.5.0",
        version_oid="1.3.6.1.4.1.11863.6.1.1.6.0",
        serial_oid="1.3.6.1.4.1.11863.6.1.1.8.0",
    ),
    # SNMP::Info Layer3::EdgeSwitch: EDGESWITCH-MIB agentInventoryGroup
    # (4413 is Broadcom FASTPATH, hence the sysDescr match, not the
    # enterprise): MachineType .2.0 (value "US-24-250W" in LibreNMS
    # edgeswitch_us-24-250w.snmprec), SerialNumber .4.0, SoftwareVersion .13.0.
    Profile(
        key="ubiquiti-edgeswitch",
        vendor="Ubiquiti",
        description_match=r"^(?:EdgeSwitch|EdgePoint|USW?[ -]|UBNT US)",
        model_oid="1.3.6.1.4.1.4413.1.1.1.1.1.2.0",
        serial_oid="1.3.6.1.4.1.4413.1.1.1.1.1.4.0",
        version_oid="1.3.6.1.4.1.4413.1.1.1.1.1.13.0",
        model_from_description=r"^((?:EdgeSwitch|EdgePoint Switch|US)[ \w-]*?)(?:,| firmware)",
        version_from_description=r", (?:firmware )?(\d[\w.]*)",
    ),
    # LibreNMS edgeos.yaml: UBNT-EdgeMAX-MIB ubntModel.0 and ubntVersion.0
    # (values in edgeos-ep.snmprec / edgeosolt.snmprec); "EdgeOS v1.8.0.…".
    Profile(
        key="ubiquiti-edgeos",
        vendor="Ubiquiti",
        object_id_prefix="1.3.6.1.4.1.41112.1.5",
        description_match=r"^(?:Ubiquiti )?EdgeOS|^EdgeRouter",
        os="EdgeOS",
        model_oid="1.3.6.1.4.1.41112.1.5.1.1.0",
        version_oid="1.3.6.1.4.1.41112.1.5.1.3.0",
        version_from_description=r"\bv(\d+\.\d+\.\d+)",
    ),
    # LibreNMS unifi.yaml: "UAP-nanoHD 5.60.3.12934", "UK-Ultra 6.6.77.15402";
    # sysObjectID is 41112 bare or Net-SNMP's.
    Profile(
        key="ubiquiti-unifi",
        vendor="Ubiquiti",
        enterprise=41112,
        description_match=r"^(?:UAP|U6|U7|E7|UK|U-LTE)[ -]",
        os="UniFi",
        model_from_description=r"^(\S+) ",
        version_from_description=r"^\S+ (\d[\d.]*)",
    ),
    # LibreNMS airos.yaml: sysObjectID 10002.1 or 41112.1.4 with a plain
    # "Linux …" sysDescr; nothing but the vendor comes out of it.
    Profile(
        key="ubiquiti-airos",
        vendor="Ubiquiti",
        enterprise=10002,
        object_id_prefix="1.3.6.1.4.1.41112.1.4",
        os="airOS",
    ),
    # --- MikroTik, Juniper -----------------------------------------------
    # SNMP::Info Layer3::Mikrotik: os_ver mtxrLicVersion, serial1
    # mtxrSystem.3.0; values in LibreNMS routeros_ccr2004-7.24.snmprec.
    # Model from "RouterOS <model> [<version> (<channel>)]".
    Profile(
        key="mikrotik",
        vendor="MikroTik",
        enterprise=14988,
        os="RouterOS",
        version_oid="1.3.6.1.4.1.14988.1.1.4.4.0",
        serial_oid="1.3.6.1.4.1.14988.1.1.7.3.0",
        model_from_description=r"^RouterOS\s+(.+?)(?:\s+v?\d+\.\d+[\w.]*(?:\s+\([\w-]+\))?)?\s*$",
    ),
    # SNMP::Info Layer3::Juniper: serial jnxBoxSerialNo (value in LibreNMS
    # junos_ex3300-12.3r4.6.snmprec), os_ver "kernel JUNOS X".
    Profile(
        key="juniper",
        vendor="Juniper",
        enterprise=2636,
        os="JunOS",
        serial_oid="1.3.6.1.4.1.2636.3.1.3.0",
        model_from_description=r"^Juniper Networks, Inc\. (\S+)",
        version_from_description=r"kernel JUNOS ([^,\s]+)",
    ),
    # --- Firewalls -------------------------------------------------------
    # LibreNMS fortigate.yaml: fgSysVersion.0 (value in fortigate.snmprec);
    # FORTINET-CORE-MIB fnSysSerial.0 (value in fortios.snmprec). Model from
    # ENTITY-MIB (entPhysicalModelName "FGT_100E").
    Profile(
        key="fortinet",
        vendor="Fortinet",
        enterprise=12356,
        os="FortiOS",
        version_oid="1.3.6.1.4.1.12356.101.4.1.1.0",
        serial_oid="1.3.6.1.4.1.12356.100.1.1.1.0",
    ),
    # SNMP::Info Layer3::PaloAlto: panSysSwVersion, panSysSerialNumber,
    # panChassisType; values in LibreNMS panos.snmprec.
    Profile(
        key="paloalto",
        vendor="Palo Alto Networks",
        enterprise=25461,
        os="PAN-OS",
        version_oid="1.3.6.1.4.1.25461.2.1.2.1.1.0",
        serial_oid="1.3.6.1.4.1.25461.2.1.2.1.3.0",
        model_oid="1.3.6.1.4.1.25461.2.1.2.2.1.0",
    ),
    # SNMP::Info Layer3::CheckPoint: svnVersion, svnApplianceSerialNumber,
    # svnApplianceProductName; osName (value "Gaia" in LibreNMS gaia_23900.snmprec).
    # The 1100/1400 appliances answer with Net-SNMP's sysObjectID and land in "linux".
    Profile(
        key="checkpoint",
        vendor="Check Point",
        enterprise=2620,
        version_oid="1.3.6.1.4.1.2620.1.6.4.1.0",
        serial_oid="1.3.6.1.4.1.2620.1.6.16.3.0",
        model_oid="1.3.6.1.4.1.2620.1.6.16.7.0",
        os_oid="1.3.6.1.4.1.2620.1.6.5.1.0",
    ),
    # SNMP::Info Layer3::Sophos: sfosDeviceType, sfosDeviceFWVersion,
    # sfosDeviceAppKey (its serial); values in LibreNMS sophos-xg_xgs2100.snmprec.
    Profile(
        key="sophos",
        vendor="Sophos",
        enterprise=2604,
        object_id_prefix="1.3.6.1.4.1.2604.5",
        os="SFOS",
        model_oid="1.3.6.1.4.1.2604.5.1.1.2.0",
        version_oid="1.3.6.1.4.1.2604.5.1.1.3.0",
        serial_oid="1.3.6.1.4.1.2604.5.1.1.4.0",
    ),
    # --- Huawei, D-Link, Allied Telesis ----------------------------------
    # Netdisco gets the Huawei model by translating sysObjectID with the
    # vendor MIB, which the agent has not got; LibreNMS (os_discovery/vrp.yaml)
    # asks hwEntitySystemModel.0 and hwProductName.0, the ESN for the serial
    # (hwDeviceEsn.0, HUAWEI-DEVICE-EXT-MIB = hwDatacomm 188), and reads the
    # banner with `\((?<hardware>[^)]+) (?<version>V\d{3}R\d{3}...)`.
    #
    # The banner is always «Huawei Versatile Routing Platform Software … VRP
    # (R) software, Version 5.170 (S5720 V200R019C10SPC500)»: the old regex
    # «the word after Huawei» read «Versatile» as the model on every VRP, and
    # that non-empty answer also stopped ENTITY-MIB from being asked. Now:
    # the first word when the banner starts with the model itself
    # («S2700-9TP-EI-AC Huawei Versatile…», LibreNMS vrp_4.snmprec, the full
    # name), else the family in the parentheses («S5720», «AR1220», «CE6850EI»).
    Profile(
        key="huawei",
        vendor="Huawei",
        enterprise=2011,
        os="VRP",
        model_oid="1.3.6.1.4.1.2011.5.25.31.6.5.0",  # hwEntitySystemModel.0
        serial_oid="1.3.6.1.4.1.2011.5.25.188.1.1.0",  # hwDeviceEsn.0
        model_from_description=(
            r"^(?!Huawei\b)(\S+)\s+Huawei Versatile Routing Platform"
            r"|\(([^)\s][^)]*?) V\d{3}R\d{3}[0-9A-Z]*\)"
        ),
        version_from_description=r"\b(V\d{3}R\d{3}[0-9A-Z]*)\b",
    ),
    # LibreNMS dlink.yaml: serial .171.12.1.1.12.0 (value in
    # dlink_dgs-3000-28x.snmprec), version probeSoftwareRev.0 (RMON2, value in
    # dlink_des-3526.snmprec); "WS6-DGS-1210-52/F1 6.10.007".
    Profile(
        key="dlink",
        vendor="D-Link",
        enterprise=171,
        serial_oid="1.3.6.1.4.1.171.12.1.1.12.0",
        version_oid="1.3.6.1.2.1.16.19.2.0",
        model_from_description=r"^(?:D-Link )?(\S+)",
        version_from_description=r"^\S+ (\d+\.\d+[\w.]*)",
    ),
    # LibreNMS awplus.yaml: "Allied Telesis router/switch, AW+ v5.4.7-2.1" /
    # "Software (AlliedWare Plus) Version 5.4.8-2.1"; model from ENTITY-MIB.
    Profile(
        key="allied-telesis",
        vendor="Allied Telesis",
        enterprise=207,
        os="AlliedWare Plus",
        version_from_description=r"(?:AW\+ v|Version )(\S+)",
    ),
    # --- UPS -------------------------------------------------------------
    # PowerNet-MIB: upsBasicIdentModel, upsAdvIdentFirmwareRevision,
    # upsAdvIdentSerialNumber; values in LibreNMS apc_smt750x-nmc2.snmprec.
    # On a PDU the UPS objects stay silent and "MN:<model>" in sysDescr serves.
    Profile(
        key="apc",
        vendor="APC",
        enterprise=318,
        model_oid="1.3.6.1.4.1.318.1.1.1.1.1.1.0",
        version_oid="1.3.6.1.4.1.318.1.1.1.1.2.1.0",
        serial_oid="1.3.6.1.4.1.318.1.1.1.1.2.3.0",
        model_from_description=r"\bMN:(\S+)",
    ),
    # XUPS-MIB: xupsIdentModel .1.1.2.0, xupsIdentSoftwareVersion .1.1.3.0
    # (.1.1.1.0 is xupsIdentManufacturer); values in LibreNMS
    # eatonups_eaton-connectups.snmprec. Serial: ENTITY-MIB when present.
    Profile(
        key="eaton",
        vendor="Eaton",
        enterprise=534,
        model_oid="1.3.6.1.4.1.534.1.1.2.0",
        version_oid="1.3.6.1.4.1.534.1.1.3.0",
    ),
    # --- NAS, hypervisors, generic hosts ---------------------------------
    # LibreNMS qnap.yaml (sysObjectID 24681) and NAS-MIB modelName
    # { systemInfo 12 } (no sample with a value; serial is tabular there).
    # QNAP fills ENTITY-MIB (entPhysicalMfgName "QNAP Systems").
    Profile(
        key="qnap",
        vendor="QNAP",
        enterprise=24681,
        model_oid="1.3.6.1.4.1.24681.1.2.12.0",
    ),
    # SNMP::Info Layer3::VMware: vmwProdName (os), vmwProdVersion; values in
    # LibreNMS vmware-esxi.snmprec. Hardware model/serial from ENTITY-MIB.
    Profile(
        key="vmware",
        vendor="VMware",
        enterprise=6876,
        os_oid="1.3.6.1.4.1.6876.1.1.0",
        version_oid="1.3.6.1.4.1.6876.1.2.0",
        os_from_description=r"^(VMware ESXi)\b",
        version_from_description=r"^VMware ESXi (\S+)",
    ),
    # SNMP::Info Layer3::NetSNMP (os_ver: third word of "Linux host 4.9.0 #1 …").
    # No vendor: the box could be anyone's. Not a sysDescr match on purpose,
    # so Check Point, Sophos XG or QNAP keep their enterprise.
    Profile(
        key="linux",
        vendor="",
        enterprise=8072,
        os="Linux",
        version_from_description=r"^Linux \S+ (\S+)",
    ),
    # SNMP::Info Layer3::Microsoft; LibreNMS windows.yaml. No vendor either:
    # the hardware maker is not Microsoft. Model/serial from ENTITY-MIB if any.
    Profile(
        key="windows",
        vendor="",
        enterprise=311,
        os="Windows",
        version_from_description=r"Software: Windows (?:NT )?Version ([\d.]+)",
    ),
    # LibreNMS zywall.yaml / zyxelnwa.yaml: ZYXEL-ES-COMMON sysSwVersionString.0,
    # sysProductModel.0, sysProductSerialNumber.0 (values in zynos.snmprec);
    # USG/ATP put the model in sysDescr ("USG20-VPN").
    Profile(
        key="zyxel",
        vendor="Zyxel",
        enterprise=890,
        version_oid="1.3.6.1.4.1.890.1.15.3.1.6.0",
        model_oid="1.3.6.1.4.1.890.1.15.3.1.11.0",
        serial_oid="1.3.6.1.4.1.890.1.15.3.1.12.0",
        model_from_description=r"^((?:ZyWALL \S+|(?:USG|NWA|ATP|VPN|NXC|WAX|WAC|GS|XGS|XS)[\w-]*))\s*$",
    ),
    # --- Printers --------------------------------------------------------
    # BROTHER-MIB: model name .2.4.3.2435.5.13.3.0 and serial
    # .2.3.9.4.2.1.5.5.1.0, both with values in LibreNMS brother.snmprec /
    # brother_hl5370dw.snmprec; firmware in sysDescr ("Firmware Ver.1.14").
    Profile(
        key="brother",
        vendor="Brother",
        enterprise=2435,
        model_oid="1.3.6.1.4.1.2435.2.4.3.2435.5.13.3.0",
        serial_oid="1.3.6.1.4.1.2435.2.3.9.4.2.1.5.5.1.0",
        version_from_description=r"Firmware Ver\.(\S+)",
    ),
    # LibreNMS jetdirect*.snmprec: sysObjectID 1.3.6.1.4.1.11.2.3.9.1 (the
    # 11.2.3.7 arc is ProCurve, hence the prefix), model after "PID:" in
    # "HP ETHERNET MULTI-ENVIRONMENT,SN:…,PID:HP LaserJet MFP M130nw".
    Profile(
        key="hp-printer",
        vendor="HP",
        object_id_prefix="1.3.6.1.4.1.11.2.3.9",
        model_from_description=r"\bPID:([^,]+)",
    ),
    # LibreNMS canonprinter.yaml: model .1602.1.1.1.1.0, version .1602.1.1.1.4.0
    # (values in canonprinter_lbp.snmprec); "Canon iR-ADV C5235 /P".
    Profile(
        key="canon",
        vendor="Canon",
        enterprise=1602,
        model_oid="1.3.6.1.4.1.1602.1.1.1.1.0",
        version_oid="1.3.6.1.4.1.1602.1.1.1.4.0",
        model_from_description=r"^Canon (.+?)\s*/P",
    ),
    # LibreNMS epson.snmprec: sysDescr "EPSON Built-in" says nothing; only the
    # vendor comes out (Printer-MIB objects are tabular).
    Profile(
        key="epson",
        vendor="Epson",
        enterprise=1248,
    ),
    # --- Cameras ---------------------------------------------------------
    # LibreNMS hikvision-cam.yaml: HIK-DEVICE-MIB deviceType.0 and
    # softwVersion.0 (values in hikvision-cam.snmprec, whose sysObjectID is
    # empty); NVRs say "Hikvision company products" with a sysObjectID that
    # is not Hikvision's (50001), hence the sysDescr match. 39165 is the IANA number.
    Profile(
        key="hikvision",
        vendor="Hikvision",
        enterprise=39165,
        description_match=r"^Hikvision company products",
        model_oid="1.3.6.1.4.1.39165.1.1.0",
        version_oid="1.3.6.1.4.1.39165.1.3.0",
    ),
    # DAHUA-SNMP-MIB: deviceType .2.1.2.6.0, serialNumber .2.1.2.4.0,
    # softwareRevision .2.1.1.1.0 (values in LibreNMS dahua-nvr.snmprec). The
    # devices report 1004849 although IANA lists Dahua as 37496.
    Profile(
        key="dahua",
        vendor="Dahua",
        enterprise=1004849,
        model_oid="1.3.6.1.4.1.1004849.2.1.2.6.0",
        serial_oid="1.3.6.1.4.1.1004849.2.1.2.4.0",
        version_oid="1.3.6.1.4.1.1004849.2.1.1.1.0",
        model_from_description=r"^(DH-\S+)",
    ),
    # LibreNMS axiscam.yaml: "; AXIS P5534-E; PTZ Dome Network Camera; 5.40.9.2; …".
    Profile(
        key="axis",
        vendor="Axis",
        enterprise=368,
        os="AXIS OS",
        model_from_description=r";\s*(AXIS [^;]+?)\s*;",
        version_from_description=r"^;[^;]*;[^;]*;\s*([^;]+?)\s*;",
    ),
)
