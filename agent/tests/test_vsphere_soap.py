"""El cliente SOAP mínimo de vSphere (`agent/vsphere_soap.py`).

Las respuestas son XML con la forma que da un vCenter de verdad: espacios de
nombres, `xsi:type` en los elementos polimórficos y listas como hijos
repetidos. Si el análisis se equivoca, un datastore iSCSI llega como «origen
desconocido» y la traza se queda sin cabina sin que nadie lo note.
"""

from __future__ import annotations

import io
import unittest
import urllib.error
import xml.etree.ElementTree as ET
from typing import Any
from unittest import mock

from agent import hypervisor, vsphere_soap
from agent.hypervisor import HypervisorError, VMwareClient

NS = 'xmlns="urn:vim25" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'


def val(inner: str, xsi_type: str = "") -> ET.Element:
    kind = f' xsi:type="{xsi_type}"' if xsi_type else ""
    return ET.fromstring(f"<val {NS}{kind}>{inner}</val>")


SYSTEM_INFO = val(
    "<vendor>Dell Inc.</vendor><model>PowerEdge R650</model><uuid>x</uuid><serialNumber>7XK2Q53</serialNumber>",
    "HostSystemInfo",
)
HBAS = val(
    '<HostHostBusAdapter xsi:type="HostInternetScsiHba"><key>key-vim.host.InternetScsiHba-vmhba64</key>'
    "<device>vmhba64</device><iScsiName>iqn.1998-01.com.vmware:esxi01-1a2b</iScsiName></HostHostBusAdapter>"
    '<HostHostBusAdapter xsi:type="HostBlockHba"><key>key-vim.host.BlockHba-vmhba0</key><device>vmhba0</device></HostHostBusAdapter>'
    '<HostHostBusAdapter xsi:type="HostFibreChannelHba"><key>key-vim.host.FibreChannelHba-vmhba2</key><device>vmhba2</device>'
    "<portWorldWideName>2377900762148634625</portWorldWideName><nodeWorldWideName>2305843168110706689</nodeWorldWideName></HostHostBusAdapter>"
    '<HostHostBusAdapter xsi:type="HostFibreChannelHba"><key>key-vim.host.FibreChannelHba-vmhba3</key><device>vmhba3</device>'
    "<portWorldWideName>2377900762148634626</portWorldWideName></HostHostBusAdapter>",
    "ArrayOfHostHostBusAdapter",
)
LUNS = val(
    '<ScsiLun xsi:type="HostScsiDisk"><key>key-lun-san</key><canonicalName>naa.6001405aaa</canonicalName></ScsiLun>'
    '<ScsiLun xsi:type="HostScsiDisk"><key>key-lun-local</key><canonicalName>naa.local000</canonicalName></ScsiLun>'
    '<ScsiLun xsi:type="HostScsiDisk"><key>key-lun-fc</key><canonicalName>naa.fc0000</canonicalName></ScsiLun>',
    "ArrayOfScsiLun",
)
ISCSI_PATH = (
    "<path><key>p1</key><name>vmhba64:C0:T0:L1</name><state>active</state>"
    "<adapter>key-vim.host.InternetScsiHba-vmhba64</adapter>"
    '<transport xsi:type="HostInternetScsiTargetTransport"><iScsiName>iqn.2000-01.com.synology:nas01.Target-1</iScsiName>'
    "<iScsiAlias>nas01</iScsiAlias><address>10.0.30.5:3260</address></transport></path>"
)
MULTIPATH = val(
    "<lun><key>m1</key><id>x</id><lun>key-lun-san</lun>"
    + ISCSI_PATH
    + ISCSI_PATH.replace("10.0.30.5", "10.0.31.5").replace("<key>p1</key>", "<key>p2</key>")
    + "</lun>"
    "<lun><key>m2</key><id>y</id><lun>key-lun-local</lun><path><key>p3</key><name>vmhba0:C0:T0:L0</name>"
    '<state>active</state><adapter>key-vim.host.BlockHba-vmhba0</adapter><transport xsi:type="HostBlockAdapterTargetTransport"/></path></lun>'
    "<lun><key>m3</key><id>z</id><lun>key-lun-fc</lun><path><key>p5</key><name>vmhba3:C0:T3:L7</name>"
    '<state>dead</state><adapter>key-vim.host.FibreChannelHba-vmhba3</adapter><transport xsi:type="HostFibreChannelTargetTransport">'
    "<portWorldWideName>5766297921370718209</portWorldWideName><nodeWorldWideName>5766297887010979840</nodeWorldWideName></transport></path>"
    "<path><key>p4</key><name>vmhba2:C0:T3:L7</name>"
    '<state>active</state><adapter>key-vim.host.FibreChannelHba-vmhba2</adapter><transport xsi:type="HostFibreChannelTargetTransport">'
    "<portWorldWideName>5766297887010979841</portWorldWideName><nodeWorldWideName>5766297887010979840</nodeWorldWideName></transport></path></lun>",
    "HostMultipathInfo",
)
HOST_DATASTORES = val(
    '<ManagedObjectReference type="Datastore">datastore-10</ManagedObjectReference>'
    '<ManagedObjectReference type="Datastore">datastore-11</ManagedObjectReference>'
    '<ManagedObjectReference type="Datastore">datastore-12</ManagedObjectReference>'
    '<ManagedObjectReference type="Datastore">datastore-13</ManagedObjectReference>'
    '<ManagedObjectReference type="Datastore">datastore-14</ManagedObjectReference>',
    "ArrayOfManagedObjectReference",
)


def datastore(name: str, kind: str, info: str, info_type: str, capacity: int = 2 * 1024**4) -> dict[str, ET.Element]:
    return {
        "summary": val(f"<name>{name}</name><capacity>{capacity}</capacity><type>{kind}</type>", "DatastoreSummary"),
        "info": val(info, info_type),
    }


DATASTORES = {
    "datastore-10": datastore(
        "LUN-VMFS-01", "VMFS", "<vmfs><extent><diskName>naa.6001405aaa</diskName><partition>1</partition></extent></vmfs>", "VmfsDatastoreInfo"
    ),
    "datastore-11": datastore(
        "datastore1", "VMFS", "<vmfs><extent><diskName>naa.local000</diskName></extent></vmfs>", "VmfsDatastoreInfo", 500 * 1024**3
    ),
    "datastore-12": datastore(
        "NFS-Backups", "NFS", "<nas><remoteHost>truenas.acme.local</remoteHost><remotePath>/mnt/tank/vm</remotePath></nas>", "NasDatastoreInfo"
    ),
    "datastore-13": datastore("FC-LUN", "VMFS", "<vmfs><extent><diskName>naa.fc0000</diskName></extent></vmfs>", "VmfsDatastoreInfo"),
    "datastore-14": datastore("vsanDatastore", "vsan", "", "VsanDatastoreInfo"),
}

HOST_PROPS = {
    "name": val("esxi01.acme.local"),
    "hardware.systemInfo": SYSTEM_INFO,
    "config.storageDevice.hostBusAdapter": HBAS,
    "config.storageDevice.scsiLun": LUNS,
    "config.storageDevice.multipathInfo": MULTIPATH,
    "datastore": HOST_DATASTORES,
}


class HostInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.found = vsphere_soap.host_inventory(HOST_PROPS, DATASTORES)
        self.stores = {s["name"]: s for s in self.found["datastores"]}

    def test_the_hardware_of_the_box(self) -> None:
        self.assertEqual(
            (self.found["manufacturer"], self.found["model"], self.found["serial"]),
            ("Dell Inc.", "PowerEdge R650", "7XK2Q53"),
        )

    def test_an_iscsi_vmfs_carries_target_portal_initiator_lun_and_paths(self) -> None:
        self.assertEqual(
            self.stores["LUN-VMFS-01"],
            {
                "name": "LUN-VMFS-01",
                "type": "iscsi",
                "gb": 2048,
                "target_iqn": "iqn.2000-01.com.synology:nas01.Target-1",
                "portal": "10.0.30.5:3260",
                "initiator_iqn": "iqn.1998-01.com.vmware:esxi01-1a2b",
                "lun": 1,
                "paths": 2,
            },
        )

    def test_a_vmfs_on_the_internal_controller_is_local(self) -> None:
        self.assertEqual(self.stores["datastore1"], {"name": "datastore1", "type": "vmfs", "gb": 500, "local": True})

    def test_an_nfs_datastore_carries_server_and_export(self) -> None:
        self.assertEqual(self.stores["NFS-Backups"]["server"], "truenas.acme.local")
        self.assertEqual(self.stores["NFS-Backups"]["export"], "/mnt/tank/vm")

    def test_a_fibre_channel_lun_counts_only_live_paths(self) -> None:
        self.assertEqual(self.stores["FC-LUN"]["type"], "fc")
        self.assertEqual(self.stores["FC-LUN"]["lun"], 7)
        self.assertEqual(self.stores["FC-LUN"]["paths"], 1)

    def test_a_fibre_channel_lun_says_which_array_and_which_card(self) -> None:
        """La WWNN de destino es la cabina; la WWPN de la tarjeta por la que
        sale la ruta viva, el iniciador. Sin esto un datastore de fibra no
        tenía de dónde colgar y no entraba en el inventario."""
        store = self.stores["FC-LUN"]

        self.assertEqual(store["target_wwn"], "50:06:01:60:88:60:00:00")
        self.assertEqual(store["initiator_wwn"], "21:00:00:24:ff:00:00:01")
        self.assertEqual(self.stores["FC-LUN"]["paths"], 1)

    def test_vsan_travels_with_its_own_word(self) -> None:
        """El servidor no lo modela en la v1; que lo decida él."""
        self.assertEqual(self.stores["vsanDatastore"]["type"], "vsan")

    def test_a_vmfs_without_known_paths_says_nothing_of_its_origin(self) -> None:
        props = {**HOST_PROPS, "config.storageDevice.multipathInfo": val("", "HostMultipathInfo")}

        store = {s["name"]: s for s in vsphere_soap.host_inventory(props, DATASTORES)["datastores"]}["LUN-VMFS-01"]

        self.assertEqual(store, {"name": "LUN-VMFS-01", "type": "vmfs", "gb": 2048})

    def test_an_old_esxi_gives_its_serial_among_the_identifiers(self) -> None:
        info = val(
            "<vendor>HPE</vendor><model>ProLiant DL360 Gen9</model>"
            "<otherIdentifyingInfo><identifierValue>CZJ1234567</identifierValue>"
            "<identifierType><label>Service tag</label><summary>x</summary><key>ServiceTag</key></identifierType>"
            "</otherIdentifyingInfo>"
        )

        found = vsphere_soap.host_inventory({**HOST_PROPS, "hardware.systemInfo": info}, DATASTORES)

        self.assertEqual(found["serial"], "CZJ1234567")

    def test_a_lazy_bios_placeholder_is_no_serial(self) -> None:
        info = val("<vendor>Supermicro</vendor><model>X11</model><serialNumber>To Be Filled By O.E.M.</serialNumber>")

        self.assertEqual(vsphere_soap.host_inventory({**HOST_PROPS, "hardware.systemInfo": info}, DATASTORES)["serial"], "")

    def test_a_host_with_nothing_readable_still_comes_out(self) -> None:
        self.assertEqual(
            vsphere_soap.host_inventory({"name": val("x")}, {}),
            {"manufacturer": "", "model": "", "serial": "", "datastores": []},
        )


# --- El transporte ------------------------------------------------------------------


def envelope(body: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
        f' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body>{body}</soapenv:Body></soapenv:Envelope>'
    ).encode()


SERVICE_CONTENT = envelope(
    '<RetrieveServiceContentResponse xmlns="urn:vim25"><returnval>'
    '<rootFolder type="Folder">group-d1</rootFolder><propertyCollector type="PropertyCollector">propertyCollector</propertyCollector>'
    '<viewManager type="ViewManager">ViewManager</viewManager><sessionManager type="SessionManager">SessionManager</sessionManager>'
    "</returnval></RetrieveServiceContentResponse>"
)
LOGIN = envelope('<LoginResponse xmlns="urn:vim25"><returnval><key>s</key></returnval></LoginResponse>')
VIEW = envelope('<CreateContainerViewResponse xmlns="urn:vim25"><returnval type="ContainerView">session[1]v</returnval></CreateContainerViewResponse>')
LOGOUT = envelope('<LogoutResponse xmlns="urn:vim25"/>')


def page(objects: str, token: str = "", continued: bool = False) -> bytes:
    name = "ContinueRetrievePropertiesExResponse" if continued else "RetrievePropertiesExResponse"
    token_xml = f"<token>{token}</token>" if token else ""
    return envelope(f'<{name} xmlns="urn:vim25"><returnval>{token_xml}{objects}</returnval></{name}>')


def obj(moid: str, kind: str, props: str) -> str:
    return f'<objects><obj type="{kind}">{moid}</obj>{props}</objects>'


def prop(name: str, value: str, xsi_type: str = "") -> str:
    kind = f' xsi:type="{xsi_type}"' if xsi_type else ""
    return f"<propSet><name>{name}</name><val{kind}>{value}</val></propSet>"


class _Response(io.BytesIO):
    def __init__(self, raw: bytes, cookie: str = "") -> None:
        super().__init__(raw)
        self.headers = {"Set-Cookie": cookie} if cookie else {}

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class _Opener:
    """El vCenter de mentira: contesta por el nombre de la llamada."""

    def __init__(self, answers: dict[str, list[bytes] | bytes | Exception]) -> None:
        self.answers = answers
        self.requests: list[Any] = []

    def open(self, request: Any, timeout: float = 0) -> _Response:
        self.requests.append(request)
        body = request.data.decode()
        call = body.split("<soapenv:Body><", 1)[1].split(">", 1)[0].split(" ", 1)[0]
        answer = self.answers[call]
        if isinstance(answer, list):
            answer = answer.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return _Response(answer, "vmware_soap_session=\"abc\"; Path=/; HttpOnly" if call == "Login" else "")


class TransportTests(unittest.TestCase):
    def _client(self, answers: dict[str, Any]) -> tuple[vsphere_soap.SoapClient, _Opener]:
        client = vsphere_soap.SoapClient("vc.acme.local")
        opener = _Opener(answers)
        client._opener = opener  # type: ignore[assignment]
        return client, opener

    def test_login_keeps_the_session_cookie_and_escapes_the_password(self) -> None:
        client, opener = self._client({"RetrieveServiceContent": SERVICE_CONTENT, "Login": LOGIN})

        client.login("lector@vsphere.local", "a<b&c")

        self.assertEqual(client._cookie, 'vmware_soap_session="abc"')
        self.assertIn("<password>a&lt;b&amp;c</password>", opener.requests[1].data.decode())
        self.assertEqual(opener.requests[1].headers["Soapaction"], vsphere_soap.SOAP_ACTION)

    def test_pages_are_followed_with_the_token(self) -> None:
        client, opener = self._client(
            {
                "RetrieveServiceContent": SERVICE_CONTENT,
                "Login": LOGIN,
                "CreateContainerView": VIEW,
                "RetrievePropertiesEx": page(obj("host-1", "HostSystem", prop("name", "esxi01")), token="t1"),
                "ContinueRetrievePropertiesEx": page(obj("host-2", "HostSystem", prop("name", "esxi02")), continued=True),
            }
        )
        client.login("u", "s")

        names = [props["name"].text for _moid, props in client.objects("HostSystem", ("name",))]

        self.assertEqual(names, ["esxi01", "esxi02"])
        self.assertIn("<token>t1</token>", opener.requests[-1].data.decode())
        self.assertIn("Cookie", opener.requests[-1].headers)

    def test_a_soap_fault_says_its_reason(self) -> None:
        fault = envelope("<soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>Cannot complete login due to an incorrect user name or password.</faultstring></soapenv:Fault>")
        error = urllib.error.HTTPError("https://vc/sdk", 500, "Internal", {}, io.BytesIO(fault))
        client, _ = self._client({"RetrieveServiceContent": SERVICE_CONTENT, "Login": error})

        with self.assertRaises(HypervisorError) as caught:
            client.login("u", "mala")

        self.assertIn("incorrect user name", str(caught.exception))
        self.assertNotIn("mala", str(caught.exception))

    def test_html_instead_of_xml_is_an_error_not_a_crash(self) -> None:
        client, _ = self._client({"RetrieveServiceContent": b"<html><body>portal cautivo"})

        with self.assertRaises(HypervisorError):
            client.login("u", "s")

    def test_inventory_end_to_end_and_logs_out(self) -> None:
        hosts = obj(
            "host-1",
            "HostSystem",
            prop("name", "esxi01.acme.local")
            + prop("hardware.systemInfo", "<vendor>Dell Inc.</vendor><model>R650</model><serialNumber>7XK</serialNumber>", "HostSystemInfo")
            + prop("datastore", '<ManagedObjectReference type="Datastore">datastore-12</ManagedObjectReference>', "ArrayOfManagedObjectReference"),
        )
        stores = obj(
            "datastore-12",
            "Datastore",
            prop("summary", "<name>NFS-VM</name><capacity>1099511627776</capacity><type>NFS</type>", "DatastoreSummary")
            + prop("info", "<nas><remoteHost>10.0.30.6</remoteHost><remotePath>/vm</remotePath></nas>", "NasDatastoreInfo"),
        )
        _client, opener = self._client(
            {
                "RetrieveServiceContent": SERVICE_CONTENT,
                "Login": LOGIN,
                "CreateContainerView": [VIEW, VIEW, VIEW],
                "RetrievePropertiesEx": [page(stores), page(hosts), page("")],
                "Logout": LOGOUT,
            }
        )
        with mock.patch.object(vsphere_soap.SoapClient, "__init__", lambda self, *a, **k: _init(self, opener)):
            found = vsphere_soap.inventory("vc.acme.local", "u", "s")

        self.assertEqual(found["esxi01.acme.local"]["serial"], "7XK")
        self.assertEqual(
            found["esxi01.acme.local"]["datastores"],
            [{"name": "NFS-VM", "type": "nfs", "gb": 1024, "server": "10.0.30.6", "export": "/vm"}],
        )
        self.assertIn("<Logout>", opener.requests[-1].data.decode())


PNICS = val(
    "<PhysicalNic><key>key-vim.host.PhysicalNic-vmnic0</key><device>vmnic0</device><driver>ixgben</driver>"
    "<linkSpeed><speedMb>10000</speedMb><duplex>true</duplex></linkSpeed><mac>3C:EC:EF:01:02:03</mac></PhysicalNic>"
    "<PhysicalNic><key>key-vim.host.PhysicalNic-vmnic1</key><device>vmnic1</device><driver>ixgben</driver>"
    "<mac>3c:ec:ef:01:02:04</mac></PhysicalNic>",
    "ArrayOfPhysicalNic",
)
VNICS = val(
    "<HostVirtualNic><device>vmk0</device><key>key-vim.host.VirtualNic-vmk0</key><portgroup>Management Network</portgroup>"
    "<spec><ip><dhcp>false</dhcp><ipAddress>10.0.0.11</ipAddress><subnetMask>255.255.255.0</subnetMask></ip>"
    "<mac>3c:ec:ef:01:02:03</mac></spec></HostVirtualNic>"
    "<HostVirtualNic><device>vmk1</device><key>key-vim.host.VirtualNic-vmk1</key><portgroup>vMotion</portgroup>"
    "<spec><ip><dhcp>false</dhcp><ipAddress>10.0.50.11</ipAddress></ip><mac>00:50:56:6a:00:01</mac></spec></HostVirtualNic>",
    "ArrayOfHostVirtualNic",
)
NET_CONFIG = val(
    "<VirtualNicManagerNetConfig><nicType>vmotion</nicType><multiSelectAllowed>true</multiSelectAllowed>"
    "<selectedVnic>vmotion.key-vim.host.VirtualNic-vmk1</selectedVnic></VirtualNicManagerNetConfig>"
    "<VirtualNicManagerNetConfig><nicType>management</nicType><multiSelectAllowed>true</multiSelectAllowed>"
    "<selectedVnic>management.key-vim.host.VirtualNic-vmk0</selectedVnic></VirtualNicManagerNetConfig>",
    "ArrayOfVirtualNicManagerNetConfig",
)
NETWORK_PROPS = {
    "name": val("esxi01.acme.local"),
    "config.network.pnic": PNICS,
    "config.network.vnic": VNICS,
    "config.virtualNicManagerInfo.netConfig": NET_CONFIG,
}
CDP_HINT = (
    "<returnval><device>vmnic0</device><connectedSwitchPort><cdpVersion>2</cdpVersion>"
    "<devId>sw-core-01.acme.local</devId><address>10.0.0.2</address><portId>TenGigabitEthernet1/0/12</portId>"
    "<hardwarePlatform>cisco C9300-48T</hardwarePlatform><mgmtAddr>10.0.0.2</mgmtAddr></connectedSwitchPort></returnval>"
)
LLDP_HINT = (
    "<returnval><device>vmnic1</device><lldpInfo><chassisId>f4:8e:38:aa:bb:cc</chassisId><portId>ethernet1/1/12</portId>"
    "<timeToLive>120</timeToLive>"
    '<parameter><key>System Name</key><value xsi:type="xsd:string">sw-dell-02</value></parameter>'
    '<parameter><key>Management Address</key><value xsi:type="xsd:string">10.0.0.3</value></parameter>'
    "</lldpInfo></returnval>"
)


def hints(*answers: str) -> list[ET.Element]:
    root = ET.fromstring(f"<QueryNetworkHintResponse {NS}>{''.join(answers)}</QueryNetworkHintResponse>")
    return list(root)


class HostNetworkTests(unittest.TestCase):
    """Las vmnic y las VMkernel de un ESXi, y el switch al otro lado.

    Sin esto un ESXi entraba sin puertos: ni la MAC de sus tarjetas, ni cuál
    está caída, ni a qué boca del switch va cada una, y «¿dónde acaba este
    cable?» se quedaba sin respuesta justo en el servidor que más importa.
    """

    def setUp(self) -> None:
        self.found = vsphere_soap.host_network(NETWORK_PROPS, hints(CDP_HINT, LLDP_HINT))
        self.ports = {port["name"]: port for port in self.found["interfaces"]}

    def test_each_vmnic_is_a_port_with_its_mac_speed_and_link(self) -> None:
        self.assertEqual(
            self.ports["vmnic0"],
            {"name": "vmnic0", "mac": "3c:ec:ef:01:02:03", "status": "up", "speed_mbps": 10000, "type": "ethernet"},
        )
        self.assertEqual(self.ports["vmnic1"]["status"], "down")

    def test_the_vmkernel_marked_for_management_gives_the_ip_and_mac(self) -> None:
        self.assertEqual(self.ports["vmk1"]["type"], "virtual")
        self.assertEqual(self.found["management_interface"], "vmk0")
        self.assertEqual(self.found["management_ip"], "10.0.0.11")
        self.assertEqual(self.found["mac"], "3c:ec:ef:01:02:03")

    def test_without_the_management_tags_vmk0_is_the_one(self) -> None:
        props = {k: v for k, v in NETWORK_PROPS.items() if k != "config.virtualNicManagerInfo.netConfig"}

        self.assertEqual(vsphere_soap.host_network(props, [])["management_interface"], "vmk0")

    def test_cdp_gives_the_switch_and_its_port_as_the_switch_writes_it(self) -> None:
        cdp = self.found["neighbors"][0]

        self.assertEqual(
            cdp,
            {
                "protocol": "cdp",
                "local_port": "vmnic0",
                "remote_name": "sw-core-01.acme.local",
                "remote_port": "TenGigabitEthernet1/0/12",
                "remote_mac": "",
                "remote_ip": "10.0.0.2",
                "remote_platform": "cisco C9300-48T",
            },
        )

    def test_lldp_gives_chassis_mac_name_and_management_address(self) -> None:
        lldp = self.found["neighbors"][1]

        self.assertEqual(lldp["protocol"], "lldp")
        self.assertEqual((lldp["local_port"], lldp["remote_port"]), ("vmnic1", "ethernet1/1/12"))
        self.assertEqual((lldp["remote_name"], lldp["remote_mac"], lldp["remote_ip"]), ("sw-dell-02", "f4:8e:38:aa:bb:cc", "10.0.0.3"))

    def test_a_port_announced_by_its_mac_uses_its_description(self) -> None:
        hint = LLDP_HINT.replace("<portId>ethernet1/1/12</portId>", "<portId>f4:8e:38:aa:bb:d8</portId>").replace(
            "</lldpInfo>", "<parameter><key>Port Description</key><value>ethernet1/1/24</value></parameter></lldpInfo>"
        )

        lldp = vsphere_soap.host_network(NETWORK_PROPS, hints(hint))["neighbors"][0]

        self.assertEqual(lldp["remote_port"], "ethernet1/1/24")

    def test_a_vmnic_that_hears_nothing_has_no_neighbor(self) -> None:
        found = vsphere_soap.host_network(NETWORK_PROPS, hints("<returnval><device>vmnic2</device></returnval>"))

        self.assertNotIn("neighbors", found)

    def test_a_host_without_network_data_adds_nothing(self) -> None:
        self.assertEqual(vsphere_soap.host_network({"name": val("x")}, []), {})


VSWITCHES = val(
    "<HostVirtualSwitch><name>vSwitch0</name><key>key-vim.host.VirtualSwitch-vSwitch0</key>"
    "<portgroup>key-vim.host.PortGroup-Management Network</portgroup><portgroup>key-vim.host.PortGroup-Servidores</portgroup>"
    "<pnic>key-vim.host.PhysicalNic-vmnic0</pnic><pnic>key-vim.host.PhysicalNic-vmnic1</pnic></HostVirtualSwitch>"
    "<HostVirtualSwitch><name>vSwitch1</name><key>key-vim.host.VirtualSwitch-vSwitch1</key>"
    "<portgroup>key-vim.host.PortGroup-Invitados</portgroup></HostVirtualSwitch>",
    "ArrayOfHostVirtualSwitch",
)
PORTGROUPS = val(
    "<HostPortGroup><key>key-vim.host.PortGroup-Management Network</key>"
    "<spec><name>Management Network</name><vlanId>0</vlanId><vswitchName>vSwitch0</vswitchName></spec></HostPortGroup>"
    "<HostPortGroup><key>key-vim.host.PortGroup-Servidores</key>"
    "<spec><name>Servidores</name><vlanId>20</vlanId><vswitchName>vSwitch0</vswitchName></spec></HostPortGroup>"
    "<HostPortGroup><key>key-vim.host.PortGroup-Trunk</key>"
    "<spec><name>Trunk</name><vlanId>4095</vlanId><vswitchName>vSwitch0</vswitchName></spec></HostPortGroup>"
    "<HostPortGroup><key>key-vim.host.PortGroup-Voz</key>"
    "<spec><name>Voz</name><vlanId>10</vlanId><vswitchName>vSwitch0</vswitchName></spec></HostPortGroup>"
    "<HostPortGroup><key>key-vim.host.PortGroup-Invitados</key>"
    "<spec><name>Invitados</name><vlanId>99</vlanId><vswitchName>vSwitch1</vswitchName></spec></HostPortGroup>",
    "ArrayOfHostPortGroup",
)
PNICS_WITH_KEYS = val(
    "<PhysicalNic><key>key-vim.host.PhysicalNic-vmnic0</key><device>vmnic0</device>"
    "<linkSpeed><speedMb>10000</speedMb></linkSpeed><mac>3c:ec:ef:01:02:03</mac></PhysicalNic>"
    "<PhysicalNic><key>key-vim.host.PhysicalNic-vmnic1</key><device>vmnic1</device>"
    "<linkSpeed><speedMb>10000</speedMb></linkSpeed><mac>3c:ec:ef:01:02:04</mac></PhysicalNic>"
    "<PhysicalNic><key>key-vim.host.PhysicalNic-vmnic2</key><device>vmnic2</device><mac>3c:ec:ef:01:02:05</mac></PhysicalNic>",
    "ArrayOfPhysicalNic",
)


class WwnTests(unittest.TestCase):
    def test_a_positive_long_is_written_in_pairs(self) -> None:
        self.assertEqual(vsphere_soap.wwn("5764607523034234880"), "50:00:00:00:00:00:00:00")

    def test_a_negative_long_is_the_same_64_bits(self) -> None:
        """vSphere da el WWN como entero con signo: los que empiezan por 8 o
        más llegan negativos."""
        self.assertEqual(vsphere_soap.wwn("-8070450532247928832"), "90:00:00:00:00:00:00:00")

    def test_nothing_or_zero_is_no_wwn(self) -> None:
        self.assertEqual(vsphere_soap.wwn(""), "")
        self.assertEqual(vsphere_soap.wwn("0"), "")
        self.assertEqual(vsphere_soap.wwn("no"), "")


class DistributedSwitchTests(unittest.TestCase):
    """Las VLAN de un switch distribuido (vDS) viven en sus grupos de puertos,
    no en el host: hay que cruzarlas por el uuid del switch."""

    def test_a_fixed_vlan_is_that_vlan(self) -> None:
        config = val(
            '<vlan xsi:type="VmwareDistributedVirtualSwitchVlanIdSpec"><inherited>false</inherited><vlanId>20</vlanId></vlan>',
            "VMwareDVSPortSetting",
        )

        self.assertEqual(vsphere_soap.portgroup_vlans(config), {20})

    def test_a_narrow_trunk_is_its_ranges(self) -> None:
        config = val(
            '<vlan xsi:type="VmwareDistributedVirtualSwitchTrunkVlanSpec"><inherited>false</inherited>'
            "<vlanId><start>10</start><end>12</end></vlanId><vlanId><start>30</start><end>30</end></vlanId></vlan>",
            "VMwareDVSPortSetting",
        )

        self.assertEqual(vsphere_soap.portgroup_vlans(config), {10, 11, 12, 30})

    def test_the_uplink_group_and_vlan_0_say_nothing(self) -> None:
        uplinks = val(
            '<vlan xsi:type="VmwareDistributedVirtualSwitchTrunkVlanSpec"><inherited>false</inherited>'
            "<vlanId><start>0</start><end>4094</end></vlanId></vlan>",
            "VMwareDVSPortSetting",
        )
        untagged = val(
            '<vlan xsi:type="VmwareDistributedVirtualSwitchVlanIdSpec"><inherited>false</inherited><vlanId>0</vlanId></vlan>',
            "VMwareDVSPortSetting",
        )
        private = val(
            '<vlan xsi:type="VmwareDistributedVirtualSwitchPvlanSpec"><inherited>false</inherited><pvlanId>101</pvlanId></vlan>',
            "VMwareDVSPortSetting",
        )

        self.assertEqual(vsphere_soap.portgroup_vlans(uplinks), set())
        self.assertEqual(vsphere_soap.portgroup_vlans(untagged), set())
        self.assertEqual(vsphere_soap.portgroup_vlans(private), set())

    def _inventory(self, *, portgroups: Any) -> dict[str, dict[str, Any]]:
        hosts = obj("host-1", "HostSystem", prop("name", "esxi01.acme.local"))
        network = page(
            obj(
                "host-1",
                "HostSystem",
                prop("name", "esxi01.acme.local")
                + prop(
                    "config.network.pnic",
                    "<PhysicalNic><key>key-vim.host.PhysicalNic-vmnic0</key><device>vmnic0</device>"
                    "<linkSpeed><speedMb>10000</speedMb></linkSpeed><mac>3c:ec:ef:01:02:03</mac></PhysicalNic>"
                    "<PhysicalNic><key>key-vim.host.PhysicalNic-vmnic1</key><device>vmnic1</device>"
                    "<linkSpeed><speedMb>10000</speedMb></linkSpeed><mac>3c:ec:ef:01:02:04</mac></PhysicalNic>",
                    "ArrayOfPhysicalNic",
                )
                + prop(
                    "config.network.proxySwitch",
                    "<HostProxySwitch><dvsUuid>50 2c 1a 7e 00 11 22 33-44 55 66 77 88 99 aa bb</dvsUuid>"
                    "<dvsName>DSwitch-Produccion</dvsName><key>k</key>"
                    "<pnic>key-vim.host.PhysicalNic-vmnic1</pnic></HostProxySwitch>",
                    "ArrayOfHostProxySwitch",
                ),
            )
        )
        switches = page(obj("dvs-21", "VmwareDistributedVirtualSwitch", prop("uuid", "50 2c 1a 7e 00 11 22 33-44 55 66 77 88 99 aa bb")))
        opener = _Opener(
            {
                "RetrieveServiceContent": SERVICE_CONTENT,
                "Login": LOGIN,
                "CreateContainerView": [VIEW, VIEW, VIEW, VIEW, VIEW],
                "RetrievePropertiesEx": [page(""), page(hosts), network, switches, portgroups],
                "Logout": LOGOUT,
            }
        )
        with mock.patch.object(vsphere_soap.SoapClient, "__init__", lambda self, *a, **k: _init(self, opener)):
            return vsphere_soap.inventory("vc.acme.local", "u", "s")

    def test_each_card_of_a_vds_carries_the_vlans_of_its_portgroups(self) -> None:
        def group(moid: str, vlan: str) -> str:
            return obj(
                moid,
                "DistributedVirtualPortgroup",
                '<propSet><name>config.distributedVirtualSwitch</name>'
                '<val type="VmwareDistributedVirtualSwitch" xsi:type="ManagedObjectReference">dvs-21</val></propSet>'
                + prop(
                    "config.defaultPortConfig",
                    '<vlan xsi:type="VmwareDistributedVirtualSwitchVlanIdSpec"><inherited>false</inherited>'
                    f"<vlanId>{vlan}</vlanId></vlan>",
                    "VMwareDVSPortSetting",
                ),
            )

        found = self._inventory(portgroups=page(group("dvportgroup-31", "20") + group("dvportgroup-32", "40")))

        ports = {port["name"]: port for port in found["esxi01.acme.local"]["interfaces"]}
        self.assertEqual(ports["vmnic1"]["vlans"], [20, 40])
        self.assertNotIn("vlans", ports["vmnic0"])

    def test_without_permission_for_the_portgroups_the_cards_stay_as_they_were(self) -> None:
        fault = envelope("<soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>NoPermission</faultstring></soapenv:Fault>")
        error = urllib.error.HTTPError("https://vc/sdk", 500, "Internal", {}, io.BytesIO(fault))

        found = self._inventory(portgroups=error)

        ports = {port["name"]: port for port in found["esxi01.acme.local"]["interfaces"]}
        self.assertNotIn("vlans", ports["vmnic1"])


class HostDetailsTests(unittest.TestCase):
    """La ficha de un ESXi que el vCenter sabe y la persona no tiene por qué
    escribir: versión exacta, núcleos y memoria, y las VLAN de cada tarjeta."""

    def test_version_cores_and_memory(self) -> None:
        props = {
            "config.product": val(
                "<name>VMware ESXi</name><fullName>VMware ESXi 8.0.2 build-22380479</fullName><version>8.0.2</version>",
                "AboutInfo",
            ),
            "hardware.cpuInfo": val("<numCpuPackages>2</numCpuPackages><numCpuCores>32</numCpuCores><numCpuThreads>64</numCpuThreads>", "HostCpuInfo"),
            "hardware.memorySize": val("549755813888", "xsd:long"),
        }

        self.assertEqual(
            vsphere_soap.host_details(props),
            {"os": "VMware ESXi 8.0.2 build-22380479", "cpu_count": 64, "ram_gb": 512},
        )

    def test_nothing_readable_adds_nothing(self) -> None:
        self.assertEqual(vsphere_soap.host_details({}), {})

    def test_each_uplink_carries_the_vlans_of_its_vswitch(self) -> None:
        """Las VLAN de los grupos de su vSwitch: lo que el puerto del switch
        al otro lado tiene que llevar etiquetado. Ni la 0 ni la 4095."""
        props = {"config.network.pnic": PNICS_WITH_KEYS, "config.network.vswitch": VSWITCHES, "config.network.portgroup": PORTGROUPS}

        ports = {port["name"]: port for port in vsphere_soap.host_network(props, [])["interfaces"]}

        self.assertEqual(ports["vmnic0"]["vlans"], [10, 20])
        self.assertEqual(ports["vmnic1"]["vlans"], [10, 20])
        self.assertNotIn("vlans", ports["vmnic2"])


class NetworkInventoryTests(unittest.TestCase):
    def _run(self, network_page: Any, hint: Any) -> dict[str, dict[str, Any]]:
        hosts = obj("host-1", "HostSystem", prop("name", "esxi01.acme.local"))
        opener = _Opener(
            {
                "RetrieveServiceContent": SERVICE_CONTENT,
                "Login": LOGIN,
                "CreateContainerView": [VIEW, VIEW, VIEW],
                "RetrievePropertiesEx": [page(""), page(hosts), network_page],
                "QueryNetworkHint": hint,
                "Logout": LOGOUT,
            }
        )
        self.opener = opener
        with mock.patch.object(vsphere_soap.SoapClient, "__init__", lambda self, *a, **k: _init(self, opener)):
            return vsphere_soap.inventory("vc.acme.local", "u", "s")

    NETWORK = page(
        obj(
            "host-1",
            "HostSystem",
            prop("name", "esxi01.acme.local")
            + prop(
                "config.network.pnic",
                "<PhysicalNic><device>vmnic0</device><linkSpeed><speedMb>1000</speedMb></linkSpeed><mac>3c:ec:ef:01:02:03</mac></PhysicalNic>",
                "ArrayOfPhysicalNic",
            )
            + prop("configManager.networkSystem", "networkSystem-12", "ManagedObjectReference"),
        )
    )

    def test_each_host_is_asked_what_it_hears_on_its_network_system(self) -> None:
        found = self._run(self.NETWORK, envelope(f'<QueryNetworkHintResponse xmlns="urn:vim25">{CDP_HINT}</QueryNetworkHintResponse>'))

        host = found["esxi01.acme.local"]
        self.assertEqual(host["interfaces"][0]["name"], "vmnic0")
        self.assertEqual(host["neighbors"][0]["remote_name"], "sw-core-01.acme.local")
        asked = next(r for r in self.opener.requests if b"<QueryNetworkHint>" in r.data)
        self.assertIn('<_this type="HostNetworkSystem">networkSystem-12</_this>', asked.data.decode())

    def test_without_permission_for_the_hints_the_ports_still_arrive(self) -> None:
        fault = envelope("<soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>Permission to perform this operation was denied.</faultstring></soapenv:Fault>")
        error = urllib.error.HTTPError("https://vc/sdk", 500, "Internal", {}, io.BytesIO(fault))

        host = self._run(self.NETWORK, error)["esxi01.acme.local"]

        self.assertEqual(host["interfaces"][0]["name"], "vmnic0")
        self.assertNotIn("neighbors", host)

    def test_the_cluster_comes_from_the_parent_of_the_host(self) -> None:
        """De respaldo de la REST: el clúster es el padre del host, sin filtros."""
        network = page(
            obj(
                "host-1",
                "HostSystem",
                prop("name", "esxi01.acme.local")
                + '<propSet><name>parent</name><val type="ClusterComputeResource" xsi:type="ManagedObjectReference">domain-c7</val></propSet>',
            )
        )
        clusters = page(obj("domain-c7", "ClusterComputeResource", prop("name", "Producción")))
        hosts = obj("host-1", "HostSystem", prop("name", "esxi01.acme.local"))
        opener = _Opener(
            {
                "RetrieveServiceContent": SERVICE_CONTENT,
                "Login": LOGIN,
                "CreateContainerView": [VIEW, VIEW, VIEW, VIEW],
                "RetrievePropertiesEx": [page(""), page(hosts), network, clusters],
                "Logout": LOGOUT,
            }
        )
        with mock.patch.object(vsphere_soap.SoapClient, "__init__", lambda self, *a, **k: _init(self, opener)):
            found = vsphere_soap.inventory("vc.acme.local", "u", "s")

        self.assertEqual(found["esxi01.acme.local"]["cluster"], "Producción")

    def test_a_vcenter_that_refuses_the_network_keeps_hardware_and_datastores(self) -> None:
        fault = envelope("<soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>InvalidProperty</faultstring></soapenv:Fault>")
        error = urllib.error.HTTPError("https://vc/sdk", 500, "Internal", {}, io.BytesIO(fault))

        found = self._run(error, LOGOUT)

        self.assertIn("esxi01.acme.local", found)
        self.assertNotIn("interfaces", found["esxi01.acme.local"])


def _init(client: vsphere_soap.SoapClient, opener: _Opener) -> None:
    client.url = "https://vc.acme.local:443/sdk"
    client._opener = opener  # type: ignore[assignment]
    client._cookie = ""
    client.content = {}


class VMwareClientMergeTests(unittest.TestCase):
    def test_hosts_gain_what_the_soap_api_knows(self) -> None:
        client = VMwareClient("vc.acme.local", "u", "s")
        client._soap_cache = {"esxi01.acme.local": {"serial": "7XK", "datastores": [{"name": "d", "type": "nfs"}]}}
        client.prefix, client.token = "/api", "t"
        client.rest = mock.Mock()  # type: ignore[assignment]
        client.rest.request.side_effect = lambda method, path, **kw: (
            [{"host": "host-16", "name": "esxi01.acme.local"}] if path == "/api/vcenter/host" else []
        )

        host = client.hosts()[0]

        self.assertEqual(host["serial"], "7XK")
        self.assertEqual(host["datastores"], [{"name": "d", "type": "nfs"}])

    def test_the_rest_cluster_wins_and_the_soap_one_fills_the_gap(self) -> None:
        client = VMwareClient("vc.acme.local", "u", "s")
        client._soap_cache = {
            "esxi01.acme.local": {"cluster": "Viejo"},
            "esxi02.acme.local": {"cluster": "Producción"},
        }
        client._cluster_cache = {"esxi01.acme.local": "Producción"}
        client.prefix, client.token = "/api", "t"
        client.rest = mock.Mock()  # type: ignore[assignment]
        client.rest.request.side_effect = lambda method, path, **kw: (
            [{"host": "host-16", "name": "esxi01.acme.local"}, {"host": "host-22", "name": "esxi02.acme.local"}]
            if path == "/api/vcenter/host"
            else []
        )

        clusters = {host["name"]: host["cluster"] for host in client.hosts()}

        self.assertEqual(clusters, {"esxi01.acme.local": "Producción", "esxi02.acme.local": "Producción"})

    def test_without_the_soap_api_hosts_arrive_as_before(self) -> None:
        client = VMwareClient("vc.acme.local", "u", "s")
        client.prefix, client.token = "/api", "t"
        client.rest = mock.Mock()  # type: ignore[assignment]
        client.rest.request.side_effect = lambda method, path, **kw: (
            [{"host": "host-16", "name": "esxi01"}] if path == "/api/vcenter/host" else []
        )
        with mock.patch("agent.vsphere_soap.inventory", side_effect=HypervisorError("403", status=403)):
            host = client.hosts()[0]

        self.assertEqual(host["name"], "esxi01")
        self.assertNotIn("datastores", host)


if __name__ == "__main__":
    unittest.main()
