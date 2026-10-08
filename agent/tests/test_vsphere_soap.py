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
    '<HostHostBusAdapter xsi:type="HostBlockHba"><key>key-vim.host.BlockHba-vmhba0</key><device>vmhba0</device></HostHostBusAdapter>',
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
    "<lun><key>m3</key><id>z</id><lun>key-lun-fc</lun><path><key>p4</key><name>vmhba2:C0:T3:L7</name>"
    '<state>active</state><adapter>a</adapter><transport xsi:type="HostFibreChannelTargetTransport"/></path>'
    "<path><key>p5</key><name>vmhba3:C0:T3:L7</name>"
    '<state>dead</state><adapter>b</adapter><transport xsi:type="HostFibreChannelTargetTransport"/></path></lun>',
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
                "CreateContainerView": [VIEW, VIEW],
                "RetrievePropertiesEx": [page(stores), page(hosts)],
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
