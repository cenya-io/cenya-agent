"""Lo justo de la API SOAP de vSphere, con la biblioteca estándar.

La API REST (vSphere Automation, `agent.hypervisor.VMwareClient`) da hosts,
máquinas y discos, pero **no dice de dónde viene un datastore** ni qué caja es
cada ESXi: el LUN que hay debajo de un VMFS, su destino iSCSI, sus rutas, el
servidor de un NFS, el fabricante y el número de serie del servidor. Todo eso
vive en la API de siempre, la SOAP (`/sdk`), y sin ello la traza «¿De qué
depende?» de una máquina de VMware se paraba en el datastore, justo donde se
paran las demás herramientas.

**`pyvmomi` sigue descartado** por lo mismo que en `agent.hypervisor`: son
decenas de megas para cinco llamadas. Esto son esas cinco, escritas a mano:
`RetrieveServiceContent`, `Login`, `CreateContainerView`,
`RetrievePropertiesEx` (con `ContinueRetrievePropertiesEx` para las páginas) y
`Logout`. Solo lectura: no hay ninguna llamada que cambie nada.

**La verificación TLS es la misma que la del cliente REST** (la CA o el
certificado en el que se confió desde la web, `agent.tlspin`), y tampoco sigue
redirecciones: la cookie de sesión no puede viajar a otro sitio.

Lo que devuelve, por nombre de host, es lo que el servidor ya sabe convertir en
volúmenes y cabinas (`core/storage_discovery.py`):

    {"esxi01": {"manufacturer": "Dell Inc.", "model": "PowerEdge R650",
                "serial": "7XK2Q53", "datastores": [{...}, ...]}}
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from typing import Any, Iterator
from xml.sax.saxutils import escape

from agent import tlspin, vmnet
from agent.hypervisor import TIMEOUT_SECONDS, HypervisorError, _NoRedirects, untrusted

#: La versión que se pide. vCenter 6.7, 7 y 8 la aceptan; las respuestas que
#: se leen aquí no han cambiado desde la 6.0.
SOAP_ACTION = "urn:vim25/6.7"
#: Una respuesta mayor que esto no es un inventario de pyme: se corta antes de
#: que llene la memoria del equipo del agente.
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
#: Por página de `RetrievePropertiesEx`, y cuántas páginas como mucho.
PAGE_SIZE = 100
MAX_PAGES = 20

XSI_TYPE = "{http://www.w3.org/2001/XMLSchema-instance}type"
_ENVELOPE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
    ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="urn:vim25">'
    "<soapenv:Body>{body}</soapenv:Body></soapenv:Envelope>"
)
_LUN_NUMBER = re.compile(r":L(\d+)$")

HOST_PROPERTIES = (
    "name",
    "hardware.systemInfo",
    "config.storageDevice.hostBusAdapter",
    "config.storageDevice.scsiLun",
    "config.storageDevice.multipathInfo",
    "datastore",
)
DATASTORE_PROPERTIES = ("summary", "info")
#: La red y el resto de la ficha de cada ESXi, en una petición aparte: un
#: vCenter que no deja leerla (permiso, versión) no se lleva por delante el
#: hardware ni los datastores.
NETWORK_PROPERTIES = (
    "name",
    "config.network.pnic",
    "config.network.vnic",
    "config.network.vswitch",
    "config.network.portgroup",
    "config.virtualNicManagerInfo.netConfig",
    "configManager.networkSystem",
    "config.product",
    "hardware.cpuInfo",
    "hardware.memorySize",
    "parent",
)
#: Hosts a los que se pregunta qué oyen por CDP o LLDP: una llamada por host.
MAX_HINT_HOSTS = 64
#: Tope de tarjetas por host: un ESXi de pyme tiene de dos a ocho.
MAX_INTERFACES = 64

#: Transportes de una ruta que son el propio servidor: un disco local, una
#: controladora RAID interna, un NVMe en la placa.
_LOCAL_TRANSPORTS = {
    "HostBlockAdapterTargetTransport",
    "HostParallelScsiTargetTransport",
    "HostSerialAttachedTargetTransport",
    "HostPcieTargetTransport",
}


# --- XML ----------------------------------------------------------------------------


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(element: ET.Element | None, name: str) -> ET.Element | None:
    if element is None:
        return None
    return next((c for c in element if _local(c.tag) == name), None)


def _children(element: ET.Element | None, name: str | None = None) -> list[ET.Element]:
    if element is None:
        return []
    return [c for c in element if name is None or _local(c.tag) == name]


def _text(element: ET.Element | None, name: str) -> str:
    found = _child(element, name)
    return (found.text or "").strip() if found is not None else ""


def _type(element: ET.Element | None) -> str:
    return (element.get(XSI_TYPE) or "").split(":")[-1] if element is not None else ""


def _moref(kind: str, value: str) -> str:
    return f'<_this type="{escape(kind)}">{escape(value)}</_this>'


# --- Cliente ------------------------------------------------------------------------


class SoapClient:
    def __init__(self, host: str, *, port: int = 443, ca_file: str = "", tls_pin: str = "") -> None:
        self.url = f"https://{host}:{port}/sdk"
        self._opener = urllib.request.build_opener(_NoRedirects, tlspin.https_handler(ca_file, tls_pin))
        self._cookie = ""
        self.content: dict[str, str] = {}

    def call(self, body: str) -> ET.Element:
        """Una llamada; devuelve el elemento de respuesta (`...Response`)."""
        request = urllib.request.Request(
            self.url,
            data=_ENVELOPE.format(body=body).encode("utf-8"),
            headers={
                "Content-Type": "text/xml; charset=utf-8",
                "SOAPAction": SOAP_ACTION,
                **({"Cookie": self._cookie} if self._cookie else {}),
            },
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                cookie = response.headers.get("Set-Cookie") or ""
        except urllib.error.HTTPError as exc:
            # Un fallo SOAP llega como 500 con el motivo en el cuerpo.
            detail = _fault(exc.read(64 * 1024)) or f"{exc.code} en /sdk"
            raise HypervisorError(detail, status=exc.code, logged_in=bool(self._cookie)) from exc
        except urllib.error.URLError as exc:
            if tlspin.is_untrusted(exc):
                raise untrusted(self.url, exc) from exc
            raise HypervisorError(str(getattr(exc, "reason", exc)), unreachable=True) from exc
        except (TimeoutError, ssl.SSLError) as exc:
            raise HypervisorError(str(getattr(exc, "reason", exc))) from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise HypervisorError("la respuesta del vCenter es demasiado grande", logged_in=True)
        if cookie and not self._cookie:
            self._cookie = cookie.split(";", 1)[0]
        try:
            root = ET.fromstring(raw)
        except ET.ParseError as exc:
            raise HypervisorError("la respuesta del vCenter no era XML", logged_in=bool(self._cookie)) from exc
        body_element = next((e for e in root.iter() if _local(e.tag) == "Body"), None)
        answer = next(iter(body_element), None) if body_element is not None else None
        if answer is None:
            raise HypervisorError("respuesta SOAP vacía", logged_in=bool(self._cookie))
        return answer

    def login(self, username: str, secret: str) -> None:
        answer = self.call(
            "<RetrieveServiceContent>" + _moref("ServiceInstance", "ServiceInstance") + "</RetrieveServiceContent>"
        )
        content = _child(answer, "returnval")
        self.content = {
            name: _text(content, name) for name in ("rootFolder", "propertyCollector", "viewManager", "sessionManager")
        }
        if not all(self.content.values()):
            raise HypervisorError("el vCenter no dio su contenido de servicio", unreachable=True)
        self.call(
            "<Login>"
            + _moref("SessionManager", self.content["sessionManager"])
            + f"<userName>{escape(username)}</userName><password>{escape(secret)}</password>"
            "</Login>"
        )

    def logout(self) -> None:
        if not self._cookie:
            return
        try:
            self.call("<Logout>" + _moref("SessionManager", self.content["sessionManager"]) + "</Logout>")
        except HypervisorError:
            pass  # la sesión caduca sola; no se deja de entregar lo leído por esto

    def objects(self, kind: str, properties: tuple[str, ...]) -> Iterator[tuple[str, dict[str, ET.Element]]]:
        """Todos los objetos de un tipo, con esas propiedades: `(moid, {propiedad: val})`."""
        view = _text(
            self.call(
                "<CreateContainerView>"
                + _moref("ViewManager", self.content["viewManager"])
                + f'<container type="Folder">{escape(self.content["rootFolder"])}</container>'
                + f"<type>{escape(kind)}</type><recursive>true</recursive>"
                "</CreateContainerView>"
            ),
            "returnval",
        )
        paths = "".join(f"<pathSet>{escape(p)}</pathSet>" for p in properties)
        answer = self.call(
            "<RetrievePropertiesEx>"
            + _moref("PropertyCollector", self.content["propertyCollector"])
            + "<specSet>"
            + f"<propSet><type>{escape(kind)}</type>{paths}</propSet>"
            + f'<objectSet><obj type="ContainerView">{escape(view)}</obj><skip>true</skip>'
            '<selectSet xsi:type="TraversalSpec"><name>view</name><type>ContainerView</type>'
            "<path>view</path><skip>false</skip></selectSet></objectSet>"
            "</specSet>"
            f"<options><maxObjects>{PAGE_SIZE}</maxObjects></options>"
            "</RetrievePropertiesEx>"
        )
        for _page in range(MAX_PAGES):
            result = _child(answer, "returnval")
            for item in _children(result, "objects"):
                moid = _text(item, "obj")
                values = {_text(p, "name"): _child(p, "val") for p in _children(item, "propSet")}
                yield moid, {k: v for k, v in values.items() if v is not None}
            token = _text(result, "token")
            if not token:
                break
            answer = self.call(
                "<ContinueRetrievePropertiesEx>"
                + _moref("PropertyCollector", self.content["propertyCollector"])
                + f"<token>{escape(token)}</token></ContinueRetrievePropertiesEx>"
            )


def _fault(raw: bytes) -> str:
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return ""
    found = next((e for e in root.iter() if _local(e.tag) == "faultstring"), None)
    return (found.text or "").strip()[:300] if found is not None else ""


# --- Inventario ---------------------------------------------------------------------


def inventory(
    host: str, username: str, secret: str, *, port: int = 443, ca_file: str = "", tls_pin: str = ""
) -> dict[str, dict[str, Any]]:
    """Hardware, datastores y red de cada ESXi del vCenter, por nombre de host."""
    client = SoapClient(host, port=port, ca_file=ca_file, tls_pin=tls_pin)
    client.login(username, secret)
    try:
        datastores = {moid: props for moid, props in client.objects("Datastore", DATASTORE_PROPERTIES)}
        found: dict[str, dict[str, Any]] = {}
        for _moid, props in client.objects("HostSystem", HOST_PROPERTIES):
            name = (props.get("name").text or "").strip() if props.get("name") is not None else ""
            if name:
                found[name] = host_inventory(props, datastores)
        _add_network(client, found)
        return found
    finally:
        client.logout()


def host_inventory(props: dict[str, ET.Element], datastores: dict[str, dict[str, ET.Element]]) -> dict[str, Any]:
    info = props.get("hardware.systemInfo")
    serial = _text(info, "serialNumber")
    if not serial:
        # Antes de la 6.7 el número de serie solo está en la lista de
        # identificadores, como «etiqueta de servicio» o «número de serie».
        for other in _children(info, "otherIdentifyingInfo"):
            key = _text(_child(other, "identifierType"), "key")
            if key in ("SerialNumberTag", "ServiceTag", "EnclosureSerialNumberTag"):
                serial = _text(other, "identifierValue")
                if serial:
                    break
    storage = _StorageMap(props)
    stores: list[dict[str, Any] | None] = []
    for reference in _children(props.get("datastore")):
        moid = (reference.text or "").strip()
        if moid in datastores:
            stores.append(storage.datastore(datastores[moid]))
    return {
        "manufacturer": _clean(_text(info, "vendor")),
        "model": _clean(_text(info, "model")),
        "serial": _clean(serial),
        "datastores": [s for s in stores if s][: vmnet.MAX_PER_MACHINE],
    }


_PLACEHOLDERS = {"", "to be filled by o.e.m.", "default string", "not specified", "none", "0", "unknown"}


def _clean(value: str) -> str:
    return "" if value.strip().casefold() in _PLACEHOLDERS else value.strip()[:200]


class _StorageMap:
    """El almacenamiento de un host: de un disco (`naa.…`) a sus rutas, su
    transporte y la tarjeta por la que sale."""

    def __init__(self, props: dict[str, ET.Element]) -> None:
        self.canonical_to_key = {
            _text(lun, "canonicalName"): _text(lun, "key") for lun in _children(props.get("config.storageDevice.scsiLun"))
        }
        self.initiators = {
            _text(hba, "key"): _text(hba, "iScsiName")
            for hba in _children(props.get("config.storageDevice.hostBusAdapter"))
            if _type(hba) == "HostInternetScsiHba"
        }
        self.paths_by_lun: dict[str, list[ET.Element]] = {}
        for lun in _children(props.get("config.storageDevice.multipathInfo"), "lun"):
            self.paths_by_lun[_text(lun, "lun")] = _children(lun, "path")

    def datastore(self, ds: dict[str, ET.Element]) -> dict[str, Any] | None:
        summary = ds.get("summary")
        name = _text(summary, "name")
        kind = _text(summary, "type").lower()
        size = vmnet.gb(_text(summary, "capacity"))
        info = ds.get("info")
        if kind in ("nfs", "nfs41"):
            nas = _child(info, "nas")
            server = _text(nas, "remoteHost") or next(
                ((h.text or "").strip() for h in _children(nas, "remoteHostNames") if (h.text or "").strip()), ""
            )
            return vmnet.datastore(name, kind, gb=size, server=server, export=_text(nas, "remotePath"))
        if kind != "vmfs":
            return vmnet.datastore(name, kind, gb=size)
        disks = [_text(extent, "diskName") for extent in _children(_child(info, "vmfs"), "extent")]
        paths = [p for disk in disks for p in self.paths_by_lun.get(self.canonical_to_key.get(disk, ""), [])]
        alive = [p for p in paths if _text(p, "state") not in ("dead", "disabled")]
        transports = [_child(p, "transport") for p in paths]
        iscsi = [t for t in transports if _type(t) == "HostInternetScsiTargetTransport"]
        if iscsi:
            target = iscsi[0]
            first = next((p for p in paths if _type(_child(p, "transport")) == "HostInternetScsiTargetTransport"), None)
            portals = [(a.text or "").strip() for t in iscsi for a in _children(t, "address") if (a.text or "").strip()]
            return vmnet.datastore(
                name,
                "iscsi",
                gb=size,
                target_iqn=_text(target, "iScsiName"),
                portal=portals[0] if portals else "",
                initiator_iqn=self.initiators.get(_text(first, "adapter"), ""),
                lun=_lun(first),
                paths=len(alive) or None,
            )
        if any(_type(t) == "HostFibreChannelTargetTransport" for t in transports):
            return vmnet.datastore(name, "fc", gb=size, lun=_lun(paths[0]), paths=len(alive) or None)
        if transports and all(_type(t) in _LOCAL_TRANSPORTS for t in transports):
            return vmnet.datastore(name, "vmfs", gb=size, local=True)
        # Sin rutas conocidas no se sabe de dónde viene: el servidor no lo
        # escribe, y eso es mejor que adivinar.
        return vmnet.datastore(name, "vmfs", gb=size)


def _lun(path: ET.Element | None) -> int | None:
    match = _LUN_NUMBER.search(_text(path, "name"))
    return int(match.group(1)) if match else None


# --- Red ----------------------------------------------------------------------------


def _add_network(client: SoapClient, found: dict[str, dict[str, Any]]) -> None:
    """Las tarjetas, las VMkernel y los vecinos de cada host, sobre lo ya leído.

    Si el vCenter no deja leer la red, cada host se queda con su hardware y sus
    datastores: lo que falta no tumba lo que ya se tiene.
    """
    asked = 0
    parents: dict[str, str] = {}
    try:
        for _moid, props in client.objects("HostSystem", NETWORK_PROPERTIES):
            name = (props.get("name").text or "").strip() if props.get("name") is not None else ""
            if name not in found:
                continue
            hints: list[ET.Element] = []
            if asked < MAX_HINT_HOSTS:
                asked += 1
                hints = _hints(client, props)
            found[name].update(host_network(props, hints))
            found[name].update(host_details(props))
            parent = props.get("parent")
            if parent is not None and parent.get("type") == "ClusterComputeResource" and (parent.text or "").strip():
                parents[name] = (parent.text or "").strip()
    except HypervisorError:
        return
    _add_clusters(client, found, parents)


def _add_clusters(client: SoapClient, found: dict[str, dict[str, Any]], parents: dict[str, str]) -> None:
    """El clúster de cada host por la API SOAP, de respaldo de la REST.

    La REST pregunta clúster por clúster con un filtro que ya falló una vez
    (el nombre cambia entre `/api` y `/rest`). Aquí el clúster es el padre del
    host, sin filtros. Solo se pide si algún host está en un clúster.
    """
    if not parents:
        return
    try:
        names = {
            moid: (props.get("name").text or "").strip()
            for moid, props in client.objects("ClusterComputeResource", ("name",))
            if props.get("name") is not None
        }
    except HypervisorError:
        return
    for host, moid in parents.items():
        if names.get(moid):
            found[host]["cluster"] = names[moid][:200]


def host_details(props: dict[str, ET.Element]) -> dict[str, Any]:
    """Lo que la ficha de un ESXi tiene sitio para guardar: la versión exacta
    («VMware ESXi 8.0.2 build-22380479»), los núcleos lógicos (con hilos, que
    es contra lo que se comparan las vCPU repartidas) y la memoria en GB."""
    product = _text(props.get("config.product"), "fullName")
    threads = _text(props.get("hardware.cpuInfo"), "numCpuThreads")
    memory = props.get("hardware.memorySize")
    memory_text = (memory.text or "").strip() if memory is not None else ""
    found: dict[str, Any] = {
        "os": product[:200],
        "cpu_count": int(threads) if threads.isdigit() else 0,
        "ram_gb": round(int(memory_text) / 1024**3) if memory_text.isdigit() else 0,
    }
    return {key: value for key, value in found.items() if value}


def _uplink_vlans(props: dict[str, ET.Element]) -> dict[str, list[int]]:
    """Las VLAN que pasan por cada vmnic de un vSwitch estándar.

    Son las de los grupos de puertos de su vSwitch: el puerto del switch al
    otro lado tiene que llevarlas todas etiquetadas. La 0 es «sin etiqueta» y
    la 4095 «la VLAN la pone la máquina»: ninguna es una VLAN que apuntar.
    Un switch distribuido (vDS) no está aquí: sus grupos viven en otro objeto.
    """
    by_switch: dict[str, set[int]] = {}
    for group in _children(props.get("config.network.portgroup")):
        spec = _child(group, "spec")
        vlan = _text(spec, "vlanId")
        if vlan.isdigit() and 1 <= int(vlan) <= 4094:
            by_switch.setdefault(_text(spec, "vswitchName"), set()).add(int(vlan))
    devices = {_text(nic, "key"): _text(nic, "device") for nic in _children(props.get("config.network.pnic"))}
    found: dict[str, list[int]] = {}
    for switch in _children(props.get("config.network.vswitch")):
        vlans = by_switch.get(_text(switch, "name"))
        if not vlans:
            continue
        for uplink in _children(switch, "pnic"):
            device = devices.get((uplink.text or "").strip())
            if device:
                found[device] = sorted(vlans)
    return found


def _hints(client: SoapClient, props: dict[str, ET.Element]) -> list[ET.Element]:
    """Lo que el ESXi oye por CDP o LLDP en cada tarjeta (`QueryNetworkHint`).

    Es una llamada por host. Una cuenta sin permiso para hacerla, o un host
    desconectado, deja ese host sin vecinos; los demás siguen.
    """
    system = props.get("configManager.networkSystem")
    moid = (system.text or "").strip() if system is not None else ""
    if not moid:
        return []
    try:
        answer = client.call("<QueryNetworkHint>" + _moref("HostNetworkSystem", moid) + "</QueryNetworkHint>")
    except HypervisorError:
        return []
    return _children(answer, "returnval")


def host_network(props: dict[str, ET.Element], hints: list[ET.Element]) -> dict[str, Any]:
    """Las tarjetas físicas (vmnic) y las VMkernel (vmk) como puertos del
    equipo, cuál es la de gestión con su IP y MAC, y los vecinos de cada vmnic.

    Las vmnic tienen la forma de las interfaces que manda SNMP; sin velocidad
    de enlace, una tarjeta está caída. Solo van las claves con algo dentro.
    """
    interfaces: list[dict[str, Any]] = []
    vlans = _uplink_vlans(props)
    for nic in _children(props.get("config.network.pnic"))[:MAX_INTERFACES]:
        name = _text(nic, "device")
        if not name:
            continue
        speed = _text(_child(nic, "linkSpeed"), "speedMb")
        port: dict[str, Any] = {
            "name": name,
            "mac": vmnet.mac(_text(nic, "mac")),
            "status": "up" if speed else "down",
            "speed_mbps": int(speed) if speed.isdigit() else 0,
            "type": "ethernet",
        }
        if vlans.get(name):
            port["vlans"] = vlans[name]
        interfaces.append(port)
    management_keys = _management_keys(props.get("config.virtualNicManagerInfo.netConfig"))
    management = management_ip = management_mac = ""
    for vnic in _children(props.get("config.network.vnic"))[:MAX_INTERFACES]:
        name = _text(vnic, "device")
        if not name:
            continue
        spec = _child(vnic, "spec")
        mac = vmnet.mac(_text(spec, "mac"))
        interfaces.append({"name": name, "mac": mac, "status": "up", "speed_mbps": 0, "type": "virtual"})
        is_management = _text(vnic, "key") in management_keys or (not management_keys and name == "vmk0")
        if is_management and not management:
            management = name
            management_ip = _text(_child(spec, "ip"), "ipAddress")
            management_mac = mac
    found: dict[str, Any] = {
        "interfaces": interfaces,
        "management_interface": management,
        "management_ip": management_ip,
        "mac": management_mac,
        "neighbors": [n for n in (_neighbor(hint) for hint in hints) if n],
    }
    return {key: value for key, value in found.items() if value}


def _management_keys(net_config: ET.Element | None) -> set[str]:
    """Las VMkernel marcadas para gestión: `management.key-vim.host.VirtualNic-vmk0`
    pasa a la clave de la VMkernel, `key-vim.host.VirtualNic-vmk0`."""
    keys: set[str] = set()
    for config in _children(net_config):
        if _text(config, "nicType") != "management":
            continue
        for selected in _children(config, "selectedVnic"):
            value = (selected.text or "").strip()
            keys.add(value.split(".", 1)[1] if value.startswith("management.") else value)
    return keys


def _neighbor(hint: ET.Element) -> dict[str, str] | None:
    """El switch y el puerto al otro lado de una vmnic.

    CDP primero: da el nombre del puerto como lo escribe el switch
    («GigabitEthernet1/0/12»), que es como se empareja con sus interfaces.
    LLDP si no hay CDP. Ni uno ni otro: esa tarjeta no tiene vecino conocido.
    """
    local = _text(hint, "device")
    if not local:
        return None
    cdp = _child(hint, "connectedSwitchPort")
    if cdp is not None and (_text(cdp, "devId") or _text(cdp, "systemName")) and _text(cdp, "portId"):
        found = {
            "protocol": "cdp",
            "local_port": local,
            "remote_name": _text(cdp, "devId") or _text(cdp, "systemName"),
            "remote_port": _text(cdp, "portId"),
            "remote_mac": "",
            "remote_ip": _text(cdp, "mgmtAddr") or _text(cdp, "address"),
            "remote_platform": _text(cdp, "hardwarePlatform"),
        }
        return {key: value[:200] for key, value in found.items()}
    lldp = _child(hint, "lldpInfo")
    if lldp is not None and _text(lldp, "portId"):
        parameters = {_text(p, "key"): _text(p, "value") for p in _children(lldp, "parameter")}
        port = _text(lldp, "portId")
        if vmnet.mac(port):
            # Algunos switches anuncian el puerto por su MAC: el nombre que
            # se empareja con sus interfaces es entonces la descripción.
            port = parameters.get("Port Description", "") or port
        found = {
            "protocol": "lldp",
            "local_port": local,
            "remote_name": parameters.get("System Name", ""),
            "remote_port": port,
            "remote_mac": vmnet.mac(_text(lldp, "chassisId")),
            "remote_ip": parameters.get("Management Address", ""),
            "remote_sys_descr": parameters.get("System Description", ""),
        }
        if not (found["remote_name"] or found["remote_mac"]):
            return None
        return {key: value[:200] for key, value in found.items()}
    return None
