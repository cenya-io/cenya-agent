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
    """Hardware y datastores de cada ESXi del vCenter, por nombre de host."""
    client = SoapClient(host, port=port, ca_file=ca_file, tls_pin=tls_pin)
    client.login(username, secret)
    try:
        datastores = {moid: props for moid, props in client.objects("Datastore", DATASTORE_PROPERTIES)}
        found: dict[str, dict[str, Any]] = {}
        for _moid, props in client.objects("HostSystem", HOST_PROPERTIES):
            name = (props.get("name").text or "").strip() if props.get("name") is not None else ""
            if name:
                found[name] = host_inventory(props, datastores)
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
