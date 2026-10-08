"""vCenter y Proxmox por REST, con la librería estándar y nada más.

**`pyvmomi` está descartado a propósito.** Los dos hipervisores se hablan hoy
con HTTP y JSON --vSphere Automation API en el de VMware, `/api2/json` en el de
Proxmox-- y el agente ya tiene su cliente HTTP de biblioteca estándar para
hablar con el servidor. Meter el SDK de VMware serían decenas de megas y una
cadena de dependencias entera para hacer cuatro peticiones GET.

**La verificación de TLS no se desactiva.** El vCenter de una pyme casi siempre
lleva un certificado autofirmado, y hay dos salidas correctas: dar la CA que lo
firma, o confiar en ese certificado concreto desde la web (`agent.tlspin`, su
huella viaja con la credencial). Sin verificación, cualquiera en medio de la
red se queda con la contraseña del vCenter, que es la llave de todas las
máquinas virtuales de la empresa.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from agent import tlspin, vmnet

TIMEOUT_SECONDS = 20
VMWARE_PORT = 443
PROXMOX_PORT = 8006

#: Cuántas máquinas virtuales se miran en detalle. Cada detalle es una petición
#: más, y en una pyme no hay dos mil; el tope está para que un vCenter de un
#: cliente grande no convierta un barrido en media hora de peticiones.
MAX_DETAILED_VMS = 500

#: Cuántos ESXi se cruzan para saber en cuál vive cada máquina. Por el mismo
#: motivo que el tope de arriba: averiguar el host es **una petición por host**,
#: porque es como la API de vCenter deja filtrar. En una pyme son dos o tres;
#: pasado el tope, las máquinas de los demás llegan sin host, que es lo que
#: pasaba con todas antes de cruzarlo.
MAX_HOSTS_CROSSED = 50

#: A cuántas máquinas encendidas se les pregunta por dentro (las direcciones
#: que dicen las VMware Tools o el agente QEMU). Es una petición más por
#: máquina; en una pyme no se llega, y en un cliente grande el resto llega
#: con sus tarjetas y sin direcciones, que es lo que había antes.
MAX_GUEST_QUERIES = 200


class HypervisorError(Exception):
    """No se pudo hablar con el hipervisor, o no dejó entrar.

    Para el límite de credenciales (spec 2.3) dice además cómo fue:
    `unreachable` si no se llegó a mandar la credencial (nada contestó, TLS no
    se fió), `logged_in` si entró y lo que falló fue otra cosa, y `status` el
    código HTTP si lo hubo. Sin ninguna de las dos marcas, cuenta como un
    inicio de sesión fallido: es lo prudente.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        unreachable: bool = False,
        logged_in: bool = False,
        certificate: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.unreachable = unreachable
        self.logged_in = logged_in
        #: Cuando no se fió del certificado: el que presentó (`tlspin.describe`),
        #: para que la web pueda ofrecer confiar en él.
        self.certificate = certificate


def login_outcome(error: "HypervisorError | None") -> str:
    """El veredicto de un `login()` para el límite de credenciales (`agent.memory`)."""
    if error is None or error.logged_in:
        return "ok"
    return "unreachable" if error.unreachable else "auth_failed"


def untrusted(url: str, exc: BaseException) -> HypervisorError:
    """El error de un certificado del que no se fía, con el certificado dentro."""
    return HypervisorError(
        str(getattr(exc, "reason", exc)), unreachable=True, certificate=tlspin.describe(url)
    )


class RestClient:
    """Peticiones JSON contra una API, con cabeceras propias.

    No sigue redirecciones por lo mismo que `agent.client`: el manejador por
    defecto de `urllib` reenvía las cabeceras al destino nuevo, y entre ellas va
    el identificador de sesión del vCenter.
    """

    def __init__(self, base_url: str, *, ca_file: str = "", tls_pin: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self._opener = urllib.request.build_opener(_NoRedirects, tlspin.https_handler(ca_file, tls_pin))

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        data = urllib.parse.urlencode(body).encode() if body else None
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"Accept": "application/json", **(headers or {})},
            method=method,
        )
        try:
            with self._opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                raw = response.read().decode(errors="replace")
        except urllib.error.HTTPError as exc:
            raise HypervisorError(f"{exc.code} en {path}", status=exc.code) from exc
        except urllib.error.URLError as exc:
            # Al conectar o al mandar (TLS incluido): la credencial no llegó a
            # evaluarse.
            if tlspin.is_untrusted(exc):
                raise untrusted(self.base_url, exc) from exc
            raise HypervisorError(str(getattr(exc, "reason", exc)), unreachable=True) from exc
        except (TimeoutError, ssl.SSLError) as exc:
            # Esperando la respuesta, con la petición ya enviada: cuenta.
            raise HypervisorError(str(getattr(exc, "reason", exc))) from exc
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            # Un portal cautivo, un proxy o el propio hipervisor devolviendo su
            # página de error en HTML. Sin esto, el `for` de más arriba recorre
            # una cadena y saca hallazgos de una letra cada uno.
            raise HypervisorError("la respuesta no era JSON") from exc


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102, ANN001
        raise urllib.error.HTTPError(
            req.full_url, code, f"Redirección a {newurl}; no se sigue.", headers, fp
        )


# --- VMware vCenter ---------------------------------------------------------------

#: La API cambió de sitio en la 7.0. Se prueban las dos rutas porque en una pyme
#: hay vCenters de 6.7 con soporte pagado y no tiene sentido dejarlos fuera.
VMWARE_SESSION_PATHS: tuple[str, ...] = ("/api/session", "/rest/com/vmware/cis/session")
VMWARE_PREFIXES: dict[str, str] = {"/api/session": "/api", "/rest/com/vmware/cis/session": "/rest"}


def _values(answer: Any) -> list[dict[str, Any]]:
    """La lista de una respuesta de vCenter, venga como venga.

    La 7.0 devuelve la lista pelada; la 6.7 la envuelve en ``{"value": [...]}``.
    """
    if isinstance(answer, dict):
        answer = answer.get("value")
    if not isinstance(answer, list):
        return []
    return [item for item in answer if isinstance(item, dict)]


class VMwareClient:
    """Lo justo del vCenter: sus hosts y sus máquinas virtuales."""

    def __init__(
        self, host: str, username: str, secret: str, *, port: int = 0, ca_file: str = "", tls_pin: str = ""
    ) -> None:
        self.rest = RestClient(f"https://{host}:{port or VMWARE_PORT}", ca_file=ca_file, tls_pin=tls_pin)
        self.username = username
        self.secret = secret
        self.prefix = ""
        self.token = ""
        self._cluster_cache: dict[str, str] | None = None

    def login(self) -> None:
        basic = base64.b64encode(f"{self.username}:{self.secret}".encode()).decode()
        last: Exception | None = None
        for path in VMWARE_SESSION_PATHS:
            try:
                answer = self.rest.request(
                    "POST", path, headers={"Authorization": f"Basic {basic}"}
                )
            except HypervisorError as exc:
                last = exc
                if exc.status == 404:
                    continue  # un vCenter 6.7: la sesión está en la otra ruta
                # Un 401 (o cualquier otra cosa) no se repite en la otra ruta:
                # sería un segundo inicio de sesión fallido de la misma cuenta.
                raise
            token = answer.get("value") if isinstance(answer, dict) else answer
            if isinstance(token, str) and token:
                self.token = token
                self.prefix = VMWARE_PREFIXES[path]
                return
        if isinstance(last, HypervisorError) and last.status == 404:
            # Ninguna de las dos rutas existe: no es un vCenter, y nadie
            # evaluó la credencial.
            raise HypervisorError(str(last), status=404, unreachable=True)
        raise HypervisorError(str(last) if last else "el vCenter no devolvió sesión")

    def _get(self, path: str) -> Any:
        return self.rest.request("GET", f"{self.prefix}{path}", headers={"vmware-api-session-id": self.token})

    def hosts(self) -> list[dict[str, Any]]:
        """Los servidores ESXi del vCenter, cada uno con su clúster.

        Fabricante, modelo y serie no los da la API REST (viven en la SOAP,
        `HostSystem.hardware`): salen vacíos y el servidor los completa por
        otro camino o cuando llegue el cliente SOAP.
        """
        clusters = self._clusters_by_host()
        return [
            {
                "name": str(host.get("name") or ""),
                "power_state": str(host.get("power_state") or ""),
                "connection_state": str(host.get("connection_state") or ""),
                "cluster": clusters.get(str(host.get("name") or ""), ""),
            }
            for host in _values(self._get("/vcenter/host"))
            if host.get("name")
        ]

    def _clusters_by_host(self) -> dict[str, str]:
        """En qué clúster está cada ESXi: `{nombre del host: nombre del clúster}`.

        `/vcenter/host` no lo dice, igual que `/vcenter/vm` no dice el host:
        se pregunta clúster por clúster, que en una pyme son uno o dos. Se
        guarda la respuesta porque `hosts()` y `virtual_machines()` la
        necesitan las dos. Un clúster que no contesta deja a sus hosts sin
        clúster; los demás ni se enteran.
        """
        if self._cluster_cache is not None:
            return self._cluster_cache
        by_host: dict[str, str] = {}
        try:
            clusters = _values(self._get("/vcenter/cluster"))
        except HypervisorError:
            clusters = []
        answers: list[tuple[str, frozenset[str]]] = []
        for cluster in clusters[:MAX_HOSTS_CROSSED]:
            identifier = str(cluster.get("cluster") or "")
            name = str(cluster.get("name") or "")
            if not identifier or not name:
                continue
            try:
                members = _values(
                    self._get(f"/vcenter/host?filter.clusters={urllib.parse.quote(identifier)}")
                )
            except HypervisorError:
                continue
            answers.append((name, frozenset(str(m.get("name") or "") for m in members if m.get("name"))))
        if _filter_ignored([hosts for _name, hosts in answers]):
            # El vCenter no ha entendido el filtro y ha contestado con todos:
            # cada host saldría en el último clúster preguntado. Mejor ninguno.
            answers = []
        for name, hosts in answers:
            for host in hosts:
                by_host[host] = name
        self._cluster_cache = by_host
        return by_host

    def _hosts_by_vm(self) -> dict[str, str]:
        """En qué ESXi vive cada máquina: `{id de la VM: nombre del host}`.

        vCenter **no lo dice** en `/vcenter/vm`, y sin esto ninguna máquina se
        colgaba de su servidor: llegaban todas sueltas, y «¿de qué depende este
        servidor?» --la pregunta que justifica el modelo de datos-- se quedaba
        sin la mitad de la respuesta. Proxmox sí lo trae de serie, así que el
        fallo solo se veía con un vCenter delante.

        Se pregunta host por host porque es como la API deja filtrar: son
        tantas peticiones como ESXi tenga el vCenter, que en una pyme son dos o
        tres. Si alguna falla, esas máquinas se quedan sin host y las demás ni
        se enteran -- un hallazgo incompleto vale más que ninguno.
        """
        by_vm: dict[str, str] = {}
        try:
            hosts = _values(self._get("/vcenter/host"))
        except HypervisorError:
            return by_vm
        answers: list[tuple[str, frozenset[str]]] = []
        for host in hosts[:MAX_HOSTS_CROSSED]:
            identifier = str(host.get("host") or "")
            name = str(host.get("name") or "")
            if not identifier or not name:
                continue
            try:
                machines = _values(
                    self._get(f"/vcenter/vm?filter.hosts={urllib.parse.quote(identifier)}")
                )
            except HypervisorError:
                continue
            answers.append((name, frozenset(str(m.get("vm") or "") for m in machines if m.get("vm"))))
        if _filter_ignored([machines for _name, machines in answers]):
            # Un filtro que no se ha entendido devuelve todas las máquinas
            # para cada host, y todas acabarían en el último. Sin host es
            # verdad; en el host equivocado, no.
            return by_vm
        for name, machines in answers:
            for machine_id in machines:
                by_vm[machine_id] = name
        return by_vm

    def virtual_machines(self) -> list[dict[str, Any]]:
        """Las máquinas virtuales, con lo que hace falta para darlas de alta."""
        found: list[dict[str, Any]] = []
        hosts_by_vm = self._hosts_by_vm()
        clusters = self._clusters_by_host()
        guests_asked = 0
        for vm in _values(self._get("/vcenter/vm"))[:MAX_DETAILED_VMS]:
            identifier = str(vm.get("vm") or "")
            if not identifier:
                continue
            detail = self._detail(identifier)
            guest: list[dict[str, Any]] = []
            powered = str(vm.get("power_state") or detail.get("power_state") or "").upper() == "POWERED_ON"
            if powered and detail.get("nics") and guests_asked < MAX_GUEST_QUERIES:
                guests_asked += 1
                guest = self._guest_interfaces(identifier)
            memory_mib = _number(vm.get("memory_size_MiB")) or _number(
                (detail.get("memory") or {}).get("size_MiB")
            )
            found.append(
                {
                    "id": identifier,
                    "name": str(vm.get("name") or identifier),
                    "host": hosts_by_vm.get(identifier, ""),
                    "cluster": clusters.get(hosts_by_vm.get(identifier, ""), ""),
                    "status": _vmware_status(str(vm.get("power_state") or "")),
                    "vcpus": int(
                        _number(vm.get("cpu_count")) or _number((detail.get("cpu") or {}).get("count"))
                    ),
                    "ram_gb": round(memory_mib / 1024) if memory_mib else 0,
                    "disk_gb": _vmware_disk_gb(detail),
                    "operating_system": _vmware_guest_os(detail),
                    "interfaces": vmnet.vmware_interfaces(detail, guest),
                    "disks": vmnet.vmware_disks(detail),
                }
            )
        return found

    def _guest_interfaces(self, identifier: str) -> list[dict[str, Any]]:
        """Las direcciones que ve el invitado. Solo con VMware Tools: sin ellas
        el vCenter contesta con un error, y la máquina llega sin direcciones."""
        try:
            return _values(self._get(f"/vcenter/vm/{urllib.parse.quote(identifier)}/guest/networking/interfaces"))
        except HypervisorError:
            return []

    def _detail(self, identifier: str) -> dict[str, Any]:
        """El detalle de una máquina. Vacío si no se puede leer: la ficha con lo
        básico vale más que ningún hallazgo, y el permiso de lectura de detalle
        no siempre lo tiene el usuario que se ha configurado."""
        try:
            answer = self._get(f"/vcenter/vm/{urllib.parse.quote(identifier)}")
        except HypervisorError:
            return {}
        if isinstance(answer, dict):
            value = answer.get("value")
            return value if isinstance(value, dict) else answer
        return {}


def _filter_ignored(answers: list[frozenset[str]]) -> bool:
    """Si un filtro de la API se ha quedado sin aplicar.

    Varias preguntas distintas («las máquinas del host 16», «las del 22») que
    contestan exactamente lo mismo, y no vacío, no son dos hosts gemelos: es
    un vCenter que no ha entendido el parámetro y ha devuelto la lista
    entera. Con una sola pregunta no se puede saber, y se da por buena.
    """
    filled = [answer for answer in answers if answer]
    return len(filled) > 1 and len(set(filled)) == 1


def _vmware_status(power_state: str) -> str:
    return {
        "POWERED_ON": "running",
        "POWERED_OFF": "stopped",
        "SUSPENDED": "suspended",
    }.get(power_state.upper(), "running")


def _vmware_disk_gb(detail: dict[str, Any]) -> int:
    """La suma de sus discos, en GB. Los discos vienen indexados por su id."""
    disks = detail.get("disks")
    total = 0.0
    values = disks.values() if isinstance(disks, dict) else (disks if isinstance(disks, list) else [])
    for disk in values:
        if isinstance(disk, dict):
            payload = disk.get("value") if isinstance(disk.get("value"), dict) else disk
            total += _number(payload.get("capacity"))
    return round(total / (1024**3)) if total else 0


def _vmware_guest_os(detail: dict[str, Any]) -> str:
    """El sistema operativo, con el nombre legible si el vCenter lo da.

    ``guest_OS`` es el identificador de VMware (`UBUNTU_64`); el nombre bonito
    solo aparece cuando las VMware Tools están puestas.
    """
    identity = detail.get("guest_identity")
    if isinstance(identity, dict) and identity.get("full_name"):
        full = identity["full_name"]
        if isinstance(full, dict):
            return str(full.get("default_message") or "")
        return str(full)
    raw = str(detail.get("guest_OS") or "")
    return raw.replace("_", " ").title() if raw else ""


# --- Proxmox ----------------------------------------------------------------------


class ProxmoxClient:
    """Lo justo de Proxmox: sus nodos y sus máquinas (KVM y contenedores).

    Admite las dos formas de entrar: usuario y contraseña, y **token de API**
    (`usuario@pam!nombre` con su secreto), que es la buena para un agente porque
    se puede limitar a solo lectura y caduca cuando se quiera.
    """

    def __init__(
        self, host: str, username: str, secret: str, *, port: int = 0, ca_file: str = "", tls_pin: str = ""
    ) -> None:
        self.rest = RestClient(f"https://{host}:{port or PROXMOX_PORT}", ca_file=ca_file, tls_pin=tls_pin)
        self.username = username
        self.secret = secret
        self.headers: dict[str, str] = {}

    @property
    def uses_token(self) -> bool:
        return "!" in self.username

    def login(self) -> None:
        if self.uses_token:
            self.headers = {"Authorization": f"PVEAPIToken={self.username}={self.secret}"}
            return
        answer = self.rest.request(
            "POST",
            "/api2/json/access/ticket",
            body={"username": self.username, "password": self.secret},
        )
        data = answer.get("data") if isinstance(answer, dict) else None
        ticket = (data or {}).get("ticket") if isinstance(data, dict) else None
        if not ticket:
            raise HypervisorError("Proxmox no devolvió sesión")
        # Solo lectura: sin `CSRFPreventionToken` no se puede escribir nada, y
        # este agente no escribe en el hipervisor ni debe poder hacerlo.
        self.headers = {"Cookie": f"PVEAuthCookie={ticket}"}

    def _get(self, path: str) -> list[dict[str, Any]]:
        answer = self.rest.request("GET", path, headers=self.headers)
        data = answer.get("data") if isinstance(answer, dict) else None
        if not isinstance(data, list):
            return []
        return [item for item in data if isinstance(item, dict)]

    def _get_object(self, path: str) -> dict[str, Any]:
        """Una respuesta cuyo `data` es un objeto (la configuración de una
        máquina), o vacío si no se puede leer."""
        try:
            answer = self.rest.request("GET", path, headers=self.headers)
        except HypervisorError:
            return {}
        data = answer.get("data") if isinstance(answer, dict) else None
        return data if isinstance(data, dict) else {}

    def _network_and_disks(self, node: str, kind: str, vmid: str, running: bool, budget: list[int]) -> dict[str, Any]:
        """Tarjetas y discos de una máquina, de su configuración.

        Una petición por máquina, y otra más para las direcciones de una KVM
        encendida con el agente QEMU puesto. `budget` es el contador de
        máquinas a las que aún se puede preguntar (`MAX_GUEST_QUERIES`).
        """
        if not node or kind not in ("qemu", "lxc") or budget[0] <= 0:
            return {"interfaces": [], "disks": []}
        budget[0] -= 1
        base = f"/api2/json/nodes/{urllib.parse.quote(node)}/{kind}/{urllib.parse.quote(vmid)}"
        config = self._get_object(f"{base}/config")
        container = kind == "lxc"
        guest: Any = None
        agent_on = str(config.get("agent") or "").split(",")[0].strip() in ("1", "enabled=1")
        if not container and running and agent_on:
            guest = self._get_object(f"{base}/agent/network-get-interfaces")
        return {
            "interfaces": vmnet.proxmox_interfaces(config, container=container, guest=guest),
            "disks": vmnet.proxmox_disks(config, container=container),
        }

    def hosts(self) -> list[dict[str, Any]]:
        cluster = self._cluster_name()
        storages = self._storage_config()
        usage = self._storage_usage()
        return [
            {
                "name": str(node.get("node") or ""),
                "power_state": "POWERED_ON" if node.get("status") == "online" else "",
                "connection_state": str(node.get("status") or ""),
                "cluster": cluster,
                "datastores": _proxmox_datastores(str(node.get("node") or ""), storages, usage),
            }
            for node in self._get("/api2/json/nodes")
            if node.get("node")
        ]

    def _storage_config(self) -> list[dict[str, Any]]:
        """La configuración de almacenamiento del clúster (`/storage`): tipo,
        portal y destino iSCSI, servidor y exportación NFS o SMB. Necesita
        `Datastore.Audit`; sin él, los hosts llegan sin datastores."""
        try:
            return self._get("/api2/json/storage")
        except HypervisorError:
            return []

    def _storage_usage(self) -> dict[tuple[str, str], dict[str, Any]]:
        """`{(nodo, almacenamiento): uso}`, para el tamaño de cada uno."""
        try:
            entries = self._get("/api2/json/cluster/resources?type=storage")
        except HypervisorError:
            return {}
        return {(str(e.get("node") or ""), str(e.get("storage") or "")): e for e in entries}

    def _cluster_name(self) -> str:
        """El nombre del clúster de Proxmox, o "" si el nodo va suelto.

        `/cluster/status` trae una entrada `type: cluster` solo cuando hay
        clúster; un Proxmox de un nodo --lo normal en una pyme-- no la tiene,
        y eso es la respuesta correcta, no un error.
        """
        if getattr(self, "_cluster", None) is None:
            try:
                entries = self._get("/api2/json/cluster/status")
            except HypervisorError:
                entries = []
            self._cluster = next(
                (str(e.get("name") or "") for e in entries if e.get("type") == "cluster"), ""
            )
        return self._cluster

    def virtual_machines(self) -> list[dict[str, Any]]:
        """Máquinas y contenedores en una sola consulta al clúster.

        `cluster/resources` da todo de una vez incluso en un Proxmox de un solo
        nodo, así que no hace falta recorrer nodo por nodo.
        """
        found: list[dict[str, Any]] = []
        cluster = self._cluster_name()
        budget = [MAX_GUEST_QUERIES]
        for resource in self._get("/api2/json/cluster/resources?type=vm")[:MAX_DETAILED_VMS]:
            identifier = str(resource.get("vmid") or "")
            if not identifier:
                continue
            inside = self._network_and_disks(
                str(resource.get("node") or ""),
                str(resource.get("type") or "qemu"),
                identifier,
                resource.get("status") == "running",
                budget,
            )
            memory = _number(resource.get("maxmem"))
            disk = _number(resource.get("maxdisk"))
            found.append(
                {
                    "id": identifier,
                    "name": str(resource.get("name") or f"vm-{identifier}"),
                    "status": "running" if resource.get("status") == "running" else "stopped",
                    "vcpus": int(_number(resource.get("maxcpu"))),
                    "ram_gb": round(memory / (1024**3)) if memory else 0,
                    "disk_gb": round(disk / (1024**3)) if disk else 0,
                    # Proxmox no dice qué sistema hay dentro de una KVM; de un
                    # contenedor sí, y decir «contenedor LXC» ya orienta.
                    "operating_system": "Contenedor LXC" if resource.get("type") == "lxc" else "",
                    "host": str(resource.get("node") or ""),
                    "cluster": cluster,
                    **inside,
                }
            )
        return found


#: Lo que no es un sitio donde vivan discos de máquinas.
_PROXMOX_DISK_CONTENT = {"images", "rootdir"}


def _proxmox_datastores(
    node: str, storages: list[dict[str, Any]], usage: dict[tuple[str, str], dict[str, Any]]
) -> list[dict[str, Any]]:
    """Los almacenamientos de discos que tiene este nodo, con su origen.

    Un LVM montado sobre un iSCSI (`base: <almacenamiento iscsi>:<lun>`) es,
    para la traza, ese iSCSI: el LVM es solo cómo se reparte. Por eso hereda su
    portal y su destino, y viaja como iSCSI.
    """
    by_id = {str(s.get("storage") or ""): s for s in storages}
    found: list[dict[str, Any] | None] = []
    for storage in storages:
        identifier = str(storage.get("storage") or "")
        if not identifier or str(storage.get("disable") or "") in ("1", "true"):
            continue
        nodes = {n.strip() for n in str(storage.get("nodes") or "").split(",") if n.strip()}
        if nodes and node not in nodes:
            continue
        content = {c.strip() for c in str(storage.get("content") or "").split(",") if c.strip()}
        if not content & _PROXMOX_DISK_CONTENT:
            continue
        kind = str(storage.get("type") or "")
        source = storage
        base = str(storage.get("base") or "")
        if base:
            parent = by_id.get(base.split(":", 1)[0])
            if parent is not None and str(parent.get("type") or "") == "iscsi":
                source, kind = parent, "iscsi"
        used = usage.get((node, identifier)) or {}
        export = str(source.get("export") or source.get("share") or "")
        found.append(
            vmnet.datastore(
                identifier,
                kind,
                gb=vmnet.gb(used.get("maxdisk")),
                local=not bool(storage.get("shared") or source.get("shared")) and kind not in ("nfs", "cifs", "iscsi"),
                portal=str(source.get("portal") or ""),
                target_iqn=str(source.get("target") or ""),
                server=str(source.get("server") or ""),
                export=export,
            )
        )
    return [item for item in found if item][: vmnet.MAX_PER_MACHINE]


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
