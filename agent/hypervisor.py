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

from agent import tlspin

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
        """Los servidores ESXi del vCenter."""
        return [
            {
                "name": str(host.get("name") or ""),
                "power_state": str(host.get("power_state") or ""),
                "connection_state": str(host.get("connection_state") or ""),
            }
            for host in _values(self._get("/vcenter/host"))
            if host.get("name")
        ]

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
            for machine in machines:
                machine_id = str(machine.get("vm") or "")
                if machine_id:
                    by_vm[machine_id] = name
        return by_vm

    def virtual_machines(self) -> list[dict[str, Any]]:
        """Las máquinas virtuales, con lo que hace falta para darlas de alta."""
        found: list[dict[str, Any]] = []
        hosts_by_vm = self._hosts_by_vm()
        for vm in _values(self._get("/vcenter/vm"))[:MAX_DETAILED_VMS]:
            identifier = str(vm.get("vm") or "")
            if not identifier:
                continue
            detail = self._detail(identifier)
            memory_mib = _number(vm.get("memory_size_MiB")) or _number(
                (detail.get("memory") or {}).get("size_MiB")
            )
            found.append(
                {
                    "id": identifier,
                    "name": str(vm.get("name") or identifier),
                    "host": hosts_by_vm.get(identifier, ""),
                    "status": _vmware_status(str(vm.get("power_state") or "")),
                    "vcpus": int(
                        _number(vm.get("cpu_count")) or _number((detail.get("cpu") or {}).get("count"))
                    ),
                    "ram_gb": round(memory_mib / 1024) if memory_mib else 0,
                    "disk_gb": _vmware_disk_gb(detail),
                    "operating_system": _vmware_guest_os(detail),
                }
            )
        return found

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

    def hosts(self) -> list[dict[str, Any]]:
        return [
            {
                "name": str(node.get("node") or ""),
                "power_state": "POWERED_ON" if node.get("status") == "online" else "",
                "connection_state": str(node.get("status") or ""),
            }
            for node in self._get("/api2/json/nodes")
            if node.get("node")
        ]

    def virtual_machines(self) -> list[dict[str, Any]]:
        """Máquinas y contenedores en una sola consulta al clúster.

        `cluster/resources` da todo de una vez incluso en un Proxmox de un solo
        nodo, así que no hace falta recorrer nodo por nodo.
        """
        found: list[dict[str, Any]] = []
        for resource in self._get("/api2/json/cluster/resources?type=vm")[:MAX_DETAILED_VMS]:
            identifier = str(resource.get("vmid") or "")
            if not identifier:
                continue
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
                }
            )
        return found


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
