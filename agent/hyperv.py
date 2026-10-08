"""Hyper-V por PowerShell remoto sobre WinRM.

Hyper-V **no tiene API REST**: la forma de preguntarle es la misma con la que
ya se inventaría cualquier Windows, un PowerShell remoto. Por eso este cliente
no trae transporte propio: reutiliza `agent.winrm` entero --su `pywinrm`
opcional, su `endpoint`, su orden de transportes y sus timeouts-- y solo pone
encima el guion y la traducción al contrato de `agent.hypervisor`.

El contrato es el de `VMwareClient` y `ProxmoxClient` a propósito: `login()`,
`hosts()` y `virtual_machines()`, lanzando `HypervisorError` cuando algo va
mal. Así el colector de hipervisores no cambia: Hyper-V es una entrada más en
su tabla de clientes.

Todo lo que se pregunta va en **un solo PowerShell** que devuelve JSON, por lo
mismo que en `agent.winrm`: una conexión WinRM tarda más en abrirse que en
contestar, así que `login()` ya se lo lleva todo y las otras dos llamadas leen
de lo cacheado sin volver a la red.

**La verificación de TLS no se desactiva.** Contra el 5986 con certificado
autofirmado la salida correcta es dar la CA de la empresa: sin verificación,
cualquiera en medio de la red se queda con la contraseña de administrador del
host de virtualización, que es la llave de todas sus máquinas.
"""

from __future__ import annotations

import json
from typing import Any

from agent import vmnet, winrm
from agent.hypervisor import HypervisorError

#: Lo que se le pregunta a un Hyper-V, de una vez. `has_hyperv` mira si existe
#: el servicio `vmms`: apuntar esta credencial a un Windows cualquiera es un
#: error de configuración y hay que decirlo, no devolver cero máquinas como si
#: el host estuviera vacío. El `@()` alrededor de las listas es obligatorio:
#: `ConvertTo-Json` desenvuelve una lista de un solo elemento y mandaría un
#: objeto suelto donde el agente espera una lista.
SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$vmms = Get-Service -Name 'vmms' -ErrorAction SilentlyContinue
$vms = @()
if ($vmms) {
  foreach ($vm in @(Get-VM -ErrorAction SilentlyContinue)) {
    $disk = [long](($vm.HardDrives | Get-VHD -ErrorAction SilentlyContinue |
      Measure-Object -Property Size -Sum).Sum)
    $nics = @(foreach ($n in @(Get-VMNetworkAdapter -VM $vm -ErrorAction SilentlyContinue)) {
      $tag = Get-VMNetworkAdapterVlan -VMNetworkAdapter $n -ErrorAction SilentlyContinue
      @{
        name = [string]$n.Name
        mac  = [string]$n.MacAddress
        ips  = @($n.IPAddresses | ForEach-Object { [string]$_ })
        vlan = [int]$tag.AccessVlanId
      }
    })
    $drives = @(foreach ($hd in @($vm.HardDrives)) {
      @{
        path  = [string]$hd.Path
        bytes = [long](Get-VHD -Path $hd.Path -ErrorAction SilentlyContinue).Size
      }
    })
    $vms += @{
      id         = [string]$vm.VMId
      name       = [string]$vm.Name
      state      = [string]$vm.State
      vcpus      = [int]$vm.ProcessorCount
      ram_bytes  = [long]$vm.MemoryStartup
      disk_bytes = $disk
      nics       = $nics
      drives     = $drives
    }
  }
}
$cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction SilentlyContinue
$cluster = ''
if (Get-Command -Name Get-Cluster -ErrorAction SilentlyContinue) {
  $cluster = [string](Get-Cluster -ErrorAction SilentlyContinue).Name
}
$result = @{
  hostname     = [string]$env:COMPUTERNAME
  has_hyperv   = [bool]$vmms
  vms          = @($vms)
  manufacturer = [string]$cs.Manufacturer
  model        = [string]$cs.Model
  serial       = [string]$bios.SerialNumber
  cluster      = $cluster
}
$result | ConvertTo-Json -Depth 6 -Compress
"""

def _as_list(value: Any) -> list[Any]:
    """`ConvertTo-Json` desenvuelve las listas de un elemento: una tarjeta sola
    llega como objeto y una lista vacía como `null`."""
    if isinstance(value, list):
        return value
    if value is None or value == "":
        return []
    return [value]


def _text(value: Any) -> str:
    """Un texto del guion, recortado. `ConvertTo-Json` puede mandar `null`."""
    return str(value or "").strip()[:200]


#: El estado de Hyper-V al vocabulario del producto. `Saved` es una suspensión
#: a disco, así que se cuenta como suspendida. Lo desconocido cae en `running`
#: por el mismo criterio conservador que `_vmware_status`: mejor avisar de una
#: máquina que quizá corre que darla por apagada y que alguien la desenchufe.
STATES: dict[str, str] = {
    "Running": "running",
    "Off": "stopped",
    "Paused": "suspended",
    "Saved": "suspended",
}


class HyperVClient:
    """Lo justo de un Hyper-V: él mismo como host, y sus máquinas virtuales."""

    def __init__(
        self, host: str, username: str, secret: str, *, port: int = 0, ca_file: str = "", tls_pin: str = ""
    ) -> None:
        # `tls_pin` se acepta por el contrato común y no se usa: WinRM va por
        # `requests`, que sigue con la CA (`ca_file`).
        self.host = host
        self.username = username
        self.secret = secret
        self.port = port
        self.ca_file = ca_file
        self._data: dict[str, Any] = {}

    def login(self) -> None:
        """Entra por WinRM y se lleva todo el inventario de una vez.

        El bucle de transportes es el de `winrm.query`: NTLM primero, `basic`
        después, y si el PowerShell falló **habiendo entrado**, no se prueba el
        siguiente transporte --sería un intento fallido más contra la política
        de bloqueo del dominio, y no arreglaría nada.
        """
        if not winrm.AVAILABLE:
            raise HypervisorError("falta pywinrm", unreachable=True)
        last_error = ""
        for transport in winrm.TRANSPORTS:
            try:
                session = winrm.pywinrm.Session(
                    winrm.endpoint(self.host, self.port),
                    auth=(self.username, self.secret),
                    transport=transport,
                    read_timeout_sec=winrm.READ_TIMEOUT_SECONDS,
                    operation_timeout_sec=winrm.OPERATION_TIMEOUT_SECONDS,
                    server_cert_validation="validate",
                    ca_trust_path=self.ca_file or None,
                )
                result = session.run_ps(SCRIPT)
            except Exception as exc:  # noqa: BLE001 - pywinrm lanza de todo: HTTP, TLS, WSMan
                last_error = f"{type(exc).__name__}: {exc}"
                if winrm.before_auth(exc):
                    continue
                # Como en `winrm.query`: una clave rechazada no se repite por
                # otro transporte (sería otro fallo de la misma cuenta).
                raise HypervisorError(last_error) from None
            if result.status_code != 0:
                stderr = (result.std_err or b"").decode(errors="replace").strip()[:200]
                raise HypervisorError(stderr or "el PowerShell falló sin decir por qué", logged_in=True)
            try:
                self._data = self._parse(result.std_out)
            except HypervisorError as exc:
                # Entró: lo que falla es lo que contestó, no la credencial.
                raise HypervisorError(str(exc), logged_in=True) from None
            return
        raise HypervisorError(last_error or "no se pudo conectar", unreachable=True)

    def _parse(self, raw: bytes | str) -> dict[str, Any]:
        """El JSON del guion, ya comprobado.

        Aquí es donde se distingue «no me contestó JSON» --un Windows viejo, un
        proxy en medio-- de «me contestó un Windows que no es un Hyper-V»: el
        segundo es un error de configuración de la credencial y el mensaje
        tiene que orientar hacia ahí, no hacia la red.
        """
        text = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
        try:
            parsed = json.loads(text.strip() or "null")
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HypervisorError("la respuesta no era JSON") from exc
        if not isinstance(parsed, dict):
            raise HypervisorError("la respuesta no era JSON")
        if not parsed.get("has_hyperv"):
            raise HypervisorError(
                "el equipo no es un servidor de Hyper-V (no existe el servicio vmms)"
            )
        return parsed

    def hosts(self) -> list[dict[str, Any]]:
        """El propio servidor, como host de virtualización.

        Una sola entrada: a diferencia de un vCenter, aquí se habla con el host
        directamente, y si contestó es que está encendido y en línea.
        """
        return [
            {
                "name": str(self._data.get("hostname") or self.host),
                "power_state": "POWERED_ON",
                "connection_state": "online",
                # Clúster de conmutación por error, si lo hay; fabricante,
                # modelo y serie de WMI, como los de cualquier Windows.
                "cluster": _text(self._data.get("cluster")),
                "manufacturer": _text(self._data.get("manufacturer")),
                "model": _text(self._data.get("model")),
                "serial": _text(self._data.get("serial")),
            }
        ]

    def virtual_machines(self) -> list[dict[str, Any]]:
        """Las máquinas del host, con lo que hace falta para darlas de alta.

        El identificador es el `VMId` que da Hyper-V, no el nombre: renombrar
        una máquina es un gesto de un segundo y la huella tiene que sobrevivir.
        """
        hostname = str(self._data.get("hostname") or self.host)
        vms = self._data.get("vms")
        if isinstance(vms, dict):
            # `ConvertTo-Json` desenvuelve las listas de un elemento. El guion
            # ya fuerza el array con `@()`, pero un guion editado a mano en un
            # cliente no puede convertir su única máquina en un `TypeError`.
            vms = [vms]
        if not isinstance(vms, list):
            return []
        found: list[dict[str, Any]] = []
        for vm in vms:
            if not isinstance(vm, dict):
                continue
            identifier = str(vm.get("id") or "")
            if not identifier:
                continue
            ram = _number(vm.get("ram_bytes"))
            disk = _number(vm.get("disk_bytes"))
            found.append(
                {
                    "id": identifier,
                    "name": str(vm.get("name") or identifier),
                    "status": STATES.get(str(vm.get("state") or ""), "running"),
                    "vcpus": int(_number(vm.get("vcpus"))),
                    "ram_gb": round(ram / (1024**3)) if ram else 0,
                    "disk_gb": round(disk / (1024**3)) if disk else 0,
                    # Hyper-V no sabe qué corre dentro sin los servicios de
                    # integración, y preguntarlo sería otra ronda de WinRM por
                    # máquina: se deja vacío, como las KVM de Proxmox.
                    "operating_system": "",
                    "host": hostname,
                    "interfaces": [
                        vmnet.interface(nic.get("name"), nic.get("mac"), _as_list(nic.get("ips")), nic.get("vlan"))
                        for nic in _as_list(vm.get("nics"))[: vmnet.MAX_PER_MACHINE]
                        if isinstance(nic, dict)
                    ],
                    "disks": vmnet.merge_disks(
                        [
                            vmnet.disk(vmnet.windows_datastore(drive.get("path")), drive.get("bytes"))
                            for drive in _as_list(vm.get("drives"))
                            if isinstance(drive, dict)
                        ]
                    ),
                }
            )
        return found


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
