"""WinRM, aislado detrás de dos funciones para que los tests lo finjan y el
agente siga vivo sin `pywinrm` instalado.

Mismo trato que `pysnmp` en `agent.snmp`: la librería es opcional (MIT, sin
copyleft en su cadena) y si no está, el colector se reporta no disponible y el
barrido sale parcial, nunca roto. Es lo que permite arrancar el agente con un
`python -m agent` en un servidor donde instalar cosas es un problema.

Todo lo que se pregunta va en **un solo PowerShell** que devuelve JSON: una
conexión WinRM tarda más en abrirse que en contestar, así que hacer diez
preguntas sueltas multiplica por diez el barrido de cada Windows.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

try:
    import winrm as pywinrm  # el paquete de PyPI, no este módulo

    # `hasattr` y no un `True` pelado: si alguien arranca el agente con
    # `python agent/__main__.py` en vez de `python -m agent`, la carpeta del
    # agente entra en la ruta de módulos y este fichero se importa **a sí
    # mismo** como si fuera la librería. Sin la comprobación, el colector se
    # daría por disponible y fallaría host por host sin decir por qué.
    AVAILABLE = hasattr(pywinrm, "Session")
except ImportError:  # el agente sin pywinrm: el resto del barrido sigue igual
    AVAILABLE = False

DEFAULT_PORT = 5985
DEFAULT_TLS_PORT = 5986
READ_TIMEOUT_SECONDS = 30
OPERATION_TIMEOUT_SECONDS = 20

#: En orden. NTLM primero porque es lo que un Windows de dominio acepta de
#: fábrica; `basic` solo funciona si alguien lo habilitó a mano, y entonces es
#: que es lo único que hay. Si falta `requests_ntlm`, pywinrm lanza al crear la
#: sesión y se pasa al siguiente en vez de dejar el equipo sin mirar.
TRANSPORTS: tuple[str, ...] = ("ntlm", "basic")

#: Lo que se le pregunta a un Windows, de una vez. `Get-CimInstance` no existe
#: antes de PowerShell 3, así que cada consulta cae hacia `Get-WmiObject`: en
#: una pyme todavía queda algún 2008 R2, y no leerlo es no inventariarlo.
SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
function Get-Info($class, $filter) {
  if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
    if ($filter) { Get-CimInstance -ClassName $class -Filter $filter }
    else { Get-CimInstance -ClassName $class }
  } else {
    if ($filter) { Get-WmiObject -Class $class -Filter $filter }
    else { Get-WmiObject -Class $class }
  }
}
$cs = Get-Info 'Win32_ComputerSystem' $null | Select-Object -First 1
$os = Get-Info 'Win32_OperatingSystem' $null | Select-Object -First 1
$bios = Get-Info 'Win32_BIOS' $null | Select-Object -First 1
$nics = Get-Info 'Win32_NetworkAdapterConfiguration' 'IPEnabled=True'
$interfaces = @()
foreach ($nic in $nics) {
  $address = @($nic.IPAddress) | Where-Object { $_ -and $_ -notmatch ':' } | Select-Object -First 1
  $interfaces += @{
    name = [string]$nic.Description
    mac  = [string]$nic.MACAddress
    ip   = [string]$address
  }
}
$result = @{
  hostname     = [string]$cs.DNSHostName
  domain       = [string]$cs.Domain
  in_domain    = [bool]$cs.PartOfDomain
  domain_role  = [int]$cs.DomainRole
  manufacturer = [string]$cs.Manufacturer
  model        = [string]$cs.Model
  serial       = [string]$bios.SerialNumber
  os           = [string]$os.Caption
  os_version   = [string]$os.Version
  hyperv       = [bool](Get-Service -Name 'vmms' -ErrorAction SilentlyContinue)
  interfaces   = $interfaces
}
$result | ConvertTo-Json -Depth 4 -Compress
"""


@dataclass(frozen=True)
class Answer:
    """Lo que dio un intento. ``connected`` separa «no me dejó entrar» de
    «entré y no supo contestar», igual que en SSH."""

    connected: bool
    data: dict[str, Any] | None = None
    error: str = ""
    #: No se llegó a autenticar (nada contestó, TLS no se fió, falta la
    #: librería). Solo cuando es seguro: ante la duda, `False` (spec 2.3).
    unreachable: bool = False


#: Lo que dicen `requests`/`urllib3`/pywinrm cuando no llegan a mandar la
#: credencial. En minúsculas, sobre el texto del error.
_BEFORE_AUTH = (
    "failed to establish a new connection",
    "connection refused",
    "no route to host",
    "network is unreachable",
    "name or service not known",
    "getaddrinfo failed",
    "nodename nor servname",
    "connecttimeout",
    "connect timeout",
    "certificate verify failed",
    "requests_ntlm",
    "not installed",
)


def before_auth(exc: BaseException) -> bool:
    """Whether a pywinrm exception happened before any credential was sent."""
    name = type(exc).__name__
    text = f"{name}: {exc}".lower()
    if name == "InvalidCredentialsError" or "401" in text or "unauthorized" in text or "credentials" in text:
        return False
    if name in ("ConnectTimeout", "SSLError"):
        return True
    return any(phrase in text for phrase in _BEFORE_AUTH)


def outcome(answer: Answer) -> str:
    """El veredicto de un intento para el límite de credenciales (`agent.memory`)."""
    if answer.connected:
        return "ok"
    return "unreachable" if answer.unreachable else "auth_failed"


def endpoint(host: str, port: int = 0) -> str:
    """La URL del servicio. El 5986 es el de TLS y lleva https; el 5985 va por
    HTTP, que **no es texto plano**: NTLM cifra el mensaje por dentro."""
    port = port or DEFAULT_PORT
    scheme = "https" if port == DEFAULT_TLS_PORT else "http"
    return f"{scheme}://{host}:{port}/wsman"


def query(
    *,
    host: str,
    username: str,
    secret: str,
    port: int = 0,
    ca_file: str = "",
) -> Answer:
    """Pregunta a ese Windows quién es. Nunca lanza: devuelve lo que pasó.

    **La verificación de TLS no se desactiva.** Contra el 5986 con certificado
    autofirmado --lo normal-- la salida correcta es dar la CA de la empresa, no
    aceptar cualquier certificado: sin verificación, cualquiera en medio de la
    red puede quedarse con la contraseña de administrador del dominio.
    """
    if not AVAILABLE:
        return Answer(connected=False, error="falta pywinrm", unreachable=True)
    last_error = ""
    for transport in TRANSPORTS:
        try:
            session = pywinrm.Session(
                endpoint(host, port),
                auth=(username, secret),
                transport=transport,
                read_timeout_sec=READ_TIMEOUT_SECONDS,
                operation_timeout_sec=OPERATION_TIMEOUT_SECONDS,
                server_cert_validation="validate",
                ca_trust_path=ca_file or None,
            )
            result = session.run_ps(SCRIPT)
        except Exception as exc:  # noqa: BLE001 - pywinrm lanza de todo: HTTP, TLS, WSMan
            last_error = f"{type(exc).__name__}: {exc}"
            if before_auth(exc):
                continue
            # Con la clave rechazada (o sin saber si llegó), no se repite por
            # otro transporte: sería otro inicio de sesión fallido de la misma
            # cuenta, y en un dominio eso acerca el bloqueo.
            return Answer(connected=False, error=last_error)
        if result.status_code != 0:
            last_error = (result.std_err or b"").decode(errors="replace").strip()[:200]
            # Se entró: el PowerShell falló, que es otra cosa. Probar el
            # siguiente transporte no arreglaría nada.
            return Answer(connected=True, error=last_error)
        return Answer(connected=True, data=_decode(result.std_out))
    return Answer(connected=False, error=last_error or "no se pudo conectar", unreachable=True)


def _decode(raw: bytes | str) -> dict[str, Any] | None:
    """El JSON del PowerShell. `None` cuando la salida no lo es.

    Un Windows viejo sin `ConvertTo-Json` devuelve texto suelto, y tratarlo como
    JSON lanzaría dentro del bucle del colector en vez de dejarlo sin datos.
    """
    text = raw.decode(errors="replace") if isinstance(raw, bytes) else str(raw)
    text = text.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None
