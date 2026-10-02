"""The credentials the collectors log in with, wherever they come from.

The server hands them over decrypted in the heartbeat (``ctx["config"]``); the
environment can override them for a standalone run. One module so the three
collectors that need to log in --SSH, WinRM, hypervisors-- read them the same
way, and so a malformed entry is dropped in one place instead of blowing up
inside whichever collector happened to run first.

Nothing here is ever printed: a credential in a log line is a credential in the
customer's log rotation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SSH = "ssh"
WINRM = "winrm"
VMWARE = "vmware"
PROXMOX = "proxmox"
SNMPV3 = "snmpv3"
HYPERV = "hyperv"
XCPNG = "xcpng"


@dataclass(frozen=True)
class Credential:
    """One login: who, with what, and --for a hypervisor-- against which box."""

    kind: str
    username: str
    secret: str = ""
    #: Solo para los hipervisores: la dirección del vCenter o del Proxmox. Para
    #: SSH y WinRM se deja vacío y el colector prueba contra los hosts vivos.
    host: str = ""
    port: int = 0
    #: Solo para SSH: una clave privada concreta en vez de las del usuario.
    key_file: str = ""
    #: La CA que firma el certificado de ese vCenter o ese Windows, cuando lo
    #: firma la propia empresa. La salida correcta ante un certificado
    #: autofirmado es esta, no desactivar la verificación.
    ca_file: str = ""
    #: Solo para SNMPv3. El usuario es el usuario SNMP y `secret` la contraseña
    #: de autenticación; estos tres completan el juego. Sin `secret` el nivel
    #: es noAuthNoPriv; con `secret` pero sin `priv_secret`, authNoPriv.
    auth_protocol: str = ""
    priv_protocol: str = ""
    priv_secret: str = ""
    #: Para reconocerla en la pantalla. Nunca se usa para autenticar.
    label: str = ""

    def __repr__(self) -> str:  # pragma: no cover - trivial
        # Sin esto, un `print(credential)` o un volcado de excepción escupe la
        # contraseña. El agente corre desatendido en la máquina de un cliente y
        # su salida acaba en un fichero que alguien lee meses después.
        return f"Credential(kind={self.kind!r}, username={self.username!r}, host={self.host!r})"


def _one(raw: Any) -> Credential | None:
    if not isinstance(raw, dict):
        return None
    kind = str(raw.get("kind") or "").strip().lower()
    username = str(raw.get("username") or "").strip()
    if not kind or not username:
        return None
    try:
        port = int(raw.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    return Credential(
        kind=kind,
        username=username,
        secret=str(raw.get("secret") or ""),
        host=str(raw.get("host") or "").strip(),
        port=port,
        key_file=str(raw.get("key_file") or "").strip(),
        ca_file=str(raw.get("ca_file") or "").strip(),
        auth_protocol=str(raw.get("auth_protocol") or "").strip().lower(),
        priv_protocol=str(raw.get("priv_protocol") or "").strip().lower(),
        priv_secret=str(raw.get("priv_secret") or ""),
        label=str(raw.get("label") or "").strip(),
    )


def all_from(ctx: dict) -> list[Credential]:
    """Everything configured: the server's list, or the environment's when the
    server said nothing. Same precedence as subnets and communities."""
    raw = (ctx.get("config") or {}).get("credentials") or []
    if not raw:
        env = ctx.get("env")
        raw = list(env.credentials) if env and env.credentials else []
    found = [_one(item) for item in raw]
    return [credential for credential in found if credential is not None]


def ca_file_for(ctx: dict, credential: Credential) -> str:
    """La CA con la que verificar a ese equipo: la suya, o la de la empresa.

    En una pyme el certificado del vCenter, el del Windows y el de la propia
    aplicación suelen salir de la misma CA interna, así que
    ``CENYA_CA_BUNDLE`` --que ya existe para hablar con el servidor--
    vale de respaldo. Lo que no se hace nunca es dejar de verificar.
    """
    if credential.ca_file:
        return credential.ca_file
    env = ctx.get("env")
    return getattr(env, "ca_bundle", "") or ""


def for_kind(ctx: dict, kind: str) -> list[Credential]:
    """The credentials of one protocol, in the order they were written.

    The order is the order they are tried, and it is the user's: whoever typed
    the list put the one that works everywhere first.
    """
    return [credential for credential in all_from(ctx) if credential.kind == kind]
