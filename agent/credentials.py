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

import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from typing import Any

SSH = "ssh"
WINRM = "winrm"
VMWARE = "vmware"
PROXMOX = "proxmox"
SNMPV3 = "snmpv3"
HYPERV = "hyperv"
XCPNG = "xcpng"
#: Una comunidad SNMP v2c vista como credencial. No llega así del servidor --las
#: comunidades viajan como lista de textos en `config["communities"]`--: la
#: fabrica el colector SNMP para que la memoria las trate igual que a un
#: usuario v3 (`community`).
COMMUNITY = "snmp-community"


@dataclass(frozen=True)
class Scope:
    """Dónde vale una credencial: subredes y equipos sueltos. Vacío = en todas partes.

    Un alcance escrito pero ilegible (una subred mal tecleada) no vale «en todas
    partes»: no cubre nada. Quien se molestó en acotar una credencial quería
    que no se probara fuera, y un error de tecleo no puede convertir eso en
    probarla contra toda la red.
    """

    subnets: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()

    @property
    def everywhere(self) -> bool:
        return not self.subnets and not self.hosts

    def covers(self, ip: str) -> bool:
        if self.everywhere:
            return True
        ip = (ip or "").strip()
        if not ip:
            # Sin dirección no hay forma de comprobarlo; ante la duda, no se prueba.
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            address = None
        for host in self.hosts:
            if host.strip().lower() == ip.lower():
                return True
            if address is not None:
                try:
                    if ipaddress.ip_address(host.strip()) == address:
                        return True
                except ValueError:
                    continue
        if address is None:
            return False
        for subnet in self.subnets:
            try:
                if address in ipaddress.ip_network(subnet.strip(), strict=False):
                    return True
            except (ValueError, TypeError):
                continue
        return False


def derive_ident(kind: str, username: str, host: str, port: int, label: str, position: int) -> str:
    """Un `id` estable para una credencial que no lo trae del servidor.

    Sale de lo que la describe y de su sitio en la lista, **nunca del
    secreto**: la memoria guarda este valor en disco, y un hash de una
    contraseña corta se deshace con un diccionario en una tarde.
    """
    material = json.dumps([kind, username, host, int(port or 0), label, int(position)], ensure_ascii=False)
    return "local-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


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
    #: El `id` que le da el servidor (opaco, estable mientras no cambie). Es lo
    #: único de una credencial que la memoria del agente guarda en disco. Si
    #: no viene, se deriva (`derive_ident`), nunca del secreto.
    ident: str = ""
    #: Dónde se puede probar. Vacío: en todo el perfil.
    scope: Scope = field(default_factory=Scope)

    def __post_init__(self) -> None:
        if not self.ident:
            object.__setattr__(
                self, "ident", derive_ident(self.kind, self.username, self.host, self.port, self.label, 0)
            )

    def covers(self, ip: str) -> bool:
        """¿Se puede probar contra esa dirección?"""
        return self.scope.covers(ip)

    def __repr__(self) -> str:  # pragma: no cover - trivial
        # Sin esto, un `print(credential)` o un volcado de excepción escupe la
        # contraseña. El agente corre desatendido en la máquina de un cliente y
        # su salida acaba en un fichero que alguien lee meses después.
        return (
            f"Credential(kind={self.kind!r}, username={self.username!r}, host={self.host!r}, "
            f"ident={self.ident!r})"
        )


def _strings(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(str(item).strip() for item in value if isinstance(item, str) and item.strip())


def _scope(raw: Any) -> Scope:
    """El alcance tal como lo escribe el servidor. Algo que no es un
    diccionario es «sin alcance», que es lo que dice el contrato para un campo
    ausente."""
    if not isinstance(raw, dict):
        return Scope()
    return Scope(subnets=_strings(raw.get("subnets")), hosts=_strings(raw.get("hosts")))


def _one(raw: Any, position: int = 0) -> Credential | None:
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
    host = str(raw.get("host") or "").strip()
    label = str(raw.get("label") or "").strip()
    ident = str(raw.get("id") or "").strip() or derive_ident(kind, username, host, port, label, position)
    return Credential(
        kind=kind,
        username=username,
        secret=str(raw.get("secret") or ""),
        host=host,
        port=port,
        key_file=str(raw.get("key_file") or "").strip(),
        ca_file=str(raw.get("ca_file") or "").strip(),
        auth_protocol=str(raw.get("auth_protocol") or "").strip().lower(),
        priv_protocol=str(raw.get("priv_protocol") or "").strip().lower(),
        priv_secret=str(raw.get("priv_secret") or ""),
        label=label,
        ident=ident,
        scope=_scope(raw.get("scope")),
    )


def all_from(ctx: dict) -> list[Credential]:
    """Everything configured: the server's list, or the environment's when the
    server said nothing. Same precedence as subnets and communities."""
    raw = (ctx.get("config") or {}).get("credentials") or []
    if not raw:
        env = ctx.get("env")
        raw = list(env.credentials) if env and env.credentials else []
    # La posición es la de la lista entera: es la que se usa para derivar el
    # `ident` cuando el servidor no lo manda, y tiene que ser la misma de un
    # barrido al siguiente mientras nadie toque la lista.
    found = [_one(item, position) for position, item in enumerate(raw)]
    return [credential for credential in found if credential is not None]


def community(value: str, index: int) -> Credential:
    """Una comunidad v2c como credencial, para que la memoria la recuerde.

    Su `ident` es su número en la lista (`community-1`, `community-2`...), el
    mismo con el que la cita «Analizar». Nunca el valor: una comunidad **es**
    un secreto, y la memoria se escribe en disco.
    """
    return Credential(kind=COMMUNITY, username="", secret=value, ident=f"community-{index}")


def covers(credential: Credential, ip: str) -> bool:
    """¿Se puede probar esa credencial contra esa dirección? (su `scope`)."""
    return credential.scope.covers(ip)


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
