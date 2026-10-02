"""The credentials the collectors log in with, wherever they come from.

The server hands them over in the configuration (``ctx["config"]``); the
environment can override them for a standalone run. One module so the
collectors that need to log in --SNMP, SSH, WinRM, hypervisors-- read them the
same way, and so a malformed entry is dropped in one place instead of blowing
up inside whichever collector happened to run first.

Since phase 3 (spec 3.2) a credential usually arrives **sealed**: its secrets
are an envelope only this agent can open (`agent/sealing.py`). They are opened
here, in memory, once per run (`Unsealer`), and never written anywhere. The
plaintext form (``secret`` and ``communities``) of protocol 1 keeps working
while a server still sends it.

Nothing here is ever printed: a credential in a log line is a credential in the
customer's log rotation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import threading
from collections.abc import Mapping
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
#: Una comunidad SNMP v2c que sí llega como credencial, sellada (spec 3.2): la
#: comunidad va en `secret` y `username` se queda vacío. Alimenta al colector
#: SNMP igual que `communities`, pero la memoria la recuerda por su `id`.
SNMP = "snmp"

#: Las clases que no necesitan un secreto para existir: una clave SSH en un
#: fichero, un usuario SNMPv3 noAuthNoPriv. Sin sobre y sin `secret` siguen
#: valiendo, también en una configuración sellada.
_SECRETLESS_OK = (SSH, SNMPV3)


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
    #: Si `ident` es el `id` del servidor y no uno derivado: solo de esas se
    #: informa en `stats.credentials_ok` (el servidor no sabe de las otras).
    from_server: bool = False

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


def _kind(raw: dict) -> str:
    return str(raw.get("kind") or "").strip().lower()


def _one(raw: Any, position: int = 0, secrets: Mapping[str, Any] | None = None) -> Credential | None:
    """Una entrada de la lista, o `None` si no sirve.

    `secrets` es lo que salió del sobre (spec 3.2); sin él, los secretos son
    los que vengan en claro en la propia entrada (spec 1.4).
    """
    if not isinstance(raw, dict):
        return None
    kind = _kind(raw)
    username = str(raw.get("username") or "").strip()
    # Una comunidad v2c no tiene usuario: es la única clase a la que no se le pide.
    if not kind or (not username and kind != SNMP):
        return None
    try:
        port = int(raw.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    host = str(raw.get("host") or "").strip()
    # `name` es como lo llama la spec 3.2; `label`, como lo llamaba la 1.4.
    label = str(raw.get("label") or raw.get("name") or "").strip()
    server_id = str(raw.get("id") or "").strip()
    ident = server_id or derive_ident(kind, username, host, port, label, position)
    source = secrets if secrets is not None else raw
    return Credential(
        kind=kind,
        username=username,
        secret=_secret_text(source.get("secret")),
        host=host,
        port=port,
        key_file=str(raw.get("key_file") or "").strip(),
        ca_file=str(raw.get("ca_file") or "").strip(),
        auth_protocol=str(raw.get("auth_protocol") or "").strip().lower(),
        priv_protocol=str(raw.get("priv_protocol") or "").strip().lower(),
        priv_secret=_secret_text(source.get("priv_secret")),
        label=label,
        ident=ident,
        scope=_scope(raw.get("scope")),
        from_server=bool(server_id),
    )


def _secret_text(value: Any) -> str:
    return value if isinstance(value, str) else ""


# --- Credenciales selladas (spec 3.2) ------------------------------------------------

SEALED = "sealed"
LEGACY = "legacy"
UNREADABLE = "unreadable"


def entry_state(raw: Any, sealed_config: bool) -> str:
    """Cómo hay que tratar una entrada: sellada, en claro (1.4) o ilegible.

    * Con la clave ``sealed`` (aunque sea ``null``): sellada. Si el sobre no
      está o no abre, ilegible.
    * Sin ella, en una configuración en la que alguna entrada viene sellada, y
      sin ``secret``: es «sin sobre para este agente» (spec 3.2), ilegible.
      Salvo las clases que no necesitan secreto (`_SECRETLESS_OK`).
    * Si no, en claro, como siempre.
    """
    if not isinstance(raw, dict):
        return LEGACY
    if SEALED in raw:
        return SEALED
    if sealed_config and "secret" not in raw and _kind(raw) not in _SECRETLESS_OK:
        return UNREADABLE
    return LEGACY


class Unsealer:
    """Opens the sealed credentials of one run, once, in memory only.

    Se abren **todas a la vez la primera vez que alguien pide credenciales**
    en esa ejecución, y se guardan aquí hasta que la ejecución acaba (el `ctx`
    que la lleva se tira con ella). Ni una vez por equipo --sería una operación
    RSA por intento de login, y la nota de ilegibles saldría repetida-- ni una
    vez por configuración --el texto en claro viviría en el proceso días
    enteros, también mientras el agente no hace nada--. Así el secreto existe
    en claro lo que dura la tarea que lo usa, y una tarea que no toca
    credenciales (la presencia) no abre ninguna.

    Python no permite borrar una cadena de la memoria: «en memoria» quiere
    decir que no se escribe en ningún sitio y que deja de estar referenciado
    al acabar, no que se sobrescriba.
    """

    def __init__(self, agent_uuid: str = "", environ: Mapping[str, str] | None = None) -> None:
        self.agent_uuid = agent_uuid or ""
        self._environ = environ
        self._lock = threading.Lock()
        self._opened: dict[str, dict[str, str] | None] = {}
        self._unreadable: set[int] = set()
        self._done = False

    def __repr__(self) -> str:
        # Ni el uuid hace falta; solo cifras, para que un volcado no diga nada.
        return f"Unsealer(opened={len(self._opened)}, unreadable={len(self._unreadable)})"

    def prepare(self, raw: list[Any]) -> None:
        """Abre todos los sobres de la lista, la primera vez. Nunca lanza."""
        with self._lock:
            if self._done:
                return
            self._done = True
            sealed_config = any(isinstance(item, dict) and SEALED in item for item in raw)
            if not sealed_config:
                return
            from agent import sealing

            key = None
            try:
                key = sealing.own_private_key(self._environ)
            except Exception:  # noqa: BLE001 - sin clave, todas ilegibles
                key = None
            for position, item in enumerate(raw):
                state = entry_state(item, sealed_config)
                if state == UNREADABLE:
                    self._unreadable.add(position)
                    continue
                if state != SEALED:
                    continue
                ident = str(item.get("id") or "").strip()
                opened: dict[str, str] | None = None
                if ident and key is not None and isinstance(item.get(SEALED), dict):
                    try:
                        plaintext = sealing.open_envelope(
                            item[SEALED], agent_uuid=self.agent_uuid, subject_id=ident, private_key=key
                        )
                    except sealing.SealError:
                        plaintext = None
                    except Exception:  # noqa: BLE001 - un sobre raro no tumba la tarea
                        plaintext = None
                    if plaintext is not None:
                        opened = {
                            name: plaintext[name]
                            for name in ("secret", "priv_secret")
                            if isinstance(plaintext.get(name), str)
                        }
                if opened is None:
                    self._unreadable.add(position)
                elif ident:
                    self._opened[ident] = opened
            del key

    def secrets(self, raw: dict) -> dict[str, str] | None:
        """Lo que salió del sobre de esa entrada, o `None` si no abrió."""
        ident = str(raw.get("id") or "").strip()
        with self._lock:
            return self._opened.get(ident) if ident else None

    @property
    def unreadable(self) -> int:
        """Cuántas entradas selladas (o sin sobre) no se pudieron usar en esta ejecución."""
        with self._lock:
            return len(self._unreadable)


#: La clave de `ctx` en la que vive el `Unsealer` de la ejecución.
CTX_KEY = "unsealer"


def unsealer(ctx: dict) -> Unsealer:
    """El `Unsealer` de esta ejecución: el que puso el bucle, o uno nuevo.

    Sin bucle (el protocolo 1, un test) se crea con el uuid de `ctx["agent_uuid"]`
    si lo hay; sin uuid ningún sobre abre, que es lo correcto.
    """
    found = ctx.get(CTX_KEY)
    if isinstance(found, Unsealer):
        return found
    created = Unsealer(str(ctx.get("agent_uuid") or ""))
    return ctx.setdefault(CTX_KEY, created)


def raw_list(ctx: dict) -> list[Any]:
    """La lista de credenciales tal como llegó: la del servidor, o la del entorno."""
    raw = (ctx.get("config") or {}).get("credentials") or []
    if not raw:
        env = ctx.get("env")
        raw = list(env.credentials) if env and env.credentials else []
    return list(raw) if isinstance(raw, (list, tuple)) else []


def all_from(ctx: dict) -> list[Credential]:
    """Everything configured: the server's list, or the environment's when the
    server said nothing. Same precedence as subnets and communities.

    Sealed entries are opened here (`Unsealer`); one that does not open is
    left out and counted, never tried with an empty password.
    """
    raw = raw_list(ctx)
    sealed_config = any(isinstance(item, dict) and SEALED in item for item in raw)
    opener = unsealer(ctx) if sealed_config else None
    if opener is not None:
        opener.prepare(raw)
    # La posición es la de la lista entera: es la que se usa para derivar el
    # `ident` cuando el servidor no lo manda, y tiene que ser la misma de un
    # barrido al siguiente mientras nadie toque la lista.
    found: list[Credential | None] = []
    for position, item in enumerate(raw):
        state = entry_state(item, sealed_config)
        if state == UNREADABLE:
            continue
        if state == SEALED:
            secrets = opener.secrets(item) if opener is not None else None
            if secrets is None:
                continue
            found.append(_one(item, position, secrets))
        else:
            found.append(_one(item, position))
    return [credential for credential in found if credential is not None]


def find(ctx: dict, ident: str) -> tuple[Credential | None, bool]:
    """La credencial con ese `id` del servidor, y si existe en la configuración.

    ``(None, True)``: está, pero su sobre no abre. ``(None, False)``: no está.
    """
    ident = (ident or "").strip()
    if not ident:
        return None, False
    present = any(isinstance(item, dict) and str(item.get("id") or "").strip() == ident for item in raw_list(ctx))
    for credential in all_from(ctx):
        if credential.from_server and credential.ident == ident:
            return credential, True
    return None, present


def scrub(text: str, credential: Credential | None = None, *secrets: str) -> str:
    """El texto sin los secretos de esa credencial (ni de los que se añadan) dentro.

    Para los errores que escribe otro (un equipo remoto, una librería) y que el
    agente repite en una nota: no se sabe qué devuelven de lo que se les dio.
    """
    found = [*secrets]
    if credential is not None:
        found += [credential.secret, credential.priv_secret]
    for secret in found:
        if secret:
            text = text.replace(secret, "***")
    return text


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
