"""SNMP v2c and v3, isolated behind three functions so tests fake it and the
agent survives without pysnmp installed.

Every query takes an *auth*: a plain string is a v2c community, a
``credentials.Credential`` of kind ``snmpv3`` is a v3 user. The security
level is whatever the credential carries -- password only is authNoPriv,
both passwords is authPriv -- so the caller never spells it out.

Everything async lives in this module: pysnmp 7 is asyncio-only, and the
collectors stay plain synchronous code. ``query_hosts`` runs one event loop
for the whole batch, with a semaphore so two hundred hosts do not become two
hundred sockets at once.

Only OIDs, never MIBs: the agent does not ship MIB files and does not resolve
names, so ``lookupMib=False`` everywhere.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Callable

from agent import credentials as creds
from agent import stacks

try:
    from pysnmp.hlapi.asyncio import (
        CommunityData,
        ContextData,
        ObjectIdentity,
        ObjectType,
        SnmpEngine,
        UdpTransportTarget,
        UsmUserData,
        get_cmd,
        usmAesCfb128Protocol,
        usmDESPrivProtocol,
        usmHMAC192SHA256AuthProtocol,
        usmHMACMD5AuthProtocol,
        usmHMACSHAAuthProtocol,
        walk_cmd,
    )

    AVAILABLE = True
except ImportError:  # the standalone agent without pysnmp: sweep still works
    AVAILABLE = False

#: Con qué se pregunta: una comunidad v2c tal cual, o un usuario SNMPv3.
Auth = str | creds.Credential

TIMEOUT_SECONDS = 2
RETRIES = 1
CONCURRENCY = 20

SYSTEM_OIDS = {
    "description": "1.3.6.1.2.1.1.1.0",
    "object_id": "1.3.6.1.2.1.1.2.0",
    "name": "1.3.6.1.2.1.1.5.0",
}
# Column OIDs, walked: index-suffix -> value.
IF_OIDS = {
    "name": "1.3.6.1.2.1.31.1.1.1.1",  # ifName
    "descr": "1.3.6.1.2.1.2.2.1.2",  # ifDescr, for the devices without ifXTable
    "mac": "1.3.6.1.2.1.2.2.1.6",  # ifPhysAddress
    "status": "1.3.6.1.2.1.2.2.1.8",  # ifOperStatus: 1 up, 2 down
    "speed": "1.3.6.1.2.1.31.1.1.1.15",  # ifHighSpeed, in Mbps
}
IP_TO_IFINDEX_OID = "1.3.6.1.2.1.4.20.1.2"  # ipAdEntIfIndex: which interface owns an IP

# UPS-MIB (RFC 1628). Lo que un SAI sabe de sí mismo y ninguna ficha puede
# decir: los minutos que le quedan **con la batería que tiene hoy**, no con la
# que traía de fábrica. Se piden a todos los hosts porque son cuatro OIDs de
# hoja: un equipo que no es un SAI no contesta a esa rama y ya está.
UPS_OIDS = {
    "runtime_minutes": "1.3.6.1.2.1.33.1.2.3.0",  # upsEstimatedMinutesRemaining
    "charge_percent": "1.3.6.1.2.1.33.1.2.4.0",  # upsEstimatedChargeRemaining
    "output_source": "1.3.6.1.2.1.33.1.4.1.0",  # upsOutputSource
    "load_percent": "1.3.6.1.2.1.33.1.4.4.1.5.1",  # upsOutputPercentLoad, primera salida
}

#: `upsOutputSource`: de dónde sale la corriente ahora mismo. El 5 es batería;
#: el 3 es la red, que es lo normal. Los demás (ninguna, derivación, reductor,
#: elevador) no son «tirando de batería» pero tampoco son un funcionamiento
#: tranquilo, así que solo se afirma lo que se sabe: on_battery o no.
UPS_SOURCE_ON_BATTERY = "5"

# Neighbours: LLDP-MIB and Cisco's CDP.
LLDP_LOCAL_PORT_OID = "1.0.8802.1.1.2.1.3.7.1.3"  # lldpLocPortId, index = local port num
LLDP_REM_CHASSIS_OID = "1.0.8802.1.1.2.1.4.1.1.5"  # lldpRemChassisId (usually the MAC)
LLDP_REM_PORT_OID = "1.0.8802.1.1.2.1.4.1.1.7"  # lldpRemPortId
LLDP_REM_NAME_OID = "1.0.8802.1.1.2.1.4.1.1.9"  # lldpRemSysName
CDP_IFINDEX_OID = "1.3.6.1.4.1.9.9.23.1.2.1.1.2"  # cdpCacheIfIndex (redundant: it is the index)
CDP_DEVICE_OID = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"  # cdpCacheDeviceId
CDP_PORT_OID = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"  # cdpCacheDevicePort

# The forwarding table: which MAC hangs off which bridge port.
FDB_PORT_OID = "1.3.6.1.2.1.17.7.1.2.2.1.2"  # dot1qTpFdbPort, index = vlan.mac octets
BRIDGE_PORT_IFINDEX_OID = "1.3.6.1.2.1.17.1.4.1.2"  # dot1dBasePortIfIndex
# Cisco hides each VLAN's FDB behind community@vlan; the VLAN list lives here.
# ENTITY-MIB entPhysicalTable: the units of a stack, one chassis row each.
ENTITY_CLASS_OID = "1.3.6.1.2.1.47.1.1.1.1.5"  # entPhysicalClass, 3 = chassis
ENTITY_POSITION_OID = "1.3.6.1.2.1.47.1.1.1.1.6"  # entPhysicalParentRelPos
ENTITY_SERIAL_OID = "1.3.6.1.2.1.47.1.1.1.1.11"  # entPhysicalSerialNum
ENTITY_MODEL_OID = "1.3.6.1.2.1.47.1.1.1.1.13"  # entPhysicalModelName

CISCO_ENTERPRISE_PREFIX = "1.3.6.1.4.1.9"
CISCO_VTP_VLAN_OID = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"  # vtpVlanState, index = VLAN id
MAX_CISCO_VLANS = 32

_MAC_RE = re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")


def _text(value: Any) -> str:
    return value.prettyPrint().strip() if not isinstance(value, str) else value.strip()


def _mac(value: Any) -> str:
    """A MAC as ``aa:bb:cc:dd:ee:ff``. ifPhysAddress arrives as raw bytes."""
    if isinstance(value, str):
        return value.lower().replace("-", ":") if _MAC_RE.match(value) else ""
    try:
        return ":".join(f"{byte:02x}" for byte in value.asOctets())
    except Exception:  # noqa: BLE001 - a weird OctetString is no MAC, move on
        return ""


async def _target(host: str):
    # pysnmp 7: create() is a coroutine; the constructor does not take the address.
    return await UdpTransportTarget.create((host, 161), timeout=TIMEOUT_SECONDS, retries=RETRIES)


def _auth_data(auth: Auth):
    """What pysnmp calls authentication: v2c community or v3 user.

    The v3 security level is not a switch anyone sets: no password means
    noAuthNoPriv, one password authNoPriv, both authPriv -- the same rule the
    devices themselves apply. An unknown protocol name falls back to the
    conservative default (SHA-1 / AES-128) instead of failing the whole host:
    the try-next-auth loop upstream absorbs a wrong guess as one more miss.
    """
    if isinstance(auth, str):
        return CommunityData(auth, mpModel=1)  # v2c
    auth_protocols = {
        "sha": usmHMACSHAAuthProtocol,
        "sha256": usmHMAC192SHA256AuthProtocol,
        "md5": usmHMACMD5AuthProtocol,
    }
    priv_protocols = {
        "aes": usmAesCfb128Protocol,
        "des": usmDESPrivProtocol,
    }
    if not auth.secret:
        return UsmUserData(auth.username)  # noAuthNoPriv
    if not auth.priv_secret:
        return UsmUserData(
            auth.username,
            authKey=auth.secret,
            authProtocol=auth_protocols.get(auth.auth_protocol, usmHMACSHAAuthProtocol),
        )
    return UsmUserData(
        auth.username,
        authKey=auth.secret,
        privKey=auth.priv_secret,
        authProtocol=auth_protocols.get(auth.auth_protocol, usmHMACSHAAuthProtocol),
        privProtocol=priv_protocols.get(auth.priv_protocol, usmAesCfb128Protocol),
    )


def _context(context_name: str = ""):
    return ContextData(contextName=context_name) if context_name else ContextData()


async def _get(
    engine, host: str, auth: Auth, oids: dict[str, str], context_name: str = ""
) -> dict[str, str] | None:
    target = await _target(host)
    error, _, _, binds = await get_cmd(
        engine,
        _auth_data(auth),
        target,
        _context(context_name),
        *[ObjectType(ObjectIdentity(oid)) for oid in oids.values()],
        lookupMib=False,
    )
    if error or not binds:
        return None
    return {name: _text(value) for name, value in zip(oids, (bind[1] for bind in binds))}


async def _walk(engine, host: str, auth: Auth, oid: str, context_name: str = "") -> dict[str, str]:
    """Column OID -> {index suffix: value as text}."""
    target = await _target(host)
    column: dict[str, str] = {}
    async for error, _, _, binds in walk_cmd(
        engine,
        _auth_data(auth),
        target,
        _context(context_name),
        ObjectType(ObjectIdentity(oid)),
        lookupMib=False,
        lexicographicMode=False,
    ):
        if error or not binds:
            break
        for name, value in binds:
            column[str(name).removeprefix(oid + ".")] = value
    return column


def fdb_mac_from_suffix(suffix: str) -> str:
    """The MAC inside a dot1qTpFdbPort index: ``vlan.m1.m2.m3.m4.m5.m6``."""
    parts = suffix.split(".")
    if len(parts) != 7:
        return ""
    try:
        return ":".join(f"{int(part):02x}" for part in parts[1:7])
    except ValueError:
        return ""


def lldp_local_port_from_suffix(suffix: str) -> str:
    """The local port number inside an lldpRemEntry index:
    ``timeMark.localPortNum.remIndex``."""
    parts = suffix.split(".")
    return parts[1] if len(parts) == 3 else ""


async def _query_neighbors(engine, host: str, auth: Auth) -> list[dict[str, str]]:
    """LLDP neighbours first, CDP where there is no LLDP. Every entry: which
    of my ports touches what of theirs."""
    neighbors: list[dict[str, str]] = []
    try:
        local_ports = await _walk(engine, host, auth, LLDP_LOCAL_PORT_OID)
        chassis = await _walk(engine, host, auth, LLDP_REM_CHASSIS_OID)
        ports = await _walk(engine, host, auth, LLDP_REM_PORT_OID)
        names = await _walk(engine, host, auth, LLDP_REM_NAME_OID)
        for suffix, name in names.items() or ports.items():
            local_num = lldp_local_port_from_suffix(suffix)
            if not local_num:
                continue
            neighbors.append(
                {
                    "protocol": "lldp",
                    "local_port": _text(local_ports.get(local_num, "")),
                    "remote_mac": _mac(chassis.get(suffix, "")),
                    "remote_port": _text(ports.get(suffix, "")),
                    "remote_name": _text(names.get(suffix, "")),
                }
            )
        if neighbors:
            return neighbors
    except Exception:  # noqa: BLE001 - no LLDP table is normal, not an error
        pass
    try:
        devices = await _walk(engine, host, auth, CDP_DEVICE_OID)
        ports = await _walk(engine, host, auth, CDP_PORT_OID)
        ifindexes = await _walk(engine, host, auth, CDP_IFINDEX_OID)
        ifindex_names = await _walk(engine, host, auth, IF_OIDS["name"])
        for suffix, device in devices.items():
            ifindex = _text(ifindexes.get(suffix, ""))
            neighbors.append(
                {
                    "protocol": "cdp",
                    "local_port": _text(ifindex_names.get(ifindex, "")),
                    "remote_mac": "",
                    "remote_port": _text(ports.get(suffix, "")),
                    "remote_name": _text(device),
                }
            )
    except Exception:  # noqa: BLE001
        pass
    return neighbors


async def _query_members(engine, host: str, auth: Auth) -> list[dict[str, Any]]:
    """The units of a stack from ENTITY-MIB, or [] for a single unit.

    The class column goes first and alone: on a lone switch -- the usual
    case -- one chassis row means the other three columns are never asked.
    """
    classes = {index: _text(value) for index, value in (await _walk(engine, host, auth, ENTITY_CLASS_OID)).items()}
    if sum(1 for value in classes.values() if value == stacks.ENTITY_CLASS_CHASSIS) < 2:
        return []
    columns: dict[str, dict[str, str]] = {}
    for name, oid in (("position", ENTITY_POSITION_OID), ("serial", ENTITY_SERIAL_OID), ("model", ENTITY_MODEL_OID)):
        try:
            columns[name] = {index: _text(value) for index, value in (await _walk(engine, host, auth, oid)).items()}
        except Exception:  # noqa: BLE001 - a missing column leaves that field empty
            columns[name] = {}
    return stacks.entity_members(classes, columns["position"], columns["serial"], columns["model"])


async def _query_fdb(engine, host: str, auth: Auth, object_id: str) -> list[dict[str, str]]:
    """MAC -> bridge port. Cisco slices the table per VLAN: behind
    ``community@vlan`` in v2c, behind the ``vlan-N`` context in v3; everyone
    else answers on the plain auth."""
    # (auth to use, context name) pairs; the plain read always runs first.
    slices: list[tuple[Auth, str]] = [(auth, "")]
    if object_id.startswith(CISCO_ENTERPRISE_PREFIX):
        try:
            vlans = await _walk(engine, host, auth, CISCO_VTP_VLAN_OID)
            if isinstance(auth, str):
                slices += [
                    (f"{auth}@{vlan}", "") for vlan in list(vlans)[:MAX_CISCO_VLANS]
                ]
            else:
                slices += [
                    (auth, f"vlan-{vlan}") for vlan in list(vlans)[:MAX_CISCO_VLANS]
                ]
        except Exception:  # noqa: BLE001 - without the VLAN list, the plain read still runs
            pass
    fdb: dict[str, str] = {}
    for candidate, context_name in slices:
        try:
            column = await _walk(engine, host, candidate, FDB_PORT_OID, context_name)
        except Exception:  # noqa: BLE001 - that VLAN slice may just not exist
            continue
        for suffix, bridge_port in column.items():
            mac = fdb_mac_from_suffix(suffix)
            if mac:
                fdb[mac] = _text(bridge_port)
    try:
        bridge_to_ifindex = await _walk(engine, host, auth, BRIDGE_PORT_IFINDEX_OID)
    except Exception:  # noqa: BLE001
        bridge_to_ifindex = {}
    return [
        {"mac": mac, "ifindex": _text(bridge_to_ifindex.get(bridge_port, ""))}
        for mac, bridge_port in fdb.items()
    ]


async def _query_host(host: str, auths: list[Auth]) -> dict[str, Any] | None:
    """One host, trying the auths in order until one answers."""
    found = await _query_host_indexed(host, auths)
    return found[1] if found is not None else None


async def _query_host_indexed(host: str, auths: list[Auth]) -> tuple[int, dict[str, Any]] | None:
    """Like ``_query_host``, plus *which* auth answered (its index in ``auths``):
    the memory remembers it so the next inventory starts with it."""
    engine = SnmpEngine()
    for index, auth in enumerate(auths):
        try:
            system = await _get(engine, host, auth, SYSTEM_OIDS)
        except Exception:  # noqa: BLE001 - timeout, refused, garbage: next auth
            continue
        if system is None:
            continue
        return index, await _inventory(engine, host, auth, system)
    return None


async def _query_ups_host(host: str, auths: list[Auth]) -> tuple[int, dict[str, Any]] | None:
    """Solo la UPS-MIB, para la tarea `ups`: cuatro OIDs de hoja y nada más.

    Es lo que corre cada pocos minutos contra los SAI ya conocidos; repetir
    ahí la identidad, las interfaces y la tabla de reenvío sería pedir cientos
    de OIDs para refrescar cuatro números.
    """
    engine = SnmpEngine()
    for index, auth in enumerate(auths):
        try:
            raw = await _get(engine, host, auth, UPS_OIDS)
        except Exception:  # noqa: BLE001 - timeout, refused, garbage: next auth
            continue
        if raw is None:
            continue
        return index, {"ups": _ups_reading(raw)}
    return None


async def _inventory(engine, host: str, auth: Auth, system: dict[str, str]) -> dict[str, Any]:
    """Everything after the identity answered: interfaces, addresses,
    neighbours, forwarding table and -- if it is one -- the UPS reading."""
    columns: dict[str, dict[str, Any]] = {}
    for key, oid in IF_OIDS.items():
        try:
            columns[key] = await _walk(engine, host, auth, oid)
        except Exception:  # noqa: BLE001 - a missing table empties a column
            columns[key] = {}
    interfaces = []
    for index, name in (columns["name"] or columns["descr"]).items():
        interfaces.append(
            {
                "index": index,
                "name": _text(name) or _text(columns["descr"].get(index, "")),
                "mac": _mac(columns["mac"].get(index, "")),
                "status": {"1": "up", "2": "down"}.get(_text(columns["status"].get(index, "")), "unknown"),
                "speed_mbps": _text(columns["speed"].get(index, "")),
            }
        )
    try:
        ip_to_ifindex = await _walk(engine, host, auth, IP_TO_IFINDEX_OID)
    except Exception:  # noqa: BLE001
        ip_to_ifindex = {}
    # Neighbours and the forwarding table are opportunistic: a device
    # without LLDP is not an error, it is a quieter map.
    try:
        neighbors = await _query_neighbors(engine, host, auth)
    except Exception:  # noqa: BLE001
        neighbors = []
    try:
        fdb = await _query_fdb(engine, host, auth, system.get("object_id", ""))
    except Exception:  # noqa: BLE001
        fdb = []
    # El SAI, si lo es. Oportunista como los vecinos: un switch no contesta
    # a la UPS-MIB y eso no es un fallo, es que no es un SAI.
    try:
        ups = await _get(engine, host, auth, UPS_OIDS) or {}
    except Exception:  # noqa: BLE001
        ups = {}
    # The units of a stack, opportunistic too: a device without ENTITY-MIB
    # is simply one without `members`.
    try:
        members = await _query_members(engine, host, auth)
    except Exception:  # noqa: BLE001
        members = []
    return {
        "name": system.get("name", ""),
        "description": system.get("description", ""),
        "object_id": system.get("object_id", ""),
        "interfaces": interfaces,
        # ipAdEntIfIndex: the suffix is the IP, the value the ifIndex.
        "addresses": {ip: _text(ifindex) for ip, ifindex in ip_to_ifindex.items()},
        "neighbors": neighbors,
        "fdb": fdb,
        "ups": _ups_reading(ups),
        "members": members,
    }


def _ups_reading(raw: dict[str, str]) -> dict[str, Any]:
    """Lo que contestó la UPS-MIB, en cifras, o vacío si no contestó nadie.

    Se devuelve vacío en cuanto no hay minutos: sin ese dato lo demás no
    sostiene una respuesta a «¿cuánta autonomía le queda?», que es para lo que
    se pregunta. Un SAI que contesta a medias no puede acabar creando una ficha
    de SAI con todo a cero.
    """
    minutes = _number(raw.get("runtime_minutes", ""))
    if minutes is None:
        return {}
    return {
        "runtime_minutes": minutes,
        "charge_percent": _number(raw.get("charge_percent", "")),
        "load_percent": _number(raw.get("load_percent", "")),
        "on_battery": _text(raw.get("output_source", "")) == UPS_SOURCE_ON_BATTERY,
    }


def _number(value: Any) -> int | None:
    """El entero que trae un OID, o nada. Lo escribe un aparato, no nosotros."""
    try:
        return int(_text(value))
    except (TypeError, ValueError):
        return None


async def _query_all(hosts: list[str], auths: list[Auth]) -> dict[str, dict[str, Any]]:
    semaphore = asyncio.Semaphore(CONCURRENCY)

    async def bounded(host: str):
        async with semaphore:
            return host, await _query_host(host, auths)

    answers = await asyncio.gather(*(bounded(host) for host in hosts))
    return {host: data for host, data in answers if data is not None}


def query_hosts(hosts: list[str], auths: list[Auth]) -> dict[str, dict[str, Any]]:
    """Synchronous door for the collectors: {host: data} for those that answered.

    ``auths`` mixes freely: v3 users (``credentials.Credential``) and v2c
    communities (plain strings), tried per host in the order given."""
    if not AVAILABLE or not hosts:
        return {}
    return asyncio.run(_query_all(hosts, auths))


async def _query_plan(
    plan: dict[str, list[Auth]],
    concurrency: int,
    ups_only: bool,
    on_done: Callable[[], None] | None,
) -> dict[str, tuple[int, dict[str, Any]]]:
    semaphore = asyncio.Semaphore(max(1, concurrency))
    query = _query_ups_host if ups_only else _query_host_indexed

    async def bounded(host: str, auths: list[Auth]):
        async with semaphore:
            try:
                return host, await query(host, auths)
            except Exception:  # noqa: BLE001 - un equipo raro no tumba el lote
                return host, None
            finally:
                if on_done is not None:
                    try:
                        on_done()
                    except Exception:  # noqa: BLE001 - avisar del avance nunca rompe nada
                        pass

    answers = await asyncio.gather(*(bounded(host, auths) for host, auths in plan.items() if auths))
    return {host: found for host, found in answers if found is not None}


def query_plan(
    plan: dict[str, list[Auth]],
    *,
    concurrency: int = CONCURRENCY,
    ups_only: bool = False,
    on_done: Callable[[], None] | None = None,
) -> dict[str, tuple[int, dict[str, Any]]]:
    """Each host with **its own** auths, in its own order: {host: (index, data)}.

    The task-based path. ``query_hosts`` asks every host with the same list;
    here the memory has already decided, host by host, what to try first and
    what not to try at all. ``index`` says which of that host's auths answered.
    ``ups_only`` asks the UPS-MIB and nothing else (the ``ups`` task).
    ``on_done`` is called once per host as it finishes, for the progress bar.
    """
    if not AVAILABLE or not plan:
        return {}
    return asyncio.run(_query_plan(plan, concurrency, ups_only, on_done))
