"""Cabinas de discos con API: Synology DSM y TrueNAS.

Lo que los hipervisores no pueden saber de una cabina lo dice ella: con qué
RAID y qué discos está hecho cada volumen, cuánto mide de verdad y a quién deja
entrar (la lista de acceso de cada destino iSCSI, los clientes de cada NFS).
Con eso la ficha del volumen dice «Presentado a» aunque el host esté apagado, y
la cabina que un hipervisor creó «pendiente de identificar» por su IQN se funde
con esta en el servidor (`core/storage_discovery.py`, `sync_array`).

Los dos clientes cumplen el contrato de los hipervisores (`login`, `hosts`,
`virtual_machines`) a propósito: entran como una fila más en
`agent.collectors.hypervisors.CLIENTS` y heredan sin código nuevo el alcance,
las exclusiones, la memoria de credenciales, el límite de inicios de sesión y
«Probar». `hosts()` devuelve una sola entrada, la propia cabina, con sus
volúmenes en `storage_volumes`; `virtual_machines()` no devuelve nada.

**Solo lectura**: ninguna llamada cambia nada en la cabina. **TLS verificado**
como en los hipervisores (`agent.tlspin`: su CA o el certificado en el que se
confió desde la web). Una llamada auxiliar que falla deja ese dato vacío; nunca
se queda sin la cabina por ello.

QNAP no está: su información de LUN va por SNMP con su propia MIB, y esa tabla
no se escribe de memoria; hace falta un volcado de un equipo real.
"""

from __future__ import annotations

import json
from typing import Any

from agent.hypervisor import HypervisorError, RestClient

#: Tope de volúmenes por cabina: más no es una cabina de pyme, es una respuesta
#: que no se puede creer. El servidor tiene el mismo.
MAX_VOLUMES = 128


def _list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _disk_kind(kinds: list[str]) -> str:
    """El tipo de disco de un volumen a partir de los de sus discos."""
    words = {k.strip().lower() for k in kinds if k and k.strip()}
    if not words:
        return ""
    if words <= {"ssd", "nvme"}:
        return "nvme" if words == {"nvme"} else "ssd"
    if words & {"ssd", "nvme"}:
        return "hybrid"
    if "sas" in words:
        return "sas"
    return "sata"


def _array_host(name: str, vendor: str, **fields: Any) -> dict[str, Any]:
    found = {
        "name": name,
        "power_state": "POWERED_ON",
        "connection_state": "online",
        "manufacturer": vendor,
        "description": f"Cabina de discos {vendor}",
        "is_virtualization_host": False,
    }
    found.update({k: v for k, v in fields.items() if v not in (None, "", [])})
    return found


# --- Synology DSM -------------------------------------------------------------------


class SynologyClient:
    """La API web de DSM (`/webapi/`), con usuario y contraseña.

    Basta un usuario de solo lectura del grupo de administradores; DSM no tiene
    un rol más fino para leer el SAN Manager.
    """

    def __init__(
        self, host: str, username: str, secret: str, *, port: int = 0, ca_file: str = "", tls_pin: str = ""
    ) -> None:
        self.host = host
        self.rest = RestClient(f"https://{host}:{port or 5001}", ca_file=ca_file, tls_pin=tls_pin)
        self.username = username
        self.secret = secret
        self.sid = ""

    def login(self) -> None:
        answer = self.rest.request(
            "POST",
            "/webapi/auth.cgi",
            body={
                "api": "SYNO.API.Auth",
                "version": "6",
                "method": "login",
                "account": self.username,
                "passwd": self.secret,
                "session": "Cenya",
                "format": "sid",
            },
        )
        data = answer.get("data") if isinstance(answer, dict) else None
        if not isinstance(answer, dict) or not answer.get("success") or not isinstance(data, dict) or not data.get("sid"):
            code = ((answer or {}).get("error") or {}).get("code") if isinstance(answer, dict) else None
            # 400 a 404: usuario o contraseña, cuenta desactivada, permiso, doble factor.
            raise HypervisorError(f"DSM rechazó el inicio de sesión (código {code})", status=401)
        self.sid = str(data["sid"])

    def _call(self, api: str, method: str, version: int = 1, **params: Any) -> dict[str, Any]:
        """Una llamada; vacía si DSM dice que no (el dato se queda sin poner)."""
        body = {"api": api, "method": method, "version": str(version), "_sid": self.sid}
        body.update({k: json.dumps(v) if isinstance(v, (list, dict)) else str(v) for k, v in params.items()})
        try:
            answer = self.rest.request("POST", "/webapi/entry.cgi", body=body)
        except HypervisorError:
            return {}
        if not isinstance(answer, dict) or not answer.get("success"):
            return {}
        data = answer.get("data")
        return data if isinstance(data, dict) else {}

    def hosts(self) -> list[dict[str, Any]]:
        info = self._call("SYNO.DSM.Info", "getinfo", 2)
        luns = _list(self._call("SYNO.Core.ISCSI.LUN", "list", 1, additional=["allocated_size", "status"]).get("luns"))
        targets = _list(
            self._call("SYNO.Core.ISCSI.Target", "list", 1, additional=["mapped_lun", "acls", "connected_sessions"]).get(
                "targets"
            )
        )
        storage = self._call("SYNO.Storage.CGI.Storage", "load_info", 1)
        self._logout()
        volumes = synology_volumes(luns, targets, storage)
        return [
            _array_host(
                self.host,
                "Synology",
                model=str(info.get("model") or "")[:200],
                serial=str(info.get("serial") or "")[:200],
                os=f"DSM {info.get('version_string') or ''}".strip() if info else "",
                storage_volumes=volumes,
            )
        ]

    def virtual_machines(self) -> list[dict[str, Any]]:
        return []

    def _logout(self) -> None:
        try:
            self.rest.request(
                "POST", "/webapi/auth.cgi", body={"api": "SYNO.API.Auth", "version": "6", "method": "logout", "session": "Cenya", "_sid": self.sid}
            )
        except HypervisorError:
            pass


def synology_volumes(
    luns: list[dict[str, Any]], targets: list[dict[str, Any]], storage: dict[str, Any]
) -> list[dict[str, Any]]:
    """Cada LUN con su destino, su número, su lista de acceso y el RAID y los
    discos del grupo de almacenamiento en que vive."""
    by_lun: dict[str, tuple[dict[str, Any], int | None]] = {}
    for target in targets:
        for mapped in _list(target.get("mapped_luns")):
            uuid = str(mapped.get("lun_uuid") or "")
            if uuid:
                index = mapped.get("mapping_index")
                by_lun[uuid] = (target, index if isinstance(index, int) else None)
    volumes_info = _list(storage.get("volumes"))
    pools = {str(p.get("id") or ""): p for p in _list(storage.get("storagePools"))}
    disks = {str(d.get("id") or ""): d for d in _list(storage.get("disks"))}
    found: list[dict[str, Any]] = []
    for lun in luns[:MAX_VOLUMES]:
        name = str(lun.get("name") or "").strip()
        if not name:
            continue
        target, index = by_lun.get(str(lun.get("uuid") or ""), ({}, None))
        location = str(lun.get("location") or "")
        volume = next((v for v in volumes_info if str(v.get("vol_path") or "") == location), {})
        pool = pools.get(str(volume.get("pool_path") or ""), {})
        kinds = [
            "ssd" if disks.get(str(d), {}).get("isSsd") else str(disks.get(str(d), {}).get("diskType") or "")
            for d in pool.get("disks") or []
        ]
        initiators = [
            str(acl.get("iqn") or "")
            for acl in _list(target.get("acls"))
            if acl.get("iqn") and "default" not in str(acl.get("iqn")).lower()
        ]
        initiators += [str(s.get("iqn") or "") for s in _list(target.get("connected_sessions")) if s.get("iqn")]
        size = lun.get("size")
        found.append(
            {
                "name": name[:200],
                "protocol": "iscsi",
                "gb": round(float(size) / (1024**3)) if isinstance(size, (int, float)) and size > 0 else 0,
                "target_iqn": str(target.get("iqn") or "")[:255],
                "lun": index,
                "raid": str(pool.get("device_type") or pool.get("raidType") or ""),
                "disk": _disk_kind(kinds),
                "initiators": sorted(set(i for i in initiators if i)),
            }
        )
    return found


# --- TrueNAS ------------------------------------------------------------------------


class TrueNASClient:
    """La API REST v2.0 de TrueNAS, con una clave de API (`secret`).

    El usuario no hace falta: la clave ya es de alguien. Se puede crear una de
    solo lectura en TrueNAS SCALE 24.10 y posteriores.
    """

    def __init__(
        self, host: str, username: str, secret: str, *, port: int = 0, ca_file: str = "", tls_pin: str = ""
    ) -> None:
        self.host = host
        self.rest = RestClient(f"https://{host}:{port or 443}", ca_file=ca_file, tls_pin=tls_pin)
        self.headers = {"Authorization": f"Bearer {secret}"}
        self.info: dict[str, Any] = {}

    def login(self) -> None:
        answer = self.rest.request("GET", "/api/v2.0/system/info", headers=self.headers)
        if not isinstance(answer, dict):
            raise HypervisorError("TrueNAS no dio su información de sistema", logged_in=True)
        self.info = answer

    def _get(self, path: str) -> Any:
        try:
            return self.rest.request("GET", f"/api/v2.0{path}", headers=self.headers)
        except HypervisorError:
            return None

    def hosts(self) -> list[dict[str, Any]]:
        global_config = self._get("/iscsi/global")
        tables = {
            name: _list(self._get(path))
            for name, path in (
                ("targets", "/iscsi/target"),
                ("extents", "/iscsi/extent"),
                ("links", "/iscsi/targetextent"),
                ("initiators", "/iscsi/initiator"),
                ("pools", "/pool"),
                ("disks", "/disk"),
                ("nfs", "/sharing/nfs"),
                ("interfaces", "/interface"),
                ("zvols", "/pool/dataset?type=VOLUME"),
            )
        }
        basename = str((global_config or {}).get("basename") or "") if isinstance(global_config, dict) else ""
        info = self.info
        return [
            _array_host(
                self.host,
                str(info.get("system_manufacturer") or "") or "TrueNAS",
                model=str(info.get("system_product") or "")[:200],
                serial=str(info.get("system_serial") or "")[:200],
                os=f"TrueNAS {info.get('version') or ''}".strip(),
                description="Cabina de discos TrueNAS",
                storage_volumes=truenas_volumes(basename, tables),
                addresses=truenas_addresses(tables["interfaces"]),
            )
        ]

    def virtual_machines(self) -> list[dict[str, Any]]:
        return []


def _pool_facts(pools: list[dict[str, Any]], disks: list[dict[str, Any]]) -> dict[str, tuple[str, str]]:
    """`{pool: (RAID, tipo de disco)}` desde la topología de datos de cada pool."""
    kinds = {str(d.get("name") or ""): str(d.get("type") or "") for d in disks}
    facts: dict[str, tuple[str, str]] = {}
    for pool in pools:
        vdevs = _list((pool.get("topology") or {}).get("data")) if isinstance(pool.get("topology"), dict) else []
        raid = str(vdevs[0].get("type") or "") if vdevs else ""
        names = [str(c.get("disk") or "") for v in vdevs for c in _list(v.get("children"))]
        facts[str(pool.get("name") or "")] = (raid, _disk_kind([kinds.get(n, "") for n in names]))
    return facts


def truenas_volumes(basename: str, tables: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    facts = _pool_facts(tables["pools"], tables["disks"])
    targets = {t.get("id"): t for t in tables["targets"]}
    extents = {e.get("id"): e for e in tables["extents"]}
    initiator_groups = {g.get("id"): [str(i) for i in g.get("initiators") or [] if i] for g in tables["initiators"]}
    sizes = {
        str(z.get("id") or ""): (z.get("volsize") or {}).get("parsed") if isinstance(z.get("volsize"), dict) else None
        for z in tables["zvols"]
    }
    found: list[dict[str, Any]] = []
    for link in tables["links"][:MAX_VOLUMES]:
        target, extent = targets.get(link.get("target")), extents.get(link.get("extent"))
        if not target or not extent or not extent.get("name"):
            continue
        dataset = str(extent.get("disk") or "").removeprefix("zvol/")
        pool = dataset.split("/", 1)[0] if dataset else str(extent.get("path") or "").removeprefix("/mnt/").split("/", 1)[0]
        raid, disk = facts.get(pool, ("", ""))
        size = sizes.get(dataset) or extent.get("filesize")
        initiators = [
            iqn
            for group in _list(target.get("groups"))
            for iqn in initiator_groups.get(group.get("initiator"), [])
        ]
        found.append(
            {
                "name": str(extent["name"])[:200],
                "protocol": "iscsi",
                "gb": round(float(size) / (1024**3)) if isinstance(size, (int, float)) and size > 0 else 0,
                "target_iqn": f"{basename}:{target.get('name')}" if basename and target.get("name") else "",
                "lun": link.get("lunid") if isinstance(link.get("lunid"), int) else None,
                "raid": raid,
                "disk": disk,
                "initiators": sorted(set(initiators)),
            }
        )
    for share in tables["nfs"][: max(0, MAX_VOLUMES - len(found))]:
        paths = [str(p) for p in share.get("paths") or [] if p] or ([str(share["path"])] if share.get("path") else [])
        for path in paths:
            raid, disk = facts.get(path.removeprefix("/mnt/").split("/", 1)[0], ("", ""))
            found.append(
                {
                    "name": path[:200],
                    "protocol": "nfs",
                    "export": path[:300],
                    "raid": raid,
                    "disk": disk,
                    "clients": [str(h) for h in share.get("hosts") or [] if h],
                }
            )
    return found


def truenas_addresses(interfaces: list[dict[str, Any]]) -> list[str]:
    """Todas sus direcciones: la de gestión y las de la red de almacenamiento.
    Son las que un hipervisor pudo ver como portal y con las que creó la
    cabina provisional que el servidor funde con esta."""
    found: list[str] = []
    for interface in interfaces:
        state = interface.get("state") if isinstance(interface.get("state"), dict) else {}
        for alias in _list(interface.get("aliases")) + _list(state.get("aliases")):
            address = str(alias.get("address") or "")
            if address and alias.get("type", "INET") in ("INET", "INET6") and address not in found:
                found.append(address)
    return found[:64]
