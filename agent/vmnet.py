"""Tarjetas de red y discos de una máquina virtual, en una sola forma.

Cada hipervisor cuenta lo mismo a su manera: vCenter da las tarjetas en el
detalle de la VM y los discos como `"[datastore1] carpeta/disco.vmdk"`;
Proxmox lo escribe en su configuración como `virtio=BC:24:11:…,bridge=vmbr0,
tag=10` y `local-lvm:vm-100-disk-0,size=32G`; Hyper-V da rutas de Windows y
MACs sin separadores; XCP-ng, tablas que se cruzan. Este módulo lo deja todo
en la forma que espera el servidor, para que ningún cliente invente la suya:

    interfaces: [{"name": str, "mac": str, "ips": [str], "vlan": int | None}]
    disks:      [{"datastore": str, "gb": int}]

Lo que no se puede leer se queda vacío; nunca lanza. Un payload incompleto
vale más que una máquina que no llega.
"""

from __future__ import annotations

import re
from typing import Any

#: Tope de tarjetas y discos por máquina. Una VM con más no es una VM: es una
#: respuesta que no se puede creer, y el servidor tiene el mismo tope.
MAX_PER_MACHINE = 64

_MAC_HEX = re.compile(r"^[0-9a-fA-F]{12}$")
_PROXMOX_DISK_KEY = re.compile(r"^(scsi|virtio|sata|ide|efidisk|tpmstate)\d+$")
_PROXMOX_LXC_DISK_KEY = re.compile(r"^(rootfs|mp\d+)$")
_PROXMOX_NET_KEY = re.compile(r"^net\d+$")
_SIZE = re.compile(r"^(\d+(?:\.\d+)?)([KMGT]?)$", re.IGNORECASE)
_CSV = re.compile(r"^([a-zA-Z]:\\ClusterStorage\\[^\\]+)", re.IGNORECASE)


def mac(value: Any) -> str:
    """Una MAC con dos puntos y en minúsculas, o "" si no lo es.

    Hyper-V la da como `00155D0A1B2C`; los demás, con dos puntos o guiones.
    """
    text = str(value or "").strip().replace("-", "").replace(":", "").replace(".", "")
    if not _MAC_HEX.match(text):
        return ""
    text = text.lower()
    return ":".join(text[index : index + 2] for index in range(0, 12, 2))


def interface(name: Any, mac_address: Any, ips: Any = None, vlan: Any = None) -> dict[str, Any]:
    addresses = [str(ip).strip() for ip in (ips or []) if str(ip or "").strip()] if isinstance(ips, list) else []
    try:
        vid: int | None = int(vlan) if vlan not in (None, "", 0, "0") else None
    except (TypeError, ValueError):
        vid = None
    if vid is not None and not 1 <= vid <= 4094:
        vid = None
    return {"name": str(name or "").strip()[:200], "mac": mac(mac_address), "ips": addresses[:32], "vlan": vid}


def disk(datastore: Any, size_bytes: Any) -> dict[str, Any] | None:
    name = str(datastore or "").strip()[:200]
    if not name:
        return None
    try:
        size = float(size_bytes or 0)
    except (TypeError, ValueError):
        size = 0.0
    return {"datastore": name, "gb": round(size / (1024**3)) if size > 0 else 0}


def merge_disks(disks: list[dict[str, Any] | None]) -> list[dict[str, Any]]:
    """Un datastore una vez, con la suma de lo que la máquina tiene en él.

    Dos discos en el mismo datastore son una sola dependencia: si ese
    datastore cae, la máquina cae una vez, no dos.
    """
    total: dict[str, int] = {}
    for item in disks:
        if item:
            total[item["datastore"]] = total.get(item["datastore"], 0) + int(item["gb"])
    return [{"datastore": name, "gb": gb} for name, gb in list(total.items())[:MAX_PER_MACHINE]]


# --- vCenter ----------------------------------------------------------------------


def vmware_datastore(vmdk_file: Any) -> str:
    """`"[datastore1] srv/srv.vmdk"` → `"datastore1"`."""
    text = str(vmdk_file or "").strip()
    if text.startswith("[") and "]" in text:
        return text[1 : text.index("]")].strip()
    return ""


def _entries(value: Any) -> list[tuple[str, dict[str, Any]]]:
    """Los elementos indexados de un detalle de vCenter, en las dos formas.

    `/api` los da como `{"4000": {...}}`; `/rest`, como `[{"key": "4000",
    "value": {...}}]`.
    """
    if isinstance(value, dict):
        return [(str(key), item) for key, item in value.items() if isinstance(item, dict)]
    if isinstance(value, list):
        found = []
        for item in value:
            if isinstance(item, dict) and isinstance(item.get("value"), dict):
                found.append((str(item.get("key") or ""), item["value"]))
        return found
    return []


def vmware_disks(detail: dict[str, Any]) -> list[dict[str, Any]]:
    return merge_disks(
        [
            disk(vmware_datastore((item.get("backing") or {}).get("vmdk_file")), item.get("capacity"))
            for _key, item in _entries(detail.get("disks"))
        ]
    )


def vmware_interfaces(detail: dict[str, Any], guest: Any = None) -> list[dict[str, Any]]:
    """Las tarjetas del detalle, con las direcciones que dicen las VMware Tools.

    El detalle trae MAC y etiqueta; las direcciones solo las sabe el invitado
    (`/guest/networking/interfaces`), y se cruzan por MAC. La VLAN del grupo
    de puertos no la da la API REST: se queda vacía.
    """
    ips_by_mac: dict[str, list[str]] = {}
    for entry in guest if isinstance(guest, list) else []:
        if not isinstance(entry, dict):
            continue
        address = mac(entry.get("mac_address"))
        ip_block = entry.get("ip") if isinstance(entry.get("ip"), dict) else {}
        for raw in ip_block.get("ip_addresses") or []:
            if isinstance(raw, dict) and raw.get("ip_address"):
                prefix = raw.get("prefix_length")
                text = str(raw["ip_address"])
                ips_by_mac.setdefault(address, []).append(f"{text}/{prefix}" if prefix else text)
    found = []
    for key, item in _entries(detail.get("nics"))[:MAX_PER_MACHINE]:
        address = mac(item.get("mac_address"))
        found.append(interface(item.get("label") or f"nic-{key}", address, ips_by_mac.get(address, [])))
    return found


# --- Proxmox ----------------------------------------------------------------------


def _options(value: Any) -> tuple[str, dict[str, str]]:
    """`"local-lvm:vm-100-disk-0,size=32G"` → (`"local-lvm:vm-100-disk-0"`, `{"size": "32G"}`)."""
    parts = [part.strip() for part in str(value or "").split(",") if part.strip()]
    head = ""
    options: dict[str, str] = {}
    for index, part in enumerate(parts):
        if "=" in part:
            key, _, val = part.partition("=")
            options[key.strip().lower()] = val.strip()
        elif index == 0:
            head = part
    return head, options


def _size_bytes(text: str) -> float:
    match = _SIZE.match(text.strip())
    if not match:
        return 0.0
    unit = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}[match.group(2).upper()]
    return float(match.group(1)) * unit


def proxmox_disks(config: dict[str, Any], *, container: bool) -> list[dict[str, Any]]:
    pattern = _PROXMOX_LXC_DISK_KEY if container else _PROXMOX_DISK_KEY
    found = []
    for key, value in config.items():
        if not pattern.match(str(key)):
            continue
        head, options = _options(value)
        if options.get("media") == "cdrom" or head in ("", "none") or ":" not in head:
            continue
        found.append(disk(head.split(":", 1)[0], _size_bytes(options.get("size", ""))))
    return merge_disks(found)


def proxmox_interfaces(
    config: dict[str, Any], *, container: bool, guest: Any = None
) -> list[dict[str, Any]]:
    """Las tarjetas de la configuración, con su VLAN (`tag`).

    De un contenedor la dirección está en la propia configuración
    (`ip=192.168.1.5/24`); de una KVM solo la sabe el agente QEMU de dentro,
    si está puesto, y se cruza por MAC.
    """
    ips_by_mac: dict[str, list[str]] = {}
    result = guest.get("result") if isinstance(guest, dict) else guest
    for entry in result if isinstance(result, list) else []:
        if not isinstance(entry, dict):
            continue
        address = mac(entry.get("hardware-address"))
        for raw in entry.get("ip-addresses") or []:
            if isinstance(raw, dict) and raw.get("ip-address"):
                prefix = raw.get("prefix")
                text = str(raw["ip-address"])
                ips_by_mac.setdefault(address, []).append(f"{text}/{prefix}" if prefix is not None else text)
    found = []
    for key in sorted(k for k in config if _PROXMOX_NET_KEY.match(str(k))):
        _head, options = _options(config[key])
        if container:
            address = mac(options.get("hwaddr"))
            ips = [options[k] for k in ("ip", "ip6") if options.get(k) and options[k] not in ("dhcp", "manual", "auto")]
            name = options.get("name") or key
        else:
            # `virtio=BC:24:11:…`: el modelo de la tarjeta es la clave y la MAC el valor.
            address = next((mac(v) for v in options.values() if mac(v)), "")
            ips = ips_by_mac.get(address, [])
            name = key
        found.append(interface(name, address, ips, options.get("tag")))
    return found[:MAX_PER_MACHINE]


# --- Hyper-V ----------------------------------------------------------------------


def windows_datastore(path: Any) -> str:
    """Dónde vive un disco de Hyper-V, al nivel en que se comparte.

    Un volumen compartido del clúster (`C:\\ClusterStorage\\Volume1`) o un
    recurso SMB (`\\\\nas\\vms`) son el «datastore»; un disco local es su
    unidad (`D:`). La carpeta de cada máquina no lo es.
    """
    text = str(path or "").strip()
    if not text:
        return ""
    if text.startswith("\\\\"):
        parts = [part for part in text.split("\\") if part]
        return "\\\\" + "\\".join(parts[:2]) if len(parts) >= 2 else ""
    csv = _CSV.match(text)
    if csv:
        return csv.group(1)
    if len(text) >= 2 and text[1] == ":":
        return text[:2].upper()
    return ""
