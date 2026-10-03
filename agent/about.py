"""The agent introduces itself: the `about` of protocol 2 (spec 1.5).

Where it runs, what version, which networks it sits on and what it is able to
do with what this installation has (SNMP needs pysnmp, a password over SSH
needs a way to type it, sealed credentials need a key...). The server shows it
in Ajustes → Agentes and uses it to explain why a collector said nothing.

It travels by hash: every check-in carries ``about_hash``, the SHA-256 of the
canonical JSON, and the whole thing only when it changed or the server asks.
The hash does not depend on key order, so the same machine always gives the
same hash.

**Never raises, never a secret.** A network list that cannot be read is an
empty list; the proxy URL (it may carry a password) is not in here.

The networks come from the operating system without parsing anything written
for a person, so the language of the system does not matter: on Windows,
``GetAdaptersAddresses`` through ``ctypes``; on Linux, the JSON of ``ip -j
addr``.
"""

from __future__ import annotations

import ipaddress
import json
import platform
import socket
import subprocess
import sys
from hashlib import sha256
from typing import Any

from agent import __version__

#: El tope del servidor (spec 1.5): más redes que esto se recortan aquí.
MAX_NETWORKS = 64


def canonical(data: Any) -> bytes:
    """El JSON canónico: claves ordenadas, sin espacios, UTF-8."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(data: Any) -> str:
    return sha256(canonical(data)).hexdigest()


# --- Redes -------------------------------------------------------------------------


def _network_row(interface: str, address: str, prefix: int, mac: str) -> dict[str, str] | None:
    """Una fila de `networks`, o `None` si no merece estar (bucle local, APIPA)."""
    try:
        ip = ipaddress.ip_address(address)
        network = ipaddress.ip_network(f"{address}/{int(prefix)}", strict=False)
    except (ValueError, TypeError):
        return None
    if ip.version != 4 or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return None
    return {"interface": str(interface), "address": str(ip), "cidr": str(network), "mac": _mac(mac)}


def _mac(raw: str) -> str:
    cleaned = raw.replace("-", ":").lower()
    return "" if cleaned in ("", "00:00:00:00:00:00") else cleaned


def parse_ip_json(output: str) -> list[dict[str, str]]:
    """Las redes IPv4 de la salida de `ip -j addr` (Linux)."""
    try:
        links = json.loads(output)
    except ValueError:
        return []
    rows: list[dict[str, str]] = []
    if not isinstance(links, list):
        return rows
    for link in links:
        if not isinstance(link, dict):
            continue
        flags = link.get("flags") or []
        if "LOOPBACK" in flags or (link.get("operstate") == "DOWN"):
            continue
        for info in link.get("addr_info") or []:
            if not isinstance(info, dict) or info.get("family") != "inet":
                continue
            row = _network_row(
                str(link.get("ifname") or ""), str(info.get("local") or ""), info.get("prefixlen") or 32,
                str(link.get("address") or ""),
            )
            if row:
                rows.append(row)
    return rows


def _linux_networks() -> list[dict[str, str]]:
    try:
        result = subprocess.run(
            ["ip", "-j", "addr"], capture_output=True, text=True, errors="replace", timeout=10, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    return parse_ip_json(result.stdout) if result.returncode == 0 else []


def _windows_networks() -> list[dict[str, str]]:
    """Las redes IPv4 con `GetAdaptersAddresses`: datos, no texto traducido."""
    import ctypes
    from ctypes import wintypes

    class SOCKET_ADDRESS(ctypes.Structure):  # noqa: N801 - nombres de la API de Windows
        _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]

    class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):  # noqa: N801
        pass

    IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
        ("Length", wintypes.ULONG),
        ("Flags", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("Address", SOCKET_ADDRESS),
        ("PrefixOrigin", ctypes.c_int),
        ("SuffixOrigin", ctypes.c_int),
        ("DadState", ctypes.c_int),
        ("ValidLifetime", wintypes.ULONG),
        ("PreferredLifetime", wintypes.ULONG),
        ("LeaseLifetime", wintypes.ULONG),
        ("OnLinkPrefixLength", ctypes.c_uint8),
    ]

    class IP_ADAPTER_ADDRESSES(ctypes.Structure):  # noqa: N801
        pass

    # Solo hasta `OperStatus`: lo de detrás no se lee, y los punteros `Next`
    # apuntan dentro del búfer que rellena Windows, no a esta estructura.
    IP_ADAPTER_ADDRESSES._fields_ = [
        ("Length", wintypes.ULONG),
        ("IfIndex", wintypes.DWORD),
        ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
        ("AdapterName", ctypes.c_char_p),
        ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", ctypes.c_wchar_p),
        ("Description", ctypes.c_wchar_p),
        ("FriendlyName", ctypes.c_wchar_p),
        ("PhysicalAddress", ctypes.c_ubyte * 8),
        ("PhysicalAddressLength", wintypes.ULONG),
        ("Flags", wintypes.ULONG),
        ("Mtu", wintypes.ULONG),
        ("IfType", wintypes.ULONG),
        ("OperStatus", ctypes.c_int),
    ]

    af_inet = 2
    # Sin anycast, multicast ni DNS: menos que copiar y nada que se use.
    flags = 0x0002 | 0x0004 | 0x0008
    error_buffer_overflow = 111
    if_oper_status_up = 1
    if_type_loopback = 24

    get = ctypes.windll.iphlpapi.GetAdaptersAddresses
    get.argtypes = [wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG)]
    get.restype = wintypes.ULONG
    size = wintypes.ULONG(16 * 1024)
    for _ in range(3):
        buffer = ctypes.create_string_buffer(size.value)
        answer = get(af_inet, flags, None, buffer, ctypes.byref(size))
        if answer != error_buffer_overflow:
            break
    if answer != 0:
        return []

    rows: list[dict[str, str]] = []
    adapter = ctypes.cast(buffer, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    while adapter:
        item = adapter.contents
        if item.OperStatus == if_oper_status_up and item.IfType != if_type_loopback:
            length = min(int(item.PhysicalAddressLength), 8)
            mac = ":".join(f"{byte:02x}" for byte in bytes(item.PhysicalAddress)[:length]) if length == 6 else ""
            unicast = item.FirstUnicastAddress
            while unicast:
                address = unicast.contents
                raw = ctypes.string_at(address.Address.lpSockaddr, 8) if address.Address.lpSockaddr else b""
                # sockaddr_in: familia (2 bytes, little endian), puerto, y la dirección.
                if len(raw) == 8 and int.from_bytes(raw[0:2], "little") == af_inet:
                    row = _network_row(item.FriendlyName or "", socket.inet_ntoa(raw[4:8]), address.OnLinkPrefixLength, mac)
                    if row:
                        rows.append(row)
                unicast = address.Next
        adapter = item.Next
    return rows


def networks() -> list[dict[str, str]]:
    """Las redes de esta máquina, o `[]` si no se pueden leer. Nunca lanza."""
    try:
        rows = _windows_networks() if sys.platform == "win32" else _linux_networks()
    except Exception:  # noqa: BLE001 - sin redes, pero con about
        return []
    # Orden estable: el mismo equipo tiene que dar siempre el mismo hash.
    rows.sort(key=lambda row: (row["interface"], row["address"]))
    return rows[:MAX_NETWORKS]


# --- Capacidades ---------------------------------------------------------------------


def capabilities() -> dict[str, bool]:
    """Lo que esta instalación puede hacer. Cada una se mira por separado."""

    def check(probe) -> bool:  # noqa: ANN001
        try:
            return bool(probe())
        except Exception:  # noqa: BLE001
            return False

    def _snmp() -> bool:
        from agent import snmp

        return snmp.AVAILABLE

    def _ssh() -> bool:
        from agent import ssh

        return ssh.AVAILABLE

    def _ssh_password() -> bool:
        from agent import ssh

        return getattr(ssh, "PASSWORD_AUTH_AVAILABLE", ssh.SSHPASS_AVAILABLE)

    def _winrm() -> bool:
        from agent import winrm

        return winrm.AVAILABLE

    def _hypervisors() -> bool:
        # vCenter, Proxmox y XCP-ng van por HTTPS con la librería estándar;
        # basta con que el colector esté entre los registrados.
        from agent.collectors import all_collectors

        return any(collector.name == "hypervisors" for collector in all_collectors())

    def _sealed() -> bool:
        # La clave en disco, la librería, y una ida y vuelta que funciona: decir
        # «sí» con una clave que no abre haría que la web sellara para nada.
        from agent import sealing

        return sealing.self_test()

    return {
        "snmp": check(_snmp),
        "ssh": check(_ssh),
        "ssh_password": check(_ssh_password),
        "winrm": check(_winrm),
        "hypervisors": check(_hypervisors),
        "sealed_credentials": check(_sealed),
    }


# --- Todo junto ------------------------------------------------------------------------


def build(
    *,
    excluded_subnets: tuple[str, ...] | list[str] = (),
    excluded_addresses: tuple[str, ...] | list[str] = (),
    auto_update: bool = True,
) -> dict[str, Any]:
    """El `about` entero. Nunca lanza: lo que no se sepa va vacío."""

    def safe(probe, default):  # noqa: ANN001, ANN202
        try:
            return probe()
        except Exception:  # noqa: BLE001
            return default

    return {
        "hostname": safe(socket.gethostname, ""),
        "os": {
            "system": safe(platform.system, ""),
            "release": safe(platform.release, ""),
            "version": safe(platform.version, ""),
        },
        "python": safe(platform.python_version, ""),
        "agent_version": __version__,
        "frozen": bool(getattr(sys, "frozen", False)),
        "networks": networks(),
        "capabilities": safe(capabilities, {}),
        "excluded": {"subnets": list(excluded_subnets), "addresses": list(excluded_addresses)},
        "auto_update": bool(auto_update),
    }
