"""The ARP and MAC tables of a device read over SSH (phase 4 of the Netdisco
plan): for the networks where only the firewall knows who is there.

A firewall or a router in a small business has the most complete ARP table
of the network, and often nobody turned SNMP on. The SSH collector already
gets in by family; here each family gets one order for its ARP table and,
for the switches, one for its MAC table, and the answers come back **in the
same shape the SNMP collector produces** (``arp`` as ``[{ip, mac}]``, ``fdb``
as ``[{mac, ifindex, vlan}]`` with the port name as ``ifindex``), so the
links and the ``fdb_ports`` of the finding are built by the same code.

Everything here is pure text in, lists out. Nothing raises: a line that is
not a row is skipped, an order a family does not have is not sent.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable

#: The order that prints the ARP table, per family (the ``family`` the SSH
#: collector decided). Linux takes IPv4 and IPv6 in one go. Families without
#: an entry (ESXi, a bare CLI) are not asked.
ARP_COMMANDS: dict[str, str] = {
    "linux": "ip neigh show",
    "cisco": "show ip arp",
    "junos": "show arp no-resolve",
    "aruba": "show arp",
    "dell": "show arp",
    "huawei": "display arp",
    "comware": "display arp",
    "mikrotik": "/ip arp print without-paging",
    "fortinet": "get system arp",
    "gaia": "show arp dynamic all",
}

#: The order that prints the MAC (forwarding) table, only for the families
#: that are switches. A firewall's "MAC table" is its ARP table.
MAC_COMMANDS: dict[str, str] = {
    "cisco": "show mac address-table",
    "junos": "show ethernet-switching table",
    "aruba": "show mac-address",
    "dell": "show mac address-table",
    "huawei": "display mac-address",
    "comware": "display mac-address",
    "mikrotik": "/interface bridge host print without-paging",
}

#: Every way a CLI writes a MAC: colons, dashes, Cisco dots, Huawei dashes
#: in threes (Fortinet, colons in threes), ProCurve dash in the middle.
_MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:.-])("
    r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
    r"|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}"
    r"|(?:[0-9A-Fa-f]{4}[-:]){2}[0-9A-Fa-f]{4}"
    r"|[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}"
    r")(?![0-9A-Fa-f:.-])"
)
_IP_RE = re.compile(r"(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:]+)(?![\w.:])")
#: Rows that are not a neighbour: the ARP entry of an address nobody
#: answered for, or the row of the device itself.
_NOT_A_NEIGHBOUR = ("incomplete", "failed", "noarp")
#: Ports that are not a cable: the switch's own CPU, a drop, a flood.
_NOT_A_PORT = {"cpu", "router", "drop", "switch", "self", "all-members", "vlan"}


def normalize_mac(raw: str) -> str:
    """Any CLI spelling of a MAC as ``aa:bb:cc:dd:ee:ff``, or ""."""
    digits = re.sub(r"[^0-9A-Fa-f]", "", raw or "")
    if len(digits) != 12:
        return ""
    digits = digits.lower()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def _ip(raw: str) -> str:
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def parse_arp(output: str) -> list[dict[str, str]]:
    """``[{ip, mac}]`` out of any ARP listing: a row is a line with one IP
    and one MAC, whatever the columns around them. Works for the ten
    families above because every CLI prints those two the same way; a row
    marked incomplete or failed (no MAC anyway) is skipped, and so is a
    multicast or broadcast MAC."""
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in (output or "").splitlines():
        lowered = line.lower()
        if any(word in lowered for word in _NOT_A_NEIGHBOUR):
            continue
        mac_match = _MAC_RE.search(line)
        if not mac_match:
            continue
        mac = normalize_mac(mac_match.group(1))
        if not mac or mac == "ff:ff:ff:ff:ff:ff" or int(mac[:2], 16) & 1:
            continue
        ip = next((_ip(m.group(1)) for m in _IP_RE.finditer(line) if _ip(m.group(1))), "")
        if not ip or ip.startswith(("224.", "ff")):
            continue
        if (ip, mac) not in seen:
            seen.add((ip, mac))
            rows.append({"ip": ip, "mac": mac})
    return rows


# --- MAC tables, one reader per family --------------------------------------


def _row(mac: str, port: str, vlan: str = "") -> dict[str, str] | None:
    mac = normalize_mac(mac)
    port = (port or "").strip()
    if not mac or not port or port.lower() in _NOT_A_PORT or int(mac[:2], 16) & 1:
        return None
    if re.match(r"^(?:vlan|vlanif|loopback|lo)\d*$", port, re.IGNORECASE):
        # A routed interface of the switch itself (Dell lists its management
        # row there): nothing is cabled to it.
        return None
    return {"mac": mac, "ifindex": port, "vlan": vlan if vlan.isdigit() else ""}


_CISCO_MAC_RE = re.compile(r"^\s*(\d+|All)\s+((?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})\s+\S+\s+(\S+)")


def _cisco_like(output: str) -> list[dict[str, str]]:
    """IOS and Dell OS6: ``Vlan  Mac Address  Type  Ports``."""
    rows = []
    for line in output.splitlines():
        match = _CISCO_MAC_RE.match(line)
        if match:
            row = _row(match.group(2), match.group(3), match.group(1))
            if row:
                rows.append(row)
    return rows


_PROCURVE_RE = re.compile(r"^\s*([0-9A-Fa-f]{6}-[0-9A-Fa-f]{6})\s+(\S+)\s+(\d+)")


def _procurve(output: str) -> list[dict[str, str]]:
    """ProCurve / ArubaOS-Switch: ``MAC Address  Port  VLAN``."""
    rows = []
    for line in output.splitlines():
        match = _PROCURVE_RE.match(line)
        if match:
            row = _row(match.group(1), match.group(2), match.group(3))
            if row:
                rows.append(row)
    return rows


_HUAWEI_RE = re.compile(r"^\s*((?:[0-9A-Fa-f]{4}-){2}[0-9A-Fa-f]{4})\s+(\d+)\S*\s+(?:\S+\s+)?(\S+)\s+(\S+)")


def _huawei_like(output: str) -> list[dict[str, str]]:
    """VRP ``MAC Address  VLAN/VSI/BD  Learned-From  Type`` and Comware
    ``MAC Address  VLAN ID  State  Port/Nickname  Aging``: the MAC first,
    the VLAN second, and the port is the column that looks like one."""
    rows = []
    for line in output.splitlines():
        match = re.match(r"^\s*((?:[0-9A-Fa-f]{4}-){2}[0-9A-Fa-f]{4})\s+(\d+)\S*\s+(.*)$", line)
        if not match:
            continue
        rest = match.group(3).split()
        port = next((token for token in rest if _looks_like_port(token)), "")
        row = _row(match.group(1), port, match.group(2))
        if row:
            rows.append(row)
    return rows


_PORT_TOKEN_RE = re.compile(r"^(?:[A-Za-z]{1,3}[A-Za-z-]*\d+(?:[/:.]\d+)*(?:\.\d+)?|[A-Za-z]+-\d+/\d+/\d+(?:\.\d+)?|\d+/\d+(?:/\d+)?|ether\d+|sfp\S*\d+|wlan\d+|bridge\S*)$")


def _looks_like_port(token: str) -> bool:
    """Whether a token is an interface name and not a state word."""
    return bool(_PORT_TOKEN_RE.match(token)) and token.lower() not in ("learned", "dynamic", "static", "config")


def _junos(output: str) -> list[dict[str, str]]:
    """``show ethernet-switching table``, old and ELS layouts: the VLAN is
    a name (no number), the port is the token that looks like one after the
    MAC, with its ``.0`` unit dropped."""
    rows = []
    for line in output.splitlines():
        mac_match = _MAC_RE.search(line)
        if not mac_match:
            continue
        after = line[mac_match.end() :].split()
        port = next((token for token in after if _looks_like_port(token)), "")
        row = _row(mac_match.group(1), re.sub(r"\.0$", "", port))
        if row:
            rows.append(row)
    return rows


def _mikrotik(output: str) -> list[dict[str, str]]:
    """``/interface bridge host print``: flags, MAC, optional VID, port,
    bridge. Rows flagged ``L`` (local: the bridge's own MACs) are skipped."""
    rows = []
    for line in output.splitlines():
        mac_match = _MAC_RE.search(line)
        if not mac_match:
            continue
        flags = line[: mac_match.start()].split()
        if any("L" in flag for flag in flags[1:]) or (flags and "L" in flags[0] and not flags[0].isdigit()):
            continue
        after = line[mac_match.end() :].split()
        vlan = after[0] if after and after[0].isdigit() else ""
        rest = after[1:] if vlan else after
        row = _row(mac_match.group(1), rest[0] if rest else "", vlan)
        if row:
            rows.append(row)
    return rows


MAC_PARSERS: dict[str, Callable[[str], list[dict[str, str]]]] = {
    "cisco": _cisco_like,
    "dell": _cisco_like,
    "aruba": _procurve,
    "huawei": _huawei_like,
    "comware": _huawei_like,
    "junos": _junos,
    "mikrotik": _mikrotik,
}


def parse_mac_table(family: str, output: str) -> list[dict[str, str]]:
    """``[{mac, ifindex, vlan}]`` (``ifindex`` is the port name) for the
    family, or [] for one without a reader."""
    parser = MAC_PARSERS.get(family)
    if parser is None or not output:
        return []
    try:
        return parser(output)
    except Exception:  # noqa: BLE001 - a weird listing is an empty table, never a crash
        return []


def read_tables(family: str, ask: Callable[[str], str]) -> dict[str, Any]:
    """The ``arp`` and ``fdb`` of a device, through ``ask(command) -> output``
    (one more SSH order each, with the credential that got in). Only the
    keys with something in them; a family without orders gets nothing."""
    tables: dict[str, Any] = {}
    command = ARP_COMMANDS.get(family)
    if command:
        try:
            arp = parse_arp(ask(command))
        except Exception:  # noqa: BLE001
            arp = []
        if arp:
            tables["arp"] = arp
    command = MAC_COMMANDS.get(family)
    if command:
        try:
            fdb = parse_mac_table(family, ask(command))
        except Exception:  # noqa: BLE001
            fdb = []
        if fdb:
            tables["fdb"] = fdb
    return tables
