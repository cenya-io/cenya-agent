"""L3b: who is this server, asked without credentials.

SNMP, SSH and WinRM all need a secret. Most of a small business's servers have
none configured yet, and those hosts stayed as "responds to ping" in the tray.
This collector asks every live host the questions the protocols themselves
answer to anybody, read-only:

* **SMB (445) and RDP (3389)**: the first NTLM message of a login is a
  NEGOTIATE; the server's reply, the CHALLENGE, carries the NetBIOS and DNS
  names, the domain and the Windows version. We send the NEGOTIATE and read the
  CHALLENGE. **We never send the AUTHENTICATE message**, so the server never
  sees a failed logon: nothing lands in its security log and no account lockout
  counter moves.
* **SSH (22)**: only the banner line the server volunteers.
* **HTTPS (443, 8006, 8443)**: the TLS certificate (subject, SAN, issuer) and,
  to recognise a known admin panel, a ``GET /`` whose first 2 KB are checked
  against fixed strings. Only the *name* of the matched panel leaves the
  machine, never any of the HTML.

How it merges with the other collectors
---------------------------------------
The finding is ``kind="host"`` with the sweep's identity (MAC, else IP), so it
enriches the existing row. ``fingerprint`` (a new dict) is the source of truth
for what was seen; ``hostname`` and ``os`` are only convenience copies. The
server's ``merge_payload`` lets the *last* finding win for plain keys, so this
collector runs **before** SNMP/SSH/WinRM in ``RUN_ORDER``: whatever they know
about the host overwrites our hints within the same cycle. Its ``seen_by`` is
``fingerprint``, ranked as poor as the sweep, so on the server a richer source
is never downgraded by it. (Across cycles the inventory task runs every few
hours and no collector can see what the others said earlier; the server's
"a poorer source does not lower a richer one" rule covers ``hostname`` and
``seen_by``.)

``os`` is a hint, not a certainty: the NTLM version carries the Windows build,
which does not tell a Server from a client edition (hence names such as
"Windows 10 1809 / Server 2019").

* **NetBIOS (UDP 137), SSDP/UPnP (UDP 1900), mDNS (UDP 5353)**: one standard
  query each, unicast to the host. They name NAS boxes, printers, Macs and
  Samba machines that have no SNMP and no credentials (``fingerprint.netbios``,
  ``fingerprint.upnp``, ``fingerprint.mdns``). The UPnP description is only
  downloaded from the *same IP* that answered (never a LOCATION pointing
  elsewhere), over http, at most 64 KB.

``manufacturer``/``model``/``serial`` are deliberately NOT copied to the top
level of the payload: the server's ``merge_payload`` only protects ``seen_by``
and ``hostname`` from a poorer source, so a UPnP guess would overwrite what SNMP
or SSH had found. They live only inside ``fingerprint.upnp`` and ``.mdns``.

Silence is the rule: a closed port, a timeout or garbage on the wire adds
nothing and notes nothing (the server has no sentence for such notes).
"""

from __future__ import annotations

import http.client
import ipaddress
import os
import re
import socket
import ssl
import struct
import time
import uuid
from urllib.parse import urlsplit
from xml.etree import ElementTree
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from agent.collectors import register, tasking
from agent.collectors.base import Finding

TIMEOUT = 2.0
WORKERS = 30
SSH_BANNER_MAX = 200
HTTP_READ_MAX = 2048

PORT_SSH = 22
PORT_SMB = 445
PORT_RDP = 3389
PORT_HTTPS: tuple[int, ...] = (443, 8006, 8443)
PORTS: tuple[int, ...] = (PORT_SSH, PORT_SMB, PORT_RDP, *PORT_HTTPS)

# --- Windows build -> name ----------------------------------------------------------------

#: (major, minor, build) -> name. Easy to extend: one line per build. A build
#: does not tell Server from client, so shared builds name both.
WINDOWS_BUILDS: dict[tuple[int, int, int], str] = {
    (6, 1, 7601): "Windows 7 / Server 2008 R2",
    (6, 2, 9200): "Windows 8 / Server 2012",
    (6, 3, 9600): "Windows 8.1 / Server 2012 R2",
    (10, 0, 10240): "Windows 10 1507",
    (10, 0, 10586): "Windows 10 1511",
    (10, 0, 14393): "Windows 10 1607 / Server 2016",
    (10, 0, 15063): "Windows 10 1703",
    (10, 0, 16299): "Windows 10 1709",
    (10, 0, 17134): "Windows 10 1803",
    (10, 0, 17763): "Windows 10 1809 / Server 2019",
    (10, 0, 18362): "Windows 10 1903",
    (10, 0, 18363): "Windows 10 1909",
    (10, 0, 19041): "Windows 10 2004-22H2",
    (10, 0, 19042): "Windows 10 2004-22H2",
    (10, 0, 19043): "Windows 10 2004-22H2",
    (10, 0, 19044): "Windows 10 2004-22H2",
    (10, 0, 19045): "Windows 10 2004-22H2",
    (10, 0, 20348): "Windows Server 2022",
    (10, 0, 22000): "Windows 11 21H2",
    (10, 0, 22621): "Windows 11 22H2/23H2",
    (10, 0, 22631): "Windows 11 22H2/23H2",
    (10, 0, 26100): "Windows 11 24H2 / Server 2025",
}


def windows_name(version: str) -> str:
    """``"10.0.20348"`` -> ``"Windows Server 2022"``; unknown builds keep their number."""
    try:
        major, minor, build = (int(part) for part in version.split("."))
    except ValueError:
        return ""
    return WINDOWS_BUILDS.get((major, minor, build)) or f"Windows (build {major}.{minor}.{build})"


# --- NTLM ---------------------------------------------------------------------------------

NTLM_SIGNATURE = b"NTLMSSP\x00"
_NEGOTIATE_VERSION = 0x02000000
#: UNICODE | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXTENDED_SESSIONSECURITY | VERSION | 128 | 56
_NEGOTIATE_FLAGS = (
    0x00000001 | 0x00000004 | 0x00000200 | 0x00008000 | 0x00080000 | _NEGOTIATE_VERSION | 0x20000000 | 0x80000000
)

_AV_NAMES = {1: "nb_name", 2: "nb_domain", 3: "dns_name", 4: "dns_domain", 5: "dns_tree"}


def ntlm_negotiate() -> bytes:
    """The NTLMSSP NEGOTIATE message (type 1): no domain, no workstation, so it
    says nothing about this machine. Declared version 10.0.0 like a plain client."""
    version = struct.pack("<BBH3xB", 10, 0, 0, 15)
    return NTLM_SIGNATURE + struct.pack("<IIHHIHHI", 1, _NEGOTIATE_FLAGS, 0, 0, 0, 0, 0, 0) + version


def parse_ntlm_challenge(blob: bytes) -> dict[str, str]:
    """Names, domain and version out of an NTLMSSP CHALLENGE (type 2).

    Finds the signature anywhere in ``blob`` (it may sit inside an SMB2 reply
    or a SPNEGO/CredSSP wrapper). Returns only the keys that came, or ``{}`` for
    anything that is not a well-formed challenge. Never raises.
    """
    try:
        start = blob.find(NTLM_SIGNATURE)
        if start < 0:
            return {}
        msg = blob[start:]
        if struct.unpack_from("<I", msg, 8)[0] != 2:
            return {}
        flags = struct.unpack_from("<I", msg, 20)[0]
        found: dict[str, str] = {}
        if flags & _NEGOTIATE_VERSION and len(msg) >= 56:
            major, minor, build = struct.unpack_from("<BBH", msg, 48)
            if major and build:  # Samba and friends send zeros: no information
                found["os_version"] = f"{major}.{minor}.{build}"
        length, _max, offset = struct.unpack_from("<HHI", msg, 40)
        info = msg[offset : offset + length]
        position = 0
        while position + 4 <= len(info):
            av_id, av_len = struct.unpack_from("<HH", info, position)
            value = info[position + 4 : position + 4 + av_len]
            position += 4 + av_len
            if av_id == 0:  # MsvAvEOL
                break
            name = _AV_NAMES.get(av_id)
            if name:
                text = value.decode("utf-16-le", errors="replace").strip()
                if text:
                    found[name] = text
            # id 7 (MsvAvTimestamp) is skipped on purpose: it is a clock
            # reading, not an identity, and it is not reported.
        return found
    except (struct.error, ValueError):
        return {}


# --- DER helpers (just enough for an X.509 name and the SPNEGO / CredSSP wrappers) --------


def _der(tag: int, body: bytes) -> bytes:
    size = len(body)
    if size < 0x80:
        head = bytes([tag, size])
    elif size < 0x100:
        head = bytes([tag, 0x81, size])
    else:
        head = bytes([tag, 0x82]) + size.to_bytes(2, "big")
    return head + body


def _tlv(data: bytes, pos: int = 0) -> tuple[int, bytes, int]:
    """(tag, body, next position) of the element at ``pos``."""
    tag = data[pos]
    size = data[pos + 1]
    pos += 2
    if size & 0x80:
        count = size & 0x7F
        size = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    if pos + size > len(data):
        raise ValueError("truncated DER")
    return tag, data[pos : pos + size], pos + size


def _children(body: bytes) -> list[tuple[int, bytes]]:
    out, pos = [], 0
    while pos < len(body):
        tag, value, pos = _tlv(body, pos)
        out.append((tag, value))
    return out


_OID_CN = bytes.fromhex("550403")
_OID_SAN = bytes.fromhex("551d11")


def _name_cn(name_body: bytes) -> str:
    for _tag, rdn in _children(name_body):
        for _t, attribute in _children(rdn):
            parts = _children(attribute)
            if len(parts) == 2 and parts[0][1] == _OID_CN:
                return parts[1][1].decode("utf-8", errors="replace").strip()
    return ""


def parse_certificate(der: bytes) -> dict[str, Any]:
    """``{"cn", "san": [...], "issuer"}`` from a DER certificate; only keys
    that exist. The issuer is its common name. Never raises."""
    try:
        _tag, cert, _ = _tlv(der)
        _tag, tbs, _ = _tlv(cert)
        items = _children(tbs)
        if items and items[0][0] == 0xA0:  # explicit version
            items = items[1:]
        # serial, signature algorithm, issuer, validity, subject, spki, ...
        issuer = _name_cn(items[2][1])
        subject = _name_cn(items[4][1])
        san: list[str] = []
        for tag, value in items[6:]:
            if tag != 0xA3:
                continue
            _t, extensions, _ = _tlv(value)
            for _t2, extension in _children(extensions):
                fields = _children(extension)
                if fields and fields[0][1] == _OID_SAN:
                    _t3, general, _ = _tlv(fields[-1][1])
                    san = [v.decode("ascii", errors="replace") for t, v in _children(general) if t == 0x82][:20]
        found: dict[str, Any] = {}
        if subject:
            found["cn"] = subject
        if san:
            found["san"] = san
        if issuer:
            found["issuer"] = issuer
        return found
    except (ValueError, IndexError):
        return {}


# --- Panels and SSH banners ---------------------------------------------------------------

#: (needle, name), first match wins. The needle is looked for, lower-cased, in
#: the page title and in the certificate's subject and issuer.
PANELS: tuple[tuple[str, str], ...] = (
    ("proxmox", "Proxmox VE"),
    ("vmware esxi", "VMware ESXi"),
    ("idrac", "iDRAC"),
    ("integrated dell remote access", "iDRAC"),
    ("integrated lights-out", "iLO"),
    ("synology", "Synology DSM"),
    ("diskstation", "Synology DSM"),
    ("qnap", "QNAP"),
    ("truenas", "TrueNAS"),
    ("unifi", "UniFi"),
)

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def recognise_panel(*texts: str) -> str:
    """The known panel the given strings (title, cert fields) point to, or ``""``."""
    haystack = " ".join(texts).lower()
    for needle, name in PANELS:
        if needle in haystack:
            return name
    return ""


def page_title(html: bytes) -> str:
    match = _TITLE.search(html)
    return match.group(1).decode("utf-8", errors="replace").strip()[:200] if match else ""


_DISTROS = ("Ubuntu", "Debian", "FreeBSD", "Raspbian", "OpenBSD", "NetBSD", "Fedora", "CentOS", "Alpine")


def parse_ssh_banner(line: str) -> dict[str, str]:
    """``{"ssh_banner", "distro"}`` from the first line a server sends."""
    line = line.strip()[:SSH_BANNER_MAX]
    if not line.startswith("SSH-"):
        return {}
    found = {"ssh_banner": line}
    for distro in _DISTROS:
        if distro.lower() in line.lower():
            found["distro"] = distro
            break
    return found


# --- Probes (each: one attempt, short timeout, never raises) ------------------------------


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise OSError("closed")
        data += chunk
    return data


def _smb2_header(command: int, message_id: int) -> bytes:
    # StructureSize, CreditCharge, Status, Command, CreditRequest, Flags,
    # NextCommand, MessageId, Reserved, TreeId, SessionId, then a zero signature.
    return b"\xfeSMB" + struct.pack("<HHIHHIIQIIQ", 64, 1 if message_id else 0, 0, command, 1, 0, 0, message_id, 0, 0, 0) + b"\x00" * 16


def _netbios(packet: bytes) -> bytes:
    return b"\x00" + len(packet).to_bytes(3, "big") + packet


def _read_netbios(sock: socket.socket) -> bytes:
    size = int.from_bytes(_recv_exact(sock, 4)[1:], "big")
    if size > 65536:
        raise OSError("absurd length")
    return _recv_exact(sock, size)


def _spnego_init(ntlm: bytes) -> bytes:
    """NegTokenInit offering NTLM: what a Windows client puts in the first
    SESSION_SETUP, accepted by Windows and Samba alike."""
    ntlm_oid = _der(0x06, bytes.fromhex("2b06010401823702020a"))
    mech_types = _der(0xA0, _der(0x30, ntlm_oid))
    mech_token = _der(0xA2, _der(0x04, ntlm))
    init = _der(0xA0, _der(0x30, mech_types + mech_token))
    return _der(0x60, _der(0x06, bytes.fromhex("2b0601050502")) + init)


def _smb_negotiate_body() -> bytes:
    dialects = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]
    fixed = 64 + 36 + 2 * len(dialects)
    padding = (-fixed) % 8
    # 3.1.1 obliges the client to send a pre-auth integrity context.
    preauth = struct.pack("<HHH", 1, 32, 0x0001) + os.urandom(32)
    context = struct.pack("<HHI", 1, len(preauth), 0) + preauth
    body = struct.pack("<HHHHI", 36, len(dialects), 1, 0, 0x7F) + uuid.uuid4().bytes
    body += struct.pack("<IHH", fixed + padding, 1, 0)
    return body + b"".join(struct.pack("<H", d) for d in dialects) + b"\x00" * padding + context


def probe_smb(ip: str, port: int = PORT_SMB, timeout: float = TIMEOUT) -> dict[str, str]:
    """SMB2 NEGOTIATE, then SESSION_SETUP with only an NTLM NEGOTIATE inside.

    The server answers STATUS_MORE_PROCESSING_REQUIRED plus the CHALLENGE and we
    close: no AUTHENTICATE is ever sent.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_netbios(_smb2_header(0, 0) + _smb_negotiate_body()))
            reply = _read_netbios(sock)
            if reply[:4] != b"\xfeSMB" or struct.unpack_from("<I", reply, 8)[0] != 0:
                return {}
            token = _spnego_init(ntlm_negotiate())
            setup = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 64 + 24, len(token), 0) + token
            sock.sendall(_netbios(_smb2_header(1, 1) + setup))
            reply = _read_netbios(sock)
            if reply[:4] != b"\xfeSMB" or struct.unpack_from("<I", reply, 8)[0] != 0xC0000016:
                return {}
            return parse_ntlm_challenge(reply)
    except (OSError, struct.error, ValueError):
        return {}


def _tls_context() -> ssl.SSLContext:
    """No verification on purpose: this reads what a server presents, it does
    not trust it nor send it anything that matters."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        pass
    return context


def probe_rdp(ip: str, port: int = PORT_RDP, timeout: float = TIMEOUT) -> dict[str, str]:
    """X.224 request for CredSSP, TLS, then a TSRequest holding an NTLM NEGOTIATE.

    Returns the same fields as SMB when the server does NLA; otherwise just the
    certificate's common name (``cert_cn``), if TLS was negotiated at all.
    """
    negotiation = struct.pack("<BBHI", 1, 0, 8, 3)  # RDP_NEG_REQ: SSL | HYBRID
    x224 = bytes([6 + len(negotiation), 0xE0, 0, 0, 0, 0, 0]) + negotiation
    packet = b"\x03\x00" + (4 + len(x224)).to_bytes(2, "big") + x224
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            raw.sendall(packet)
            reply = _recv_exact(raw, int.from_bytes(_recv_exact(raw, 4)[2:4], "big") - 4)
            # X.224 Connection Confirm carrying an RDP_NEG_RSP (type 2).
            if len(reply) < 15 or reply[1] != 0xD0 or reply[7] != 2:
                return {}
            selected = struct.unpack_from("<I", reply, 11)[0]
            if not selected & 0b11:  # plain RDP security: no TLS to read
                return {}
            with _tls_context().wrap_socket(raw, server_hostname=None) as tls:
                tls.settimeout(timeout)
                found: dict[str, str] = {}
                cert = parse_certificate(tls.getpeercert(binary_form=True) or b"")
                if cert.get("cn"):
                    found["cert_cn"] = cert["cn"]
                if selected & 2:
                    token = _der(0x30, _der(0x30, _der(0xA0, _der(0x04, ntlm_negotiate()))))
                    tls.sendall(_der(0x30, _der(0xA0, b"\x02\x01\x06") + _der(0xA1, token)))
                    found.update(parse_ntlm_challenge(tls.recv(8192)))
                return found
    except (OSError, ssl.SSLError, struct.error, ValueError):
        return {}


def probe_ssh(ip: str, port: int = PORT_SSH, timeout: float = TIMEOUT) -> dict[str, str]:
    """The banner line, read and nothing else sent: we close without a key exchange."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = b""
            while b"\n" not in data and len(data) < 512:
                chunk = sock.recv(512)
                if not chunk:
                    break
                data += chunk
        return parse_ssh_banner(data.split(b"\n", 1)[0].decode("utf-8", errors="replace"))
    except OSError:
        return {}


def probe_https(ip: str, port: int, timeout: float = TIMEOUT) -> dict[str, Any]:
    """Certificate fields, plus ``panel`` when a known admin panel is recognised."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with _tls_context().wrap_socket(raw, server_hostname=None) as tls:
                cert = parse_certificate(tls.getpeercert(binary_form=True) or b"")
                title = ""
                try:
                    tls.sendall(f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: cenya-agent\r\nConnection: close\r\n\r\n".encode())
                    data = b""
                    while len(data) < HTTP_READ_MAX:
                        chunk = tls.recv(HTTP_READ_MAX - len(data))
                        if not chunk:
                            break
                        data += chunk
                    title = page_title(data)
                except (OSError, ssl.SSLError):
                    pass
        found: dict[str, Any] = dict(cert)
        panel = recognise_panel(title, cert.get("cn", ""), cert.get("issuer", ""))
        if panel:
            found["panel"] = panel
        return found
    except (OSError, ssl.SSLError, ValueError):
        return {}


# --- UDP probes: NetBIOS, SSDP/UPnP, mDNS ---------------------------------------------------
#
# Three more questions a host answers to anybody on the LAN, aimed at what has no
# SNMP and no credentials: NAS boxes, printers, Macs, Samba and old Windows.
# Same rules as above: read-only, one attempt per host, ~2 s, silence on failure.
# The UDP "ports" double as the keys of the per-host answers dict, next to the
# TCP ports (no TCP service is probed on them here, so there is no clash).

PORT_NETBIOS = 137
PORT_SSDP = 1900
PORT_MDNS = 5353
UDP_PORTS: tuple[int, ...] = (PORT_NETBIOS, PORT_SSDP, PORT_MDNS)

UPNP_XML_MAX = 64 * 1024
MDNS_SERVICES_MAX = 20
_TEXT_MAX = 200
_DNS_MAX_HOPS = 16


def _clip(text: str) -> str:
    return text.replace("\x00", "").strip()[:_TEXT_MAX]


def _udp_ask(ip: str, port: int, packets: list[bytes], timeout: float, expected: int = 1) -> list[bytes]:
    """Send ``packets`` to ``ip:port`` from one socket and collect up to
    ``expected`` datagrams that really come from that address (anything else on
    the wire is ignored) before ``timeout`` seconds pass in total."""
    replies: list[bytes] = []
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            for packet in packets:
                sock.sendto(packet, (ip, port))
            deadline = time.monotonic() + timeout
            while len(replies) < expected:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                sock.settimeout(remaining)
                data, sender = sock.recvfrom(8192)
                if sender[0] == ip:
                    replies.append(data)
    except OSError:  # includes timeout and ICMP "port unreachable" resets
        pass
    return replies


# DNS wire format, just enough for NBSTAT and mDNS.


def dns_read_name(data: bytes, pos: int) -> tuple[str, int]:
    """A (possibly compressed) domain name at ``pos`` -> ``(name, next position)``.

    ``next position`` is where the record continues in the *original* stream,
    i.e. just after the first pointer. A pointer that loops, or too many hops,
    raises ``ValueError``: a hostile responder cannot make us spin.
    """
    labels: list[str] = []
    end = -1
    hops = 0
    while True:
        length = data[pos]
        if length & 0xC0 == 0xC0:
            hops += 1
            if hops > _DNS_MAX_HOPS:
                raise ValueError("compression loop")
            if end < 0:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | data[pos + 1]
            continue
        if length & 0xC0:
            raise ValueError("bad label")
        pos += 1
        if length == 0:
            return ".".join(labels), end if end >= 0 else pos
        if pos + length > len(data):
            raise ValueError("truncated label")
        labels.append(data[pos : pos + length].decode("utf-8", errors="replace"))
        pos += length
        if len(labels) > 127:
            raise ValueError("name too long")


def dns_encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("utf-8")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def dns_records(data: bytes) -> list[tuple[str, int, int, int]]:
    """Every record of a DNS message as ``(owner, type, rdata offset, rdata length)``.
    Questions are skipped. Raises ``ValueError``/``IndexError``/``struct.error`` on junk."""
    _ident, _flags, questions, answers, authority, additional = struct.unpack_from(">HHHHHH", data, 0)
    pos = 12
    for _ in range(questions):
        _name, pos = dns_read_name(data, pos)
        pos += 4
    records = []
    for _ in range(min(answers + authority + additional, 100)):
        owner, pos = dns_read_name(data, pos)
        rtype, _cls, _ttl, rdlen = struct.unpack_from(">HHIH", data, pos)
        pos += 10
        if pos + rdlen > len(data):
            raise ValueError("truncated record")
        records.append((owner, rtype, pos, rdlen))
        pos += rdlen
    return records


# NetBIOS Name Service (RFC 1002): NBSTAT ("node status") query for "*".

_NBSTAT_ID = 0x4E42


def netbios_query() -> bytes:
    """NBSTAT for the wildcard name: "*" padded with NULs to 16 bytes, first-level
    encoded (each nibble becomes a letter A-P)."""
    raw = b"*" + b"\x00" * 15
    encoded = bytes(65 + nibble for byte in raw for nibble in (byte >> 4, byte & 0x0F))
    return struct.pack(">HHHHHH", _NBSTAT_ID, 0, 1, 0, 0, 0) + b"\x20" + encoded + b"\x00" + struct.pack(">HH", 0x21, 1)


def parse_nbstat(data: bytes) -> dict[str, str]:
    """``{"name", "workgroup", "mac"}`` from an NBSTAT response; only keys that came.

    ``name`` is the unique name with suffix 0x00 (the workstation service),
    ``workgroup`` the *group* name with suffix 0x00. An all-zero MAC (Samba, some
    NAS) is no information and is dropped. Never raises.
    """
    try:
        ident, flags = struct.unpack_from(">HH", data, 0)
        if ident != _NBSTAT_ID or not flags & 0x8000:
            return {}
        questions, answers = struct.unpack_from(">HH", data, 4)
        if answers < 1:
            return {}
        pos = 12
        for _ in range(questions):
            _name, pos = dns_read_name(data, pos)
            pos += 4
        _name, pos = dns_read_name(data, pos)
        rtype = struct.unpack_from(">H", data, pos)[0]
        if rtype != 0x21:
            return {}
        pos += 10
        count = data[pos]
        pos += 1
        found: dict[str, str] = {}
        for _ in range(count):
            raw, suffix, name_flags = struct.unpack_from(">15sBH", data, pos)
            pos += 18
            if suffix != 0:
                continue
            text = _clip(raw.decode("ascii", errors="replace"))
            if not text:
                continue
            if name_flags & 0x8000:
                found.setdefault("workgroup", text)
            else:
                found.setdefault("name", text)
        mac = data[pos : pos + 6]
        if len(mac) == 6 and any(mac):
            found["mac"] = ":".join(f"{byte:02x}" for byte in mac)
        return found
    except (struct.error, IndexError, ValueError):
        return {}


def probe_netbios(ip: str, port: int = PORT_NETBIOS, timeout: float = TIMEOUT) -> dict[str, str]:
    for reply in _udp_ask(ip, port, [netbios_query()], timeout):
        found = parse_nbstat(reply)
        if found:
            return found
    return {}


# SSDP / UPnP: unicast M-SEARCH, then the device description the host points to.


def ssdp_search(ip: str) -> bytes:
    host = f"[{ip}]" if ":" in ip else ip
    return (
        f'M-SEARCH * HTTP/1.1\r\nHOST: {host}:{PORT_SSDP}\r\nMAN: "ssdp:discover"\r\n'
        "MX: 1\r\nST: upnp:rootdevice\r\n\r\n"
    ).encode()


def parse_ssdp_response(data: bytes) -> dict[str, str]:
    """Headers (lower-case names) of an SSDP ``HTTP/1.1 200 OK`` reply, or ``{}``."""
    lines = data[:4096].decode("utf-8", errors="replace").split("\r\n")
    if not lines[0].startswith("HTTP/1.") or " 200" not in lines[0]:
        return {}
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers.setdefault(name.strip().lower(), value.strip())
    return headers


def same_host_location(location: str, ip: str) -> tuple[int, str] | None:
    """``(port, path)`` of a LOCATION URL, but only when it is plain http and
    points at ``ip`` itself. The responder is untrusted: a LOCATION aimed at any
    other address would make the agent fetch arbitrary URLs inside the customer's
    network on a stranger's say-so (SSRF), so it is refused, not followed."""
    try:
        parts = urlsplit(location)
        if parts.scheme != "http" or not parts.hostname:
            return None
        if ipaddress.ip_address(parts.hostname) != ipaddress.ip_address(ip):
            return None
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        return parts.port or 80, path
    except ValueError:
        return None


def parse_upnp_description(xml: bytes) -> dict[str, str]:
    """Fields of the first ``<device>`` of a UPnP description; only keys present.

    DTDs and entities are refused outright: an entity-expansion bomb fits in 64 KB.
    """
    upper = xml.upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        return {}
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError:
        return {}

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    device = next((el for el in root.iter() if local(el.tag) == "device"), None)
    if device is None:
        return {}
    wanted = {
        "friendlyName": "friendly_name",
        "manufacturer": "manufacturer",
        "modelName": "model",
        "modelNumber": "model_number",
        "serialNumber": "serial",
        "deviceType": "device_type",
    }
    found: dict[str, str] = {}
    for child in device:
        key = wanted.get(local(child.tag))
        text = _clip(child.text or "")
        if key and text and key not in found:
            found[key] = text
    return found


def _fetch_description(ip: str, port: int, path: str, timeout: float) -> bytes:
    """GET of the description: no redirects followed, 64 KB at most (more -> nothing)."""
    conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={"User-Agent": "cenya-agent", "Connection": "close"})
        response = conn.getresponse()
        if response.status != 200:
            return b""
        data = response.read(UPNP_XML_MAX + 1)
        return data if len(data) <= UPNP_XML_MAX else b""
    finally:
        conn.close()


def probe_ssdp(ip: str, port: int = PORT_SSDP, timeout: float = TIMEOUT) -> dict[str, str]:
    """M-SEARCH to the host; if it answers with a LOCATION on its own address,
    read its description. Without a usable description there is nothing to report."""
    try:
        for reply in _udp_ask(ip, port, [ssdp_search(ip)], timeout):
            target = same_host_location(parse_ssdp_response(reply).get("location", ""), ip)
            if target is None:
                continue
            found = parse_upnp_description(_fetch_description(ip, target[0], target[1], timeout))
            if found:
                return found
    except (OSError, ValueError, http.client.HTTPException):
        pass
    return {}


# mDNS / DNS-SD (RFC 6762/6763): a unicast question straight to the host's port 5353.

MDNS_QUESTIONS = ("_device-info._tcp.local", "_workstation._tcp.local", "_services._dns-sd._udp.local")


def mdns_query(name: str, ident: int) -> bytes:
    return struct.pack(">HHHHHH", ident, 0, 1, 0, 0, 0) + dns_encode_name(name) + struct.pack(">HH", 12, 1)


def parse_mdns(packets: list[bytes]) -> dict[str, Any]:
    """``{"model", "hostname", "services"}`` out of the responses; only keys that came.

    * ``model``: the ``model=`` entry of the TXT record under ``_device-info._tcp``
      (Apple, avahi and Synology publish it).
    * ``hostname``: the SRV target, else the ``_workstation`` instance (avahi
      writes ``host [mac]``), else the ``_device-info`` instance; ``.local`` cut.
    * ``services``: the service types listed under ``_services._dns-sd._udp``
      (``_smb._tcp.local`` -> ``smb``), at most ``MDNS_SERVICES_MAX``.
    Junk packets are skipped one by one; never raises.
    """
    model = ""
    targets: list[str] = []
    workstation = ""
    device_info = ""
    services: list[str] = []
    for data in packets:
        try:
            for owner, rtype, offset, length in dns_records(data):
                low = owner.lower()
                if rtype == 12:  # PTR
                    target, _ = dns_read_name(data, offset)
                    if low == "_services._dns-sd._udp.local":
                        service = _clip(target.split(".", 1)[0].lstrip("_"))
                        if service and service not in services:
                            services.append(service)
                    elif low.endswith("_workstation._tcp.local") and not workstation:
                        workstation = target.split("._workstation", 1)[0]
                    elif low.endswith("_device-info._tcp.local") and not device_info:
                        device_info = target.split("._device-info", 1)[0]
                elif rtype == 16 and low.endswith("_device-info._tcp.local"):  # TXT
                    rdata = data[offset : offset + length]
                    position = 0
                    while position < len(rdata):
                        size = rdata[position]
                        entry = rdata[position + 1 : position + 1 + size].decode("utf-8", errors="replace")
                        position += 1 + size
                        if entry.lower().startswith("model=") and not model:
                            model = _clip(entry[6:])
                    if not device_info:
                        device_info = owner.split("._device-info", 1)[0]
                elif rtype == 33 and length >= 7:  # SRV: priority, weight, port, target
                    target, _ = dns_read_name(data, offset + 6)
                    targets.append(target)
        except (struct.error, IndexError, ValueError):
            continue
    hostname = ""
    for candidate in (*targets, workstation.split(" [", 1)[0], device_info):
        candidate = _clip(candidate)
        if candidate.lower().endswith(".local"):
            candidate = candidate[: -len(".local")]
        if candidate:
            hostname = candidate
            break
    found: dict[str, Any] = {}
    if model:
        found["model"] = model
    if hostname:
        found["hostname"] = hostname
    if services:
        found["services"] = services[:MDNS_SERVICES_MAX]
    return found


def probe_mdns(ip: str, port: int = PORT_MDNS, timeout: float = TIMEOUT) -> dict[str, Any]:
    queries = [mdns_query(name, index + 1) for index, name in enumerate(MDNS_QUESTIONS)]
    return parse_mdns(_udp_ask(ip, port, queries, timeout, expected=len(queries)))


# --- Assembly -----------------------------------------------------------------------------

_NAME_KEYS = ("nb_name", "nb_domain", "dns_name", "dns_domain", "dns_tree", "os_version")


def _probe(ip: str, port: int) -> tuple[str, int, Any]:
    try:
        if port == PORT_SMB:
            return ip, port, probe_smb(ip)
        if port == PORT_RDP:
            return ip, port, probe_rdp(ip)
        if port == PORT_SSH:
            return ip, port, probe_ssh(ip)
        if port == PORT_NETBIOS:
            return ip, port, probe_netbios(ip)
        if port == PORT_SSDP:
            return ip, port, probe_ssdp(ip)
        if port == PORT_MDNS:
            return ip, port, probe_mdns(ip)
        return ip, port, probe_https(ip, port)
    except Exception:  # noqa: BLE001 - a probe never costs the run
        return ip, port, {}


def assemble(answers: dict[int, Any]) -> tuple[dict[str, Any], str, str]:
    """``(fingerprint, hostname, os)`` from one host's probe answers by port.

    The hostname is the NetBIOS name (short, what WinRM reports too) and only
    falls back to the DNS computer name. Keys without a value are never emitted.
    """
    fingerprint: dict[str, Any] = {}
    windows = ""
    hostname = ""
    for key, port in (("smb", PORT_SMB), ("rdp", PORT_RDP)):
        raw = answers.get(port) or {}
        block = {name: raw[name] for name in _NAME_KEYS if raw.get(name)}
        if raw.get("cert_cn"):
            block["cert_cn"] = raw["cert_cn"]
        if block:
            fingerprint[key] = block
        if raw.get("os_version") and not windows:
            windows = windows_name(raw["os_version"])
        hostname = hostname or raw.get("nb_name", "") or raw.get("dns_name", "")
    ssh = answers.get(PORT_SSH) or {}
    if ssh.get("ssh_banner"):
        fingerprint["ssh_banner"] = ssh["ssh_banner"]
    for port in PORT_HTTPS:
        raw = answers.get(port) or {}
        tls = {name: raw[name] for name in ("cn", "san", "issuer") if raw.get(name)}
        if tls and "tls" not in fingerprint:
            fingerprint["tls"] = tls
        if raw.get("panel") and "panel" not in fingerprint:
            fingerprint["panel"] = raw["panel"]
    for key, port, names in (
        ("netbios", PORT_NETBIOS, ("name", "workgroup", "mac")),
        ("upnp", PORT_SSDP, ("manufacturer", "model", "model_number", "serial", "friendly_name", "device_type")),
        ("mdns", PORT_MDNS, ("model", "hostname", "services")),
    ):
        raw = answers.get(port) or {}
        block = {name: raw[name] for name in names if raw.get(name)}
        if block:
            fingerprint[key] = block
    # The weakest hostname hints: only when no stronger probe gave one.
    hostname = hostname or fingerprint.get("netbios", {}).get("name", "") or fingerprint.get("mdns", {}).get("hostname", "")
    return fingerprint, hostname, windows or ssh.get("distro", "")


@register
class FingerprintCollector:
    name = "fingerprint"

    def collect(self, ctx: dict) -> list[Finding]:
        if "hosts" not in ctx:
            # Same dependency as SNMP/SSH/WinRM: no sweep, nobody to ask. No
            # note: the server has no sentence for a code it does not know.
            return []
        by_ip = {
            host["ip"]: host.get("mac", "")
            for host in ctx["hosts"] or []
            if host.get("ip") and tasking.wanted(ctx, host["ip"])
        }
        if not by_ip:
            return []
        jobs = [(ip, port) for ip in by_ip for port in (*PORTS, *UDP_PORTS)]
        progress = tasking.Progress(ctx, self.name, len(jobs))

        def run(job: tuple[str, int]) -> tuple[str, int, Any]:
            try:
                return _probe(*job)
            finally:
                progress.tick()

        answers: dict[str, dict[int, Any]] = {}
        try:
            with ThreadPoolExecutor(max_workers=tasking.workers(ctx, "ping", WORKERS)) as pool:
                for ip, port, result in pool.map(run, jobs):
                    answers.setdefault(ip, {})[port] = result
        except Exception:  # noqa: BLE001
            return []

        findings: list[Finding] = []
        for ip, mac in by_ip.items():
            fingerprint, hostname, os_hint = assemble(answers.get(ip, {}))
            if not fingerprint:
                continue
            payload: dict[str, Any] = {"ip": ip, "seen_by": "fingerprint", "fingerprint": fingerprint}
            for key, value in (("mac", mac), ("hostname", hostname), ("os", os_hint)):
                if value:
                    payload[key] = value
            findings.append(Finding(kind="host", identity={"mac": mac} if mac else {"ip": ip}, payload=payload))
        return findings
