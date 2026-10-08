"""Active Directory, read with the identity of the machine itself.

A Windows server joined to a domain already knows, for every other computer of
the domain, the exact operating system ("Windows Server 2022 Standard"), its
version and its DNS name. The credential-less fingerprint can only guess the
Windows *build* from an NTLM challenge; the directory states the edition. This
collector asks for it once per cycle.

No credentials, no libraries
----------------------------
The agent runs as LocalSystem. On the network LocalSystem authenticates as the
machine account (``DOMAIN\\HOST$``), and "Authenticated Users" may read computer
objects. So a plain ADSI query from PowerShell works without any secret being
configured, requested or sent. **Nothing is written to the directory**: it is a
single LDAP search.

Silence is the rule
-------------------
Not Windows, no PowerShell, the machine is not in a domain, the domain
controller does not answer, or the output is not the JSON we expect: the
collector returns ``[]`` and notes nothing. The server has a sentence for each
note *code* and this one has none, so there is nothing to say; and a workgroup
machine is the normal case, not a problem.

The PowerShell script is a constant. No value read from the directory is ever
interpolated into a command line: the directory is data, never code.

How it merges
-------------
The directory gives no IP. Each DNS name is resolved (IPv4 only) and a finding
is emitted **only when that IP is alive in the sweep** (``ctx["hosts"]``):
retired computers that still sit in AD must not flood the review tray. The
finding carries the sweep's own identity (MAC, else IP) so it enriches the row
the sweep made. ``seen_by`` is ``directory``; ``os`` and ``hostname`` are
convenience copies the server will not let a poorer source lower. It runs right
after ``fingerprint`` so the exact operating system overwrites the build-based
guess, and before SNMP/SSH/WinRM so whatever those say about the host wins.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

from agent.collectors import register, tasking
from agent.collectors.base import Finding

POWERSHELL_TIMEOUT_SECONDS = 60
#: Objects asked of the directory and bytes accepted back. A domain with more
#: than this is not a small business; better a bounded answer than an unbounded one.
MAX_OBJECTS = 5000
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
#: ``lastLogonTimestamp`` is replicated only every ~14 days, so 60 days is
#: "has not been seen in a long time" with a wide margin for that lag.
STALE_AFTER = timedelta(days=60)
DNS_TIMEOUT_SECONDS = 3.0
WORKERS = 20

UAC_ACCOUNTDISABLE = 0x2
UAC_SERVER_TRUST_ACCOUNT = 0x2000  # 8192: the account of a domain controller

#: SPN prefix (lower case) -> role. Short and stable on purpose.
ROLE_SPNS: tuple[tuple[str, str], ...] = (
    ("mssqlsvc/", "sql"),
    ("exchangemdb/", "exchange"),
    ("exchangerfr/", "exchange"),
    ("microsoft virtual system migration service/", "hyperv"),
    ("hyper-v replica service/", "hyperv"),
)
ROLE_ORDER = ("dc", "sql", "exchange", "hyperv")

_FILETIME_UNIX_EPOCH = 116444736000000000  # 1970-01-01 in 100 ns since 1601

#: Constant script. Writes ``[]`` when the machine is not in a domain. Only the
#: SPNs that decide a role are emitted, which keeps a domain controller's long
#: SPN list out of the output.
POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try { [void][System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain() } catch { '[]'; exit 0 }
$searcher = [adsisearcher]'(&(objectCategory=computer)(!(userAccountControl:1.1.2:=2)))'
$searcher.PageSize = 500
$searcher.SizeLimit = 5000
foreach ($p in 'name','dnshostname','operatingsystem','operatingsystemversion','lastlogontimestamp','useraccountcontrol','serviceprincipalname') { [void]$searcher.PropertiesToLoad.Add($p) }
$roleSpn = '^(MSSQLSvc|exchangeMDB|exchangeRFR|Microsoft Virtual System Migration Service|Hyper-V Replica Service)/'
$rows = New-Object System.Collections.ArrayList
foreach ($r in $searcher.FindAll()) {
  if ($rows.Count -ge 5000) { break }
  $spn = @($r.Properties['serviceprincipalname'] | Where-Object { $_ -match $roleSpn } | Select-Object -First 20)
  [void]$rows.Add([ordered]@{
    name = [string]($r.Properties['name'] | Select-Object -First 1)
    dnshostname = [string]($r.Properties['dnshostname'] | Select-Object -First 1)
    operatingsystem = [string]($r.Properties['operatingsystem'] | Select-Object -First 1)
    operatingsystemversion = [string]($r.Properties['operatingsystemversion'] | Select-Object -First 1)
    lastlogontimestamp = [int64]($r.Properties['lastlogontimestamp'] | Select-Object -First 1)
    useraccountcontrol = [int64]($r.Properties['useraccountcontrol'] | Select-Object -First 1)
    spn = $spn
  })
}
ConvertTo-Json -InputObject @($rows) -Compress -Depth 4
"""


def filetime_to_datetime(value: Any) -> datetime | None:
    """A Windows FILETIME (100 ns ticks since 1601-01-01 UTC) as an aware UTC
    datetime, or ``None`` for zero ("never"), negatives, junk and overflow."""
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return None
    if ticks <= 0 or ticks >= 0x7FFFFFFFFFFFFFFF:
        return None
    try:
        return datetime.fromtimestamp((ticks - _FILETIME_UNIX_EPOCH) / 1e7, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def roles_for(uac: int, spns: list[str]) -> list[str]:
    """The short, stable role list deduced from the account flags and SPNs."""
    roles: set[str] = set()
    if uac & UAC_SERVER_TRUST_ACCOUNT:
        roles.add("dc")
    lowered = [spn.lower() for spn in spns]
    for prefix, role in ROLE_SPNS:
        if any(spn.startswith(prefix) for spn in lowered):
            roles.add(role)
    return sorted(roles, key=ROLE_ORDER.index)


def _powershell_path() -> str | None:
    found = shutil.which("powershell") or shutil.which("powershell.exe")
    if found:
        return found
    root = os.environ.get("SystemRoot", r"C:\Windows")
    candidate = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    return candidate if os.path.isfile(candidate) else None


def run_powershell(script: str = POWERSHELL_SCRIPT, timeout: float = POWERSHELL_TIMEOUT_SECONDS) -> str | None:
    """Run ``script`` and return its stdout, or ``None`` for anything that is
    not a clean exit. The script travels as -EncodedCommand (UTF-16LE base64)
    so quoting can never matter; it is a constant anyway."""
    binary = _powershell_path()
    if not binary:
        return None
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        result = subprocess.run(
            [binary, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if result.returncode != 0 or len(result.stdout) > MAX_OUTPUT_BYTES:
        return None
    return result.stdout.decode("utf-8-sig", errors="replace")


def parse_computers(raw: str | None, now: datetime | None = None) -> list[dict[str, Any]]:
    """The usable computers out of the script's JSON, newest logon first.

    Defends in Python against what LDAP should already have filtered
    (disabled accounts) and applies the rest: stale logons, and objects with
    neither an operating system nor a DNS name. Bad JSON gives ``[]``.
    """
    if not raw or not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []
    now = now or datetime.now(timezone.utc)
    computers: list[dict[str, Any]] = []
    for row in data[:MAX_OBJECTS]:
        if not isinstance(row, dict):
            continue
        try:
            uac = int(row.get("useraccountcontrol") or 0)
        except (TypeError, ValueError):
            uac = 0
        if uac & UAC_ACCOUNTDISABLE:
            continue
        name = str(row.get("name") or "").strip()
        dns_name = str(row.get("dnshostname") or "").strip().lower()
        os_name = str(row.get("operatingsystem") or "").strip()
        if not os_name and not dns_name:
            continue
        last = filetime_to_datetime(row.get("lastlogontimestamp"))
        if last is not None and now - last > STALE_AFTER:
            continue
        spns = row.get("spn") or []
        if isinstance(spns, str):
            spns = [spns]
        computers.append(
            {
                "name": name,
                "dns_name": dns_name,
                "os": os_name,
                "os_version": str(row.get("operatingsystemversion") or "").strip(),
                "last_logon": last,
                "roles": roles_for(uac, [spn for spn in spns if isinstance(spn, str)]),
            }
        )
    computers.sort(key=lambda c: c["last_logon"] or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return computers


def resolve_ipv4(name: str, timeout: float = DNS_TIMEOUT_SECONDS) -> str:
    """The first IPv4 address of ``name``, or "" -- never waiting longer than
    ``timeout`` (``getaddrinfo`` has no timeout of its own)."""
    if not name:
        return ""
    answer: dict[str, str] = {}

    def look_up() -> None:
        try:
            for info in socket.getaddrinfo(name, None, socket.AF_INET):
                answer["ip"] = str(info[4][0])
                return
        except (OSError, UnicodeError):
            pass

    worker = threading.Thread(target=look_up, daemon=True)
    worker.start()
    worker.join(timeout)
    ip = answer.get("ip", "")
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return ""
    return ip


@register
class DirectoryCollector:
    name = "directory"

    def collect(self, ctx: dict) -> list[Finding]:
        try:
            return self._collect(ctx)
        except Exception:  # noqa: BLE001 - a collector that cannot run is silent
            return []

    def _collect(self, ctx: dict) -> list[Finding]:
        if sys.platform != "win32" or "hosts" not in ctx:
            return []
        live = {
            host["ip"]: host.get("mac", "")
            for host in ctx["hosts"] or []
            if host.get("ip") and tasking.wanted(ctx, host["ip"])
        }
        if not live:
            return []
        computers = parse_computers(run_powershell())
        if not computers:
            return []

        def resolve(computer: dict[str, Any]) -> str:
            return resolve_ipv4(computer["dns_name"] or computer["name"])

        with ThreadPoolExecutor(max_workers=tasking.workers(ctx, "ping", WORKERS)) as pool:
            addresses = list(pool.map(resolve, computers))

        findings: list[Finding] = []
        seen: set[str] = set()
        for computer, ip in zip(computers, addresses):
            if not ip or ip not in live or ip in seen:
                continue  # not alive in the sweep (or a duplicate: the newest wins)
            seen.add(ip)
            mac = live[ip]
            dns_name = computer["dns_name"]
            short = (dns_name.split(".")[0] if dns_name else computer["name"]).lower()
            payload: dict[str, Any] = {"ip": ip, "seen_by": "directory"}
            for key, value in (("mac", mac), ("hostname", short), ("os", computer["os"])):
                if value:
                    payload[key] = value
            block: dict[str, Any] = {}
            for key, value in (("dns_name", dns_name), ("os_version", computer["os_version"])):
                if value:
                    block[key] = value
            if computer["last_logon"] is not None:
                block["last_logon"] = computer["last_logon"].astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if computer["roles"]:
                block["roles"] = computer["roles"]
            if block:
                payload["directory"] = block
            findings.append(Finding(kind="host", identity={"mac": mac} if mac else {"ip": ip}, payload=payload))
        return findings
