"""WMI over DCOM, for Windows servers that have no WinRM.

A Windows server with 5985/5986 closed but with WMI reachable (TCP 135 plus
the dynamic RPC range) is still a Windows server we can identify: this is how
Lansweeper and ServiceNow classify them. We do it with the **native**
PowerShell CIM cmdlets (``New-CimSession`` with ``-Protocol Dcom``), so there is
no new library: Windows itself negotiates DCOM packet integrity (KB5004442) and
we never reimplement the RPC dialect. For that reason it only works in an agent
that runs on Windows with PowerShell present; anywhere else ``available()`` is
false and the collector does nothing.

How the credential travels
--------------------------
Never in the command line (visible to every local process through the process
list) and never inside the script text. The script is a **constant**; the
target host, user and password reach the child process through its standard
input, as base64 of a UTF-8 JSON document (ASCII-safe, so the console code page
cannot mangle a password with accents). PowerShell builds a ``PSCredential``
with a ``SecureString`` from it. Environment variables were the fallback if
stdin had proved unusable; it did not, so they are not used.

Same answer shape as ``agent.winrm`` (``winrm.Answer`` and the same JSON keys),
so the collector maps both to one payload and the credential breaker judges
both with the same verdicts.
"""

from __future__ import annotations

import base64
import json
import shutil
import subprocess
import sys
from typing import Callable

from agent import winrm
from agent.winrm import Answer

#: TCP port of the RPC endpoint mapper: the one that must answer for DCOM.
PORT = 135
#: Whole-process budget per host, seconds. The CIM operation timeout is lower,
#: so a slow Windows ends with a PowerShell error before this kills the process.
TOTAL_TIMEOUT_SECONDS = 45
OPERATION_TIMEOUT_SECONDS = 20

#: Constant script. Nothing from the host or the credential is interpolated.
#: Stdin: base64(UTF-8 JSON {"host", "username", "password"}).
SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
  $raw = [Console]::In.ReadToEnd().Trim()
  $req = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($raw)) | ConvertFrom-Json
  $secure = ConvertTo-SecureString -String ([string]$req.password) -AsPlainText -Force
  $cred = New-Object System.Management.Automation.PSCredential ([string]$req.username, $secure)
  $option = New-CimSessionOption -Protocol Dcom
  $session = New-CimSession -ComputerName ([string]$req.host) -Credential $cred -SessionOption $option -OperationTimeoutSec 20
  $cs = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem | Select-Object -First 1
  $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem | Select-Object -First 1
  $bios = Get-CimInstance -CimSession $session -ClassName Win32_BIOS | Select-Object -First 1
  $nics = @(Get-CimInstance -CimSession $session -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True')
  $vmms = @(Get-CimInstance -CimSession $session -ClassName Win32_Service -Filter "Name='vmms'")
  $interfaces = @()
  foreach ($nic in $nics) {
    $address = @($nic.IPAddress) | Where-Object { $_ -and $_ -notmatch ':' } | Select-Object -First 1
    $interfaces += @{ name = [string]$nic.Description; mac = [string]$nic.MACAddress; ip = [string]$address }
  }
  $result = @{
    hostname     = [string]$cs.Name
    domain       = [string]$cs.Domain
    in_domain    = [bool]$cs.PartOfDomain
    domain_role  = [int]$cs.DomainRole
    manufacturer = [string]$cs.Manufacturer
    model        = [string]$cs.Model
    serial       = [string]$bios.SerialNumber
    os           = [string]$os.Caption
    os_version   = [string]$os.Version
    build        = [string]$os.BuildNumber
    boot_time    = [string]$os.LastBootUpTime
    memory_bytes = [string]$cs.TotalPhysicalMemory
    hyperv       = [bool]($vmms.Count -gt 0)
    interfaces   = $interfaces
  }
  $bytes = ([Text.UTF8Encoding]::new($false)).GetBytes(($result | ConvertTo-Json -Depth 4 -Compress))
  $stdout = [Console]::OpenStandardOutput()
  $stdout.Write($bytes, 0, $bytes.Length)
  $stdout.Flush()
  Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue
} catch {
  [Console]::Error.WriteLine(([string]$_.Exception.GetType().Name + ': ' + [string]$_.Exception.Message))
  exit 2
}
"""

#: What a failure says (lower case) when the credential was certainly never
#: judged. Anything not recognised is treated as a rejection: with doubt, the
#: prudent verdict for the account-lockout breaker.
_UNREACHABLE = (
    "rpc server is unavailable",
    "0x800706ba",
    "0x800706be",
    "timed out",
    "timeout",
    "the network path was not found",
    "no such host",
)

#: `(argv, stdin text, timeout) -> (returncode, stdout, stderr)`; injected by tests.
Runner = Callable[[list, str, float], tuple]


def powershell_path() -> str:
    """Windows PowerShell 5.1 (always on a Windows box), or empty."""
    if sys.platform != "win32":
        return ""
    return shutil.which("powershell") or shutil.which("powershell.exe") or ""


def available() -> bool:
    """Whether this agent can speak DCOM: Windows and PowerShell present."""
    return bool(powershell_path())


def encoded_script() -> str:
    """The script as `-EncodedCommand` wants it: base64 of UTF-16LE."""
    return base64.b64encode(SCRIPT.encode("utf-16-le")).decode("ascii")


def command_line(exe: str) -> list[str]:
    """The argv of the child. Constant: no host, user or password in it."""
    return [exe, "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded_script()]


def stdin_payload(host: str, username: str, secret: str) -> str:
    document = json.dumps({"host": host, "username": username, "password": secret})
    return base64.b64encode(document.encode("utf-8")).decode("ascii")


def _run(argv: list[str], stdin: str, timeout: float) -> tuple[int, bytes, bytes]:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    done = subprocess.run(  # noqa: S603 - argv is constant and no shell is involved
        argv,
        input=stdin.encode("ascii"),
        capture_output=True,
        timeout=timeout,
        creationflags=flags,
        check=False,
    )
    return done.returncode, done.stdout, done.stderr


def _first_line(text: str) -> str:
    """The error line, without the CLIXML envelope PowerShell wraps stderr in."""
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith(("#<", "<")):
            return line
    return ""


def _scrub(text: str, secret: str) -> str:
    return text.replace(secret, "***") if secret else text


def query(*, host: str, username: str, secret: str, runner: Runner | None = None) -> Answer:
    """Ask that Windows who it is over WMI/DCOM. Never raises."""
    exe = powershell_path()
    if runner is None:
        if not exe:
            return Answer(connected=False, error="PowerShell no disponible", unreachable=True)
        runner = _run
    argv = command_line(exe or "powershell")
    try:
        code, out, err = runner(argv, stdin_payload(host, username, secret), TOTAL_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return Answer(connected=False, error="tiempo agotado", unreachable=True)
    except Exception as exc:  # noqa: BLE001 - the child could not even start
        return Answer(connected=False, error=_scrub(f"{type(exc).__name__}: {exc}", secret)[:200], unreachable=True)
    if code != 0:
        text = _scrub(_first_line(err.decode("utf-8", errors="replace")), secret)[:200]
        low = text.lower()
        # Checked first: a rejection must never be mistaken for "not reached".
        if "access is denied" in low or "0x80070005" in low or "logon failure" in low:
            return Answer(connected=False, error=text)
        return Answer(connected=False, error=text, unreachable=any(p in low for p in _UNREACHABLE))
    return Answer(connected=True, data=winrm._decode(out.decode("utf-8-sig", errors="replace")))
