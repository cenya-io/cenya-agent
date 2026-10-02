"""Where the agent keeps its permanent token once it has enrolled.

The person never sees the token: the agent redeems a one-time code and writes
what it gets here. That makes this file the one secret the agent keeps on disk,
so the rules are strict:

* **Readable only by whoever must read it.** ``0600`` on Linux. On Windows the
  inherited permissions are removed and only SYSTEM (who runs the service), the
  Administrators and whoever enrolled keep access -- by SID, because the group
  names are translated ("Administradores", "Administratoren"…).
* **If it cannot be protected, it is not written.** A token saved readable by
  every user of the machine is the failure this exists to avoid; better an
  enrolment that says why it failed than one that quietly leaks.
* **Atomic.** A crash half-way never leaves a half-written file the service
  would read as an enrolment.
* **A broken file is "not enrolled", never a crash.** The agent lives in a
  machine nobody watches; refusing to start over a corrupt file would be worse
  than asking to be enrolled again.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from agent.i18n import _t

FILE_NAME = "enrollment.json"

#: SID de SYSTEM y del grupo Administradores, iguales en cualquier idioma.
_WINDOWS_SYSTEM_SID = "*S-1-5-18"
_WINDOWS_ADMINS_SID = "*S-1-5-32-544"


class StoreError(RuntimeError):
    """The enrolment could not be saved safely. Its text is for a person."""


@dataclass(frozen=True)
class Enrollment:
    url: str
    token: str
    name: str = ""


def state_dir(environ: Mapping[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    override = (env.get("CENYA_STATE_DIR") or "").strip()
    if override:
        return Path(override)
    if sys.platform == "win32":
        return Path(env.get("ProgramData") or r"C:\ProgramData") / "Cenya"
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/var/lib/cenya-agent")
    return Path.home() / ".config" / "cenya-agent"


def path(environ: Mapping[str, str] | None = None) -> Path:
    return state_dir(environ) / FILE_NAME


def load(environ: Mapping[str, str] | None = None) -> Enrollment | None:
    """The saved enrolment, or `None` if there is none or it cannot be read."""
    try:
        data = json.loads(path(environ).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    url, token = data.get("url"), data.get("token")
    if not isinstance(url, str) or not isinstance(token, str) or not url or not token:
        return None
    return Enrollment(url=url, token=token, name=str(data.get("name") or ""))


def _restrict_windows(target: Path) -> None:
    """Quita lo heredado y deja a SYSTEM, Administradores y a quien enrola."""
    who = f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}".strip("\\")
    grants = [f"{_WINDOWS_SYSTEM_SID}:F", f"{_WINDOWS_ADMINS_SID}:F"]
    if who:
        grants.append(f"{who}:F")
    result = subprocess.run(  # noqa: S603 - argumentos fijos, sin shell
        ["icacls", str(target), "/inheritance:r", "/grant:r", *grants],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise OSError(result.stderr.strip() or result.stdout.strip() or f"icacls {result.returncode}")


def save(enrollment: Enrollment, environ: Mapping[str, str] | None = None) -> Path:
    """Write the enrolment, protected, replacing any previous one."""
    target = path(environ)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # El temporal ya nace cerrado (mkstemp usa 0600) y se protege antes de
        # recibir el token, no después: ni un instante legible por otros.
        fd, tmp_name = tempfile.mkstemp(dir=target.parent, prefix=".enrollment-", suffix=".tmp")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                if sys.platform == "win32":
                    handle.flush()
                    _restrict_windows(tmp)
                json.dump({"url": enrollment.url, "token": enrollment.token, "name": enrollment.name}, handle)
            os.replace(tmp, target)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise StoreError(
            _t("No se pudo guardar el enrolamiento de forma segura en %(path)s: %(error)s")
            % {"path": target, "error": exc}
        ) from exc
    return target
