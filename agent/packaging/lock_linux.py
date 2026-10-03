"""Regenerate (or check) the hash-pinned dependency lock that install.sh uses on Linux.

install.sh runs as root, so it never asks PyPI for "whatever is newest": it
installs `cenya-agent[completo]` with ``pip install --require-hashes --no-deps``
from ``agent/deploy/requirements-linux.txt``, which this script writes. Two
outputs, both derived from ``agent/pyproject.toml``:

* ``agent/deploy/requirements-linux.txt``: every runtime dependency of
  ``cenya-agent[completo]`` plus the build backend (``[build-system] requires``,
  needed because the agent itself is installed with ``--no-build-isolation``),
  exact versions and a ``--hash=sha256:`` for every distribution file of each
  version, so one lock serves x86_64 and aarch64 on CPython 3.10-3.13. Packages
  that only ever install on Windows (their marker is false on every Linux) are
  left out.
* the block between ``# BEGIN verify-requirements`` and ``# END
  verify-requirements`` in ``agent/deploy/install.sh``: the same lines for
  ``cryptography`` and what it pulls in, which install.sh needs to check the
  manifest signature *before* it has the archive (and so the lock) in hand.

The resolver is uv (MIT/Apache-2.0; a development tool, never shipped):

    python -m pip install uv==0.12.23   # the version CI uses
    python agent/packaging/lock_linux.py            # rewrite both
    python agent/packaging/lock_linux.py --check    # CI: fail if either is stale
    python agent/packaging/lock_linux.py --upgrade  # move every pin to the newest

Without ``--upgrade`` the current pins are kept wherever pyproject.toml still
allows them (uv reads the existing lock as its preferences), so ``--check`` only
fails when pyproject.toml changed and nobody regenerated.
"""

from __future__ import annotations

import argparse
import itertools
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent.parent
REPO = AGENT_DIR.parent
PYPROJECT = AGENT_DIR / "pyproject.toml"
LOCK = AGENT_DIR / "deploy" / "requirements-linux.txt"
INSTALL_SH = AGENT_DIR / "deploy" / "install.sh"
BEGIN = "# BEGIN verify-requirements"
END = "# END verify-requirements"
VERIFY_ROOT = "cryptography"
BUILD_NOTE = "build-system.requires (agent/pyproject.toml)"

HEADER = """\
# Hash-pinned dependencies of cenya-agent[completo] on Linux (x86_64 and
# aarch64, CPython 3.10-3.13), plus the build backend. GENERATED: do not edit.
# install.sh installs exactly this, as root, with
#   pip install --require-hashes --no-deps --only-binary :all: -r requirements-linux.txt
# and then the agent itself with --no-deps --no-build-isolation --no-index.
# Regenerate after touching agent/pyproject.toml (CI fails until you do):
#   python -m pip install uv==0.12.23
#   python agent/packaging/lock_linux.py
# (--upgrade moves every pin to the newest allowed version). Check the licence
# of anything new: the agent is Apache-2.0, nothing copyleft goes in.
"""

# Every Linux the installer supports: CPython 3.10-3.13 on x86_64 and aarch64.
LINUX_ENVIRONMENTS = [
    {
        "implementation_name": "cpython",
        "platform_python_implementation": "CPython",
        "sys_platform": "linux",
        "platform_system": "Linux",
        "os_name": "posix",
        "platform_machine": machine,
        "python_version": f"3.{minor}",
        "python_full_version": f"3.{minor}.0",
        "implementation_version": f"3.{minor}.0",
    }
    for minor, machine in itertools.product((10, 11, 12, 13), ("x86_64", "aarch64"))
]


def find_uv(explicit: str | None) -> str:
    if explicit:
        return explicit
    found = os.environ.get("UV") or shutil.which("uv")
    if found:
        return found
    try:
        from uv import find_uv_bin  # type: ignore[import-not-found]
    except ImportError:
        sys.exit("lock_linux.py: hace falta uv (python -m pip install uv) o --uv RUTA.")
    return find_uv_bin()


def marker_evaluator():  # noqa: ANN201
    try:
        from packaging.markers import Marker  # type: ignore[import-not-found]
    except ImportError:  # pip always carries it
        from pip._vendor.packaging.markers import Marker  # type: ignore[import-not-found,no-redef]
    return Marker


def split_entries(text: str) -> list[str]:
    """The compiled file as one string per requirement (its hash and via lines included)."""
    entries: list[str] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if line[0].isspace():
            if not entries:
                raise ValueError(f"línea suelta en la salida de uv: {line!r}")
            entries[-1] += "\n" + line
        elif line.startswith("#"):
            continue
        else:
            entries.append(line)
    return entries


def entry_name(entry: str) -> str:
    return re.split(r"[=;\s\[]", entry, maxsplit=1)[0].lower().replace("_", "-")


def entry_marker(entry: str) -> str | None:
    first = entry.split("\n", 1)[0].rstrip(" \\")
    return first.split(";", 1)[1].strip() if ";" in first else None


def installs_on_linux(entry: str) -> bool:
    marker = entry_marker(entry)
    if marker is None:
        return True
    parsed = marker_evaluator()(marker)
    return any(parsed.evaluate(env) for env in LINUX_ENVIRONMENTS)


def via(entry: str) -> list[str]:
    """Who asked for this package, from uv's annotations."""
    names: list[str] = []
    lines = entry.split("\n")
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("# via "):
            names.append(stripped[len("# via "):])
        elif stripped == "# via":
            names.extend(rest.strip().lstrip("#").strip() for rest in lines[index + 1:] if rest.strip().startswith("#   "))
    return [name.split(" ", 1)[0].lower() for name in names]


def verify_closure(entries: list[str]) -> list[str]:
    """`cryptography` and everything in the lock that is there because of it."""
    by_name = {entry_name(entry): entry for entry in entries}
    if VERIFY_ROOT not in by_name:
        raise ValueError(f"{VERIFY_ROOT} no está en el lock")
    wanted = {VERIFY_ROOT}
    changed = True
    while changed:
        changed = False
        for name, entry in by_name.items():
            if name not in wanted and wanted.intersection(via(entry)):
                wanted.add(name)
                changed = True
    return [entry for entry in entries if entry_name(entry) in wanted]


def strip_annotations(entry: str) -> str:
    return "\n".join(line for line in entry.split("\n") if not line.strip().startswith("#")).rstrip(" \\")


def compile_lock(uv: str, upgrade: bool) -> list[str]:
    build_requires = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["build-system"]["requires"]
    with tempfile.TemporaryDirectory() as tmp:
        build_in = Path(tmp) / "build-system.in"
        build_in.write_text("\n".join(build_requires) + "\n", encoding="utf-8")
        out = Path(tmp) / "requirements-linux.txt"
        if LOCK.exists() and not upgrade:
            shutil.copyfile(LOCK, out)  # uv keeps these pins wherever they still fit
        command = [uv, "pip", "compile", "--quiet", "--universal", "--generate-hashes", "--no-header",
                   "--python-version", "3.10", "--extra", "completo",
                   "agent/pyproject.toml", str(build_in), "--output-file", str(out)]
        if upgrade:
            command.append("--upgrade")
        subprocess.run(command, cwd=REPO, check=True)
        text = out.read_text(encoding="utf-8")
        # The temporary path would make every run differ.
        text = re.sub(r"-r \S*build-system\.in", BUILD_NOTE, text)
    entries = [entry for entry in split_entries(text) if installs_on_linux(entry)]
    for entry in entries:
        if "--hash=sha256:" not in entry:
            raise ValueError(f"sin huella: {entry.splitlines()[0]}")
    return entries


def render_lock(entries: list[str]) -> str:
    return HEADER + "\n".join(entries) + "\n"


def render_install_sh(entries: list[str]) -> str:
    script = INSTALL_SH.read_text(encoding="utf-8")
    pattern = re.compile(rf"(^[ \t]*{re.escape(BEGIN)}\n)(.*?)(^[ \t]*{re.escape(END)}$)", re.M | re.S)
    if not pattern.search(script):
        raise ValueError(f"install.sh no tiene el bloque {BEGIN} ... {END}")
    block = "\n".join(strip_annotations(entry) for entry in verify_closure(entries)) + "\n"
    return pattern.sub(lambda m: m.group(1) + block + m.group(3), script, count=1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--check", action="store_true", help="no escribe: falla si algo está desfasado")
    parser.add_argument("--upgrade", action="store_true", help="lleva cada versión a la más nueva permitida")
    parser.add_argument("--uv", help="ruta de uv, si no está en el PATH ni instalado como módulo")
    args = parser.parse_args(argv)
    entries = compile_lock(find_uv(args.uv), args.upgrade)
    outputs = {LOCK: render_lock(entries), INSTALL_SH: render_install_sh(entries)}
    stale = [path for path, text in outputs.items()
             if not path.exists() or path.read_text(encoding="utf-8") != text]
    if args.check:
        for path in stale:
            print(f"{path.relative_to(REPO).as_posix()} no corresponde a agent/pyproject.toml: "
                  "python agent/packaging/lock_linux.py", file=sys.stderr)
        return 1 if stale else 0
    for path in stale:
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(outputs[path])
        print(f"{path.relative_to(REPO).as_posix()}: actualizado.")
    if not stale:
        print("Nada que cambiar.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
