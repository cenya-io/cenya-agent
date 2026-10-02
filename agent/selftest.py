"""`cenya-agent selftest`: what this build can do, as JSON, with no network.

It exists for the installer. A frozen build can look fine and still be missing
the one module a collector imports lazily, a translation catalogue, or the
Windows service libraries -- and the symptom, months later, is a collector that
says "not available" on a customer's machine. CI runs this on the build it just
made, and so can anyone who doubts an installation. Never prints a secret and
never touches the network.
"""

from __future__ import annotations

import importlib.util
import json
import sys

from agent import __version__, i18n, store
from agent.collectors import all_collectors

#: Lo que tiene que haber en una instalación completa. `snmp` y `winrm` son
#: opcionales a propósito en `pip install`, pero el instalador las lleva dentro.
OPTIONAL_MODULES = {
    "snmp": "pysnmp",
    "winrm": "winrm",
    "ntlm": "requests_ntlm",
    # La clave del agente (agent/identity.py): sin ella, `sealed_credentials`
    # sale en falso y el servidor no puede sellarle credenciales.
    "crypto": "cryptography",
}
WINDOWS_MODULES = ("win32serviceutil", "servicemanager", "win32gui")
#: El núcleo del protocolo 2. Los importa el bucle de forma estática, pero un
#: `excludes` mal puesto en el .spec los dejaría fuera sin que nada fallara
#: hasta que el servicio arrancase en casa de un cliente.
RUNTIME_MODULES = (
    "about",
    "control",
    "identity",
    "logs",
    "outbox",
    "runtime",
    "scheduler",
    "settings",
    "tasks",
)


def _has(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def report() -> dict[str, object]:
    languages = {}
    for code in ("es", "en", "de", "fr", "pt_BR"):
        # `None` solo para el idioma fuente: el castellano no necesita catálogo.
        languages[code] = code == "es" or i18n.catalog_path([code], i18n.LOCALE_DIR) is not None
    data: dict[str, object] = {
        "version": __version__,
        "frozen": bool(getattr(sys, "frozen", False)),
        "platform": sys.platform,
        "collectors": [collector.name for collector in all_collectors()],
        "modules": {name: _has(module) for name, module in OPTIONAL_MODULES.items()},
        "runtime": {name: _has(f"agent.{name}") for name in RUNTIME_MODULES},
        "languages": languages,
        "state_file": str(store.path()),
    }
    if sys.platform == "win32":
        data["windows_modules"] = {name: _has(name) for name in WINDOWS_MODULES}
    return data


def complete(data: dict[str, object]) -> bool:
    """Si es una instalación completa: todos los colectores, todos los
    catálogos y, en Windows, las librerías del servicio y del icono."""
    ok = len(data["collectors"]) >= 6  # type: ignore[arg-type]
    ok = ok and all(data["modules"].values())  # type: ignore[union-attr]
    ok = ok and all(data["languages"].values())  # type: ignore[union-attr]
    ok = ok and all(data.get("runtime", {}).values())  # type: ignore[union-attr]
    if "windows_modules" in data:
        ok = ok and all(data["windows_modules"].values())  # type: ignore[union-attr]
    return bool(ok)


def run() -> int:
    data = report()
    data["complete"] = complete(data)
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0 if data["complete"] else 1
