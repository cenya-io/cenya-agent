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
from pathlib import Path

from agent import __version__, i18n, ssh, store
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
    # El canal local (spec 4): sin él la aplicación de escritorio y los
    # comandos `status`, `pause`... no tienen con quién hablar.
    "localapi",
    "localclient",
    "localops",
    "localpipe",
    "logs",
    "outbox",
    "runtime",
    "scheduler",
    "settings",
    "tasks",
    # La actualización (docs/agente-v2-instalacion.md, 4) y el ajuste de la CA
    # que usa el instalador con /CA=.
    "update",
    "release",
    "release_keys",
    "settings_command",
)


def release_keys_report() -> dict[str, object]:
    """How many valid release keys this build trusts, and their short fingerprints.

    No forma parte de «completa»: un agente sin claves funciona, solo que no se
    actualiza solo. Lo mira el flujo de publicación (la versión que se publica
    no puede llevar la clave de prueba de CI) y quien dude de una compilación.
    """
    from agent import release
    from agent.release_keys import PUBLIC_KEYS

    try:
        keys = release.load_public_keys(PUBLIC_KEYS)
    except release.ReleaseError as exc:
        return {"count": 0, "fingerprints": [], "error": exc.code}
    return {"count": len(keys), "fingerprints": [release.key_fingerprint(key) for key in keys]}


def _has(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def ssh_report() -> dict[str, object]:
    """The OpenSSH the SSH collector will run and whether passwords can use it.

    ``bundled`` is whether it is the one the installer ships in the
    ``openssh`` folder next to the executable: a frozen build that fell back to the system's would
    work on this machine and fail on a Windows Server 2019 with an old one.
    """
    binary = ssh.BINARY
    bundled = bool(getattr(sys, "frozen", False)) and bool(binary) and Path(binary).parent.name == "openssh"
    return {
        "binary": binary,
        "bundled": bundled,
        "version": f"{ssh.VERSION[0]}.{ssh.VERSION[1]}" if ssh.VERSION else None,
        "askpass": bool(ssh.ASKPASS),
        "password_auth": ssh.PASSWORD_AUTH_AVAILABLE,
    }


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
        "ssh": ssh_report(),
        "release_keys": release_keys_report(),
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
        if data.get("frozen"):
            # El instalador de Windows lleva su OpenSSH y su askpass: sin ellos
            # la contraseña SSH no funcionaría en una máquina con un OpenSSH viejo.
            report_ssh = data["ssh"]
            ok = ok and bool(report_ssh["bundled"]) and bool(report_ssh["password_auth"])  # type: ignore[index]
    return bool(ok)


def run() -> int:
    data = report()
    data["complete"] = complete(data)
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0 if data["complete"] else 1
