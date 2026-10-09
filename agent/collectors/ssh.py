"""L3: SSH.

A los hosts vivos con el 22 abierto se entra y se les pregunta quién son. Lo
que sale de aquí es lo que convierte una IP que contestó a un ping en una ficha
de inventario: sistema operativo, nombre real, interfaces con su MAC y su IP y,
cuando el equipo lo deja, fabricante, modelo y número de serie.

**Una tentativa por familia, gana la que conteste.** Un switch Cisco no sabe qué
es ``uname`` y un Linux no sabe qué es ``show version``, así que en vez de
adivinar por el banner --que miente y que cada versión cambia-- se prueban los
comandos de cada familia en orden y se acepta el primero cuya salida se puede
leer. Añadir HP, Juniper o un NAS es una entrada más en ``FAMILIES``: el bucle
no cambia, que es lo que importa aquí más que la cobertura de hoy.

El hallazgo mantiene el ``kind`` ``host`` y la identidad del barrido, así que en
vez de una segunda fila en la bandeja *enriquece* la que ya existe.
"""

from __future__ import annotations

import re
from collections.abc import Collection
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Any, Callable

from agent import credentials as creds
from agent import net, ssh, sshshell, stacks, tables
from agent.collectors import register, tasking
from agent.collectors.base import Finding
from agent.collectors.snmp import ROUTER_MIN_IPS, _arp_ips, _links_for, _port_tables
from agent.notes import collector_note

SSH_PORT = 22
#: Cuántos equipos a la vez. Bajo a propósito: cada uno es un proceso `ssh`, y
#: cincuenta procesos simultáneos en el servidor de una pyme se notan.
WORKERS = 10
#: Tope de todo el paso, no de un equipo: cada orden ya tiene el suyo, pero un
#: hilo que no vuelve (un proceso `ssh` que no muere) dejaba la tarea en su
#: 95 % para siempre y bloqueaba las demás. Pasado el tope, lo que falta se
#: abandona y se anota; lo ya recogido se conserva.
STEP_DEADLINE_SECONDS = 15 * 60


def map_with_deadline(
    workers: int, fn: Callable[[Any], Any], items: list, default: Any, errors: list, seconds: float | None = None
) -> list:
    """`pool.map` con tope global: lo que no acaba a tiempo devuelve `default`."""
    pool = ThreadPoolExecutor(max_workers=workers)
    futures = [pool.submit(fn, item) for item in items]
    done, pending = wait(futures, timeout=STEP_DEADLINE_SECONDS if seconds is None else seconds)
    # Sin esperar a los atascados: su hilo se queda solo, pero el paso sigue.
    pool.shutdown(wait=False, cancel_futures=True)
    if pending:
        errors.append(
            collector_note(
                "ssh",
                "step_timeout",
                "se abandonaron %d equipos que no contestaron a tiempo" % len(pending),
                count=len(pending),
            )
        )
    results = []
    for future in futures:
        try:
            results.append(future.result() if future in done and not future.cancelled() else default)
        except Exception:  # a visit that raised must not sink the step
            results.append(default)
    return results

#: La marca que separa las secciones de la salida de Linux. Sin `#` delante: en
#: un shell, una palabra que empieza por almohadilla es un comentario y el
#: `echo` no imprimiría nada -- la salida llegaba entera y sin separar.
MARK = "@@netinv:"


# --- Familias -------------------------------------------------------------------


@dataclass(frozen=True)
class Family:
    """Un intento: qué se pregunta y cómo se lee la respuesta.

    ``parse`` devuelve un diccionario vacío cuando la salida no es de esta
    familia. Eso es lo que decide que se pruebe la siguiente. Un analizador
    puede devolver ``family`` dentro del diccionario para afinar: varios
    fabricantes contestan al mismo comando de detección, y abrir una conexión
    por fabricante para repetirlo serían intentos de autenticación de más sin
    aprender nada nuevo.
    """

    name: str
    command: str
    parse: Callable[[str], dict[str, Any]]


#: Cada sección va precedida de su marca para poder trocear la salida. Los
#: `2>/dev/null` son deliberados: en un equipo sin `dmidecode` ni DMI en `/sys`
#: --una máquina virtual, un contenedor-- el error iría a la salida de error y
#: no rompería nada, pero llena el informe de ruido que no dice nada.
_LINUX_SECTIONS: tuple[tuple[str, str], ...] = (
    ("uname", "uname -sr"),
    ("os", "cat /etc/os-release 2>/dev/null"),
    ("host", "hostname"),
    ("link", "ip -o link 2>/dev/null"),
    ("addr", "ip -o -4 addr 2>/dev/null"),
    ("vendor", "cat /sys/class/dmi/id/sys_vendor 2>/dev/null"),
    ("model", "cat /sys/class/dmi/id/product_name 2>/dev/null"),
    # El serie del DMI solo lo lee root. Se pide igual y si no hay permiso sale
    # vacío: pedirlo con `sudo` sería pedir una contraseña que no tenemos.
    ("serial", "cat /sys/class/dmi/id/product_serial 2>/dev/null"),
    # EdgeOS is a Linux underneath: `uname` answers, so it would be signed as
    # a plain Linux and never get a configuration copy. These two clues tell
    # it apart (see `_is_edgeos`).
    ("vyatta", "test -x /opt/vyatta/bin/vyatta-op-cmd-wrapper && echo yes"),
    ("ubnt", "cat /etc/version 2>/dev/null"),
)

LINUX_COMMAND = "; ".join(f"echo {MARK}{name}; {command}" for name, command in _LINUX_SECTIONS)


def _sections(output: str) -> dict[str, list[str]]:
    """La salida troceada por marcas. Sin marcas, nada: no es de esta familia."""
    found: dict[str, list[str]] = {}
    current = ""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith(MARK):
            current = stripped[len(MARK) :].strip()
            found[current] = []
        elif current:
            found[current].append(line.rstrip())
    return found


_MAC_RE = re.compile(r"link/ether\s+([0-9a-fA-F:]{17})")
_IFACE_RE = re.compile(r"^\d+:\s*([^:@]+)")
_ADDR_RE = re.compile(r"^\d+:\s*(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)")
_PRETTY_RE = re.compile(r'^PRETTY_NAME="?([^"]+)"?', re.MULTILINE)


def parse_linux(output: str) -> dict[str, Any]:
    """Lo que dice un Linux de sí mismo. Vacío si esto no es un Linux."""
    sections = _sections(output)
    if not sections:
        return {}
    uname = " ".join(sections.get("uname") or []).strip()
    os_release = "\n".join(sections.get("os") or [])
    pretty = _PRETTY_RE.search(os_release)
    description = (pretty.group(1) if pretty else uname).strip()
    hostname = next((line.strip() for line in sections.get("host") or [] if line.strip()), "")

    interfaces: list[dict[str, str]] = []
    addresses: dict[str, str] = {}
    for line in sections.get("addr") or []:
        match = _ADDR_RE.match(line.strip())
        if match:
            addresses.setdefault(match.group(1), match.group(2))
    for line in sections.get("link") or []:
        name_match = _IFACE_RE.match(line.strip())
        if not name_match:
            continue
        name = name_match.group(1).strip()
        if name == "lo":
            # El bucle local no es una interfaz del inventario: está en todas
            # las máquinas, con la misma dirección, y no lleva a ningún sitio.
            continue
        mac_match = _MAC_RE.search(line)
        interfaces.append(
            {
                "name": name,
                "mac": (mac_match.group(1).lower() if mac_match else ""),
                "status": "up" if ",UP" in line or "<UP" in line else "down",
                "ip": addresses.get(name, ""),
            }
        )

    if not (uname or hostname or interfaces):
        # Contestó, pero no a esto. Que lo intente la familia siguiente.
        return {}
    edgeos = _is_edgeos(uname, sections)
    return {
        # Only set for EdgeOS; every other Linux keeps the family of the try.
        **({"family": "edgeos"} if edgeos else {}),
        "hostname": hostname,
        "description": description,
        "os": description or uname,
        "interfaces": interfaces,
        "manufacturer": _first_line(sections.get("vendor")) or ("Ubiquiti" if edgeos else ""),
        "model": _first_line(sections.get("model")),
        "serial": _first_line(sections.get("serial")),
    }


def _is_edgeos(uname: str, sections: dict[str, list[str]]) -> bool:
    """Whether this Linux is a Ubiquiti EdgeOS (EdgeRouter, EdgeSwitch on EdgeOS).

    The Vyatta op-mode wrapper is what the copy needs, so it has to be there;
    on top of it, either the kernel says "UBNT" or ``/etc/version`` says
    "Edge". Both are needed so a VyOS (same wrapper, no Ubiquiti) stays a plain
    Linux. The "-UBNT" kernel suffix and the "Edge..." text of ``/etc/version``
    are from public forum output, still to be confirmed on a real device.
    """
    if "yes" not in [line.strip() for line in sections.get("vyatta") or []]:
        return False
    version = " ".join(sections.get("ubnt") or []).lower()
    return "ubnt" in uname.lower() or "edge" in version


def _first_line(lines: list[str] | None) -> str:
    for line in lines or []:
        value = line.strip()
        # Los equipos de fábrica traen estos rellenos en el DMI. Guardarlos
        # sería peor que dejarlo vacío: parece un dato y no lo es.
        if value and value.lower() not in {"none", "to be filled by o.e.m.", "default string", "system serial number"}:
            return value
    return ""


_CISCO_HOSTNAME_RE = re.compile(r"^(\S+)\s+uptime is", re.MULTILINE)
# IOS writes "System serial number", IOS-XE "System Serial Number": either case.
_CISCO_SERIAL_RE = re.compile(r"system serial number\s*:\s*(\S+)", re.IGNORECASE)
_CISCO_MODEL_RE = re.compile(r"model number\s*:\s*(\S+)", re.IGNORECASE)
_CISCO_BANNER_RE = re.compile(r"^(Cisco IOS.*|.*Software.*Version.*)$", re.MULTILINE)
#: «IOS» as a whole word: a Huawei prints «BIOS Version» and was signed as a
#: Cisco by the plain substring (08-10-2026).
_CISCO_MARK_RE = re.compile(r"\bCisco\b|\bIOS\b")


def parse_cisco(output: str) -> dict[str, Any]:
    """Un IOS clásico: `show version` y poco más.

    No se sacan las interfaces: hacen falta otros comandos y en un equipo de red
    eso ya lo da SNMP mejor, que además no necesita entrar. Aquí interesan el
    nombre, la versión y el número de serie, que SNMP no siempre da.
    """
    if not _CISCO_MARK_RE.search(output):
        return {}
    banner = _CISCO_BANNER_RE.search(output)
    hostname = _CISCO_HOSTNAME_RE.search(output)
    serial = _CISCO_SERIAL_RE.search(output)
    model = _CISCO_MODEL_RE.search(output)
    description = (banner.group(1).strip() if banner else "Cisco IOS")
    # A stack lists every unit in this same output; the first serial above is
    # the active unit's, which stays the main one.
    members = stacks.cisco_members(output)
    return {
        **({"members": members} if members else {}),
        "family": "cisco",
        "hostname": hostname.group(1) if hostname else "",
        "description": description,
        "os": description,
        "interfaces": [],
        "manufacturer": "Cisco",
        "model": model.group(1) if model else "",
        "serial": serial.group(1) if serial else "",
    }


MIKROTIK_COMMAND = "/system resource print; /system identity print; /system routerboard print"

_KEY_VALUE_RE = re.compile(r"^\s*([a-z][a-z0-9-]*)\s*:\s*(.+?)\s*$")


def parse_mikrotik(output: str) -> dict[str, Any]:
    """RouterOS contesta con pares `clave: valor` a tres comandos seguidos."""
    values: dict[str, str] = {}
    for line in output.splitlines():
        match = _KEY_VALUE_RE.match(line)
        if match:
            values.setdefault(match.group(1), match.group(2))
    if "version" not in values and "board-name" not in values:
        return {}
    platform = values.get("platform", "MikroTik")
    version = values.get("version", "")
    description = f"{platform} RouterOS {version}".strip()
    return {
        "hostname": values.get("name", ""),
        "description": description,
        "os": description,
        "interfaces": [],
        "manufacturer": platform,
        "model": values.get("model") or values.get("board-name", ""),
        "serial": values.get("serial-number", ""),
    }


# --- Los que comparten «show version» ---------------------------------------------

_JUNOS_HOST_RE = re.compile(r"^Hostname:\s*(\S+)", re.MULTILINE)
_JUNOS_MODEL_RE = re.compile(r"^Model:\s*(\S+)", re.MULTILINE)
_JUNOS_VERSION_RE = re.compile(r"^Junos:\s*(\S+)", re.MULTILINE)


def parse_junos(output: str) -> dict[str, Any]:
    """Un JunOS: `show version` con sus `Hostname:`, `Model:` y `Junos:`."""
    if "JUNOS" not in output and "Junos:" not in output:
        return {}
    version = _JUNOS_VERSION_RE.search(output)
    hostname = _JUNOS_HOST_RE.search(output)
    model = _JUNOS_MODEL_RE.search(output)
    description = f"Juniper JunOS {version.group(1)}".strip() if version else "Juniper JunOS"
    return {
        "family": "junos",
        "hostname": hostname.group(1) if hostname else "",
        "description": description,
        "os": description,
        "interfaces": [],
        "manufacturer": "Juniper",
        "model": model.group(1) if model else "",
        "serial": "",
    }


_ARUBA_MARK_RE = re.compile(r"ArubaOS(?:-CX)?|ProCurve|\bAruba\b")
_ARUBA_SERIAL_RE = re.compile(r"Serial\s+Number\s*:?\s*(\S+)", re.IGNORECASE)


def parse_aruba(output: str) -> dict[str, Any]:
    """Un Aruba (AOS-S, AOS-CX) o su antepasado ProCurve."""
    mark = _ARUBA_MARK_RE.search(output)
    if not mark:
        return {}
    banner = next(
        (line.strip() for line in output.splitlines() if _ARUBA_MARK_RE.search(line)),
        mark.group(0),
    )
    serial = _ARUBA_SERIAL_RE.search(output)
    return {
        "family": "aruba",
        "hostname": "",
        "description": banner,
        "os": banner,
        "interfaces": [],
        "manufacturer": "HP ProCurve" if "ProCurve" in output else "Aruba",
        "model": "",
        "serial": serial.group(1) if serial else "",
    }


def _dotted_value(output: str, label: str) -> str:
    """«Label........ value» or «Label: value», as Dell and Aruba print them."""
    found = re.search(rf"^\s*{re.escape(label)}\s*[.:]+\s*(\S.*?)\s*$", output, re.MULTILINE | re.IGNORECASE)
    return found.group(1) if found else ""


def parse_dell(output: str) -> dict[str, Any]:
    """Un Dell Networking (OS10, series N…, PowerConnect): la firma es la marca en el banner."""
    if "Dell" not in output and "PowerConnect" not in output:
        return {}
    # OS6 prints «Machine Type............ Dell EMC Networking N1548P»: the
    # value, never the dotted label (it came out as the device's description).
    banner = (
        _dotted_value(output, "Machine Type")
        or _dotted_value(output, "Machine Description")
        or _dotted_value(output, "System Description")
        or next(
            (line.strip() for line in output.splitlines() if "Dell" in line or "PowerConnect" in line),
            "Dell Networking",
        )
    )
    # N-series (OS6) prints "Serial Number....." per unit; the first section is
    # the management unit. OS10 has neither and keeps both empty.
    serial, model = stacks.dell_identity(output)
    members = stacks.dell_members_from_version(output)
    return {
        **({"members": members} if members else {}),
        "family": "dell",
        "hostname": "",
        "description": banner,
        "os": banner,
        "interfaces": [],
        "manufacturer": "Dell",
        "model": model,
        "serial": serial,
    }


_EXOS_IMAGE_RE = re.compile(r"^\s*Image\s*:\s*(ExtremeXOS.*?)\s*$", re.MULTILINE)
_EXOS_SWITCH_RE = re.compile(r"^\s*Switch\s*:\s*(\S+)\s+(\S+)", re.MULTILINE)


def parse_exos(output: str) -> dict[str, Any]:
    """Extreme Networks EXOS: ``show version`` with its "Image :" and "Switch :" lines.

    The signature is the word "ExtremeXOS" (or "Extreme Networks" next to an
    "Image :"/"Switch :" line), never a banner. The "Switch :" line is
    ``<part number> <serial> Rev ...``; the model (``X460-24t``) is only in
    ``show switch``, so it stays empty here. Format from public documentation,
    still to be confirmed on a real X4xx/X6xx.
    """
    image = _EXOS_IMAGE_RE.search(output)
    switch = _EXOS_SWITCH_RE.search(output)
    if "ExtremeXOS" not in output and not ("Extreme Networks" in output and (image or switch)):
        return {}
    description = image.group(1) if image else "ExtremeXOS"
    return {
        "family": "exos",
        "hostname": "",
        "description": description,
        "os": description,
        "interfaces": [],
        "manufacturer": "Extreme Networks",
        "model": "",
        "serial": switch.group(2) if switch else "",
    }


_ICX_MARK_RE = re.compile(r"\bICX\d|FastIron", re.IGNORECASE)
_ICX_VENDOR_RE = re.compile(r"Ruckus|Brocade|Foundry|CommScope|UNIT\s+\d+:\s+compiled on", re.IGNORECASE)
_ICX_MODEL_RE = re.compile(r"^\s*HW:\s*(?:Stackable\s+)?(ICX\S+)", re.MULTILINE | re.IGNORECASE)
_ICX_SERIAL_RE = re.compile(r"Serial\s*#\s*:\s*(\S+)", re.IGNORECASE)
_ICX_SW_RE = re.compile(r"^\s*SW:\s*(Version\s+\S+)", re.MULTILINE | re.IGNORECASE)


def parse_icx(output: str) -> dict[str, Any]:
    """Ruckus ICX / Brocade FastIron: ``show version`` with "UNIT 1: compiled on" and "HW: Stackable ICX...".

    Needs the model line (``ICX7150``/"FastIron") **and** a vendor clue, so an
    unrelated output that mentions "ICX" does not sign. In a stack the first
    serial is the active unit's. Format from public documentation, still to be
    confirmed on a real ICX.
    """
    if not (_ICX_MARK_RE.search(output) and _ICX_VENDOR_RE.search(output)):
        return {}
    model = _ICX_MODEL_RE.search(output)
    version = _ICX_SW_RE.search(output)
    serial = _ICX_SERIAL_RE.search(output)
    vendor = "Brocade" if "Brocade" in output and "Ruckus" not in output else "Ruckus"
    description = f"{vendor} FastIron {version.group(1)}" if version else f"{vendor} FastIron"
    return {
        "family": "icx",
        "hostname": "",
        "description": description,
        "os": description,
        "interfaces": [],
        "manufacturer": vendor,
        "model": model.group(1) if model else "",
        "serial": serial.group(1) if serial else "",
    }


_AWPLUS_MODEL_RE = re.compile(r"\b((?:x\d{3}|GS\d{3}|XS\d{3}|IE\d{3}|IX\d|SBx\d{3,4}|AR\d{4})[\w-]*)")
_AWPLUS_VERSION_RE = re.compile(r"AlliedWare Plus(?:\s*\(TM\))?\s*(\d[\w.\-]*)")


def parse_awplus(output: str) -> dict[str, Any]:
    """Allied Telesis AlliedWare Plus: "AlliedWare Plus" or "Allied Telesis" in ``show version``/``show system``.

    The model is looked for with the product-line prefixes (x230, x510, GS900,
    x930...). The hostname is in neither output (``show system`` has it as
    "System Name"). Format from public documentation, still to be confirmed on
    a real x230/x510/GS900MX/x930.
    """
    if "AlliedWare Plus" not in output and "Allied Telesis" not in output:
        return {}
    version = _AWPLUS_VERSION_RE.search(output)
    model = _AWPLUS_MODEL_RE.search(output)
    description = f"AlliedWare Plus {version.group(1)}" if version else "AlliedWare Plus"
    return {
        "family": "awplus",
        "hostname": "",
        "description": description,
        "os": description,
        "interfaces": [],
        "manufacturer": "Allied Telesis",
        "model": model.group(1) if model else "",
        "serial": "",
    }


_EDGEOS_VERSION_RE = re.compile(r"^\s*Version:\s*(\S+)", re.MULTILINE)
_EDGEOS_MODEL_RE = re.compile(r"^\s*HW model:\s*(\S.*?)\s*$", re.MULTILINE)
_EDGEOS_SERIAL_RE = re.compile(r"^\s*HW S/N:\s*(\S+)", re.MULTILINE)


def parse_edgeos(output: str) -> dict[str, Any]:
    """Ubiquiti EdgeOS (Vyatta-based): ``show version`` with "Version:", "Build ID:", "HW model:".

    "Build ID:" is required next to a Ubiquiti clue, so a plain "Version:"
    (Fortinet, a VyOS) never signs. This path is for the session fallback
    (`parse_session`) and for an EdgeOS whose CLI answers `show version`; an
    EdgeRouter reached by exec is a Linux and is told apart in `parse_linux`.
    The EdgeSwitch IOS-like firmware prints "System Description...." instead
    and is left alone. Format from public forum output, still to be confirmed
    on a real EdgeRouter.
    """
    if not re.search(r"^\s*Build ID\s*:", output, re.MULTILINE):
        return {}
    if not re.search(r"Ubiquiti|EdgeRouter|EdgeOS|^\s*HW model\s*:", output, re.MULTILINE):
        return {}
    version = _EDGEOS_VERSION_RE.search(output)
    model = _EDGEOS_MODEL_RE.search(output)
    serial = _EDGEOS_SERIAL_RE.search(output)
    description = f"EdgeOS {version.group(1)}" if version else "EdgeOS"
    return {
        "family": "edgeos",
        "hostname": "",
        "description": description,
        "os": description,
        "interfaces": [],
        "manufacturer": "Ubiquiti",
        "model": model.group(1) if model else "",
        "serial": serial.group(1) if serial else "",
    }


def parse_show_version(output: str) -> dict[str, Any]:
    """Un solo comando, varios fabricantes: la firma del texto decide.

    `show version` lo entienden IOS, JunOS, ArubaOS, Dell Networking, EXOS,
    ICX, AlliedWare Plus y EdgeOS; una
    conexión por fabricante para repetir el mismo comando serían intentos de
    autenticación de más sin aprender nada nuevo. Cisco va primero por ser lo
    más común; JunOS antes que Aruba y Dell porque su firma es inconfundible. Los
    cuatro últimos (EXOS, ICX, AW+, EdgeOS) van detrás de los que ya existían:
    sus firmas son estrechas y, así, no pueden quitarle un equipo a nadie.
    """
    for parse in (
        parse_cisco,
        parse_junos,
        parse_aruba,
        parse_dell,
        parse_exos,
        parse_icx,
        parse_awplus,
        parse_edgeos,
    ):
        data = parse(output)
        if data:
            return data
    return {}


# --- Los que comparten «display version» ------------------------------------------


def parse_display_version(output: str) -> dict[str, Any]:
    """Huawei (VRP) y HPE/H3C (Comware) comparten mandos —la herencia
    Huawei-3Com— y captura; se distinguen por la firma del banner."""
    huawei = "Versatile Routing Platform" in output or re.search(r"\bVRP\b", output) is not None
    comware = "Comware" in output
    if not huawei and not comware:
        return {}
    banner = next(
        (line.strip() for line in output.splitlines() if "Version" in line and line.strip()),
        "Huawei VRP" if huawei else "Comware",
    )
    return {
        "family": "huawei" if huawei else "comware",
        "hostname": "",
        "description": banner,
        "os": banner,
        "interfaces": [],
        "manufacturer": "Huawei" if huawei else "HPE / H3C",
        "model": "",
        "serial": "",
    }


# --- Los de comando propio ---------------------------------------------------------

_FORTI_VERSION_RE = re.compile(r"^Version:\s*(\S+)\s+(\S+)", re.MULTILINE)
_FORTI_SERIAL_RE = re.compile(r"^Serial-Number:\s*(\S+)", re.MULTILINE)
_FORTI_HOSTNAME_RE = re.compile(r"^Hostname:\s*(\S+)", re.MULTILINE)


def parse_fortinet(output: str) -> dict[str, Any]:
    """Un FortiOS: `get system status` con sus `Version:` y `Serial-Number:`."""
    if "Forti" not in output:
        return {}
    version = _FORTI_VERSION_RE.search(output)
    hostname = _FORTI_HOSTNAME_RE.search(output)
    serial = _FORTI_SERIAL_RE.search(output)
    description = f"{version.group(1)} {version.group(2)}".strip() if version else "FortiOS"
    return {
        "family": "fortinet",
        "hostname": hostname.group(1) if hostname else "",
        "description": description,
        "os": description,
        "interfaces": [],
        "manufacturer": "Fortinet",
        "model": version.group(1) if version else "",
        "serial": serial.group(1) if serial else "",
    }


_GAIA_VERSION_RE = re.compile(r"Product version\s+(.+)$", re.MULTILINE)


def parse_gaia(output: str) -> dict[str, Any]:
    """Un CheckPoint con Gaia: `show version all` en su clish."""
    if "Check Point" not in output and "Gaia" not in output:
        return {}
    version = _GAIA_VERSION_RE.search(output)
    description = version.group(1).strip() if version else "Check Point Gaia"
    return {
        "family": "gaia",
        "hostname": "",
        "description": description,
        "os": description,
        "interfaces": [],
        "manufacturer": "Check Point",
        "model": "",
        "serial": "",
    }


def parse_esxi(output: str) -> dict[str, Any]:
    """Un ESXi por su consola: se identifica, pero no se captura — su
    «configuración» es un `state.tgz` binario, no un volcado de texto, y su
    inventario de verdad ya llega mejor por el colector de hipervisores."""
    if "VMware ESXi" not in output:
        return {}
    description = next(
        (line.strip() for line in output.splitlines() if "VMware ESXi" in line),
        "VMware ESXi",
    )
    return {
        "family": "esxi",
        "hostname": "",
        "description": description,
        "os": description,
        "interfaces": [],
        "manufacturer": "VMware",
        "model": "",
        "serial": "",
    }


#: El orden es el orden en que se prueban, y no es arbitrario: en la red de una
#: pyme hay muchos más Linux que equipos de red, y cada intento fallido es una
#: conexión. Detrás de Linux, los grupos por comando compartido; al final, los
#: fabricantes de comando propio, que son los menos comunes.
FAMILIES: tuple[Family, ...] = (
    Family("linux", LINUX_COMMAND, parse_linux),
    Family("show-version", "show version", parse_show_version),
    Family("display-version", "display version", parse_display_version),
    Family("mikrotik", MIKROTIK_COMMAND, parse_mikrotik),
    Family("fortinet", "get system status", parse_fortinet),
    Family("gaia", "show version all", parse_gaia),
    Family("esxi", "vmware -v", parse_esxi),
)

#: El comando que vuelca la configuración de cada familia, para la copia con
#: historial y diff. Quien no está aquí no captura, y es deliberado: la
#: «configuración» de un Linux no es un archivo, y la de un ESXi es un tgz
#: binario — fingir que se copian sería prometer una copia que no restaura.
#:
#: `show running-config` en IOS puede paginar en algún equipo raro por canal
#: exec; si pagina, el timeout de `ssh.run` lo corta y esa copia simplemente
#: no sale (con su línea en errors), nunca sale truncada en silencio.
CAPTURE_COMMANDS: dict[str, str] = {
    "cisco": "show running-config",
    "mikrotik": "/export",
    "aruba": "show running-config",
    "junos": "show configuration | display set",
    "dell": "show running-config",
    "huawei": "display current-configuration",
    "comware": "display current-configuration",
    "fortinet": "show full-configuration",
    "gaia": "show configuration",
    # EXOS pages unless `disable clipaging` was sent; the exec channel has no
    # tty and the session fallback switches paging off (`sshshell.PAGING_OFF`).
    "exos": "show configuration",
    # Privileged exec needed; ICX paging is off in the fallback (`skip-page-display`).
    "icx": "show running-config",
    "awplus": "show running-config",
    # An exec channel is a plain shell where `show` does not exist: the Vyatta
    # op-mode wrapper is what runs it (also fine inside an interactive session).
    "edgeos": "/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration",
}

#: La orden que vuelca la configuración **guardada** --la que el equipo carga al
#: reiniciar-- en las familias que la distinguen de la que está en marcha. Con
#: las dos, el servidor compara y avisa de lo que un reinicio perdería (el
#: puerto que alguien abrió y no guardó con `write memory`). Quien no está aquí
#: no la tiene, y es deliberado: MikroTik, Fortinet y Gaia guardan al aplicar,
#: así que no hay segundo texto; y la «candidata» de Junos es un borrador, no
#: lo que carga al arrancar. Para ellos el hallazgo va sin la clave.
SAVED_CONFIG_COMMANDS: dict[str, str] = {
    "cisco": "show startup-config",
    "aruba": "show startup-config",
    "dell": "show startup-config",
    "huawei": "display saved-configuration",
    "comware": "display saved-configuration",
}

#: Techo por copia. El mismo número que `core.discovery.MAX_CONFIG_BYTES`: el
#: agente no puede importarlo --no tiene Django-- así que se repite aquí. Se
#: aplica por separado a la que está en marcha y a la guardada.
MAX_CONFIG_BYTES = 256 * 1024

#: Lo que una CLI de red imprime cuando la orden no existe o no está permitida
#: (IOS y Comware «% Invalid/Unrecognized…», Huawei «Error: Unrecognized
#: command», Aruba «Invalid input»). Para `ssh` eso es «entré y me contestó»:
#: salida no vacía. Mandarla como configuración guardada haría al servidor
#: comparar un mensaje de error con una configuración y avisar de cambios sin
#: guardar que no existen.
_CLI_REJECTION_RE = re.compile(
    r"^\s*(?:%+\s*(?:Invalid|Ambiguous|Incomplete|Unrecognized|Unknown|Error|Authorization|Access denied)"
    r"|Error:\s*Unrecognized|Invalid input|Unknown command|Line has invalid autocommand"
    r"|Command authorization failed|Not authorized|Insufficient privilege|Permission denied"
    r"|[^\n]*command not found)",
    re.IGNORECASE | re.MULTILINE,
)

#: Dell OS6 echoes the command before refusing it, on the same line
#: (``show running-config : Command Is Not Authorized``, 09-10-2026), so this
#: one is looked for anywhere in the line, not only at its start.
_CLI_REFUSAL_ANYWHERE_RE = re.compile(r"command (?:is )?not authori[sz]ed|insufficient privilege", re.IGNORECASE)

#: What surrounds a refusal in a session without being configuration: the
#: prompt (``<SW-Huawei-01>``, ``SW-1#``), the caret under the bad word, and a
#: Huawei's login banner (``Info: The max number of VTY users…``, ``The current
#: login time is…``). Set aside before counting lines: with them, a Huawei's
#: «Unrecognized command» was nine lines long and passed for a configuration.
_REFUSAL_SURROUNDINGS_RE = re.compile(
    r"^(?:<[^<>]+>|\[[^\[\]]+\]|\S+[#>]|\^|info:.*|the current login time is.*)$", re.IGNORECASE
)

#: Una respuesta de rechazo son una o dos líneas. Una configuración de verdad
#: son decenas, y así una que cite «Error:» en un banner no se confunde.
_REJECTION_MAX_LINES = 5

#: The families whose CLI has a user mode (``SW>``) and a privileged one
#: (``SW#``) reached with `enable`, where reading the configuration needs the
#: second. A capture inside a session asks for `enable` when the prompt says
#: user mode (`sshshell.unprivileged`).
ENABLE_FAMILIES: frozenset[str] = frozenset({"cisco", "dell", "aruba", "icx", "awplus"})


#: The extra order that lists the units of a stack, for the families whose
#: detection output does not. Cisco needs none: its `show version` already
#: lists every unit with its serial. Dell asks only when its `show version`
#: described a single unit (some OS6 releases print just the management one).
#: Comware adds `display device manuinfo` for the serials, and only when
#: `display irf` showed two or more members: a lone switch costs one order.
STACK_COMMANDS: dict[str, str] = {
    "dell": "show switch",
    "aruba": "show stacking",
    "junos": "show virtual-chassis",
    "comware": "display irf",
}
COMWARE_MANUINFO_COMMAND = "display device manuinfo"


def _ask(host: str, credential: creds.Credential, command: str, logins: tasking.Logins | None) -> str:
    """The output of one more order with the credential that got in, or ""
    when it did not connect, was skipped or the CLI rejected the order."""
    answer = _login(logins, host, credential, command)
    if answer is tasking.SKIPPED or not answer.connected:
        return ""
    output = answer.output or ""
    return "" if rejected_by_cli(output) else output


def stack_members(
    host: str, credential: creds.Credential, data: dict[str, Any], logins: tasking.Logins | None = None
) -> dict[str, Any]:
    """``data`` with ``members`` when the device is a stack of two or more.

    One more connection with **the credential that already got in** (never
    another one: that would be failed logins for nothing), only for the
    families in ``STACK_COMMANDS`` and only when detection did not already
    bring the members. When the main serial or model is missing, the master's
    fills it. Nothing here raises: a stack we cannot read is a host without
    ``members``, and the server deduces the units from the port names.
    """
    family = str(data.get("family") or "")
    command = STACK_COMMANDS.get(family)
    if not command or data.get("members"):
        return data
    try:
        output = _ask(host, credential, command, logins)
        if not output:
            return data
        serial = str(data.get("serial") or "")
        if family == "dell":
            members = stacks.dell_members_from_switch(output, serial)
        elif family == "aruba":
            members = stacks.aruba_members(output)
        elif family == "junos":
            members = stacks.junos_members(output)
            # A standalone EX answers too, with one row: its serial is worth
            # keeping, since JunOS `show version` has none.
            serial = serial or stacks.junos_master_serial(output)
        else:
            members = stacks.irf_members(output)
            if members:
                manuinfo = _ask(host, credential, COMWARE_MANUINFO_COMMAND, logins)
                if manuinfo:
                    stacks.add_manuinfo(members, manuinfo)
    except Exception:  # noqa: BLE001 - the units are an extra; never lose the host for them
        return data
    master = next((m for m in members if m["role"] == stacks.MASTER), None)
    enriched = {**data, "serial": serial or (master["serial"] if master else "")}
    if not enriched.get("model") and master is not None:
        enriched["model"] = master["model"]
    if members:
        enriched["members"] = members
    return enriched


def with_tables(
    host: str, credential: creds.Credential, data: dict[str, Any], logins: tasking.Logins | None = None
) -> dict[str, Any]:
    """``data`` with its ``arp`` and ``fdb`` (``agent.tables``), read with
    the credential that already got in. Nothing here raises: a device whose
    tables cannot be read is a host without them."""
    family = str(data.get("family") or "")
    if family not in tables.ARP_COMMANDS and family not in tables.MAC_COMMANDS:
        return data
    try:
        found = tables.read_tables(family, lambda command: _ask(host, credential, command, logins))
    except Exception:  # noqa: BLE001
        return data
    return {**data, **found} if found else data


def _as_snmp_shape(data: dict[str, Any]) -> dict[str, Any]:
    """The SSH answer in the shape ``collectors.snmp`` reads: the port name is
    its own index, so the forwarding rows (``ifindex`` = port) resolve."""
    ports = {row["ifindex"] for row in data.get("fdb") or []}
    return {
        "name": data.get("hostname", ""),
        "interfaces": [{"index": port, "name": port} for port in sorted(ports)],
        "neighbors": [],
        "fdb": data.get("fdb") or [],
        "arp": data.get("arp") or [],
    }



# --- El colector ----------------------------------------------------------------


_SYSTEM_DESCRIPTION_RE = re.compile(r"^\s*System Description\s*[:.]*\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)
_SW_VERSION_RE = re.compile(r"^\s*(?:SW version|Software version|Version)\s*[:.]*\s*(\S.*?)\s*$", re.MULTILINE | re.IGNORECASE)


def parse_session(output: str) -> dict[str, Any]:
    """What an interactive session said (`agent.sshshell`).

    First the vendors that sign their answer; if none does, the device still
    presented itself -- a CLI answered with its name in the prompt -- and that
    is enough to stop being «solo responde»: its name, and the line that says
    what it is if there is one. The name in the prompt also fills the
    hostname a vendor parser left empty.
    """
    name = sshshell.prompt_name(output)
    for parse in (parse_display_version, parse_show_version):
        data = parse(output)
        if data:
            return {**data, "hostname": data.get("hostname") or name}
    if not name:
        return {}
    described = _SYSTEM_DESCRIPTION_RE.search(output) or _SW_VERSION_RE.search(output)
    description = described.group(1)[:200] if described else ""
    return {
        "family": "cli",
        "hostname": name,
        "description": description,
        "os": description,
        "interfaces": [],
        "manufacturer": "",
        "model": "",
        "serial": "",
    }


#: Where each family keeps its name when its version answer does not say it
#: (Dell OS6 and Aruba: `show system`; VRP and Comware: the sysname line).
NAME_COMMANDS: dict[str, str] = {
    "dell": "show system",
    "aruba": "show system",
    "huawei": "display current-configuration | include sysname",
    "comware": "display current-configuration | include sysname",
}
_SYSTEM_NAME_RE = re.compile(r"^\s*System Name\s*[.:]+\s*(\S.*?)\s*$", re.MULTILINE | re.IGNORECASE)
_SYSNAME_RE = re.compile(r"^\s*sysname\s+(\S+)", re.MULTILINE)


def parse_name(output: str) -> str:
    """The device's name out of `show system` or the sysname line, or empty."""
    found = _SYSTEM_NAME_RE.search(output) or _SYSNAME_RE.search(output)
    return found.group(1).strip()[:200] if found else ""


def _with_name(host: str, credential: creds.Credential, data: dict[str, Any], logins: tasking.Logins | None) -> dict[str, Any]:
    """`data` with its hostname asked for, when the family knows where (08-10-2026).

    A second login with the credential that just got in, like the config
    capture does: a device without a name enters the tray as «Sin nombre», and
    that is what the person sees first.
    """
    command = NAME_COMMANDS.get(str(data.get("family") or ""), "")
    if data.get("hostname") or not command:
        return data
    answer = _login(logins, host, credential, command)
    if answer is tasking.SKIPPED or not answer.connected:
        return data
    output = answer.output or ""
    if not output.strip() and _wants_session(answer):
        session = _session(logins, host, credential, commands=(*sshshell.PAGING_OFF, command))
        if session is tasking.SKIPPED or not session.connected:
            return data
        output = sshshell.command_output(session.output, command)
    name = parse_name(output)
    if not name:
        return data
    described = _dotted_value(output, "System Description")
    return {**data, "hostname": name, **({"description": described} if described and not data.get("description") else {})}


def _wants_session(answer: Any) -> bool:
    """When the plain command did not work but a session might.

    It got in and no family recognised the answer (empty: the device only
    talks inside a terminal; unknown: the prompt still says its name), SSH
    authenticated and then the command hung (a PowerConnect asks for the user
    inside the session), or it closed without a clear «Permission denied».
    Never after a clear denial or before the login was offered: that would be
    a failed try more.
    """
    if answer is tasking.SKIPPED or answer is None:
        return False
    if answer.connected or getattr(answer, "authenticated", False):
        return True
    error = (answer.error or "").lower()
    return not answer.unreachable and "permission denied" not in error and "too many" not in error


def interrogate(
    host: str, credentials: list[creds.Credential], logins: tasking.Logins | None = None
) -> tuple[dict[str, Any], creds.Credential | None]:
    """Lo que ese equipo cuenta de sí mismo, y con qué credencial se entró.

    Se prueba credencial por credencial hasta que una entra; **con la primera
    que entra se deja de probar**, aunque su familia no diga nada. Seguir
    probando contra un equipo donde ya se ha entrado son intentos fallidos de
    autenticación de más, y contra un Directorio Activo eso bloquea cuentas.

    La credencial vuelve con los datos porque la captura de configuración
    reutiliza **exactamente la que funcionó**: probar otras sería engordar la
    misma cuenta de intentos fallidos que este bucle se cuida de no engordar.

    Cada inicio de sesión pasa por `logins` (el límite global de credenciales,
    spec 2.3): una credencial suspendida se salta sin intentarlo.
    """
    for credential in credentials:
        connected = False
        answer: Any = None
        for family in FAMILIES:
            answer = _login(logins, host, credential, family.command)
            if answer is tasking.SKIPPED or not answer.connected:
                break
            connected = True
            data = family.parse(answer.output)
            if data:
                # El analizador puede afinar la familia (un `show version`
                # sirve a cuatro fabricantes); si no lo hace, vale la del
                # intento.
                data = {**data, "family": data.get("family", family.name)}
                return _with_name(host, credential, data, logins), credential
        if _wants_session(answer):
            session = _session(logins, host, credential)
            if session is not tasking.SKIPPED and session.connected:
                data = parse_session(session.output)
                return (_with_name(host, credential, data, logins) if data else data), credential
        if connected:
            return {}, credential
    return {}, None


def _session(
    logins: tasking.Logins | None,
    host: str,
    credential: creds.Credential,
    commands: tuple[str, ...] = sshshell.IDENTIFY,
    enable: bool = False,
) -> Any:
    """Una sesión interactiva (`agent.sshshell`), por el límite de credenciales si lo hay."""

    def call() -> ssh.Answer:
        return sshshell.run(
            host=host,
            username=credential.username,
            secret=credential.secret,
            port=credential.port,
            key_file=credential.key_file,
            commands=commands,
            enable=enable,
        )

    if logins is None:
        return call()
    return logins.run(credential, call, ssh.outcome)


def _login(logins: tasking.Logins | None, host: str, credential: creds.Credential, command: str) -> Any:
    """Un `ssh.run`, por el límite de credenciales si lo hay. `tasking.SKIPPED` si no toca."""

    def call() -> ssh.Answer:
        return ssh.run(
            host=host,
            username=credential.username,
            secret=credential.secret,
            port=credential.port,
            key_file=credential.key_file,
            command=command,
        )

    if logins is None:
        return call()
    return logins.run(credential, call, ssh.outcome)


def fetch_config(
    host: str,
    credential: creds.Credential,
    command: str,
    logins: tasking.Logins | None = None,
    enable: bool = False,
) -> str:
    """La configuración del equipo, o "". Nunca truncada en silencio.

    Si la orden suelta no contesta (un Huawei, un PowerConnect: ver
    `agent.sshshell`), se pide dentro de una sesión, con la paginación apagada.

    Con ``enable`` (las familias de `ENABLE_FAMILIES`), una orden suelta que el
    equipo **rechaza** también pasa a la sesión: allí se lee el indicador y, si
    dice modo usuario (``SW>``), se entra con `enable` antes de pedirla. Por el
    canal suelto no hay forma de hacerlo: cada orden es una conexión nueva que
    vuelve a empezar en modo usuario.
    """
    answer = _login(logins, host, credential, command)
    if answer is tasking.SKIPPED:
        return ""
    output = (answer.output or "") if answer.connected else ""
    needs_session = not output.strip() and _wants_session(answer)
    refused_here = enable and answer.connected and rejected_by_cli(output)
    if needs_session or refused_here:
        session = _session(logins, host, credential, commands=(*sshshell.PAGING_OFF, command), enable=enable)
        if session is tasking.SKIPPED or not session.connected:
            # A refusal stays what it was: the caller notes the missing privilege.
            return output if refused_here else ""
        in_session = sshshell.command_output(session.output, command)
        output = in_session if in_session.strip() or not refused_here else output
    if len(output.encode()) > MAX_CONFIG_BYTES:
        # Una configuración de pyme cabe de sobra en 256 KB; algo mayor es
        # otra cosa (un volcado, un banner infinito) y guardar media copia
        # sería peor que no guardarla: parecería completa.
        return ""
    return output


def rejected_by_cli(output: str) -> bool:
    """Si esa salida es la CLI diciendo «esa orden no existe aquí», no una copia.

    Los indicadores, el ``^`` y el banner de entrada no cuentan como líneas:
    rodean al rechazo sin ser configuración.
    """
    lines = [
        line
        for line in output.splitlines()
        if line.strip() and not _REFUSAL_SURROUNDINGS_RE.match(line.strip())
    ]
    if not 0 < len(lines) <= _REJECTION_MAX_LINES:
        return False
    kept = "\n".join(lines)
    return _CLI_REJECTION_RE.search(kept) is not None or _CLI_REFUSAL_ANYWHERE_RE.search(kept) is not None


def fetch_configs(
    host: str,
    credential: creds.Credential,
    family: str,
    logins: tasking.Logins | None = None,
    errors: list | None = None,
    reidentify: bool = True,
) -> dict[str, str]:
    """Las copias de ese equipo para el hallazgo `config`: ``config`` y, en las
    familias que la distinguen, ``saved_config``.

    **Una familia equivocada se corrige aquí** (09-10-2026): la tarea `configs`
    usa la familia que la memoria apuntó, y un Huawei apuntado como Cisco por
    una versión antigua del agente recibía `show running-config` cada noche y
    contestaba «Unrecognized command». Si el equipo rechaza la orden, se le
    vuelve a preguntar quién es con la misma credencial; si es otra familia
    con copia, se pide con la suya y el resultado lleva ``family`` con la
    buena, para el hallazgo y para la memoria. Una sola vez: si tampoco, es
    falta de permiso de verdad y se anota.

    Vacío si la que está en marcha no sale: sin ella no hay copia. La guardada
    es un extra encima: si la orden falla, vuelve vacía, pasa del tope o la CLI
    la rechaza, el hallazgo va **sin la clave** --nunca con una cadena vacía:
    para el servidor «sin clave» es «no lo sé» y una vacía sería «no hay nada
    guardado»--, se anota y se sigue. Nada de aquí tumba el colector.

    Es una **segunda conexión** con la misma credencial: `ssh.run` es un proceso
    `ssh` por orden, sin sesión que mantener, y en un IOS no se pueden encadenar
    dos órdenes en un canal exec. Reutilizar la conexión sería reescribir el
    transporte (ControlMaster) para ahorrar un inicio de sesión que ya entró.
    """
    command = CAPTURE_COMMANDS.get(family, "")
    if not command:
        return {}
    enable = family in ENABLE_FAMILIES
    running = fetch_config(host, credential, command, logins, enable=enable)
    if not running.strip():
        return {}
    if rejected_by_cli(running) and reidentify:
        data, _credential = interrogate(host, [credential], logins)
        actual = str((data or {}).get("family") or "")
        if actual and actual != family and actual in CAPTURE_COMMANDS:
            copies = fetch_configs(host, credential, actual, logins, errors, reidentify=False)
            return {**copies, "family": actual} if copies else {}
    if rejected_by_cli(running):
        # The device refused the order: on Dell OS6 and Cisco that is a user
        # without privilege (level 15) to see the configuration. The refusal
        # is not a copy, and sending it as one stored «% Invalid input» as
        # the device's configuration.
        if errors is not None:
            errors.append(
                collector_note(
                    "ssh",
                    "config_needs_privilege",
                    f"{host}: el usuario SSH entra sin privilegios y el equipo no le enseña la configuración",
                    ip=host,
                )
            )
        return {}
    copies = {"config": running}
    saved_command = SAVED_CONFIG_COMMANDS.get(family, "")
    if not saved_command:
        return copies
    try:
        saved = fetch_config(host, credential, saved_command, logins, enable=enable)
    except Exception:  # noqa: BLE001 - la guardada es un extra; nunca se lleva por delante la copia
        saved = ""
    if saved.strip() and not rejected_by_cli(saved):
        copies["saved_config"] = saved
    elif errors is not None:
        errors.append(
            collector_note(
                "ssh",
                "saved_config_unavailable",
                f"{host}: no entregó la configuración guardada («{saved_command}»); la copia va sin ella",
                ip=host,
                family=family,
                command=saved_command,
            )
        )
    return copies


def _capture_enabled(ctx: dict) -> bool:
    """Si el servidor lo dice, manda; si no, la variable de entorno; y el
    valor de fábrica es encendido: es la mitad del valor del agente."""
    config = ctx.get("config") or {}
    if "capture_configs" in config:
        return bool(config["capture_configs"])
    env = ctx.get("env")
    return bool(getattr(env, "capture_configs", True))


@register
class SshCollector:
    name = "ssh"

    def collect(self, ctx: dict) -> list[Finding]:
        errors = ctx.setdefault("errors", [])
        if not ssh.AVAILABLE:
            errors.append(
                collector_note("ssh", "missing_binary", "no hay binario «ssh» en esta máquina (OpenSSH no está instalado)")
            )
            return []
        if "hosts" not in ctx:
            # El mismo fallo que dejó SNMP mudo: sin el barrido delante no hay a
            # quién llamar, y callarse aquí marca la ejecución como correcta.
            errors.append(
                collector_note(
                    "ssh", "sweep_not_run", "el barrido no ha corrido antes; revisa RUN_ORDER en agent/collectors."
                )
            )
            return []
        credentials = creds.for_kind(ctx, creds.SSH)
        if not credentials:
            errors.append(
                collector_note("ssh", "no_credentials", "no hay credenciales SSH configuradas (Ajustes -> Agentes -> Barrido)")
            )
            return []
        if not ssh.PASSWORD_AUTH_AVAILABLE and any(credential.secret for credential in credentials):
            # No es un error que pare nada: las credenciales con clave siguen
            # funcionando. Se dice porque, si no, el usuario ve «no entró en
            # ningún equipo» y no sabe por qué. Y se dice lo cierto: con un
            # OpenSSH anterior a 8.4 lo que arregla esto es actualizarlo.
            if ssh.VERSION is not None and ssh.VERSION < ssh.MIN_ASKPASS_VERSION:
                errors.append(
                    collector_note(
                        "ssh",
                        "password_auth_unavailable",
                        f"hay credenciales con contraseña pero el OpenSSH instalado ({ssh.VERSION[0]}.{ssh.VERSION[1]}) "
                        "es anterior a 8.4 y no sirve para ellas; actualízalo o instala «sshpass»; solo se usarán las de clave",
                        version=f"{ssh.VERSION[0]}.{ssh.VERSION[1]}",
                    )
                )
            else:
                errors.append(
                    collector_note(
                        "ssh", "sshpass_missing", "hay credenciales con contraseña y falta «sshpass»; solo se usarán las de clave"
                    )
                )

        hosts = ctx["hosts"] or []
        if not hosts:
            return []
        task = tasking.task(ctx)
        if task == "configs":
            return self._configs(ctx, credentials)
        by_ip = {
            host["ip"]: host.get("mac", "") for host in hosts if host.get("ip") and tasking.wanted(ctx, host["ip"])
        }

        # Qué puertos se sondean sale de las credenciales, no de una constante.
        # Con el 22 fijo, un servidor con SSH en el 2222 --que es de lo más
        # común-- se caía de la lista **aquí**, antes de que nadie llegara a
        # probar su credencial, y sin dejar ni una línea en `errors`: cero
        # hallazgos y ningún motivo. El mismo fallo mudo que dejó SNMP inerte.
        ports = {credential.port or SSH_PORT for credential in credentials}
        open_ports: dict[str, set[int]] = {}
        for port in sorted(ports):
            for ip in net.hosts_listening(list(by_ip), port, **tasking.listen_options(ctx)):
                open_ports.setdefault(ip, set()).add(port)
        reachable = [ip for ip in by_ip if ip in open_ports]
        if not reachable:
            return []

        def usable(ip: str) -> list[creds.Credential]:
            """Las credenciales cuyo puerto está abierto en ese equipo.

            Una sin puerto vale para el de siempre; una que lo trae escrito solo
            vale para el suyo. Probar las demás son intentos de autenticación de
            más contra un equipo que no los va a atender, y esa es justo la
            cuenta que `interrogate` se cuida de no engordar.
            """
            return [c for c in credentials if (c.port or SSH_PORT) in open_ports[ip]]

        progress = tasking.Progress(ctx, self.name, len(reachable))

        def visit(ip: str) -> tuple[dict[str, Any], creds.Credential | None]:
            """Un equipo: qué credenciales tocan (alcance y memoria), y entrar."""
            try:
                order, full = tasking.plan(ctx, ip, by_ip[ip], "ssh", usable(ip))
                if not order:
                    # La memoria dice que hoy no toca: ni un intento, y no es
                    # un error que anotar.
                    return {}, None
                logins = tasking.Logins(ctx, self.name, "ssh", ip, by_ip[ip])
                data, credential = interrogate(ip, order, logins)
                # Una credencial saltada por el límite global no es una ronda
                # entera: no se apunta como fallida.
                full = full and not logins.skipped
                tasking.settle(ctx, ip, by_ip[ip], "ssh", credential, attempted=True, full=full)
                if credential is not None and not data:
                    # Entró, pero ninguna orden conocida le sirvió: sin esto el
                    # equipo desaparecía sin rastro (08-10-2026, un Huawei).
                    tasking.record(ctx, ip, "ssh", tasking.UNRECOGNISED, credential)
                if data and credential is not None:
                    # A stack answers as one host: ask for its units, with the
                    # same credential, after the login rounds are settled.
                    data = stack_members(ip, credential, data, logins)
                    # And its ARP and MAC tables (phase 4): the firewall that
                    # knows who is in the network, the switch without SNMP.
                    data = with_tables(ip, credential, data, logins)
                return data, credential
            finally:
                progress.tick()

        answers = map_with_deadline(
            tasking.workers(ctx, "login", WORKERS), visit, list(reachable), ({}, None), errors
        )

        # En la tarea `inventory` se interroga pero no se copia: la copia es
        # de la tarea `configs`, una vez al día, con la credencial que entró hoy.
        capture = _capture_enabled(ctx) and task != "inventory"
        findings: list[Finding] = []
        # MACs this sweep knows, for the links the MAC tables propose: the
        # live hosts, the devices themselves, and what their ARP tables say
        # (same rule as the SNMP collector: what the sweep saw wins).
        known: dict[str, dict[str, str]] = {}
        for host in hosts:
            if host.get("mac"):
                known[host["mac"]] = {"ip": host["ip"], "hostname": ""}
        for ip, (data, _credential) in zip(reachable, answers):
            for iface in data.get("interfaces") or [] if data else []:
                if iface.get("mac"):
                    known.setdefault(iface["mac"], {"ip": ip, "hostname": data.get("hostname", "")})
        for mac, ips in _arp_ips({ip: data for ip, (data, _c) in zip(reachable, answers) if data}).items():
            if mac not in known:
                known[mac] = {"ip": sorted(ips)[0] if len(ips) < ROUTER_MIN_IPS else "", "hostname": ""}
        for ip, (data, credential) in zip(reachable, answers):
            if not data:
                continue
            sweep_mac = by_ip.get(ip, "")
            own_mac = next((iface["mac"] for iface in data.get("interfaces") or [] if iface.get("mac")), "")
            # La identidad prefiere la MAC **que vio el barrido**, no la primera
            # que devuelve el equipo: la huella se calcula de aquí, y elegir otra
            # MAC del mismo equipo abriría una segunda fila en la bandeja para
            # algo que ya está ahí. Es el fallo silencioso que este orden evita.
            identity = {"mac": sweep_mac or own_mac} if (sweep_mac or own_mac) else {"ip": ip}
            if credential is not None:
                # Para la tarea `configs`: qué familia es (un equipo de red con
                # comando de copia, o nada) y con qué identidad se presentó.
                family = data.get("family", "")
                tasking.flag(
                    ctx,
                    ip,
                    sweep_mac,
                    config_family=family if family in CAPTURE_COMMANDS else "",
                    identity_mac=sweep_mac or own_mac,
                )
            findings.append(
                Finding(
                    kind="host",
                    identity=identity,
                    payload={
                        "hostname": data.get("hostname", ""),
                        "ip": ip,
                        "mac": sweep_mac or own_mac,
                        "description": data.get("description", ""),
                        "os": data.get("os", ""),
                        "manufacturer": data.get("manufacturer", ""),
                        "model": data.get("model", ""),
                        "serial": data.get("serial", ""),
                        "interfaces": data.get("interfaces") or [],
                        "family": data.get("family", ""),
                        "seen_by": "ssh",
                        # Only for a stack of two or more units; never an
                        # empty list (for the server, no key is "a single unit").
                        **({"members": data["members"]} if data.get("members") else {}),
                        # Its tables, when it has them (phase 4), in the shape
                        # of the SNMP finding: the server places devices behind
                        # ports with them, and puts IPs to MACs.
                        **({"arp": data["arp"]} if data.get("arp") else {}),
                        **({"fdb_ports": ports} if (ports := _port_tables(_as_snmp_shape(data))) else {}),
                    },
                )
            )
            if data.get("fdb"):
                findings.extend(_links_for(ip, _as_snmp_shape(data), sweep_mac or own_mac, known))

            # La copia de configuración, con la misma credencial que entró.
            # Solo las familias que tienen comando (equipos de red): la del
            # Linux no es un archivo, y no se finge que lo sea. El hallazgo
            # «config» no pasa por la bandeja: el servidor lo adjunta directo
            # al equipo ya inventariado, y solo cuando el contenido cambió.
            # Donde la familia distingue la guardada, va también (`saved_config`).
            family = data.get("family", "")
            if not capture or credential is None or family not in CAPTURE_COMMANDS:
                continue
            copies = fetch_configs(ip, credential, family, tasking.Logins(ctx, self.name, "ssh", ip, sweep_mac), errors)
            if not copies:
                continue
            family = copies.pop("family", family)
            findings.append(
                Finding(
                    kind="config",
                    identity=identity,
                    payload={
                        **copies,
                        "family": family,
                        "hostname": data.get("hostname", ""),
                        "ip": ip,
                        "mac": sweep_mac or own_mac,
                    },
                )
            )
        return findings

    def capture(self, ctx: dict, only: Collection[str]) -> list[Finding]:
        """Las copias de **esos** equipos, por el mismo camino que la tarea `configs`.

        Es lo que usa `agent.confwatch` cuando un equipo avisa de que su
        configuración cambió: la misma credencial recordada, las mismas
        órdenes y el mismo hallazgo `config`, sin esperar a la copia nocturna
        y sin tocar al resto. Sin credenciales SSH no hace nada ni lo anota:
        ya lo anota la tarea que las necesita.
        """
        credentials = creds.for_kind(ctx, creds.SSH)
        if not credentials or not only:
            return []
        return self._configs(ctx, credentials, only=only)

    def _configs(
        self, ctx: dict, credentials: list[creds.Credential], only: Collection[str] | None = None
    ) -> list[Finding]:
        """La tarea `configs`: solo la copia, solo donde ya se entró.

        Sobre los equipos de red que la memoria apuntó en el inventario y que
        siguen vivos, con **la credencial que entró entonces** y ninguna otra:
        sin interrogar, sin sondear puertos y sin rondas. Un equipo cuya
        credencial ya no está en la lista (alguien la borró) se salta: probar
        otras aquí sería justo el ruido que esta tarea existe para no hacer.
        """
        mem = tasking.memory(ctx)
        if mem is None or not _capture_enabled(ctx):
            return []
        errors = ctx.setdefault("errors", [])
        jobs: list[tuple[str, str, dict, creds.Credential, str]] = []
        for ip, mac, entry in tasking.alive_from_memory(ctx, mem.config_hosts()):
            family = str(entry.get("family") or "")
            if family not in CAPTURE_COMMANDS or (only is not None and ip not in only):
                continue
            ident = mem.remembered(tasking.host_key(ctx, ip, mac), "ssh")
            credential = next(
                (c for c in credentials if ident and c.ident == ident and c.covers(ip)),
                None,
            )
            if credential is None:
                continue
            jobs.append((ip, mac, entry, credential, family))
        if not jobs:
            return []

        progress = tasking.Progress(ctx, self.name, len(jobs))

        def fetch(job: tuple[str, str, dict, creds.Credential, str]) -> dict[str, str]:
            ip, mac, _entry, credential, family = job
            try:
                return fetch_configs(ip, credential, family, tasking.Logins(ctx, self.name, "ssh", ip, mac), errors)
            finally:
                progress.tick()

        contents = map_with_deadline(tasking.workers(ctx, "login", WORKERS), fetch, jobs, {}, errors)

        findings: list[Finding] = []
        for (ip, mac, entry, _credential, family), copies in zip(jobs, contents):
            if not copies:
                continue
            actual = copies.pop("family", family)
            if actual != family:
                # The memory had it wrong: next night, straight with the right one.
                tasking.flag(ctx, ip, mac, config_family=actual)
                family = actual
            # La misma identidad con la que el inventario presentó al equipo:
            # el servidor cuelga la copia de esa fila.
            identity_mac = str(entry.get("identity_mac") or "") or mac
            identity = {"mac": identity_mac} if identity_mac else {"ip": ip}
            findings.append(
                Finding(
                    kind="config",
                    identity=identity,
                    payload={
                        **copies,
                        "family": family,
                        # Esta tarea no interroga, así que no sabe el nombre;
                        # el servidor engancha la copia por la identidad.
                        "hostname": "",
                        "ip": ip,
                        "mac": identity_mac,
                    },
                )
            )
        return findings
