"""Redfish: lo que la tarjeta de control remoto de un servidor dice de él.

iDRAC (Dell), iLO (HPE), XClarity (Lenovo), iRMC (Fujitsu) y las BMC de
Supermicro hablan el mismo estándar: HTTPS y JSON bajo ``/redfish/v1``. Con el
usuario de la tarjeta se lee, en pocas peticiones:

- el servidor que la lleva (``Systems``): fabricante, modelo, número de serie,
  nombre y si está encendido;
- la tarjeta (``Managers``): su versión;
- sus fuentes de alimentación y su estado (``Chassis/…/Power``);
- las MAC de las tarjetas de red del servidor (``Systems/…/EthernetInterfaces``).

El contrato con el servidor está en ``redfish-contrato.md`` del repositorio del
servidor. Tres reglas de este módulo:

* **El certificado se fija la primera vez, como SSH** (decidido el 11-10-2026).
  Cada tarjeta trae uno propio que el equipo del agente no conoce. La primera
  conexión lee su huella sin mandar nada (`tlspin.describe`); desde entonces
  solo se habla con ese certificado (`tlspin.PinnedHTTPSHandler`), y si cambia
  la contraseña no sale.
* **Solo se siguen enlaces de la propia tarjeta**: un ``@odata.id`` que no
  empieza por ``/redfish/v1/`` se ignora, así una respuesta no puede mandar al
  agente, con la contraseña, a otro sitio.
* **Nada lanza hacia fuera** salvo `RedfishError`, con un código estable.

Las funciones de lectura (`identity`, `power_supplies`, `nics`) son puras: JSON
dentro, diccionarios fuera, para probarlas con respuestas reales.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from agent import tlspin

ROOT = "/redfish/v1/"
TIMEOUT_SECONDS = 10
#: Una respuesta de Redfish de verdad cabe en esto con mucho margen.
MAX_BYTES = 2 * 1024 * 1024
#: Tarjetas de red y fuentes que se miran como mucho.
MAX_NICS = 32
MAX_SUPPLIES = 16

# Los códigos de fallo: los mismos que la línea de «Probar» en el servidor.
AUTH_FAILED = "auth_failed"
UNREACHABLE = "unreachable"
NOT_REDFISH = "not_redfish"
CERTIFICATE_CHANGED = "certificate_changed"

#: El nombre de la tarjeta por fabricante, que es el del puerto en la ficha.
CARDS_BY_MAKER = (("dell", "iDRAC"), ("hpe", "iLO"), ("hewlett", "iLO"), ("lenovo", "XCC"), ("fujitsu", "iRMC"))
#: Los nombres que el servidor acepta en ``redfish.card``.
CARDS = ("iDRAC", "iLO", "XCC", "IMM", "iRMC", "BMC")


class RedfishError(Exception):
    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


@dataclass
class Answer:
    """Lo que devolvió una tarjeta. ``certificate`` solo cuando el certificado
    cambió (para que el registro de intentos lo cuente como ``tls_untrusted``)."""

    connected: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    code: str = ""
    pin: str = ""
    certificate: dict[str, str] | None = None


# --- Lectura pura -------------------------------------------------------------------------


def _text(value: Any, limit: int = 200) -> str:
    return str(value).strip()[:limit] if isinstance(value, (str, int, float)) and str(value).strip() else ""


def card_name(manufacturer: str, hint: str = "") -> str:
    """El nombre de la tarjeta: el que ya se sabía (panel o SNMP) o el del fabricante."""
    if hint in CARDS:
        return hint
    maker = (manufacturer or "").lower()
    return next((name for needle, name in CARDS_BY_MAKER if needle in maker), "BMC")


def identity(system: dict[str, Any]) -> dict[str, str]:
    """Fabricante, modelo y número de serie del servidor.

    En Dell el número que importa es el *service tag*, y Redfish lo da en
    ``SKU``: ``SerialNumber`` es el de la placa. En los demás, ``SerialNumber``.
    """
    manufacturer = _text(system.get("Manufacturer"))
    serial = _text(system.get("SerialNumber"))
    sku = _text(system.get("SKU"))
    if "dell" in manufacturer.lower() and sku:
        serial = sku
    return {
        key: value
        for key, value in (("manufacturer", manufacturer), ("model", _text(system.get("Model"))), ("serial", serial))
        if value
    }


def supply_status(raw: dict[str, Any]) -> str:
    """El estado de una fuente con las palabras de `agent/power.py`, o ``""``."""
    status = raw.get("Status") if isinstance(raw.get("Status"), dict) else {}
    state = str(status.get("State") or "")
    health = str(status.get("Health") or "")
    voltage = raw.get("LineInputVoltage")
    if state == "Absent":
        return "absent"
    if state in ("UnavailableOffline", "StandbyOffline", "Disabled"):
        return "off"
    if isinstance(voltage, (int, float)) and not isinstance(voltage, bool) and voltage == 0:
        return "no_input"
    if health in ("Critical", "Warning"):
        return "failed"
    if health == "OK":
        return "ok"
    return ""


def power_supplies(power: dict[str, Any]) -> list[dict[str, str]]:
    """Las fuentes de ``Chassis/…/Power``, en el formato del hallazgo."""
    raws = power.get("PowerSupplies") if isinstance(power, dict) else None
    if not isinstance(raws, list):
        return []
    supplies = []
    for position, raw in enumerate(raws[:MAX_SUPPLIES], start=1):
        if not isinstance(raw, dict):
            continue
        supply = {
            "name": _text(raw.get("Name"), 100) or f"PSU{position}",
            "model": _text(raw.get("Model"), 100),
            "serial": _text(raw.get("SerialNumber"), 100),
            "status": supply_status(raw),
        }
        watts = raw.get("PowerCapacityWatts")
        if isinstance(watts, (int, float)) and not isinstance(watts, bool) and watts > 0:
            supply["capacity_w"] = int(watts)
        supplies.append({key: value for key, value in supply.items() if value != "" or key == "status"})
    return supplies


def nic(raw: dict[str, Any], position: int) -> dict[str, str] | None:
    """Una tarjeta de red del servidor, o nada si no dice su MAC."""
    mac = _text(raw.get("MACAddress") or raw.get("PermanentMACAddress"), 40).lower().replace("-", ":")
    if len(mac) != 17 or mac == "00:00:00:00:00:00":
        return None
    name = _text(raw.get("Id")) or _text(raw.get("Name")) or f"NIC{position}"
    return {"name": name, "mac": mac}


def members(collection: dict[str, Any], limit: int) -> list[str]:
    """Los ``@odata.id`` de una colección que son de la propia tarjeta."""
    raws = collection.get("Members") if isinstance(collection, dict) else None
    if not isinstance(raws, list):
        return []
    found = []
    for raw in raws:
        path = raw.get("@odata.id") if isinstance(raw, dict) else None
        if isinstance(path, str) and path.startswith(ROOT) and ".." not in path:
            found.append(path)
        if len(found) >= limit:
            break
    return found


def link(resource: dict[str, Any], key: str) -> str:
    """El ``@odata.id`` de un enlace, solo si es de la propia tarjeta."""
    value = resource.get(key) if isinstance(resource, dict) else None
    path = value.get("@odata.id") if isinstance(value, dict) else None
    return path if isinstance(path, str) and path.startswith(ROOT) and ".." not in path else ""


# --- La conversación ------------------------------------------------------------------------

Fetch = Callable[[str], dict[str, Any]]


def _opener_fetch(host: str, username: str, secret: str, pin: str) -> Fetch:
    opener = urllib.request.build_opener(tlspin.PinnedHTTPSHandler(pin))
    token = base64.b64encode(f"{username}:{secret}".encode("utf-8")).decode("ascii")

    def fetch(path: str) -> dict[str, Any]:
        request = urllib.request.Request(
            f"https://{host}{path}",
            headers={"Accept": "application/json", "Authorization": f"Basic {token}", "OData-Version": "4.0"},
        )
        try:
            with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                body = response.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise RedfishError(AUTH_FAILED) from None
            if exc.code == 404 and path == ROOT:
                raise RedfishError(NOT_REDFISH) from None
            raise RedfishError(UNREACHABLE, f"HTTP {exc.code}") from None
        except Exception as exc:  # noqa: BLE001
            if isinstance(exc, tlspin.PinMismatch) or isinstance(getattr(exc, "reason", None), tlspin.PinMismatch):
                raise RedfishError(CERTIFICATE_CHANGED) from None
            raise RedfishError(UNREACHABLE, type(exc).__name__) from None
        if len(body) > MAX_BYTES:
            raise RedfishError(NOT_REDFISH, "respuesta demasiado grande")
        try:
            data = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            raise RedfishError(NOT_REDFISH, "no es JSON") from None
        if not isinstance(data, dict):
            raise RedfishError(NOT_REDFISH, "no es un objeto")
        return data

    return fetch


def collect(fetch: Fetch, card_hint: str = "") -> dict[str, Any]:
    """Todo lo que se lee de una tarjeta, con `fetch` ya autenticado.

    Lo único imprescindible es el servidor (``Systems``); la tarjeta, las
    fuentes y las tarjetas de red se intentan y, si fallan, faltan.
    """
    root = fetch(ROOT)
    if "RedfishVersion" not in root and not link(root, "Systems"):
        raise RedfishError(NOT_REDFISH)
    systems = members(fetch(link(root, "Systems") or ROOT + "Systems"), 1)
    if not systems:
        raise RedfishError(NOT_REDFISH, "sin Systems")
    system = fetch(systems[0])
    data: dict[str, Any] = dict(identity(system))
    block: dict[str, Any] = {"card": card_name(data.get("manufacturer", ""), card_hint)}
    for key, source in (("hostname", "HostName"), ("power_state", "PowerState")):
        value = _text(system.get(source))
        if value:
            block[key] = value

    def optional(step: Callable[[], None]) -> None:
        try:
            step()
        except RedfishError as exc:
            if exc.code in (AUTH_FAILED, CERTIFICATE_CHANGED):
                raise
        except Exception:  # noqa: BLE001 - lo opcional nunca tumba la lectura
            pass

    def manager() -> None:
        found = members(fetch(link(root, "Managers") or ROOT + "Managers"), 1)
        if found:
            firmware = _text(fetch(found[0]).get("FirmwareVersion"), 100)
            if firmware:
                block["firmware"] = firmware

    def power() -> None:
        found = members(fetch(link(root, "Chassis") or ROOT + "Chassis"), 1)
        if found:
            path = link(fetch(found[0]), "Power")
            if path:
                supplies = power_supplies(fetch(path))
                if supplies:
                    data["power_supplies"] = supplies

    def network() -> None:
        path = link(system, "EthernetInterfaces")
        if not path:
            return
        found = []
        for position, member in enumerate(members(fetch(path), MAX_NICS), start=1):
            entry = nic(fetch(member), position)
            if entry is not None and entry["mac"] not in {n["mac"] for n in found}:
                found.append(entry)
        if found:
            block["nics"] = found

    for step in (manager, power, network):
        optional(step)
    data["os"] = " ".join(part for part in (block["card"], block.get("firmware", "")) if part)
    data["redfish"] = block
    return data


def read(host: str, username: str, secret: str, pin: str = "", card_hint: str = "") -> Answer:
    """Entra en la tarjeta de ``host`` y lee lo suyo. Nunca lanza.

    Sin ``pin`` se fija el certificado que presente ahora (la primera vez,
    como SSH); el `Answer` lo devuelve en ``pin`` para que la memoria lo
    guarde. Con ``pin``, otro certificado es ``certificate_changed`` y la
    contraseña no llega a salir.
    """
    if not pin:
        seen = tlspin.describe(f"https://{host}/")
        if not seen:
            return Answer(connected=False, code=UNREACHABLE, error="sin TLS")
        pin = seen["sha256"]
    try:
        data = collect(_opener_fetch(host, username, secret, pin), card_hint)
    except RedfishError as exc:
        answer = Answer(connected=False, code=exc.code, error=exc.code, pin=pin)
        if exc.code == CERTIFICATE_CHANGED:
            answer.certificate = {"sha256": ""}
        return answer
    except Exception as exc:  # noqa: BLE001
        return Answer(connected=False, code=UNREACHABLE, error=type(exc).__name__, pin=pin)
    return Answer(connected=True, data=data, code="ok", pin=pin)


def outcome(answer: Answer) -> str:
    """El veredicto para el cortacircuitos: solo «no entra» cuenta contra la credencial."""
    if answer.connected:
        return "ok"
    return "auth_failed" if answer.code == AUTH_FAILED else "unreachable"
