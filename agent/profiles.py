"""Vendor profiles: what a device *is*, from sysObjectID and sysDescr.

The method is SNMP::Info's (Netdisco): look at ``sysObjectID`` and
``sysDescr``, pick a vendor profile, and with it ask the two or three leaf
OIDs that give model, serial, operating system and version. The profiles
themselves live in ``profiles_data.py``; this module is the engine that
chooses one and reads a device through it.

Everything here is pure: strings in, dataclasses out, no network. The SNMP
calls live in ``agent/snmp.py``; the fields reach the server inside the
``host`` finding's payload (``Identity.payload_fields``). The protocol does
not change: the server ignores the keys it does not know.

Nothing here raises on odd input. A profile with a broken regex matches
nothing, an empty answer leaves the field empty, and a device nobody
recognises resolves to ``None`` and is identified by ENTITY-MIB alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class Profile:
    key: str  # "mikrotik", "cisco-ios", "cisco-sb"... stable, lowercase
    vendor: str  # What the person sees: "MikroTik", "Cisco", "HPE Aruba"
    enterprise: int | None = None  # IANA enterprise number: sysObjectID = 1.3.6.1.4.1.<enterprise>...
    object_id_prefix: str = ""  # Long prefix when one enterprise has several families
    description_match: str = ""  # Regex (re.search, IGNORECASE) over sysDescr. Beats enterprise.
    os: str = ""  # Fixed OS name ("RouterOS", "IOS"); empty when an OID or regex gives it
    serial_oid: str = ""  # Leaf OID (ends in .0) with the serial number
    model_oid: str = ""  # Leaf OID with the model
    version_oid: str = ""  # Leaf OID with the OS version
    os_oid: str = ""  # Leaf OID with the OS name (rare)
    model_from_description: str = ""  # Regex with ONE group: the model, from sysDescr
    version_from_description: str = ""  # Regex with ONE group: the version, from sysDescr
    os_from_description: str = ""  # Regex with ONE group: the OS name, from sysDescr
    entity_fallback: bool = True  # If model or serial is still missing, ask ENTITY-MIB (chassis)


@dataclass(frozen=True)
class Identity:
    manufacturer: str = ""
    model: str = ""
    serial: str = ""
    os: str = ""  # name: "IOS", "RouterOS"
    os_version: str = ""  # "15.2(7)E8", "7.15.3"
    profile: str = ""  # key of the profile, or "" when resolved by ENTITY-MIB alone

    def payload_fields(self) -> dict[str, str]:
        """Only the fields with a value: manufacturer, model, serial, os
        (composed), os_version.

        ``os`` is what the server stores as ``os_firmware``: name and version
        together when both are known, whichever exists when only one is, and
        nothing at all when neither -- the server already falls back to the
        description, so sysDescr is never sent as ``os``.
        """
        fields = {
            "manufacturer": self.manufacturer,
            "model": self.model,
            "serial": self.serial,
            "os": " ".join(part for part in (self.os, self.os_version) if part),
            "os_version": self.os_version,
        }
        return {key: value for key, value in fields.items() if value}


#: The real table, loaded on first use. ``profiles_data`` imports ``Profile``
#: from here, so importing it at module level would be circular: whichever of
#: the two modules loaded first would silently see an empty table. Tests may
#: patch this attribute with a table of their own.
PROFILES: tuple[Profile, ...] | None = None


def table() -> tuple[Profile, ...]:
    """The vendor table (``agent.profiles_data.PROFILES``), loaded lazily."""
    global PROFILES
    if PROFILES is None:
        from agent.profiles_data import PROFILES as loaded

        PROFILES = loaded
    return PROFILES

ENTERPRISE_ARC = "1.3.6.1.4.1"

#: entPhysicalClass value for a chassis.
ENTITY_CLASS_CHASSIS = "3"


def _search(pattern: str, text: str) -> re.Match[str] | None:
    """``re.search`` that treats a broken or empty pattern as no match."""
    if not pattern or not text:
        return None
    try:
        return re.search(pattern, text, re.IGNORECASE)
    except re.error:
        return None


def _extract(pattern: str, text: str) -> str:
    """The first group of *pattern* in *text*, stripped, or ""."""
    match = _search(pattern, text)
    if match is None:
        return ""
    group = match.group(1) if match.groups() else match.group(0)
    return (group or "").strip()


def enterprise_of(object_id: str) -> int | None:
    """The IANA enterprise number inside a sysObjectID (``1.3.6.1.4.1.N...``)."""
    parts = object_id.strip().lstrip(".").split(".")
    if len(parts) < 7 or ".".join(parts[:6]) != ENTERPRISE_ARC:
        return None
    try:
        return int(parts[6])
    except ValueError:
        return None


def _has_prefix(object_id: str, prefix: str) -> bool:
    """Whole-arc prefix: ``1.3.6.1.4.1.9.1`` is not a prefix of ``...9.10``."""
    return object_id == prefix or object_id.startswith(prefix + ".")


def resolve(object_id: str, description: str, profiles: Iterable[Profile] | None = None) -> Profile | None:
    """The profile for a device, or ``None`` when nobody recognises it.

    The order is SNMP::Info's ``device_type``: a ``description_match`` wins
    (first in table order), then the longest ``object_id_prefix`` that is a
    prefix of sysObjectID, then the enterprise number. ``profiles`` defaults
    to the real table (read at call time, so tests can swap it).
    """
    candidates = list(table() if profiles is None else profiles)
    object_id = (object_id or "").strip().lstrip(".")
    description = description or ""
    for profile in candidates:
        if profile.description_match and _search(profile.description_match, description):
            return profile
    by_prefix = [p for p in candidates if p.object_id_prefix and _has_prefix(object_id, p.object_id_prefix.strip("."))]
    if by_prefix:
        return max(by_prefix, key=lambda p: len(p.object_id_prefix.strip(".")))
    enterprise = enterprise_of(object_id)
    if enterprise is not None:
        for profile in candidates:
            if profile.enterprise == enterprise:
                return profile
    return None


def extra_oids(profile: Profile | None) -> dict[str, str]:
    """The leaf OIDs a profile wants asked, keyed ``serial``, ``model``,
    ``version``, ``os`` -- only the ones it has."""
    if profile is None:
        return {}
    wanted = {
        "serial": profile.serial_oid,
        "model": profile.model_oid,
        "version": profile.version_oid,
        "os": profile.os_oid,
    }
    return {key: oid for key, oid in wanted.items() if oid}


def needs_entity(profile: Profile | None, identity: Identity) -> bool:
    """Whether ENTITY-MIB is worth asking: model or serial still missing and
    the profile (or the absence of one) allows the fallback."""
    if profile is not None and not profile.entity_fallback:
        return False
    return not (identity.model and identity.serial)


def chassis_from_entity(
    classes: dict[str, str],
    models: dict[str, str],
    serials: dict[str, str],
    versions: dict[str, str],
    mfgs: dict[str, str],
) -> dict[str, str]:
    """The chassis fields from ENTITY-MIB columns (``{entPhysicalIndex: text}``):
    the first row -- by index -- whose entPhysicalClass is 3 (chassis).

    Returns ``model``, ``serial``, ``version``, ``manufacturer``, each "" when
    that column has nothing for the chassis; ``{}`` when there is no chassis.
    """
    index = chassis_index(classes)
    if not index:
        return {}
    return {
        "model": str(models.get(index, "") or "").strip(),
        "serial": str(serials.get(index, "") or "").strip(),
        "version": str(versions.get(index, "") or "").strip(),
        "manufacturer": str(mfgs.get(index, "") or "").strip(),
    }


def chassis_index(classes: dict[str, str]) -> str:
    """The entPhysicalIndex of the chassis: the first row -- lowest index --
    whose entPhysicalClass is 3, or "" when there is none."""
    chassis = sorted(
        (str(index) for index, value in classes.items() if str(value).strip() == ENTITY_CLASS_CHASSIS),
        key=_index_key,
    )
    return chassis[0] if chassis else ""


def _index_key(index: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in str(index).split("."))
    except ValueError:
        return (0,)


def identify(
    profile: Profile | None,
    description: str,
    extra: dict[str, str],
    entity: dict[str, str],
) -> Identity:
    """One Identity from the three sources, each field falling back in order:
    profile OID -> regex over sysDescr -> ENTITY-MIB chassis -> "".

    ``extra`` is what the profile's OIDs answered (keys as ``extra_oids``),
    ``entity`` what ``chassis_from_entity`` gave. The vendor is always the
    profile's; without one, entPhysicalMfgName. The OS name has no ENTITY
    fallback, and a fixed ``profile.os`` beats everything.
    """
    description = description or ""
    extra = {key: (value or "").strip() for key, value in (extra or {}).items()}
    entity = {key: (value or "").strip() for key, value in (entity or {}).items()}
    if profile is None:
        return Identity(
            manufacturer=entity.get("manufacturer", ""),
            model=entity.get("model", ""),
            serial=entity.get("serial", ""),
            os_version=entity.get("version", ""),
        )
    model = (
        extra.get("model", "")
        or _extract(profile.model_from_description, description)
        or entity.get("model", "")
    )
    serial = extra.get("serial", "") or entity.get("serial", "")
    version = (
        extra.get("version", "")
        or _extract(profile.version_from_description, description)
        or entity.get("version", "")
    )
    os_name = profile.os or extra.get("os", "") or _extract(profile.os_from_description, description)
    return Identity(
        manufacturer=profile.vendor,
        model=model,
        serial=serial,
        os=os_name,
        os_version=version,
        profile=profile.key,
    )
