"""Power supplies of a device, from ENTITY-MIB and the vendor's status MIB.

The question this answers for the server is the one the inventory could not
answer on its own: **how many power supplies does this device have, and is
each one actually receiving power?** A switch with two inlets and only one
of them live is the classic false redundancy, and no spreadsheet knows it.

Where the data comes from:

- **How many, and their names:** the rows of ``entPhysicalClass`` equal to
  ``powerSupply(6)``. The class column is already walked for every device
  (identity and stacks read it), so counting the supplies costs nothing new;
  their names are one ``get`` per supply of the leaf instances
  ``entPhysicalName.<index>`` / ``entPhysicalDescr.<index>`` -- never a walk
  of those columns, which on a chassis run to hundreds of rows.
- **Their state:** vendor-specific, because ENTITY-MIB itself says nothing
  about it. Each vendor keeps a status column indexed by the same
  ``entPhysicalIndex``, so the state is again one leaf instance per supply.
  A vendor without a known column leaves ``status`` empty: the server shows
  "unknown", never a guess.

Two caveats the server has to live with, and this module does not hide:
many devices list an **empty slot** as a power supply too (a Catalyst with
one PSU fitted still shows "Power Supply B"), so the count is of bays, not of
units fitted -- the state, when there is one, tells them apart; and the
cheaper ranges (Cisco SB, TP-Link, Ubiquiti, older MikroTik) implement no
ENTITY-MIB at all, so they report nothing and the server falls back to the
model's template.

Everything here is pure: dicts of text in, dicts of text out. The SNMP calls
live in ``agent/snmp.py``.
"""

from __future__ import annotations

from typing import Any

#: entPhysicalClass value for a power supply (RFC 6933 PhysicalClass).
ENTITY_CLASS_POWER_SUPPLY = "6"

#: Bays a chassis can be asked about. A modular core switch may list more,
#: and each one is a `get` or two: past this the rest are simply not asked.
MAX_POWER_SUPPLIES = 16

# The status words. Stable identifiers for the server, never shown as such.
OK = "ok"  # fitted and delivering power
FAILED = "failed"  # fitted and broken (or running degraded: fan failed...)
NO_INPUT = "no_input"  # fitted, nothing coming in (cable unplugged, breaker off)
OFF = "off"  # fitted and switched off, by admin or by the device (heat, fan...)
ABSENT = "absent"  # the bay is empty
UNKNOWN = ""

STATUSES = (OK, FAILED, NO_INPUT, OFF, ABSENT, UNKNOWN)


# --- Who keeps the status where -----------------------------------------------
#
# One column per vendor, indexed by entPhysicalIndex, with its value map. The
# generic ENTITY-STATE-MIB (RFC 4268) is tried for everybody else; most
# devices do not implement it, and then the status stays unknown.

#: CISCO-ENTITY-FRU-CONTROL-MIB cefcFRUPowerOperStatus (IOS, IOS XE, NX-OS).
CISCO_FRU_POWER_OID = "1.3.6.1.4.1.9.9.117.1.1.2.1.2"
CISCO_FRU_POWER_STATES = {
    "1": OFF,  # offEnvOther
    "2": OK,  # on
    "3": OFF,  # offAdmin
    "4": OFF,  # offDenied (not enough power budget)
    "5": NO_INPUT,  # offEnvPower
    "6": OFF,  # offEnvTemp
    "7": OFF,  # offEnvFan
    "8": FAILED,  # failed
    "9": FAILED,  # onButFanFail
    "10": OFF,  # offCooling
    "11": OFF,  # offConnectorRating
    "12": FAILED,  # onButInlinePowerFail
}

#: HUAWEI-ENTITY-EXTENT-MIB hwEntityOperStatus (VRP switches and routers).
HUAWEI_ENTITY_STATUS_OID = "1.3.6.1.4.1.2011.5.25.31.1.1.1.1.2"
HUAWEI_ENTITY_STATES = {
    "1": UNKNOWN,  # notSupported
    "2": OFF,  # disabled
    "3": OK,  # enabled
    "4": ABSENT,  # offline
}

#: ENTITY-STATE-MIB entStateOper, the vendor-neutral column (RFC 4268).
ENTITY_STATE_OPER_OID = "1.3.6.1.2.1.131.1.1.1.3"
ENTITY_STATE_OPER_STATES = {
    "1": UNKNOWN,  # unknown
    "2": OFF,  # disabled
    "3": OK,  # enabled
    "4": UNKNOWN,  # testing
}

#: (sysObjectID prefix, status column, value map). First prefix that matches
#: wins; a device under none of them gets the generic column.
STATUS_COLUMNS: tuple[tuple[str, str, dict[str, str]], ...] = (
    ("1.3.6.1.4.1.9.", CISCO_FRU_POWER_OID, CISCO_FRU_POWER_STATES),
    ("1.3.6.1.4.1.2011.", HUAWEI_ENTITY_STATUS_OID, HUAWEI_ENTITY_STATES),
)


def status_column(object_id: str) -> tuple[str, dict[str, str]]:
    """Which column holds the state of this device's supplies, by sysObjectID."""
    for prefix, oid, states in STATUS_COLUMNS:
        if object_id.startswith(prefix) or object_id == prefix.rstrip("."):
            return oid, states
    return ENTITY_STATE_OPER_OID, ENTITY_STATE_OPER_STATES


def status_of(raw: Any, states: dict[str, str]) -> str:
    """The state word for a raw column value; unknown for anything not mapped
    (a NoSuchInstance, an empty answer, a value a newer MIB added)."""
    return states.get(str(raw).strip(), UNKNOWN)


# --- Which rows are supplies --------------------------------------------------


def supply_indexes(classes: dict[str, str]) -> list[str]:
    """The entPhysicalIndex of every row of class powerSupply, in index order,
    at most ``MAX_POWER_SUPPLIES`` of them."""
    found = sorted(
        (index for index, value in classes.items() if str(value).strip() == ENTITY_CLASS_POWER_SUPPLY),
        key=_index_key,
    )
    return found[:MAX_POWER_SUPPLIES]


def supply(index: str, position: int, row: dict[str, str], status: str) -> dict[str, str]:
    """One supply as the finding carries it.

    ``name`` is entPhysicalName when the device fills it, else its
    description, else "PSU<n>" by position -- the finding never carries a
    nameless supply, because the server names the inlet after it.
    """
    name = _clean(row.get("name")) or _clean(row.get("description")) or f"PSU{position}"
    return {
        "index": index,
        "name": name[:100],
        "description": _clean(row.get("description"))[:200],
        "model": _clean(row.get("model"))[:100],
        "serial": _clean(row.get("serial"))[:100],
        "status": status if status in STATUSES else UNKNOWN,
    }


def _clean(value: Any) -> str:
    text = str(value or "").strip()
    # A NoSuchInstance that slipped through as text is not a name.
    if text.startswith(("NoSuch", "No Such")) or text == "EndOfMibView":
        return ""
    return text


def _index_key(index: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in index.split("."))
    except ValueError:
        return (0,)
