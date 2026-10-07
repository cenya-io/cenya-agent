"""Stack members: which physical units sit behind one management address.

A stack of switches (Cisco StackWise, Dell N-series stacking, Aruba backplane
stacking, Juniper Virtual Chassis, HPE Comware IRF) answers on one IP with one
hostname and the ports of every unit. The server models each unit as its own
device, so the host finding may carry ``payload["members"]``: one entry per
physical unit, ``{"unit": int, "serial": str, "model": str, "role": str}``,
with ``role`` one of ``master``, ``standby``, ``member`` or ``""``.

The contract has two rules every parser here keeps:

* **Only with two or more units.** A lone switch is not a stack, and the key is
  left out of the payload altogether -- never an empty list (``finish``).
* **Pure functions over text.** The collectors fetch the output; everything
  here takes a string (or SNMP columns) and returns a list, so each vendor is
  tested against a real-looking capture without a network.

Nothing here raises on odd input: an output we do not understand is simply
"no members", and the server falls back to deducing units from port names.
"""

from __future__ import annotations

import re
from typing import Any

Member = dict[str, Any]

MASTER = "master"
STANDBY = "standby"
MEMBER = "member"


def finish(members: list[Member]) -> list[Member]:
    """The members as the payload wants them: sorted by unit, one per unit,
    and only when there are at least two. Otherwise ``[]``, which callers
    turn into "no key at all"."""
    by_unit: dict[int, Member] = {}
    for member in members:
        by_unit.setdefault(int(member["unit"]), member)
    if len(by_unit) < 2:
        return []
    return [
        {
            "unit": unit,
            "serial": str(by_unit[unit].get("serial") or ""),
            "model": str(by_unit[unit].get("model") or ""),
            "role": str(by_unit[unit].get("role") or ""),
        }
        for unit in sorted(by_unit)
    ]


def master_serial(members: list[Member]) -> str:
    """The serial of the master unit, or "" when none is marked or known."""
    return next((m["serial"] for m in members if m.get("role") == MASTER and m.get("serial")), "")


# --- Cisco IOS / IOS-XE: `show version` --------------------------------------

#: One row of the "Switch Ports Model SW Version SW Image" table. The leading
#: asterisk marks the switch the session landed on, which is the active one.
_CISCO_ROW_RE = re.compile(r"^[ \t]*(\*?)[ \t]*(\d+)[ \t]+(\d+)[ \t]+(\S+)[ \t]+\S+[ \t]+\S+", re.MULTILINE)
_CISCO_TABLE_RE = re.compile(r"^\s*Switch\s+Ports\s+Model\s+SW Version", re.MULTILINE | re.IGNORECASE)
#: "Switch 02" followed by a dashed underline opens the block of each other unit.
_CISCO_BLOCK_RE = re.compile(r"^Switch\s+0*(\d+)\s*\n-{3,}\s*$", re.MULTILINE)
_CISCO_SERIAL_RE = re.compile(r"^\s*System serial number\s*:\s*(\S+)", re.MULTILINE | re.IGNORECASE)
_CISCO_MODEL_RE = re.compile(r"^\s*Model number\s*:\s*(\S+)", re.MULTILINE | re.IGNORECASE)


def cisco_members(output: str) -> list[Member]:
    """The units of a Catalyst stack from one `show version`.

    The table lists every unit with its model; the serials live further down:
    the active unit's in the top section (before any "Switch 0N" block), each
    other unit's in its own block. A unit missing from the blocks keeps the
    table model and an empty serial rather than borrowing someone else's.
    """
    table = _CISCO_TABLE_RE.search(output)
    if not table:
        return []
    blocks = list(_CISCO_BLOCK_RE.finditer(output))
    table_end = blocks[0].start() if blocks else len(output)
    rows: list[Member] = []
    for row in _CISCO_ROW_RE.finditer(output, table.end(), table_end):
        rows.append(
            {
                "unit": int(row.group(2)),
                "model": row.group(4),
                "serial": "",
                "role": MASTER if row.group(1) else MEMBER,
            }
        )
    if not rows:
        return []
    details: dict[int, tuple[str, str]] = {}
    head = output[: blocks[0].start()] if blocks else output
    for index, block in enumerate(blocks):
        end = blocks[index + 1].start() if index + 1 < len(blocks) else len(output)
        details[int(block.group(1))] = _cisco_detail(output[block.end() : end])
    head_detail = _cisco_detail(head)
    for row in rows:
        serial, model = details.get(row["unit"], ("", ""))
        if row["role"] == MASTER:
            serial, model = head_detail
        row["serial"] = serial
        row["model"] = model or row["model"]
    return finish(rows)


def _cisco_detail(text: str) -> tuple[str, str]:
    serial = _CISCO_SERIAL_RE.search(text)
    model = _CISCO_MODEL_RE.search(text)
    return (serial.group(1) if serial else "", model.group(1) if model else "")


# --- Dell N-series (OS6): `show version`, then `show switch` ------------------

#: Dell prints "Field.......... value" with a dotted leader of varying length.
_DELL_SERIAL_RE = re.compile(r"^\s*Serial Number\.{2,}\s*(\S+)", re.MULTILINE)
_DELL_MODEL_RE = re.compile(r"^\s*System Model ID\.{2,}\s*(\S+)", re.MULTILINE)
#: A unit section of `show version` on a stack: "Unit 2" or "Switch: 2".
_DELL_UNIT_RE = re.compile(r"^[ \t]*(?:Unit|Switch):?[ \t]+(\d+)[ \t]*$", re.MULTILINE)
#: A present unit of `show switch`: management status is "Mgmt Sw" or "Stack Mbr"
#: (absent, preconfigured units say "Unassigned" and are not physical units).
_DELL_SWITCH_ROW_RE = re.compile(
    r"^[ \t]*(\d+)[ \t]+(Mgmt Sw|Stack Mbr)[ \t]+(?:(Oper Stby|Cfg Stby)[ \t]+)?(\S+)[ \t]+(\S+)[ \t]+OK\b",
    re.MULTILINE,
)


def dell_identity(output: str) -> tuple[str, str]:
    """Serial and model of the unit `show version` describes first (the
    management unit), or empty strings."""
    serial = _DELL_SERIAL_RE.search(output)
    model = _DELL_MODEL_RE.search(output)
    return (serial.group(1) if serial else "", model.group(1) if model else "")


def dell_members_from_version(output: str) -> list[Member]:
    """The units of a Dell stack when `show version` prints one section per
    unit ("Unit 1 ... Serial Number ...."). The first section is the
    management unit. A standalone switch, or a version that only describes
    the management unit, gives ``[]``: then `show switch` is asked."""
    heads = list(_DELL_UNIT_RE.finditer(output))
    members: list[Member] = []
    for index, head in enumerate(heads):
        end = heads[index + 1].start() if index + 1 < len(heads) else len(output)
        serial, model = dell_identity(output[head.end() : end])
        if not serial and not model:
            continue
        members.append({"unit": int(head.group(1)), "serial": serial, "model": model, "role": ""})
    if members:
        members[0]["role"] = MASTER
        for member in members[1:]:
            member["role"] = MEMBER
    return finish(members)


def dell_members_from_switch(output: str, master_serial_number: str = "") -> list[Member]:
    """The units of a Dell stack from `show switch`.

    The table has the plugged-in model and who manages the stack, but no
    serials; the management unit's serial comes from `show version` and is
    passed in. The others stay without one rather than guessing.
    """
    members: list[Member] = []
    for row in _DELL_SWITCH_ROW_RE.finditer(output):
        if row.group(2) == "Mgmt Sw":
            role, serial = MASTER, master_serial_number
        else:
            role, serial = (STANDBY if row.group(3) == "Oper Stby" else MEMBER), ""
        members.append({"unit": int(row.group(1)), "serial": serial, "model": row.group(5), "role": role})
    return finish(members)


# --- Aruba / ArubaOS-Switch (ProCurve): `show stacking` -----------------------

#: "Mbr ID, Mac Address, Model, Pri, Status". The model is free text with
#: spaces ("HP JL075A 3810M-16SFP+-2-slot Switch"), so the row is anchored on
#: the MAC before it and the priority and status after it. The model is greedy
#: so that a numeric word inside it is never taken for the priority.
_ARUBA_ROW_RE = re.compile(
    r"^[ \t]*(\d+)[ \t]+[0-9a-fA-F]{6}-[0-9a-fA-F]{6}[ \t]+(.+)[ \t]+(\d+)[ \t]+([A-Za-z][A-Za-z -]*?)[ \t]*$",
    re.MULTILINE,
)
_ARUBA_ROLES = {"commander": MASTER, "standby": STANDBY, "member": MEMBER}


def aruba_members(output: str) -> list[Member]:
    """The units of an ArubaOS-Switch backplane stack. `show stacking` gives
    no serials; units in any status other than Commander, Standby or Member
    (Missing, Not Joined, Provisioned...) are not physically there and are
    left out."""
    members: list[Member] = []
    for row in _ARUBA_ROW_RE.finditer(output):
        role = _ARUBA_ROLES.get(row.group(4).strip().lower())
        if role is None:
            continue
        members.append({"unit": int(row.group(1)), "serial": "", "model": row.group(2).strip(), "role": role})
    return finish(members)


# --- Juniper EX: `show virtual-chassis` ---------------------------------------

#: "0 (FPC 0)  Prsnt  PE3714100218  ex4300-48p  129  Master*". Members that are
#: provisioned but not present ("NotPrsnt") have no serial and are skipped.
_JUNOS_ROW_RE = re.compile(
    r"^[ \t]*(\d+)[ \t]+\(FPC[ \t]+\d+\)[ \t]+Prsnt[ \t]+(\S+)[ \t]+(\S+)[ \t]+\d+[ \t]+(Master|Backup|Linecard)\*?",
    re.MULTILINE,
)
_JUNOS_ROLES = {"Master": MASTER, "Backup": STANDBY, "Linecard": MEMBER}


def junos_members(output: str) -> list[Member]:
    """The members of a Virtual Chassis. Juniper numbers them from 0 and the
    unit keeps that number: it is what the port names carry (ge-1/0/3)."""
    members = [
        {"unit": int(row.group(1)), "serial": row.group(2), "model": row.group(3), "role": _JUNOS_ROLES[row.group(4)]}
        for row in _JUNOS_ROW_RE.finditer(output)
    ]
    return finish(members)


def junos_master_serial(output: str) -> str:
    """The serial of the Virtual Chassis master, even when it is alone: a
    standalone EX still answers `show virtual-chassis` with one row, and
    `show version` on JunOS carries no serial."""
    for row in _JUNOS_ROW_RE.finditer(output):
        if row.group(4) == "Master":
            return row.group(2)
    return ""


# --- HPE / H3C Comware IRF: `display irf`, then `display device manuinfo` ----

#: Comware 7: " *+1   1   Master  32   00e0-fc0f-8c02  ---" (MemberID, Slot,
#: Role, Priority, CPU-Mac); Comware 5 has no Slot column and says "Slave".
_IRF_ROW_RE = re.compile(
    r"^[ \t]*[*+]*[ \t]*(\d+)[ \t]+(?:\d+[ \t]+)?(Master|Standby|Slave|Loading)[ \t]+\d+[ \t]+"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}",
    re.MULTILINE,
)
_IRF_ROLES = {"Master": MASTER, "Standby": STANDBY, "Slave": STANDBY, "Loading": ""}
#: `display device manuinfo`: one "Slot N" section per member (on a box switch
#: in IRF the slot number is the member ID), with DEVICE_NAME and
#: DEVICE_SERIAL_NUMBER. Power supplies and fans get their own sections
#: ("Fan 1:", "Power 1:") which do not start with "Slot".
_MANUINFO_SLOT_RE = re.compile(r"^[ \t]*Slot[ \t]+(\d+)(?:[ \t]+CPU[ \t]+\d+)?[ \t]*:", re.MULTILINE)
_MANUINFO_SECTION_RE = re.compile(r"^[ \t]*[A-Za-z][A-Za-z ]*[ \t]+\d+(?:[ \t]+CPU[ \t]+\d+)?[ \t]*:\s*$", re.MULTILINE)
_MANUINFO_SERIAL_RE = re.compile(r"^[ \t]*DEVICE_SERIAL_NUMBER[ \t]*:[ \t]*(\S+)", re.MULTILINE)
_MANUINFO_NAME_RE = re.compile(r"^[ \t]*DEVICE_NAME[ \t]*:[ \t]*(\S+)", re.MULTILINE)


def irf_members(output: str) -> list[Member]:
    """The members of an IRF fabric from `display irf`: unit and role. No
    model and no serial there; ``add_manuinfo`` fills them when asked."""
    members = [
        {"unit": int(row.group(1)), "serial": "", "model": "", "role": _IRF_ROLES[row.group(2)]}
        for row in _IRF_ROW_RE.finditer(output)
    ]
    return finish(members)


def manuinfo_by_slot(output: str) -> dict[int, tuple[str, str]]:
    """{slot: (serial, model)} from `display device manuinfo`."""
    sections = list(_MANUINFO_SECTION_RE.finditer(output))
    found: dict[int, tuple[str, str]] = {}
    for index, section in enumerate(sections):
        slot = _MANUINFO_SLOT_RE.match(section.group(0))
        if not slot:
            continue
        end = sections[index + 1].start() if index + 1 < len(sections) else len(output)
        body = output[section.end() : end]
        serial = _MANUINFO_SERIAL_RE.search(body)
        name = _MANUINFO_NAME_RE.search(body)
        if serial or name:
            found.setdefault(int(slot.group(1)), (serial.group(1) if serial else "", name.group(1) if name else ""))
    return found


def add_manuinfo(members: list[Member], output: str) -> list[Member]:
    """The IRF members with serial and model from `display device manuinfo`,
    matched by member ID. A member without a section keeps them empty."""
    info = manuinfo_by_slot(output)
    for member in members:
        serial, model = info.get(member["unit"], ("", ""))
        member["serial"] = member["serial"] or serial
        member["model"] = member["model"] or model
    return members


# --- SNMP: ENTITY-MIB entPhysicalTable --------------------------------------

#: entPhysicalClass value for a chassis: one per physical unit in a stack.
ENTITY_CLASS_CHASSIS = "3"


def entity_members(
    classes: dict[str, str], positions: dict[str, str], serials: dict[str, str], models: dict[str, str]
) -> list[Member]:
    """The units of a stack from ENTITY-MIB columns, each ``{entPhysicalIndex:
    text}``: every row of class chassis is a unit.

    The unit number is entPhysicalParentRelPos (a Catalyst stack puts each
    switch at its stack number under the "stack" entity) when every chassis
    has a distinct positive one; otherwise the chassis are numbered 1, 2...
    in index order. ENTITY-MIB does not say who is master, so ``role`` is "".
    """
    chassis = sorted(
        (index for index, value in classes.items() if str(value).strip() == ENTITY_CLASS_CHASSIS),
        key=_index_key,
    )
    if len(chassis) < 2:
        return []
    numbers = [_positive(positions.get(index, "")) for index in chassis]
    if any(number is None for number in numbers) or len(set(numbers)) != len(numbers):
        numbers = list(range(1, len(chassis) + 1))
    members = [
        {
            "unit": number,
            "serial": str(serials.get(index, "")).strip(),
            "model": str(models.get(index, "")).strip(),
            "role": "",
        }
        for index, number in zip(chassis, numbers)
    ]
    return finish(members)


def _index_key(index: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in index.split("."))
    except ValueError:
        return (0,)


def _positive(value: Any) -> int | None:
    try:
        number = int(str(value).strip())
    except ValueError:
        return None
    return number if number > 0 else None
