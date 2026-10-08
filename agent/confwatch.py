"""Notice a configuration change within minutes, without listening to anything.

The ``configs`` task copies every network device once a day. Between two
copies a change goes unseen, and that is exactly when someone wants to know.
The usual answer is syslog, which means opening a listening port; the agent
does not do that (it only pushes and polls). This is the polling answer: a
few devices publish *when their configuration last changed* as a plain SNMP
leaf, and reading one leaf is a single small packet. So, as one more step of
the ``presence`` task (every five minutes by default):

1. For each network device the memory knows (SSH got in, family recorded) and
   that is alive now, ask for that stamp, with the SNMP credential the memory
   already trusts for it and through the same veto (``tasking.plan`` /
   ``tasking.settle``): a device that does not answer SNMP gets one failed
   round and then rests 24 h, it is not knocked on every five minutes.
2. First time a device is seen, keep the stamp and do nothing: the nightly copy
   covers it.
3. When the stamp changed, run the SSH capture of *that device only*
   (``SshCollector.capture``: same remembered credential, same commands, same
   ``config`` finding as the ``configs`` task). The server already stores a copy
   only when its content differs, so a false alarm costs one login.

Why a step of ``presence`` and not a task of its own: the server validates task
names (``AgentTaskName``) for its schedule, its screens and the "run now"
orders. A new name would be accepted in reports but would show up as a raw
word, would have no cadence in the profile, could not be switched off from the
web, and would add a history row every ten minutes per agent. A step of
``presence`` needs no protocol change. It follows presence's cadence and its
off switch; ``capture_configs`` off, or the ``configs`` task off, switches it
off too.

The memory is disposable: with it gone every device is "first time" again, and
the price is one missed alarm, never a lost inventory.

Where the stamp lives (verified against the MIB text, not from memory)
----------------------------------------------------------------------

* Cisco, ``CISCO-CONFIG-MAN-MIB`` (github.com/cisco/cisco-mibs, v2/
  CISCO-CONFIG-MAN-MIB.my): ``ciscoConfigManMIB ::= { ciscoMgmt 43 }`` (line
  197), ``ciscoMgmt ::= { cisco 9 }`` (CISCO-SMI.my line 169), ``cisco ::=
  { enterprises 9 }`` (CISCO-SMI.my line 71), ``ccmHistory ::=
  { ciscoConfigManMIBObjects 1 }`` (line 204). Both are ``TimeTicks``, "the
  value of sysUpTime when ..." (lines 246-290):
  ``ccmHistoryRunningLastChanged ::= { ccmHistory 1 }`` ->
  1.3.6.1.4.1.9.9.43.1.1.1.0 and ``ccmHistoryStartupLastChanged ::=
  { ccmHistory 3 }`` -> 1.3.6.1.4.1.9.9.43.1.1.3.0 (scalars, so ``.0``).
  The saved one is watched too because the Cisco copy includes the startup
  config.
* Juniper, ``JUNIPER-CFGMGMT-MIB`` (github.com/librenms/librenms, mibs/juniper/
  junos/JUNIPER-CFGMGMT-MIB): ``jnxCfgMgmt ::= { jnxMibs 18 }`` (line 42),
  ``jnxCmCfgChg ::= { jnxCfgMgmt 1 }`` (line 74), ``jnxMibs ::= { juniperMIB 3 }``
  and ``juniperMIB ::= { enterprises 2636 }`` (JUNIPER-SMI lines 205-209, 135).
  ``jnxCmCfgChgLatestTime ::= { jnxCmCfgChg 2 }`` is ``TimeTicks`` but "will
  return 0" after a management reset (lines 85-95), so it is not used;
  ``jnxCmCfgChgLatestDate ::= { jnxCmCfgChg 3 }`` is ``DateAndTime`` (lines
  97-103) -> 1.3.6.1.4.1.2636.3.18.1.3.0, compared as a value.
* Huawei, ``HUAWEI-CONFIG-MAN-MIB`` (librenms mibs/huawei/HUAWEI-CONFIG-MAN-MIB):
  the MIB itself writes the full OID in the comment above the object (line
  226): ``hwCfgRunModifiedLast`` (``TimeTicks``, line 227, "sysUpTime when the
  current configuration running in the system was last modified") is
  1.3.6.1.4.1.2011.6.10.1.1.1 (``huaweiUtility ::= { huawei 6 }``, HUAWEI-MIB
  line 5865; ``hwConfig ::= { huaweiUtility 10 }``, line 178); ``.0`` instance.
* H3C / HPE Comware, ``HH3C-CONFIG-MAN-MIB`` (librenms mibs/comware/
  HH3C-CONFIG-MAN-MIB): ``hh3cConfig ::= { hh3cCommon 4 }`` (line 148),
  ``hh3cCommon ::= { hh3c 2 }`` and ``hh3c ::= { enterprises 25506 }``
  (HH3C-OID-MIB lines 63, 59), ``hh3cConfigManObjects ::= { hh3cConfig 1 }``,
  ``hh3cCfgLog ::= { hh3cConfigManObjects 1 }``, ``hh3cCfgRunModifiedLast
  ::= { hh3cCfgLog 1 }`` (``TimeTicks``, line 287-297) ->
  1.3.6.1.4.1.25506.2.4.1.1.1.0.

Families with a capture command but no OID checked here (Aruba/HPE ICX, Dell,
Fortinet, MikroTik, Extreme EXOS, Check Point Gaia, Allied Telesis, EdgeOS)
stay on the nightly copy only. A TimeTicks stamp is only meaningful next to
sysUpTime (a reboot restarts it), so the pair is stored and compared.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from agent import snmp
from agent.collectors import tasking
from agent.collectors.base import Finding
from agent.collectors.snmp import snmp_credentials, as_auth
from agent.collectors.ssh import CAPTURE_COMMANDS, SshCollector, _capture_enabled
from agent.notes import collector_note
from agent.scheduler import CONFIGS, every_seconds

#: How the leaves of a family are compared.
TICKS = "ticks"
DATE = "date"


@dataclass(frozen=True)
class Watch:
    """What to ask a family: the named leaves and how to compare them."""

    kind: str
    oids: dict[str, str]


#: Family (as ``agent.collectors.ssh`` names it) -> what to watch. Sources and
#: lines in the module docstring.
WATCHES: dict[str, Watch] = {
    "cisco": Watch(
        TICKS,
        {
            "running": "1.3.6.1.4.1.9.9.43.1.1.1.0",  # ccmHistoryRunningLastChanged
            "startup": "1.3.6.1.4.1.9.9.43.1.1.3.0",  # ccmHistoryStartupLastChanged
        },
    ),
    "junos": Watch(DATE, {"changed": "1.3.6.1.4.1.2636.3.18.1.3.0"}),  # jnxCmCfgChgLatestDate
    "huawei": Watch(TICKS, {"running": "1.3.6.1.4.1.2011.6.10.1.1.1.0"}),  # hwCfgRunModifiedLast
    "comware": Watch(TICKS, {"running": "1.3.6.1.4.1.25506.2.4.1.1.1.0"}),  # hh3cCfgRunModifiedLast
}

#: A device is asked at most this often, whatever presence's cadence is: an
#: order for "sweep now" or a one-minute presence must not become a poll storm.
#: A bit under five minutes so the default cadence (300 s plus scheduling
#: jitter) always passes.
MIN_POLL = timedelta(minutes=4)
#: A device is copied at most this often because of a change: one that changes
#: all the time (a script, a flapping auto-save) must not be logged into on
#: every cycle. The stamp is not updated while it waits, so the change is
#: still noticed afterwards.
MIN_CAPTURE_GAP = timedelta(minutes=5)
#: Copies per cycle. The rest wait, with their stamp untouched, for the next one.
MAX_CAPTURES = 10


def _ticks(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _uptime(raw: dict[str, str]) -> int | None:
    return _ticks(raw.get("uptime", ""))


def current_stamp(watch: Watch, raw: dict[str, str]) -> list[str]:
    """The values read, in ``watch.oids`` order; ``[]`` if the device publishes none.

    A leaf that came back empty (``noSuchObject``) is kept as ``""`` so the
    positions stay aligned, but a stamp with nothing in it at all is "no
    information", not a value.
    """
    values = [str(raw.get(name, "") or "").strip() for name in watch.oids]
    return values if any(values) else []


def changed(watch: Watch, previous: dict[str, Any], stamp: list[str], uptime: int | None) -> bool:
    """Whether the configuration changed since ``previous``.

    ``previous`` is what was stored the last time (``{}`` the first time: no
    change, there is nothing to compare with). For a date the value is
    compared. For ticks, per leaf: the device rebooted (uptime went backwards)
    -> yes, once, out of prudence, because the counter restarted and we cannot
    tell; otherwise yes if the value differs, or if it is later than the uptime
    of the previous poll (a change newer than the last time we looked).
    """
    old = previous.get("stamp") if isinstance(previous, dict) else None
    if not old or not stamp or len(old) != len(stamp):
        return False
    if watch.kind == DATE:
        return any(new and new != before for before, new in zip(old, stamp))
    old_uptime = previous.get("uptime")
    if isinstance(old_uptime, int) and uptime is not None and uptime < old_uptime:
        return True
    for before, new in zip(old, stamp):
        now_ticks, was_ticks = _ticks(new), _ticks(before)
        if now_ticks is None:
            continue
        if was_ticks is None or now_ticks != was_ticks:
            return True
        if isinstance(old_uptime, int) and now_ticks > old_uptime:
            return True
    return False


def _within(moment: str, gap: timedelta, now: datetime) -> bool:
    try:
        then = datetime.fromisoformat(moment)
    except (TypeError, ValueError):
        return False
    if then.tzinfo is None:
        return False
    return now - then < gap


def _enabled(ctx: dict) -> bool:
    """Needs the memory (nowhere else to keep the stamps), copies switched on and
    the ``configs`` task not switched off from the web."""
    config = ctx.get("config") or {}
    if tasking.memory(ctx) is None or not _capture_enabled(ctx):
        return False
    tasks = config.get("tasks") if isinstance(config, dict) else None
    return every_seconds(tasks, CONFIGS) != 0


def run(ctx: dict) -> list[Finding]:
    """The step: ``config`` findings for the devices whose configuration changed.

    Never raises: like a collector that cannot run, it notes it in
    ``ctx["errors"]`` (an existing code, ``crashed``) and returns ``[]``.
    """
    try:
        return _run(ctx)
    except Exception as exc:  # noqa: BLE001 - a broken watch is not a broken presence
        ctx.setdefault("errors", []).append(
            collector_note("snmp", "crashed", str(exc), detail=f"{type(exc).__name__}: {exc}")
        )
        return []


def _run(ctx: dict) -> list[Finding]:
    if not snmp.AVAILABLE or "hosts" not in ctx or not ctx["hosts"] or not _enabled(ctx):
        return []
    mem = tasking.memory(ctx)
    now = tasking.now()
    candidates = snmp_credentials(ctx)

    # Who to ask: known network devices of a watched family, alive now, not
    # polled a moment ago, with the SNMP credentials the memory orders.
    plan: dict[str, tuple[list[Any], dict[str, str]]] = {}
    asked: dict[str, tuple[str, str, list[Any], bool, str, Watch, dict[str, Any]]] = {}
    for ip, mac, entry in tasking.alive_from_memory(ctx, mem.config_hosts()):
        family = str(entry.get("family") or "")
        watch = WATCHES.get(family)
        if watch is None or family not in CAPTURE_COMMANDS:
            continue
        key = tasking.host_key(ctx, ip, mac)
        state = mem.confwatch_state(key)
        if state and _within(state.get("polled_at", ""), MIN_POLL, now):
            continue
        order, full = tasking.plan(ctx, ip, mac, "snmp", candidates)
        if not order:
            continue
        plan[ip] = ([as_auth(credential) for credential in order], watch.oids)
        asked[ip] = (mac, key, order, full, family, watch, state)
    if not plan:
        return []

    found = snmp.query_stamps(
        plan,
        concurrency=tasking.workers(ctx, "snmp", snmp.CONCURRENCY),
        known=[ip for ip, (mac, *_rest) in asked.items() if tasking.answered_before(ctx, ip, mac, "snmp")],
    )

    due: list[tuple[str, str, str, str, list[str], int | None]] = []
    for ip, (mac, key, order, full, family, watch, state) in asked.items():
        hit = found.get(ip)
        credential = None
        if hit is not None and 0 <= hit[0] < len(order):
            credential = order[hit[0]]
        # Same bookkeeping as the inventory's SNMP: the credential that answered
        # is remembered, a whole failed round starts the 24 h rest.
        tasking.settle(ctx, ip, mac, "snmp", credential, attempted=True, full=full)
        if credential is None or hit is None:
            continue
        raw = hit[1]
        stamp = current_stamp(watch, raw)
        uptime = _uptime(raw)
        if not stamp:
            # Answers SNMP but does not publish the stamp (an old image, a
            # restricted view): nothing to compare, nothing to do. If it was
            # known, only the poll time moves.
            if state:
                mem.set_confwatch(key, {**state, "polled_at": now.isoformat()})
            continue
        if not state:
            # First sighting: keep it, the nightly copy covers the rest.
            mem.set_confwatch(key, {"stamp": stamp, "uptime": uptime, "polled_at": now.isoformat(), "captured_at": ""})
            continue
        if changed(watch, state, stamp, uptime):
            due.append((ip, mac, key, family, stamp, uptime))
        else:
            mem.set_confwatch(key, {**state, "stamp": stamp, "uptime": uptime, "polled_at": now.isoformat()})

    # Copies: at most MAX_CAPTURES now and one per device every MIN_CAPTURE_GAP.
    # What waits keeps its old stamp, so the change is noticed again later.
    chosen: list[tuple[str, str, str, str, list[str], int | None]] = []
    for item in due:
        ip, mac, key, family, stamp, uptime = item
        state = asked[ip][6]
        polled = {**state, "polled_at": now.isoformat()}
        if len(chosen) >= MAX_CAPTURES or _within(state.get("captured_at", ""), MIN_CAPTURE_GAP, now):
            mem.set_confwatch(key, polled)
            continue
        chosen.append(item)
    if not chosen:
        return []

    findings = SshCollector().capture(ctx, {ip for ip, *_rest in chosen})
    copied = {finding.payload.get("ip") for finding in findings}
    for ip, mac, key, family, stamp, uptime in chosen:
        state = asked[ip][6]
        if ip in copied:
            # Copied: this stamp is now the one on file.
            mem.set_confwatch(
                key,
                {"stamp": stamp, "uptime": uptime, "polled_at": now.isoformat(), "captured_at": now.isoformat()},
            )
        else:
            # The login failed or the device refused: try again at the next
            # cycle (the SSH side has its own veto against hammering).
            mem.set_confwatch(key, {**state, "polled_at": now.isoformat()})
    ctx["confwatch_copies"] = len(findings)
    return findings
