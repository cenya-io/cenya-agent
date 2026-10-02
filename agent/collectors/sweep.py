"""L1: the subnet sweep.

Ping the subnet, read the ARP cache the pings just filled, resolve names
backwards. The live hosts go into ``ctx["hosts"]`` so the SNMP collector only
knocks on doors that answered.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from agent import net
from agent.collectors import tasking
from agent.collectors.base import Finding
from agent.notes import collector_note
from agent.collectors import register


def _subnets(ctx: dict) -> list[str]:
    """Server config first, the environment as an override, the agent's own
    /24 when nothing is said at all."""
    server = (ctx.get("config") or {}).get("subnets") or []
    if server:
        return list(server)
    env = ctx.get("env")
    if env and env.subnets:
        return list(env.subnets)
    own = net.own_subnet()
    return [own] if own else []


@register
class SweepCollector:
    name = "sweep"

    def collect(self, ctx: dict) -> list[Finding]:
        subnets = _subnets(ctx)
        if not subnets:
            ctx.setdefault("errors", []).append(
                collector_note("sweep", "no_subnets", "no hay subredes que barrer")
            )
            return []

        addresses = net.expand_subnets(subnets)
        # Una dirección excluida no recibe ni el ping: es la promesa que se le
        # hace a quien la excluyó, no una cortesía.
        addresses = [ip for ip in addresses if not tasking.excluded(ctx, ip)]
        progress = tasking.Progress(ctx, self.name, len(addresses))
        ping_workers = tasking.workers(ctx, "ping", net.SWEEP_WORKERS)
        alive = net.sweep(addresses, workers=ping_workers, on_done=progress.tick)
        arp = net.arp_table()

        # Reverse lookups can block; run them concurrently with a hard cap
        # (which the task's gentleness can only lower).
        with ThreadPoolExecutor(max_workers=max(1, min(20, ping_workers))) as pool:
            hostnames = list(pool.map(net.reverse_dns, alive))

        hosts = []
        findings = []
        for ip, hostname in zip(alive, hostnames):
            mac = arp.get(ip, "")
            hosts.append({"ip": ip, "mac": mac})
            # Identity prefers the MAC; a host that changes IP is the same host.
            identity = {"mac": mac} if mac else {"ip": ip}
            findings.append(
                Finding(
                    kind="host",
                    identity=identity,
                    payload={
                        "hostname": hostname,
                        "ip": ip,
                        "mac": mac,
                        "seen_by": "sweep",
                    },
                )
            )
        ctx["hosts"] = hosts
        return findings
