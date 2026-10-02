"""L1: the subnet sweep.

Ping the subnet, read the ARP cache the pings just filled, resolve names
backwards. The live hosts go into ``ctx["hosts"]`` so the SNMP collector only
knocks on doors that answered.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from agent import net
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

        alive = net.sweep(net.expand_subnets(subnets))
        arp = net.arp_table()

        # Reverse lookups can block; run them concurrently with a hard cap.
        with ThreadPoolExecutor(max_workers=20) as pool:
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
