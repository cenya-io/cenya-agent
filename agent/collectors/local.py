"""The local collector: the machine the agent runs on.

Reports the agent's own host as a finding. It exists so the whole pipeline --
enrol, heartbeat, push, review, accept -- can be exercised end to end before
the first real collector (SNMP) exists, and so a freshly enrolled agent always
has something to show for itself.
"""

from __future__ import annotations

import socket
import uuid

from agent import net
from agent.collectors.base import Finding
from agent.collectors import register


def _mac() -> str:
    node = uuid.getnode()
    # getnode() sets the multicast bit when it had to invent the address; an
    # invented MAC is no identity at all.
    if node & (1 << 40):
        return ""
    return ":".join(f"{(node >> shift) & 0xFF:02x}" for shift in range(40, -1, -8))


@register
class LocalCollector:
    name = "local"

    def collect(self, ctx: dict) -> list[Finding]:
        hostname = socket.gethostname()
        ip = net.primary_ip()
        mac = _mac()
        # Identity prefers the MAC; a host that changes IP is the same host.
        identity = {"mac": mac} if mac else ({"ip": ip} if ip else {"hostname": hostname})
        return [
            Finding(
                kind="host",
                identity=identity,
                payload={
                    "hostname": hostname,
                    "ip": ip,
                    "mac": mac,
                    "seen_by": "local",
                },
            )
        ]
