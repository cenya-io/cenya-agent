"""What a collector is and how findings look.

A collector answers one question about the network ("who is on this subnet",
"what does this switch say about itself") and returns plain findings. It never
talks to the server: shaping the payload and pushing it is the client's job,
so a collector can be tested without any network at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class Finding:
    """One thing the agent saw.

    ``identity`` holds the stable keys the fingerprint is built from (a host's
    MAC, never its hostname -- a renamed host is the same host); ``payload`` is
    everything worth showing a person in the review tray.
    """

    kind: str
    identity: dict[str, Any]
    payload: dict[str, Any] = field(default_factory=dict)

    def as_json(self) -> dict[str, Any]:
        return {"kind": self.kind, "identity": self.identity, "payload": self.payload}


class Collector(Protocol):
    """One source of findings. Implementations register themselves in
    ``agent.collectors`` and the main loop runs them all, one after another.

    ``ctx`` is shared, in registration order: the sweep leaves the live hosts
    in ``ctx["hosts"]`` and SNMP only queries those. The server-sent
    configuration travels in ``ctx["config"]``. A collector that cannot run
    (its library is missing, its input is absent) appends a line to
    ``ctx["errors"]`` and returns nothing instead of killing the sweep.
    """

    name: str

    def collect(self, ctx: dict) -> list[Finding]: ...
