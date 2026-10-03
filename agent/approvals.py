"""Reseal requests wait for a person on this machine (the security review, finding 3).

A `reseal` order asks this agent to open its sealed credentials and seal them
again for another agent's public key. The server cannot open them; that is the
whole promise. But the server is also who says which key the "new agent" has,
so an attacker in control of the server could present its own key and walk
away with every password. The defence: this agent only reseals for a key that
someone *here* has allowed, in the window, after seeing its fingerprint.

Once a key is allowed (agent uuid + fingerprint), later reseals for it go
through on their own: credentials added later, a password changed. A new key
for the same agent is a new question. A refusal answers the order and is not
remembered: the server asks again the next day, at most.

Nothing here holds a secret: the order's credentials stay sealed until the
person says yes, and they are opened in `agent.orders`, not here.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent import sealing, store
from agent.i18n import _t

#: El fichero con las claves ya permitidas (uuid + huella), en la carpeta de estado.
FILE_NAME = store.RESEAL_TRUST_FILE
#: Cuánto espera un resellado a que alguien decida. El servidor da el encargo
#: por perdido a las 24 h; un poco antes, para contestar algo.
WAIT_SECONDS = 23 * 3600
#: Cuántas claves recuerda. Una pyme tiene dos o tres agentes.
MAX_TRUSTED = 200

ALLOW = "allow"
DENY = "deny"
TIMEOUT = "timeout"


def fingerprint(public_key_pem: str) -> str:
    """SHA-256 of the key (SubjectPublicKeyInfo, DER), as the window shows it: 16 groups of 4.

    Raises `sealing.SealError` for a key that is not valid.
    """
    from cryptography.hazmat.primitives import serialization

    key = sealing.load_public_key(public_key_pem)
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashlib.sha256(der).hexdigest().upper()
    return " ".join(digest[i : i + 4] for i in range(0, len(digest), 4))


@dataclass
class Request:
    order_id: str
    agent: str
    agent_name: str
    fingerprint: str
    count: int
    received_at: str
    decided: threading.Event = field(default_factory=threading.Event, repr=False)
    decision: str = ""

    def view(self) -> dict[str, Any]:
        return {
            "id": self.order_id,
            "agent": self.agent,
            "agent_name": self.agent_name,
            "fingerprint": self.fingerprint,
            "count": self.count,
            "received_at": self.received_at,
        }


class ResealApprovals:
    """The pending requests (in memory) and the allowed keys (on disk, protected). Thread-safe."""

    def __init__(
        self,
        environ: Mapping[str, str] | None = None,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        say: Callable[[str], None] = lambda _line: None,
    ) -> None:
        self._environ = environ
        self._clock = clock
        self._say = say
        self._lock = threading.Lock()
        self._pending: dict[str, Request] = {}

    # --- Las claves permitidas ------------------------------------------------------------

    def _path(self) -> Path:
        return store.state_dir(self._environ) / FILE_NAME

    def _load(self) -> list[dict[str, str]]:
        try:
            data = json.loads(self._path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        entries = data.get("trusted") if isinstance(data, dict) else None
        if not isinstance(entries, list):
            return []
        return [e for e in entries if isinstance(e, dict) and isinstance(e.get("agent"), str) and isinstance(e.get("fingerprint"), str)]

    def trusted(self, agent: str, key_fingerprint: str) -> bool:
        with self._lock:
            return any(e["agent"] == agent and e["fingerprint"] == key_fingerprint for e in self._load())

    def _trust(self, agent: str, key_fingerprint: str, name: str) -> None:
        entries = [e for e in self._load() if e["agent"] != agent]
        entries.append({"agent": agent, "fingerprint": key_fingerprint, "name": name[:120], "at": self._clock().isoformat()})
        try:
            store.write_protected(self._path(), json.dumps({"trusted": entries[-MAX_TRUSTED:]}, ensure_ascii=False, indent=1))
        except OSError:
            # Sin poder guardarlo, se vuelve a preguntar la próxima vez: más
            # molesto, nunca menos seguro.
            pass

    # --- Las peticiones ------------------------------------------------------------------

    def ask(self, order_id: str, agent: str, agent_name: str, key_fingerprint: str, count: int, *, timeout: float = WAIT_SECONDS) -> str:
        """Wait until someone decides in the window. Returns `ALLOW`, `DENY` or `TIMEOUT`."""
        request = Request(
            order_id=order_id,
            agent=agent,
            agent_name=agent_name,
            fingerprint=key_fingerprint,
            count=count,
            received_at=self._clock().isoformat(),
        )
        with self._lock:
            self._pending[order_id] = request
        self._say(
            _t(
                "[agente] El agente «%(name)s» pide las credenciales de este perfil: hay que permitirlo "
                "o rechazarlo en la ventana de Cenya Agent de este equipo."
            )
            % {"name": agent_name or agent}
        )
        try:
            request.decided.wait(timeout)
            return request.decision or TIMEOUT
        finally:
            with self._lock:
                self._pending.pop(order_id, None)

    def decide(self, order_id: str, allow: bool) -> bool:
        """Answer a pending request. `False` if there is none with that id (already answered, expired)."""
        with self._lock:
            request = self._pending.get(order_id)
            if request is None or request.decided.is_set():
                return False
            if allow:
                self._trust(request.agent, request.fingerprint, request.agent_name)
            request.decision = ALLOW if allow else DENY
            request.decided.set()
        return True

    def pending(self) -> list[dict[str, Any]]:
        with self._lock:
            return [request.view() for request in self._pending.values()]
