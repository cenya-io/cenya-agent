"""The connection string: where the portal is, and the one-time code.

``cenya://portal.midominio.com/K7QF-9M2X-4TQN`` is everything a person pastes.
``cenya://`` means HTTPS; ``cenya+http://`` exists only for a local test
portal, and `agent.config.check_transport` still refuses it against any other
machine.

Parsing is strict on purpose. The string comes from a clipboard, an e-mail or
a deployment script, and what the agent does with it is send a credential to
the host it names: anything that is not exactly *host, optional port, code* is
an error, never a guess. In particular a ``user:password@`` part is refused --
it is how a string that looks like one host reaches another.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from agent.i18n import _t

#: scheme -> the URL scheme the agent will actually speak.
SCHEMES = {"cenya": "https", "cenya+http": "http"}

_CODE = re.compile(r"^[A-Za-z0-9]{4}(-?[A-Za-z0-9]{4}){2}$")


class ConnectionStringError(ValueError):
    """The string is not one the portal could have produced. Its text is for a person."""


@dataclass(frozen=True)
class Connection:
    url: str
    code: str


def _invalid() -> ConnectionStringError:
    return ConnectionStringError(
        _t(
            "La cadena de conexión no es válida: debe parecerse a "
            "cenya://portal.midominio.com/XXXX-XXXX-XXXX. Cópiala entera de Ajustes → Agentes."
        )
    )


def parse(raw: str) -> Connection:
    """The portal URL and the code inside a connection string, or raise."""
    text = str(raw or "").strip().strip("\"'").strip()
    try:
        parts = urlsplit(text)
        host = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise _invalid() from exc
    scheme = SCHEMES.get(parts.scheme.lower())
    code = parts.path.strip("/")
    if (
        scheme is None
        or not host
        or "@" in parts.netloc
        or parts.query
        or parts.fragment
        or "/" in code
        or not _CODE.match(code)
    ):
        raise _invalid()
    # Un IPv6 literal pierde los corchetes en `hostname` y los necesita en la URL.
    shown = f"[{host}]" if ":" in host else host
    return Connection(url=f"{scheme}://{shown}{f':{port}' if port else ''}", code=code.upper())
