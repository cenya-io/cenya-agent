"""What a collector could not do, said so the web can translate it.

Collector notes ("ssh: no hay credenciales SSH configuradas") and the reports of
«Analizar» are not read on the agent's machine: they travel to the server and
the web shows them -- in Ajustes → Agentes and in the findings tray -- to
whoever is signed in, in *their* language. So the agent must not translate them
(that would store, say, German in the database for a Spanish user). It sends a
**code with its parameters**, and the server writes the sentence at render time
in the viewer's language (``core/agent_notes.py``).

A note is still a ``str``: its Spanish text, exactly as before. Everything that
joined, printed, compared or stored these strings keeps working, a server that
does not know the codes yet shows that text, and so does a server that meets a
code newer than itself. The code and parameters ride along on the object and
go out with ``as_json``.

Parameters are only what the sentence needs, and never a secret: a user by
name, an SNMP community by its number (``agent/probe.py``).
"""

from __future__ import annotations

from typing import Any

Param = str | int | float | bool


class Note(str):
    """Un texto en castellano que además sabe qué código y datos lo forman."""

    collector: str
    code: str
    params: dict[str, Param]

    def __new__(cls, text: str, *, collector: str, code: str, **params: Param) -> "Note":
        note = super().__new__(cls, text)
        note.collector = collector
        note.code = code
        note.params = {key: value for key, value in params.items() if value is not None}
        return note

    def as_json(self) -> dict[str, Any]:
        return {"collector": self.collector, "code": self.code, "params": dict(self.params), "text": str(self)}


def collector_note(collector: str, code: str, text: str, **params: Param) -> Note:
    """Lo que un colector no pudo hacer, con su prefijo de siempre («ssh: ...»)."""
    return Note(f"{collector}: {text}", collector=collector, code=code, **params)


def probe_note(protocol: str, code: str, text: str, **params: Param) -> Note:
    """Una línea del informe de «Analizar»: sin prefijo, la pantalla pone el protocolo."""
    return Note(text, collector=protocol, code=code, **params)


def to_json(entry: object) -> dict[str, Any]:
    """Cualquier cosa de `ctx["errors"]` como nota: un texto suelto va sin código.

    Un texto sin código es lo que el servidor enseña tal cual, que es justo lo
    que merece algo que nadie previó (una excepción de un colector nuevo).
    """
    if isinstance(entry, Note):
        return entry.as_json()
    return {"collector": "", "code": "", "params": {}, "text": str(entry)}
