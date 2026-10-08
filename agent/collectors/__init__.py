"""The collector registry.

Importing this package registers every built-in collector. New levels of the
roadmap (SNMP, SSH, WinRM, hypervisors) each land as one module here with a
``@register`` on their class -- the main loop never changes.
"""

from __future__ import annotations

from agent.collectors.base import Collector, Finding

_REGISTRY: list[type[Collector]] = []


def register(cls: type[Collector]) -> type[Collector]:
    _REGISTRY.append(cls)
    return cls


#: The order the main loop runs them in, which is **not** the order the imports
#: happen to be written in.
#:
#: This mattered more than it looks: the sweep is what fills ``ctx["hosts"]``
#: and the SNMP collector only knocks on doors that answered, so SNMP running
#: first meant it found an empty list, returned nothing, and said nothing about
#: it. Leaving the order to the import line -- where alphabetical is the natural
#: thing to write -- put `snmp` before `sweep` and silently disabled every SNMP
#: finding in the product. Named here so it cannot happen again by accident.
#:
#: `fingerprint` (huellas sin credenciales) va justo detrás del barrido y
#: **delante** de SNMP/SSH/WinRM a propósito: el servidor deja que el último
#: hallazgo gane en las claves sueltas (`os`, `hostname`), así lo que cuenten
#: los protocolos con credencial pisa lo que este solo adivina.
#:
#: Lo mismo vale para SSH y WinRM, que tampoco llaman a nadie que no haya
#: contestado antes al barrido. Los hipervisores van al final porque no
#: dependen de `ctx["hosts"]` --un vCenter tiene dirección propia-- pero sí
#: interesa que sus hallazgos lleguen después de los del barrido: así los
#: enriquecen en vez de estrenar la fila.
RUN_ORDER: tuple[str, ...] = ("local", "sweep", "fingerprint", "snmp", "ssh", "winrm", "hypervisors")


def all_collectors() -> list[Collector]:
    """One instance of every registered collector, in the order they must run.

    A collector whose name is not in ``RUN_ORDER`` still runs, at the end: a
    new module should not have to be added in two places to work at all.
    """
    place = {name: index for index, name in enumerate(RUN_ORDER)}
    ordered = sorted(_REGISTRY, key=lambda cls: place.get(cls.name, len(place)))
    return [cls() for cls in ordered]


# Importing the modules is what fills the registry; `RUN_ORDER` decides who
# goes first, so this line is free to stay alphabetical.
from agent.collectors import (  # noqa: E402,F401
    fingerprint,
    hypervisors,
    local,
    snmp,
    ssh,
    sweep,
    winrm,
)

__all__ = ["Collector", "Finding", "all_collectors", "register"]
