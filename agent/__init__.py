"""Cenya discovery agent.

A small, stateless process that lives inside the customer's network and only
pushes out over HTTPS: heartbeat, sweep, push, sleep. No open ports, no local
database, nothing to restore if the machine dies -- enrol another one and the
server remembers everything that matters.
"""

# La misma que declara agent/pyproject.toml: es la que viaja en el latido y la
# que enseña Ajustes -> Agentes, así que las dos tienen que contar lo mismo.
__version__ = "0.14.0"
