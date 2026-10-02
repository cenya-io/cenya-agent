"""Leaving: ``cenya-agent goodbye`` (spec 1.7).

The agent tells the server it is going away -- the server marks it as
uninstalled and its token stops working -- and then removes its enrolment and
its identity key from the state folder. The uninstaller will call this.

**It always leaves.** A server that cannot be reached (the machine is being
decommissioned, the portal moved, there is no network) is no reason to keep a
token on a disk that is about to be thrown away: the local state goes anyway,
the exit code is 0, and the person is told what happened and what is left to
do on the web.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping

from agent import store
from agent import settings as local_settings
from agent.client import AgentClient, PushError
from agent.config import from_env
from agent.i18n import _t

REASON = "uninstall"


def run(args: list[str], environ: Mapping[str, str] | None = None) -> int:
    """The `goodbye` subcommand. Returns the process exit code."""
    env = os.environ if environ is None else environ
    try:
        store.secure_state_dir(env)
    except store.StoreError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    try:
        config = from_env(dict(env))
    except SystemExit as exc:
        # Sin enrolar, o una dirección a la que no se habla (http:// fuera de
        # esta máquina): no hay a quién avisar, pero lo de aquí se borra igual.
        print(str(exc.code), file=sys.stderr)
    else:
        local = local_settings.load(env)
        client = AgentClient(config.url, config.token, ca_bundle=config.ca_bundle or local.ca_bundle, proxy=local.proxy)
        try:
            client.goodbye(REASON)
        except PushError as exc:
            print(
                _t(
                    "No se pudo avisar al servidor (%(error)s). El enrolamiento de este equipo se borra igualmente; "
                    "el agente seguirá apareciendo en Ajustes → Agentes hasta que se borre allí."
                )
                % {"error": exc},
                file=sys.stderr,
            )
        else:
            print(_t("Se ha avisado al servidor (%(url)s): este agente queda dado de baja.") % {"url": config.url})
    removed = store.remove(env)
    for target in removed:
        print(_t("Borrado: %(path)s") % {"path": target})
    if not removed:
        print(_t("No había enrolamiento que borrar en %(path)s.") % {"path": store.state_dir(env)})
    return 0
