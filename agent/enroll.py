"""Enrolling the agent: `cenya-agent enroll <connection string>`.

The portal gives a short-lived, single-use code inside a connection string; this
trades it for the agent's permanent token and saves that in the protected store
(`agent.store`). Nobody copies a token anywhere: it goes from the server's
response to a file only the service can read, and is never printed.

Two ways in, same result:

* the command, which is what a person (or the installer) runs once;
* ``CENYA_CONNECTION`` in the environment, for a container or a script that
  starts the agent directly. `ensure_enrolled` redeems it on first start and
  *only* then: once an enrolment is saved the code is ignored, so a restart
  never tries to spend a code that is already used.
"""

from __future__ import annotations

import os
import socket
import sys
from collections.abc import Mapping

from agent import __version__, about, connection, identity, store
from agent import settings as local_settings
from agent.client import AgentClient, PushError
from agent.config import check_transport, setting
from agent.i18n import _t


def redeem(
    raw_connection: str, environ: Mapping[str, str], *, ca_bundle: str = "", save: bool = True
) -> store.Enrollment:
    """Redeem the code in `raw_connection` and save the result.

    Raises `SystemExit` with a message written for a person on any failure: this
    runs from a console or from a service start-up, where a stack trace helps
    nobody.

    Con `save=False` no guarda nada: el canal local (`connect`) canjea primero
    y solo guarda si salió bien, para que un fallo deje el enrolamiento de antes.
    """
    try:
        target = connection.parse(raw_connection)
    except connection.ConnectionStringError as exc:
        raise SystemExit(str(exc)) from exc
    check_transport(target.url, dict(environ))
    local = local_settings.load(environ)
    client = AgentClient(target.url, "", ca_bundle=ca_bundle or local.ca_bundle, proxy=local.proxy)
    # Protocolo 2 (spec 1.1): la clave pública, para que el servidor pueda
    # sellarle credenciales, y la presentación del agente. Las dos son
    # opcionales: sin `cryptography` no hay clave, y se enrola igual.
    public_key = identity.ensure(environ)
    presentation = about.build(
        excluded_subnets=local.excluded_subnets,
        excluded_addresses=local.excluded_addresses,
        auto_update=local.auto_update,
    )
    try:
        answer = client.enroll(
            code=target.code,
            hostname=socket.gethostname(),
            version=__version__,
            public_key=public_key,
            about=presentation,
        )
    except PushError as exc:
        raise SystemExit(str(exc)) from exc
    token = answer.get("token")
    if not isinstance(token, str) or not token:
        raise SystemExit(_t("El servidor no devolvió ningún token. ¿Es la dirección de un portal de Cenya?"))
    agent_uuid = answer.get("uuid")
    saved = store.Enrollment(
        url=target.url,
        token=token,
        name=str(answer.get("name") or ""),
        uuid=agent_uuid.strip() if isinstance(agent_uuid, str) else "",
    )
    if not save:
        return saved
    try:
        store.save(saved, environ)
    except store.StoreError as exc:
        # El código ya se gastó y el token no pudo guardarse: se dice, porque la
        # salida es generar otra cadena en el portal y no reintentar esta.
        raise SystemExit(
            _t("%(error)s El código ya se ha usado: genera otra cadena en Ajustes → Agentes.")
            % {"error": exc}
        ) from exc
    return saved


def ensure_enrolled(environ: Mapping[str, str] | None = None) -> None:
    """Enrol from ``CENYA_CONNECTION`` if, and only if, nothing says who we are yet."""
    env = os.environ if environ is None else environ
    if setting(env, "AGENT_TOKEN") or store.load(env) is not None:
        return
    raw = setting(env, "CONNECTION")
    if raw:
        saved = redeem(raw, env)
        print(_t("[agente] Enrolado como «%(name)s» en %(url)s.") % {"name": saved.name, "url": saved.url}, flush=True)


def run(args: list[str], environ: Mapping[str, str] | None = None) -> int:
    """The `enroll` subcommand. Returns the process exit code."""
    env = os.environ if environ is None else environ
    force = "--force" in args
    ca_bundle = ""
    positional: list[str] = []
    rest = iter(a for a in args if a != "--force")
    for arg in rest:
        if arg == "--ca-bundle":
            ca_bundle = next(rest, "")
        else:
            positional.append(arg)

    # Antes de leer nada de la carpeta: lo que haya en una sin proteger no se
    # usa, y en una que no se puede proteger no se guarda el token.
    try:
        securing = store.secure_state_dir(env)
    except store.StoreError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if securing.moved:
        print(store.moved_line(securing), file=sys.stderr)

    existing = store.load(env)
    if existing is not None and not force:
        print(
            _t("Este equipo ya está enrolado como «%(name)s» en %(url)s. Para enrolarlo de nuevo, añade --force.")
            % {"name": existing.name, "url": existing.url},
            file=sys.stderr,
        )
        return 1

    raw = positional[0] if positional else setting(env, "CONNECTION")
    if not raw and sys.stdin is not None and sys.stdin.isatty():
        raw = input(_t("Cadena de conexión (la de Ajustes → Agentes): ")).strip()
    if not raw:
        print(
            _t("Falta la cadena de conexión: cenya-agent enroll cenya://portal.midominio.com/XXXX-XXXX-XXXX"),
            file=sys.stderr,
        )
        return 2

    try:
        saved = redeem(raw, env, ca_bundle=ca_bundle)
    except SystemExit as exc:
        print(exc.code if isinstance(exc.code, str) else _t("El enrolamiento ha fallado."), file=sys.stderr)
        return 1
    print(_t("Agente «%(name)s» enrolado en %(url)s.") % {"name": saved.name, "url": saved.url})
    print(_t("El token queda guardado de forma protegida en %(path)s; no hace falta copiarlo.") % {"path": store.path(env)})
    print(_t("Para dejarlo funcionando, ejecuta: cenya-agent"))
    return 0
