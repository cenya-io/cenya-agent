"""``cenya-agent settings``: change a local setting from a console or the installer.

Today two settings, the ones something outside the agent needs to set before
the agent itself can talk to anyone:

* ``set ca_bundle <file>`` -- the certificate of a company CA. The file is
  **copied** into the protected state folder (``ca.pem``) and that copy is what
  ``settings.json`` names: the original may sit in a user's Downloads folder,
  where anyone could swap it for their own CA later. It is validated first
  (PEM or DER, at least one certificate) and stored as PEM. The installer's
  ``/CA=`` calls exactly this, before enrolling, so a portal with its own
  certificate enrols straight from the installer.
* ``set auto_update on|off`` -- whether the agent updates itself when the
  server offers a new version (``docs/agente-v2-instalacion.md``, 4).

``unset ca_bundle`` forgets the CA (the copy is deleted). Nothing here prints
a secret, and the proxy URL, which may carry one, is not touched.
"""

from __future__ import annotations

import os
import ssl
import sys
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

from agent import settings as local_settings
from agent import store
from agent.i18n import _t

#: Un certificado de CA, o una cadena de unos pocos, nunca pasa de esto.
MAX_CA_BYTES = 1024 * 1024

_ON = {"on", "1", "true", "yes", "si", "sí"}
_OFF = {"off", "0", "false", "no"}


def _usage() -> int:
    print(
        _t("Uso: cenya-agent settings set ca_bundle <fichero> | set auto_update on|off | unset ca_bundle"),
        file=sys.stderr,
    )
    return 2


def ca_as_pem(data: bytes) -> str:
    """The CA certificate(s) in `data` as PEM, or raise `ValueError` if there is none.

    `ssl` carga la cadena igual que lo hará el cliente (`agent.client`): si
    aquí no vale, allí tampoco valdría, y es mejor saberlo en el instalador.
    """
    if b"-----BEGIN CERTIFICATE-----" in data:
        pem = data.decode("ascii", errors="strict")
    else:
        pem = ssl.DER_cert_to_PEM_cert(data)
    context = ssl.create_default_context(cadata=pem)
    # `x509` cuenta también un certificado autofirmado sin la marca de CA, que
    # es lo que muchas pymes tienen y también vale como ancla de confianza.
    if not context.cert_store_stats().get("x509"):
        raise ValueError("no certificate")
    return pem


def _set_ca(source: str, env: Mapping[str, str]) -> int:
    path = Path(source)
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_CA_BYTES + 1)
    except OSError as exc:
        print(_t("No se pudo leer el certificado %(path)s: %(error)s") % {"path": path, "error": exc}, file=sys.stderr)
        return 1
    try:
        if len(data) > MAX_CA_BYTES:
            raise ValueError("too big")
        pem = ca_as_pem(data)
    except (ValueError, UnicodeDecodeError, ssl.SSLError):
        print(
            _t("%(path)s no contiene ningún certificado de CA válido (PEM o DER).") % {"path": path}, file=sys.stderr
        )
        return 1
    target = store.state_dir(env) / store.CA_FILE
    try:
        store.write_protected(target, pem)
    except OSError as exc:
        print(_t("No se pudo guardar el certificado en %(path)s: %(error)s") % {"path": target, "error": exc}, file=sys.stderr)
        return 1
    return _save(replace(local_settings.load_file(env), ca_bundle=str(target)), env, _t(
        "Certificado de CA guardado en %(path)s: el agente lo usará para verificar el portal."
    ) % {"path": target})


def _save(settings: local_settings.Settings, env: Mapping[str, str], said: str) -> int:
    if not local_settings.save(settings, env):
        print(_t("No se pudieron guardar los ajustes en %(path)s.") % {"path": local_settings.path(env)}, file=sys.stderr)
        return 1
    print(said)
    return 0


def run(args: list[str], environ: Mapping[str, str] | None = None) -> int:
    """The `settings` subcommand. Returns the process exit code."""
    env = os.environ if environ is None else environ
    if len(args) < 2 or args[0] not in ("set", "unset"):
        return _usage()
    # Como cualquier otra entrada: la carpeta protegida antes de escribir en ella.
    try:
        securing = store.secure_state_dir(env)
    except store.StoreError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if securing.moved:
        print(store.moved_line(securing), file=sys.stderr)
    verb, name = args[0], args[1]
    if verb == "unset" and name == "ca_bundle" and len(args) == 2:
        (store.state_dir(env) / store.CA_FILE).unlink(missing_ok=True)
        return _save(replace(local_settings.load_file(env), ca_bundle=""), env, _t("Certificado de CA olvidado."))
    if verb == "set" and name == "ca_bundle" and len(args) == 3:
        return _set_ca(args[2], env)
    if verb == "set" and name == "auto_update" and len(args) == 3:
        value = args[2].strip().lower()
        if value not in _ON | _OFF:
            return _usage()
        on = value in _ON
        said = _t("La actualización automática queda encendida.") if on else _t("La actualización automática queda apagada.")
        return _save(replace(local_settings.load_file(env), auto_update=on), env, said)
    return _usage()
