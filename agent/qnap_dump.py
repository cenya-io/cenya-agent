"""``cenya-agent qnap-dump``: what a real QNAP answers, in a file to send us.

QNAP publishes no documented API, so the inventory reader in
``agent.storage_arrays`` was written from what other projects use. This
command logs in once, asks the same calls the agent asks, and writes every
answer as it came, so the field names can be checked against a real device
before anyone relies on them.

It changes nothing on the QNAP (only reads), needs no enrolment, and never
writes the password or the session: the password is asked for without being
shown (or read from ``CENYA_QNAP_PASSWORD``), and the session id is replaced
in every answer before it reaches the file.
"""

from __future__ import annotations

import getpass
import os
import ssl
import sys
import urllib.request
from pathlib import Path
from typing import Any

from agent import storage_arrays
from agent.hypervisor import HypervisorError, _NoRedirects
from agent.i18n import _t

PASSWORD_ENV_VAR = "CENYA_QNAP_PASSWORD"
DEFAULT_FILENAME = "cenya-qnap-dump.txt"
#: An answer bigger than this is cut in the file: nobody reads 4 MB of XML.
MAX_ANSWER_CHARS = 4 * 1024 * 1024


def _usage(prog: str) -> str:
    return _t("Uso: %(prog)s DIRECCIÓN USUARIO [--port PUERTO] [--output FICHERO] [--insecure]") % {"prog": prog}


def scrub(text: str, secrets: list[str]) -> str:
    """The answer without the session id (or anything else secret in it)."""
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<retirado>")
    return text


def dump(client: storage_arrays.QNAPClient) -> str:
    """Every call the agent makes, as the QNAP answered it, the session removed."""
    sections: list[str] = []
    for name, path in storage_arrays.QNAP_CALLS.items():
        print(_t("Leyendo %(path)s…") % {"path": path}, file=sys.stderr, flush=True)
        answer = client.call(path)[:MAX_ANSWER_CHARS]
        sections.append(f"===== {name}: {path}\n{scrub(answer, [client.sid, client.secret])}\n")
    return "\n".join(sections)


def run(args: list[str], prog: str = "cenya-agent qnap-dump", environ: Any = None) -> int:
    """The command. Returns the process exit code: 0 done, 1 failed, 2 misused."""
    env = os.environ if environ is None else environ
    port = 0
    insecure = False
    output = Path.home() / DEFAULT_FILENAME
    positional: list[str] = []
    rest = iter(args)
    for arg in rest:
        if arg == "--insecure":
            insecure = True
        elif arg == "--port":
            value = next(rest, "")
            if not value.isdigit():
                print(_usage(prog), file=sys.stderr)
                return 2
            port = int(value)
        elif arg in ("--output", "-o"):
            value = next(rest, "")
            if not value:
                print(_usage(prog), file=sys.stderr)
                return 2
            output = Path(value).expanduser()
        elif arg in ("--help", "-h"):
            print(_usage(prog))
            return 0
        else:
            positional.append(arg)
    if len(positional) != 2:
        print(_usage(prog), file=sys.stderr)
        return 2
    host, username = positional
    password = (env.get(PASSWORD_ENV_VAR) or "").strip()
    if not password:
        if sys.stdin is None or not sys.stdin.isatty():
            print(_t("Falta la contraseña de la QNAP: pásala en la variable %(var)s.") % {"var": PASSWORD_ENV_VAR}, file=sys.stderr)
            return 2
        password = getpass.getpass(
            _t("Contraseña de %(user)s en la QNAP (no se muestra ni se guarda): ") % {"user": username}
        )
    client = storage_arrays.QNAPClient(host, username, password, port=port)
    if insecure:
        # Solo para este volcado puntual, a petición de quien lo lanza: una
        # QNAP con su certificado de fábrica. El agente nunca lo hace.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        client.rest._opener = urllib.request.build_opener(_NoRedirects, urllib.request.HTTPSHandler(context=context))
    try:
        client.login()
    except HypervisorError as exc:
        if exc.status == 401:
            print(_t("La QNAP no aceptó ese usuario y contraseña, o la cuenta pide doble factor."), file=sys.stderr)
        else:
            print(_t("No se pudo hablar con la QNAP: %(reason)s") % {"reason": exc}, file=sys.stderr)
        return 1
    try:
        text = dump(client)
    finally:
        client.logout()
    output.write_text(text, encoding="utf-8")
    print(
        _t("Hecho: %(file)s. No lleva la contraseña ni la sesión; ábrelo antes de enviarlo si quieres revisarlo.")
        % {"file": output}
    )
    return 0
