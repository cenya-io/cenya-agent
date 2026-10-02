"""The program OpenSSH runs when it needs a password: ``SSH_ASKPASS``.

``ssh`` has no option to take a password from a variable or from stdin, and
``sshpass`` does not exist for Windows. What OpenSSH does have (>= 8.4) is
``SSH_ASKPASS_REQUIRE=force``: ``ssh`` runs the program named by ``SSH_ASKPASS``
with the prompt as its only argument and reads the answer from its standard
output. This is that program. It is deliberately tiny and does not import
anything else from the agent, so the frozen executable that carries it
(``cenya-agent-askpass``) starts fast: ``ssh`` runs it once per login.

The password reaches it through an environment variable of the ``ssh`` child
process (``SECRET_ENV``) -- never the command line, never a file -- which is the
same trust model as ``sshpass -e``. Nothing is interpolated by a shell anywhere
on the way, so spaces, quotes, ``%``, ``!``, ``^``, ``&``, ``|``, ``<``, ``>``,
accents and a trailing backslash arrive exactly as typed.

It answers **only** a password prompt. ``ssh`` uses the same mechanism to ask
"Are you sure you want to continue connecting?" and for a key's passphrase, and
handing the password to either would be a leak (to whoever is on the other end
of a host-key prompt). For those it prints nothing and exits non-zero, which
``ssh`` treats as "no answer".
"""

from __future__ import annotations

import os
import re
import sys

#: The environment variable of the ``ssh`` child that carries the secret.
SECRET_ENV = "CENYA_SSH_SECRET"

#: OpenSSH's own password prompts end in "password:" ("user@host's password: ",
#: "(user@host) Password: " for keyboard-interactive).
_PASSWORD_PROMPT = re.compile(r"password\s*:?\s*$", re.IGNORECASE)


def wants_password(prompt: str, prompt_kind: str = "") -> bool:
    """Whether ``prompt`` is a request for the account password and nothing else.

    ``prompt_kind`` is ``SSH_ASKPASS_PROMPT``: newer ``ssh`` sets it to
    ``confirm`` (a yes/no question) or ``none`` (information only), which are
    refused outright whatever the text says.
    """
    if prompt_kind.lower() in ("confirm", "none"):
        return False
    lowered = prompt.lower()
    # A key's passphrase is not the account password, even if its comment says so.
    if "passphrase" in lowered or "pin" in lowered.split():
        return False
    return bool(_PASSWORD_PROMPT.search(prompt))


def _secret() -> bytes | None:
    """The secret as raw bytes. On POSIX straight from ``environb`` so a
    non-UTF-8 locale cannot alter it; on Windows the environment is Unicode and
    OpenSSH sends what it reads, so UTF-8 is what the server should receive."""
    if os.name == "posix":
        return os.environb.get(SECRET_ENV.encode())
    value = os.environ.get(SECRET_ENV)
    return None if value is None else value.encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    prompt = args[0] if args else ""
    if not wants_password(prompt, os.environ.get("SSH_ASKPASS_PROMPT", "")):
        return 1
    secret = _secret()
    if secret is None or b"\n" in secret or b"\r" in secret:
        return 1
    # `buffer`: the console's code page must not re-encode the secret.
    sys.stdout.buffer.write(secret + b"\n")
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
