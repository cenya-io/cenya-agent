"""An interactive SSH session, for the devices that do not answer a bare command.

``ssh host "show version"`` works on a Cisco or a Linux box, but a Huawei VRP,
many Dell PowerConnect and other switches only talk inside a terminal: the
command alone comes back empty. And a PowerConnect lets the SSH connection in
without a password and then asks «User Name:» and «Password:» inside the
session, the way a console does -- SecureCRT answers them on its own, the
agent never did (08-10-2026: six switches of one office stayed as «solo
responde» with the right password, and the failed tries suspended it).

So, when the plain command gives nothing, the collector opens a session like a
person would: answers the login prompts with the credential, turns paging off
with every vendor's command (the unknown ones are a harmless error), asks for
the version, and reads the device's name from its own prompt. Read-only
commands only; nothing is configured, and paging is switched off **for this
session** (``temporary``, ``terminal length 0``).

The password goes typed into the encrypted channel, exactly as a person types
it; it never goes on a command line and is scrubbed from what is read back.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
from typing import IO

from agent import ssh

#: What a device asks for inside the session.
LOGIN_RE = re.compile(r"(?:user\s*name|username|login)\s*:\s*$", re.IGNORECASE)
PASSWORD_RE = re.compile(r"password\s*:\s*$", re.IGNORECASE)
#: A CLI prompt at the end of what was read: ``SW-1#``, ``SW-1>``,
#: ``<SW-Huawei-01>`` (VRP, Comware), ``[~SW-1]``, ``SW-1(config)#``.
PROMPT_RE = re.compile(
    r"(?:^|\n)[ \t]*(?:<(?P<vrp>[\w.\-:/~]+)>|\[[~*]?(?P<square>[\w.\-:/]+)\]|(?P<cli>[\w.\-:/]+)(?:\([\w.\-]+\))?[ \t]*[>#])[ \t]*$"
)
#: A pager waiting for a key.
MORE_RE = re.compile(r"(?:-+\s*more\s*-+|--more--|<--- more --->|press any key to continue)\s*$", re.IGNORECASE)
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\x08|\r")

#: The whole session, from connecting to the last answer.
SESSION_SECONDS = 60
#: Output must stop for this long before a prompt counts: a line ending in
#: «#» half-way through a long answer is not the prompt.
SETTLE_SECONDS = 0.6
#: After the last command, with nothing new for this long, it is over.
QUIET_SECONDS = 5

#: Paging off for this session, each vendor its own (the rest answer with a
#: harmless «unknown command»), then who it is.
PAGING_OFF = (
    "terminal length 0",  # Cisco, Dell N
    "terminal datadump",  # Dell PowerConnect
    "screen-length 0 temporary",  # Huawei VRP
    "screen-length disable",  # HPE Comware
    "no page",  # ArubaOS-Switch
)
IDENTIFY = (*PAGING_OFF, "show version", "display version", "show system")


_MORE_ANYWHERE = re.compile(r"-+\s*more\s*-+|--more--|<--- more --->", re.IGNORECASE)


def command_output(output: str, command: str) -> str:
    """What one command printed in a session: after its echo, before the next prompt.

    The pager residue («---- More ----») a device leaves when paging could not
    be switched off is taken out.
    """
    text = _clean(output)
    index = text.rfind(command)
    if index < 0:
        return ""
    lines = text[index + len(command) :].split("\n")[1:]
    if lines and PROMPT_RE.search("\n" + lines[-1]):
        lines = lines[:-1]
    body = "\n".join(_MORE_ANYWHERE.sub("", line).rstrip() for line in lines).strip("\n")
    return body + "\n" if body else ""


def prompt_name(output: str) -> str:
    """The device's name as its prompt says it, or empty."""
    found = ""
    for match in PROMPT_RE.finditer(_clean(output)):
        found = match.group("vrp") or match.group("square") or match.group("cli") or found
    return found


#: A pager prompt and the way the device rubs it out: the cursor goes back
#: (``ESC[42D`` on a Huawei, backspaces on a Cisco), spaces cover it, and the
#: cursor goes back again, so what follows starts at the left margin with its
#: own indentation.
_PAGER_RE = re.compile(
    r"[ \t]*(?:-+ ?more ?-+|--more--|<--- more --->)[ \t]*(?:\x1b\[\d+D|\x08+)?[ \t]*(?:\x1b\[\d+D|\x08+)?",
    re.IGNORECASE,
)


def _clean(text: str) -> str:
    return _ANSI_RE.sub("", _PAGER_RE.sub("", text))


def run(
    *,
    host: str,
    username: str,
    secret: str = "",
    port: int = 0,
    key_file: str = "",
    commands: tuple[str, ...] = IDENTIFY,
    timeout: float = SESSION_SECONDS,
) -> ssh.Answer:
    """A session with those commands. Never raises: returns what happened.

    ``connected`` is that a CLI prompt was reached. An old device that only
    speaks SHA-1 is retried with its algorithms, as `ssh.run` does.
    """
    answer, stderr = _session(host, username, secret, port, key_file, commands, timeout, legacy=False)
    if not answer.connected and ssh.negotiation_failed(stderr) and ssh.legacy_options():
        answer, _ = _session(host, username, secret, port, key_file, commands, timeout, legacy=True)
    return answer


def _argv(host: str, username: str, port: int, key_file: str, mode: str, legacy: bool) -> list[str]:
    argv = ssh.argv_for(
        host=host,
        username=username,
        port=port,
        key_file=key_file,
        with_password=bool(mode),
        askpass=mode == "askpass",
        legacy=legacy,
    )
    # A terminal even though stdin is a pipe: that is what these devices want.
    position = 3 if argv and argv[0] == "sshpass" else 1
    return [*argv[:position], "-tt", *argv[position:]]


def _pump(stream: IO[bytes], sink: list[bytes]) -> None:
    try:
        while True:
            data = stream.read1(4096) if hasattr(stream, "read1") else stream.read(1)  # type: ignore[attr-defined]
            if not data:
                return
            sink.append(data)
    except (OSError, ValueError):
        return


def _session(
    host: str,
    username: str,
    secret: str,
    port: int,
    key_file: str,
    commands: tuple[str, ...],
    timeout: float,
    *,
    legacy: bool,
) -> tuple[ssh.Answer, str]:
    mode = ssh.password_mode() if secret else ""
    if secret and ("\n" in secret or "\r" in secret):
        return ssh.Answer(connected=False, error="la contraseña contiene un salto de línea", unreachable=True), ""
    try:
        process = subprocess.Popen(
            _argv(host, username, port, key_file, mode, legacy),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=ssh.environment_for(secret, mode),
        )
    except OSError as exc:
        return ssh.Answer(connected=False, error=str(exc), unreachable=True), ""
    out: list[bytes] = []
    err: list[bytes] = []
    readers = [
        threading.Thread(target=_pump, args=(process.stdout, out), daemon=True),
        threading.Thread(target=_pump, args=(process.stderr, err), daemon=True),
    ]
    for reader in readers:
        reader.start()

    def text() -> str:
        return _clean(b"".join(out).decode(errors="replace"))

    def send(line: str) -> bool:
        try:
            assert process.stdin is not None
            process.stdin.write(line.encode() + b"\r\n")
            process.stdin.flush()
            return True
        except (OSError, ValueError, AssertionError):
            return False

    def key(char: str) -> bool:
        """One key, without Enter: a pager takes the space as «next page»."""
        try:
            assert process.stdin is not None
            process.stdin.write(char.encode())
            process.stdin.flush()
            return True
        except (OSError, ValueError, AssertionError):
            return False

    pending = list(commands)
    paged_at = 0  # length of the raw screen when the pager last got its key
    logged_in = False
    sent_user = False
    sent_password = False
    rejected = False
    acted_at = 0  # length of the text when we last answered something
    last_length = 0
    last_growth = time.monotonic()
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            current = text()
            now = time.monotonic()
            if len(current) != last_length:
                last_length, last_growth = len(current), now
            settled = now - last_growth >= SETTLE_SECONDS
            fresh = len(current) > acted_at
            last_line = current.rstrip(" \t").rsplit("\n", 1)[-1]
            if process.poll() is not None and settled:
                break
            # The pager is looked for in the raw screen: `text()` already rubs it
            # out, so neither its text nor its freshness can come from there.
            screen = _ANSI_RE.sub("", b"".join(out).decode(errors="replace")).rstrip(" \t")
            if len(screen) > paged_at and MORE_RE.search(screen.rsplit("\n", 1)[-1]):
                if not key(" "):
                    break
                paged_at, acted_at = len(screen), len(current)
            elif fresh and settled and not logged_in and LOGIN_RE.search(last_line):
                if sent_user:
                    rejected = True  # asked again: the login was refused
                    break
                if not send(username):
                    break
                sent_user, acted_at = True, len(current)
            elif fresh and settled and not logged_in and PASSWORD_RE.search(last_line):
                if sent_password:
                    rejected = True
                    break
                if not send(secret):
                    break
                sent_password, acted_at = True, len(current)
            elif fresh and settled and PROMPT_RE.search(current[-300:]):
                logged_in = True
                if not pending:
                    break
                if not send(pending.pop(0)):
                    break
                acted_at = len(current)
            elif logged_in and not pending and now - last_growth >= QUIET_SECONDS:
                break
            time.sleep(0.1)
    finally:
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass
        for reader in readers:
            reader.join(timeout=2)
        for stream in (process.stdin, process.stdout, process.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass
    output = text()
    if secret:
        output = output.replace(secret, "***")
    stderr = b"".join(err).decode(errors="replace")
    if logged_in:
        return ssh.Answer(connected=True, output=output, error=""), stderr
    if rejected:
        return ssh.Answer(connected=False, error="Permission denied (inicio de sesión dentro de la sesión)"), stderr
    reason = ssh._reason(stderr) if stderr.strip() else "no apareció el indicador del equipo"
    return (
        ssh.Answer(
            connected=False,
            error=reason,
            unreachable=ssh.before_auth(stderr),
            authenticated=ssh.authenticated(stderr),
        ),
        stderr,
    )
