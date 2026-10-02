"""A real ``ssh`` binary, a real password login, and what the server received.

Everything else about password authentication is tested with mocks, and a mock
cannot tell whether OpenSSH really honours ``SSH_ASKPASS_REQUIRE=force`` or
whether a password with a quote, a ``%`` or an accent survives the trip through
``ssh`` and the helper. This does: ``ssh_stub_server`` speaks enough SSH to
record the exact bytes ``ssh`` sent as the password.

Skipped, never failed, when a prerequisite is missing: no ``cryptography``
(test-only; the agent does not use it), no OpenSSH >= 8.4, or no askpass
program. On POSIX the program is a throwaway launcher written to a temp
directory; on Windows it has to be a real executable, so point
``CENYA_TEST_ASKPASS`` at a built ``cenya-agent-askpass.exe``.

Never touches the user's ``~/.ssh``: every run gets its own empty ``-F`` config
and its own known-hosts file in a temp directory.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado y fija el idioma

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent import askpass, ssh
from agent.tests import ssh_stub_server

#: Lo que un administrador de verdad puede tener de contraseña, y lo que rompe
#: a quien la pasa por un intérprete de órdenes.
NASTY_PASSWORDS = [
    "simple",
    "with space and  two",
    "it's \"quoted\" `tick`",
    "100% %PATH% %1",
    "bang!! ^caret & pipe | <in> >out",
    "$HOME $(id) ${x}",
    "ñandú-üß-€-日本語",
    "trailing\\",
    "\\\\server\\share\\",
    "-oProxyCommand=evil",
]


def _launcher(directory: Path) -> str:
    """The askpass program: a real executable (Windows) or a throwaway script."""
    env = os.environ.get("CENYA_TEST_ASKPASS", "")
    if env and Path(env).is_file():
        return env
    if os.name == "posix":
        script = directory / "askpass-launcher"
        script.write_text(f'#!/bin/sh\nexec "{sys.executable}" -m agent.askpass "$@"\n', encoding="utf-8")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        return str(script)
    return ""


@unittest.skipUnless(ssh_stub_server.AVAILABLE, "needs the `cryptography` package (test-only)")
@unittest.skipUnless(
    ssh.VERSION is not None and ssh.VERSION >= ssh.MIN_ASKPASS_VERSION, "needs OpenSSH >= 8.4 on the PATH"
)
class RealSshPasswordLoginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = tempfile.TemporaryDirectory(prefix="cenya-ssh-it-")
        cls.addClassCleanup(cls.dir.cleanup)
        cls.workdir = Path(cls.dir.name)
        cls.askpass = _launcher(cls.workdir)
        if not cls.askpass:
            raise unittest.SkipTest("no askpass executable (set CENYA_TEST_ASKPASS on Windows)")
        (cls.workdir / "ssh_config").write_text("", encoding="utf-8")
        cls.server = ssh_stub_server.StubSshServer()
        cls.addClassCleanup(cls.server.close)

    def setUp(self) -> None:
        self.server.attempts.clear()
        real_argv_for = ssh.argv_for
        isolation = [
            "-F",
            str(self.workdir / "ssh_config"),
            "-o",
            f"UserKnownHostsFile={self.workdir / 'known_hosts'}",
            "-o",
            "GlobalKnownHostsFile=" + os.devnull,
        ]

        def isolated(**kwargs: object) -> list[str]:
            argv = real_argv_for(**kwargs)  # type: ignore[arg-type]
            at = argv.index(ssh.BINARY or "ssh") + 1
            return argv[:at] + isolation + argv[at:]

        for patcher in (
            mock.patch("agent.ssh.ASKPASS", self.askpass),
            mock.patch("agent.ssh.ASKPASS_AVAILABLE", True),
            mock.patch("agent.ssh.argv_for", isolated),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _login(self, password: str, *, expected: str | None = None) -> ssh.Answer:
        self.server.expected = (password if expected is None else expected).encode("utf-8")
        return ssh.run(host="127.0.0.1", username="tester", secret=password, port=self.server.port, command="true")

    def test_the_server_receives_the_exact_password_whatever_its_characters(self) -> None:
        for password in NASTY_PASSWORDS:
            with self.subTest(password=password):
                self.server.attempts.clear()

                answer = self._login(password)

                self.assertTrue(answer.connected, answer.error)
                self.assertEqual(answer.output, "hello-from-stub\n")
                passwords = [a.password for a in self.server.attempts if a.method == "password"]
                self.assertEqual(passwords, [password.encode("utf-8")])

    def test_a_wrong_password_is_offered_once_and_is_not_a_login(self) -> None:
        answer = self._login("the-one-we-have", expected="the-one-it-wants")

        self.assertFalse(answer.connected)
        passwords = [a.password for a in self.server.attempts if a.method == "password"]
        self.assertEqual(passwords, [b"the-one-we-have"])

    def test_the_secret_is_not_in_the_error_text_either(self) -> None:
        answer = self._login("ultra-secret-value", expected="other")

        self.assertNotIn("ultra-secret-value", answer.error)

    def test_a_host_key_question_never_gets_the_password(self) -> None:
        """With `ask` instead of `accept-new`, `ssh` puts "Are you sure you want
        to continue connecting?" through the same askpass program. Answering it
        with the password would hand the secret to whoever is on that port."""
        import subprocess

        self.server.expected = b"must-not-leak"
        environment = ssh.environment_for("must-not-leak", "askpass")
        argv = [
            ssh.BINARY, "-F", str(self.workdir / "ssh_config"),
            "-o", f"UserKnownHostsFile={self.workdir / 'fresh_known_hosts'}",
            "-o", "GlobalKnownHostsFile=" + os.devnull,
            "-o", "StrictHostKeyChecking=ask", "-o", "BatchMode=no", "-o", "NumberOfPasswordPrompts=1",
            "-o", "PubkeyAuthentication=no", "-p", str(self.server.port), "tester@127.0.0.1", "true",
        ]  # fmt: skip
        environment["SSH_ASKPASS"] = self.askpass

        result = subprocess.run(argv, capture_output=True, text=True, env=environment, timeout=30)

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([a for a in self.server.attempts if a.method == "password"], [])


class AskpassHelperRealProcessTests(unittest.TestCase):
    """The helper as a process, which is how ``ssh`` runs it."""

    def _run(self, prompt: str, secret: str, **env: str) -> tuple[int, bytes]:
        import subprocess

        environment = {key: value for key, value in os.environ.items() if key != "SSH_ASKPASS_PROMPT"}
        environment.update({askpass.SECRET_ENV: secret, **env})
        result = subprocess.run(
            [sys.executable, "-m", "agent.askpass", prompt], capture_output=True, env=environment, timeout=30
        )
        return result.returncode, result.stdout

    def test_it_prints_the_password_bytes_exactly_for_a_password_prompt(self) -> None:
        for password in NASTY_PASSWORDS:
            with self.subTest(password=password):
                code, out = self._run("tester@127.0.0.1's password: ", password)

                self.assertEqual(code, 0)
                self.assertEqual(out, password.encode("utf-8") + b"\n")

    def test_it_prints_nothing_for_a_host_key_question_or_a_passphrase(self) -> None:
        for prompt in (
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
            "Enter passphrase for key '/home/x/.ssh/id_ed25519': ",
        ):
            with self.subTest(prompt=prompt):
                code, out = self._run(prompt, "must-not-leak")

                self.assertNotEqual(code, 0)
                self.assertEqual(out, b"")


if __name__ == "__main__":
    unittest.main()
