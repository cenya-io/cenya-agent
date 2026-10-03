"""Password login through OpenSSH's own askpass mechanism, without a network.

What is pinned here: how the ``ssh`` binary is chosen and its version read, the
exact command line and environment of a password run (the secret only in the
child's environment, never in argv), that the askpass helper answers a password
prompt and nothing else, the fallback to ``sshpass`` on an old OpenSSH, and what
the collector says when neither works. The real-login proof against an actual
``ssh`` is in ``test_ssh_askpass_integration``.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado y fija el idioma

import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from agent import askpass, notes, ssh
from agent.collectors.ssh import SshCollector

SECRET = "pa ss'\"%!^&|<>ñ\\"


class VersionTests(unittest.TestCase):
    def test_every_flavour_of_ssh_dash_v_is_understood(self) -> None:
        cases = {
            "OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2": (8, 1),
            "OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2": (9, 5),
            "OpenSSH_10.5p1, OpenSSL 3.5.7 9 Jun 2026": (10, 5),
            "OpenSSH_8.4p1 Debian-5+deb11u3, OpenSSL 1.1.1w  11 Sep 2023": (8, 4),
            "OpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017": (7, 4),
        }
        for text, expected in cases.items():
            with self.subTest(text=text):
                self.assertEqual(ssh.parse_version(text), expected)

    def test_garbage_is_not_a_version(self) -> None:
        for text in ("", "Dropbear v2022.83", "usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy]", "OpenSSH_"):
            with self.subTest(text=text):
                self.assertIsNone(ssh.parse_version(text))

    def test_the_version_comes_from_the_error_stream_where_ssh_writes_it(self) -> None:
        done = subprocess.CompletedProcess([], 0, stdout="", stderr="OpenSSH_9.5p2, LibreSSL 3.8.2\n")
        with mock.patch("agent.ssh.subprocess.run", return_value=done):
            self.assertEqual(ssh.detect_version("ssh"), (9, 5))

    def test_a_binary_that_does_not_run_has_no_version_and_does_not_raise(self) -> None:
        for failure in (FileNotFoundError(2, "no"), subprocess.TimeoutExpired("ssh", 5), PermissionError(13, "no")):
            with self.subTest(failure=type(failure).__name__), mock.patch("agent.ssh.subprocess.run", side_effect=failure):
                self.assertIsNone(ssh.detect_version("ssh"))


class BinarySelectionTests(unittest.TestCase):
    def test_the_one_next_to_the_frozen_executable_comes_first(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bundled = Path(tmp) / "openssh" / ("ssh.exe" if os.name == "nt" else "ssh")
            bundled.parent.mkdir()
            bundled.write_bytes(b"")
            with mock.patch.object(sys, "frozen", True, create=True), \
                 mock.patch.object(sys, "executable", str(Path(tmp) / "cenya-agent.exe")), \
                 mock.patch("agent.ssh.shutil.which", return_value="/usr/bin/ssh"):
                found = ssh.binary_candidates()

        self.assertEqual(found, [str(bundled.resolve()), "/usr/bin/ssh"])

    def test_not_frozen_means_the_systems_only(self) -> None:
        with mock.patch.object(sys, "frozen", False, create=True), mock.patch("agent.ssh.shutil.which", return_value="/usr/bin/ssh"):
            self.assertEqual(ssh.binary_candidates(), ["/usr/bin/ssh"])

    def test_frozen_without_the_bundled_folder_falls_back_to_the_system(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(sys, "frozen", True, create=True), \
             mock.patch.object(sys, "executable", str(Path(tmp) / "cenya-agent.exe")), \
             mock.patch("agent.ssh.shutil.which", return_value="/usr/bin/ssh"):
            self.assertEqual(ssh.binary_candidates(), ["/usr/bin/ssh"])

    def test_nothing_anywhere_is_no_binary(self) -> None:
        with mock.patch.object(sys, "frozen", False, create=True), mock.patch("agent.ssh.shutil.which", return_value=None):
            self.assertEqual(ssh.pick_binary(), ("", None))

    def test_a_bundled_binary_that_does_not_run_is_skipped_for_the_one_that_does(self) -> None:
        """A missing DLL makes the bundled `ssh.exe` die on `-V`; the agent must
        not conclude it has no SSH while the system has one."""
        versions = {"bundled": None, "system": (9, 5)}
        with mock.patch("agent.ssh.binary_candidates", return_value=["bundled", "system"]), \
             mock.patch("agent.ssh.detect_version", side_effect=lambda path: versions[path]):
            self.assertEqual(ssh.pick_binary(), ("system", (9, 5)))

    def test_one_that_never_says_its_version_is_used_but_not_trusted_for_passwords(self) -> None:
        with mock.patch("agent.ssh.binary_candidates", return_value=["odd"]), \
             mock.patch("agent.ssh.detect_version", return_value=None):
            self.assertEqual(ssh.pick_binary(), ("odd", None))


class CapabilityTests(unittest.TestCase):
    """The module constants are computed at import; recompute them the same way."""

    def _capability(self, *, version: tuple[int, int] | None, helper: str, sshpass: bool) -> tuple[bool, bool]:
        askpass_ok = bool(helper) and version is not None and version >= ssh.MIN_ASKPASS_VERSION
        return askpass_ok, askpass_ok or sshpass

    def test_the_threshold_is_8_4(self) -> None:
        self.assertEqual(ssh.MIN_ASKPASS_VERSION, (8, 4))
        self.assertEqual(self._capability(version=(8, 4), helper="h", sshpass=False), (True, True))
        self.assertEqual(self._capability(version=(8, 3), helper="h", sshpass=False), (False, False))
        self.assertEqual(self._capability(version=(8, 1), helper="h", sshpass=True), (False, True))

    def test_the_module_applies_it_at_import(self) -> None:
        """The same expression the module evaluated, against what it exposes."""
        expected = bool(ssh.ASKPASS) and ssh.VERSION is not None and ssh.VERSION >= ssh.MIN_ASKPASS_VERSION
        self.assertEqual(ssh.ASKPASS_AVAILABLE, expected)
        self.assertEqual(ssh.PASSWORD_AUTH_AVAILABLE, ssh.ASKPASS_AVAILABLE or ssh.SSHPASS_AVAILABLE)

    def test_askpass_beats_sshpass_and_nothing_is_nothing(self) -> None:
        with mock.patch("agent.ssh.ASKPASS_AVAILABLE", True), mock.patch("agent.ssh.SSHPASS_AVAILABLE", True):
            self.assertEqual(ssh.password_mode(), "askpass")
        with mock.patch("agent.ssh.ASKPASS_AVAILABLE", False), mock.patch("agent.ssh.SSHPASS_AVAILABLE", True):
            self.assertEqual(ssh.password_mode(), "sshpass")
        with mock.patch("agent.ssh.ASKPASS_AVAILABLE", False), mock.patch("agent.ssh.SSHPASS_AVAILABLE", False):
            self.assertEqual(ssh.password_mode(), "")

    def test_the_helper_is_found_next_to_the_interpreter_or_frozen_executable(self) -> None:
        name = "cenya-agent-askpass" + (".exe" if os.name == "nt" else "")
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / name).write_bytes(b"")
            with mock.patch.object(sys, "executable", str(Path(tmp) / "python")), \
                 mock.patch("agent.ssh.shutil.which", return_value=None):
                self.assertEqual(Path(ssh.askpass_path()).resolve(), (Path(tmp) / name).resolve())

    def test_without_the_helper_there_is_no_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(sys, "executable", str(Path(tmp) / "python")), \
             mock.patch("agent.ssh.sysconfig.get_path", return_value=tmp), \
             mock.patch("agent.ssh.shutil.which", return_value=None):
            self.assertEqual(ssh.askpass_path(), "")


class PasswordRunTests(unittest.TestCase):
    def _run(self, *, mode: str, secret: str = SECRET, **kwargs: Any) -> tuple[ssh.Answer, dict[str, Any]]:
        captured: dict[str, Any] = {}

        def fake_run(argv: list[str], **kw: Any) -> Any:
            captured["argv"] = argv
            captured.update(kw)
            return subprocess.CompletedProcess(argv, 0, stdout="ok", stderr="")

        with mock.patch("agent.ssh.ASKPASS_AVAILABLE", mode == "askpass"), \
             mock.patch("agent.ssh.SSHPASS_AVAILABLE", mode == "sshpass"), \
             mock.patch("agent.ssh.ASKPASS", "/opt/cenya/cenya-agent-askpass"), \
             mock.patch("agent.ssh.subprocess.run", fake_run):
            answer = ssh.run(host="10.0.0.5", username="admin", secret=secret, command="show version", **kwargs)
        return answer, captured

    def test_askpass_run_puts_the_secret_only_in_the_child_environment(self) -> None:
        answer, captured = self._run(mode="askpass")

        self.assertTrue(answer.connected)
        env = captured["env"]
        self.assertEqual(env[askpass.SECRET_ENV], SECRET)
        self.assertEqual(env["SSH_ASKPASS"], "/opt/cenya/cenya-agent-askpass")
        self.assertEqual(env["SSH_ASKPASS_REQUIRE"], "force")
        self.assertNotIn("SSHPASS", env)
        for part in captured["argv"]:
            self.assertNotIn(SECRET, part)
            self.assertNotIn("sshpass", part)
        # Y no pasa a nadie más: el proceso del agente conserva su entorno intacto.
        self.assertNotIn(askpass.SECRET_ENV, os.environ)

    def test_the_command_line_of_an_askpass_run_keeps_every_safety_option(self) -> None:
        _, captured = self._run(mode="askpass")
        argv = captured["argv"]

        self.assertEqual(argv[0], ssh.BINARY or "ssh")
        for option in (
            "StrictHostKeyChecking=accept-new",
            "ConnectTimeout=%d" % ssh.CONNECT_TIMEOUT_SECONDS,
            "BatchMode=no",
            "NumberOfPasswordPrompts=1",
            "PubkeyAuthentication=no",
        ):
            self.assertIn(option, argv)
        self.assertNotIn("-A", argv)
        self.assertEqual(argv[-5:], ["-l", "admin", "--", "10.0.0.5", "show version"])
        self.assertEqual(captured["timeout"], ssh.COMMAND_TIMEOUT_SECONDS)

    def test_sshpass_is_the_fallback_and_keeps_working_as_before(self) -> None:
        _, captured = self._run(mode="sshpass")

        self.assertEqual(captured["argv"][:3], ["sshpass", "-e", ssh.BINARY or "ssh"])
        self.assertEqual(captured["env"]["SSHPASS"], SECRET)
        self.assertNotIn(askpass.SECRET_ENV, captured["env"])
        self.assertNotEqual(captured["env"].get("SSH_ASKPASS"), "/opt/cenya/cenya-agent-askpass")
        for part in captured["argv"]:
            self.assertNotIn(SECRET, part)

    def test_no_mechanism_means_no_secret_anywhere_and_batch_mode(self) -> None:
        _, captured = self._run(mode="")

        self.assertIn("BatchMode=yes", captured["argv"])
        self.assertNotIn(askpass.SECRET_ENV, captured["env"])
        self.assertNotIn("SSHPASS", captured["env"])

    def test_a_key_run_scrubs_a_secret_variable_inherited_from_outside(self) -> None:
        with mock.patch.dict(os.environ, {askpass.SECRET_ENV: "from-outside", "SSHPASS": "also"}):
            _, captured = self._run(mode="askpass", secret="")

        self.assertNotIn(askpass.SECRET_ENV, captured["env"])
        self.assertNotIn("SSHPASS", captured["env"])
        self.assertIn("BatchMode=yes", captured["argv"])

    def test_key_authentication_is_unchanged(self) -> None:
        _, captured = self._run(mode="askpass", secret="", key_file="/k/id_ed25519")

        argv = captured["argv"]
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertIn("/k/id_ed25519", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertNotIn("SSH_ASKPASS", captured["env"])

    def test_a_password_with_a_newline_is_refused_instead_of_truncated(self) -> None:
        with mock.patch("agent.ssh.subprocess.run") as run:
            with mock.patch("agent.ssh.ASKPASS_AVAILABLE", True):
                answer = ssh.run(host="10.0.0.5", username="a", secret="one\ntwo", command="x")

        run.assert_not_called()
        self.assertFalse(answer.connected)
        self.assertNotIn("one", answer.error)

    def test_an_error_never_quotes_the_secret(self) -> None:
        for failure in (OSError(f"cannot run {ssh.BINARY}"), subprocess.TimeoutExpired("ssh", 20)):
            with self.subTest(failure=type(failure).__name__), \
                 mock.patch("agent.ssh.ASKPASS_AVAILABLE", True), \
                 mock.patch("agent.ssh.subprocess.run", side_effect=failure):
                answer = ssh.run(host="h", username="u", secret=SECRET, command="x")
                self.assertFalse(answer.connected)
                self.assertNotIn(SECRET, answer.error)


class AskpassHelperTests(unittest.TestCase):
    def _main(self, prompt: str, *, env: dict[str, str]) -> tuple[int, bytes]:
        out = io.BytesIO()
        fake_stdout = mock.Mock(buffer=out)
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(sys, "stdout", fake_stdout):
            code = askpass.main([prompt])
        return code, out.getvalue()

    def setUp(self) -> None:
        os.environ.pop("SSH_ASKPASS_PROMPT", None)

    def test_it_answers_the_prompts_openssh_uses_for_a_password(self) -> None:
        for prompt in (
            "admin@10.0.0.5's password: ",
            "(admin@10.0.0.5) Password: ",
            "Password:",
            "ADMIN@host's PASSWORD:",
        ):
            with self.subTest(prompt=prompt):
                code, out = self._main(prompt, env={askpass.SECRET_ENV: SECRET})
                self.assertEqual(code, 0)
                self.assertEqual(out, SECRET.encode("utf-8") + b"\n")

    def test_it_answers_nothing_else(self) -> None:
        for prompt in (
            "Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
            "Enter passphrase for key '/home/u/.ssh/id_ed25519': ",
            "Enter passphrase for key 'a password: ': ",
            "Enter PIN for 'ECDSA-SK key':",
            "Verification code: ",
            "",
        ):
            with self.subTest(prompt=prompt):
                code, out = self._main(prompt, env={askpass.SECRET_ENV: SECRET})
                self.assertNotEqual(code, 0)
                self.assertEqual(out, b"")

    def test_a_confirm_or_info_prompt_kind_is_refused_whatever_the_text(self) -> None:
        for kind in ("confirm", "none", "CONFIRM"):
            with self.subTest(kind=kind):
                code, out = self._main("password: ", env={askpass.SECRET_ENV: SECRET, "SSH_ASKPASS_PROMPT": kind})
                self.assertNotEqual(code, 0)
                self.assertEqual(out, b"")

    def test_with_no_secret_it_prints_nothing(self) -> None:
        with mock.patch.dict(os.environ):
            os.environ.pop(askpass.SECRET_ENV, None)
            out = io.BytesIO()
            with mock.patch.object(sys, "stdout", mock.Mock(buffer=out)):
                code = askpass.main(["password: "])
        self.assertNotEqual(code, 0)
        self.assertEqual(out.getvalue(), b"")

    def test_it_never_prints_the_secret_on_the_error_stream(self) -> None:
        err = io.StringIO()
        with mock.patch.object(sys, "stderr", err):
            self._main("Are you sure?", env={askpass.SECRET_ENV: SECRET})
        self.assertEqual(err.getvalue(), "")


class CollectorNoteTests(unittest.TestCase):
    CREDENTIALS = {"credentials": [{"kind": "ssh", "username": "admin", "secret": "x"}]}

    def _collect(self, *, version: tuple[int, int] | None, available: bool = False) -> list[Any]:
        ctx: dict[str, Any] = {"config": self.CREDENTIALS, "env": None, "hosts": []}
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", available), \
             mock.patch("agent.collectors.ssh.ssh.VERSION", version):
            SshCollector().collect(ctx)
        return ctx["errors"]

    def test_an_openssh_older_than_8_4_says_so_with_its_version(self) -> None:
        errors = self._collect(version=(8, 1))

        self.assertEqual(len(errors), 1)
        note = errors[0]
        self.assertIsInstance(note, notes.Note)
        self.assertEqual((note.collector, note.code), ("ssh", "password_auth_unavailable"))
        self.assertEqual(note.params, {"version": "8.1"})
        self.assertIn("8.1", note)
        self.assertIn("8.4", note)
        self.assertNotIn("x", note.params.values())

    def test_a_missing_helper_with_a_new_enough_openssh_keeps_the_old_code(self) -> None:
        errors = self._collect(version=(9, 5))

        self.assertEqual([note.code for note in errors], ["sshpass_missing"])

    def test_an_unknown_version_keeps_the_old_code(self) -> None:
        self.assertEqual([note.code for note in self._collect(version=None)], ["sshpass_missing"])

    def test_when_a_password_can_be_used_nothing_is_said(self) -> None:
        self.assertEqual(self._collect(version=(9, 5), available=True), [])


class SelftestTests(unittest.TestCase):
    def test_it_reports_the_ssh_the_collector_will_use(self) -> None:
        from agent import selftest

        with mock.patch("agent.selftest.ssh.BINARY", "C:/Cenya/openssh/ssh.exe"),              mock.patch("agent.selftest.ssh.VERSION", (10, 0)),              mock.patch("agent.selftest.ssh.ASKPASS", "C:/Cenya/cenya-agent-askpass.exe"),              mock.patch("agent.selftest.ssh.PASSWORD_AUTH_AVAILABLE", True),              mock.patch.object(sys, "frozen", True, create=True):
            data = selftest.ssh_report()

        self.assertEqual(data["version"], "10.0")
        self.assertTrue(data["bundled"])
        self.assertTrue(data["askpass"])
        self.assertTrue(data["password_auth"])

    def test_a_system_ssh_is_not_reported_as_bundled(self) -> None:
        from agent import selftest

        with mock.patch("agent.selftest.ssh.BINARY", "C:/Windows/System32/OpenSSH/ssh.exe"),              mock.patch.object(sys, "frozen", True, create=True):
            self.assertFalse(selftest.ssh_report()["bundled"])

    def _data(self, **ssh_report: object) -> dict[str, object]:
        return {
            "collectors": list("abcdef"),
            "modules": {"snmp": True},
            "languages": {"es": True},
            "windows_modules": {"win32serviceutil": True},
            "frozen": True,
            "ssh": {"bundled": True, "password_auth": True, **ssh_report},
            "app": {"executable": True, "page": True, "webview_files": True, "modules": {"view": True}, "webview2_runtime": None},
        }

    def test_a_frozen_windows_build_without_its_own_openssh_is_incomplete(self) -> None:
        from agent import selftest

        self.assertTrue(selftest.complete(self._data()))
        self.assertFalse(selftest.complete(self._data(bundled=False)))
        self.assertFalse(selftest.complete(self._data(password_auth=False)))

    def test_a_frozen_windows_build_without_the_windows_pieces_is_incomplete(self) -> None:
        from agent import selftest

        for missing in ("executable", "page", "webview_files"):
            with self.subTest(missing=missing):
                data = self._data()
                data["app"][missing] = False
                self.assertFalse(selftest.complete(data))
        # El runtime de WebView2 es de Windows, no del instalador: no cuenta.
        self.assertTrue(selftest.complete(self._data()))

    def test_the_app_report_looks_at_files_not_at_pywebview(self) -> None:
        from agent import selftest

        report = selftest.app_report()
        self.assertTrue(report["page"])  # agent/app/ui está en el repositorio
        self.assertTrue(all(report["modules"].values()))


if __name__ == "__main__":
    unittest.main()
