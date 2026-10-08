"""The interactive SSH session (08-10-2026).

Against a stand-in device -- a small program that talks like a PowerConnect
(asks «User Name:» and «Password:» inside the session) or a Huawei VRP (only
answers inside a terminal) -- so the prompt handling is tested for real, not
with a mock of itself.
"""

from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from agent import credentials as creds
from agent import ssh, sshshell
from agent.collectors import ssh as collector

SECRET = "Sistemas13$"

DEVICE = textwrap.dedent(
    r'''
    import sys

    mode = sys.argv[1]


    def out(text):
        sys.stdout.write(text)
        sys.stdout.flush()


    def read():
        raw = sys.stdin.readline()
        if raw == "":
            sys.exit(0)
        return raw.strip()


    if mode in ("powerconnect", "powerconnect-wrong"):
        prompt = "SEMI-SOTANO-SW#"
        out("\r\n\r\nUser Name:")
        user = read()
        out(user + "\r\nPassword:")
        password = read()
        if password != "Sistemas13$":
            out("\r\n\r\nUser Name:")
            read()
            sys.exit(0)
        out("*" * len(password) + "\r\n\r\n" + prompt)
    else:
        prompt = "<SW-Huawei-01>"
        out("Info: The max number of VTY users is 5.\r\n" + prompt)
    answers = {
        ("huawei", "display version"): "Huawei Versatile Routing Platform Software\r\nVRP (R) software, Version 5.170 (S5735 V200R021C10SPC600)\r\nHUAWEI S5735-L48T4S-A1 Routing Switch uptime is 120 days",
        ("powerconnect", "show version"): "SW version    4.1.0.6 ( date  02-Feb-2012 time  10:10:44 )\r\nBoot version    4.1.0.2\r\nHW version    00.00.02",
        ("powerconnect", "show system"): "System Description:                       PowerConnect 5548\r\nSystem Name:                              SEMI-SOTANO-SW",
    }
    while True:
        command = read()
        out(command + "\r\n")
        if mode == "huawei" and command == "display current-configuration":
            out("#\r\nsysname SW-Huawei-01\r\n  ---- More ----")
            if sys.stdin.read(1) != " ":
                sys.exit(1)
            out("\x1b[42D" + " " * 42 + "\x1b[42D vlan batch 10 20\r\n#\r\nreturn\r\n" + prompt)
            continue
        out(answers.get((mode, command), "% Unrecognized command") + "\r\n" + prompt)
    '''
)


class SessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.folder = tempfile.TemporaryDirectory()
        cls.device = Path(cls.folder.name) / "device.py"
        cls.device.write_text(DEVICE, encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.folder.cleanup()

    def session(self, mode: str, secret: str = SECRET) -> ssh.Answer:
        with mock.patch.object(sshshell, "_argv", return_value=[sys.executable, str(self.device), mode]), mock.patch.object(
            sshshell, "SETTLE_SECONDS", 0.2
        ):
            return sshshell.run(host="172.20.5.20", username="sistemas", secret=secret, timeout=30)

    def test_a_powerconnect_gets_its_user_and_password_inside_the_session(self) -> None:
        answer = self.session("powerconnect")

        self.assertTrue(answer.connected)
        self.assertIn("PowerConnect 5548", answer.output)
        self.assertNotIn(SECRET, answer.output)
        data = collector.parse_session(answer.output)
        self.assertEqual((data["family"], data["hostname"], data["manufacturer"]), ("dell", "SEMI-SOTANO-SW", "Dell"))

    def test_a_password_refused_inside_the_session_is_a_failed_login(self) -> None:
        answer = self.session("powerconnect-wrong", secret="mala")

        self.assertFalse(answer.connected)
        self.assertEqual(ssh.outcome(answer), "auth_failed")

    def test_a_huawei_answers_inside_a_terminal(self) -> None:
        answer = self.session("huawei")

        data = collector.parse_session(answer.output)
        self.assertEqual((data["family"], data["hostname"], data["manufacturer"]), ("huawei", "SW-Huawei-01", "Huawei"))

    def test_a_paged_answer_gets_a_space_and_comes_back_whole(self) -> None:
        with mock.patch.object(sshshell, "_argv", return_value=[sys.executable, str(self.device), "huawei"]), mock.patch.object(
            sshshell, "SETTLE_SECONDS", 0.2
        ):
            answer = sshshell.run(
                host="172.20.5.28",
                username="sistemas",
                secret=SECRET,
                timeout=30,
                commands=(*sshshell.PAGING_OFF, "display current-configuration"),
            )

        config = sshshell.command_output(answer.output, "display current-configuration")
        self.assertEqual(config, "#\nsysname SW-Huawei-01\n vlan batch 10 20\n#\nreturn\n")

    def test_an_unknown_cli_still_presents_itself_by_its_prompt(self) -> None:
        data = collector.parse_session("Welcome\r\nPLANTA-BAJA-SW# show version\r\n% Invalid\r\nPLANTA-BAJA-SW#")

        self.assertEqual((data["family"], data["hostname"]), ("cli", "PLANTA-BAJA-SW"))


class WhenToOpenASessionTests(unittest.TestCase):
    def test_ssh_that_authenticated_and_then_hung_is_not_a_wrong_password(self) -> None:
        hung = ssh.Answer(connected=False, error="tiempo de espera agotado", authenticated=True)

        self.assertEqual(ssh.outcome(hung), "unreachable")
        self.assertTrue(collector._wants_session(hung))

    def test_a_clear_denial_never_opens_a_session(self) -> None:
        denied = ssh.Answer(connected=False, error="sistemas@10.0.0.5: Permission denied (password).")

        self.assertEqual(ssh.outcome(denied), "auth_failed")
        self.assertFalse(collector._wants_session(denied))

    def test_the_verbose_log_says_whether_ssh_authenticated(self) -> None:
        self.assertTrue(ssh.authenticated('Authenticated to 172.20.5.21 ([172.20.5.21]:22) using "none".'))
        self.assertFalse(ssh.authenticated("sistemas@10.0.0.5: Permission denied (password)."))
        self.assertEqual(
            ssh._reason('Authenticated to x ([x]:22) using "none".\nexec request failed on channel 0'),
            "exec request failed on channel 0",
        )

    def test_interrogate_falls_back_to_the_session(self) -> None:
        credential = creds._one({"kind": "ssh", "username": "sistemas", "secret": SECRET, "id": "c"}, 0)
        hung = ssh.Answer(connected=False, error="tiempo de espera agotado", authenticated=True)
        session = ssh.Answer(connected=True, output="System Description: PowerConnect 5548\r\nSEMI-SOTANO-SW#")

        with mock.patch.object(collector, "_login", return_value=hung) as plain, mock.patch.object(
            collector, "_session", return_value=session
        ):
            data, used = collector.interrogate("172.20.5.20", [credential])

        self.assertEqual(plain.call_count, 1, "una orden colgada no se repite con otra familia")
        self.assertEqual((data["hostname"], used), ("SEMI-SOTANO-SW", credential))


if __name__ == "__main__":
    unittest.main()


class ConfigInASessionTests(unittest.TestCase):
    def test_the_command_output_is_cut_between_its_echo_and_the_next_prompt(self) -> None:
        output = (
            "<SW-Huawei-01>screen-length 0 temporary\r\nInfo: The configuration takes effect on the current user terminal interface only.\r\n"
            "<SW-Huawei-01>display current-configuration\r\n#\r\nsysname SW-Huawei-01\r\n  ---- More ----\x1b[42D                                          \x1b[42Dvlan batch 10 20\r\n#\r\nreturn\r\n<SW-Huawei-01>"
        )

        config = sshshell.command_output(output, "display current-configuration")

        self.assertEqual(config, "#\nsysname SW-Huawei-01\nvlan batch 10 20\n#\nreturn\n")

    def test_fetch_config_asks_inside_a_session_when_the_plain_command_hangs(self) -> None:
        credential = creds._one({"kind": "ssh", "username": "sistemas", "secret": SECRET, "id": "c"}, 0)
        hung = ssh.Answer(connected=False, error="tiempo de espera agotado", authenticated=True)
        session = ssh.Answer(connected=True, output="<SW>display current-configuration\r\nsysname SW\r\n<SW>")

        with mock.patch.object(collector, "_login", return_value=hung), mock.patch.object(
            collector, "_session", return_value=session
        ) as opened:
            config = collector.fetch_config("172.20.5.28", credential, "display current-configuration")

        self.assertEqual(config, "sysname SW\n")
        self.assertEqual(opened.call_args.kwargs["commands"][-1], "display current-configuration")
