"""`enable` before the capture, refusals that are not copies, and a stale family (09-10-2026).

Three things seen on the same day: a Dell whose account lands in user mode
(``SW>``) answered «Command Is Not Authorized» to `show running-config`; a
Huawei the memory still called a Cisco got `show running-config` every night;
and both refusals went to the server as configurations, because the check
for them missed the Dell's echoed command and the Huawei's banner.

The session tests run against a stand-in device, as `test_sshshell` does, so
the prompt reading is tested for real.
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

DELL = textwrap.dedent(
    r'''
    import sys

    mode = sys.argv[1]
    name = "PLANTA-BAJA-SW"


    def out(text):
        sys.stdout.write(text)
        sys.stdout.flush()


    def read():
        raw = sys.stdin.readline()
        if raw == "":
            sys.exit(0)
        return raw.strip()


    privileged = mode in ("privileged", "privileged-asks")
    out("\r\n" + name + ("#" if privileged else ">"))
    while True:
        command = read()
        out(command + "\r\n")
        if command == "enable":
            if privileged:
                out("ENABLE-SENT-TWICE\r\n")
            elif mode == "open":
                privileged = True
            else:
                for _try in range(3):
                    out("Password:")
                    if read() == ("otra" if mode == "wrong" else "Sistemas13$"):
                        privileged = True
                        break
                    out("\r\n")
                else:
                    out("% Access denied\r\n")
        elif command == "show running-config":
            if mode in ("privileged-asks", "open-asks") and privileged:
                # A device that asks something *after* the command: whatever is
                # typed there is echoed back, as a real one would.
                out("Password:")
                typed = read()
                out("\r\n" + ("LEAKED " + typed if typed else "nothing typed") + "\r\n")
            elif privileged:
                out("hostname PLANTA-BAJA-SW\r\nvlan database\r\nvlan 10,20\r\nexit\r\n")
            else:
                out("show running-config : Command Is Not Authorized\r\n")
        out(name + ("#" if privileged else ">"))
    '''
)

DELL_REFUSAL = "\n\n\nshow running-config : Command Is Not Authorized\n"
HUAWEI_REFUSAL = (
    "Info: The max number of VTY users is 5, the number of current VTY users online is 1.\n"
    "      The current login time is 2026-05-14 03:27:37.\n"
    "<SW-Huawei-01>\n            ^\n\n"
    "Error: Unrecognized command found at '^' position.\n"
    "<SW-Huawei-01>\n<SW-Huawei-01>\n<SW-Huawei-01>\n"
    "Info: The max number of VTY users is 5, and the number of current VTY users on line is 0.\n"
)
HUAWEI_CONFIG = "#\nsysname SW-Huawei-01\n#\nvlan batch 10 20\n#\nreturn\n"


def credential() -> creds.Credential:
    return creds._one({"kind": "ssh", "username": "sistemas", "secret": SECRET, "id": "c"}, 0)


class EnableInASessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.folder = tempfile.TemporaryDirectory()
        cls.device = Path(cls.folder.name) / "dell.py"
        cls.device.write_text(DELL, encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.folder.cleanup()

    def capture(self, mode: str, *, enable: bool = True) -> ssh.Answer:
        with mock.patch.object(sshshell, "_argv", return_value=[sys.executable, str(self.device), mode]), mock.patch.object(
            sshshell, "SETTLE_SECONDS", 0.2
        ), mock.patch.object(sshshell, "QUIET_SECONDS", 1):
            return sshshell.run(
                host="172.20.5.21",
                username="sistemas",
                secret=SECRET,
                timeout=30,
                commands=("terminal length 0", "show running-config"),
                enable=enable,
            )

    def test_a_user_mode_prompt_gets_enable_and_the_login_password(self) -> None:
        answer = self.capture("user")

        self.assertTrue(answer.connected)
        self.assertEqual(
            sshshell.command_output(answer.output, "show running-config"),
            "hostname PLANTA-BAJA-SW\nvlan database\nvlan 10,20\nexit\n",
        )
        self.assertNotIn(SECRET, answer.output)

    def test_enable_without_a_password_goes_straight_in(self) -> None:
        answer = self.capture("open")

        self.assertIn("hostname PLANTA-BAJA-SW", sshshell.command_output(answer.output, "show running-config"))

    def test_a_privileged_prompt_gets_no_enable(self) -> None:
        answer = self.capture("privileged")

        self.assertNotIn("ENABLE-SENT-TWICE", answer.output)
        self.assertNotIn("\nenable", answer.output.replace("\r", ""))
        self.assertIn("hostname PLANTA-BAJA-SW", answer.output)

    def test_a_wrong_enable_password_gives_up_and_lets_the_device_refuse(self) -> None:
        answer = self.capture("wrong")

        self.assertTrue(answer.connected)
        output = sshshell.command_output(answer.output, "show running-config")
        self.assertTrue(collector.rejected_by_cli(output), output)

    def test_without_enable_nothing_changes(self) -> None:
        answer = self.capture("user", enable=False)

        self.assertTrue(collector.rejected_by_cli(sshshell.command_output(answer.output, "show running-config")))

    def test_the_account_password_never_answers_a_later_prompt(self) -> None:
        """A «Password:» after the capture command is the device asking for
        something else. The login password must not go there: it would be
        echoed and end up inside the stored copy (seen in review, 09-10-2026,
        when a privileged prompt marked `enable` as sent without sending it).
        """
        for mode in ("privileged-asks", "open-asks"):
            answer = self.capture(mode)
            self.assertNotIn(SECRET, answer.output, mode)
            self.assertNotIn("LEAKED", answer.output, mode)

    def test_a_vrp_prompt_is_not_user_mode(self) -> None:
        self.assertFalse(sshshell.unprivileged("Info: hello\n<SW-Huawei-01>"))
        self.assertFalse(sshshell.unprivileged("[~SW-Huawei-01]"))
        self.assertFalse(sshshell.unprivileged("SW-1#"))
        self.assertTrue(sshshell.unprivileged("User Access Verification\nSW-1>"))


class RefusalTests(unittest.TestCase):
    def test_the_dell_refusal_with_its_echoed_command(self) -> None:
        self.assertTrue(collector.rejected_by_cli(DELL_REFUSAL))

    def test_the_huawei_refusal_with_banner_caret_and_prompts(self) -> None:
        self.assertTrue(collector.rejected_by_cli(HUAWEI_REFUSAL))

    def test_a_configuration_is_not_a_refusal(self) -> None:
        self.assertFalse(collector.rejected_by_cli(HUAWEI_CONFIG))
        self.assertFalse(collector.rejected_by_cli("hostname sw\ninterface Gi1/0/1\n"))


class FetchWithEnableTests(unittest.TestCase):
    def test_a_refused_plain_command_is_asked_again_in_a_session_with_enable(self) -> None:
        refused = ssh.Answer(connected=True, output=DELL_REFUSAL)
        session = ssh.Answer(connected=True, output="SW#show running-config\r\nhostname SW\r\nSW#")

        with mock.patch.object(collector, "_login", return_value=refused), mock.patch.object(
            collector, "_session", return_value=session
        ) as opened:
            config = collector.fetch_config("172.20.5.21", credential(), "show running-config", enable=True)

        self.assertEqual(config, "hostname SW\n")
        self.assertTrue(opened.call_args.kwargs["enable"])

    def test_without_enable_a_refusal_does_not_open_a_session(self) -> None:
        refused = ssh.Answer(connected=True, output=DELL_REFUSAL)

        with mock.patch.object(collector, "_login", return_value=refused), mock.patch.object(
            collector, "_session"
        ) as opened:
            collector.fetch_config("172.20.5.21", credential(), "show running-config")

        opened.assert_not_called()

    def test_dell_captures_ask_for_enable(self) -> None:
        calls: list[bool] = []

        def fetch(host, cred, command, logins=None, enable=False):  # noqa: ANN001, ANN202
            calls.append(enable)
            return "hostname SW\n"

        with mock.patch.object(collector, "fetch_config", side_effect=fetch):
            collector.fetch_configs("172.20.5.21", credential(), "dell")

        self.assertEqual(calls, [True, True], "la que corre y la guardada")


class StaleFamilyTests(unittest.TestCase):
    def test_a_huawei_remembered_as_cisco_is_asked_again_and_captured_as_huawei(self) -> None:
        def fetch(host, cred, command, logins=None, enable=False):  # noqa: ANN001, ANN202
            return {
                "show running-config": HUAWEI_REFUSAL,
                "display current-configuration": HUAWEI_CONFIG,
                "display saved-configuration": HUAWEI_CONFIG,
            }[command]

        with mock.patch.object(collector, "fetch_config", side_effect=fetch), mock.patch.object(
            collector, "interrogate", return_value=({"family": "huawei"}, credential())
        ) as asked:
            copies = collector.fetch_configs("172.20.5.28", credential(), "cisco", errors=[])

        asked.assert_called_once()
        self.assertEqual(copies["family"], "huawei")
        self.assertEqual(copies["config"], HUAWEI_CONFIG)

    def test_a_real_lack_of_privilege_is_noted_once_without_looping(self) -> None:
        errors: list = []
        with mock.patch.object(collector, "fetch_config", return_value=DELL_REFUSAL), mock.patch.object(
            collector, "interrogate", return_value=({"family": "dell"}, credential())
        ) as asked:
            copies = collector.fetch_configs("172.20.5.21", credential(), "dell", errors=errors)

        self.assertEqual(copies, {})
        asked.assert_called_once()
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].code, "config_needs_privilege")


if __name__ == "__main__":
    unittest.main()
