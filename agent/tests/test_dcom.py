"""WMI over DCOM as the fallback of the WinRM collector, with PowerShell faked.

Nothing here starts a process or opens a socket: the runner is injected, and
the port probe and the Windows/PowerShell gate are patched.
"""

from __future__ import annotations

import base64
import json
import subprocess
import unittest
from typing import Any
from unittest import mock

from agent import dcom, winrm
from agent.collectors.winrm import WinrmCollector
from agent.tests.test_winrm import DC_2019, as_stdout

SECRET = "pa$$w0rd-ñ-\"quoted\""
HOST = "192.168.1.20"


def _ctx(**extra: Any) -> dict:
    ctx: dict[str, Any] = {
        "config": {"credentials": [{"kind": "winrm", "username": "ACME\\svc", "secret": SECRET}]},
        "env": None,
        "hosts": [{"ip": HOST, "mac": "b0:83:fe:11:22:33"}],
    }
    ctx.update(extra)
    return ctx


class QueryTests(unittest.TestCase):
    def _query(self, code: int, out: bytes = b"", err: bytes = b"") -> tuple[winrm.Answer, list]:
        seen: list = []

        def runner(argv: list, stdin: str, timeout: float) -> tuple[int, bytes, bytes]:
            seen.append((argv, stdin, timeout))
            return code, out, err

        with mock.patch("agent.dcom.powershell_path", return_value="powershell.exe"):
            return dcom.query(host=HOST, username="ACME\\svc", secret=SECRET, runner=runner), seen

    def test_a_windows_server_answers_with_the_winrm_record(self) -> None:
        answer, _ = self._query(0, as_stdout(DC_2019))
        self.assertTrue(answer.connected)
        self.assertEqual(answer.data, DC_2019)

    def test_a_utf8_bom_in_the_output_is_tolerated(self) -> None:
        answer, _ = self._query(0, b"\xef\xbb\xbf" + as_stdout(DC_2019))
        self.assertEqual(answer.data, DC_2019)

    def test_access_denied_is_a_rejection_not_unreachable(self) -> None:
        answer, _ = self._query(2, err=b"CimException: Access is denied.")
        self.assertFalse(answer.connected)
        self.assertFalse(answer.unreachable)
        self.assertEqual(winrm.outcome(answer), "auth_failed")

    def test_rpc_unavailable_is_unreachable(self) -> None:
        answer, _ = self._query(2, err=b"CimException: The RPC server is unavailable.")
        self.assertTrue(answer.unreachable)
        self.assertEqual(winrm.outcome(answer), "unreachable")

    def test_an_unknown_failure_is_treated_as_a_rejection(self) -> None:
        answer, _ = self._query(2, err=b"SomethingNew: nobody knows")
        self.assertEqual(winrm.outcome(answer), "auth_failed")

    def test_a_timeout_of_the_process_is_unreachable(self) -> None:
        def runner(argv: list, stdin: str, timeout: float) -> tuple[int, bytes, bytes]:
            raise subprocess.TimeoutExpired(argv, timeout)

        with mock.patch("agent.dcom.powershell_path", return_value="powershell.exe"):
            answer = dcom.query(host=HOST, username="u", secret="p", runner=runner)
        self.assertTrue(answer.unreachable)

    def test_the_total_timeout_is_forty_five_seconds(self) -> None:
        _, seen = self._query(0, as_stdout(DC_2019))
        self.assertEqual(seen[0][2], 45)

    def test_the_password_is_only_on_stdin_never_in_the_command_line(self) -> None:
        _, seen = self._query(0, as_stdout(DC_2019))
        argv, stdin, _ = seen[0]
        joined = " ".join(argv)
        for needle in (SECRET, "ACME\\svc", HOST, base64.b64encode(SECRET.encode()).decode()):
            self.assertNotIn(needle, joined)
        document = json.loads(base64.b64decode(stdin))
        self.assertEqual(document, {"host": HOST, "username": "ACME\\svc", "password": SECRET})

    def test_the_script_is_constant_and_has_no_values_in_it(self) -> None:
        _, first = self._query(0, as_stdout(DC_2019))
        with mock.patch("agent.dcom.powershell_path", return_value="powershell.exe"):
            dcom.query(host="10.0.0.9", username="other", secret="other-pw", runner=lambda *a: (0, b"{}", b""))
        self.assertEqual(first[0][0], dcom.command_line("powershell.exe"))
        encoded = first[0][0][first[0][0].index("-EncodedCommand") + 1]
        script = base64.b64decode(encoded).decode("utf-16-le")
        self.assertEqual(script, dcom.SCRIPT)
        self.assertIn("-Protocol Dcom", script)

    def test_the_password_is_not_in_the_error_text(self) -> None:
        answer, _ = self._query(2, err=("CimException: bad " + SECRET).encode())
        self.assertNotIn(SECRET, answer.error)

    def test_the_real_subprocess_call_has_no_password_in_argv(self) -> None:
        """The default runner, with `subprocess.run` replaced: the argv that
        would reach the operating system must not carry the secret."""
        calls: list = []

        def fake_run(argv: list, **kwargs: Any) -> subprocess.CompletedProcess:
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, as_stdout(DC_2019), b"")

        with mock.patch("agent.dcom.powershell_path", return_value="powershell.exe"), \
             mock.patch("agent.dcom.subprocess.run", fake_run):
            answer = dcom.query(host=HOST, username="ACME\\svc", secret=SECRET)

        self.assertTrue(answer.connected)
        argv, kwargs = calls[0]
        self.assertNotIn(SECRET, " ".join(argv))
        self.assertNotIn("shell", kwargs)
        self.assertIn(b"=", kwargs["input"])  # base64, ASCII only
        self.assertNotIn(SECRET.encode(), kwargs["input"])

    def test_without_powershell_it_says_so_instead_of_raising(self) -> None:
        with mock.patch("agent.dcom.powershell_path", return_value=""):
            answer = dcom.query(host=HOST, username="u", secret="p")
        self.assertFalse(answer.connected)
        self.assertTrue(answer.unreachable)

    def test_not_windows_means_not_available(self) -> None:
        with mock.patch("agent.dcom.sys.platform", "linux"):
            self.assertFalse(dcom.available())


class CollectorFallbackTests(unittest.TestCase):
    def _collect(
        self,
        ctx: dict,
        *,
        listening: dict[int, list[str]],
        winrm_answers: dict[str, winrm.Answer] | None = None,
        dcom_answer: winrm.Answer | None = None,
        available: bool = True,
        dcom_calls: list | None = None,
        winrm_calls: list | None = None,
    ):
        def fake_listening(ips: list[str], port: int, **_: Any) -> list[str]:
            return [ip for ip in ips if ip in listening.get(port, [])]

        def fake_winrm(*, host: str, username: str, secret: str, port: int = 0, ca_file: str = "") -> winrm.Answer:
            if winrm_calls is not None:
                winrm_calls.append(host)
            return (winrm_answers or {}).get(host, winrm.Answer(False, None, "401"))

        def fake_dcom(*, host: str, username: str, secret: str, runner: Any = None) -> winrm.Answer:
            if dcom_calls is not None:
                dcom_calls.append((host, username))
            return dcom_answer or winrm.Answer(False, None, "Access is denied.")

        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", True), \
             mock.patch("agent.collectors.winrm.dcom.available", return_value=available), \
             mock.patch("agent.collectors.winrm.net.hosts_listening", fake_listening), \
             mock.patch("agent.collectors.winrm.winrm.query", fake_winrm), \
             mock.patch("agent.collectors.winrm.dcom.query", fake_dcom):
            return WinrmCollector().collect(ctx)

    def test_a_server_with_only_135_open_is_identified_with_the_winrm_payload(self) -> None:
        calls: list = []
        findings = self._collect(
            _ctx(), listening={135: [HOST]}, dcom_answer=winrm.Answer(True, DC_2019), dcom_calls=calls
        )
        self.assertEqual(calls, [(HOST, "ACME\\svc")])
        self.assertEqual(len(findings), 1)
        payload = findings[0].payload
        self.assertEqual(payload["seen_by"], "winrm")
        self.assertEqual(payload["transport"], "dcom")
        self.assertEqual(payload["hostname"], "SRV-DC01")
        self.assertEqual(payload["serial"], "7X8Y9Z1")
        self.assertEqual(payload["domain"], "acme.local")
        self.assertIn("controlador de dominio principal", payload["roles"])
        self.assertEqual(payload["interfaces"][0]["mac"], "b0:83:fe:11:22:33")

    def test_the_payload_is_the_same_as_the_winrm_one_apart_from_transport(self) -> None:
        by_winrm = self._collect(
            _ctx(), listening={5985: [HOST]}, winrm_answers={HOST: winrm.Answer(True, DC_2019)}
        )[0].payload
        by_dcom = self._collect(
            _ctx(), listening={135: [HOST]}, dcom_answer=winrm.Answer(True, DC_2019)
        )[0].payload
        by_dcom = {k: v for k, v in by_dcom.items() if k != "transport"}
        self.assertEqual(by_winrm, by_dcom)
        self.assertNotIn("transport", self._collect(
            _ctx(), listening={5985: [HOST]}, winrm_answers={HOST: winrm.Answer(True, DC_2019)}
        )[0].payload)

    def test_with_winrm_open_dcom_is_never_tried(self) -> None:
        calls: list = []
        findings = self._collect(
            _ctx(),
            listening={5985: [HOST], 135: [HOST]},
            winrm_answers={HOST: winrm.Answer(True, DC_2019)},
            dcom_calls=calls,
        )
        self.assertEqual(calls, [])
        self.assertEqual(len(findings), 1)

    def test_winrm_that_rejected_the_credential_is_not_followed_by_dcom(self) -> None:
        """A second failed login against the same account would lock it."""
        calls: list = []
        findings = self._collect(
            _ctx(),
            listening={5985: [HOST], 135: [HOST]},
            winrm_answers={HOST: winrm.Answer(False, None, "401 Unauthorized")},
            dcom_calls=calls,
        )
        self.assertEqual(calls, [])
        self.assertEqual(findings, [])

    def test_without_135_it_is_silent(self) -> None:
        ctx = _ctx()
        calls: list = []
        findings = self._collect(ctx, listening={}, dcom_calls=calls)
        self.assertEqual(findings, [])
        self.assertEqual(calls, [])
        self.assertEqual(ctx.get("errors", []), [])

    def test_a_failed_dcom_login_goes_through_the_breaker_and_leaves_no_row(self) -> None:
        ctx = _ctx()
        calls: list = []
        findings = self._collect(ctx, listening={135: [HOST]}, dcom_calls=calls)
        self.assertEqual(findings, [])
        self.assertEqual(len(calls), 1)
        attempts = [a for a in ctx.get("attempts", []) if a["ip"] == HOST]
        self.assertEqual([a["code"] for a in attempts], ["auth_failed"])
        self.assertEqual(attempts[0]["protocol"], "winrm")

    def test_dcom_uses_the_credential_veto_like_winrm(self) -> None:
        """When the memory says the account is resting, no attempt is made."""
        ctx = _ctx()
        calls: list = []
        with mock.patch("agent.collectors.winrm.tasking.plan", return_value=([], False)):
            findings = self._collect(ctx, listening={135: [HOST]}, dcom_calls=calls)
        self.assertEqual((findings, calls), ([], []))

    def test_dcom_goes_through_the_logins_breaker(self) -> None:
        ctx = _ctx()
        seen: list = []
        real_run = __import__("agent.collectors.tasking", fromlist=["Logins"]).Logins.run

        def spy(self_: Any, credential: Any, call: Any, outcome: Any) -> Any:
            seen.append(credential.username)
            return real_run(self_, credential, call, outcome)

        with mock.patch("agent.collectors.winrm.tasking.Logins.run", spy):
            self._collect(ctx, listening={135: [HOST]}, dcom_answer=winrm.Answer(True, DC_2019))
        self.assertEqual(seen, ["ACME\\svc"])

    def test_the_first_credential_that_gets_in_stops_the_probing(self) -> None:
        ctx = _ctx(
            config={
                "credentials": [
                    {"kind": "winrm", "username": "ACME\\malo", "secret": "x"},
                    {"kind": "winrm", "username": "ACME\\svc", "secret": "y"},
                    {"kind": "winrm", "username": "ACME\\nunca", "secret": "z"},
                ]
            }
        )
        tried: list[str] = []

        def fake_dcom(*, host: str, username: str, secret: str, runner: Any = None) -> winrm.Answer:
            tried.append(username)
            return winrm.Answer(False, None, "Access is denied.") if "malo" in username else winrm.Answer(True, DC_2019)

        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", True), \
             mock.patch("agent.collectors.winrm.dcom.available", return_value=True), \
             mock.patch("agent.collectors.winrm.net.hosts_listening", lambda ips, port, **_: ips if port == 135 else []), \
             mock.patch("agent.collectors.winrm.dcom.query", fake_dcom):
            findings = WinrmCollector().collect(ctx)
        self.assertEqual(len(findings), 1)
        self.assertEqual(tried, ["ACME\\malo", "ACME\\svc"])

    def test_not_windows_or_without_powershell_does_nothing(self) -> None:
        calls: list = []
        probed: list = []

        def fake_listening(ips: list[str], port: int, **_: Any) -> list[str]:
            probed.append(port)
            return list(ips)

        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", True), \
             mock.patch("agent.collectors.winrm.dcom.available", return_value=False), \
             mock.patch("agent.collectors.winrm.net.hosts_listening", lambda ips, port, **_: []), \
             mock.patch("agent.collectors.winrm.dcom.query", lambda **k: calls.append(k)):
            findings = WinrmCollector().collect(_ctx())
        self.assertEqual((findings, calls), ([], []))

        # And the 135 is not even probed when DCOM is impossible.
        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", True), \
             mock.patch("agent.collectors.winrm.dcom.available", return_value=False), \
             mock.patch("agent.collectors.winrm.net.hosts_listening", fake_listening):
            WinrmCollector().collect(_ctx())
        self.assertNotIn(135, probed)

    def test_only_credentials_without_a_pinned_port_are_used_for_dcom(self) -> None:
        ctx = _ctx(config={"credentials": [{"kind": "winrm", "username": "u", "secret": "s", "port": 5443}]})
        calls: list = []
        findings = self._collect(ctx, listening={135: [HOST]}, dcom_calls=calls)
        self.assertEqual((findings, calls), ([], []))


if __name__ == "__main__":
    unittest.main()
