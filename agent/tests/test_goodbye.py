"""``cenya-agent goodbye``: tell the server (spec 1.7), then remove the local enrolment.

The property that matters: the local token and key are gone afterwards
whether the server answered or not, and the exit code is 0 either way.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent import goodbye, store
from agent.client import PushError


class FakeClient:
    calls: list[tuple[str, str, str]] = []
    error: Exception | None = None

    def __init__(self, base_url: str, token: str, *, ca_bundle: str = "", proxy: object = None) -> None:
        self.base_url, self.token = base_url, token

    def goodbye(self, reason: str = "uninstall") -> dict:
        FakeClient.calls.append((self.base_url, self.token, reason))
        if FakeClient.error is not None:
            raise FakeClient.error
        return {"ok": True}


class GoodbyeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="cenya-goodbye-"))
        self.env = {"CENYA_STATE_DIR": str(self.dir)}
        FakeClient.calls, FakeClient.error = [], None
        patcher = mock.patch.object(goodbye, "AgentClient", FakeClient)
        patcher.start()
        self.addCleanup(patcher.stop)

    def enrol(self) -> None:
        store.save(store.Enrollment("https://portal.example", "cya_secreto", "CPD"), self.env)
        store.write_protected(self.dir / store.IDENTITY_FILE, "-----BEGIN PRIVATE KEY-----\n")

    def run_goodbye(self) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = goodbye.run([], self.env)
        return code, out.getvalue() + err.getvalue()

    def test_it_tells_the_server_and_removes_the_enrolment_and_the_key(self) -> None:
        self.enrol()

        code, said = self.run_goodbye()

        self.assertEqual(code, 0)
        self.assertEqual(FakeClient.calls, [("https://portal.example", "cya_secreto", "uninstall")])
        self.assertIsNone(store.load(self.env))
        self.assertFalse((self.dir / store.IDENTITY_FILE).exists())
        self.assertIn("avisado", said)
        self.assertNotIn("cya_secreto", said)

    def test_an_unreachable_server_still_removes_the_local_state(self) -> None:
        self.enrol()
        FakeClient.error = PushError("No se pudo hablar con el servidor: timed out")

        code, said = self.run_goodbye()

        self.assertEqual(code, 0)
        self.assertIsNone(store.load(self.env))
        self.assertFalse((self.dir / store.IDENTITY_FILE).exists())
        self.assertIn("No se pudo avisar al servidor", said)
        self.assertIn("Ajustes → Agentes", said)

    def test_without_an_enrolment_there_is_nothing_to_say_and_it_is_fine(self) -> None:
        code, said = self.run_goodbye()

        self.assertEqual(code, 0)
        self.assertEqual(FakeClient.calls, [])
        self.assertIn("No había enrolamiento", said)

    def test_it_is_a_subcommand_of_the_agent(self) -> None:
        from agent import __main__ as loop

        with mock.patch.object(goodbye, "run", return_value=0) as run:
            with self.assertRaises(SystemExit) as raised:
                loop.main(["goodbye"])
        self.assertEqual(raised.exception.code, 0)
        run.assert_called_once_with([])


if __name__ == "__main__":
    unittest.main()
