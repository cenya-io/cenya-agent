"""An agent upgraded in place from 0.10.x: enrolled, but with no key (spec 1.1, 1.2).

`enroll` is what creates the key, so an agent that was enrolled before 0.11
never had one and could never be sent a sealed credential. The protocol-2
runtime creates it once at start-up and presents it in every check-in until
the server confirms it holds it; it never replaces a key that exists; and if
the server holds a different key, it says so once, with a coded note.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from agent import identity, logs, store
from agent.client import AgentClient
from agent.config import Config
from agent.runtime import Runtime

TOKEN = "cya_TOKEN_DE_PRUEBA_0123"
OK = {"ok": True, "protocol": 2, "checkin_seconds": 30, "config_etag": "e1", "config": {}}


@unittest.skipUnless(identity.available(), "sin cryptography no hay clave")
class UpgradedAgentKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = Path(tempfile.mkdtemp(prefix="cenya-identity-"))
        for patcher in (
            mock.patch.dict(os.environ, {"CENYA_STATE_DIR": str(self.state)}),
            mock.patch("agent.runtime.about.build", return_value={"hostname": "PRUEBA"}),
            # Una clave de 3072 bits tarda; para esto vale una pequeña.
            mock.patch.object(identity, "KEY_BITS", 1024),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        logs.setup()
        self.addCleanup(logs.close)
        store.save(store.Enrollment("https://portal.example", TOKEN, "CPD"))  # como lo dejó la 0.10.x: sin clave
        self.client = AgentClient("https://portal.example", TOKEN)

    def runtime(self) -> Runtime:
        return Runtime(self.client, Config(url="https://portal.example", token=TOKEN), report=False)

    def bodies(self, runtime: Runtime, answers: list[dict]) -> list[dict]:
        sent: list[dict] = []
        with mock.patch.object(self.client, "checkin", side_effect=lambda body: sent.append(body) or answers.pop(0)):
            while answers:
                runtime.control.checkin_once()
        return sent

    def test_the_upgrade_creates_the_key_and_presents_it_until_the_server_confirms(self) -> None:
        self.assertFalse(identity.path().exists())
        runtime = self.runtime()
        self.assertTrue(identity.path().exists())
        pem = identity.public_key()
        self.assertIn("BEGIN PUBLIC KEY", pem)
        sent = self.bodies(runtime, [dict(OK), {**OK, "has_public_key": False}, {**OK, "has_public_key": True}, dict(OK)])
        self.assertEqual([body.get("public_key") for body in sent], [pem, pem, pem, None])
        self.assertTrue(runtime.snapshot()["identity"]["server_has_key"])
        self.assertIsNone(runtime.snapshot()["identity"]["problem"])
        self.assertNotIn("PRIVATE", "".join(str(body) for body in sent))

    def test_an_existing_key_is_never_regenerated(self) -> None:
        identity.ensure()
        before = identity.path().read_bytes()
        with mock.patch.object(identity, "ensure", wraps=identity.ensure) as ensure:
            self.runtime()
        ensure.assert_not_called()
        self.assertEqual(identity.path().read_bytes(), before)

    def test_an_unenrolled_agent_or_a_manual_once_run_creates_nothing(self) -> None:
        store.remove()
        self.runtime()
        self.assertFalse(identity.path().exists())
        store.save(store.Enrollment("https://portal.example", TOKEN, "CPD"))
        Runtime(self.client, Config(url="https://portal.example", token=TOKEN), report=False, once=True)
        self.assertFalse(identity.path().exists())

    def test_a_different_key_on_the_server_is_said_once_with_a_coded_note(self) -> None:
        runtime = self.runtime()
        other = "0" * 64
        with mock.patch.object(logs, "error") as said:
            sent = self.bodies(runtime, [{**OK, "has_public_key": True, "public_key_sha256": other},
                                         {**OK, "has_public_key": True, "public_key_sha256": other}])
        self.assertEqual(said.call_count, 1)
        self.assertIn("enroll", said.call_args.args[0])
        problem = runtime.snapshot()["identity"]["problem"]
        self.assertEqual((problem["collector"], problem["code"]), ("identity", "key_mismatch"))
        self.assertIsNone(sent[1].get("public_key"))  # no se insiste: el servidor nunca la sustituiría

    def test_the_same_key_on_the_server_is_no_problem(self) -> None:
        runtime = self.runtime()
        mine = identity.fingerprint(identity.public_key())
        self.assertEqual(len(mine), 64)
        self.bodies(runtime, [{**OK, "has_public_key": True, "public_key_sha256": mine.upper()}])
        self.assertIsNone(runtime.snapshot()["identity"]["problem"])

    def test_the_fingerprint_of_garbage_is_empty(self) -> None:
        self.assertEqual(identity.fingerprint("no es una clave"), "")
        self.assertEqual(identity.fingerprint(""), "")


if __name__ == "__main__":
    unittest.main()
