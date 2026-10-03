"""Un resellado solo para una clave que alguien ha permitido en esta máquina (`agent.approvals`)."""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from agent import approvals, sealing

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:  # pragma: no cover - el CI las instala
    rsa = None

AGENT = "4b9d6f0e-2a71-4c3b-8e5d-9f1a2c7b6e43"


def _pem() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


@unittest.skipIf(rsa is None or not sealing.available(), "hace falta cryptography")
class ApprovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pem = _pem()
        cls.other_pem = _pem()

    def setUp(self) -> None:
        self.state = Path(tempfile.mkdtemp(prefix="cenya-approvals-"))
        self.environ = {"CENYA_STATE_DIR": str(self.state)}
        self.approvals = approvals.ResealApprovals(self.environ)

    def ask_in_background(self, order_id: str, key: str, **kw) -> tuple[threading.Thread, list[str]]:
        answer: list[str] = []
        thread = threading.Thread(
            target=lambda: answer.append(self.approvals.ask(order_id, AGENT, "SRV-ALMACEN", approvals.fingerprint(key), 7, **kw)),
            daemon=True,
        )
        thread.start()
        for _ in range(200):
            if self.approvals.pending():
                break
            time.sleep(0.01)
        return thread, answer

    def test_the_fingerprint_is_stable_and_differs_per_key(self) -> None:
        self.assertEqual(approvals.fingerprint(self.pem), approvals.fingerprint(self.pem))
        self.assertNotEqual(approvals.fingerprint(self.pem), approvals.fingerprint(self.other_pem))
        self.assertEqual(len(approvals.fingerprint(self.pem).split()), 16)
        with self.assertRaises(sealing.SealError):
            approvals.fingerprint("not a key")

    def test_a_request_waits_and_is_shown_until_someone_allows_it(self) -> None:
        thread, answer = self.ask_in_background("order-1", self.pem)

        pending = self.approvals.pending()
        self.assertEqual([p["id"] for p in pending], ["order-1"])
        self.assertEqual(pending[0]["agent_name"], "SRV-ALMACEN")
        self.assertEqual(pending[0]["count"], 7)
        self.assertTrue(self.approvals.decide("order-1", True))
        thread.join(2)

        self.assertEqual(answer, [approvals.ALLOW])
        self.assertEqual(self.approvals.pending(), [])
        # La clave queda permitida: la próxima vez no se pregunta…
        self.assertTrue(self.approvals.trusted(AGENT, approvals.fingerprint(self.pem)))
        # …pero otra clave para el mismo agente es otra pregunta.
        self.assertFalse(self.approvals.trusted(AGENT, approvals.fingerprint(self.other_pem)))
        # Y lo recuerda otro proceso (un reinicio del servicio).
        self.assertTrue(approvals.ResealApprovals(self.environ).trusted(AGENT, approvals.fingerprint(self.pem)))

    def test_a_refusal_is_not_remembered(self) -> None:
        thread, answer = self.ask_in_background("order-2", self.pem)

        self.assertTrue(self.approvals.decide("order-2", False))
        thread.join(2)

        self.assertEqual(answer, [approvals.DENY])
        self.assertFalse(self.approvals.trusted(AGENT, approvals.fingerprint(self.pem)))

    def test_nobody_answering_is_a_timeout(self) -> None:
        self.assertEqual(
            self.approvals.ask("order-3", AGENT, "", approvals.fingerprint(self.pem), 1, timeout=0.05), approvals.TIMEOUT
        )
        self.assertEqual(self.approvals.pending(), [])

    def test_deciding_what_is_not_pending_says_so(self) -> None:
        self.assertFalse(self.approvals.decide("nope", True))

    def test_a_planted_trust_file_counts_as_untrusted_folder_content(self) -> None:
        from agent import store

        self.assertIn(approvals.FILE_NAME, store.PRIVATE_FILES)


@unittest.skipIf(rsa is None or not sealing.available(), "hace falta cryptography")
class RuntimeResealTests(unittest.TestCase):
    """El encargo `reseal` pasa por la ventana antes de abrir nada."""

    def setUp(self) -> None:
        from agent.client import AgentClient
        from agent.config import Config
        from agent.runtime import Runtime

        self.state = Path(tempfile.mkdtemp(prefix="cenya-reseal-"))
        patcher = mock.patch.dict(os.environ, {"CENYA_STATE_DIR": str(self.state)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.runtime = Runtime(AgentClient("https://portal.example", "t" * 40), Config(url="https://portal.example", token="t" * 40), report=False)
        self.params = {"agent": AGENT, "agent_name": "SRV-ALMACEN", "public_key": _pem(), "credential_ids": ["a", "b"]}

    def test_nothing_is_opened_when_the_person_refuses(self) -> None:
        with mock.patch("agent.orders.reseal") as reseal, mock.patch.object(self.runtime.approvals, "ask", return_value=approvals.DENY):
            outcome, result, notes = self.runtime._reseal("order-1", self.params)

        reseal.assert_not_called()
        self.assertEqual(outcome, "failed")
        self.assertEqual(result, {})
        self.assertEqual(notes[0].code, "denied")

    def test_nobody_answering_opens_nothing_either(self) -> None:
        with mock.patch("agent.orders.reseal") as reseal, mock.patch.object(self.runtime.approvals, "ask", return_value=approvals.TIMEOUT):
            _outcome, _result, notes = self.runtime._reseal("order-1", self.params)

        reseal.assert_not_called()
        self.assertEqual(notes[0].code, "not_approved")

    def test_allowed_reseals_go_ahead(self) -> None:
        done = ("done", {"envelopes": {}, "missing": ["a", "b"]}, [])
        with mock.patch("agent.orders.reseal", return_value=done) as reseal, mock.patch.object(self.runtime.approvals, "ask", return_value=approvals.ALLOW):
            self.assertEqual(self.runtime._reseal("order-1", self.params), done)
        reseal.assert_called_once()

    def test_an_already_trusted_key_does_not_ask_again(self) -> None:
        done = ("done", {"envelopes": {}, "missing": []}, [])
        with mock.patch("agent.orders.reseal", return_value=done), mock.patch.object(self.runtime.approvals, "trusted", return_value=True), mock.patch.object(self.runtime.approvals, "ask") as ask:
            self.runtime._reseal("order-1", self.params)
        ask.assert_not_called()

    def test_the_window_sees_what_is_waiting(self) -> None:
        with mock.patch.object(self.runtime.approvals, "pending", return_value=[{"id": "order-1"}]):
            self.assertEqual(self.runtime.snapshot()["reseal_requests"], [{"id": "order-1"}])


if __name__ == "__main__":
    unittest.main()
