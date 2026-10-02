"""Tests for what the running agent tells a person: console, `docker logs`, and
the Windows Event Viewer.

The Windows service redirects the agent's output to the Event Viewer, and adds
its own message when it stops. All of it goes through the agent's catalogue:
these tests check it arrives translated through the real code paths, and guard
against a new untranslated message sneaking in.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - fija idioma y fichero de estado también bajo `unittest discover`

import ast
import importlib
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from agent.tests.test_i18n import AGENT_DIR, InLanguage

#: Las llamadas que acaban delante de una persona: la salida del bucle (y, con
#: el servicio, el Visor de eventos), los errores que el bucle imprime y los
#: mensajes con que el servicio o la configuración se detienen.
PERSON_FACING_CALLS = {"print", "PushError", "SystemExit", "LogInfoMsg", "LogWarningMsg", "LogErrorMsg"}


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


class NothingLeftUntranslatedTests(unittest.TestCase):
    def test_no_person_facing_call_gets_a_literal_or_an_f_string(self) -> None:
        """Un `print("Detenido.")` o un `PushError(f"...")` nuevo saldría en
        castellano en cualquier idioma, y nadie lo notaría hasta verlo en un
        Visor de eventos en alemán."""
        offenders = []
        for path in sorted(AGENT_DIR.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or _call_name(node) not in PERSON_FACING_CALLS or not node.args:
                    continue
                first = node.args[0]
                is_text = isinstance(first, ast.JoinedStr) or (
                    isinstance(first, ast.Constant) and isinstance(first.value, str) and any(c.isalpha() for c in first.value)
                )
                if is_text:
                    offenders.append(f"{path.name}:{node.lineno} {_call_name(node)}(...)")
        self.assertEqual(offenders, [])


class LoopOutputTests(unittest.TestCase):
    def test_the_sweep_line_uses_each_language_plural(self) -> None:
        from agent.__main__ import _sweep_line

        with InLanguage("de"):
            self.assertEqual(_sweep_line(1, 14, 1), "[Agent] Scan gesendet: 1 neuer Fund, 14 bereits bekannt.")
            self.assertEqual(
                _sweep_line(3, 1, 2), "[Agent] Scan gesendet in 2 Teilen: 3 neue Funde, 1 bereits bekannt."
            )
        with InLanguage("es"):
            self.assertEqual(_sweep_line(0, 10, 1), "[agente] Barrido enviado: 0 hallazgos nuevos, 10 ya conocidos.")

    def test_the_loop_says_start_failure_and_stop_in_the_session_language(self) -> None:
        from agent import __main__ as loop
        from agent.client import PushError
        from agent.config import Config

        event = threading.Event()

        def fail(client, config, **kwargs):
            event.set()
            raise PushError("x")

        printed: list[str] = []
        with InLanguage("fr"), mock.patch.object(
            loop, "from_env", return_value=Config(url="https://inventario.local", token="t")
        ), mock.patch.object(loop, "AgentClient"), mock.patch.object(loop, "sweep", side_effect=fail), mock.patch(
            "builtins.print", side_effect=lambda text, **kwargs: printed.append(text)
        ):
            loop.main([], stop_event=event)

        self.assertEqual(printed[0], "[agent] Envoi vers https://inventario.local toutes les ~900 s.")
        self.assertEqual(printed[1], "[agent] x")
        self.assertEqual(printed[-1], "[agent] Arrêté.")

    def test_an_unexpected_error_keeps_the_exception_type(self) -> None:
        from agent.__main__ import unexpected_error

        with InLanguage("pt_BR"):
            self.assertEqual(unexpected_error(KeyError("host")), "Erro inesperado: KeyError: 'host'")


class ClientAndConfigTests(unittest.TestCase):
    def test_a_server_that_cannot_be_reached_is_said_in_the_session_language(self) -> None:
        from agent.client import AgentClient, PushError

        client = AgentClient("https://inventario.local", "nia_x")
        with InLanguage("de"), mock.patch.object(
            client._opener, "open", side_effect=urllib.error.URLError("timed out")
        ):
            with self.assertRaises(PushError) as caught:
                client.heartbeat(version="0.9.1", hostname="pc")

        self.assertTrue(str(caught.exception).startswith("Keine Verbindung zum Server: "))
        self.assertNotIn("nia_x", str(caught.exception))

    def _refused(self, body: bytes, language: str) -> tuple[str, list]:
        import io

        from agent.client import AgentClient, PushError

        client = AgentClient("https://inventario.local", "nia_x")
        sent: list = []

        def refuse(request, timeout=None):
            sent.append(request)
            raise urllib.error.HTTPError(request.full_url, 401, "Unauthorized", {}, io.BytesIO(body))

        with InLanguage(language), mock.patch.object(client._opener, "open", side_effect=refuse):
            with self.assertRaises(PushError) as caught:
                client.heartbeat(version="0.9.2", hostname="pc")
        return str(caught.exception), sent

    def test_the_server_reason_is_shown_without_its_json_envelope(self) -> None:
        """Antes llegaba `{"error": "Token de agente no v\\u00e1lido."}` al Visor
        de eventos y al icono: llaves, comillas y la tilde escapada."""
        said, _sent = self._refused('{"error": "Jeton d\'agent invalide."}'.encode(), "fr")

        self.assertEqual(said, "Le serveur a répondu 401 : Jeton d'agent invalide.")

    def test_the_agent_asks_the_server_to_answer_in_its_language(self) -> None:
        for language, header in (("de", "de"), ("pt_BR", "pt-BR, pt;q=0.8"), ("fr_CA", "fr-CA, fr;q=0.8")):
            with self.subTest(language=language):
                _said, sent = self._refused(b'{"error": "x"}', language)
                self.assertEqual(sent[0].get_header("Accept-language"), header)

    def test_a_body_that_is_not_the_servers_goes_as_it_came(self) -> None:
        """Un proxy o un portal cautivo: lo que diga, recortado, sin inventar."""
        said, _sent = self._refused(b"<html>Proxy authentication required</html>", "en")
        self.assertEqual(said, "The server answered 401: <html>Proxy authentication required</html>")

        said, _sent = self._refused(b'{"detail": "otra forma"}', "en")
        self.assertEqual(said, 'The server answered 401: {"detail": "otra forma"}')

    def test_a_missing_token_is_said_in_the_session_language(self) -> None:
        from agent import config

        # Con una carpeta de estado vacía: en una máquina ya enrolada, el
        # almacén de verdad haría que no faltara ningún token.
        with tempfile.TemporaryDirectory() as empty, InLanguage("fr"), self.assertRaises(SystemExit) as caught:
            config.from_env({"CENYA_STATE_DIR": empty})

        self.assertEqual(
            caught.exception.code,
            "Cet agent n'est pas enrôlé. Dans Paramètres → Agents, générer une chaîne de connexion "
            "puis exécuter : cenya-agent enroll <chaîne>",
        )


class EventViewerTests(unittest.TestCase):
    """Lo que el servicio deja en el Visor de eventos, por el camino de verdad."""

    def setUp(self) -> None:
        from agent.tests.test_winservice import fake_pywin32

        self.tmp = Path(tempfile.mkdtemp())
        self.fakes = fake_pywin32(self.tmp)
        patcher = mock.patch.dict(sys.modules, self.fakes)
        patcher.start()
        self.addCleanup(patcher.stop)
        sys.modules.pop("agent.winservice", None)
        self.ws = importlib.import_module("agent.winservice")

    def logged(self, level: str) -> list[str]:
        return [msg for lvl, msg in self.fakes["servicemanager"].logged if lvl == level]

    def test_a_service_without_token_says_why_it_stopped_in_german(self) -> None:
        """Sin tocar el bucle: el `from_env` real, sin token, y el mensaje que
        llega al Visor de eventos."""
        service = self.ws.CenyaAgentService(["CenyaAgent"])
        environ = {k: v for k, v in os.environ.items() if k != "NETINVENTORY_AGENT_TOKEN"}
        with InLanguage("de"), mock.patch.dict(os.environ, environ, clear=True), mock.patch.dict(
            os.environ, {"CENYA_LANGUAGE": "de"}
        ):
            with self.assertRaises(RuntimeError):
                service.SvcDoRun()

        self.assertEqual(
            self.logged("Error"),
            [
                "Cenya Agent wurde angehalten: Dieser Agent ist nicht registriert. Unter "
                "Einstellungen → Agenten eine Verbindungszeichenfolge erzeugen und ausführen: "
                "cenya-agent enroll <Zeichenfolge>"
            ],
        )

    def test_what_the_loop_prints_reaches_the_event_viewer_translated(self) -> None:
        from agent.__main__ import _sweep_line

        def agent(argv, stop_event):
            print(_sweep_line(2, 5, 1))
            stop_event.set()

        service = self.ws.CenyaAgentService(["CenyaAgent"])
        with InLanguage("pt_BR"), mock.patch.object(self.ws, "agent_main", side_effect=agent):
            service.SvcDoRun()

        self.assertEqual(self.logged("Info"), ["[agente] Varredura enviada: 2 novas descobertas, 5 já conhecidas."])

    def test_a_loop_that_ends_by_itself_is_explained_in_the_session_language(self) -> None:
        service = self.ws.CenyaAgentService(["CenyaAgent"])
        with InLanguage("en"), mock.patch.object(self.ws, "agent_main", return_value=None):
            with self.assertRaises(RuntimeError):
                service.SvcDoRun()

        self.assertEqual(
            self.logged("Error"), ["Cenya Agent has stopped: The agent loop ended without anyone stopping it."]
        )


if __name__ == "__main__":
    unittest.main()
