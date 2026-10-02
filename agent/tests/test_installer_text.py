"""Tests for the installer's translated texts.

`deploy/install-service.ps1` cannot use gettext, so it asks
`agent.installer_text` for its texts. These tests keep the two halves honest:
the script only asks for texts that exist, every text is used, the script fills
in exactly the placeholders each text has, no literal message sneaks back into
the script, and what reaches PowerShell survives its console code page.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - fija idioma y fichero de estado también bajo `unittest discover`

import contextlib
import io
import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

from agent import installer_text
from agent.tests.test_i18n import PLACEHOLDER, InLanguage

SCRIPT = Path(installer_text.__file__).resolve().parent / "deploy" / "install-service.ps1"

#: `Msg "clave"` o `Msg "clave" @{ nombre = ...; otro = ... }`
MSG_CALL = re.compile(r'Msg\s+"(\w+)"(?:\s+@\{([^}]*)\})?')


def script_calls() -> list[tuple[str, set[str]]]:
    text = SCRIPT.read_text(encoding="utf-8-sig")
    calls = []
    for key, values in MSG_CALL.findall(text):
        names = {part.split("=")[0].strip() for part in values.split(";") if "=" in part}
        calls.append((key, names))
    return calls


class ScriptAndMessagesAgreeTests(unittest.TestCase):
    def test_every_text_the_script_asks_for_exists_and_every_text_is_used(self) -> None:
        asked = {key for key, _names in script_calls()}
        defined = set(installer_text.install_script_messages())

        self.assertGreater(len(asked), 10)  # si esto baja a cero, la expresión regular se ha roto
        self.assertEqual(sorted(asked - defined), [], "el script pide textos que no existen")
        self.assertEqual(sorted(defined - asked), [], "textos que el script ya no usa")

    def test_the_script_fills_exactly_the_placeholders_of_each_text(self) -> None:
        """Uno sin rellenar saldría como `%(exe)s` en la consola de quien instala."""
        messages = installer_text.install_script_messages()
        for key, names in script_calls():
            with self.subTest(key=key):
                self.assertEqual(names, set(PLACEHOLDER.findall(messages[key])))

    def test_no_literal_message_is_left_in_the_script(self) -> None:
        """Todo lo que ve una persona pasa por `Msg`, con dos excepciones que no
        pueden traducirse: el aviso de que no hay agente (es el agente quien
        traduce) y el error interno de `Msg` cuando falta un texto, que es un
        fallo de programación que los tests de arriba ya impiden que llegue a
        nadie."""
        text = SCRIPT.read_text(encoding="utf-8-sig")
        literal = re.findall(r'(?:throw|Write-Host|Write-Warning|-Prompt)\s+"([^"]+)"', text)

        self.assertEqual(len(literal), 2, literal)
        self.assertTrue(any("NetInventory agent not found" in message for message in literal))
        self.assertTrue(any(message.startswith("install-service.ps1: falta el texto") for message in literal))


class OutputTests(unittest.TestCase):
    def _printed(self, language: str) -> str:
        buffer = io.StringIO()
        with InLanguage(language), contextlib.redirect_stdout(buffer):
            installer_text.main()
        return buffer.getvalue()

    def test_the_json_is_pure_ascii_so_no_code_page_can_mangle_it(self) -> None:
        for language in ("es", "de", "fr", "pt_BR"):
            with self.subTest(language=language):
                self.assertTrue(self._printed(language).isascii())

    def test_the_json_carries_the_session_language(self) -> None:
        data = json.loads(self._printed("de"))

        self.assertEqual(data["installed"], "Dienst „Cenya Agent“ installiert und gestartet.")
        self.assertEqual(json.loads(self._printed("es"))["installed"], "Servicio «Cenya Agent» instalado y en marcha.")


class ServiceCommandSpeaksTheLanguageTests(unittest.TestCase):
    """Los mensajes que imprime `cenya-agent-service install` también se traducen."""

    def test_install_output_follows_the_session_language(self) -> None:
        import importlib
        import os
        import tempfile

        from agent.tests.test_winservice import fake_pywin32

        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(sys.modules, fake_pywin32(Path(tmp))):
            sys.modules.pop("agent.winservice", None)
            ws = importlib.import_module("agent.winservice")
            buffer = io.StringIO()
            env = {"NETINVENTORY_AGENT_TOKEN": "nia_x", "NETINVENTORY_URL": "https://inventario.local"}
            with InLanguage("fr"), mock.patch.dict(os.environ, env), mock.patch.object(
                ws, "_store_environment"
            ), mock.patch.object(ws, "restrict_key_to_administrators"), mock.patch.object(
                ws, "lock_status_directory"
            ), contextlib.redirect_stdout(buffer):
                ws._after_install([])

        said = buffer.getvalue()
        # La lista incluye cuanto `CENYA_*`/`NETINVENTORY_*` haya en la consola
        # (los tests fijan `CENYA_STATE_DIR`), así que se miran las dos mitades.
        self.assertIn("Variables enregistrées dans le service :", said)
        self.assertIn("NETINVENTORY_AGENT_TOKEN", said)
        self.assertIn("La clé de registre du service n'est désormais lisible que par SYSTEM", said)
        self.assertNotIn("nia_x", said)


if __name__ == "__main__":
    unittest.main()
