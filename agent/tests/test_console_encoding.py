"""La consola no puede tumbar un comando por la codificación.

`cenya-agent status`, con la salida redirigida en un Windows en castellano,
escribe en cp1252, donde no existe la «→» de «Ajustes → Agentes»: el comando
moría con `UnicodeEncodeError`. Lo cazó la prueba del instalador en CI.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado y fija el idioma

import io
import unittest

from agent.logs import tolerant_console


class TolerantConsoleTests(unittest.TestCase):
    def cp1252_stream(self) -> tuple[io.BytesIO, io.TextIOWrapper]:
        raw = io.BytesIO()
        return raw, io.TextIOWrapper(raw, encoding="cp1252")

    def test_a_character_the_console_cannot_show_no_longer_raises(self) -> None:
        raw, stream = self.cp1252_stream()
        with self.assertRaises(UnicodeEncodeError):
            stream.write("Ajustes → Agentes")
            stream.flush()

        raw, stream = self.cp1252_stream()
        tolerant_console((stream,))
        stream.write("Ajustes → Agentes")
        stream.flush()

        self.assertEqual(raw.getvalue(), "Ajustes ? Agentes".encode("cp1252"))

    def test_what_the_console_can_show_comes_out_untouched(self) -> None:
        raw, stream = self.cp1252_stream()
        tolerant_console((stream,))
        stream.write("No está conectado")
        stream.flush()

        self.assertEqual(raw.getvalue().decode("cp1252"), "No está conectado")

    def test_a_stream_that_cannot_be_reconfigured_is_left_alone(self) -> None:
        tolerant_console((io.StringIO(), object()))  # no lanza


if __name__ == "__main__":
    unittest.main()
