"""Lo que encontró la revisión de seguridad del agente v2, cada cosa con su prueba.

Los arreglos de la instalación en Windows (la carpeta `previous`, la del
programa con /DIR=, WebView2) se comprueban de verdad en `smoke-test.ps1`;
aquí, que el texto del instalador los sigue llevando.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import json
import os
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from agent import credentials, localpipe, ssh, update
from agent.localapi import Admission, Caller
from agent.localops import redact

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"


class SshArgumentTests(unittest.TestCase):
    """Usuario y equipo vienen del servidor o de la red: nunca como opción de `ssh`."""

    def test_the_destination_goes_after_a_double_dash(self) -> None:
        argv = ssh.argv_for(host="-oLocalCommand=x", username="-oProxyCommand=calc", command="show version")

        self.assertEqual(argv[-5:], ["-l", "-oProxyCommand=calc", "--", "-oLocalCommand=x", "show version"])

    def test_option_like_users_and_hosts_are_not_credentials(self) -> None:
        for raw in (
            {"kind": "ssh", "username": "-oProxyCommand=calc", "secret": "x"},
            {"kind": "ssh", "username": "admin", "host": "-oProxyCommand=calc", "secret": "x"},
            {"kind": "ssh", "username": "ad min", "secret": "x"},
            {"kind": "ssh", "username": "admin\n", "host": "10.0.0.1\x00", "secret": "x"},
        ):
            with self.subTest(raw=raw):
                self.assertIsNone(credentials._one(raw))
        self.assertIsNotNone(credentials._one({"kind": "ssh", "username": "admin", "host": "10.0.0.0/24", "secret": "x"}))


class PipeOwnerTests(unittest.TestCase):
    """Una ventana elevada no habla con un canal de un proceso sin elevar de la misma cuenta."""

    ME = "S-1-5-21-1-2-3-1001"

    def test_only_system_or_admins_when_own_is_not_allowed(self) -> None:
        self.assertFalse(localpipe.trusted_pipe_owner(self.ME, self.ME, allow_own=False))
        self.assertTrue(localpipe.trusted_pipe_owner("S-1-5-18", self.ME, allow_own=False))
        self.assertTrue(localpipe.trusted_pipe_owner("S-1-5-32-544", self.ME, allow_own=False))
        # Sin elevar y en un canal de desarrollo, el de uno mismo sigue valiendo.
        self.assertTrue(localpipe.trusted_pipe_owner(self.ME, self.ME))


class AdmissionReserveTests(unittest.TestCase):
    def test_strangers_that_never_speak_do_not_fill_the_real_slots(self) -> None:
        admission = Admission(total=4, per_caller=4)
        # Las conexiones mudas tienen su propio tope, más holgado…
        self.assertEqual(sum(admission.enter() for _ in range(20)), 12)
        # …y no gastan ninguno de los huecos que se reparten al identificarse.
        self.assertTrue(admission.claim(Caller(admin=True, who="admin")))


class SupportBundleRedactionTests(unittest.TestCase):
    def test_a_secret_with_quotes_is_redacted_in_its_json_form_too(self) -> None:
        secret = 'pa"ss\\word-123'
        text = json.dumps({"note": f"falló con {secret}"}, ensure_ascii=False)
        secrets = [secret, json.dumps(secret, ensure_ascii=False)[1:-1]]

        self.assertNotIn("word-123", redact(text, secrets))


@unittest.skipIf(sys.platform == "win32", "el ayudante con privilegios es de Linux")
class RootResultFileTests(unittest.TestCase):
    """Root escribe `result.json` en una carpeta del agente: nada por ruta tras abrir."""

    def test_a_link_in_place_of_the_folder_is_not_followed(self) -> None:
        base = Path(tempfile.mkdtemp())
        elsewhere = base / "elsewhere"
        elsewhere.mkdir()
        (base / "updates").symlink_to(elsewhere)

        update._write_result(base / "updates", "1.2.3", "bad_hash")

        self.assertFalse((elsewhere / update.RESULT_FILE).exists())

    def test_the_result_is_written_and_owned_by_the_folder_owner(self) -> None:
        folder = Path(tempfile.mkdtemp())

        update._write_result(folder, "1.2.3", "bad_hash")

        written = folder / update.RESULT_FILE
        self.assertEqual(json.loads(written.read_text(encoding="utf-8")), {"version": "1.2.3", "error": "bad_hash"})
        self.assertEqual(os.stat(written).st_uid, os.stat(folder).st_uid)


class InstallerTextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.iss = (PACKAGING / "cenya-agent.iss").read_text(encoding="utf-8")
        self.install_sh = (PACKAGING.parent / "deploy" / "install.sh").read_text(encoding="utf-8")

    def test_previous_is_rebuilt_from_scratch_before_an_update(self) -> None:
        backup = self.iss[self.iss.index("function BackupPrevious") :]
        backup = backup[: backup.index("\nend;")]
        self.assertIn("DelTree(PreviousDir, True, True, True)", backup)
        self.assertIn("if DirExists(PreviousDir)", backup)

    def test_the_program_folder_is_closed_before_copying(self) -> None:
        self.assertIn("ProtectAppDir;", self.iss)
        self.assertIn("/inheritance:r", self.iss)

    def test_webview2_is_installed_when_missing(self) -> None:
        self.assertIn("InstallWebView2;", self.iss)
        self.assertIn("MicrosoftEdgeWebview2Setup.exe", self.iss)
        for language in ("spanish", "english", "german", "french", "brazilianportuguese"):
            self.assertIn(f"{language}.WebView2Installing=", self.iss)

    def test_a_connection_from_the_file_name_is_shown_before_use(self) -> None:
        self.assertIn("ConnectionPage.Values[0] := InstallerNameConnection;", self.iss)
        self.assertIn("(InstallerNameConnection <> '') and WizardSilent", self.iss)

    def test_install_sh_never_touches_update_markers_as_root(self) -> None:
        watchdog = self.install_sh[self.install_sh.index("\nwatchdog() {") :]
        watchdog = watchdog[: watchdog.index("\n}\n")]
        self.assertNotIn(">\"$STATE/updates", watchdog)
        self.assertNotIn("chown", watchdog)
        self.assertIn("mark_as_agent", watchdog)


if __name__ == "__main__":
    unittest.main()


class WhatEveryoneMayReadTests(unittest.TestCase):
    """Un usuario cualquiera de la máquina: el estado sí, el registro y el mapa de la red no."""

    def test_the_log_is_for_administrators(self) -> None:
        from agent.localapi import may

        self.assertFalse(may("log", Caller(admin=False, who="u")))
        self.assertTrue(may("log", Caller(admin=True, who="a")))
        self.assertTrue(may("status", Caller(admin=False, who="u")))

    def test_about_without_admin_hides_the_networks(self) -> None:
        from unittest import mock

        from agent.localops import LocalService

        full = {"hostname": "PC", "os": {"system": "Windows"}, "agent_version": "0.11.0", "networks": [{"cidr": "10.0.0.0/24"}],
                "excluded": {"subnets": ["10.0.0.0/28"], "addresses": []}, "capabilities": {"snmp": True}}
        service = LocalService()
        with mock.patch("agent.localops.about.build", return_value=full):
            reader = service.op_about({}, Caller(admin=False, who="u"))
            admin = service.op_about({}, Caller(admin=True, who="a"))

        self.assertEqual(set(reader), {"hostname", "os", "agent_version"})
        self.assertEqual(admin, full)
