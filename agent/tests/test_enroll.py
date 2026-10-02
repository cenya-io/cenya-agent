"""Tests for enrolment on the agent's side: the connection string, the protected
store, the redemption and how the configuration picks the token up.

The properties that matter: a malformed or hostile string never reaches the
network, the token is never printed and never left readable, an enrolled agent
restarts without trying to spend a used code, and an agent installed before the
rename (``NETINVENTORY_*``) keeps working.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent import config, connection, enroll, store
from agent.client import PushError

CODE = "K7QF-9M2X-4TQN"


class ConnectionStringTests(unittest.TestCase):
    def test_a_portal_string_means_https(self) -> None:
        parsed = connection.parse(f"cenya://inventario.midominio.com/{CODE}")

        self.assertEqual(parsed.url, "https://inventario.midominio.com")
        self.assertEqual(parsed.code, CODE)

    def test_the_http_flavour_is_explicit(self) -> None:
        parsed = connection.parse(f"cenya+http://localhost:8010/{CODE}")

        self.assertEqual(parsed.url, "http://localhost:8010")

    def test_a_port_is_kept(self) -> None:
        self.assertEqual(connection.parse(f"cenya://portal:8443/{CODE}").url, "https://portal:8443")

    def test_an_ipv6_literal_keeps_its_brackets(self) -> None:
        self.assertEqual(connection.parse(f"cenya+http://[::1]:8000/{CODE}").url, "http://[::1]:8000")

    def test_whitespace_quotes_case_and_missing_dashes_are_forgiven(self) -> None:
        for raw in (
            f"  cenya://portal/{CODE}\n",
            f'"cenya://portal/{CODE}"',
            f"'cenya://portal/{CODE.lower()}'",
            f"cenya://portal/{CODE.replace('-', '')}",
        ):
            with self.subTest(raw=raw):
                # El servidor normaliza guiones y mayúsculas: basta con que sea el mismo código.
                self.assertEqual(connection.parse(raw).code.replace("-", ""), CODE.replace("-", ""))

    def test_anything_else_is_refused(self) -> None:
        for raw in (
            "",
            "   ",
            None,
            "K7QF-9M2X-4TQN",  # el código solo, sin portal
            f"https://portal/{CODE}",  # esquema que no es de Cenya
            f"cenya:///{CODE}",  # sin host
            "cenya://portal/",  # sin código
            "cenya://portal/K7QF-9M2X",  # código corto
            f"cenya://portal/{CODE}/extra",
            f"cenya://portal/{CODE}?x=1",
            f"cenya://portal/{CODE}#frag",
            f"cenya://portal:notaport/{CODE}",
            "cenya://portal/K7QF-9M2X-4T!N",
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(connection.ConnectionStringError):
                    connection.parse(raw)  # type: ignore[arg-type]

    def test_credentials_in_the_host_part_are_refused(self) -> None:
        # `cenya://portal.legit.com@evil.example/CODE` parece ir a un sitio y va a otro.
        for raw in (
            f"cenya://portal.legit.com@evil.example/{CODE}",
            f"cenya://user:pass@portal/{CODE}",
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(connection.ConnectionStringError):
                    connection.parse(raw)


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="cenya-store-")
        self.env = {"CENYA_STATE_DIR": self.dir}

    def test_nothing_saved_means_not_enrolled(self) -> None:
        self.assertIsNone(store.load(self.env))

    def test_what_is_saved_is_loaded(self) -> None:
        store.save(store.Enrollment(url="https://portal", token="cya_secreto", name="CPD"), self.env)

        self.assertEqual(store.load(self.env), store.Enrollment("https://portal", "cya_secreto", "CPD"))

    def test_saving_again_replaces_it(self) -> None:
        store.save(store.Enrollment("https://a", "cya_1"), self.env)
        store.save(store.Enrollment("https://b", "cya_2"), self.env)

        self.assertEqual(store.load(self.env).token, "cya_2")

    def test_a_corrupt_file_is_not_enrolled_not_a_crash(self) -> None:
        for content in ("", "no es json", "[]", '{"url": "x"}', '{"url": "", "token": "t"}', '{"url": 1, "token": 2}'):
            with self.subTest(content=content):
                Path(self.dir, store.FILE_NAME).write_text(content, encoding="utf-8")
                self.assertIsNone(store.load(self.env))

    @unittest.skipIf(sys.platform == "win32", "los permisos de Windows se prueban aparte")
    def test_the_file_is_private_to_its_owner(self) -> None:
        target = store.save(store.Enrollment("https://portal", "cya_secreto"), self.env)

        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_no_temporary_file_is_left_behind(self) -> None:
        store.save(store.Enrollment("https://portal", "cya_secreto"), self.env)

        self.assertEqual([p.name for p in Path(self.dir).iterdir()], [store.FILE_NAME])

    def test_if_it_cannot_be_protected_nothing_is_written(self) -> None:
        # En Windows se cierra con icacls; si falla, el token no puede quedar legible.
        with mock.patch.object(store.sys, "platform", "win32"), mock.patch.object(
            store, "_restrict_windows", side_effect=OSError("acceso denegado")
        ):
            with self.assertRaises(store.StoreError):
                store.save(store.Enrollment("https://portal", "cya_secreto"), self.env)

        self.assertEqual(list(Path(self.dir).iterdir()), [])
        self.assertIsNone(store.load(self.env))

    def test_on_windows_it_drops_inheritance_and_names_groups_by_sid(self) -> None:
        calls: list[list[str]] = []

        def fake_run(command, **_kwargs):
            calls.append(command)
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(store.subprocess, "run", fake_run):
            store._restrict_windows(Path("C:/x/enrollment.json"))

        command = calls[0]
        self.assertEqual(command[0], "icacls")
        self.assertIn("/inheritance:r", command)
        # Por SID, no por nombre: «Administradores» no se llama así en otro idioma.
        self.assertIn("*S-1-5-18:F", command)
        self.assertIn("*S-1-5-32-544:F", command)

    def test_the_default_place_depends_on_the_platform(self) -> None:
        with mock.patch.object(store.sys, "platform", "win32"):
            self.assertEqual(store.state_dir({"ProgramData": "D:\\PD"}), Path("D:\\PD") / "Cenya")
        self.assertEqual(store.state_dir({"CENYA_STATE_DIR": "/x"}), Path("/x"))


class FakeClient:
    """Un `AgentClient` que contesta lo que se le diga, sin red."""

    answer: dict | Exception = {"ok": True, "token": "cya_nuevo", "name": "CPD"}
    calls: list[dict] = []
    extras: list[dict] = []

    def __init__(self, base_url: str, token: str, *, ca_bundle: str = "", proxy: object = None) -> None:
        self.base_url, self.token, self.ca_bundle = base_url, token, ca_bundle

    def enroll(self, *, code: str, hostname: str, version: str, public_key: str = "", about: dict | None = None) -> dict:
        FakeClient.calls.append({"url": self.base_url, "token": self.token, "code": code})
        # Lo nuevo del protocolo 2 (spec 1.1), aparte: los tests de antes
        # comparan las llamadas enteras y no tienen por qué saber de ello.
        FakeClient.extras.append({"public_key": public_key, "about": about})
        if isinstance(FakeClient.answer, Exception):
            raise FakeClient.answer
        return FakeClient.answer


class RedeemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="cenya-redeem-")
        self.env = {"CENYA_STATE_DIR": self.dir}
        FakeClient.answer = {"ok": True, "token": "cya_nuevo", "name": "CPD"}
        FakeClient.calls = []
        FakeClient.extras = []
        patcher = mock.patch.object(enroll, "AgentClient", FakeClient)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_protocol_2_sends_the_public_key_and_the_about(self) -> None:
        """Spec 1.1: la clave pública (si hay `cryptography`) y la presentación."""
        from agent import identity

        enroll.redeem(f"cenya://portal/{CODE}", self.env)

        extra = FakeClient.extras[0]
        self.assertEqual(extra["about"]["agent_version"], enroll.__version__)
        if identity.available():
            self.assertTrue(extra["public_key"].startswith("-----BEGIN PUBLIC KEY-----"))
            self.assertEqual(extra["public_key"], identity.public_key(self.env))
        else:
            self.assertEqual(extra["public_key"], "")

    def test_redeeming_saves_the_token_the_server_gave(self) -> None:
        saved = enroll.redeem(f"cenya://portal/{CODE}", self.env)

        self.assertEqual(saved.token, "cya_nuevo")
        self.assertEqual(store.load(self.env).token, "cya_nuevo")
        self.assertEqual(store.load(self.env).url, "https://portal")

    def test_the_code_goes_out_without_any_token(self) -> None:
        enroll.redeem(f"cenya://portal/{CODE}", self.env)

        self.assertEqual(FakeClient.calls, [{"url": "https://portal", "token": "", "code": CODE}])

    def test_a_bad_string_never_reaches_the_network(self) -> None:
        with self.assertRaises(SystemExit):
            enroll.redeem("esto no es una cadena", self.env)

        self.assertEqual(FakeClient.calls, [])

    def test_plain_http_to_another_machine_is_refused(self) -> None:
        with self.assertRaises(SystemExit):
            enroll.redeem(f"cenya+http://otra-maquina/{CODE}", self.env)

        self.assertEqual(FakeClient.calls, [])
        self.assertIsNone(store.load(self.env))

    def test_a_server_error_is_a_message_and_saves_nothing(self) -> None:
        FakeClient.answer = PushError("El servidor respondió 401: Código no válido")

        with self.assertRaises(SystemExit) as caught:
            enroll.redeem(f"cenya://portal/{CODE}", self.env)

        self.assertIn("401", str(caught.exception))
        self.assertIsNone(store.load(self.env))

    def test_an_answer_without_a_token_is_refused(self) -> None:
        # Un portal equivocado, un proxy que contesta 200 con otra cosa.
        for answer in ({"ok": True}, {"token": ""}, {"token": 5}):
            with self.subTest(answer=answer):
                FakeClient.answer = answer
                with self.assertRaises(SystemExit):
                    enroll.redeem(f"cenya://portal/{CODE}", self.env)
                self.assertIsNone(store.load(self.env))

    def test_if_the_token_cannot_be_stored_it_says_the_code_is_spent(self) -> None:
        with mock.patch.object(enroll.store, "save", side_effect=store.StoreError("no se pudo")):
            with self.assertRaises(SystemExit) as caught:
                enroll.redeem(f"cenya://portal/{CODE}", self.env)

        self.assertIn("no se pudo", str(caught.exception))
        self.assertIn("otra cadena", str(caught.exception))


class EnsureEnrolledTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="cenya-ensure-")
        FakeClient.answer = {"ok": True, "token": "cya_nuevo", "name": "CPD"}
        FakeClient.calls = []
        patcher = mock.patch.object(enroll, "AgentClient", FakeClient)
        patcher.start()
        self.addCleanup(patcher.stop)

    def env(self, **extra: str) -> dict[str, str]:
        return {"CENYA_STATE_DIR": self.dir, **extra}

    def test_the_first_start_redeems_the_connection_from_the_environment(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            enroll.ensure_enrolled(self.env(CENYA_CONNECTION=f"cenya://portal/{CODE}"))

        self.assertEqual(store.load(self.env()).token, "cya_nuevo")

    def test_a_restart_does_not_spend_the_code_again(self) -> None:
        env = self.env(CENYA_CONNECTION=f"cenya://portal/{CODE}")
        with contextlib.redirect_stdout(io.StringIO()):
            enroll.ensure_enrolled(env)
            enroll.ensure_enrolled(env)

        self.assertEqual(len(FakeClient.calls), 1)

    def test_an_explicit_token_means_no_enrolment(self) -> None:
        enroll.ensure_enrolled(self.env(CENYA_AGENT_TOKEN="cya_x", CENYA_CONNECTION=f"cenya://portal/{CODE}"))

        self.assertEqual(FakeClient.calls, [])

    def test_the_old_variable_name_counts_too(self) -> None:
        enroll.ensure_enrolled(self.env(NETINVENTORY_AGENT_TOKEN="nia_x", CENYA_CONNECTION=f"cenya://portal/{CODE}"))

        self.assertEqual(FakeClient.calls, [])

    def test_nothing_to_do_without_a_connection(self) -> None:
        enroll.ensure_enrolled(self.env())

        self.assertEqual(FakeClient.calls, [])


class EnrollCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="cenya-cmd-")
        self.env = {"CENYA_STATE_DIR": self.dir}
        FakeClient.answer = {"ok": True, "token": "cya_secretisimo", "name": "CPD"}
        FakeClient.calls = []
        patcher = mock.patch.object(enroll, "AgentClient", FakeClient)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_command(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = enroll.run(list(args), self.env)
        return code, out.getvalue(), err.getvalue()

    def test_it_enrols_and_never_prints_the_token(self) -> None:
        code, out, err = self.run_command(f"cenya://portal/{CODE}")

        self.assertEqual(code, 0)
        self.assertEqual(store.load(self.env).token, "cya_secretisimo")
        self.assertNotIn("cya_secretisimo", out + err)
        self.assertIn("CPD", out)

    def test_an_enrolled_machine_is_not_enrolled_twice_by_accident(self) -> None:
        self.run_command(f"cenya://portal/{CODE}")
        FakeClient.calls = []

        code, _out, err = self.run_command(f"cenya://portal/{CODE}")

        self.assertEqual(code, 1)
        self.assertIn("--force", err)
        self.assertEqual(FakeClient.calls, [])

    def test_force_enrols_again(self) -> None:
        self.run_command(f"cenya://portal/{CODE}")
        FakeClient.answer = {"ok": True, "token": "cya_otro", "name": "Otro"}

        code, _out, _err = self.run_command(f"cenya://portal/{CODE}", "--force")

        self.assertEqual(code, 0)
        self.assertEqual(store.load(self.env).token, "cya_otro")

    def test_without_a_string_it_says_how(self) -> None:
        with mock.patch.object(enroll.sys, "stdin", None):
            code, _out, err = self.run_command()

        self.assertEqual(code, 2)
        self.assertIn("cenya-agent enroll", err)

    def test_a_failure_is_a_message_and_exit_code_one(self) -> None:
        FakeClient.answer = PushError("El servidor respondió 401: Código no válido")

        code, _out, err = self.run_command(f"cenya://portal/{CODE}")

        self.assertEqual(code, 1)
        self.assertIn("401", err)
        self.assertIsNone(store.load(self.env))

    def test_the_main_entry_point_routes_the_subcommand(self) -> None:
        from agent import __main__ as entry

        with mock.patch.object(entry.enroll, "run", return_value=0) as run:
            with self.assertRaises(SystemExit) as caught:
                entry.main(["enroll", f"cenya://portal/{CODE}"])

        self.assertEqual(caught.exception.code, 0)
        run.assert_called_once_with([f"cenya://portal/{CODE}"])


class ConfigPicksTheTokenUpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="cenya-config-")

    def env(self, **extra: str) -> dict[str, str]:
        return {"CENYA_STATE_DIR": self.dir, **extra}

    def test_the_enrolled_token_and_url_are_used(self) -> None:
        store.save(store.Enrollment("https://portal", "cya_guardado"), self.env())

        cfg = config.from_env(self.env())

        self.assertEqual((cfg.url, cfg.token), ("https://portal", "cya_guardado"))

    def test_the_environment_token_wins_over_the_saved_one(self) -> None:
        store.save(store.Enrollment("https://portal", "cya_guardado"), self.env())

        cfg = config.from_env(self.env(CENYA_AGENT_TOKEN="cya_entorno", CENYA_URL="https://otro"))

        self.assertEqual((cfg.url, cfg.token), ("https://otro", "cya_entorno"))

    def test_a_url_from_the_environment_overrides_the_saved_one(self) -> None:
        # Un portal que cambia de dirección no obliga a enrolar de nuevo.
        store.save(store.Enrollment("https://viejo", "cya_guardado"), self.env())

        cfg = config.from_env(self.env(CENYA_URL="https://nuevo"))

        self.assertEqual((cfg.url, cfg.token), ("https://nuevo", "cya_guardado"))

    def test_the_old_variable_names_still_work(self) -> None:
        cfg = config.from_env(self.env(NETINVENTORY_AGENT_TOKEN="nia_viejo", NETINVENTORY_URL="https://portal"))

        self.assertEqual((cfg.url, cfg.token), ("https://portal", "nia_viejo"))

    def test_the_new_name_wins_when_both_are_set(self) -> None:
        cfg = config.from_env(
            self.env(CENYA_AGENT_TOKEN="cya_nuevo", NETINVENTORY_AGENT_TOKEN="nia_viejo", CENYA_URL="https://p")
        )

        self.assertEqual(cfg.token, "cya_nuevo")

    def test_without_any_token_it_tells_how_to_enrol(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            config.from_env(self.env())

        self.assertIn("cenya-agent enroll", str(caught.exception))

    def test_a_broken_store_is_the_same_as_none(self) -> None:
        Path(self.dir, store.FILE_NAME).write_text("{roto", encoding="utf-8")

        with self.assertRaises(SystemExit):
            config.from_env(self.env())

    def test_the_transport_check_still_applies_to_the_saved_url(self) -> None:
        store.save(store.Enrollment("http://otra-maquina", "cya_guardado"), self.env())

        with self.assertRaises(SystemExit):
            config.from_env(self.env())


if __name__ == "__main__":
    unittest.main()


class RenamedNamesTests(unittest.TestCase):
    """Lo que cambió con el nombre, y lo de antes que sigue valiendo."""

    def test_the_status_file_is_in_the_cenya_folder_on_windows(self) -> None:
        from agent import status

        with mock.patch.object(status.sys, "platform", "win32"), mock.patch.dict(
            os.environ, {"ProgramData": r"D:\PD"}, clear=True
        ):
            self.assertEqual(status.path(), Path(r"D:\PD") / "Cenya" / "status.json")

    def test_the_status_file_variable_old_name_still_works(self) -> None:
        from agent import status

        with mock.patch.dict(os.environ, {"NETINVENTORY_STATUS_FILE": "/x/viejo.json"}, clear=True):
            self.assertEqual(status.path(), Path("/x/viejo.json"))
        with mock.patch.dict(
            os.environ, {"NETINVENTORY_STATUS_FILE": "/x/viejo.json", "CENYA_STATUS_FILE": "/x/nuevo.json"}, clear=True
        ):
            self.assertEqual(status.path(), Path("/x/nuevo.json"))

    def test_the_language_variable_old_name_still_works(self) -> None:
        from agent import i18n

        with mock.patch.dict(os.environ, {"NETINVENTORY_LANGUAGE": "de"}, clear=True):
            self.assertEqual(i18n._session_languages()[0], "de")
        with mock.patch.dict(os.environ, {"NETINVENTORY_LANGUAGE": "de", "CENYA_LANGUAGE": "fr"}, clear=True):
            self.assertEqual(i18n._session_languages()[0], "fr")

    def test_service_and_tray_agree_on_the_new_names(self) -> None:
        # El mismo vigilante que ya había, ahora con el nombre nuevo: si el
        # icono busca un servicio que no existe, dice «no instalado» para siempre.
        source = Path(agent.tests.__file__).resolve().parent.parent
        self.assertIn('SERVICE_NAME = "CenyaAgent"', (source / "winservice.py").read_text(encoding="utf-8"))
        self.assertIn('SERVICE_NAME = "CenyaAgent"', (source / "tray.py").read_text(encoding="utf-8"))

    def test_the_package_ships_cenya_executables(self) -> None:
        import tomllib

        pyproject = tomllib.loads(
            (Path(agent.tests.__file__).resolve().parent.parent / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(pyproject["project"]["name"], "cenya-agent")
        self.assertEqual(
            set(pyproject["project"]["scripts"]), {"cenya-agent", "cenya-agent-service"}
        )
        self.assertEqual(set(pyproject["project"]["gui-scripts"]), {"cenya-agent-tray"})
