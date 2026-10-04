"""Tests for the Windows installer's two halves that run without Windows.

* The frozen service: inside the installer there is no ``pythonservice.exe`` and
  no virtualenv -- the executable is its own service host. How it decides
  between "Windows started me" and "a person did" is tested against stand-ins
  for pywin32, like the rest of the service.
* The packaging files (PyInstaller spec, Inno Setup script, build and smoke
  scripts) that nothing here can run, but whose agreement with the code can be
  checked: the service name, the executables, the exit codes and, above all,
  that every text the installer shows exists in the five languages. A missing
  one shows nothing wrong until someone installs in German.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado y fija el idioma

import re
import sys
import tomllib
import types
import unittest
from pathlib import Path
from unittest import mock

from agent.tests.test_winservice import ServiceTestCase

AGENT_DIR = Path(__file__).resolve().parents[1]
PACKAGING = AGENT_DIR / "packaging"
ISS = (PACKAGING / "cenya-agent.iss").read_text(encoding="utf-8-sig")
LANGUAGES = ("spanish", "english", "german", "french", "brazilianportuguese")


def pascal_routine(header: str) -> str:
    """The body of a [Code] routine: from its header to its `end;` at column 0."""
    start = ISS.index(header)
    return ISS[start : ISS.index("\nend;", start)]


class FrozenServiceTestCase(ServiceTestCase):
    def setUp(self) -> None:
        super().setUp()
        # Lo que el servicio congelado importa además: el error de pywin32 y su
        # código de «no me ha lanzado el Administrador de servicios».
        pywintypes = sys.modules["pywintypes"]

        class Error(Exception):
            def __init__(self, winerror: int, funcname: str = "", strerror: str = "") -> None:
                super().__init__(winerror, funcname, strerror)
                self.winerror = winerror

        pywintypes.error = Error  # type: ignore[attr-defined]
        self.error = Error
        winerror = types.ModuleType("winerror")
        winerror.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT = 1063  # type: ignore[attr-defined]
        patcher = mock.patch.dict(sys.modules, {"winerror": winerror})
        patcher.start()
        self.addCleanup(patcher.stop)
        manager = self.fakes["servicemanager"]
        manager.Initialize = mock.Mock()  # type: ignore[attr-defined]
        manager.PrepareToHostSingle = mock.Mock()  # type: ignore[attr-defined]
        manager.StartServiceCtrlDispatcher = mock.Mock()  # type: ignore[attr-defined]
        self.manager = manager
        self.handle = self.fakes["win32serviceutil"].HandleCommandLine

    def frozen(self, value: bool = True):
        return mock.patch.object(sys, "frozen", value, create=True)


class FrozenServiceHostTests(FrozenServiceTestCase):
    def test_started_by_windows_it_hosts_the_service_and_never_parses_arguments(self) -> None:
        with self.frozen():
            self.ws.main(["cenya-agent-service.exe"])

        self.manager.Initialize.assert_called_once()
        self.manager.PrepareToHostSingle.assert_called_once_with(self.ws.CenyaAgentService)
        self.manager.StartServiceCtrlDispatcher.assert_called_once()
        self.handle.assert_not_called()

    def test_opened_by_a_person_it_falls_back_to_the_help(self) -> None:
        # Doble clic o consola: Windows contesta 1063 y se enseña la ayuda de pywin32.
        self.manager.StartServiceCtrlDispatcher.side_effect = self.error(1063, "StartServiceCtrlDispatcher")

        with self.frozen():
            self.ws.main(["cenya-agent-service.exe"])

        self.handle.assert_called_once()

    def test_any_other_dispatcher_failure_is_not_swallowed(self) -> None:
        self.manager.StartServiceCtrlDispatcher.side_effect = self.error(5, "StartServiceCtrlDispatcher")

        with self.frozen(), self.assertRaises(self.error):
            self.ws.main(["cenya-agent-service.exe"])

        self.handle.assert_not_called()

    def test_install_inside_the_installer_needs_no_host_preparation(self) -> None:
        # Sin venv ni pythonservice.exe: pywin32 registra el propio ejecutable.
        with self.frozen(), mock.patch.object(self.ws, "prepare_service_host") as prepare:
            self.ws.main(["cenya-agent-service.exe", "--startup", "delayed", "install"])

        prepare.assert_not_called()
        self.handle.assert_called_once()
        self.manager.StartServiceCtrlDispatcher.assert_not_called()

    def test_other_commands_inside_the_installer_go_to_pywin32(self) -> None:
        for command in ("stop", "start", "remove", "update", "debug"):
            with self.subTest(command=command):
                self.handle.reset_mock()
                with self.frozen():
                    self.ws.main(["cenya-agent-service.exe", command])
                self.handle.assert_called_once()
                self.manager.StartServiceCtrlDispatcher.assert_not_called()

    def test_not_frozen_it_never_tries_to_host_itself(self) -> None:
        with self.frozen(False):
            self.ws.main(["x"])

        self.manager.StartServiceCtrlDispatcher.assert_not_called()
        self.handle.assert_called_once()


class PackagingAgreesWithTheCodeTests(unittest.TestCase):
    def test_the_service_name_is_the_same_everywhere(self) -> None:
        sources = {
            "winservice": (AGENT_DIR / "winservice.py").read_text(encoding="utf-8"),
            "tray": (AGENT_DIR / "tray.py").read_text(encoding="utf-8"),
        }
        for name, text in sources.items():
            with self.subTest(file=name):
                self.assertIn('SERVICE_NAME = "CenyaAgent"', text)
        self.assertIn('#define ServiceName "CenyaAgent"', ISS)
        smoke = (PACKAGING / "smoke-test.ps1").read_text(encoding="utf-8-sig")
        self.assertIn('"CenyaAgent"', smoke)

    def test_the_backup_of_the_old_version_is_renamed_patiently(self) -> None:
        """04-10-2026, a real Windows: robocopy copied the old version to
        previous\\app.partial and the rename to previous\\app failed at once
        (code 1002), most likely the antivirus still scanning the new .exe and
        .dll. The update was given up and 0.11.1 vetoed for that agent. The
        rename now retries for half a minute and logs Windows' reason."""
        backup = ISS[ISS.index("function BackupPrevious"):]
        backup = backup[: backup.index("\nend;")]
        self.assertIn("RenamePatiently(Partial, Target)", backup)
        self.assertNotIn("RenameFile(", backup)
        helper = ISS[ISS.index("function RenamePatiently"):]
        helper = helper[: helper.index("\nend;")]
        self.assertIn("Sleep(", helper)
        self.assertIn("SysErrorMessage(DLLGetLastError)", helper)
        self.assertIn("'MoveFileW@kernel32.dll stdcall'", ISS)

    def test_the_package_says_the_same_version_as_the_code(self) -> None:
        """pip and the server read the version from pyproject.toml; the agent
        and the release tag from agent/__init__.py. 0.11.1 first left with the
        two apart, and only the server's tests noticed."""
        from agent import __version__

        pyproject = tomllib.loads((AGENT_DIR / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(pyproject["project"]["version"], __version__)

    def test_the_spec_builds_exactly_the_executables_the_package_declares(self) -> None:
        pyproject = tomllib.loads((AGENT_DIR / "pyproject.toml").read_text(encoding="utf-8"))
        declared = set(pyproject["project"]["scripts"]) | set(pyproject["project"]["gui-scripts"])
        spec = (PACKAGING / "cenya-agent.spec").read_text(encoding="utf-8")

        built = set(re.findall(r'name="(cenya-agent[\w-]*)"', spec)) - {"cenya-agent"} | {"cenya-agent"}
        self.assertEqual(declared, built)

    def test_every_entry_point_script_exists_and_calls_the_real_main(self) -> None:
        targets = {
            "entry_agent.py": "agent.__main__",
            "entry_service.py": "agent.winservice",
            "entry_tray.py": "agent.tray",
            "entry_askpass.py": "agent.askpass",
            "entry_app.py": "agent.app.main",
        }
        spec = (PACKAGING / "cenya-agent.spec").read_text(encoding="utf-8")
        for script, module in targets.items():
            with self.subTest(script=script):
                text = (PACKAGING / script).read_text(encoding="utf-8")
                self.assertIn(f"from {module} import main", text)
                self.assertIn(script, spec)

    def test_the_translations_travel_inside_the_installer(self) -> None:
        # `agent/i18n.py` las lee de al lado de sí mismo: sin esto, el instalador
        # habla castellano en todos los idiomas y nadie lo nota hasta instalarlo.
        spec = (PACKAGING / "cenya-agent.spec").read_text(encoding="utf-8")
        self.assertIn('"agent/translations"', spec)

    def test_the_installer_ships_every_executable_and_the_tray_starts_at_logon(self) -> None:
        # El askpass no se nombra en el .iss: `Source: {#SourceDir}\*` copia la
        # carpeta entera, y lo que importa es que el spec lo construya.
        for exe in ("cenya-agent.exe", "cenya-agent-service.exe", "cenya-agent-tray.exe", "cenya-agent-app.exe"):
            with self.subTest(exe=exe):
                self.assertIn(exe, ISS)
        # La misma clave de arranque que ya usaba `install-service.ps1`.
        self.assertIn('ValueName: "Cenya Agent"', ISS)
        self.assertIn("uninsdeletevalue", ISS)

    def test_the_window_and_its_page_travel_with_pywebview_only_where_needed(self) -> None:
        spec = (PACKAGING / "cenya-agent.spec").read_text(encoding="utf-8")
        # La página se lee de disco al lado de agent/app/main.py.
        self.assertIn('(str(AGENT / "app" / "ui"), "agent/app/ui")', spec)
        for package in ("webview", "pythonnet", "clr_loader"):
            with self.subTest(package=package):
                self.assertIn(f'"{package}"', spec)
        # Sin consola, como el icono.
        app = spec[spec.index("exe_app = EXE("):]
        self.assertIn("console=False", app[: app.index(")\n")])
        self.assertIn("a_app.datas", spec)

    def test_the_start_menu_opens_the_window_grouped_with_it_in_the_taskbar(self) -> None:
        from agent.app import main

        icons = ISS.split("[Icons]", 1)[1].split("\n[", 1)[0]
        self.assertIn('Filename: "{app}\\cenya-agent-app.exe"', icons)
        self.assertIn(f'AppUserModelID: "{main.APP_USER_MODEL_ID}"', icons)

    def test_the_window_is_closed_before_files_are_replaced_or_removed(self) -> None:
        self.assertIn('Parameters: "/im cenya-agent-app.exe /f"', ISS)
        self.assertIn("/im cenya-agent-app.exe /f", pascal_routine("procedure StopRunningAgent;"))
        watchdog = (PACKAGING / "update-watchdog.cmd").read_text(encoding="utf-8")
        rollback = watchdog[watchdog.index(":rollback"):watchdog.index("robocopy")]
        self.assertIn("taskkill /f /im cenya-agent-app.exe", rollback)

    def test_a_missing_webview2_warns_and_never_blocks(self) -> None:
        detection = pascal_routine("function WebView2Present: Boolean;")
        # La misma clave que mira la ventana (agent/app/winsys.py).
        from agent.app import winsys

        self.assertIn(winsys.WEBVIEW2_CLIENT, detection)
        for routine in ("function InitializeSetup", "function NextButtonClick", "function PrepareToInstall"):
            with self.subTest(routine=routine):
                self.assertNotIn("WebView2", pascal_routine(routine))
        self.assertIn("CustomMessage('WebView2Missing')", pascal_routine("procedure CurPageChanged"))
        self.assertIn("CustomMessage('WebView2Missing')", pascal_routine("procedure CurStepChanged"))

    def test_the_service_is_started_even_when_the_machine_is_not_enrolled(self) -> None:
        # Sin enrolar el servicio sirve el canal y espera: la aplicación lo conecta.
        post = pascal_routine("procedure CurStepChanged")
        start = post.index("RunService('--wait 60 start')")
        self.assertNotIn("if Enrolled then", post[post.index("InstallAgentService;"):start])
        smoke = (PACKAGING / "smoke-test.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("8b. Sin conexión", smoke)
        self.assertIn("cenya-agent status contesta por el canal", smoke)
        self.assertIn("la ventana arranca y carga WebView2", smoke)

    def test_the_build_has_pywebview_before_it_freezes(self) -> None:
        build = (PACKAGING / "build.ps1").read_text(encoding="utf-8-sig")
        self.assertLess(build.index("import webview"), build.index("-m PyInstaller"))
        workflow = (AGENT_DIR.parent / ".github" / "workflows" / "agent-installer.yml").read_text(encoding="utf-8")
        self.assertIn('"./agent[completo,gui]"', workflow)

    def test_the_installer_removes_the_service_and_the_secret_when_uninstalled(self) -> None:
        self.assertIn('Parameters: "remove"', ISS)
        self.assertIn('Type: filesandordirs; Name: "{commonappdata}\\Cenya"', ISS)

    def test_the_installer_puts_the_agent_on_the_system_path_once(self) -> None:
        # Las pantallas de Cenya enseñan `cenya-agent ...` sin ruta: sin esto, una
        # consola nueva de Windows contesta que no conoce el comando.
        self.assertIn("ChangesEnvironment=yes", ISS)
        key = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        lines = [line for line in ISS.splitlines() if line.startswith(f'Root: HKLM; Subkey: "{key}";')]
        self.assertEqual(len(lines), 1, "falta la entrada del PATH en [Registry]")
        line = lines[0]
        self.assertIn('ValueName: "Path"', line)
        # Expandible y añadiendo al final: nunca se pisa el PATH que ya había.
        self.assertIn("ValueType: expandsz", line)
        self.assertIn('ValueData: "{olddata};{app}"', line)
        # Con Check, para que una actualización no lo duplique; sin
        # uninsdeletevalue, que borraría el PATH entero del equipo.
        self.assertIn("Check: NeedsPathEntry", line)
        self.assertNotIn("uninsdelete", line)
        self.assertIn("function NeedsPathEntry: Boolean;", ISS)

    def test_the_uninstaller_takes_only_its_folder_out_of_the_path(self) -> None:
        self.assertIn("procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);", ISS)
        uninstall = ISS.split("procedure CurUninstallStepChanged", 1)[1]
        self.assertIn("RemovePathEntry", uninstall)
        remove = pascal_routine("procedure RemovePathEntry;")
        self.assertIn("WithoutPathEntry", remove)
        self.assertIn("RegWriteExpandStringValue(HKLM, EnvironmentKey, 'Path'", remove)
        self.assertNotIn("RegDeleteValue", ISS)

    def test_the_path_is_left_alone_by_the_unprivileged_test_build(self) -> None:
        # El instalador de prueba no puede escribir en HKLM: ni lo intenta.
        for routine in ("function NeedsPathEntry", "procedure RemovePathEntry"):
            with self.subTest(routine=routine):
                self.assertIn("IsAdminInstallMode", pascal_routine(routine))

    def test_the_smoke_test_checks_the_path_after_install_update_and_uninstall(self) -> None:
        smoke = (PACKAGING / "smoke-test.ps1").read_text(encoding="utf-8-sig")
        self.assertIn('GetEnvironmentVariable("Path", "Machine")', smoke)
        self.assertIn("where cenya-agent", smoke)
        self.assertIn("(PathEntries) -eq 1", smoke)
        self.assertIn("(PathEntries) -eq 0", smoke)

    def test_an_enrolled_machine_ignores_a_repeated_connection_string(self) -> None:
        # Repetir el despliegue con un código ya gastado no puede dejar parado un
        # agente que funcionaba: lo primero que se mira es si ya está enrolado.
        chosen = pascal_routine("function ChosenConnection")
        self.assertLess(chosen.index("FileExists(EnrollmentFile)"), chosen.index("Result := ConnectionParam"))
        smoke = (PACKAGING / "smoke-test.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("repetir el despliegue con /CONNECTION termina con 0", smoke)

    def test_the_connection_string_never_goes_through_a_shell(self) -> None:
        # La cadena la escribe una persona o un script y el instalador corre como
        # administrador: nada de cmd.exe, y solo caracteres de una cadena buena.
        enroll = pascal_routine("function EnrollAgent")
        self.assertIn("ExecAndCaptureOutput(", enroll)
        self.assertIn("{app}\\cenya-agent.exe", enroll)
        self.assertNotIn("{cmd}", ISS)
        self.assertIn("EncodeVer(6,3,0)", ISS)
        looks = pascal_routine("function LooksLikeConnection")
        allowed = re.search(r"Pos\(Lower\[I\], '([^']*)'\)", looks)
        self.assertIsNotNone(allowed)
        for dangerous in "\"' &|<>^%()!;,`":
            with self.subTest(char=dangerous):
                self.assertNotIn(dangerous, allowed.group(1))
        # Y se comprueba también en silencio, donde nadie pasa por la página.
        post_install = pascal_routine("procedure CurStepChanged")
        self.assertIn("if LooksLikeConnection(Connection) then", post_install)

    def test_the_exit_codes_are_documented_and_used_and_the_smoke_test_expects_them(self) -> None:
        for code in ("21", "22"):
            with self.subTest(code=code):
                self.assertIn(f"FailDeployment({code},", ISS)
        header = ISS.split("[Setup]")[0]
        self.assertIn("21", header)
        self.assertIn("22", header)
        smoke = (PACKAGING / "smoke-test.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("-eq 21", smoke)

    def test_the_build_takes_the_version_from_the_agent_not_from_a_copy(self) -> None:
        build = (PACKAGING / "build.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("__version__", build)
        self.assertIn("/DAppVersion=", build)
        self.assertIn("selftest", build)

    def test_the_stub_server_speaks_the_agents_real_endpoints(self) -> None:
        stub = (PACKAGING / "ci_stub_server.py").read_text(encoding="utf-8")
        client = (AGENT_DIR / "client.py").read_text(encoding="utf-8")
        for path in re.findall(r'"(/api/agent/[a-z]+/)"', client):
            with self.subTest(path=path):
                self.assertIn(path, stub)

    def test_the_workflow_builds_and_runs_the_smoke_test(self) -> None:
        workflow = (AGENT_DIR.parent / ".github" / "workflows" / "agent-installer.yml").read_text(encoding="utf-8")
        self.assertIn("build.ps1", workflow)
        self.assertIn("smoke-test.ps1", workflow)
        self.assertIn("windows", workflow)


class InstallerSpeaksFiveLanguagesTests(unittest.TestCase):
    """Cada texto propio del instalador existe en los cinco idiomas del producto."""

    def messages(self) -> dict[str, dict[str, str]]:
        by_language: dict[str, dict[str, str]] = {language: {} for language in LANGUAGES}
        for language, key, text in re.findall(r"^(\w+)\.(\w+)=(.*)$", ISS, re.M):
            if language in by_language:
                by_language[language][key] = text
        return by_language

    def test_the_five_languages_are_declared(self) -> None:
        declared = re.findall(r'^Name: "(\w+)"; MessagesFile:', ISS, re.M)
        self.assertEqual(sorted(declared), sorted(LANGUAGES))

    def test_every_language_has_exactly_the_same_texts(self) -> None:
        messages = self.messages()
        keys = {language: set(texts) for language, texts in messages.items()}
        self.assertGreater(len(keys["spanish"]), 5)
        for language in LANGUAGES:
            with self.subTest(language=language):
                self.assertEqual(keys[language], keys["spanish"])

    def test_every_text_the_code_uses_is_defined(self) -> None:
        used = set(re.findall(r"CustomMessage\('(\w+)'\)", ISS)) | set(re.findall(r"\{cm:(\w+)\}", ISS))
        defined = set(self.messages()["spanish"])
        self.assertEqual(used - defined, set())
        self.assertEqual(defined - used, set(), "textos que el instalador ya no usa")

    def test_no_text_is_empty_or_left_in_another_language(self) -> None:
        messages = self.messages()
        for key in messages["spanish"]:
            texts = {language: messages[language][key] for language in LANGUAGES}
            with self.subTest(key=key):
                self.assertTrue(all(text.strip() for text in texts.values()))
                # Si dos idiomas dicen lo mismo en una frase larga, se copió sin traducir.
                if len(texts["spanish"]) > 40:
                    self.assertEqual(len(set(texts.values())), len(LANGUAGES))

    def test_the_placeholders_survive_translation(self) -> None:
        messages = self.messages()
        for key in messages["spanish"]:
            expected = sorted(re.findall(r"%\d", messages["spanish"][key]))
            for language in LANGUAGES:
                with self.subTest(key=key, language=language):
                    self.assertEqual(sorted(re.findall(r"%\d", messages[language][key])), expected)

    def test_the_cli_text_the_installer_quotes_matches_the_agents_command(self) -> None:
        # Las frases de error mandan a `cenya-agent enroll`: que ese comando exista.
        main = (AGENT_DIR / "__main__.py").read_text(encoding="utf-8")
        self.assertIn('["enroll"]', main)
        for language, texts in self.messages().items():
            with self.subTest(language=language):
                self.assertIn("cenya-agent enroll", texts["EnrollFailed"])

    def test_the_script_is_saved_with_a_bom_so_inno_reads_the_accents(self) -> None:
        self.assertTrue((PACKAGING / "cenya-agent.iss").read_bytes().startswith(b"\xef\xbb\xbf"))
        for script in ("build.ps1", "smoke-test.ps1"):
            with self.subTest(script=script):
                self.assertTrue((PACKAGING / script).read_bytes().startswith(b"\xef\xbb\xbf"))


class PascalCommentTests(unittest.TestCase):
    """Un comentario `{ ... }` de Pascal termina en la PRIMERA llave que cierra.

    Con otra llave dentro --una constante de Inno, una expresión regular con
    un cuantificador--, el comentario acaba ahí y lo que sigue se compila como
    código: «'BEGIN' expected», y solo se ve al construir el instalador en CI.
    Pasó con tres comentarios a la vez.
    """

    def test_no_code_comment_has_a_brace_inside(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "packaging" / "cenya-agent.iss").read_text(encoding="utf-8")
        start = script.index("[Code]")
        code, first_line = script[start:], script[:start].count("\n") + 1
        nested: list[int] = []
        position = 0
        while position < len(code):
            if code[position] == "'":
                position = code.index("'", position + 1) + 1
            elif code.startswith("//", position):
                end = code.find("\n", position)
                position = end if end > 0 else len(code)
            elif code[position] == "{":
                end = code.index("}", position)
                if "{" in code[position + 1 : end]:
                    nested.append(first_line + code[:position].count("\n"))
                position = end + 1
            else:
                position += 1
        self.assertEqual(nested, [], "comentarios con una llave dentro, en estas líneas del .iss")



class WatchdogTaskXmlTests(unittest.TestCase):
    """El XML de la tarea del vigilante tiene que poder leerlo `schtasks /XML`.

    Con `<?xml ... encoding="UTF-8"?>` delante, schtasks fallaba con un código 1
    y el instalador abortaba la actualización: el analizador de tareas recibe el
    texto ya en UTF-16 y una declaración UTF-8 le hace fallar («unable to switch
    the encoding»). Solo se veía en el Windows de CI, al actualizar de verdad.
    """

    def setUp(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "packaging" / "cenya-agent.iss").read_text(encoding="utf-8")
        start = script.index("function CreateWatchdog")
        self.create = script[start : script.index("end;", script.index("Result := ResultCode;", start))]
        start = script.index("function XmlEscape")
        self.escape = script[start : script.index(nl_end := "end;" + "\n", start) + len(nl_end)]

    def test_the_task_xml_carries_no_encoding_declaration(self) -> None:
        # Solo las cadenas que construyen el XML (entre comillas simples), no los comentarios.
        built = "".join(re.findall(r"'([^']*)'", self.create))
        self.assertNotIn("<?xml", built)
        self.assertIn("<Task version=", self.create)

    def test_the_file_for_schtasks_is_written_without_a_byte_order_mark(self) -> None:
        # Con la marca de UTF-8 delante, schtasks decía «The task XML is malformed».
        self.assertNotIn("SaveStringsToUTF8File(XmlFile", self.create)
        self.assertIn("SaveStringToFile(XmlFile, AnsiString(Xml), False)", self.create)

    def test_the_description_is_escaped_to_plain_ascii(self) -> None:
        # La descripción alemana lleva «Ü»: sale como referencia numérica.
        self.assertIn("Ord(Value[I]) > 127", self.escape)
        self.assertIn("'&#' + IntToStr(Ord(Value[I])) + ';'", self.escape)
        self.assertIn("XmlEscape(CustomMessage('WatchdogDescription'))", self.create)


if __name__ == "__main__":
    unittest.main()
