"""Tests for stopping the agent from outside and for the Windows service.

None of this needs Windows or pywin32. The loop only needs something with
`is_set`/`wait`; the service module is imported against stand-ins for the
pywin32 modules whose signatures copy the real ones (pywin32 312) -- so a call
the real API does not accept, like a `checkPoint` argument to
`ReportServiceStatus`, fails here the same way it would fail in the service.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado también bajo `unittest discover`

import importlib
import os
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from agent.config import Config

REPO_ROOT = Path(__file__).resolve().parents[2]


class FakeEvent:
    """Un `stop_event` con guion: qué devuelve cada espera, sin dormir nunca."""

    def __init__(self, waits: list[bool], already_set: bool = False) -> None:
        self._waits = list(waits)
        self._set = already_set
        self.wait_calls: list[float | None] = []

    def is_set(self) -> bool:
        return self._set

    def wait(self, timeout: float | None = None) -> bool:
        self.wait_calls.append(timeout)
        result = self._waits.pop(0) if self._waits else False
        if result:
            self._set = True
        return result


# --- El bucle, parado desde fuera ---------------------------------------------


class NapStopTests(unittest.TestCase):
    def _client(self, answers: list[dict]) -> mock.Mock:
        client = mock.Mock()
        client.heartbeat.side_effect = answers
        return client

    def test_a_stop_given_before_the_nap_skips_it_entirely(self) -> None:
        """La orden de parar llegó durante el barrido: no se duerme ni un sorbo."""
        from agent.__main__ import _nap

        client = self._client([])
        event = FakeEvent([], already_set=True)
        with mock.patch("agent.__main__.time.sleep") as slept:
            _nap(client, interval=900, stop_event=event)

        slept.assert_not_called()
        self.assertEqual(event.wait_calls, [])
        client.heartbeat.assert_not_called()

    def test_a_stop_during_the_nap_wakes_it_without_waiting_for_the_minute(self) -> None:
        from agent.__main__ import _nap

        client = self._client([{"interval_seconds": 900, "sweep_now": False}])
        # Primer sorbo: nadie para. Segundo: «Detener» a mitad.
        event = FakeEvent([False, True])
        with mock.patch("agent.__main__.time.sleep") as slept:
            result = _nap(client, interval=900, stop_event=event)

        slept.assert_not_called()
        self.assertEqual(event.wait_calls, [60, 60])
        self.assertEqual(client.heartbeat.call_count, 1)
        self.assertEqual(result, 900)

    def test_with_a_stop_event_the_nap_still_polls_the_server(self) -> None:
        """Esperar sobre el evento no puede costar «Barrer ahora»."""
        from agent.__main__ import _nap

        client = self._client([{"interval_seconds": 900, "sweep_now": True}])
        event = FakeEvent([False, False])
        _nap(client, interval=900, stop_event=event)

        self.assertEqual(event.wait_calls, [60])
        self.assertFalse(event.is_set())


class MainStopTests(unittest.TestCase):
    def setUp(self) -> None:
        config = Config(url="http://localhost:8000", token="nia_prueba")
        patches = [
            mock.patch("agent.__main__.from_env", return_value=config),
            mock.patch("agent.__main__.AgentClient"),
            mock.patch("builtins.print"),
        ]
        for patcher in patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_an_event_already_set_means_no_sweep_at_all(self) -> None:
        from agent import __main__ as loop

        with mock.patch.object(loop, "sweep") as sweep:
            loop.main(argv=[], stop_event=FakeEvent([], already_set=True))

        sweep.assert_not_called()

    def test_a_stop_during_a_sweep_lets_it_finish_and_starts_no_other(self) -> None:
        from agent import __main__ as loop

        event = threading.Event()

        def sweep_then_stop(client, config):
            event.set()  # alguien pulsa «Detener» mientras barre
            return 900

        with mock.patch.object(loop, "sweep", side_effect=sweep_then_stop) as sweep:
            loop.main(argv=[], stop_event=event)

        self.assertEqual(sweep.call_count, 1)

    def test_a_failing_sweep_does_not_keep_a_stopped_agent_alive(self) -> None:
        from agent import __main__ as loop
        from agent.client import PushError

        event = threading.Event()

        def fail_then_stop(client, config):
            event.set()
            raise PushError("servidor caído")

        with mock.patch.object(loop, "sweep", side_effect=fail_then_stop) as sweep:
            loop.main(argv=[], stop_event=event)

        self.assertEqual(sweep.call_count, 1)


class ImportIsolationTests(unittest.TestCase):
    def test_the_agent_never_imports_pywin32_or_the_service(self) -> None:
        """Lo que mantiene el agente instalable en Linux y en CI sin pywin32.

        En un proceso aparte: en este, otro test puede haberlos importado ya.
        """
        code = (
            "import sys, agent.__main__, agent.collectors, agent.probe\n"
            "bad = sorted(m for m in sys.modules if m.startswith("
            "('win32', 'servicemanager', 'pywintypes', 'agent.winservice')))\n"
            "print(bad)\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "[]")


# --- El servicio, contra dobles de pywin32 --------------------------------------


SERVICE_STOP_PENDING = 3
SERVICE_RUNNING = 4


def fake_pywin32(tmp: Path) -> dict[str, types.ModuleType]:
    """Dobles de los módulos de pywin32 que importa `agent.winservice`."""
    servicemanager = types.ModuleType("servicemanager")
    servicemanager.logged = []  # type: ignore[attr-defined]
    for level in ("Info", "Warning", "Error"):
        setattr(
            servicemanager,
            f"Log{level}Msg",
            lambda msg, level=level: servicemanager.logged.append((level, msg)),  # type: ignore[attr-defined]
        )

    win32service = types.ModuleType("win32service")
    win32service.SERVICE_STOP_PENDING = SERVICE_STOP_PENDING  # type: ignore[attr-defined]
    win32service.SERVICE_RUNNING = SERVICE_RUNNING  # type: ignore[attr-defined]
    win32service.__file__ = str(tmp / "win32" / "win32service.pyd")

    class ServiceFramework:
        # La firma de pywin32 312, tal cual: sin `checkPoint`.
        def __init__(self, args):
            self.reports: list[tuple[int, int]] = []

        def ReportServiceStatus(self, serviceStatus, waitHint=5000, win32ExitCode=0, svcExitCode=0):
            self.reports.append((serviceStatus, waitHint))

    win32serviceutil = types.ModuleType("win32serviceutil")
    win32serviceutil.ServiceFramework = ServiceFramework  # type: ignore[attr-defined]
    # Como el real: devuelve el código de error, 0 si fue bien.
    win32serviceutil.HandleCommandLine = mock.Mock(return_value=0)  # type: ignore[attr-defined]

    pywintypes = types.ModuleType("pywintypes")
    pywintypes.__file__ = str(tmp / "pywin32_system32" / "pywintypes312.dll")

    return {
        "servicemanager": servicemanager,
        "win32service": win32service,
        "win32serviceutil": win32serviceutil,
        "pywintypes": pywintypes,
    }


class ServiceTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))
        self.fakes = fake_pywin32(self.tmp)
        # patch.dict deja sys.modules como estaba al salir: el `agent.winservice`
        # importado contra los dobles no sobrevive a este test.
        patcher = mock.patch.dict(sys.modules, self.fakes)
        patcher.start()
        self.addCleanup(patcher.stop)
        sys.modules.pop("agent.winservice", None)
        self.ws = importlib.import_module("agent.winservice")

    def logged(self, level: str) -> list[str]:
        return [msg for lvl, msg in self.fakes["servicemanager"].logged if lvl == level]


class ServiceRunStopTests(ServiceTestCase):
    def service(self):
        return self.ws.CenyaAgentService(["CenyaAgent"])

    def run_in_background(self, service) -> tuple[threading.Thread, list[BaseException]]:
        errors: list[BaseException] = []

        def target():
            try:
                service.SvcDoRun()
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        return thread, errors

    def test_stop_returns_at_once_while_the_sweep_is_still_finishing(self) -> None:
        """SvcStop llega por el hilo de control de Windows: no puede esperar al barrido."""
        finish = threading.Event()

        def agent(argv, stop_event):
            stop_event.wait()
            finish.wait(5)  # el barrido en curso, que aún tarda

        service = self.service()
        with mock.patch.object(self.ws, "agent_main", side_effect=agent):
            thread, errors = self.run_in_background(service)
            started = time.monotonic()
            service.SvcStop()
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 1.0)
            self.assertTrue(service.stop_event.is_set())
            self.assertEqual(service.reports[0], (SERVICE_STOP_PENDING, self.ws.STOP_WAIT_HINT_MS))
            finish.set()
            thread.join(5)

        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])

    def test_while_stopping_windows_keeps_hearing_that_it_progresses(self) -> None:
        finish = threading.Event()

        def agent(argv, stop_event):
            stop_event.wait()
            finish.wait(5)

        service = self.service()
        with mock.patch.object(self.ws, "STOP_REPORT_SECONDS", 0.01), mock.patch.object(
            self.ws, "agent_main", side_effect=agent
        ):
            thread, _errors = self.run_in_background(service)
            service.SvcStop()
            time.sleep(0.2)
            finish.set()
            thread.join(5)

        pending = [r for r in service.reports if r[0] == SERVICE_STOP_PENDING]
        self.assertGreaterEqual(len(pending), 3)
        # Al volver SvcDoRun, el hilo que avisa ya no sigue diciendo nada.
        reports_after = len(service.reports)
        time.sleep(0.05)
        self.assertEqual(len(service.reports), reports_after)
        self.assertFalse(service._stop_reporter.is_alive())

    def test_stopping_twice_is_one_stop(self) -> None:
        service = self.service()
        service.SvcStop()
        first_reporter = service._stop_reporter
        service.SvcShutdown()

        self.assertIs(service._stop_reporter, first_reporter)
        self.assertEqual(len(service.reports), 1)
        service._finished.set()

    def test_the_agent_runs_with_the_services_stop_event(self) -> None:
        service = self.service()
        service.stop_event.set()
        with mock.patch.object(self.ws, "agent_main") as agent:
            service.SvcDoRun()

        agent.assert_called_once_with(argv=[], stop_event=service.stop_event)

    def test_a_missing_token_stops_the_service_with_an_error_and_says_why(self) -> None:
        """Salir con error es lo que dispara el reinicio automático de Windows.

        Salir en limpio dejaría el servicio «detenido» como si nada, y nadie
        sabría por qué el inventario dejó de actualizarse.
        """
        reason = "Falta NETINVENTORY_AGENT_TOKEN."
        service = self.service()
        with mock.patch.object(self.ws, "agent_main", side_effect=SystemExit(reason)):
            with self.assertRaises(RuntimeError):
                service.SvcDoRun()

        self.assertTrue(any(reason in msg for msg in self.logged("Error")))
        # Y el icono de bandeja sabrá por qué, no solo que no hay noticias.
        self.assertEqual(self.ws.status.read()["stop_reason"], reason)
        self.assertEqual(self.ws.status.read()["state"], "detenido")

    def test_a_loop_that_ends_on_its_own_is_a_failure_not_a_stop(self) -> None:
        service = self.service()
        with mock.patch.object(self.ws, "agent_main", return_value=None):
            with self.assertRaises(RuntimeError):
                service.SvcDoRun()

    def test_an_unexpected_crash_is_logged_and_reported_as_failure(self) -> None:
        service = self.service()
        with mock.patch.object(self.ws, "agent_main", side_effect=ValueError("dato raro")):
            with self.assertRaises(RuntimeError):
                service.SvcDoRun()

        self.assertTrue(any("dato raro" in msg for msg in self.logged("Error")))

    def test_what_the_agent_prints_ends_up_in_the_event_log(self) -> None:
        """Un servicio no tiene consola: sin esto los mensajes se pierden."""
        saved = sys.stdout, sys.stderr

        def agent(argv, stop_event):
            print("[agente] Barrido enviado: 3 nuevos, 10 ya conocidos.")
            print("[agente] el servidor no contesta", file=sys.stderr)
            sys.stdout.write("sin salto final")
            stop_event.set()

        service = self.service()
        with mock.patch.object(self.ws, "agent_main", side_effect=agent):
            service.SvcDoRun()

        self.assertIn("[agente] Barrido enviado: 3 nuevos, 10 ya conocidos.", self.logged("Info"))
        self.assertIn("sin salto final", self.logged("Info"))
        self.assertIn("[agente] el servidor no contesta", self.logged("Warning"))
        self.assertEqual((sys.stdout, sys.stderr), saved)


class ServiceHostTests(ServiceTestCase):
    """El ejecutable del servicio, colocado donde de verdad arranca."""

    def layout(self) -> tuple[Path, Path, Path, Path]:
        base = self.tmp / "Python312"
        venv = self.tmp / "venv"
        (venv / "Scripts").mkdir(parents=True)
        base.mkdir()
        dll = f"python{sys.version_info.major}{sys.version_info.minor}.dll"
        for name in (dll, "python3.dll", "vcruntime140.dll"):
            (base / name).write_bytes(name.encode())
        host = self.tmp / "win32" / "pythonservice.exe"
        pywintypes = self.tmp / "pywin32_system32" / "pywintypes312.dll"
        for path in (host, pywintypes):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(path.name.encode())
        return base, venv, host, pywintypes

    def test_outside_a_venv_pywin32_is_left_to_do_its_own_thing(self) -> None:
        base, _venv, host, pywintypes = self.layout()

        self.assertIsNone(self.ws.prepare_service_host(base, base, host, pywintypes))
        self.assertFalse((base / "pythonservice.exe").exists())

    def test_in_a_venv_the_host_and_its_dlls_go_to_scripts(self) -> None:
        base, venv, host, pywintypes = self.layout()

        exe = self.ws.prepare_service_host(venv, base, host, pywintypes)

        scripts = venv / "Scripts"
        self.assertEqual(exe, scripts / "pythonservice.exe")
        dll = f"python{sys.version_info.major}{sys.version_info.minor}.dll"
        for name in ("pythonservice.exe", "pywintypes312.dll", dll, "python3.dll", "vcruntime140.dll"):
            self.assertTrue((scripts / name).exists(), name)
        # vcruntime140_1.dll no está en esta Python base: no se inventa.
        self.assertFalse((scripts / "vcruntime140_1.dll").exists())
        # Y nada en la raíz del venv, donde Windows no encuentra las DLL.
        self.assertFalse((venv / "pythonservice.exe").exists())

    def test_a_base_python_that_moved_is_said_clearly(self) -> None:
        base, venv, host, pywintypes = self.layout()
        dll = f"python{sys.version_info.major}{sys.version_info.minor}.dll"
        (base / dll).unlink()

        with self.assertRaises(FileNotFoundError) as caught:
            self.ws.prepare_service_host(venv, base, host, pywintypes)

        self.assertIn("entorno virtual", str(caught.exception))

    def test_identical_files_are_not_copied_again(self) -> None:
        """Con el servicio en marcha están bloqueados: un update no debe tropezar."""
        base, venv, host, pywintypes = self.layout()
        self.ws.prepare_service_host(venv, base, host, pywintypes)

        with mock.patch.object(self.ws.shutil, "copy2") as copy:
            self.ws.prepare_service_host(venv, base, host, pywintypes)

        copy.assert_not_called()

    def test_a_locked_file_that_did_change_asks_to_stop_the_service(self) -> None:
        base, venv, host, pywintypes = self.layout()
        self.ws.prepare_service_host(venv, base, host, pywintypes)
        host.write_bytes(b"pywin32 actualizado")

        with mock.patch.object(self.ws.shutil, "copy2", side_effect=PermissionError("en uso")):
            with self.assertRaises(PermissionError) as caught:
                self.ws.prepare_service_host(venv, base, host, pywintypes)

        self.assertIn("detén el servicio", str(caught.exception))


class InstallTests(ServiceTestCase):
    def test_only_netinventory_variables_go_to_the_service(self) -> None:
        environ = {
            "NETINVENTORY_URL": "https://inventario.local",
            "NETINVENTORY_AGENT_TOKEN": "nia_x",
            "PATH": r"C:\Windows",
            "USERNAME": "tecnico",
        }

        self.assertEqual(
            self.ws.service_environment(environ),
            ["NETINVENTORY_AGENT_TOKEN=nia_x", "NETINVENTORY_URL=https://inventario.local"],
        )

    def _after_install(self, environ: dict[str, str]):
        with mock.patch.dict(os.environ, environ, clear=True), mock.patch.object(
            self.ws, "_store_environment"
        ) as store, mock.patch.object(self.ws, "restrict_key_to_administrators") as restrict, mock.patch.object(
            self.ws, "lock_status_directory"
        ) as lock, mock.patch(
            "builtins.print"
        ) as printed:
            error = None
            try:
                self.ws._after_install([])
            except SystemExit as exc:
                error = exc
        self.locked = lock
        return store, restrict, printed, error

    def test_install_closes_the_status_folder_to_writers(self) -> None:
        """Si no, cualquier usuario podría dejar un estado falso con una URL que
        el icono abriría en el navegador de un administrador."""
        status_file = self.tmp / "ProgramData" / "NetInventory" / "status.json"
        with mock.patch.object(self.ws.status, "path", return_value=status_file):
            self._after_install({"NETINVENTORY_AGENT_TOKEN": "nia_x"})

        self.locked.assert_called_once_with(status_file.parent)

    def test_install_stores_the_variables_and_closes_the_key(self) -> None:
        store, restrict, printed, error = self._after_install(
            {"NETINVENTORY_URL": "https://inventario.local", "NETINVENTORY_AGENT_TOKEN": "nia_secreto"}
        )

        self.assertIsNone(error)
        store.assert_called_once_with(
            ["NETINVENTORY_AGENT_TOKEN=nia_secreto", "NETINVENTORY_URL=https://inventario.local"]
        )
        restrict.assert_called_once_with(rf"MACHINE\{self.ws.SERVICE_KEY}")
        # Qué variables, nunca su valor.
        said = " ".join(str(call.args) for call in printed.call_args_list)
        self.assertIn("NETINVENTORY_AGENT_TOKEN", said)
        self.assertNotIn("nia_secreto", said)

    def test_install_without_a_token_refuses_so_pywin32_removes_the_service(self) -> None:
        with mock.patch.object(self.ws.enrollment_store, "load", return_value=None):
            store, _restrict, _printed, error = self._after_install(
                {"NETINVENTORY_URL": "https://inventario.local"}
            )

        self.assertIsNotNone(error)
        store.assert_not_called()

    def test_install_without_a_token_variable_is_fine_when_the_machine_is_enrolled(self) -> None:
        # El camino normal desde que existe `cenya-agent enroll`: el token vive en
        # el almacén protegido y el servicio lo lee solo.
        enrolled = self.ws.enrollment_store.Enrollment("https://portal", "cya_x")
        with mock.patch.object(self.ws.enrollment_store, "load", return_value=enrolled):
            store, restrict, _printed, error = self._after_install({"CENYA_URL": "https://portal"})

        self.assertIsNone(error)
        store.assert_called_once_with(["CENYA_URL=https://portal"])
        restrict.assert_called_once()

    def test_the_new_variable_names_go_to_the_service_too(self) -> None:
        self.assertEqual(
            self.ws.service_environment({"CENYA_AGENT_TOKEN": "cya_x", "CENYA_URL": "https://p", "PATH": "x"}),
            ["CENYA_AGENT_TOKEN=cya_x", "CENYA_URL=https://p"],
        )

    def test_an_update_without_variables_keeps_the_ones_already_stored(self) -> None:
        store, restrict, _printed, error = self._after_install({})

        self.assertIsNone(error)
        store.assert_not_called()
        restrict.assert_called_once()

    def test_install_points_pywin32_at_the_prepared_host(self) -> None:
        exe = self.tmp / "venv" / "Scripts" / "pythonservice.exe"
        with mock.patch.object(self.ws, "prepare_service_host", return_value=exe) as prepare:
            self.ws.main(["cenya-agent-service", "--startup", "delayed", "install"])

        prepare.assert_called_once()
        self.assertEqual(self.ws.CenyaAgentService._exe_name_, str(exe))
        handle = self.fakes["win32serviceutil"].HandleCommandLine
        kwargs = handle.call_args.kwargs
        self.assertEqual(kwargs["serviceClassString"], "agent.winservice.CenyaAgentService")
        self.assertIs(kwargs["customOptionHandler"], self.ws._after_install)

    def test_a_refused_install_exits_with_its_error_code(self) -> None:
        """pywin32 devuelve el error en vez de salir con él. Visto en la prueba
        real: un `install` sin permisos terminaba con 0 y el script de
        instalación seguía como si nada."""
        self.fakes["win32serviceutil"].HandleCommandLine.return_value = 5  # acceso denegado
        with mock.patch.object(self.ws, "prepare_service_host", return_value=None):
            with self.assertRaises(SystemExit) as caught:
                self.ws.main(["cenya-agent-service", "install"])

        self.assertEqual(caught.exception.code, 5)

    def test_start_and_stop_do_not_touch_files(self) -> None:
        with mock.patch.object(self.ws, "prepare_service_host") as prepare:
            self.ws.main(["cenya-agent-service", "stop"])

        prepare.assert_not_called()

    def test_the_class_string_names_a_class_that_exists(self) -> None:
        """Si esto se desincroniza, el servicio se instala y no arranca nunca."""
        module_name, _, class_name = "agent.winservice.CenyaAgentService".rpartition(".")

        self.assertIs(getattr(sys.modules[module_name], class_name), self.ws.CenyaAgentService)


if __name__ == "__main__":
    unittest.main()
