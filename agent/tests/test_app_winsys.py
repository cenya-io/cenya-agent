"""Windows' own controls (agent/app/winsys.py) with every Win32 call mocked.

No test here starts, stops or reconfigures the real service, or touches the
registry: the pywin32 modules and `winreg` are replaced by mocks.
"""

from __future__ import annotations

import agent.tests  # noqa: F401

import sys
import types
import unittest
from unittest import mock

from agent.app import winsys


class FakeWinError(Exception):
    def __init__(self, winerror: int, strerror: str = "") -> None:
        super().__init__(strerror)
        self.winerror = winerror
        self.strerror = strerror


def pywin32_mocks() -> dict:
    pywintypes = types.SimpleNamespace(error=FakeWinError)
    service = mock.MagicMock()
    service.SERVICE_NO_CHANGE = 0xFFFFFFFF
    service.SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 3
    serviceutil = mock.MagicMock()
    return {"pywintypes": pywintypes, "win32service": service, "win32serviceutil": serviceutil}


class Win32ServiceApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.modules = pywin32_mocks()
        patcher = mock.patch.dict(sys.modules, self.modules)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.api = winsys.Win32ServiceApi("CenyaAgentTest")

    def test_state(self) -> None:
        self.modules["win32serviceutil"].QueryServiceStatus.return_value = (16, 4, 0, 0, 0, 0, 0)
        self.assertEqual(self.api.state(), winsys.SERVICE_RUNNING)

    def test_not_installed_and_access_denied(self) -> None:
        self.modules["win32serviceutil"].QueryServiceStatus.side_effect = FakeWinError(winsys.ERROR_SERVICE_DOES_NOT_EXIST)
        with self.assertRaises(winsys.ServiceControlError) as caught:
            self.api.state()
        self.assertEqual(caught.exception.code, "not_installed")
        self.modules["win32serviceutil"].StopService.side_effect = FakeWinError(winsys.ERROR_ACCESS_DENIED)
        with self.assertRaises(winsys.ServiceControlError) as caught:
            self.api.stop()
        self.assertEqual(caught.exception.code, "forbidden")

    def test_starting_a_running_service_is_fine(self) -> None:
        self.modules["win32serviceutil"].StartService.side_effect = FakeWinError(winsys.ERROR_SERVICE_ALREADY_RUNNING)
        self.api.start()
        self.modules["win32serviceutil"].StartService.assert_called_once_with("CenyaAgentTest")

    def test_autostart_is_automatic_delayed_like_the_installer(self) -> None:
        service = self.modules["win32service"]
        self.api.set_start(True)
        args = service.ChangeServiceConfig.call_args.args
        self.assertEqual(args[2], winsys.SERVICE_AUTO_START)
        service.ChangeServiceConfig2.assert_called_once_with(mock.ANY, 3, True)
        service.ChangeServiceConfig2.reset_mock()
        self.api.set_start(False)
        self.assertEqual(service.ChangeServiceConfig.call_args.args[2], winsys.SERVICE_DEMAND_START)
        service.ChangeServiceConfig2.assert_not_called()
        self.assertEqual(service.CloseServiceHandle.call_count, 4)

    def test_start_type(self) -> None:
        service = self.modules["win32service"]
        service.QueryServiceConfig.return_value = (16, winsys.SERVICE_AUTO_START, 1, "x", "", 0, [], "LocalSystem", "Cenya")
        service.QueryServiceConfig2.return_value = True
        self.assertEqual(self.api.start_type(), (winsys.SERVICE_AUTO_START, True))


class ServiceControlTests(unittest.TestCase):
    def test_query_names_states_and_start_types(self) -> None:
        api = mock.Mock()
        api.state.return_value = winsys.SERVICE_RUNNING
        api.start_type.return_value = (winsys.SERVICE_AUTO_START, True)
        self.assertEqual(winsys.ServiceControl(api).query(), {"state": "running", "start_type": "delayed"})
        api.state.side_effect = winsys.ServiceControlError("not_installed")
        self.assertEqual(winsys.ServiceControl(api).query()["state"], "not_installed")

    def test_restart_waits_for_the_stop(self) -> None:
        api = mock.Mock()
        api.state.side_effect = [winsys.SERVICE_STOP_PENDING, winsys.SERVICE_STOP_PENDING, winsys.SERVICE_STOPPED]
        winsys.ServiceControl(api, sleep=lambda s: None).restart()
        self.assertEqual([c[0] for c in api.method_calls], ["stop", "state", "state", "state", "start"])

    def test_a_stop_that_never_ends_is_a_timeout(self) -> None:
        api = mock.Mock()
        api.state.return_value = winsys.SERVICE_STOP_PENDING
        with self.assertRaises(winsys.ServiceControlError) as caught:
            winsys.ServiceControl(api, sleep=lambda s: None, wait_seconds=2).restart()
        self.assertEqual(caught.exception.code, "timeout")
        api.start.assert_not_called()

    def test_the_default_api_is_the_real_service_name(self) -> None:
        from agent import winservice  # noqa: F401 - si no importa, el nombre se vigila por texto

        self.assertEqual(winsys.Win32ServiceApi().name, "CenyaAgent")

    def test_the_name_matches_the_service(self) -> None:
        from pathlib import Path

        text = (Path(winsys.__file__).resolve().parent.parent / "winservice.py").read_text(encoding="utf-8")
        self.assertIn(f'SERVICE_NAME = "{winsys.SERVICE_NAME}"', text)


class FakeKey:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeRegistry:
    HKEY_LOCAL_MACHINE = "HKLM"
    HKEY_CURRENT_USER = "HKCU"
    KEY_READ = 1
    KEY_SET_VALUE = 2
    REG_SZ = 1
    REG_BINARY = 3

    def __init__(self, values: dict) -> None:
        self.values = values
        self.written: list = []

    def OpenKey(self, root, key, *args):  # noqa: N802 - la API de winreg
        if not any(k[0] == root and k[1] == key for k in self.values):
            raise FileNotFoundError(key)
        self._open = (root, key)
        return FakeKey()

    def QueryValueEx(self, handle, name):  # noqa: N802
        try:
            return (self.values[(*self._open, name)], 1)
        except KeyError:
            raise FileNotFoundError(name) from None

    def CreateKeyEx(self, root, key, *args):  # noqa: N802
        self._open = (root, key)
        return FakeKey()

    def SetValueEx(self, handle, name, reserved, kind, value):  # noqa: N802
        self.written.append((self._open[1], name, value))


class TrayStartupTests(unittest.TestCase):
    RUN = ("HKLM", winsys.RUN_KEY, winsys.TRAY_RUN_VALUE)
    APPROVED = ("HKLM", winsys.APPROVED_KEY, winsys.TRAY_RUN_VALUE)

    def test_enabled_reads_like_the_task_manager(self) -> None:
        self.assertFalse(winsys.TrayStartup(FakeRegistry({})).enabled())
        self.assertTrue(winsys.TrayStartup(FakeRegistry({self.RUN: '"C:\\x\\cenya-agent-tray.exe"'})).enabled())
        off = FakeRegistry({self.RUN: "x", self.APPROVED: bytes([3]) + bytes(11)})
        self.assertFalse(winsys.TrayStartup(off).enabled())

    def test_turning_off_marks_it_disabled_without_deleting(self) -> None:
        reg = FakeRegistry({self.RUN: "x"})
        winsys.TrayStartup(reg).set(False)
        self.assertEqual(reg.written, [(winsys.APPROVED_KEY, winsys.TRAY_RUN_VALUE, bytes([3]) + bytes(11))])

    def test_turning_on_without_an_entry_needs_the_tray_next_to_the_app(self) -> None:
        with self.assertRaises(winsys.ServiceControlError):
            winsys.TrayStartup(FakeRegistry({}), tray_exe=r"C:\nowhere\cenya-agent-tray.exe").set(True)

    def test_without_rights_it_is_forbidden(self) -> None:
        reg = FakeRegistry({self.RUN: "x"})
        reg.SetValueEx = mock.Mock(side_effect=PermissionError())
        with self.assertRaises(winsys.ServiceControlError) as caught:
            winsys.TrayStartup(reg).set(False)
        self.assertEqual(caught.exception.code, "forbidden")


class WebView2Tests(unittest.TestCase):
    def test_found_and_missing(self) -> None:
        key = rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{winsys.WEBVIEW2_CLIENT}"
        self.assertEqual(winsys.webview2_version(FakeRegistry({("HKLM", key, "pv"): "131.0.1"})), "131.0.1")
        self.assertIsNone(winsys.webview2_version(FakeRegistry({("HKLM", key, "pv"): "0.0.0.0"})))
        self.assertIsNone(winsys.webview2_version(FakeRegistry({})))


class CommandTests(unittest.TestCase):
    def test_development_runs_the_module_from_the_package_root(self) -> None:
        with mock.patch.object(sys, "frozen", False, create=True):
            exe, params, cwd = winsys.own_command(["--section", "status"])
        self.assertEqual(params[:2], ["-m", "agent.app"])
        self.assertTrue(cwd)

    def test_frozen_the_tray_starts_the_app_next_to_it(self) -> None:
        with mock.patch.object(sys, "frozen", True, create=True), mock.patch.object(sys, "executable", r"C:\Cenya\cenya-agent-tray.exe"):
            exe, params, cwd = winsys.app_command([])
        self.assertTrue(exe.endswith(winsys.APP_EXE))


if __name__ == "__main__":
    unittest.main()
