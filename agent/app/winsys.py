"""What the application asks Windows directly, not the service.

Three things are Windows' and not the agent's, so they do not go through the
local channel: starting and stopping the service (when it is stopped there is
nobody at the other end of the pipe to ask), the sign-in entry of the tray
icon, and the window's own housekeeping (elevation, one instance, the title
bar, the clipboard, opening a folder or a link).

Everything that touches the service control manager or the registry goes
through a small object with the Win32 calls in one place, so the tests swap
the pywin32 modules for mocks and **no test ever starts, stops or reconfigures
the real service**. Development (a pipe other than the real one) never gets
the real controls at all: `controls_for` hands out disabled ones.

Every function here is safe to import anywhere; pywin32 and ctypes' Windows
parts are only loaded when a function needs them.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

#: El nombre del servicio (`agent.winservice.SERVICE_NAME`), repetido para no
#: cargar el bucle del agente en la ventana. Un test vigila que coincidan.
SERVICE_NAME = "CenyaAgent"
#: El valor que deja el instalador en HKLM\...\Run para el icono (cenya-agent.iss).
TRAY_RUN_VALUE = "Cenya Agent"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
#: Donde el Administrador de tareas apunta si una entrada de Run está activa.
APPROVED_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
#: El identificador del runtime de WebView2 (Evergreen) en EdgeUpdate.
WEBVIEW2_CLIENT = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

APP_EXE = "cenya-agent-app.exe"
TRAY_EXE = "cenya-agent-tray.exe"
APP_MODULE = "agent.app"
MUTEX_NAME = "Local\\CenyaAgentApp"
SHOW_EVENT_NAME = "Local\\CenyaAgentAppShow"

# Códigos de error de Win32 que se distinguen.
ERROR_ACCESS_DENIED = 5
ERROR_SERVICE_ALREADY_RUNNING = 1056
ERROR_SERVICE_DOES_NOT_EXIST = 1060
ERROR_SERVICE_NOT_ACTIVE = 1062

# Estados y arranques del administrador de servicios.
SERVICE_STOPPED, SERVICE_START_PENDING, SERVICE_STOP_PENDING, SERVICE_RUNNING = 1, 2, 3, 4
SERVICE_AUTO_START, SERVICE_DEMAND_START, SERVICE_DISABLED = 2, 3, 4


class ServiceControlError(Exception):
    """`code`: ``forbidden`` | ``not_installed`` | ``timeout`` | ``dev`` | ``failed``."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


# --- Elevación y cómo volver a arrancar esta misma aplicación ---------------------


def is_elevated() -> bool:
    if sys.platform != "win32":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def own_command(args: list[str]) -> tuple[str, list[str], str | None]:
    """Ejecutable, argumentos y carpeta para arrancar la aplicación de nuevo.

    Congelada, es su propio .exe. En desarrollo, ``pythonw -m agent.app`` desde
    la carpeta que contiene el paquete, para que el módulo se encuentre.
    """
    if getattr(sys, "frozen", False):
        return sys.executable, list(args), None
    python = Path(sys.executable)
    windowed = python.with_name("pythonw.exe")
    exe = str(windowed if windowed.is_file() else python)
    root = str(Path(__file__).resolve().parent.parent.parent)
    return exe, ["-m", APP_MODULE, *args], root


def app_command(args: list[str]) -> tuple[str, list[str], str | None]:
    """Lo mismo, visto desde el icono de bandeja (otro ejecutable de la misma carpeta)."""
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).with_name(APP_EXE)), list(args), None
    return own_command(args)


def relaunch_elevated(args: list[str]) -> bool:
    """Pide a Windows (UAC) arrancar la aplicación como administrador. `True` si aceptó."""
    if sys.platform != "win32":
        return False
    import ctypes

    exe, params, cwd = own_command(args)
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, subprocess.list2cmdline(params), cwd, 1)
    return int(result) > 32


def relaunch_elevated_app(args: list[str]) -> bool:
    """Desde el icono: la ventana, elevada (el icono sigue sin elevar)."""
    if sys.platform != "win32":
        return False
    import ctypes

    exe, params, cwd = app_command(args)
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, subprocess.list2cmdline(params), cwd, 1)
    return int(result) > 32


def launch_app(args: list[str]) -> bool:
    """Arranca la ventana (desde el icono). Si ya está abierta, ella misma se trae al frente."""
    exe, params, cwd = app_command(args)
    if not Path(exe).is_file():
        return False
    try:
        flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        subprocess.Popen([exe, *params], cwd=cwd, close_fds=True, creationflags=flags)  # noqa: S603 - nuestro propio ejecutable
    except OSError:
        return False
    return True


# --- Sin servicio: ¿hay enrolamiento?, y enrolar con la consola del agente ----------


def enrollment_present(dev: bool, environ: Any = None) -> bool | None:
    """Si existe el fichero de enrolamiento. `None` si no se sabe.

    Solo mira si el fichero está (la carpeta deja listar a Usuarios), no lo
    lee: el token va dentro y no es de esta cuenta. En desarrollo solo mira una
    carpeta de estado puesta a propósito (``CENYA_STATE_DIR``), nunca la de la
    máquina, donde puede haber un agente de verdad.
    """
    env = os.environ if environ is None else environ
    if dev and not (env.get("CENYA_STATE_DIR") or "").strip():
        return None
    from agent import store

    try:
        return store.path(env).is_file()
    except OSError:
        return None


ENROLL_TIMEOUT_SECONDS = 120


def agent_cli_command(args: list[str]) -> tuple[str, list[str], str | None]:
    """``cenya-agent <args>``: el ejecutable de la consola, al lado de esta aplicación."""
    if getattr(sys, "frozen", False):
        return str(Path(sys.executable).with_name("cenya-agent.exe")), list(args), None
    root = str(Path(__file__).resolve().parent.parent.parent)
    return sys.executable, ["-m", "agent", *args], root


def enroll_with_cli(connection: str, runner: Callable[..., Any] = subprocess.run) -> tuple[bool, str]:
    """``cenya-agent enroll <cadena>``, sin intérprete de comandos. (hecho, frase para una persona).

    De lo que imprime solo se devuelve la última línea, ya limpia
    (`agent.logs.scrub`): el comando no imprime el token, pero lo que no se
    enseña no se puede filtrar.
    """
    from agent import logs

    exe, params, cwd = agent_cli_command(["enroll", connection])
    try:
        result = runner(
            [exe, *params],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=ENROLL_TIMEOUT_SECONDS,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, logs.scrub(type(exc).__name__)
    output = [line.strip() for line in f"{result.stdout or ''}\n{result.stderr or ''}".splitlines() if line.strip()]
    useful = [line for line in output if connection not in line]
    message = logs.scrub(useful[-1]) if useful else ""
    if result.returncode == 0:
        enrolled = [line for line in useful if "«" in line]
        return True, logs.scrub(enrolled[0]) if enrolled else message
    return False, message


# --- El servicio de Windows ---------------------------------------------------------


class Win32ServiceApi:
    """Las llamadas al administrador de servicios, en un solo sitio (y sustituibles)."""

    def __init__(self, name: str = SERVICE_NAME) -> None:
        self.name = name

    @staticmethod
    def _modules() -> tuple[Any, Any, Any]:
        import pywintypes
        import win32service
        import win32serviceutil

        return pywintypes, win32service, win32serviceutil

    def _translate(self, exc: Exception) -> ServiceControlError:
        code = getattr(exc, "winerror", None)
        if code == ERROR_ACCESS_DENIED:
            return ServiceControlError("forbidden")
        if code == ERROR_SERVICE_DOES_NOT_EXIST:
            return ServiceControlError("not_installed")
        return ServiceControlError("failed", str(getattr(exc, "strerror", "") or exc))

    def state(self) -> int:
        pywintypes, _, serviceutil = self._modules()
        try:
            return int(serviceutil.QueryServiceStatus(self.name)[1])
        except pywintypes.error as exc:
            raise self._translate(exc) from exc

    def start_type(self) -> tuple[int, bool]:
        """(tipo de arranque, si es «automático (retrasado)»)."""
        pywintypes, service, _ = self._modules()
        try:
            manager = service.OpenSCManager(None, None, service.SC_MANAGER_CONNECT)
            try:
                handle = service.OpenService(manager, self.name, service.SERVICE_QUERY_CONFIG)
                try:
                    start = int(service.QueryServiceConfig(handle)[1])
                    try:
                        delayed = bool(service.QueryServiceConfig2(handle, service.SERVICE_CONFIG_DELAYED_AUTO_START_INFO))
                    except pywintypes.error:
                        delayed = False
                    return start, delayed
                finally:
                    service.CloseServiceHandle(handle)
            finally:
                service.CloseServiceHandle(manager)
        except pywintypes.error as exc:
            raise self._translate(exc) from exc

    def start(self) -> None:
        pywintypes, _, serviceutil = self._modules()
        try:
            serviceutil.StartService(self.name)
        except pywintypes.error as exc:
            if exc.winerror != ERROR_SERVICE_ALREADY_RUNNING:
                raise self._translate(exc) from exc

    def stop(self) -> None:
        pywintypes, _, serviceutil = self._modules()
        try:
            serviceutil.StopService(self.name)
        except pywintypes.error as exc:
            if exc.winerror != ERROR_SERVICE_NOT_ACTIVE:
                raise self._translate(exc) from exc

    def set_start(self, automatic: bool) -> None:
        """Automático retrasado (como lo deja el instalador) o manual."""
        pywintypes, service, _ = self._modules()
        try:
            manager = service.OpenSCManager(None, None, service.SC_MANAGER_CONNECT)
            try:
                handle = service.OpenService(manager, self.name, service.SERVICE_CHANGE_CONFIG)
                try:
                    service.ChangeServiceConfig(
                        handle,
                        service.SERVICE_NO_CHANGE,
                        SERVICE_AUTO_START if automatic else SERVICE_DEMAND_START,
                        service.SERVICE_NO_CHANGE,
                        None, None, 0, None, None, None, None,
                    )
                    if automatic:
                        service.ChangeServiceConfig2(handle, service.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, True)
                finally:
                    service.CloseServiceHandle(handle)
            finally:
                service.CloseServiceHandle(manager)
        except pywintypes.error as exc:
            raise self._translate(exc) from exc


STATE_NAMES = {
    SERVICE_STOPPED: "stopped",
    SERVICE_START_PENDING: "starting",
    SERVICE_STOP_PENDING: "stopping",
    SERVICE_RUNNING: "running",
}


class ServiceControl:
    """Iniciar, detener, reiniciar y el arranque con Windows del servicio del agente."""

    dev = False

    def __init__(self, api: Any = None, *, sleep: Callable[[float], None] = time.sleep, wait_seconds: float = 60.0) -> None:
        self.api = api or Win32ServiceApi()
        self._sleep = sleep
        self.wait_seconds = wait_seconds

    def query(self) -> dict[str, str]:
        try:
            state = STATE_NAMES.get(self.api.state(), "unknown")
        except ServiceControlError as exc:
            return {"state": "not_installed" if exc.code == "not_installed" else "unknown", "start_type": "unknown"}
        try:
            start, delayed = self.api.start_type()
            start_type = {SERVICE_AUTO_START: "delayed" if delayed else "auto", SERVICE_DEMAND_START: "manual", SERVICE_DISABLED: "disabled"}.get(
                start, "unknown"
            )
        except ServiceControlError:
            start_type = "unknown"
        return {"state": state, "start_type": start_type}

    def _wait_for(self, wanted: int) -> None:
        deadline = self.wait_seconds
        while deadline > 0:
            if self.api.state() == wanted:
                return
            self._sleep(0.5)
            deadline -= 0.5
        raise ServiceControlError("timeout")

    def start(self) -> None:
        self.api.start()

    def stop(self) -> None:
        self.api.stop()

    def restart(self) -> None:
        self.api.stop()
        self._wait_for(SERVICE_STOPPED)
        self.api.start()

    def set_autostart(self, enabled: bool) -> None:
        self.api.set_start(enabled)


class DevServiceControl:
    """En desarrollo: dice si el canal contesta, y no toca ningún servicio de verdad."""

    dev = True

    def __init__(self, reachable: Callable[[], bool]) -> None:
        self._reachable = reachable

    def query(self) -> dict[str, str]:
        return {"state": "running" if self._reachable() else "stopped", "start_type": "unknown"}

    def _refuse(self, *args: object) -> None:
        raise ServiceControlError("dev")

    start = stop = restart = _refuse

    def set_autostart(self, enabled: bool) -> None:
        raise ServiceControlError("dev")


# --- El icono de bandeja al iniciar sesión --------------------------------------------


class TrayStartup:
    """La entrada del icono en HKLM\\...\\Run y su interruptor, como el del Administrador de tareas.

    Vale para todas las personas del equipo (la deja el instalador para todas),
    así que cambiarla pide administrador. Apagada no se borra: se marca como
    desactivada en ``StartupApproved``, que es lo que respeta el Explorador y
    lo que se ve en Administrador de tareas → Aplicaciones de arranque.
    """

    dev = False

    def __init__(self, registry: Any = None, tray_exe: str | None = None) -> None:
        self._winreg = registry
        self.tray_exe = tray_exe

    @property
    def reg(self) -> Any:
        if self._winreg is None:
            import winreg

            self._winreg = winreg
        return self._winreg

    def _read(self, key: str, name: str) -> Any:
        reg = self.reg
        try:
            with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, key, 0, reg.KEY_READ) as handle:
                return reg.QueryValueEx(handle, name)[0]
        except OSError:
            return None

    def enabled(self) -> bool:
        if not self._read(RUN_KEY, TRAY_RUN_VALUE):
            return False
        approved = self._read(APPROVED_KEY, TRAY_RUN_VALUE)
        if isinstance(approved, (bytes, bytearray)) and approved:
            return approved[0] % 2 == 0  # 02 y 06 activa; 03 y 07 desactivada
        return True

    def set(self, enabled: bool) -> None:
        reg = self.reg
        try:
            if enabled and not self._read(RUN_KEY, TRAY_RUN_VALUE):
                exe = self.tray_exe or str(Path(sys.executable).with_name(TRAY_EXE))
                if not Path(exe).is_file():
                    raise ServiceControlError("failed", exe)
                with reg.CreateKeyEx(reg.HKEY_LOCAL_MACHINE, RUN_KEY, 0, reg.KEY_SET_VALUE) as handle:
                    reg.SetValueEx(handle, TRAY_RUN_VALUE, 0, reg.REG_SZ, f'"{exe}"')
            with reg.CreateKeyEx(reg.HKEY_LOCAL_MACHINE, APPROVED_KEY, 0, reg.KEY_SET_VALUE) as handle:
                reg.SetValueEx(handle, TRAY_RUN_VALUE, 0, reg.REG_BINARY, bytes([2 if enabled else 3]) + bytes(11))
        except PermissionError as exc:
            raise ServiceControlError("forbidden") from exc
        except OSError as exc:
            raise ServiceControlError("failed", str(exc)) from exc


class DevTrayStartup:
    dev = True

    def enabled(self) -> bool:
        return False

    def set(self, enabled: bool) -> None:
        raise ServiceControlError("dev")


def controls_for(dev: bool, reachable: Callable[[], bool]) -> tuple[Any, Any]:
    """Los mandos de Windows que tocan: los de verdad, o los de desarrollo."""
    if dev or sys.platform != "win32":
        return DevServiceControl(reachable), DevTrayStartup()
    return ServiceControl(), TrayStartup()


# --- WebView2, tema, ventana ------------------------------------------------------------


def webview2_version(registry: Any = None) -> str | None:
    """La versión del runtime de WebView2, o `None` si no está instalado."""
    if registry is None:
        if sys.platform != "win32":
            return None
        import winreg as registry
    places = (
        (registry.HKEY_LOCAL_MACHINE, rf"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_CLIENT}"),
        (registry.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_CLIENT}"),
        (registry.HKEY_CURRENT_USER, rf"Software\Microsoft\EdgeUpdate\Clients\{WEBVIEW2_CLIENT}"),
    )
    for root, key in places:
        try:
            with registry.OpenKey(root, key) as handle:
                version = str(registry.QueryValueEx(handle, "pv")[0] or "")
        except OSError:
            continue
        if version and version != "0.0.0.0":
            return version
    return None


def windows_uses_dark() -> bool:
    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as handle:
            return int(winreg.QueryValueEx(handle, "AppsUseLightTheme")[0]) == 0
    except OSError:
        return False


def find_own_window(title: str) -> int | None:
    """La ventana visible de este proceso con ese título (la de pywebview)."""
    if sys.platform != "win32":
        return None
    import win32gui
    import win32process

    found: list[int] = []
    pid = os.getpid()

    def visit(hwnd: int, _: object) -> bool:
        if win32gui.IsWindowVisible(hwnd) and win32gui.GetWindowText(hwnd) == title:
            if win32process.GetWindowThreadProcessId(hwnd)[1] == pid:
                found.append(hwnd)
        return True

    win32gui.EnumWindows(visit, None)
    return found[0] if found else None


def set_dark_title_bar(hwnd: int, dark: bool) -> None:
    """La barra de título oscura cuando Windows está en oscuro (Windows 10 2004+)."""
    try:
        import ctypes

        value = ctypes.c_int(1 if dark else 0)
        # DWMWA_USE_IMMERSIVE_DARK_MODE: 20; antes de 20H1 era 19.
        for attribute in (20, 19):
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)) == 0:
                break
    except (AttributeError, OSError):
        pass


def bring_to_front(hwnd: int) -> None:
    try:
        import win32con
        import win32gui

        if win32gui.IsIconic(hwnd):
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        else:
            win32gui.ShowWindow(hwnd, win32con.SW_SHOW)
        win32gui.SetForegroundWindow(hwnd)
    except Exception:  # noqa: BLE001 - traer al frente es un favor, no una obligación
        pass


def message_box(text: str, title: str = "Cenya Agent", *, error: bool = False, yes_no: bool = False) -> bool:
    """Un mensaje nativo (lo único que queda cuando no hay WebView2). `True` si «Sí»."""
    if sys.platform != "win32":
        print(text, file=sys.stderr)
        return False
    import ctypes

    flags = 0x10 if error else 0x40  # MB_ICONERROR | MB_ICONINFORMATION
    if yes_no:
        flags = 0x04 | 0x20  # MB_YESNO | MB_ICONQUESTION
    flags |= 0x10000  # MB_SETFOREGROUND
    return ctypes.windll.user32.MessageBoxW(None, text, title, flags) == 6  # IDYES


def open_folder(path: str) -> bool:
    if not path or not os.path.isdir(path):
        return False
    try:
        os.startfile(path)  # type: ignore[attr-defined]  # noqa: S606 - una carpeta, en el Explorador
    except (AttributeError, OSError):
        return False
    return True


def show_in_folder(path: str) -> bool:
    """El Explorador abierto en la carpeta del fichero, con el fichero marcado."""
    if not path or not os.path.isfile(path):
        return open_folder(os.path.dirname(path))
    try:
        subprocess.Popen(["explorer.exe", "/select,", os.path.normpath(path)])  # noqa: S603, S607
    except OSError:
        return False
    return True


def open_url(url: str) -> bool:
    from agent.app.view import safe_url

    if not safe_url(url):
        return False
    import webbrowser

    return bool(webbrowser.open(url))


def copy_to_clipboard(text: str) -> bool:
    if sys.platform != "win32":
        return False
    try:
        import win32clipboard
        import win32con

        win32clipboard.OpenClipboard()
        try:
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardText(text, win32con.CF_UNICODETEXT)
        finally:
            win32clipboard.CloseClipboard()
    except Exception:  # noqa: BLE001
        return False
    return True


# --- Una sola ventana --------------------------------------------------------------------


class SingleInstance:
    """Una sola ventana por sesión, elevada o no.

    Un *mutex* con nombre dice si ya hay una; un evento con nombre le pide a la
    que hay que se traiga al frente. Los dos con una DACL explícita (la cuenta
    de la sesión, SYSTEM y Administradores) y etiqueta de integridad baja, para
    que una ventana sin elevar pueda avisar a una elevada y al revés: sin eso,
    lo que crea un proceso elevado no lo puede abrir uno normal.
    """

    def __init__(self, mutex_name: str = MUTEX_NAME, event_name: str = SHOW_EVENT_NAME) -> None:
        self.mutex_name = mutex_name
        self.event_name = event_name
        self._mutex: Any = None
        self._event: Any = None
        self._stop = threading.Event()

    @staticmethod
    def _attributes() -> Any:
        import pywintypes
        import win32api
        import win32security

        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
        sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
        sddl = f"D:(A;;GA;;;{sid})(A;;GA;;;SY)(A;;GA;;;BA)S:(ML;;NW;;;LW)"
        attributes = pywintypes.SECURITY_ATTRIBUTES()
        attributes.SECURITY_DESCRIPTOR = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
            sddl, win32security.SDDL_REVISION_1
        )
        return attributes

    def acquire(self, wait_seconds: float = 0.0) -> bool:
        """`True` si esta es la única ventana. Espera un poco a que se vaya la anterior."""
        if sys.platform != "win32":
            return True
        import win32api
        import win32event
        import winerror

        deadline = time.monotonic() + wait_seconds
        attributes = self._attributes()
        while True:
            mutex = win32event.CreateMutex(attributes, False, self.mutex_name)
            if win32api.GetLastError() != winerror.ERROR_ALREADY_EXISTS:
                self._mutex = mutex
                self._event = win32event.CreateEvent(attributes, False, False, self.event_name)
                return True
            win32api.CloseHandle(mutex)
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.2)

    def release(self) -> None:
        self._stop.set()
        if sys.platform != "win32":
            return
        import win32api

        for handle in (self._event, self._mutex):
            if handle is not None:
                try:
                    win32api.CloseHandle(handle)
                except Exception:  # noqa: BLE001
                    pass
        self._event = self._mutex = None

    def signal_existing(self) -> bool:
        """Le pide a la ventana que ya hay que se enseñe. `True` si se pudo avisar."""
        if sys.platform != "win32":
            return False
        import ctypes

        import pywintypes
        import win32event

        try:
            ctypes.windll.user32.AllowSetForegroundWindow(-1)  # ASFW_ANY
        except (AttributeError, OSError):
            pass
        try:
            event = win32event.OpenEvent(win32event.EVENT_MODIFY_STATE, False, self.event_name)
        except pywintypes.error:
            return False
        win32event.SetEvent(event)
        return True

    def watch(self, on_show: Callable[[], None]) -> None:
        """Llama a `on_show` cada vez que otra copia pide enseñar la ventana."""
        if sys.platform != "win32" or self._event is None:
            return
        import win32event

        def loop() -> None:
            while not self._stop.is_set():
                event = self._event
                if event is None:
                    return
                if win32event.WaitForSingleObject(event, 500) == win32event.WAIT_OBJECT_0:
                    try:
                        on_show()
                    except Exception:  # noqa: BLE001
                        pass

        threading.Thread(target=loop, name="show-requests", daemon=True).start()
