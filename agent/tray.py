"""The tray icon: whether the agent on this machine is working, at a glance.

A small process of its own, started when a user signs in. It never talks to
the server and never touches the service: it reads the status file the agent
writes (`agent/status.py`) and asks Windows whether the service is running,
every few seconds, and says what it sees -- green, orange or grey, with a
tooltip, a status window on click and a notification when things go wrong.

Closing the icon closes the icon, not the agent: they are separate processes
on purpose, and the service keeps sweeping with nobody signed in.

Everything that decides *what* to say lives in `agent/status.py`, as pure
functions with tests. This module is only the Win32 plumbing (pywin32, BSD in
the parts used; no `pystray`, which is LGPL), checked by hand on a Windows
desktop -- there is no desktop to test it on in CI.
"""

from __future__ import annotations

import ctypes
import time
import webbrowser
from datetime import datetime, timezone

import pywintypes
import win32api
import win32con
import win32event
import win32gui
import win32service
import win32serviceutil
import winerror

from agent import __version__, icons, status
from agent.i18n import _t

#: El nombre del servicio (`agent.winservice.SERVICE_NAME`). Repetido y no
#: importado: importar winservice cargaría el bucle entero del agente en un
#: icono que solo lee un fichero. Un test vigila que no se desincronicen.
SERVICE_NAME = "CenyaAgent"

POLL_MS = 5000
WM_TRAY = win32con.WM_USER + 20
ICON_ID = 1
CMD_STATUS, CMD_SETTINGS, CMD_CLOSE = 1001, 1002, 1003
#: Uno por sesión: abrirlo dos veces no debe dejar dos iconos.
MUTEX_NAME = "Local\\CenyaAgentTray"
#: Versión del formato de icono que espera `CreateIconFromResource` (Win32).
ICON_RESOURCE_VERSION = 0x00030000


def query_service() -> str | None:
    """Lo que dice Windows del servicio, o `None` si no se pudo preguntar."""
    try:
        state = win32serviceutil.QueryServiceStatus(SERVICE_NAME)[1]
    except pywintypes.error as exc:
        if exc.winerror == winerror.ERROR_SERVICE_DOES_NOT_EXIST:
            return status.SERVICE_NOT_INSTALLED
        return None
    if state == win32service.SERVICE_STOPPED:
        return status.SERVICE_STOPPED
    return status.SERVICE_RUNNING


class TrayApp:
    def __init__(self) -> None:
        self._hicons: dict[str, int] = {}
        self._shown: tuple[str, str] | None = None
        self._tone: str | None = None
        self._health = status.describe(None, datetime.now(timezone.utc))
        self._data: dict | None = None
        self._busy = False

        instance = win32api.GetModuleHandle(None)
        # Se reciben aparte porque su número lo da Windows al registrarlo: es
        # el aviso de que el Explorador se reinició y la bandeja está vacía.
        self._taskbar_created = win32gui.RegisterWindowMessage("TaskbarCreated")
        window_class = win32gui.WNDCLASS()
        window_class.hInstance = instance
        window_class.lpszClassName = "CenyaAgentTray"
        window_class.lpfnWndProc = {
            WM_TRAY: self._on_tray,
            self._taskbar_created: self._on_taskbar_created,
            win32con.WM_DESTROY: self._on_destroy,
        }
        atom = win32gui.RegisterClass(window_class)
        # Una ventana normal que nunca se enseña, no una de solo mensajes: a
        # esas no les llegan los avisos a todas las ventanas, y «TaskbarCreated»
        # es uno de ellos.
        self._hwnd = win32gui.CreateWindow(
            atom, "Cenya Agent", win32con.WS_OVERLAPPED, 0, 0, 0, 0, 0, 0, instance, None
        )
        self._icon_size = win32api.GetSystemMetrics(win32con.SM_CXSMICON)
        self._poll()
        self._add_icon()
        # Si al iniciar sesión ya iba mal, es justo cuando conviene decirlo.
        if status.should_notify(None, self._health.tone):
            self._balloon()

    # --- El icono --------------------------------------------------------------

    def _hicon(self, tone: str) -> int:
        if tone not in self._hicons:
            resource = icons.icon_resource(self._icon_size, tone)
            self._hicons[tone] = win32gui.CreateIconFromResource(resource, True, ICON_RESOURCE_VERSION)
        return self._hicons[tone]

    def _notify_data(self, flags: int) -> tuple:
        return (
            self._hwnd,
            ICON_ID,
            flags,
            WM_TRAY,
            self._hicon(self._health.tone),
            status.tooltip(self._health),
        )

    def _add_icon(self) -> None:
        flags = win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP
        win32gui.Shell_NotifyIcon(win32gui.NIM_ADD, self._notify_data(flags))
        self._shown = (self._health.tone, status.tooltip(self._health))

    def _refresh_icon(self) -> None:
        wanted = (self._health.tone, status.tooltip(self._health))
        if wanted == self._shown:
            return
        flags = win32gui.NIF_ICON | win32gui.NIF_TIP
        try:
            win32gui.Shell_NotifyIcon(win32gui.NIM_MODIFY, self._notify_data(flags))
            self._shown = wanted
        except pywintypes.error:
            pass  # la bandeja no está (el Explorador arrancando): TaskbarCreated lo repondrá

    def _balloon(self) -> None:
        details = self._health.details[0] if self._health.details else ""
        data = (
            *self._notify_data(win32gui.NIF_INFO),
            details[:255],
            10_000,
            self._health.headline[:63],
            win32gui.NIIF_WARNING,
        )
        try:
            win32gui.Shell_NotifyIcon(win32gui.NIM_MODIFY, data)
        except pywintypes.error:
            pass

    # --- Mirar -----------------------------------------------------------------

    def _poll(self) -> None:
        self._data = status.read()
        self._health = status.describe(self._data, datetime.now(timezone.utc), query_service())
        if self._shown is not None:
            self._refresh_icon()
            if status.should_notify(self._tone, self._health.tone):
                self._balloon()
        self._tone = self._health.tone

    # --- Lo que pide la persona ------------------------------------------------

    def _on_tray(self, hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        if self._busy:
            return 0
        if lparam == win32con.WM_LBUTTONUP:
            self._show_status()
        elif lparam == win32con.WM_RBUTTONUP:
            self._show_menu()
        return 0

    def _show_status(self) -> None:
        self._busy = True
        try:
            self._poll()
            lines = [self._health.headline, "", *self._health.details]
            footer = _t("Versión del agente: %(version)s") % {"version": (self._data or {}).get("version") or __version__}
            url = status.settings_url(self._data)
            if url:
                footer += "\n" + _t("Servidor: %(url)s") % {"url": url.removesuffix("/settings/agents/")}
            icon = win32con.MB_ICONWARNING if self._health.tone == status.WARNING else win32con.MB_ICONINFORMATION
            win32gui.MessageBox(
                self._hwnd,
                "\n".join(lines) + "\n\n" + footer,
                "Cenya Agent",
                win32con.MB_OK | icon | win32con.MB_SETFOREGROUND,
            )
        finally:
            self._busy = False

    def _show_menu(self) -> None:
        url = status.settings_url(self._data)
        menu = win32gui.CreatePopupMenu()
        win32gui.AppendMenu(menu, win32con.MF_STRING, CMD_STATUS, _t("Ver estado"))
        win32gui.SetMenuDefaultItem(menu, CMD_STATUS, False)
        settings_flags = win32con.MF_STRING | (0 if url else win32con.MF_GRAYED)
        win32gui.AppendMenu(menu, settings_flags, CMD_SETTINGS, _t("Abrir Ajustes → Agentes"))
        win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, "")
        # «Cerrar este icono» y no «Salir»: salir sonaría a parar el agente, y
        # el servicio sigue barriendo aunque nadie mire.
        win32gui.AppendMenu(menu, win32con.MF_STRING, CMD_CLOSE, _t("Cerrar este icono"))
        x, y = win32gui.GetCursorPos()
        # Sin traer la ventana al frente, el menú no se cierra al pulsar fuera
        # (comportamiento documentado de TrackPopupMenu).
        win32gui.SetForegroundWindow(self._hwnd)
        command = win32gui.TrackPopupMenu(
            menu,
            win32con.TPM_RIGHTBUTTON | win32con.TPM_RETURNCMD | win32con.TPM_NONOTIFY,
            x,
            y,
            0,
            self._hwnd,
            None,
        )
        win32gui.PostMessage(self._hwnd, win32con.WM_NULL, 0, 0)
        win32gui.DestroyMenu(menu)
        if command == CMD_STATUS:
            self._show_status()
        elif command == CMD_SETTINGS and url:
            webbrowser.open(url)
        elif command == CMD_CLOSE:
            win32gui.DestroyWindow(self._hwnd)

    # --- Ciclo de vida ---------------------------------------------------------

    def _on_taskbar_created(self, hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        self._add_icon()
        return 0

    def _on_destroy(self, hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        try:
            win32gui.Shell_NotifyIcon(win32gui.NIM_DELETE, (self._hwnd, ICON_ID))
        except pywintypes.error:
            pass
        for hicon in self._hicons.values():
            win32gui.DestroyIcon(hicon)
        win32gui.PostQuitMessage(0)
        return 0

    def run(self) -> None:
        """Mensajes de Windows, y cada `POLL_MS` una mirada al estado.

        Un solo hilo: esperar mensajes con tope de tiempo en vez de un
        temporizador aparte, que es lo que no trae pywin32 y lo que obligaría a
        tocar la bandeja desde dos hilos.
        """
        next_poll = time.monotonic() + POLL_MS / 1000
        while True:
            timeout = max(0, int((next_poll - time.monotonic()) * 1000))
            result = win32event.MsgWaitForMultipleObjects([], False, timeout, win32event.QS_ALLINPUT)
            if result == win32event.WAIT_TIMEOUT:
                self._poll()
                next_poll = time.monotonic() + POLL_MS / 1000
                continue
            if win32gui.PumpWaitingMessages():
                return  # WM_QUIT


def main() -> None:
    mutex = win32event.CreateMutex(None, False, MUTEX_NAME)
    if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
        return  # ya hay un icono en esta sesión
    try:
        try:
            # Nítido a 125 %, 150 %, 200 %: sin esto Windows escala un icono de
            # 16 px y lo emborrona.
            ctypes.windll.user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass
        TrayApp().run()
    except Exception as exc:  # noqa: BLE001 - sin consola, un fallo al arrancar sería invisible
        win32gui.MessageBox(
            0,
            _t("El icono de Cenya Agent no ha podido arrancar:\n%(error)s") % {"error": exc},
            "Cenya Agent",
            win32con.MB_OK | win32con.MB_ICONERROR,
        )
        raise SystemExit(1) from exc
    finally:
        win32api.CloseHandle(mutex)


if __name__ == "__main__":
    main()
