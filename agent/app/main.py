"""`cenya-agent-app`: the Cenya Agent window.

**Process model.** The window is its own process, separate from the tray
icon, and there is never more than one of each per Windows session:

* the tray icon (`agent.tray`) is small, starts at sign-in and stays; a left
  click starts this program;
* this program shows the window and ends when the window is closed. A second
  start does not open a second window: it asks the first one (a named event)
  to come to the front and exits.

Why two processes and not the tray hosting the window: elevation. Acting needs
an elevated administrator, and Windows elevates a *process*, not a window. With
one process, "restart as administrator" would either leave the old icon behind
next to a new one or take the icon away from the unelevated session; with two,
only the window restarts elevated and the icon never moves. It also keeps
WebView2 (a browser engine, a hundred megabytes) out of memory for the whole
day on every session of a terminal server, and a crash of the window cannot
take the icon with it.

**No socket, ever.** The page is handed to WebView2 as a string (``html=``),
with its stylesheet and scripts inlined, and talks to Python through
pywebview's JS bridge. pywebview only starts its local HTTP server (bottle) for
``url=`` pointing at a local file or with ``http_server=True``; neither is
used, and `assert_no_server` checks it once the window is up.
"""

from __future__ import annotations

import argparse
import os
import sys
import threading
from pathlib import Path
from typing import Any

from agent.app import bridge, channel, winsys
from agent.i18n import _t

UI_DIR = Path(__file__).resolve().parent / "ui"
TITLE = "Cenya Agent"
#: Sin red, sin nada de fuera: lo que la página puede cargar es lo que lleva dentro.
CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
    "img-src data:; font-src 'none'; connect-src 'none'; form-action 'none'; base-uri 'none'"
)
SECTIONS = ("status", "activity", "netbox", "tools", "connection", "settings", "about")
#: El identificador con el que Windows agrupa la ventana en la barra de tareas.
APP_USER_MODEL_ID = "Cenya.Agent.App"


def build_page() -> str:
    """La página entera en una cadena: HTML con su CSS y su JS dentro."""
    html = (UI_DIR / "index.html").read_text(encoding="utf-8")
    css = (UI_DIR / "app.css").read_text(encoding="utf-8")
    scripts = {name: (UI_DIR / name).read_text(encoding="utf-8") for name in ("icons.js", "app.js")}
    html = html.replace("<!--CSP-->", f'<meta http-equiv="Content-Security-Policy" content="{CSP}">')
    html = html.replace('<link rel="stylesheet" href="app.css">', f"<style>\n{css}\n</style>")
    for name, code in scripts.items():
        # `</` dentro de un <script> en línea lo cerraría antes de tiempo.
        html = html.replace(f'<script src="{name}"></script>', "<script>\n" + code.replace("</", "<\\/") + "\n</script>")
    return html


def window_options(page: str, api: Any, dark: bool) -> dict[str, Any]:
    """Los argumentos de `webview.create_window`: sin `url`, nunca con servidor."""
    return {
        "title": TITLE,
        "html": page,
        "url": None,
        "js_api": api,
        "width": 1120,
        "height": 740,
        "min_size": (880, 600),
        "background_color": "#0A0B0D" if dark else "#F7F8F9",
        "text_select": True,
    }


START_OPTIONS: dict[str, Any] = {"gui": "edgechromium", "http_server": False, "private_mode": True}


def assert_no_server() -> None:
    """Para la ventana si pywebview hubiera levantado su servidor HTTP local."""
    from webview import http

    if getattr(http, "global_server", None) is not None:
        raise RuntimeError("pywebview started a local HTTP server; the window must not listen on anything")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="cenya-agent-app", add_help=True)
    parser.add_argument("--section", choices=SECTIONS, default=None)
    parser.add_argument("--pipe", default="", help=argparse.SUPPRESS)
    parser.add_argument("--elevated", action="store_true", help=argparse.SUPPRESS)
    # Solo con un canal de desarrollo: ver la ventana como la vería un administrador.
    parser.add_argument("--assume-admin", action="store_true", help=argparse.SUPPRESS)
    options, _ = parser.parse_known_args(argv)
    return options


def _webview2_missing_text() -> str:
    return _t(
        "Cenya Agent necesita el componente WebView2 de Microsoft para enseñar su ventana, y no está instalado en este equipo.\n\n"
        "Se descarga gratis en https://developer.microsoft.com/microsoft-edge/webview2/ (el «Evergreen Bootstrapper»).\n\n"
        "El agente sigue funcionando: esto solo afecta a la ventana."
    )


def main(argv: list[str] | None = None) -> int:
    options = parse_args(list(sys.argv[1:] if argv is None else argv))
    if options.pipe and sys.platform == "win32" and not options.pipe.startswith(channel.PIPE_PREFIX):
        options.pipe = channel.PIPE_PREFIX + options.pipe
    address = options.pipe or channel.default_address()
    dev = bool(options.pipe or channel.address_overridden()) and not channel.is_default_address(address)

    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
        except (AttributeError, OSError):
            pass

    instance = winsys.SingleInstance()
    if not instance.acquire(wait_seconds=10.0 if options.elevated else 0.0):
        instance.signal_existing()
        return 0
    try:
        try:
            import webview
        except ImportError:
            winsys.message_box(_t("Falta pywebview: instala el agente con el extra [gui]."), error=True)
            return 2
        if sys.platform == "win32" and winsys.webview2_version() is None:
            winsys.message_box(_webview2_missing_text(), error=True)
            return 3

        elevated = winsys.is_elevated() or (dev and options.assume_admin)
        client = channel.ChannelClient(address)
        state: dict[str, Any] = {"window": None, "hwnd": None, "dark": None}

        def relaunch(section: str) -> bool:
            args = ["--elevated"]
            if section in SECTIONS:
                args += ["--section", section]
            if dev:
                args += ["--pipe", address]
            instance.release()
            if winsys.relaunch_elevated(args):
                window = state["window"]
                if window is not None:
                    threading.Timer(0.2, window.destroy).start()
                return True
            instance.acquire()
            instance.watch(show)
            return False

        api = bridge.Api(client, elevated=elevated, dev=dev, relaunch=relaunch, initial_section=options.section or "")
        dark = winsys.windows_uses_dark()
        window = webview.create_window(**window_options(build_page(), api, dark))
        state["window"] = window
        api._dialogs.window = window

        def show() -> None:
            hwnd = state["hwnd"] or winsys.find_own_window(TITLE)
            if hwnd:
                winsys.bring_to_front(hwnd)

        def follow_theme() -> None:
            # La barra de título no sigue sola al tema de Windows: se mira cada poco.
            stop = threading.Event()
            window.events.closed += stop.set
            while not stop.wait(3.0):
                hwnd = state["hwnd"]
                current = winsys.windows_uses_dark()
                if hwnd and current != state["dark"]:
                    winsys.set_dark_title_bar(hwnd, current)
                    state["dark"] = current

        def on_shown() -> None:
            assert_no_server()
            hwnd = winsys.find_own_window(TITLE)
            state["hwnd"] = hwnd
            if hwnd:
                state["dark"] = winsys.windows_uses_dark()
                winsys.set_dark_title_bar(hwnd, state["dark"])
            threading.Thread(target=follow_theme, name="theme", daemon=True).start()

        window.events.shown += on_shown
        instance.watch(show)
        webview.start(debug=bool(os.environ.get("CENYA_APP_DEBUG")), **START_OPTIONS)
        client.close()
        return 0
    finally:
        instance.release()


if __name__ == "__main__":
    sys.exit(main())
