"""The object the page calls: ``window.pywebview.api.<method>(...)``.

pywebview runs each call on a worker thread and hands the return value to the
page as JSON. Every public method here returns ``{"ok": true, ...}`` or
``{"ok": false, "error": <code>, "message": <text for a person>}`` and never
raises: a failure is something to show, not a stack trace in a console nobody
has. Only public methods are reachable from the page; everything else is
underscored on purpose (pywebview also exposes public attributes).

What it decides is delegated to `agent.app.view`; what it does goes through
the channel (`agent.app.channel`) or, for the few things that are Windows'
own, `agent.app.winsys`.

**Secrets.** The NetBox token arrives as an argument, goes into one request
and is dropped: it is not kept on this object, not logged, not echoed back.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from agent import __version__, i18n
from agent.app import channel, strings, view, winsys

REPO_URL = "https://github.com/cenya-io/cenya-agent"
#: «Qué hace el agente con tus datos» (CLAUDE.md, regla 7): pendiente de
#: escribir junto al README del repositorio público. Si cambia de nombre al
#: escribirse, cambia aquí.
DATA_DOC_URL = REPO_URL + "/blob/main/agent/QUE-HACE-CON-TUS-DATOS.md"
NETBOX_PROBE_PATH = "/api/dcim/sites/?limit=1"


def _ok(**data: Any) -> dict[str, Any]:
    return {"ok": True, **data}


def _fail(code: str, message: str) -> dict[str, Any]:
    return {"ok": False, "error": code, "message": message}


class Dialogs:
    """Los diálogos de fichero de Windows, a través de la ventana de pywebview."""

    def __init__(self) -> None:
        self.window: Any = None

    def save(self, filename: str, file_types: tuple[str, ...]) -> str | None:
        import webview

        if self.window is None:
            return None
        result = self.window.create_file_dialog(webview.FileDialog.SAVE, save_filename=filename, file_types=file_types)
        if isinstance(result, (list, tuple)):
            result = result[0] if result else None
        return str(result) if result else None

    def open(self, file_types: tuple[str, ...]) -> str | None:
        import webview

        if self.window is None:
            return None
        result = self.window.create_file_dialog(webview.FileDialog.OPEN, allow_multiple=False, file_types=file_types)
        if isinstance(result, (list, tuple)):
            result = result[0] if result else None
        return str(result) if result else None


class Api:
    def __init__(
        self,
        client: channel.ChannelClient,
        *,
        elevated: bool,
        dev: bool,
        service: Any = None,
        tray_startup: Any = None,
        dialogs: Any = None,
        clock: Callable[[], datetime] | None = None,
        relaunch: Callable[[str], bool] | None = None,
        opener: Callable[[str], bool] | None = None,
        initial_section: str = "",
        enrollment_present: Callable[[], bool | None] | None = None,
        enroll: Callable[[str], tuple[bool, str]] | None = None,
    ) -> None:
        self._client = client
        self._enrollment_present = enrollment_present or (lambda: winsys.enrollment_present(dev))
        self._enroll = enroll or winsys.enroll_with_cli
        self._elevated = elevated
        self._dev = dev
        if service is None or tray_startup is None:
            default_service, default_tray = winsys.controls_for(dev, self._reachable)
            service = service or default_service
            tray_startup = tray_startup or default_tray
        self._service = service
        self._tray = tray_startup
        self._dialogs = dialogs or Dialogs()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._relaunch = relaunch
        self._open = opener or winsys.open_url
        self._initial_section = initial_section
        self._lock = threading.Lock()
        self._forbidden = False
        #: Lo que dice el servicio de quien llama (`may_act` de `status`); `None`, no lo ha dicho.
        self._may_act: bool | None = None
        self._log_n = 0
        self._status: dict[str, Any] | None = None
        self._about: dict[str, Any] | None = None
        self._update_check: dict[str, Any] | None = None
        self._netbox: dict[str, Any] = {"state": "idle"}
        self._original_language = os.environ.get(i18n.LANGUAGE_ENV_VAR)
        self._language = ""
        self._shown_once = False

    # --- Fontanería ---------------------------------------------------------

    def _reachable(self) -> bool:
        try:
            self._client.request("status", timeout=2.0)
        except channel.ChannelError:
            return False
        return True

    def _call(self, op: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            return self._client.request(op, args)
        except channel.ChannelError as exc:
            if exc.code == channel.FORBIDDEN:
                self._forbidden = True
            raise

    def _fetch_status(self, quiet: bool = False) -> dict[str, Any]:
        """`status`, en la forma de las vistas, y lo que dice de los permisos."""
        raw = self._client.request("status") if quiet else self._call("status")
        status = view.normalize_status(raw)
        self._status = status
        if isinstance(status.get("may_act"), bool):
            self._may_act = status["may_act"]
        return status

    @staticmethod
    def _error(exc: channel.ChannelError) -> dict[str, Any]:
        if exc.code == channel.INVALID and exc.details:
            return _fail(exc.code, view.settings_error(exc.message, exc.details))
        return _fail(exc.code, view.error_message(exc.code, exc.message))

    def _perms(self) -> dict[str, Any]:
        return view.permissions(self._elevated, self._forbidden, self._may_act)

    def _refuse_if_readonly(self) -> dict[str, Any] | None:
        perms = self._perms()
        if perms["can_act"]:
            return None
        return _fail(channel.FORBIDDEN, perms["why"])

    def _now(self) -> datetime:
        return self._clock()

    def _apply_language(self, code: str) -> None:
        self._language = code
        if code:
            os.environ[i18n.LANGUAGE_ENV_VAR] = code
        elif self._original_language is None:
            os.environ.pop(i18n.LANGUAGE_ENV_VAR, None)
        else:
            os.environ[i18n.LANGUAGE_ENV_VAR] = self._original_language
        i18n._translation.cache_clear()

    # --- Arranque y armazón -------------------------------------------------

    def init(self) -> dict[str, Any]:
        """Lo que la página necesita para pintarse: textos, versión, permisos."""
        if not self._shown_once:
            self._shown_once = True
            try:
                settings = self._client.request("settings.get")
                language = str(settings.get("language") or "")
                if language:
                    self._apply_language(language)
            except channel.ChannelError:
                pass
        return _ok(
            strings=strings.ui_strings(),
            version=__version__,
            dev=self._dev,
            elevated=self._elevated,
            section=self._initial_section,
            filters=view.log_filters(),
        )

    def shell(self) -> dict[str, Any]:
        """La cara de la ventana entera; la página lo pregunta cada pocos segundos."""
        error_code = None
        status = None
        try:
            status = self._fetch_status(quiet=True)
        except channel.ChannelError as exc:
            error_code = exc.code
        service_state = "unknown"
        on_disk: bool | None = None
        if error_code is not None:
            service_state = self._service.query().get("state", "unknown")
            if error_code == channel.SERVICE_DOWN:
                on_disk = self._enrollment_present()
        return _ok(
            view=view.shell_view(
                status,
                error_code,
                service_state,
                elevated=self._elevated,
                forbidden_seen=self._forbidden,
                dev=self._dev,
                now=self._now(),
                enrolled_on_disk=on_disk,
            )
        )

    def relaunch_elevated(self, section: str = "") -> dict[str, Any]:
        if self._relaunch is None:
            return _fail("unsupported", view.error_message("unsupported"))
        if not self._relaunch(str(section or "")):
            return _fail("cancelled", "")
        return _ok()

    def open_link(self, kind: str) -> dict[str, Any]:
        targets = {"repo": REPO_URL, "data_doc": DATA_DOC_URL}
        if kind == "portal":
            url = view.safe_url(str((self._status or {}).get("portal") or ""))
        elif kind == "review":
            url = str(self._netbox.get("review_url") or "")
        else:
            url = targets.get(kind, "")
        if not url or not self._open(url):
            return _fail("no_url", "")
        return _ok()

    # --- Estado ---------------------------------------------------------------

    def status(self) -> dict[str, Any]:
        try:
            data = self._fetch_status()
        except channel.ChannelError as exc:
            return self._error(exc)
        return _ok(view=view.status_view(data, self._now(), self._perms()))

    def run_task(self, task: str) -> dict[str, Any]:
        refused = self._refuse_if_readonly()
        if refused:
            return refused
        try:
            self._call("run", {"task": str(task)})
        except channel.ChannelError as exc:
            return self._error(exc)
        return self.status()

    def pause(self, option: str) -> dict[str, Any]:
        refused = self._refuse_if_readonly()
        if refused:
            return refused
        chosen = next((o for o in view.pause_options(self._now()) if o["id"] == option), None)
        if chosen is None:
            return _fail("bad_option", "")
        try:
            self._call("pause", chosen["args"])
        except channel.ChannelError as exc:
            return self._error(exc)
        return self.status()

    def resume(self) -> dict[str, Any]:
        refused = self._refuse_if_readonly()
        if refused:
            return refused
        try:
            self._call("resume")
        except channel.ChannelError as exc:
            return self._error(exc)
        return self.status()

    # --- Actividad --------------------------------------------------------------

    def log(self, after: str = "") -> dict[str, Any]:
        """El registro: las últimas líneas, o las nuevas desde `after` (el cursor opaco del servicio)."""
        after = str(after or "")
        args: dict[str, Any] = {"lines": 500 if not after else 2000}
        if after:
            args["after"] = after
        else:
            self._log_n = 0
        try:
            data = self._call("log", args)
        except channel.ChannelError as exc:
            return self._error(exc)
        result = view.log_view(data, after, self._log_n)
        self._log_n += len(result["rows"])
        return _ok(view=result)

    def open_log_folder(self) -> dict[str, Any]:
        folder = str((self._status or {}).get("log_folder") or "")
        if not folder and not self._dev:
            from agent import logs

            folder = str(logs.path().parent)
        if not winsys.open_folder(folder):
            return _fail("no_folder", "")
        return _ok()

    def copy_text(self, text: str) -> dict[str, Any]:
        return _ok() if winsys.copy_to_clipboard(str(text)) else _fail("clipboard", "")

    # --- Importar de NetBox -------------------------------------------------------

    def netbox_test(self, url: str, token: str, insecure: bool) -> dict[str, Any]:
        """Prueba la dirección y el token desde esta máquina, sin el servicio.

        Solo lee una página (`/api/dcim/sites/?limit=1`). El token no sale de
        esta función más que en esa cabecera.
        """
        problem = view.netbox_form_error(url, token)
        if problem:
            return _fail("invalid", problem)
        from agent import netbox_export

        base = url.strip().rstrip("/")
        try:
            netbox_export._get_page(netbox_export._client(not insecure), base + NETBOX_PROBE_PATH, token.strip())
        except netbox_export.ExportError as exc:
            return _fail("netbox", str(exc))
        except Exception as exc:  # noqa: BLE001 - lo que sea, dicho sin el token
            return _fail("netbox", type(exc).__name__)
        finally:
            token = ""  # noqa: F841 - que no quede en este marco más de lo justo
        return _ok(message=strings.ui_strings()["nb_test_ok"])

    def netbox_choose_file(self) -> dict[str, Any]:
        path = self._dialogs.save("netbox-export.json", ("JSON (*.json)",))
        return _ok(path=path or "")

    def netbox_start(self, url: str, token: str, insecure: bool, mode: str, path: str = "") -> dict[str, Any]:
        refused = self._refuse_if_readonly()
        if refused:
            return refused
        problem = view.netbox_form_error(url, token)
        if problem:
            return _fail("invalid", problem)
        if mode == "save" and not path:
            return _fail("invalid", "")
        with self._lock:
            if self._netbox.get("state") == "running":
                return _fail("busy", view.error_message(channel.BUSY))
            self._netbox = {"state": "running", "mode": mode, "seen": [], "portal": str((self._status or {}).get("portal") or "")}
        args: dict[str, Any] = {"url": url.strip(), "token": token.strip(), "verify_tls": not insecure, "send": mode == "send"}
        if mode == "save":
            args["path"] = path
        token = ""
        threading.Thread(target=self._netbox_run, args=(args,), name="netbox-export", daemon=True).start()
        return _ok()

    def _netbox_run(self, args: dict[str, Any]) -> None:
        mode = "send" if args.get("send") else "save"
        try:
            data = self._call("netbox.export", args)
        except channel.ChannelError as exc:
            result = {"state": "error", "message": view.error_message(exc.code, exc.message)}
        else:
            summary = view.netbox_summary(data, mode, self._netbox.get("portal", ""))
            result = {"state": "done", "summary": summary, "review_url": summary["review_url"], "path": summary["path"]}
            if summary["review_url"]:
                self._open(summary["review_url"])
        finally:
            args.clear()  # el token, fuera
        with self._lock:
            self._netbox.update(result)

    def netbox_poll(self) -> dict[str, Any]:
        with self._lock:
            state = dict(self._netbox)
        activity = None
        if state.get("state") == "running":
            try:
                status = self._fetch_status(quiet=True)
                activity = status.get("activity")
            except channel.ChannelError:
                activity = None
        progress = view.netbox_progress(activity, state.get("seen", []))
        with self._lock:
            if self._netbox.get("state") == "running":
                self._netbox["seen"] = progress["seen"]
        if state.get("state") == "done":
            progress["rows"] = [{**row, "state": "done"} for row in progress["rows"]]
            progress["percent"] = 100
        return _ok(
            state=state.get("state", "idle"),
            mode=state.get("mode", ""),
            progress=progress,
            summary=state.get("summary"),
            message=state.get("message", ""),
        )

    def netbox_reset(self) -> dict[str, Any]:
        with self._lock:
            if self._netbox.get("state") != "running":
                self._netbox = {"state": "idle"}
        return _ok()

    def show_file(self, path: str) -> dict[str, Any]:
        return _ok() if winsys.show_in_folder(str(path)) else _fail("no_file", "")

    # --- Herramientas ------------------------------------------------------------------

    def probe(self, ip: str) -> dict[str, Any]:
        refused = self._refuse_if_readonly()
        if refused:
            return refused
        checked = view.validate_exclusion(str(ip), [])
        if not checked["ok"] or checked["kind"] != "address":
            return _fail("invalid", view.error_message("invalid_ip", _invalid_ip()))
        try:
            report = self._call("probe", {"ip": checked["value"]})
        except channel.ChannelError as exc:
            return self._error(exc)
        return _ok(view=view.probe_view(report))

    def test_connection(self) -> dict[str, Any]:
        refused = self._refuse_if_readonly()
        if refused:
            return refused
        try:
            data = self._call("test_connection")
        except channel.ChannelError as exc:
            return self._error(exc)
        return _ok(view=view.connection_test_view(data))

    def selftest(self) -> dict[str, Any]:
        """La autocomprobación de esta instalación (la misma carpeta que el servicio)."""
        from agent import selftest

        try:
            report = selftest.report()
            complete = selftest.complete(report)
        except Exception as exc:  # noqa: BLE001
            return _fail("selftest", type(exc).__name__)
        return _ok(view=view.selftest_view(report, complete))

    def support_bundle(self) -> dict[str, Any]:
        refused = self._refuse_if_readonly()
        if refused:
            return refused
        stamp = self._now().astimezone().strftime("%Y%m%d-%H%M")
        path = self._dialogs.save(f"cenya-agent-soporte-{stamp}.zip", ("Zip (*.zip)",))
        if not path:
            return _fail("cancelled", "")
        try:
            data = self._call("support_bundle", {"path": path})
        except channel.ChannelError as exc:
            return self._error(exc)
        saved = str(data.get("path") or path)
        return _ok(path=saved, message=_saved_in(saved))

    # --- Conexión ------------------------------------------------------------------------

    def connection(self) -> dict[str, Any]:
        try:
            status = self._fetch_status()
            settings = self._call("settings.get")
        except channel.ChannelError as exc:
            return self._error(exc)
        portal = str(status.get("portal") or "")
        return _ok(
            view={
                "enrolled": status.get("enrolled") is not False,
                "portal": portal,
                "portal_url": view.safe_url(portal),
                "agent_name": str(status.get("agent_name") or ""),
                "ca_bundle": str(settings.get("ca_bundle") or ""),
                "proxy": view.proxy_view(settings),
                "can_act": self._perms()["can_act"],
                "why": self._perms()["why"],
            }
        )

    def connect(self, text: str) -> dict[str, Any]:
        refused = self._refuse_if_readonly()
        if refused:
            return refused
        value = str(text or "").strip()
        if not value:
            return _fail("invalid", strings.ui_strings()["enroll_missing"])
        try:
            self._call("connect", {"connection": value})
        except channel.ChannelError as exc:
            return self._error(exc)
        return self.connection()

    def enroll_offline(self, text: str) -> dict[str, Any]:
        """Conectar un equipo cuyo servicio no corre porque no está enrolado.

        Hoy un servicio sin enrolamiento sale al arrancar, así que no hay canal
        al que pedir `connect`. Se hace lo mismo que haría una persona en una
        consola de administrador: ``cenya-agent enroll <cadena>`` (la cadena
        como argumento, nunca por un intérprete de comandos) y después arrancar
        el servicio desde el administrador de servicios. Nunca en desarrollo:
        tocaría el enrolamiento de la máquina.
        """
        if self._dev:
            return _fail("dev", _service_error(winsys.ServiceControlError("dev")))
        if not self._elevated:
            return _fail(channel.FORBIDDEN, self._perms()["why"])
        value = str(text or "").strip()
        if not value:
            return _fail("invalid", strings.ui_strings()["enroll_missing"])
        enrolled, message = self._enroll(value)
        value = ""  # noqa: F841 - la cadena lleva un código de un solo uso
        if not enrolled:
            return _fail("failed", message or view.error_message("failed"))
        try:
            self._service.start()
        except winsys.ServiceControlError as exc:
            return _fail(exc.code, _enrolled_but_not_started(_service_error(exc)))
        return _ok(message=message)

    def disconnect(self) -> dict[str, Any]:
        refused = self._refuse_if_readonly()
        if refused:
            return refused
        try:
            self._call("disconnect")
        except channel.ChannelError as exc:
            return self._error(exc)
        return self.connection()

    def choose_ca(self) -> dict[str, Any]:
        refused = self._refuse_if_readonly()
        if refused:
            return refused
        path = self._dialogs.open(("Certificados (*.pem;*.crt;*.cer)", "Todos (*.*)"))
        if not path:
            return _fail("cancelled", "")
        return self._set_settings({"ca_bundle": path}, then=self.connection)

    def clear_ca(self) -> dict[str, Any]:
        return self._set_settings({"ca_bundle": ""}, then=self.connection)

    def set_proxy(self, mode: str, url: str = "") -> dict[str, Any]:
        if mode not in ("system", "manual", "none"):
            return _fail("invalid", "")
        url = str(url or "").strip()
        if mode == "manual" and "***" not in url and not url.lower().startswith(("http://", "https://")):
            return _fail("invalid", _invalid_proxy())
        proxy: dict[str, Any] = {"mode": mode}
        # Un proxy que vuelve tapado («***@») no se reescribe: se perdería la contraseña.
        if mode == "manual" and "***" not in url:
            proxy["url"] = url
        return self._set_settings({"proxy": proxy}, then=self.connection)

    # --- Ajustes ----------------------------------------------------------------------------

    def _set_settings(self, changes: dict[str, Any], then: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        refused = self._refuse_if_readonly()
        if refused:
            return refused
        try:
            self._call("settings.set", changes)
        except channel.ChannelError as exc:
            return self._error(exc)
        return then()

    def settings(self) -> dict[str, Any]:
        try:
            settings = self._call("settings.get")
            if self._about is None:
                self._about = self._call("about")
        except channel.ChannelError as exc:
            return self._error(exc)
        perms = self._perms()
        service = self._service.query()
        tray_enabled = False
        try:
            tray_enabled = bool(self._tray.enabled())
        except Exception:  # noqa: BLE001 - un registro ilegible es «no»
            tray_enabled = False
        machine_blocker = ""
        if self._dev:
            machine_blocker = view.service_view("unknown", "unknown", False, "", dev=True)["why"]
        elif not perms["can_act"]:
            machine_blocker = perms["why"]
        return _ok(
            view={
                "can_act": perms["can_act"],
                "why": perms["why"],
                "exclusions": view.exclusions_view(settings, self._about),
                "gentleness": view.gentleness_view(settings, self._status),
                "updates": view.updates_view(settings, self._status, self._update_check),
                "service": view.service_view(
                    service.get("state", "unknown"), service.get("start_type", "unknown"), perms["can_act"], perms["why"], dev=self._dev
                ),
                "tray": {"enabled": tray_enabled, "can_change": not machine_blocker, "why": machine_blocker},
                "notifications": bool(settings.get("notifications", True)),
                "language": view.language_options(str(settings.get("language") or self._language or "")),
            }
        )

    def add_exclusion(self, text: str) -> dict[str, Any]:
        current = self._current_exclusions()
        if current is None:
            return _fail(channel.BROKEN, view.error_message(channel.BROKEN))
        checked = view.validate_exclusion(str(text), current)
        if not checked["ok"]:
            return _fail("invalid", checked["message"])
        return self._set_settings(view.exclusions_payload([*current, checked["value"]]), then=self.settings)

    def remove_exclusion(self, value: str) -> dict[str, Any]:
        current = self._current_exclusions()
        if current is None:
            return _fail(channel.BROKEN, view.error_message(channel.BROKEN))
        return self._set_settings(view.exclusions_payload([v for v in current if v != value]), then=self.settings)

    def _current_exclusions(self) -> list[str] | None:
        try:
            settings = self._call("settings.get")
        except channel.ChannelError:
            return None
        excluded = settings.get("excluded") if isinstance(settings.get("excluded"), dict) else {}
        return [str(v) for v in (excluded.get("subnets") or [])] + [str(v) for v in (excluded.get("addresses") or [])]

    def set_setting(self, key: str, value: Any) -> dict[str, Any]:
        allowed = {
            "gentleness_cap": lambda v: v in view.GENTLENESS_CAPS,
            "auto_update": lambda v: isinstance(v, bool),
            "notifications": lambda v: isinstance(v, bool),
        }
        if key not in allowed or not allowed[key](value):
            return _fail("invalid", "")
        return self._set_settings({key: value}, then=self.settings)

    def set_language(self, code: str) -> dict[str, Any]:
        """El idioma: el del agente si se puede guardar; si no, solo el de esta ventana."""
        if code not in {"", *(c for c, _ in view.LANGUAGES)}:
            return _fail("invalid", "")
        if self._perms()["can_act"]:
            try:
                self._call("settings.set", {"language": code})
            except channel.ChannelError as exc:
                return self._error(exc)
        self._apply_language(code)
        return _ok(strings=strings.ui_strings(), filters=view.log_filters())

    def check_update(self) -> dict[str, Any]:
        refused = self._refuse_if_readonly()
        if refused:
            return refused
        try:
            self._update_check = self._call("check_update")
        except channel.ChannelError as exc:
            return self._error(exc)
        return self.settings()

    def service_action(self, action: str) -> dict[str, Any]:
        if self._dev:
            return _fail("dev", view.service_view("unknown", "unknown", False, "", dev=True)["why"])
        if not self._elevated:
            return _fail(channel.FORBIDDEN, self._perms()["why"])
        operations = {"start": self._service.start, "stop": self._service.stop, "restart": self._service.restart}
        if action not in operations:
            return _fail("invalid", "")
        try:
            operations[action]()
        except winsys.ServiceControlError as exc:
            return _fail(exc.code, _service_error(exc))
        return _ok()

    def set_autostart(self, enabled: bool) -> dict[str, Any]:
        if self._dev or not self._elevated:
            return _fail(channel.FORBIDDEN, self._perms()["why"])
        try:
            self._service.set_autostart(bool(enabled))
        except winsys.ServiceControlError as exc:
            return _fail(exc.code, _service_error(exc))
        return self.settings()

    def set_tray_startup(self, enabled: bool) -> dict[str, Any]:
        if self._dev or not self._elevated:
            return _fail(channel.FORBIDDEN, self._perms()["why"])
        try:
            self._tray.set(bool(enabled))
        except winsys.ServiceControlError as exc:
            return _fail(exc.code, _service_error(exc))
        return self.settings()

    # --- Acerca de ----------------------------------------------------------------------------

    def about(self) -> dict[str, Any]:
        about: dict[str, Any] = {}
        try:
            about = self._call("about")
            self._about = about
        except channel.ChannelError:
            about = self._about or {}
        system = about.get("os") if isinstance(about.get("os"), dict) else {}
        return _ok(
            view={
                "version": str(about.get("agent_version") or __version__),
                "app_version": __version__,
                "hostname": str(about.get("hostname") or ""),
                "system": " ".join(str(system.get(k) or "") for k in ("system", "release")).strip(),
                "repo": REPO_URL.removeprefix("https://"),
            }
        )


def _invalid_ip() -> str:
    from agent.i18n import _t

    return _t("Eso no es una dirección IP.")


def _invalid_proxy() -> str:
    from agent.i18n import _t

    return _t("La dirección del proxy tiene que empezar por http:// o https://.")


def _saved_in(path: str) -> str:
    from agent.i18n import _t

    return _t("Guardado en %(path)s") % {"path": path}


def _enrolled_but_not_started(reason: str) -> str:
    from agent.i18n import _t

    return _t("El equipo ha quedado conectado, pero el servicio no ha arrancado: %(reason)s") % {"reason": reason}


def _service_error(exc: winsys.ServiceControlError) -> str:
    from agent.i18n import _t

    if exc.code == "forbidden":
        return _t("Windows no ha dejado hacerlo: hace falta un administrador.")
    if exc.code == "not_installed":
        return _t("El servicio del agente no está instalado en este equipo.")
    if exc.code == "timeout":
        return _t("El servicio no se ha detenido a tiempo. Vuelve a intentarlo en un momento.")
    if exc.code == "dev":
        return _t("Con el canal de desarrollo, el servicio de Windows no se toca desde aquí.")
    return _t("Windows no ha podido hacerlo: %(detail)s") % {"detail": exc.detail or exc.code}
