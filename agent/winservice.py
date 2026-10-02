"""The agent as a real Windows service: Services.msc, no logged-in user needed.

Installed and managed with the ``cenya-agent-service`` command, which is
pywin32's standard command line (``install``, ``update``, ``start``, ``stop``,
``remove``, ``debug``) plus three things pywin32 does not do on its own, without
which the service installs fine and then never starts or leaves its token
readable:

1. **The host executable, inside the virtualenv** (found by trying it, on
   pywin32 312 and Python 3.12). pywin32 puts
   ``pythonservice.exe`` in ``sys.exec_prefix``. From a venv that is the venv
   root, where Windows cannot find ``python3XX.dll`` (the process dies with
   0xC0000135) and, even with the DLL beside it, Python does not recognise the
   venv and cannot see its ``site-packages``. From ``<venv>\\Scripts`` with the
   DLLs copied next to it, both work -- that is what `prepare_service_host`
   does.
2. **The variables, on the service itself.** A service does not see a
   machine-level environment variable set after boot until the machine
   restarts. ``install`` copies every ``CENYA_*`` (and the older
   ``NETINVENTORY_*``) variable of the console that runs it into the service's
   own ``Environment`` registry value, which Windows reads on every start. The
   token no longer has to be one of them: an agent enrolled with
   ``cenya-agent enroll`` keeps it in its protected store, which the service
   (SYSTEM) reads by itself.
3. **That key, closed to ordinary users.** By default ``BUILTIN\\Users`` can
   read a service's registry key (checked on this machine's own services), and
   a token set by variable is in it. ``install`` leaves the key readable only by
   SYSTEM and the Administrators group.

Nothing else in the package imports this module: without pywin32 installed
(Linux, CI) the agent works exactly as before.
"""

from __future__ import annotations

import filecmp
import os
import shutil
import sys
import threading
from collections.abc import Callable, Mapping
from pathlib import Path

import servicemanager
import win32service
import win32serviceutil

from agent import status
from agent import store as enrollment_store
from agent.__main__ import main as agent_main
from agent.__main__ import unexpected_error
from agent.i18n import _t

SERVICE_NAME = "CenyaAgent"
SERVICE_KEY = rf"SYSTEM\CurrentControlSet\Services\{SERVICE_NAME}"

#: Lo que se le promete a Windows en cada aviso de «deteniéndose». Se repite
#: cada `STOP_REPORT_SECONDS` mientras el barrido en curso termina: Windows ve
#: que el servicio avanza en vez de una sola promesa larga a ciegas, y
#: Services.msc no lo da por colgado aunque el barrido tarde minutos.
STOP_WAIT_HINT_MS = 15_000
STOP_REPORT_SECONDS = 5.0

#: Los nombres de hoy y los de antes de llamarse Cenya.
ENV_PREFIXES = ("CENYA_", "NETINVENTORY_")


class _EventLogStream:
    """Un `sys.stdout` que escribe en el Visor de eventos, línea a línea.

    Un servicio no tiene consola: sin esto, los mensajes del agente --«barrido
    enviado», «el servidor no contesta»-- se pierden, y el Visor de eventos es
    donde un administrador de Windows mira cuando algo no va.
    """

    def __init__(self, log: Callable[[str], None]) -> None:
        self._log = log
        self._pending = ""

    def write(self, text: str) -> int:
        self._pending += text
        *lines, self._pending = self._pending.split("\n")
        for line in lines:
            if line.strip():
                self._log(line)
        return len(text)

    def flush(self) -> None:
        if self._pending.strip():
            self._log(self._pending)
        self._pending = ""


class CenyaAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = "Cenya Agent"
    _svc_description_ = (
        "Barre la red y empuja lo que encuentra a Cenya por HTTPS saliente. "
        "No abre ningún puerto."
    )

    def __init__(self, args: list[str]) -> None:
        super().__init__(args)
        self.stop_event = threading.Event()
        self._finished = threading.Event()
        self._stop_reporter: threading.Thread | None = None

    # --- Parar -----------------------------------------------------------------
    #
    # SvcStop llega por el hilo de control de Windows, que tiene que quedar libre
    # enseguida: aquí solo se da la orden. El aviso periódico de «deteniéndose»
    # lo hace un hilo aparte hasta que SvcDoRun termina de verdad.

    def SvcStop(self) -> None:
        self._request_stop()

    def SvcShutdown(self) -> None:
        self._request_stop()

    def _request_stop(self) -> None:
        if self.stop_event.is_set():
            return
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING, waitHint=STOP_WAIT_HINT_MS)
        self.stop_event.set()
        self._stop_reporter = threading.Thread(
            target=self._report_stopping, name="cenya-stop-reporter", daemon=True
        )
        self._stop_reporter.start()

    def _report_stopping(self) -> None:
        while not self._finished.wait(STOP_REPORT_SECONDS):
            self.ReportServiceStatus(
                win32service.SERVICE_STOP_PENDING, waitHint=STOP_WAIT_HINT_MS
            )

    # --- Correr ----------------------------------------------------------------

    def SvcDoRun(self) -> None:
        """El bucle del agente, en el hilo que pywin32 ya dedica a esto.

        Si el bucle termina sin que nadie haya pedido parar --falta el token,
        un fallo inesperado--, se lanza: pywin32 lo comunica a Windows como una
        salida con error, y es lo que activa el reinicio automático que
        configura `deploy/install-service.ps1`. Devolver sin más dejaría el
        servicio «detenido» como si todo estuviera bien.
        """
        saved = sys.stdout, sys.stderr
        sys.stdout = _EventLogStream(servicemanager.LogInfoMsg)  # type: ignore[assignment]
        sys.stderr = _EventLogStream(servicemanager.LogWarningMsg)  # type: ignore[assignment]
        failure = ""
        try:
            agent_main(argv=[], stop_event=self.stop_event)
        except SystemExit as exc:
            # `config.from_env` sale así cuando falta el token o la URL es
            # insegura, con el motivo ya escrito para una persona.
            failure = str(exc.code)
        except Exception as exc:  # noqa: BLE001 - se dice en el Visor y se relanza abajo
            failure = unexpected_error(exc)
        else:
            if not self.stop_event.is_set():
                failure = _t("El bucle del agente terminó sin que nadie lo parara.")
        finally:
            for stream in (sys.stdout, sys.stderr):
                stream.flush()
            sys.stdout, sys.stderr = saved
            self._finished.set()
            if self._stop_reporter is not None:
                self._stop_reporter.join(timeout=STOP_REPORT_SECONDS * 2)
        if failure:
            servicemanager.LogErrorMsg(_t("Cenya Agent se ha detenido: %(reason)s") % {"reason": failure})
            # Para el icono de bandeja: sin esto, un servicio que no arrancó por
            # falta de token dejaba el fichero con la última ejecución buena, y
            # el icono solo podía decir «sin noticias», no por qué.
            status.stopped(reason=failure)
            raise RuntimeError(failure)


# --- Instalación ---------------------------------------------------------------


def _runtime_dlls(base: Path) -> list[Path]:
    """Las DLL de la Python base que el ejecutable del servicio necesita al lado."""
    main = base / f"python{sys.version_info.major}{sys.version_info.minor}.dll"
    optional = [base / name for name in ("python3.dll", "vcruntime140.dll", "vcruntime140_1.dll")]
    return [main] + [dll for dll in optional if dll.exists()]


def prepare_service_host(
    prefix: Path,
    base: Path,
    host_exe: Path,
    pywintypes_dll: Path,
) -> Path | None:
    """Deja el ejecutable del servicio donde puede arrancar. Devuelve su ruta.

    Solo hace falta dentro de un venv (`prefix` distinto de `base`); con la
    Python del sistema, lo que hace pywin32 por defecto ya funciona y se
    devuelve `None` para no tocarlo.

    Copia solo lo que falta o ha cambiado: con el servicio corriendo, sus
    ficheros están bloqueados, y un `update` que no los necesita no debe fallar
    por eso.
    """
    if prefix.resolve() == base.resolve():
        return None
    scripts = prefix / "Scripts"
    main_dll = _runtime_dlls(base)[0]
    if not main_dll.exists():
        raise FileNotFoundError(
            _t(
                "No se encuentra %(dll)s: la Python con la que se creó este entorno "
                "ya no está donde estaba. Vuelve a crear el entorno virtual."
            )
            % {"dll": main_dll}
        )
    for source in [host_exe, pywintypes_dll, *_runtime_dlls(base)]:
        target = scripts / source.name
        if target.exists() and filecmp.cmp(source, target, shallow=False):
            continue
        try:
            shutil.copy2(source, target)
        except PermissionError as exc:
            raise PermissionError(
                _t("No se puede reemplazar %(file)s: detén el servicio antes de actualizarlo (%(command)s stop).")
                % {"file": target, "command": sys.argv[0]}
            ) from exc
    return scripts / host_exe.name


def service_environment(environ: Mapping[str, str]) -> list[str]:
    """Las variables `CENYA_*` (y las antiguas `NETINVENTORY_*`) de esta consola,
    en el formato del registro."""
    return sorted(f"{key}={value}" for key, value in environ.items() if key.startswith(ENV_PREFIXES))


def _store_environment(entries: list[str]) -> None:
    import winreg

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "Environment", 0, winreg.REG_MULTI_SZ, entries)


def _set_protected_dacl(name: str, object_type: int, full_access: int, readers: dict[int, int]) -> None:
    """Sustituye los permisos de `name` por SYSTEM y Administradores con control
    total, más `readers` (SID conocido → máscara), sin heredar nada de arriba.

    Protegida a propósito: lo heredado de la carpeta o clave madre es lo que
    abría la puerta a los usuarios normales.
    """
    import win32security

    dacl = win32security.ACL()
    inherit = win32security.OBJECT_INHERIT_ACE | win32security.CONTAINER_INHERIT_ACE
    grants = {win32security.WinLocalSystemSid: full_access, win32security.WinBuiltinAdministratorsSid: full_access}
    grants.update(readers)
    for well_known, mask in grants.items():
        sid = win32security.CreateWellKnownSid(well_known, None)
        dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, inherit, mask, sid)
    win32security.SetNamedSecurityInfo(
        name,
        object_type,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )


def restrict_key_to_administrators(key_name: str) -> None:
    """Deja la clave (y sus subclaves) legible solo por SYSTEM y Administradores.

    `key_name` en el formato de `SetNamedSecurityInfo`: `MACHINE\\SYSTEM\\...`.
    SYSTEM es quien arranca el servicio y lee `PythonClass`; Administradores,
    quien lo gestiona desde Services.msc. Nadie más necesita leerla, y en ella
    está el token del agente.
    """
    import win32con
    import win32security

    _set_protected_dacl(key_name, win32security.SE_REGISTRY_KEY, win32con.KEY_ALL_ACCESS, {})


def lock_status_directory(directory: Path) -> None:
    """La carpeta del fichero de estado: escribe el servicio, lee cualquiera.

    `%ProgramData%` deja por defecto que cualquier usuario cree carpetas y
    ficheros dentro, y se quede como dueño -- comprobado en esta máquina. Sin
    cerrarla, un usuario podría dejar ahí un estado falso, con una URL que el
    icono de bandeja abriría en el navegador de un administrador. Queda:
    SYSTEM y Administradores con control total, Usuarios solo lectura, y
    «OWNER RIGHTS» también solo lectura, para que quien la hubiera creado antes
    de instalar no conserve el permiso implícito de dueño para reabrirla.
    """
    import ntsecuritycon
    import win32security

    directory.mkdir(parents=True, exist_ok=True)
    read = ntsecuritycon.FILE_GENERIC_READ | ntsecuritycon.FILE_GENERIC_EXECUTE
    _set_protected_dacl(
        str(directory),
        win32security.SE_FILE_OBJECT,
        ntsecuritycon.FILE_ALL_ACCESS,
        {win32security.WinBuiltinUsersSid: read, win32security.WinCreatorOwnerRightsSid: read},
    )


def _after_install(opts: list[tuple[str, str]]) -> None:
    """Lo que pywin32 llama tras `install` o `update`.

    Si esto lanza durante `install`, pywin32 quita el servicio que acaba de
    crear: mejor sin servicio que con uno que no puede arrancar.
    """
    entries = service_environment(os.environ)
    names = [entry.split("=", 1)[0] for entry in entries]
    if entries:
        has_token = any(f"{prefix}AGENT_TOKEN" in names for prefix in ENV_PREFIXES)
        if not has_token and enrollment_store.load(os.environ) is None:
            raise SystemExit(
                _t(
                    "Este equipo no está enrolado y en esta consola no hay ningún token: el servicio "
                    "no podría arrancar. Ejecuta antes cenya-agent enroll <cadena> y vuelve a instalar."
                )
            )
        _store_environment(entries)
        # Nunca el valor: solo qué variables quedaron guardadas.
        print(_t("Variables guardadas en el servicio: %(names)s") % {"names": ", ".join(names)})
    else:
        print(_t("Sin variables CENYA_* en esta consola: se dejan las que ya tuviera el servicio."))
    restrict_key_to_administrators(rf"MACHINE\{SERVICE_KEY}")
    print(_t("La clave del servicio queda legible solo por SYSTEM y Administradores."))
    status_file = status.path()
    if status_file is not None:
        lock_status_directory(status_file.parent)
        print(
            _t("Estado del agente en %(path)s (lo escribe el servicio; lo lee el icono de bandeja).")
            % {"path": status_file}
        )


def _frozen() -> bool:
    """Si corre dentro del ejecutable que construye PyInstaller (el instalador)."""
    return bool(getattr(sys, "frozen", False))


def _host_as_frozen_service() -> bool:
    """Arranca como servicio si es el Administrador de servicios quien lo lanzó.

    Dentro del instalador no hay `pythonservice.exe` ni entorno virtual: el
    propio ejecutable es el servicio. Windows lo arranca sin argumentos y
    espera que enseguida se presente (`StartServiceCtrlDispatcher`); si en vez
    de Windows lo abre una persona con doble clic o desde una consola, esa
    llamada falla con 1063 («no se inició como servicio») y se sigue con la
    línea de comandos normal, que enseña la ayuda.
    """
    import pywintypes
    import winerror

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(CenyaAgentService)
    try:
        servicemanager.StartServiceCtrlDispatcher()
    except pywintypes.error as exc:
        if exc.winerror == winerror.ERROR_FAILED_SERVICE_CONTROLLER_CONNECT:
            return False
        raise
    return True


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv if argv is None else argv)
    if _frozen() and len(argv) == 1 and _host_as_frozen_service():
        return
    if not _frozen() and any(command in argv[1:] for command in ("install", "update")):
        import pywintypes

        host = prepare_service_host(
            prefix=Path(sys.prefix),
            base=Path(sys.base_exec_prefix),
            host_exe=Path(win32service.__file__).parent / "pythonservice.exe",
            pywintypes_dll=Path(pywintypes.__file__),
        )
        # `_exe_name_` es cómo pywin32 deja elegir el ejecutable; sin venv se
        # queda en None y pywin32 hace lo suyo.
        CenyaAgentService._exe_name_ = str(host) if host else None
    # Ya instalado como ejecutable congelado, pywin32 registra `sys.executable`
    # como el programa del servicio (`LocatePythonServiceExe`): no hay nada que
    # preparar, y por eso lo de arriba solo corre fuera del instalador.
    # pywin32 imprime el error pero *devuelve* el código en vez de salir con él:
    # sin pasarlo a SystemExit, un `install` denegado terminaba con 0 y el
    # script de instalación lo daba por bueno.
    error = win32serviceutil.HandleCommandLine(
        CenyaAgentService,
        # Explícito: si alguien lo lanza con `python -m agent.winservice`, pywin32
        # deduciría la clase por la ruta del fichero y el servicio importaría
        # `winservice` suelto, fuera de su paquete.
        serviceClassString="agent.winservice.CenyaAgentService",
        argv=argv,
        customOptionHandler=_after_install,
    )
    if error:
        raise SystemExit(error)


if __name__ == "__main__":
    main()
