# -*- mode: python ; coding: utf-8 -*-
#
# El agente de Cenya congelado con PyInstaller: una carpeta con cinco
# ejecutables que comparten Python y las librerías, lista para que Inno Setup
# (`cenya-agent.iss`) la meta en el instalador.
#
#   cenya-agent.exe          la línea de comandos: enroll, selftest, export-netbox, el bucle
#   cenya-agent-service.exe  el servicio de Windows y su instalación
#   cenya-agent-tray.exe     el icono de bandeja (sin consola)
#   cenya-agent-askpass.exe  lo que OpenSSH ejecuta para pedir la contraseña (SSH_ASKPASS);
#                            con consola a propósito: `ssh` lee su salida estándar
#   cenya-agent-app.exe      la ventana de Cenya Agent (agent/app; sin consola): pywebview
#                            sobre el WebView2 de Windows, que el instalador no lleva
#
# El OpenSSH que usa el colector SSH no sale de aquí: build.ps1 lo baja, lo
# verifica y lo deja en dist\cenya-agent\openssh antes de empaquetar.
#
# Construir, desde la raíz del repositorio y con el agente instalado con todos
# sus extras (`pip install ./agent[completo,gui] pyinstaller`):
#
#   pyinstaller --noconfirm --distpath agent/dist --workpath agent/build-pyi agent/packaging/cenya-agent.spec
#
# Licencia: PyInstaller es GPL-2.0-or-later CON una excepción expresa que
# permite distribuir bajo cualquier licencia lo que construye (su bootloader
# incluido). El agente sigue siendo Apache-2.0; esta herramienta no entra en él,
# solo lo empaqueta. Avisado como copyleft en CLAUDE.md (regla 7).

from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_data_files

REPO = Path(SPECPATH).resolve().parent.parent
AGENT = REPO / "agent"
PACKAGING = AGENT / "packaging"

common = dict(
    pathex=[str(REPO)],
    # Los catálogos de traducción: `agent/i18n.py` los lee de `agent/translations`
    # junto a sí mismo, y dentro del instalador esa carpeta tiene que existir.
    # Y la lista de CA públicas de certifi, la segunda opinión del agente
    # cuando el almacén de Windows rechaza un certificado bueno
    # (agent/client.py::AgentClient._open).
    # La página de la ventana (agent/app/ui: HTML, CSS, JS y la licencia ISC
    # de los iconos Lucide, que viaja con ellos): `agent/app/main.py` la lee de
    # al lado del módulo y se la da a WebView2 en una cadena. Sin ella la
    # ventana no arranca, y `selftest` lo comprueba.
    datas=[(str(AGENT / "translations"), "agent/translations"), (str(AGENT / "app" / "ui"), "agent/app/ui")]
    + collect_data_files("certifi"),
    # El servicio y el icono viven en sus propios ejecutables, pero `selftest`
    # corre en el de la línea de comandos y tiene que poder ver las librerías
    # de Windows para decir la verdad sobre ellas. Compartido por MERGE: no pesa.
    hiddenimports=[
        "agent.winservice",
        "agent.tray",
        "agent.netbox_export",
        "agent.goodbye",
        # El canal local (spec 4): `localclient` lo importa `main` dentro de
        # una función, y el pipe usa pywin32 también importado al vuelo.
        "agent.localapi",
        "agent.localclient",
        "agent.localops",
        "agent.localpipe",
        "win32pipe",
        "win32file",
        "win32event",
        "pywintypes",
        # `cenya-agent settings` (lo llama el instalador con /CA=) y la
        # actualización: los importa __main__ dentro de una función.
        "agent.settings_command",
        "agent.update",
        "agent.release",
        "agent.release_keys",
        # Los permisos de la carpeta de estado (agent/store.py) los lee y
        # escribe pywin32 si está, importado dentro de una función.
        "win32security",
        "win32api",
        "win32serviceutil",
        "win32service",
        "servicemanager",
        "win32gui",
        "certifi",
        # La clave del agente (agent/identity.py) la importa dentro de una
        # función, solo si está: dicho aquí para que no dependa del análisis.
        "cryptography",
        # La aplicación sin pywebview: lo que comparten la ventana y el icono
        # (vistas, textos, servicio de Windows) y lo que `selftest` busca. Puro
        # Python; pywebview solo entra en el análisis de la ventana.
        "agent.app",
        "agent.app.strings",
        "agent.app.view",
        "agent.app.winsys",
        "win32clipboard",
        "win32process",
        "winerror",
    ],
    # Lo que el agente nunca usa y pesa: una interfaz gráfica de Tk, las
    # pruebas de unittest de terceros...
    excludes=["tkinter", "test", "unittest.mock"],
    noarchive=False,
)

a_cli = Analysis([str(PACKAGING / "entry_agent.py")], **common)
a_svc = Analysis([str(PACKAGING / "entry_service.py")], **common)
a_tray = Analysis([str(PACKAGING / "entry_tray.py")], **common)
a_askpass = Analysis([str(PACKAGING / "entry_askpass.py")], **common)

# La ventana: lo común más pywebview y lo que arrastra --pythonnet y
# clr_loader (el puente a .NET de WebView2), las DLL del SDK de WebView2 que
# trae pywebview en webview/lib, su JavaScript propio en webview/js--. Solo en
# este análisis: el icono, el servicio y la consola no cargan un navegador.
# `bottle` lo importa pywebview al cargarse aunque la ventana nunca arranque su
# servidor (agent/app/main.py::assert_no_server). Licencias: ver el extra `gui`
# de agent/pyproject.toml (todas permisivas).
gui = {"datas": [], "binaries": [], "hiddenimports": []}
for package in ("webview", "pythonnet", "clr_loader"):
    datas, binaries, hiddenimports = collect_all(package)
    gui["datas"] += datas
    gui["binaries"] += binaries
    gui["hiddenimports"] += hiddenimports
# pywebview lleva también lo de Android: aquí no sirve de nada.
gui["datas"] = [item for item in gui["datas"] if not item[0].lower().endswith(".jar")]
a_app = Analysis(
    [str(PACKAGING / "entry_app.py")],
    **{
        **common,
        "datas": common["datas"] + gui["datas"],
        "binaries": gui["binaries"],
        "hiddenimports": common["hiddenimports"]
        + gui["hiddenimports"]
        + ["webview", "webview.platforms.winforms", "webview.platforms.edgechromium", "clr", "clr_loader",
           "pythonnet", "proxy_tools", "bottle"],
    },
)

# Un solo juego de librerías compartido: sin esto, cada ejecutable llevaría su
# propia copia de Python y de pysnmp (tres veces el mismo peso).
MERGE(
    (a_cli, "cenya-agent", "cenya-agent"),
    (a_svc, "cenya-agent-service", "cenya-agent-service"),
    (a_tray, "cenya-agent-tray", "cenya-agent-tray"),
    (a_askpass, "cenya-agent-askpass", "cenya-agent-askpass"),
    (a_app, "cenya-agent-app", "cenya-agent-app"),
)

# El icono de los ejecutables: el de la marca (copia del favicon.ico del
# paquete, aquí dentro para que el agente no dependa de nada del servidor).
ICON = str(Path(SPECPATH) / "cenya.ico")

exe_cli = EXE(
    PYZ(a_cli.pure),
    a_cli.scripts,
    [],
    exclude_binaries=True,
    name="cenya-agent",
    console=True,
    icon=ICON,
    upx=False,
)
exe_svc = EXE(
    PYZ(a_svc.pure),
    a_svc.scripts,
    [],
    exclude_binaries=True,
    name="cenya-agent-service",
    console=True,
    icon=ICON,
    upx=False,
)
exe_tray = EXE(
    PYZ(a_tray.pure),
    a_tray.scripts,
    [],
    exclude_binaries=True,
    name="cenya-agent-tray",
    console=False,
    icon=ICON,
    upx=False,
)

exe_askpass = EXE(
    PYZ(a_askpass.pure),
    a_askpass.scripts,
    [],
    exclude_binaries=True,
    name="cenya-agent-askpass",
    console=True,
    icon=ICON,
    upx=False,
)

exe_app = EXE(
    PYZ(a_app.pure),
    a_app.scripts,
    [],
    exclude_binaries=True,
    name="cenya-agent-app",
    console=False,
    icon=ICON,
    upx=False,
)

coll = COLLECT(
    exe_cli,
    a_cli.binaries,
    a_cli.datas,
    exe_svc,
    a_svc.binaries,
    a_svc.datas,
    exe_tray,
    a_tray.binaries,
    a_tray.datas,
    exe_askpass,
    a_askpass.binaries,
    a_askpass.datas,
    exe_app,
    a_app.binaries,
    a_app.datas,
    strip=False,
    upx=False,
    name="cenya-agent",
)
