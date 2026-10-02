# -*- mode: python ; coding: utf-8 -*-
#
# El agente de Cenya congelado con PyInstaller: una carpeta con tres
# ejecutables que comparten Python y las librerías, lista para que Inno Setup
# (`cenya-agent.iss`) la meta en el instalador.
#
#   cenya-agent.exe          la línea de comandos: enroll, selftest, export-netbox, el bucle
#   cenya-agent-service.exe  el servicio de Windows y su instalación
#   cenya-agent-tray.exe     el icono de bandeja (sin consola)
#
# Construir, desde la raíz del repositorio y con el agente instalado con todos
# sus extras (`pip install ./agent[completo] pyinstaller`):
#
#   pyinstaller --noconfirm --distpath agent/dist --workpath agent/build-pyi agent/packaging/cenya-agent.spec
#
# Licencia: PyInstaller es GPL-2.0-or-later CON una excepción expresa que
# permite distribuir bajo cualquier licencia lo que construye (su bootloader
# incluido). El agente sigue siendo Apache-2.0; esta herramienta no entra en él,
# solo lo empaqueta. Avisado como copyleft en CLAUDE.md (regla 7).

from pathlib import Path

REPO = Path(SPECPATH).resolve().parent.parent
AGENT = REPO / "agent"
PACKAGING = AGENT / "packaging"

common = dict(
    pathex=[str(REPO)],
    # Los catálogos de traducción: `agent/i18n.py` los lee de `agent/translations`
    # junto a sí mismo, y dentro del instalador esa carpeta tiene que existir.
    datas=[(str(AGENT / "translations"), "agent/translations")],
    # El servicio y el icono viven en sus propios ejecutables, pero `selftest`
    # corre en el de la línea de comandos y tiene que poder ver las librerías
    # de Windows para decir la verdad sobre ellas. Compartido por MERGE: no pesa.
    hiddenimports=[
        "agent.winservice",
        "agent.tray",
        "agent.netbox_export",
        "win32serviceutil",
        "win32service",
        "servicemanager",
        "win32gui",
    ],
    # Lo que el agente nunca usa y pesa: una interfaz gráfica de Tk, las
    # pruebas de unittest de terceros...
    excludes=["tkinter", "test", "unittest.mock"],
    noarchive=False,
)

a_cli = Analysis([str(PACKAGING / "entry_agent.py")], **common)
a_svc = Analysis([str(PACKAGING / "entry_service.py")], **common)
a_tray = Analysis([str(PACKAGING / "entry_tray.py")], **common)

# Un solo juego de librerías compartido: sin esto, cada ejecutable llevaría su
# propia copia de Python y de pysnmp (tres veces el mismo peso).
MERGE(
    (a_cli, "cenya-agent", "cenya-agent"),
    (a_svc, "cenya-agent-service", "cenya-agent-service"),
    (a_tray, "cenya-agent-tray", "cenya-agent-tray"),
)

# El icono de los tres ejecutables: el de la marca (copia del favicon.ico del
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
    strip=False,
    upx=False,
    name="cenya-agent",
)
