"""The texts of ``deploy/install-service.ps1``, translated like everything else.

PowerShell has no gettext, and a second translation system (``.psd1`` files)
would split the agent's texts in two: two formats, two sets of files to keep in
step, and the catalogue tests covering only half. Instead the script asks the
agent it is installing for its texts, already translated:

    & "<venv>\\Scripts\\python.exe" -m agent.installer_text

prints them as JSON, keyed by a stable name. The Spanish texts are marked with
``_t`` here, so they live in the same ``cenya-agent.po`` catalogues as
the tray icon's and the same tests watch them.

The JSON is pure ASCII (``\\u00f3`` rather than ``ó``): Windows PowerShell 5.1
decodes a program's output with the console code page (850 on a Spanish
Windows), which would turn every accent into rubbish before the script ever
saw it. An escape survives any code page, and ``ConvertFrom-Json`` undoes it.

Placeholders are the catalogue's ``%(name)s``; the script replaces them itself.
``agent/tests/test_installer_text.py`` checks that every text the script asks
for exists here, that every one here is used, and that the script fills in
exactly the placeholders each text has.
"""

from __future__ import annotations

import json

from agent.i18n import _t


def install_script_messages() -> dict[str, str]:
    """Los textos del script de instalación, en el idioma de esta sesión."""
    return {
        "need_admin": _t("Hace falta un PowerShell de administrador: instalar un servicio lo exige Windows."),
        "no_service_exe": _t("No se encuentra %(exe)s. ¿Está instalado el agente con el extra [windows] en %(dir)s?"),
        "connection_prompt": _t("Cadena de conexión (Ajustes → Agentes → Añadir un agente)"),
        "no_enrollment": _t("Sin enrolar el agente, el servicio no puede arrancar."),
        "enroll_failed": _t("El enrolamiento ha fallado: el motivo está justo encima."),
        "no_url": _t("Con -Token hace falta también -Url."),
        "stopping_to_update": _t("Deteniendo el servicio para actualizarlo…"),
        "install_failed": _t("La instalación del servicio falló (código %(code)s)."),
        "restart_policy_failed": _t("No se pudo configurar el reinicio automático (sc.exe failure)."),
        "no_tray_exe": _t("No se encuentra %(tray)s: el icono de bandeja no se instala (¿agente anterior a esta versión?)."),
        "start_failed": _t("El servicio no arrancó. Mira el Visor de eventos: Registros de Windows → Aplicación, origen %(source)s."),
        "installed": _t("Servicio «Cenya Agent» instalado y en marcha."),
        "event_log_hint": _t("Sus mensajes van al Visor de eventos (Aplicación, origen %(source)s)."),
        "manage_hint": _t("Se gestiona desde services.msc, o con: %(exe)s stop | start | remove"),
        "tray_hint": _t("El icono de bandeja aparecerá al iniciar sesión. Para verlo ya: %(tray)s"),
        "tray_overflow_hint": _t(
            "Windows lo guarda al principio en el desplegable ^ de la barra de tareas: arrástralo fuera para tenerlo siempre a la vista."
        ),
    }


def main() -> None:
    print(json.dumps(install_script_messages(), ensure_ascii=True))


if __name__ == "__main__":
    main()
