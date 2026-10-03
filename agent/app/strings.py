"""Every fixed text of the window, marked for translation, handed to the page.

The page has no catalogue of its own: Python reads the agent's catalogues
(`agent.i18n`) and gives the page this dictionary at start-up and again when
the language changes. Texts that depend on data (counts, times, states) are
built by `agent.app.view`, also here in Python, with real plurals (`_tn`).

Keys are stable identifiers; the page never compares a translated text.
Placeholders keep the agent's ``%(name)s`` form; the page fills them in with
the same rule (``fmt`` in ``app.js``).
"""

from __future__ import annotations

from agent.i18n import _t


def ui_strings() -> dict[str, str]:
    return {
        # La navegación y las cabeceras de cada sección.
        "nav_status": _t("Estado"),
        "nav_activity": _t("Actividad"),
        "nav_netbox": _t("Importar de NetBox"),
        "nav_tools": _t("Herramientas"),
        "nav_connection": _t("Conexión"),
        "nav_settings": _t("Ajustes"),
        "nav_about": _t("Acerca de"),
        "sub_status": _t("Qué está haciendo el agente en este equipo."),
        "sub_activity": _t("El registro del agente, en directo."),
        "sub_netbox": _t("Trae a Cenya lo que ya tienes en NetBox, leído desde dentro de tu red."),
        "sub_tools": _t("Comprobaciones para cuando algo no va como debería."),
        "sub_connection": _t("El portal de Cenya al que informa este equipo."),
        "sub_settings": _t("Lo que decide quien está en esta máquina."),
        "sub_about": _t("El agente de descubrimiento de Cenya."),
        # Comunes.
        "loading": _t("Cargando…"),
        "retry": _t("Reintentar"),
        "error_title": _t("No se pudo cargar"),
        "cancel": _t("Cancelar"),
        "close": _t("Cerrar"),
        "saved": _t("Guardado"),
        "save": _t("Guardar"),
        "dev_badge": _t("Canal de desarrollo"),
        # Permisos.
        "readonly_banner": _t("Solo lectura — reiniciar como administrador para hacer cambios"),
        "readonly_button": _t("Reiniciar como administrador"),
        # Otro agente pide las credenciales selladas (agent/approvals.py).
        "reseal_title": _t("El agente «%(name)s» pide las credenciales de este perfil"),
        "reseal_body": _t(
            "Se cerrarán con la clave de ese agente para que pueda usarlas. Permítelo solo si acabas de "
            "añadir ese agente en Cenya; si no lo reconoces, recházalo: alguien podría estar intentando llevárselas."
        ),
        "reseal_count": _t("Credenciales: %(count)s"),
        "reseal_fingerprint": _t("Huella de su clave: %(fingerprint)s"),
        "reseal_allow": _t("Permitir"),
        "reseal_deny": _t("Rechazar"),
        "reseal_allowed": _t("Permitido: el otro agente recibirá las credenciales."),
        "reseal_denied": _t("Rechazado: no se ha compartido nada."),
        "readonly_tip": _t("Hace falta abrir Cenya Agent como administrador para hacer cambios."),
        # Servicio parado.
        "down_title": _t("El servicio del agente no está en marcha"),
        "down_body": _t(
            "Sin el servicio, este equipo no barre la red ni informa al portal. "
            "Esta ventana se pondrá al día sola en cuanto arranque."
        ),
        "down_start": _t("Iniciar el servicio"),
        "not_installed_title": _t("El servicio del agente no está instalado"),
        "not_installed_body": _t("Vuelve a ejecutar el instalador de Cenya Agent para recuperarlo."),
        # Sin enrolar.
        "enroll_title": _t("Conecta este equipo a Cenya"),
        "enroll_body": _t("Pega la cadena de conexión que da el portal en Ajustes → Agentes → Añadir un agente."),
        "enroll_placeholder": _t("cenya://portal.midominio.com/XXXX-XXXX-XXXX"),
        "enroll_button": _t("Conectar"),
        "enroll_missing": _t("Pega antes la cadena de conexión."),
        # Estado.
        "status_connection": _t("Conexión"),
        "status_current": _t("Tarea en curso"),
        "status_tasks": _t("Tareas"),
        "status_counters": _t("Último resultado"),
        "col_task": _t("Tarea"),
        "col_last": _t("Última ejecución"),
        "col_result": _t("Resultado"),
        "col_next": _t("Próxima"),
        "run_now": _t("Ejecutar ahora"),
        "run_queued": _t("En cola: empezará en cuanto termine la tarea en curso."),
        "pause": _t("Pausar"),
        "resume": _t("Reanudar"),
        "idle_title": _t("Sin tareas en marcha"),
        "no_counters": _t("Todavía no ha terminado ninguna tarea."),
        "no_tasks": _t("El portal todavía no ha mandado la agenda de tareas."),
        # Actividad.
        "filter_task": _t("Tarea"),
        "filter_level": _t("Nivel"),
        "filter_all_tasks": _t("Todas las tareas"),
        "filter_all_levels": _t("Todos los niveles"),
        "level_info": _t("Información"),
        "level_warning": _t("Avisos"),
        "level_error": _t("Errores"),
        "task_general": _t("General"),
        "copy": _t("Copiar"),
        "copied": _t("Copiado"),
        "open_folder": _t("Abrir la carpeta"),
        "log_empty": _t("Todavía no hay nada en el registro."),
        "log_filtered_empty": _t("Nada coincide con el filtro."),
        "live": _t("En directo"),
        # Importar de NetBox.
        "nb_step_source": _t("NetBox"),
        "nb_url": _t("Dirección de NetBox"),
        "nb_url_ph": _t("https://netbox.midominio.local"),
        "nb_token": _t("Token de solo lectura"),
        "nb_token_help": _t(
            "¿Cómo se crea? En NetBox, tu usuario → API Tokens → Añadir, sin marcar «Write enabled». "
            "Se usa una vez y no se guarda."
        ),
        "nb_insecure": _t("Aceptar un certificado no válido (NetBox con certificado propio o caducado)"),
        "nb_test": _t("Probar"),
        "nb_test_ok": _t("NetBox contesta y acepta el token."),
        "nb_step_destination": _t("Al terminar"),
        "nb_send": _t("Enviar a Cenya y revisar"),
        "nb_send_hint": _t("Se sube al portal y se abre la revisión en el navegador. Nada se importa hasta que lo confirmes allí."),
        "nb_save": _t("Guardar como fichero"),
        "nb_save_hint": _t("Para subirlo después en Ajustes → Importar → «NetBox, desde un fichero»."),
        "nb_read": _t("Leer NetBox"),
        "nb_reading": _t("Leyendo NetBox…"),
        "nb_progress": _t("Avance"),
        "nb_done_title": _t("Lectura terminada"),
        "nb_open_review": _t("Abrir la revisión"),
        "nb_show_file": _t("Mostrar en la carpeta"),
        "nb_again": _t("Leer otro NetBox"),
        "nb_missing_url": _t("Escribe la dirección de NetBox."),
        "nb_missing_token": _t("Pega el token de NetBox."),
        "nb_token_cleared": _t("El token se ha borrado de este formulario."),
        # Herramientas.
        "probe_title": _t("Analizar una IP"),
        "probe_body": _t("Prueba SNMP, SSH y WinRM contra una sola dirección y dice qué pasó con cada uno."),
        "probe_ph": _t("192.168.1.20"),
        "probe_button": _t("Analizar"),
        "conn_test_title": _t("Probar la conexión con el portal"),
        "conn_test_body": _t("Nombre, puerto, certificado y token, paso a paso."),
        "conn_test_button": _t("Probar"),
        "selftest_title": _t("Autocomprobación"),
        "selftest_body": _t("Qué puede hacer esta instalación: colectores, librerías e idiomas."),
        "selftest_button": _t("Comprobar"),
        "bundle_title": _t("Paquete de soporte"),
        "bundle_body": _t(
            "Un fichero con el registro, los ajustes locales y el estado, sin contraseñas ni tokens, para enviarlo a soporte."
        ),
        "bundle_button": _t("Guardar el paquete…"),
        "working": _t("Trabajando…"),
        # Conexión.
        "conn_portal": _t("Portal"),
        "conn_name": _t("Este equipo aparece como"),
        "conn_open_portal": _t("Abrir en el navegador"),
        "conn_change_title": _t("Conectar o cambiar de portal"),
        "conn_change_body": _t("Pega una cadena de conexión o un código del portal."),
        "conn_change_confirm_title": _t("¿Cambiar de portal?"),
        "conn_change_confirm_body": _t("Este equipo dejará de informar a %(portal)s y pasará a informar al portal nuevo."),
        "conn_change_confirm": _t("Cambiar de portal"),
        "ca_title": _t("Certificado de la empresa"),
        "ca_body": _t(
            "Si la salida a internet pasa por una inspección TLS con una autoridad propia, indica aquí su certificado (.pem, .crt o .cer)."
        ),
        "ca_choose": _t("Elegir fichero…"),
        "ca_clear": _t("Quitar"),
        "ca_none": _t("Ninguno: se usan los certificados de Windows."),
        "proxy_title": _t("Proxy"),
        "proxy_system": _t("El del sistema"),
        "proxy_manual": _t("Manual"),
        "proxy_none": _t("Ninguno"),
        "proxy_url_ph": _t("http://proxy.midominio.local:8080"),
        "proxy_hint": _t("Si lleva usuario y contraseña, no se vuelven a mostrar."),
        "disconnect_title": _t("Desconectar este equipo"),
        "disconnect_body": _t(
            "Avisa al portal, borra el enrolamiento y deja de barrer. Para volver hará falta una cadena de conexión nueva."
        ),
        "disconnect_button": _t("Desconectar…"),
        "disconnect_confirm_title": _t("¿Desconectar este equipo?"),
        "disconnect_confirm_body": _t("El agente dejará de informar a %(portal)s. Lo ya inventariado se queda en el portal."),
        "disconnect_confirm": _t("Desconectar"),
        # Ajustes.
        "excl_title": _t("Redes y direcciones que nunca se barren"),
        "excl_body": _t("El agente no hace ping ni entra en ellas, tampoco si se pide desde el portal."),
        "excl_ph": _t("10.0.5.0/24 o 10.0.5.7"),
        "excl_add": _t("Añadir"),
        "excl_empty": _t("Ninguna: se barre todo lo que diga el portal."),
        "excl_suggest": _t("Redes de este equipo"),
        "excl_remove": _t("Quitar"),
        "excl_network": _t("Red"),
        "excl_address": _t("Dirección"),
        "gentle_title": _t("Suavidad máxima"),
        "gentle_body": _t("Cuántas conexiones a la vez puede abrir el agente. Puede bajar lo que diga el portal, nunca subirlo."),
        "upd_title": _t("Actualizaciones"),
        "upd_auto": _t("Automáticas"),
        "upd_notify": _t("Solo avisar"),
        "upd_check": _t("Buscar ahora"),
        "upd_installed": _t("Instalada"),
        "upd_latest": _t("Vigente"),
        "svc_title": _t("Servicio"),
        "svc_start": _t("Iniciar"),
        "svc_stop": _t("Detener"),
        "svc_restart": _t("Reiniciar"),
        "svc_autostart": _t("Arrancar con Windows"),
        "tray_title": _t("Icono de bandeja al iniciar sesión"),
        "tray_hint": _t("Para todas las personas que usan este equipo."),
        "notif_title": _t("Avisos de Windows"),
        "notif_hint": _t("Un aviso cuando el agente deja de poder trabajar."),
        "lang_title": _t("Idioma"),
        # Acerca de.
        "about_version": _t("Versión"),
        "about_license": _t("Licencia"),
        "about_license_value": _t("Apache 2.0, código abierto"),
        "about_repo": _t("Código fuente"),
        "about_data": _t("Qué hace el agente con tus datos"),
        "about_body": _t(
            "El agente descubre la red de tu empresa y la propone en Cenya. Solo habla con el portal por HTTPS saliente: no abre puertos."
        ),
        "about_machine": _t("Equipo"),
        "about_system": _t("Sistema"),
        "about_icons": _t("Iconos: Lucide (licencia ISC)."),
    }
