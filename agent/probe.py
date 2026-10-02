"""Sondeo dirigido: por qué un equipo se queda en «solo responde».

El barrido normal ya prueba todas las credenciales contra todos los vivos,
pero cuando nada entra, el resultado es silencio: una fila sin descripción y
nadie que diga si falta una credencial, si el protocolo está apagado o si el
puerto está cerrado. Este módulo prueba **una IP a fondo** y apunta el
resultado de cada intento, para que la bandeja pueda decir «SSH: puerto
abierto, ninguna credencial entró» en vez de dejar que alguien lo averigüe
con telnet y paciencia.

El encargo llega del servidor en el latido (``probe_ips``) -- el agente no
tiene estado -- y el informe vuelve como un hallazgo más, fusionado por IP
con la fila que ya estaba en la bandeja.

**Ningún secreto sale de aquí.** Una comunidad SNMP es una credencial: los
informes citan «la comunidad nº 2» o «el usuario “lector”», nunca el valor.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any

from agent import credentials as creds
from agent import snmp, ssh, winrm
from agent.collectors import tasking
from agent.collectors.snmp import as_auth, snmp_credentials
from agent import notes
from agent.notes import Note, probe_note

#: Techo de sondeos por barrido. Un encargo es un gesto de una persona; veinte
#: gestos pendientes son muchos, y doscientos son un bucle roto en el servidor.
MAX_PROBES = 20

SSH_PORT = 22
CONNECT_TIMEOUT_SECONDS = 3


def report_for(ip: str, ctx: dict) -> dict[str, Any]:
    """El informe de una IP: una línea por protocolo. Nunca lanza: cada
    protocolo se defiende solo.

    Cada línea va en castellano, como siempre, y en `codes` su código y datos:
    el servidor la escribe en el idioma de quien la lee en la bandeja. Un
    servidor anterior a los códigos enseña el texto y no mira `codes`.
    """
    report: dict[str, Any] = {}
    codes: dict[str, dict[str, Any]] = {}
    refused = _excluded(ip, ctx)
    for name, check in (("snmp", _snmp_line), ("ssh", _ssh_line), ("winrm", _winrm_line)):
        try:
            # Una dirección excluida en esta máquina no se sondea, aunque lo
            # pida una persona desde la web: quien la excluyó está aquí, y
            # manda. La línea lo dice para que nadie piense que no contesta.
            line = (
                probe_note(name, "excluded", "dirección excluida en este agente; no se sondea")
                if refused
                else check(ip, ctx)
            )
        except Exception as exc:  # noqa: BLE001 - un informe a medias vale más que ninguno
            line = probe_note(
                name, "check_failed", f"no se pudo comprobar ({type(exc).__name__})", error=type(exc).__name__
            )
        report[name] = str(line)
        # Una línea sin código (un texto suelto) viaja sin él: el servidor la
        # enseña tal cual, igual que una nota de colector sin código.
        entry = notes.to_json(line)
        codes[name] = {"code": entry["code"], "params": entry["params"]}
    report["codes"] = codes
    report["at"] = datetime.now(timezone.utc).isoformat()
    return report


def findings_for(ctx: dict) -> list[dict[str, Any]]:
    """Los encargos del servidor, ya sondeados, como items listos de empujar.

    La identidad es la IP: el servidor fusiona por payload con la fila que ya
    estaba en la bandeja (`_match_by_payload`), y al recibir el informe borra
    el encargo -- por eso no hace falta confirmarlo por otro canal.
    """
    requested = (ctx.get("config") or {}).get("probe_ips") or []
    items: list[dict[str, Any]] = []
    for raw in list(requested)[:MAX_PROBES]:
        ip = str(raw).strip()
        if not ip:
            continue
        items.append(
            {
                "kind": "host",
                "identity": {"ip": ip},
                "payload": {"ip": ip, "probe_report": report_for(ip, ctx), "seen_by": "probe"},
            }
        )
    return items


def _port_open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT_SECONDS):
            return True
    except OSError:
        return False


def _auth_label(auth: Any, index: int) -> str:
    """Cómo citar una credencial sin citarla: una comunidad ES un secreto."""
    if isinstance(auth, str):
        return f"la comunidad nº {index}"
    return f"el usuario v3 «{auth.username}»"


def _excluded(ip: str, ctx: dict) -> bool:
    return tasking.excluded(ctx, ip)


def _remember(ctx: dict, ip: str, protocol: str, credential: creds.Credential) -> None:
    """Lo que entró, a la memoria: el próximo inventario empezará por ella.

    Solo el acierto. Un sondeo es una petición explícita de una persona y
    prueba todo lo que está en alcance, así que ni mira ni toca el veto de 24 h
    de las rondas fallidas: no cuenta como una ronda del agente.
    """
    tasking.settle(ctx, ip, "", protocol, credential, attempted=True, full=False)


def _snmp_line(ip: str, ctx: dict) -> Note:
    if not snmp.AVAILABLE:
        return probe_note("snmp", "missing_library", "sin pysnmp en el agente (pip install -r agent/requirements.txt)")
    # El número es el de la lista entera (usuarios v3 delante, comunidades
    # detrás), también para las que se saltan por alcance: así «la comunidad
    # nº 2» es siempre la misma, se pruebe o no.
    for index, credential in enumerate(snmp_credentials(ctx), start=1):
        if not credential.covers(ip):
            continue
        auth = as_auth(credential)
        if snmp.query_hosts([ip], [auth]):
            _remember(ctx, ip, "snmp", credential)
            text = f"contesta con {_auth_label(auth, index)}"
            if isinstance(auth, str):
                # El número, nunca la comunidad: es un secreto.
                return probe_note("snmp", "answers_community", text, index=index)
            return probe_note("snmp", "answers_v3_user", text, username=auth.username)
    return probe_note("snmp", "silent", "no contesta: SNMP apagado, o comunidad/usuario equivocados")


def _ssh_line(ip: str, ctx: dict) -> Note:
    if not _port_open(ip, SSH_PORT):
        return probe_note("ssh", "closed", "puerto 22 cerrado", port=SSH_PORT)
    credentials = creds.for_kind(ctx, creds.SSH)
    if not credentials:
        return probe_note("ssh", "open_no_credentials", "puerto 22 abierto; sin credenciales SSH configuradas", port=SSH_PORT)
    for credential in credentials:
        if not credential.covers(ip):
            continue
        answer = ssh.run(
            host=ip,
            username=credential.username,
            secret=credential.secret,
            port=credential.port,
            key_file=credential.key_file,
            command="true",
        )
        if answer.connected:
            _remember(ctx, ip, "ssh", credential)
            return probe_note(
                "ssh", "logged_in", f"puerto abierto; entró con «{credential.username}»", username=credential.username
            )
    return probe_note("ssh", "none_worked", "puerto abierto; ninguna credencial entró")


def _winrm_line(ip: str, ctx: dict) -> Note:
    open_port = next(
        (port for port in (winrm.DEFAULT_PORT, winrm.DEFAULT_TLS_PORT) if _port_open(ip, port)),
        0,
    )
    if not open_port:
        return probe_note(
            "winrm",
            "closed",
            f"puertos {winrm.DEFAULT_PORT}/{winrm.DEFAULT_TLS_PORT} cerrados",
            ports=f"{winrm.DEFAULT_PORT}/{winrm.DEFAULT_TLS_PORT}",
        )
    credentials = creds.for_kind(ctx, creds.WINRM)
    if not credentials:
        return probe_note(
            "winrm", "open_no_credentials", f"puerto {open_port} abierto; sin credenciales WinRM configuradas", port=open_port
        )
    last_error = ""
    for credential in credentials:
        if not credential.covers(ip):
            continue
        answer = winrm.query(
            host=ip,
            username=credential.username,
            secret=credential.secret,
            port=credential.port or open_port,
            ca_file=creds.ca_file_for(ctx, credential),
        )
        if answer.connected:
            _remember(ctx, ip, "winrm", credential)
            return probe_note(
                "winrm",
                "logged_in",
                f"puerto {open_port} abierto; entró con «{credential.username}»",
                port=open_port,
                username=credential.username,
            )
        last_error = answer.error
    detail = f" ({last_error[:80]})" if last_error else ""
    return probe_note(
        "winrm",
        "none_worked",
        f"puerto {open_port} abierto; ninguna credencial entró{detail}",
        port=open_port,
        detail=last_error[:80],
    )
