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


# --- Un intento con una credencial (lo comparten «Analizar» y «Probar credencial») ---


def _snmp_answers(ip: str, ctx: dict, credential: creds.Credential) -> bool:
    """¿Contesta ese equipo por SNMP con esa credencial? Si sí, a la memoria."""
    if snmp.query_hosts([ip], [as_auth(credential)]):
        _remember(ctx, ip, "snmp", credential)
        return True
    return False


def _ssh_logs_in(ip: str, ctx: dict, credential: creds.Credential) -> ssh.Answer | None:
    """Un intento de SSH con esa credencial, por el cortacircuitos (spec 2.3).

    Lo pide una persona (`explicit`): puede probar una credencial suspendida,
    una vez, y si entra la levanta; un fallo cuenta igual que cualquier otro.
    """

    def call() -> ssh.Answer:
        return ssh.run(
            host=ip,
            username=credential.username,
            secret=credential.secret,
            port=credential.port,
            key_file=credential.key_file,
            command="true",
        )

    answer = tasking.Logins(ctx, "probe", "ssh", ip, explicit=True).run(credential, call, ssh.outcome)
    if answer is tasking.SKIPPED:
        return None
    if answer.connected:
        _remember(ctx, ip, "ssh", credential)
    return answer


def _ssh_failed_line(answers: list[ssh.Answer | None]) -> Note:
    """Por qué no entró: si ni se llegó a ofrecer la contraseña, se dice eso.

    «Ninguna credencial entró» hace pensar en una contraseña mal escrita; con
    un equipo que no comparte ningún algoritmo con este, la contraseña ni salió.
    """
    if answers and all(answer is not None and ssh.negotiation_failed(answer.error) for answer in answers):
        return probe_note(
            "ssh", "no_common_algorithms",
            "puerto abierto, pero el equipo solo habla un SSH antiguo que el de este equipo no admite; la contraseña no llegó a enviarse",
        )
    return probe_note("ssh", "none_worked", "puerto abierto; ninguna credencial entró")


def _winrm_logs_in(ip: str, ctx: dict, credential: creds.Credential, open_port: int) -> tuple[bool, str]:
    def call() -> winrm.Answer:
        return winrm.query(
            host=ip,
            username=credential.username,
            secret=credential.secret,
            port=credential.port or open_port,
            ca_file=creds.ca_file_for(ctx, credential),
        )

    answer = tasking.Logins(ctx, "probe", "winrm", ip, explicit=True).run(credential, call, winrm.outcome)
    if answer is tasking.SKIPPED:
        return False, ""
    if answer.connected:
        _remember(ctx, ip, "winrm", credential)
        return True, ""
    return False, answer.error or ""


#: Las clases que se prueban contra una IP, y con qué protocolo del informe.
TESTABLE = {
    creds.SNMP: "snmp",
    creds.SNMPV3: "snmp",
    creds.SSH: "ssh",
    creds.WINRM: "winrm",
}


def test_line(ip: str, ctx: dict, credential: creds.Credential) -> tuple[bool, Note]:
    """Una credencial concreta contra una IP: ``(entró, línea)``. Nunca lanza.

    El encargo `test_credential` (spec 3.3): lo pide una persona, así que ni
    mira ni toca el veto de 24 h de la memoria, pero un acierto sí se apunta.
    La línea es la de un informe de «Analizar», con los mismos códigos, y no
    cita nunca el secreto: una comunidad no se nombra, un usuario sí.
    """
    protocol = TESTABLE.get(credential.kind, credential.kind)
    try:
        if protocol == "snmp":
            if not snmp.AVAILABLE:
                return False, probe_note("snmp", "missing_library", "sin pysnmp en el agente")
            if not _snmp_answers(ip, ctx, credential):
                return False, probe_note("snmp", "silent", "no contesta: SNMP apagado, o comunidad/usuario equivocados")
            if credential.kind == creds.SNMPV3:
                return True, probe_note(
                    "snmp", "answers_v3_user", f"contesta con el usuario v3 «{credential.username}»",
                    username=credential.username,
                )
            return True, probe_note("snmp", "answers", "contesta con esa comunidad")
        if protocol == "ssh":
            if not _port_open(ip, SSH_PORT):
                return False, probe_note("ssh", "closed", "puerto 22 cerrado", port=SSH_PORT)
            answer = _ssh_logs_in(ip, ctx, credential)
            if answer is not None and answer.connected:
                return True, probe_note(
                    "ssh", "logged_in", f"puerto abierto; entró con «{credential.username}»", username=credential.username
                )
            return False, _ssh_failed_line([answer])
        if protocol == "winrm":
            open_port = next(
                (port for port in (winrm.DEFAULT_PORT, winrm.DEFAULT_TLS_PORT) if _port_open(ip, port)), 0
            )
            if not open_port:
                ports = f"{winrm.DEFAULT_PORT}/{winrm.DEFAULT_TLS_PORT}"
                return False, probe_note("winrm", "closed", f"puertos {ports} cerrados", ports=ports)
            connected, _error = _winrm_logs_in(ip, ctx, credential, open_port)
            if connected:
                return True, probe_note(
                    "winrm", "logged_in", f"puerto {open_port} abierto; entró con «{credential.username}»",
                    port=open_port, username=credential.username,
                )
            # Sin el detalle del error: lo escribe el equipo remoto y no se
            # sabe qué repite de lo que se le mandó.
            return False, probe_note("winrm", "none_worked", f"puerto {open_port} abierto; ninguna credencial entró",
                                     port=open_port)
    except Exception as exc:  # noqa: BLE001 - una prueba que revienta es una línea, no un hilo muerto
        return False, probe_note(
            protocol, "check_failed", f"no se pudo comprobar ({type(exc).__name__})", error=type(exc).__name__
        )
    return False, probe_note(protocol, "unsupported", "esta clase de credencial no se prueba contra una IP")


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
        if _snmp_answers(ip, ctx, credential):
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
    answers: list[ssh.Answer | None] = []
    for credential in credentials:
        if not credential.covers(ip):
            continue
        answer = _ssh_logs_in(ip, ctx, credential)
        if answer is not None and answer.connected:
            return probe_note(
                "ssh", "logged_in", f"puerto abierto; entró con «{credential.username}»", username=credential.username
            )
        answers.append(answer)
    return _ssh_failed_line(answers)


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
        connected, error = _winrm_logs_in(ip, ctx, credential, open_port)
        if connected:
            return probe_note(
                "winrm",
                "logged_in",
                f"puerto {open_port} abierto; entró con «{credential.username}»",
                port=open_port,
                username=credential.username,
            )
        last_error = creds.scrub(error, credential)
    detail = f" ({last_error[:80]})" if last_error else ""
    return probe_note(
        "winrm",
        "none_worked",
        f"puerto {open_port} abierto; ninguna credencial entró{detail}",
        port=open_port,
        detail=last_error[:80],
    )
