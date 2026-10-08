"""L3: WinRM.

Lo mismo que el colector SSH, para el otro lado de la sala: a los hosts vivos
con el 5985 (o el 5986) abierto se les pregunta por PowerShell quién son.

Un Windows sabe de sí mismo bastante más que un Linux: además del nombre, la
versión y el hardware, dice **si está en un dominio y qué papel juega en él**.
Eso último es lo que convierte una lista de servidores en un mapa: saber cuál
es el controlador de dominio y cuál tiene Hyper-V es media respuesta a «¿de qué
depende esto?», que es la pregunta que vende el producto.

Si un Windows no tiene WinRM (5985/5986 cerrados) pero sí el 135, y el agente
corre en Windows, se le pregunta por WMI sobre DCOM con las mismas credenciales
(`agent.dcom`): ver `_dcom_targets`. Si WinRM contestó y rechazó la credencial,
DCOM no se prueba: sería un segundo intento fallido contra la misma cuenta.

El hallazgo mantiene el ``kind`` ``host`` y la identidad del barrido: enriquece
la fila que ya está en la bandeja en vez de abrir otra.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from agent import credentials as creds
from agent import dcom, net, winrm
from agent.collectors import register, tasking
from agent.collectors.base import Finding
from agent.notes import collector_note

#: Los dos puertos del servicio. Se prueba el de siempre y, si no, el de TLS:
#: un Windows endurecido tiene el 5985 cerrado y solo escucha en el 5986.
PORTS: tuple[int, ...] = (winrm.DEFAULT_PORT, winrm.DEFAULT_TLS_PORT)
WORKERS = 10
#: Con DCOM cada equipo es un proceso PowerShell: pocos a la vez.
DCOM_WORKERS = 4

#: `Win32_ComputerSystem.DomainRole`. Los dos últimos son controladores de
#: dominio; los demás, miembros o máquinas sueltas. Números y no texto porque es
#: lo que devuelve Windows, y traducirlo aquí evita depender del idioma del
#: sistema operativo -- el mismo motivo por el que la caché ARP se lee con
#: expresiones regulares y no por el título de sus columnas.
DOMAIN_ROLES: dict[int, str] = {
    0: "estación de trabajo suelta",
    1: "estación de trabajo del dominio",
    2: "servidor suelto",
    3: "servidor del dominio",
    4: "controlador de dominio",
    5: "controlador de dominio principal",
}
DOMAIN_CONTROLLER_ROLES = (4, 5)


def roles_of(data: dict[str, Any]) -> list[str]:
    """Para qué sirve esta máquina, en palabras. Lo que se enseña en la bandeja."""
    found: list[str] = []
    try:
        role = int(data.get("domain_role") or 0)
    except (TypeError, ValueError):
        role = 0
    if role in DOMAIN_CONTROLLER_ROLES:
        found.append(DOMAIN_ROLES[role])
    if data.get("hyperv"):
        found.append("host de Hyper-V")
    return found


def interrogate(host: str, port: int, credentials: list[creds.Credential], ctx: dict) -> dict[str, Any]:
    """Lo que ese Windows cuenta de sí mismo, o nada.

    Con la primera credencial que entra se deja de probar. En un Directorio
    Activo esto no es una optimización: cada intento fallido cuenta para la
    política de bloqueo de la cuenta, y un barrido cada quince minutos contra
    cien equipos bloquea al usuario antes de la primera hora.
    """
    return interrogate_with(host, port, credentials, ctx)[0]


def interrogate_with(
    host: str,
    port: int,
    credentials: list[creds.Credential],
    ctx: dict,
    logins: tasking.Logins | None = None,
    transport: str = "winrm",
) -> tuple[dict[str, Any], creds.Credential | None]:
    """``interrogate``, y además con qué credencial se entró: la memoria la
    recuerda para empezar por ella la próxima vez.

    Cada intento pasa por `logins` (el límite global de credenciales, spec
    2.3): es aquí donde una clave de dominio equivocada bloquearía la cuenta.
    `transport` ``"dcom"`` hace la misma pregunta por WMI/DCOM (el `port` se
    ignora): mismo veto, mismo cortacircuitos, mismos veredictos.
    """
    for credential in credentials:

        def call(credential: creds.Credential = credential) -> winrm.Answer:
            if transport == "dcom":
                return dcom.query(host=host, username=credential.username, secret=credential.secret)
            return winrm.query(
                host=host,
                username=credential.username,
                secret=credential.secret,
                port=credential.port or port,
                ca_file=creds.ca_file_for(ctx, credential),
            )

        answer = call() if logins is None else logins.run(credential, call, winrm.outcome)
        if answer is not tasking.SKIPPED and answer.connected:
            return answer.data or {}, credential
    return {}, None


@register
class WinrmCollector:
    name = "winrm"

    def collect(self, ctx: dict) -> list[Finding]:
        errors = ctx.setdefault("errors", [])
        if not winrm.AVAILABLE:
            errors.append(
                collector_note("winrm", "missing_library", "falta pywinrm (pip install -r agent/requirements.txt)")
            )
            return []
        if "hosts" not in ctx:
            errors.append(
                collector_note(
                    "winrm", "sweep_not_run", "el barrido no ha corrido antes; revisa RUN_ORDER en agent/collectors."
                )
            )
            return []
        credentials = creds.for_kind(ctx, creds.WINRM)
        if not credentials:
            errors.append(
                collector_note(
                    "winrm", "no_credentials", "no hay credenciales de Windows configuradas (Ajustes -> Agentes -> Barrido)"
                )
            )
            return []

        hosts = ctx["hosts"] or []
        if not hosts:
            return []
        by_ip = {
            host["ip"]: host.get("mac", "") for host in hosts if host.get("ip") and tasking.wanted(ctx, host["ip"])
        }

        # Qué puerto tiene abierto cada uno. Se mira antes de autenticarse por lo
        # mismo que en SSH: intentar entrar en los ciento veinte equipos que
        # contestaron al ping se come el barrido en tiempos de espera.
        # Los puertos salen también de las credenciales y no solo de los dos de
        # fábrica: un Windows con WinRM en un puerto propio se caía de la lista
        # aquí, antes de que nadie probara su credencial y sin dejar ni una línea
        # en `errors`. El puerto escrito a mano se sondea primero: si alguien se
        # ha molestado en ponerlo, es el que quiere.
        ports = list(
            dict.fromkeys(
                [credential.port for credential in credentials if credential.port] + list(PORTS)
            )
        )
        targets: list[tuple[str, int]] = []
        pending = list(by_ip)
        for port in ports:
            if not pending:
                break
            listening = set(net.hosts_listening(pending, port, **tasking.listen_options(ctx)))
            targets.extend((ip, port) for ip in pending if ip in listening)
            pending = [ip for ip in pending if ip not in listening]
        # Windows sin WinRM: los que no abrieron ningún puerto de WinRM y tienen
        # el 135. Solo los que no escuchan: uno que escucha y rechazó la
        # credencial ya cuenta como intento fallido de esa cuenta.
        dcom_ips = _dcom_targets(ctx, pending, credentials)
        if not targets and not dcom_ips:
            return []

        def usable(port: int) -> list[creds.Credential]:
            """Las credenciales que aplican al puerto que se encontró abierto.

            Una sin puerto vale para cualquiera; una que lo trae escrito solo
            vale para el suyo. Probar las demás son intentos fallidos de más, y
            contra un Directorio Activo eso bloquea la cuenta: es el mismo
            motivo por el que `interrogate` para en la primera que entra.
            """
            return [c for c in credentials if (c.port or port) == port]

        all_targets: list[tuple[str, int, str]] = [(ip, port, "winrm") for ip, port in targets]
        all_targets += [(ip, dcom.PORT, "dcom") for ip in dcom_ips]
        progress = tasking.Progress(ctx, self.name, len(all_targets))

        def visit(target: tuple[str, int, str]) -> dict[str, Any]:
            """Un equipo: qué credenciales tocan (alcance y memoria), y entrar."""
            ip, port, transport = target
            try:
                # DCOM no tiene puerto propio de credencial: valen las que no
                # fijan uno (un puerto escrito es de un WinRM concreto).
                candidates = usable(port) if transport == "winrm" else [c for c in credentials if not c.port]
                order, full = tasking.plan(ctx, ip, by_ip[ip], "winrm", candidates)
                if not order:
                    # La memoria dice que hoy no toca: ni un intento contra un
                    # dominio que cuenta los fallos.
                    return {}
                logins = tasking.Logins(ctx, self.name, "winrm", ip, by_ip[ip])
                data, credential = interrogate_with(ip, port, order, ctx, logins, transport)
                full = full and not logins.skipped
                tasking.settle(ctx, ip, by_ip[ip], "winrm", credential, attempted=True, full=full)
                if credential is not None and not data:
                    tasking.record(ctx, ip, "winrm", tasking.UNRECOGNISED, credential)
                return data
            finally:
                progress.tick()

        # Cada DCOM es un PowerShell entero (decenas de MB y varios segundos):
        # menos a la vez que las conexiones WinRM, que son sockets.
        pool_size = tasking.workers(ctx, "login", WORKERS)
        if dcom_ips:
            pool_size = min(pool_size, DCOM_WORKERS)
        with ThreadPoolExecutor(max_workers=pool_size) as pool:
            answers = list(pool.map(visit, all_targets))

        findings: list[Finding] = []
        for (ip, _port, transport), data in zip(all_targets, answers):
            if not data:
                continue
            findings.append(host_finding(ip, by_ip.get(ip, ""), data, transport))
        return findings


def _dcom_targets(ctx: dict, pending: list[str], credentials: list[creds.Credential]) -> list[str]:
    """Hosts without WinRM that answer on the RPC port, when DCOM is possible.

    Silent (no error line) when this agent cannot do DCOM: on Linux or Docker
    there is nothing to report, it is simply not a thing that agent does.
    """
    if not pending or not dcom.available() or not any(not c.port for c in credentials):
        return []
    return list(net.hosts_listening(pending, dcom.PORT, **tasking.listen_options(ctx)))


def host_finding(ip: str, sweep_mac: str, data: dict[str, Any], transport: str = "winrm") -> Finding:
    """The finding for one answered Windows; the same for WinRM and DCOM.

    ``transport`` is only added to the payload for DCOM, as a diagnostic.
    """
    interfaces = _interfaces(data)
    own_mac = next((iface["mac"] for iface in interfaces if iface["mac"]), "")
    # La MAC del barrido manda sobre la que diga el equipo: la huella se
    # calcula de la identidad, y cambiar de MAC entre barridos abre una
    # segunda fila en la bandeja para un equipo que ya estaba.
    identity = {"mac": sweep_mac or own_mac} if (sweep_mac or own_mac) else {"ip": ip}
    description = " ".join(
        part for part in (str(data.get("os") or ""), str(data.get("os_version") or "")) if part
    ).strip()
    payload: dict[str, Any] = {
        "hostname": str(data.get("hostname") or ""),
        "ip": ip,
        "mac": sweep_mac or own_mac,
        "description": description,
        "os": description,
        "domain": str(data.get("domain") or "") if data.get("in_domain") else "",
        "roles": roles_of(data),
        "manufacturer": str(data.get("manufacturer") or ""),
        "model": str(data.get("model") or ""),
        "serial": str(data.get("serial") or ""),
        "interfaces": interfaces,
        "seen_by": "winrm",
    }
    if transport != "winrm":
        payload["transport"] = transport
    return Finding(kind="host", identity=identity, payload=payload)


def _interfaces(data: dict[str, Any]) -> list[dict[str, str]]:
    """Las interfaces con IP, normalizadas.

    Windows escribe las MAC con guiones y en mayúsculas; el resto del producto
    las guarda con dos puntos y en minúsculas. Sin normalizar aquí, la misma
    tarjeta vista por el barrido y por WinRM parecían dos.
    """
    found: list[dict[str, str]] = []
    for raw in data.get("interfaces") or []:
        if not isinstance(raw, dict):
            continue
        mac = str(raw.get("mac") or "").strip().lower().replace("-", ":")
        name = str(raw.get("name") or "").strip()
        if not name:
            continue
        found.append({"name": name, "mac": mac, "status": "up", "ip": str(raw.get("ip") or "")})
    return found
