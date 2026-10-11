"""Redfish: entra en las tarjetas de control remoto y cuenta su servidor.

**Solo en las tarjetas** (decidido el 11-10-2026): las IP que el colector de
huella reconoció por su panel web (iDRAC, iLO) o el de SNMP por su perfil
(``dell-idrac``) quedan en ``ctx["cards"]``, y este colector va detrás de los
dos en ``RUN_ORDER``. La contraseña de la tarjeta nunca viaja a un equipo que
no lo es.

Cada tarjeta es un hallazgo ``host`` con la misma identidad que el barrido, para
que se funda con el de su panel o su SNMP, y con lo que dice
``agent/redfish.py``. El certificado se fija la primera vez en la memoria del
agente, como SSH. Las credenciales pasan por el mismo cortacircuitos que WinRM
(`tasking.Logins`): con la primera que entra se deja de probar.

Un colector que no puede correr anota en ``ctx["errors"]`` y devuelve ``[]``;
nunca lanza.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

from agent import credentials as creds
from agent import redfish
from agent.collectors import register, tasking
from agent.collectors.base import Finding
from agent.notes import collector_note

#: La clave de ``ctx`` donde los colectores anteriores dejan las tarjetas: ``{ip: nombre}``.
CARDS = "cards"
WORKERS = 8
PROTOCOL = "redfish"


def mark_card(ctx: dict, ip: str, name: str) -> None:
    """Apunta que esa IP es una tarjeta. Lo llaman el colector de huella y el de SNMP."""
    if ip and name:
        try:
            ctx.setdefault(CARDS, {}).setdefault(ip, name)
        except Exception:  # noqa: BLE001 - una marca no tumba un colector
            pass


def _host_key(ctx: dict, ip: str, mac: str) -> str:
    return tasking.host_key(ctx, ip, mac)


def interrogate(ctx: dict, ip: str, mac: str, hint: str, order: list[creds.Credential]) -> tuple[dict[str, Any], creds.Credential | None]:
    """Prueba las credenciales en orden contra esa tarjeta; con la primera que entra, para."""
    mem = tasking.memory(ctx)
    key = _host_key(ctx, ip, mac) if mem is not None else ""
    pin = ""
    if mem is not None:
        try:
            pin = mem.pin_for(key, PROTOCOL)
        except Exception:  # noqa: BLE001 - la memoria es prescindible
            pin = ""
    logins = tasking.Logins(ctx, "redfish", PROTOCOL, ip, mac)
    for credential in order:

        def call(credential: creds.Credential = credential) -> redfish.Answer:
            return redfish.read(ip, credential.username, credential.secret, pin=pin, card_hint=hint)

        answer = logins.run(credential, call, redfish.outcome)
        if answer is tasking.SKIPPED:
            continue
        if answer.pin and not pin:
            # La primera vez que se ve esa tarjeta: su certificado queda fijado,
            # haya entrado o no la contraseña. Es `accept-new`.
            pin = answer.pin
            if mem is not None:
                try:
                    mem.remember_pin(key, PROTOCOL, pin)
                except Exception:  # noqa: BLE001
                    pass
        if answer.connected:
            return answer.data, credential
        if answer.code in (redfish.CERTIFICATE_CHANGED, redfish.NOT_REDFISH, redfish.UNREACHABLE):
            # Ni otra credencial lo arreglaría: no se sigue mandando contraseñas.
            break
    full = not logins.skipped
    tasking.settle(ctx, ip, mac, PROTOCOL, None, attempted=bool(order), full=full)
    return {}, None


@register
class RedfishCollector:
    name = "redfish"

    def collect(self, ctx: dict) -> list[Finding]:
        cards = ctx.get(CARDS)
        if not isinstance(cards, dict) or not cards:
            return []
        macs = {host["ip"]: str(host.get("mac") or "") for host in ctx.get("hosts") or [] if host.get("ip")}
        wanted = {ip: name for ip, name in cards.items() if tasking.wanted(ctx, ip)}
        if not wanted:
            return []
        credentials = creds.for_kind(ctx, creds.REDFISH)
        if not credentials:
            ctx.setdefault("errors", []).append(
                collector_note(
                    "redfish",
                    "no_credentials",
                    "hay tarjetas de control remoto y ninguna credencial Redfish las cubre (Descubrimiento -> Credenciales)",
                )
            )
            for ip in wanted:
                tasking.record(ctx, ip, PROTOCOL, tasking.NO_CREDENTIALS)
            return []
        progress = tasking.Progress(ctx, self.name, len(wanted))

        def visit(item: tuple[str, str]) -> tuple[str, dict[str, Any]]:
            ip, hint = item
            mac = macs.get(ip, "")
            try:
                order, _full = tasking.plan(ctx, ip, mac, PROTOCOL, credentials)
                if not order:
                    if not any(credential.covers(ip) for credential in credentials):
                        tasking.record(ctx, ip, PROTOCOL, tasking.NO_CREDENTIALS)
                    return ip, {}
                data, credential = interrogate(ctx, ip, mac, hint, order)
                if credential is not None:
                    tasking.settle(ctx, ip, mac, PROTOCOL, credential, attempted=True, full=True)
                return ip, data
            except Exception:  # noqa: BLE001 - una tarjeta rara no tumba a las demás
                return ip, {}
            finally:
                progress.tick()

        with ThreadPoolExecutor(max_workers=tasking.workers(ctx, "login", WORKERS)) as pool:
            answers = list(pool.map(visit, wanted.items()))

        findings: list[Finding] = []
        for ip, data in answers:
            if not data:
                continue
            mac = macs.get(ip, "")
            payload: dict[str, Any] = {"ip": ip, "seen_by": "redfish", **data}
            if mac:
                payload["mac"] = mac
            findings.append(Finding(kind="host", identity={"mac": mac} if mac else {"ip": ip}, payload=payload))
        return findings
