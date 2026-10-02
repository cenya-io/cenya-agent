"""L2: SNMP.

Every live host from the sweep gets asked what it is: identity (sysDescr,
sysName), its real interfaces with their MACs and state, and its addresses.
The finding keeps the ``host`` kind and the MAC identity, so instead of a
second row in the tray it *enriches* the one the sweep already filed -- same
fingerprint, better payload.
"""

from __future__ import annotations

from agent import credentials as creds
from agent import snmp
from agent.collectors.base import Finding
from agent.collectors import register
from agent.notes import collector_note


def _communities(ctx: dict) -> list[str]:
    server = (ctx.get("config") or {}).get("communities") or []
    if server:
        return list(server)
    env = ctx.get("env")
    if env and env.communities:
        return list(env.communities)
    return ["public"]


def _auths(ctx: dict) -> list:
    """With what to ask, in trying order: v3 users first, communities after.

    First because they are the stronger claim: a device configured for v3
    usually has v2c switched off, and a v2c-only device rejects the v3 user in
    one packet. The other way round, a device with both would always answer to
    the community and the v3 user nobody typed for fun would never be used.
    """
    return list(creds.for_kind(ctx, creds.SNMPV3)) + _communities(ctx)


@register
class SnmpCollector:
    name = "snmp"

    def collect(self, ctx: dict) -> list[Finding]:
        if not snmp.AVAILABLE:
            ctx.setdefault("errors", []).append(
                collector_note("snmp", "missing_library", "falta pysnmp (pip install -r agent/requirements.txt)")
            )
            return []
        if "hosts" not in ctx:
            # El barrido no ha corrido todavía. Callarse aquí es lo que dejó
            # este colector mudo en producción sin que nadie se enterara: la
            # ejecución se marcaba «ok» y no salía ni un hallazgo por SNMP.
            ctx.setdefault("errors", []).append(
                collector_note(
                    "snmp", "sweep_not_run", "el barrido no ha corrido antes; revisa RUN_ORDER en agent/collectors."
                )
            )
            return []
        hosts = ctx["hosts"] or []
        if not hosts:
            # Nadie contestó al barrido. Es una respuesta legítima, no un error.
            return []

        answers = snmp.query_hosts([host["ip"] for host in hosts], _auths(ctx))
        findings = []
        # MACs this sweep already knows: live hosts from the ARP table and the
        # SNMP devices themselves. The forwarding table only proposes links for
        # these -- a whole FDB of stranger MACs is noise, not inventory.
        known: dict[str, dict[str, str]] = {}
        for host in hosts:
            if host.get("mac"):
                known[host["mac"]] = {"ip": host["ip"], "hostname": ""}
        device_macs: dict[str, str] = {}
        for ip, data in answers.items():
            interfaces = [iface for iface in data["interfaces"] if iface["name"]]
            device_mac = next((iface["mac"] for iface in interfaces if iface["mac"]), "")
            device_macs[ip] = device_mac
            if device_mac:
                known.setdefault(device_mac, {"ip": ip, "hostname": data["name"]})

        for ip, data in answers.items():
            interfaces = [iface for iface in data["interfaces"] if iface["name"]]
            device_mac = device_macs[ip]
            identity = {"mac": device_mac} if device_mac else {"ip": ip}
            # Which interface holds the polled IP becomes the management one.
            management = data["addresses"].get(ip, "")
            management_name = next(
                (iface["name"] for iface in interfaces if iface["index"] == management), ""
            )
            findings.append(
                Finding(
                    kind="host",
                    identity=identity,
                    payload={
                        "hostname": data["name"],
                        "ip": ip,
                        "mac": device_mac,
                        "description": data["description"],
                        "interfaces": [
                            {
                                "name": iface["name"],
                                "mac": iface["mac"],
                                "status": iface["status"],
                                "speed_mbps": iface["speed_mbps"],
                            }
                            for iface in interfaces
                        ],
                        "management_interface": management_name,
                        "seen_by": "snmp",
                        # Solo si contestó a la UPS-MIB. Va dentro del mismo
                        # hallazgo y no en uno aparte: un SAI es un equipo más,
                        # y la huella tiene que seguir siendo una sola fila.
                        **({"ups": data["ups"]} if data.get("ups") else {}),
                    },
                )
            )
            findings.extend(_links_for(ip, data, device_mac, known))
        return findings


def _links_for(
    ip: str, data: dict, device_mac: str, known: dict[str, dict[str, str]]
) -> list[Finding]:
    """The cables this device reports: LLDP/CDP neighbours, and the hosts its
    forwarding table places behind each port."""
    links: list[Finding] = []
    local_base = {"device_mac": device_mac, "device_name": data["name"], "device_ip": ip}
    ifindex_names = {iface["index"]: iface["name"] for iface in data["interfaces"]}

    for neighbor in data.get("neighbors") or []:
        remote = {
            "device_mac": neighbor["remote_mac"],
            "device_name": neighbor["remote_name"],
            "device_ip": "",
            "port": neighbor["remote_port"],
        }
        if not any(remote.values()):
            continue
        local = {**local_base, "port": neighbor["local_port"]}
        links.append(_link(neighbor["protocol"], local, remote))

    for entry in data.get("fdb") or []:
        mac = entry["mac"]
        if mac == device_mac or mac not in known:
            continue
        port = ifindex_names.get(entry["ifindex"], "")
        if not port:
            # "Somewhere on this switch" cannot be cabled to a port; skip it.
            continue
        host = known[mac]
        local = {**local_base, "port": port}
        remote = {
            "device_mac": mac,
            "device_name": host["hostname"],
            "device_ip": host["ip"],
            "port": "",
        }
        links.append(_link("fdb", local, remote))
    return links


def _link(protocol: str, local: dict, remote: dict) -> Finding:
    return Finding(
        kind="link",
        identity={"local": local, "remote": remote},
        payload={"protocol": protocol, "local": local, "remote": remote},
    )
