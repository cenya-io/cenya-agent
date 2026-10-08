"""L2: SNMP.

Every live host from the sweep gets asked what it is: identity (sysDescr,
sysName), its real interfaces with their MACs and state, and its addresses.
The finding keeps the ``host`` kind and the MAC identity, so instead of a
second row in the tray it *enriches* the one the sweep already filed -- same
fingerprint, better payload.
"""

from __future__ import annotations

from agent import credentials as creds
from agent import profiles
from agent import snmp
from agent.collectors import register, tasking
from agent.collectors.base import Finding
from agent.notes import collector_note

#: Cuántas MAC de cada boca viajan en ``fdb_ports`` como mucho; el recuento
#: real va aparte. Acordado con el servidor (`core/port_placement.py`).
MAX_MACS_PER_PORT = 64

#: Una MAC con tantas IP o más en las tablas ARP es un equipo que enruta (proxy
#: ARP, VPN): se conoce, pero sin IP. El mismo umbral que el servidor.
ROUTER_MIN_IPS = 5


def _has_sealed_communities(ctx: dict) -> bool:
    """Si el servidor manda comunidades como credenciales `snmp` (spec 3.2), legibles o no."""
    return any(
        isinstance(item, dict) and str(item.get("kind") or "").strip().lower() == creds.SNMP
        for item in creds.raw_list(ctx)
    )


def _communities(ctx: dict) -> list[str]:
    server = (ctx.get("config") or {}).get("communities") or []
    if server:
        return list(server)
    env = ctx.get("env")
    if env and env.communities:
        return list(env.communities)
    if _has_sealed_communities(ctx):
        # Alguien escribió sus comunidades: «public» era solo el valor de quien
        # no había dicho nada. Si las suyas no abren, probar «public» en su
        # lugar no es lo que pidió.
        return []
    return ["public"]


def _auths(ctx: dict) -> list:
    """With what to ask, in trying order: v3 users first, communities after.

    First because they are the stronger claim: a device configured for v3
    usually has v2c switched off, and a v2c-only device rejects the v3 user in
    one packet. The other way round, a device with both would always answer to
    the community and the v3 user nobody typed for fun would never be used.
    """
    return [as_auth(credential) for credential in snmp_credentials(ctx)]


def snmp_credentials(ctx: dict) -> list[creds.Credential]:
    """Lo mismo que ``_auths``, todo como credenciales: así la memoria recuerda
    una comunidad igual que un usuario v3. La comunidad de la lista vieja se
    identifica por su número (`community-1`...), nunca por su valor; la que
    llega como credencial `snmp`, por su `id`. Las selladas van delante de las
    de la lista: son las que alguien escribió en la pantalla nueva."""
    return (
        list(creds.for_kind(ctx, creds.SNMPV3))
        + list(creds.for_kind(ctx, creds.SNMP))
        + [creds.community(value, index) for index, value in enumerate(_communities(ctx), start=1)]
    )


def as_auth(credential: creds.Credential) -> snmp.Auth:
    """De credencial a lo que entiende `agent.snmp`: una comunidad es su texto."""
    return credential.secret if credential.kind in (creds.COMMUNITY, creds.SNMP) else credential


def _device_mac(data: dict) -> str:
    """La MAC con la que el inventario presenta al equipo: la de su primera
    interfaz con nombre y MAC. La tarea `ups` tiene que repetir esta misma."""
    return next((iface["mac"] for iface in data.get("interfaces") or [] if iface.get("name") and iface.get("mac")), "")


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

        if tasking.task(ctx) is not None:
            return self._planned(ctx, hosts)
        answers = snmp.query_hosts([host["ip"] for host in hosts], _auths(ctx))
        return _inventory_findings(hosts, answers)

    def _planned(self, ctx: dict, hosts: list[dict]) -> list[Finding]:
        """Dentro de una tarea: cada equipo con sus credenciales, en el orden
        de la memoria; `ups` solo contra los SAI ya conocidos y solo la UPS-MIB."""
        ups_task = tasking.task(ctx) == "ups"
        if ups_task:
            mem = tasking.memory(ctx)
            if mem is None:
                # Sin memoria no se sabe quién es un SAI. No es un error: es
                # que la tarea no tiene a quién preguntar.
                return []
            alive = tasking.alive_from_memory(ctx, mem.ups_hosts())
            selected = [(ip, mac) for ip, mac, _entry in alive]
            identities = {ip: str(entry.get("identity_mac") or "") for ip, _mac, entry in alive}
        else:
            selected = [
                (host["ip"], str(host.get("mac") or "")) for host in hosts if tasking.wanted(ctx, host.get("ip", ""))
            ]
            identities = {}

        candidates = snmp_credentials(ctx)
        plan: dict[str, list[snmp.Auth]] = {}
        orders: dict[str, tuple[str, list[creds.Credential], bool]] = {}
        for ip, mac in selected:
            order, full = tasking.plan(ctx, ip, mac, "snmp", candidates)
            if not order:
                continue
            plan[ip] = [as_auth(credential) for credential in order]
            orders[ip] = (mac, order, full)
        if not plan:
            return []

        progress = tasking.Progress(ctx, self.name, len(plan))
        found = snmp.query_plan(
            plan,
            concurrency=tasking.workers(ctx, "snmp", snmp.CONCURRENCY),
            ups_only=ups_task,
            on_done=progress.tick,
        )
        answers: dict[str, dict] = {}
        for ip, (mac, order, full) in orders.items():
            hit = found.get(ip)
            credential = None
            if hit is not None and 0 <= hit[0] < len(order):
                credential = order[hit[0]]
                answers[ip] = hit[1]
            if not ups_task:
                tasking.record(ctx, ip, "snmp", tasking.LOGGED_IN if credential else tasking.SILENT, credential)
            tasking.settle(ctx, ip, mac, "snmp", credential, attempted=True, full=full)

        if ups_task:
            return _ups_findings(answers, orders, identities)

        for ip, data in answers.items():
            mac = orders[ip][0]
            # El inventario es quien descubre los SAI: lo que contesta a la
            # UPS-MIB queda apuntado, con la MAC con la que se le presentó,
            # para que la tarea `ups` refresque la misma fila.
            if data.get("ups"):
                tasking.flag(ctx, ip, mac, ups=True, identity_mac=_device_mac(data))
            else:
                tasking.flag(ctx, ip, mac, ups=False)
        return _inventory_findings(hosts, answers)


def _ups_findings(
    answers: dict[str, dict], orders: dict[str, tuple[str, list, bool]], identities: dict[str, str]
) -> list[Finding]:
    """La lectura del SAI, como el mismo hallazgo `host` que dejó el inventario.

    Misma identidad --la MAC guardada en la memoria-- para que el servidor
    refresque la fila que ya existe en vez de abrir otra. Solo lo que esta
    tarea sabe: ni nombre ni interfaces, que no ha preguntado, para no pisar
    con vacíos lo que el inventario sí trajo.
    """
    findings: list[Finding] = []
    for ip, data in answers.items():
        reading = data.get("ups") or {}
        if not reading:
            # Contestó, pero ya no da los minutos: no se inventa una lectura.
            continue
        identity_mac = identities.get(ip, "")
        mac = identity_mac or orders[ip][0]
        findings.append(
            Finding(
                kind="host",
                identity={"mac": identity_mac} if identity_mac else {"ip": ip},
                payload={"ip": ip, "mac": mac, "ups": reading, "seen_by": "snmp"},
            )
        )
    return findings


def _inventory_findings(hosts: list[dict], answers: dict[str, dict]) -> list[Finding]:
    """Lo que contestaron los equipos, como hallazgos `host` y `link`."""
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
    # And every MAC in the ARP table of any device that answered: that is how
    # a camera in another VLAN, which the sweep of this subnet never sees,
    # gets its IP and its link. What the sweep saw itself wins (it is the
    # freshest), and a MAC answering for many IPs is a router doing proxy ARP:
    # it is still known, but with none of them.
    for mac, ips in _arp_ips(answers).items():
        if mac not in known:
            only = sorted(ips)[0] if len(ips) < ROUTER_MIN_IPS else ""
            known[mac] = {"ip": only, "hostname": ""}

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
                    # What the device is, through its vendor profile
                    # (`agent/profiles`): manufacturer, model, serial, os,
                    # os_version. Only the fields with a value: a device
                    # nobody recognises carries exactly the payload it
                    # always did, no empty keys.
                    **_identity_fields(data),
                    # Solo si contestó a la UPS-MIB. Va dentro del mismo
                    # hallazgo y no en uno aparte: un SAI es un equipo más,
                    # y la huella tiene que seguir siendo una sola fila.
                    **({"ups": data["ups"]} if data.get("ups") else {}),
                    # Sus tablas, para que el servidor deduzca quién está
                    # detrás de qué boca (formato 2 del hallazgo; las dos
                    # opcionales, y solo si traen algo).
                    **({"arp": data["arp"]} if data.get("arp") else {}),
                    **({"fdb_ports": ports} if (ports := _port_tables(data)) else {}),
                    # Only for a stack (two or more chassis in ENTITY-MIB);
                    # never an empty list.
                    **({"members": data["members"]} if data.get("members") else {}),
                },
            )
        )
        findings.extend(_links_for(ip, data, device_mac, known))
    return findings


def _identity_fields(data: dict) -> dict[str, str]:
    """The identity's payload fields, or nothing when the inventory brought
    no `Identity` (an older answer shape, or a test double without one)."""
    identity = data.get("identity")
    if not isinstance(identity, profiles.Identity):
        return {}
    return identity.payload_fields()


def _arp_ips(answers: dict[str, dict]) -> dict[str, set[str]]:
    """MAC -> every IP the ARP tables of all the answering devices give it."""
    found: dict[str, set[str]] = {}
    for data in answers.values():
        for entry in data.get("arp") or []:
            if entry.get("mac") and entry.get("ip"):
                found.setdefault(entry["mac"], set()).add(entry["ip"])
    return found


def _port_tables(data: dict) -> list[dict]:
    """The forwarding table grouped by port: how many MACs each one sees and,
    at most `MAX_MACS_PER_PORT`, which. The server counts with it which port
    is closest to each device; the links only carry the known ones."""
    names = {iface["index"]: iface["name"] for iface in data["interfaces"]}
    ports: dict[str, list[str]] = {}
    for entry in data.get("fdb") or []:
        port = names.get(entry["ifindex"], "")
        if port and entry["mac"] not in ports.setdefault(port, []):
            ports[port].append(entry["mac"])
    return [
        {"port": port, "count": len(macs), "macs": macs[:MAX_MACS_PER_PORT]}
        for port, macs in ports.items()
    ]


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

    proposed: set[tuple[str, str]] = set()
    for entry in data.get("fdb") or []:
        mac = entry["mac"]
        if mac == device_mac or mac not in known:
            continue
        port = ifindex_names.get(entry["ifindex"], "")
        if not port:
            # "Somewhere on this switch" cannot be cabled to a port; skip it.
            continue
        if (port, mac) in proposed:
            # The same MAC on the same port in a second VLAN is the same cable.
            continue
        proposed.add((port, mac))
        host = known[mac]
        local = {**local_base, "port": port}
        remote = {
            "device_mac": mac,
            "device_name": host["hostname"],
            "device_ip": host["ip"],
            "port": "",
        }
        # The VLAN goes in the payload and never in the identity: the link's
        # fingerprint must not change because this version reads VLANs.
        vlan = str(entry.get("vlan") or "")
        links.append(_link("fdb", local, remote, vlan=int(vlan) if vlan.isdigit() else None))
    return links


def _link(protocol: str, local: dict, remote: dict, *, vlan: int | None = None) -> Finding:
    payload: dict = {"protocol": protocol, "local": local, "remote": remote}
    if vlan is not None:
        payload["vlan"] = vlan
    return Finding(
        kind="link",
        identity={"local": local, "remote": remote},
        payload=payload,
    )
