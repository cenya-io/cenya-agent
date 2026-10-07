"""L4: los hipervisores.

vCenter y Proxmox por REST. De cada uno salen dos cosas:

* sus **servidores** (los ESXi del vCenter, los nodos de Proxmox), que son
  equipos como cualquier otro y se fusionan con lo que ya vio el barrido;
* sus **máquinas virtuales**, que no son equipos: aceptarlas crea una
  `VirtualMachine` colgada de su host.

Esto último es lo que enlaza con la pregunta que vende el producto -- «¿de qué
depende este servidor?» --. Sin las VMs, apagar un host es apagar una caja; con
ellas, es apagar el servidor de ficheros, el de correo y la contabilidad.

A diferencia de SSH y WinRM, este colector **no depende del barrido**: un
vCenter tiene una dirección conocida, se escribe en Ajustes y se pregunta ahí.
Un CPD donde el barrido no llega (otra VLAN, otra sede) se inventaría igual.
"""

from __future__ import annotations

from typing import Any

from agent import credentials as creds
from agent import hyperv, hypervisor, net, xcpng
from agent.collectors import register, tasking
from agent.collectors.base import Finding
from agent.notes import collector_note

#: Qué cliente habla con cada cosa. Un hipervisor nuevo es una entrada más aquí
#: y una clase con `login`, `hosts` y `virtual_machines`: el bucle de abajo no
#: cambia. Así entraron Hyper-V (PowerShell sobre WinRM) y XCP-ng (XAPI).
CLIENTS = {
    creds.VMWARE: hypervisor.VMwareClient,
    creds.PROXMOX: hypervisor.ProxmoxClient,
    creds.HYPERV: hyperv.HyperVClient,
    creds.XCPNG: xcpng.XcpNgClient,
}

KIND_LABELS = {
    creds.VMWARE: "vmware",
    creds.PROXMOX: "proxmox",
    creds.HYPERV: "hyperv",
    creds.XCPNG: "xcpng",
}


@register
class HypervisorCollector:
    name = "hypervisors"

    def collect(self, ctx: dict) -> list[Finding]:
        errors = ctx.setdefault("errors", [])
        credentials = [
            credential for kind in CLIENTS for credential in creds.for_kind(ctx, kind)
        ]
        if not credentials:
            errors.append(
                collector_note(
                    "hypervisors",
                    "none_configured",
                    "no hay ningún hipervisor configurado "
                    "(vCenter, Proxmox, Hyper-V o XCP-ng; Ajustes -> Agentes -> Barrido)",
                )
            )
            return []

        findings: list[Finding] = []
        progress = tasking.Progress(ctx, self.name, len(credentials))
        for credential in credentials:
            try:
                findings.extend(self._one(credential, ctx, errors))
            finally:
                progress.tick()
        return findings

    def _one(self, credential: creds.Credential, ctx: dict, errors: list) -> list[Finding]:
        if not credential.host:
            # Sin dirección no hay a quién preguntar: un vCenter no se
            # descubre solo, se escribe. Se dice cuál falla, no se calla.
            name = credential.label or credential.username
            errors.append(
                collector_note(
                    "hypervisors",
                    "credential_without_host",
                    f"la credencial «{name}» no dice contra qué servidor va",
                    credential=name,
                )
            )
            return []
        # Las exclusiones valen siempre, también en el protocolo 1 (spec 2.4).
        # Dentro de una tarea, además, alcance y memoria; sin tarea se pregunta
        # como siempre.
        key = ""
        address = net.resolve(credential.host) if ctx.get("excluded") is not None or tasking.task(ctx) else ""
        if tasking.excluded(ctx, credential.host) or (address and tasking.excluded(ctx, address)):
            # Un servidor excluido en la máquina del agente no se toca, ni
            # siquiera porque alguien haya escrito su credencial en la web.
            # Se dice, para que nadie busque por qué no salen sus VMs.
            errors.append(
                collector_note(
                    "hypervisors",
                    "excluded",
                    f"{credential.host}: dirección excluida en este agente; no se consulta",
                    host=credential.host,
                )
            )
            return []
        if tasking.task(ctx) is not None:
            # La clave de la memoria es la dirección, salvo que el alcance de la
            # credencial nombre al servidor por su nombre: la memoria comprueba
            # el alcance con la clave, y tiene que ser algo que el alcance cubra.
            key = address if address and credential.covers(address) else credential.host
            if not self._allowed(ctx, credential, key, address):
                return []
        try:
            found = self._from(credential, ctx, key or address or credential.host)
            if found is tasking.SKIPPED:
                return []  # suspendida: lo dice su nota (`credential_suspended`)
        except hypervisor.HypervisorError as exc:
            # Un hipervisor caído o una contraseña cambiada no pueden tumbar
            # el barrido: se anota y se sigue con el siguiente. El detalle va
            # tal cual: lo escribe el hipervisor, o es un error de red.
            detail = creds.scrub(str(exc), credential)
            if exc.certificate:
                # Lo arregla una persona en la web: «Probar» la credencial
                # enseña ese certificado y deja confiar en él.
                errors.append(
                    collector_note(
                        "hypervisors",
                        "tls_untrusted",
                        f"{credential.host}: el certificado no es de confianza en este equipo",
                        host=credential.host,
                    )
                )
            else:
                errors.append(
                    collector_note(
                        "hypervisors", "failed", f"{credential.host}: {detail}", host=credential.host, detail=detail
                    )
                )
            self._remember(ctx, key, credential, ok=False)
            return []
        self._remember(ctx, key, credential, ok=True)
        tasking.note_ok(ctx, credential, credential.host)
        return found

    @staticmethod
    def _allowed(ctx: dict, credential: creds.Credential, key: str, address: str) -> bool:
        """¿Toca preguntar a ese servidor con esa credencial en esta pasada?

        El alcance, si la credencial lo tiene; y la memoria: una credencial que
        nunca ha entrado y falló en las últimas 24 h espera al día siguiente (o
        a que alguien la cambie). Una que ya entró alguna vez se prueba siempre:
        un vCenter reiniciándose no puede dejar sin VMs el inventario un día.
        """
        if not credential.covers(address or credential.host):
            return False
        mem = tasking.memory(ctx)
        if mem is None or not key:
            return True
        try:
            return bool(mem.order_for(key, credential.kind, [credential], tasking.now()))
        except Exception:  # noqa: BLE001 - la memoria es prescindible
            return True

    @staticmethod
    def _remember(ctx: dict, key: str, credential: creds.Credential, *, ok: bool) -> None:
        mem = tasking.memory(ctx)
        if mem is None or not key:
            return
        try:
            if ok:
                mem.record_success(key, credential.kind, credential, tasking.now())
            else:
                mem.record_round_failed(key, credential.kind, tasking.now())
        except Exception:  # noqa: BLE001
            pass

    def _from(self, credential: creds.Credential, ctx: dict, server: str) -> Any:
        """Lo que da ese hipervisor, o `tasking.SKIPPED` si su credencial está suspendida.

        El inicio de sesión pasa por el límite de credenciales (spec 2.3): una
        cuenta de dominio en un Hyper-V o un vCenter con su SSO se bloquea igual
        que contra un Windows suelto.
        """
        client = CLIENTS[credential.kind](
            credential.host,
            credential.username,
            credential.secret,
            port=credential.port,
            **creds.client_options(ctx, credential),
        )
        logins = tasking.Logins(ctx, "hypervisors", credential.kind, server)
        error = logins.run(credential, lambda: _login(client), hypervisor.login_outcome)
        if error is tasking.SKIPPED:
            return tasking.SKIPPED
        if error is not None:
            raise error
        platform = KIND_LABELS[credential.kind]
        findings = [_host_finding(host, platform, credential) for host in client.hosts()]
        findings.extend(
            _vm_finding(vm, platform, credential) for vm in client.virtual_machines()
        )
        return findings


def _login(client: Any) -> hypervisor.HypervisorError | None:
    """`client.login()`, con el error devuelto en vez de lanzado (para su veredicto)."""
    try:
        client.login()
    except hypervisor.HypervisorError as exc:
        return exc
    return None


def _host_finding(host: dict[str, Any], platform: str, credential: creds.Credential) -> Finding:
    """Un servidor del hipervisor, como equipo.

    La identidad va por IP y no por nombre **cuando se puede resolver**: es lo
    que hace que este hallazgo y el que dejó el barrido para esa misma máquina
    sean una fila y no dos. Un ESXi contesta al ping como cualquier otro.
    """
    name = host["name"]
    ip = net.resolve(name)
    identity = {"ip": ip} if ip else {"hostname": name}
    return Finding(
        kind="host",
        identity=identity,
        payload={
            "hostname": name,
            "ip": ip,
            "mac": "",
            "description": f"Host de virtualización ({platform})",
            "is_virtualization_host": True,
            "cluster": credential.host,
            "platform": platform,
            "interfaces": [],
            "seen_by": "hypervisor",
        },
    )


def _vm_finding(vm: dict[str, Any], platform: str, credential: creds.Credential) -> Finding:
    """Una máquina virtual.

    La identidad lleva el hipervisor y el identificador que le da él, no el
    nombre: renombrar una máquina virtual es un gesto de un segundo, y con el
    nombre dentro de la huella cada renombrado abriría una fila nueva en la
    bandeja y dejaría la vieja huérfana.
    """
    return Finding(
        kind="vm",
        identity={"hypervisor": credential.host, "vm_id": vm["id"]},
        payload={
            "name": vm["name"],
            "status": vm.get("status", ""),
            "vcpus": vm.get("vcpus") or 0,
            "ram_gb": vm.get("ram_gb") or 0,
            "disk_gb": vm.get("disk_gb") or 0,
            "operating_system": vm.get("operating_system", ""),
            "host": vm.get("host", ""),
            "cluster": credential.host,
            "platform": platform,
            "seen_by": "hypervisor",
        },
    )
