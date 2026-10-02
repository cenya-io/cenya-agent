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
from agent.collectors import register
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
        for credential in credentials:
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
                continue
            try:
                findings.extend(self._from(credential, ctx))
            except hypervisor.HypervisorError as exc:
                # Un hipervisor caído o una contraseña cambiada no pueden tumbar
                # el barrido: se anota y se sigue con el siguiente. El detalle va
                # tal cual: lo escribe el hipervisor, o es un error de red.
                errors.append(
                    collector_note(
                        "hypervisors", "failed", f"{credential.host}: {exc}", host=credential.host, detail=str(exc)
                    )
                )
        return findings

    def _from(self, credential: creds.Credential, ctx: dict) -> list[Finding]:
        client = CLIENTS[credential.kind](
            credential.host,
            credential.username,
            credential.secret,
            port=credential.port,
            ca_file=creds.ca_file_for(ctx, credential),
        )
        client.login()
        platform = KIND_LABELS[credential.kind]
        findings = [_host_finding(host, platform, credential) for host in client.hosts()]
        findings.extend(
            _vm_finding(vm, platform, credential) for vm in client.virtual_machines()
        )
        return findings


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
