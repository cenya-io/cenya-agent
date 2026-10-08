"""XCP-ng con la XAPI fingida y ni una petición de verdad.

Las fixturas calcan lo que devuelve un XCP-ng 8 por JSON-RPC: `get_all_records`
con las referencias opacas como claves, los números como cadenas, y las
plantillas y el dominio de control mezclados con las máquinas de verdad. Lo que
más importa aquí es lo de siempre: que una autenticación fallida diga su código
XAPI (que viaja escondido en `error.data`), y que una llamada auxiliar caída
--VBD, VDI, guest metrics-- deje datos incompletos en vez de tumbar el barrido.
"""

from __future__ import annotations

import json
import unittest
import urllib.error
import urllib.request
from typing import Any

from agent import xcpng
from agent.hypervisor import MAX_DETAILED_VMS, HypervisorError

XcpNgClient = xcpng.XcpNgClient

# --- Fixturas de XAPI ---------------------------------------------------------------

SESSION = "OpaqueRef:1f6d3a52-9c41-4e8b-b0e2-7a5d9c3f1024"

#: `host.get_all_records`: el pool, indexado por referencias opacas. Uno
#: habilitado y otro en mantenimiento (o apagado: XAPI no distingue).
HOST_RECORDS: dict[str, Any] = {
    "OpaqueRef:host-1": {
        "uuid": "0b7e1c2d-1111-4a5b-8c9d-000000000001",
        "name_label": "xcp01",
        "hostname": "xcp01.acme.local",
        "enabled": True,
    },
    "OpaqueRef:host-2": {
        "uuid": "0b7e1c2d-1111-4a5b-8c9d-000000000002",
        "name_label": "xcp02",
        "hostname": "xcp02.acme.local",
        "enabled": False,
    },
}

#: `VM.get_all_records`: máquinas de verdad revueltas con una plantilla, una
#: plantilla de fábrica y el dom0, que es como lo devuelve XAPI de verdad.
#: Los números van como cadenas porque así los da XAPI.
VM_RECORDS: dict[str, Any] = {
    "OpaqueRef:vm-run": {
        "uuid": "9a1b2c3d-aaaa-4e5f-8a9b-000000000101",
        "name_label": "srv-ficheros",
        "power_state": "Running",
        "VCPUs_max": "4",
        "memory_static_max": "8589934592",  # 8 GiB
        "is_a_template": False,
        "is_control_domain": False,
        "resident_on": "OpaqueRef:host-1",
        "guest_metrics": "OpaqueRef:gm-1",
    },
    "OpaqueRef:vm-halted": {
        "uuid": "9a1b2c3d-aaaa-4e5f-8a9b-000000000102",
        "name_label": "srv-backup",
        "power_state": "Halted",
        "VCPUs_max": "2",
        "memory_static_max": "4294967296",  # 4 GiB
        "is_a_template": False,
        "is_control_domain": False,
        "resident_on": "OpaqueRef:NULL",  # apagada: no reside en ningún host
        "guest_metrics": "OpaqueRef:NULL",  # sin guest tools
    },
    "OpaqueRef:vm-template": {
        "uuid": "9a1b2c3d-aaaa-4e5f-8a9b-000000000103",
        "name_label": "Debian Bookworm 12",
        "power_state": "Halted",
        "is_a_template": True,
        "is_default_template": True,
        "is_control_domain": False,
    },
    "OpaqueRef:vm-custom-template": {
        # Una plantilla de fábrica reciente: `is_a_template` a falso pero
        # `is_default_template` a verdadero. Tampoco es una máquina.
        "uuid": "9a1b2c3d-aaaa-4e5f-8a9b-000000000104",
        "name_label": "Ubuntu Jammy 22.04",
        "power_state": "Halted",
        "is_a_template": False,
        "is_default_template": True,
        "is_control_domain": False,
    },
    "OpaqueRef:vm-dom0": {
        "uuid": "9a1b2c3d-aaaa-4e5f-8a9b-000000000105",
        "name_label": "Control domain on host: xcp01",
        "power_state": "Running",
        "is_a_template": False,
        "is_control_domain": True,
        "resident_on": "OpaqueRef:host-1",
    },
}

#: `VBD.get_all_records`: los dos discos de la encendida, su lector de CD (que
#: no cuenta) y el disco de la apagada.
VBD_RECORDS: dict[str, Any] = {
    "OpaqueRef:vbd-1": {"VM": "OpaqueRef:vm-run", "type": "Disk", "VDI": "OpaqueRef:vdi-1"},
    "OpaqueRef:vbd-2": {"VM": "OpaqueRef:vm-run", "type": "Disk", "VDI": "OpaqueRef:vdi-2"},
    "OpaqueRef:vbd-3": {"VM": "OpaqueRef:vm-run", "type": "CD", "VDI": "OpaqueRef:NULL"},
    "OpaqueRef:vbd-4": {"VM": "OpaqueRef:vm-halted", "type": "Disk", "VDI": "OpaqueRef:vdi-3"},
}

VDI_RECORDS: dict[str, Any] = {
    "OpaqueRef:vdi-1": {"virtual_size": "137438953472"},  # 128 GiB
    "OpaqueRef:vdi-2": {"virtual_size": "68719476736"},  # 64 GiB
    "OpaqueRef:vdi-3": {"virtual_size": "42949672960"},  # 40 GiB
}

#: `VM_guest_metrics.get_all_records`: solo la máquina con las guest tools.
GUEST_METRICS_RECORDS: dict[str, Any] = {
    "OpaqueRef:gm-1": {
        "os_version": {
            "name": "Ubuntu 22.04.3 LTS",
            "distro": "ubuntu",
            "major": "22",
            "minor": "04",
        }
    }
}

XAPI_RESULTS: dict[str, Any] = {
    "host.get_all_records": HOST_RECORDS,
    "VM.get_all_records": VM_RECORDS,
    "VBD.get_all_records": VBD_RECORDS,
    "VDI.get_all_records": VDI_RECORDS,
    "VM_guest_metrics.get_all_records": GUEST_METRICS_RECORDS,
}

#: El error de autenticación tal cual lo devuelve XAPI por JSON-RPC: el
#: `message` es un genérico y el código de verdad viaja en `data` como lista.
AUTH_FAILED_BODY: dict[str, Any] = {
    "jsonrpc": "2.0",
    "id": 1,
    "error": {
        "code": 1,
        "message": "There was an error processing your request",
        "data": ["SESSION_AUTHENTICATION_FAILED", "root"],
    },
}


# --- Dobles -------------------------------------------------------------------------


class _FakeXapi:
    """Una XAPI de mentira: métodos a resultados, y lo que se le preguntó."""

    def __init__(self, results: dict[str, Any], errors: dict[str, Exception] | None = None) -> None:
        self.results = results
        self.errors = errors or {}
        self.calls: list[tuple[str, list[Any]]] = []

    def __call__(self, method: str, params: list[Any]) -> Any:
        self.calls.append((method, list(params)))
        if method in self.errors:
            raise self.errors[method]
        if method not in self.results:
            raise HypervisorError(f"método no simulado: {method}")
        return self.results[method]


class _FakeResponse:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args: Any) -> bool:
        return False


class _FakeOpener:
    def __init__(self, answer: Any) -> None:
        self.answer = answer
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: float | None = None) -> Any:
        self.requests.append(request)
        if isinstance(self.answer, BaseException):
            raise self.answer
        return _FakeResponse(self.answer)


def logged_in(
    results: dict[str, Any] | None = None, errors: dict[str, Exception] | None = None
) -> tuple[XcpNgClient, _FakeXapi]:
    """Un cliente con la XAPI sustituida entera y la sesión ya abierta."""
    client = XcpNgClient("xcp.acme.local", "root", "s3cr3t")
    fake = _FakeXapi(
        {"session.login_with_password": SESSION, **(results if results is not None else XAPI_RESULTS)},
        errors,
    )
    client._call = fake  # type: ignore[method-assign]
    client.login()
    return client, fake


def wire_client(answer: Any) -> tuple[XcpNgClient, _FakeOpener]:
    """Un cliente con el `_call` de verdad y solo el HTTP fingido."""
    client = XcpNgClient("xcp.acme.local", "root", "s3cr3t")
    opener = _FakeOpener(answer)
    client._opener = opener  # type: ignore[assignment]
    return client, opener


# --- El transporte JSON-RPC ---------------------------------------------------------


class JsonRpcTests(unittest.TestCase):
    def test_the_call_travels_as_json_and_not_urlencoded(self) -> None:
        """El `RestClient` del agente urlencodea el cuerpo; JSON-RPC exige
        JSON. Es el motivo de que este módulo lleve su propio `_call`."""
        client, opener = wire_client(json.dumps({"jsonrpc": "2.0", "id": 1, "result": SESSION}).encode())

        client.login()

        request = opener.requests[0]
        self.assertTrue(request.full_url.endswith("/jsonrpc"))
        self.assertEqual(request.get_header("Content-type"), "application/json")
        body = json.loads(request.data.decode())
        self.assertEqual(body["jsonrpc"], "2.0")
        self.assertEqual(body["method"], "session.login_with_password")
        self.assertEqual(body["params"], ["root", "s3cr3t"])
        # La contraseña viaja en el cuerpo, nunca en la ruta.
        self.assertNotIn("s3cr3t", request.full_url)
        self.assertEqual(client.session, SESSION)

    def test_failed_authentication_names_the_xapi_code_and_not_the_password(self) -> None:
        """El código de verdad viaja en `error.data`, no en `error.message`.
        El error acaba en el informe de la ejecución, que se guarda: tiene que
        decir qué pasó, y no puede llevar la contraseña dentro."""
        client, _ = wire_client(json.dumps(AUTH_FAILED_BODY).encode())

        with self.assertRaises(HypervisorError) as caught:
            client.login()

        self.assertIn("SESSION_AUTHENTICATION_FAILED", str(caught.exception))
        self.assertNotIn("s3cr3t", str(caught.exception))

    def test_an_html_error_page_is_not_mistaken_for_an_answer(self) -> None:
        """Un portal cautivo, un proxy o el propio XCP-ng devolviendo su página
        de error en HTML."""
        client, _ = wire_client(b"<html><body>503 Service Unavailable</body></html>")

        with self.assertRaises(HypervisorError) as caught:
            client.login()

        self.assertIn("no era JSON", str(caught.exception))

    def test_a_timeout_becomes_an_error_and_not_a_traceback(self) -> None:
        client, _ = wire_client(TimeoutError("timed out"))

        with self.assertRaises(HypervisorError):
            client.login()

    def test_a_redirect_is_refused_so_the_session_does_not_travel(self) -> None:
        """El manejador por defecto de `urllib` reenvía cabeceras y cuerpo al
        destino nuevo, y en el cuerpo de un `_call` va la sesión."""
        handler = xcpng._NoRedirects()
        request = urllib.request.Request("https://xcp.acme.local/jsonrpc")

        with self.assertRaises(urllib.error.HTTPError) as caught:
            handler.redirect_request(request, None, 302, "Found", {}, "https://otro.sitio/")

        caught.exception.close()

    def test_a_login_without_a_session_is_an_error_and_not_a_silent_pass(self) -> None:
        client, _ = wire_client(json.dumps({"jsonrpc": "2.0", "id": 1, "result": None}).encode())

        with self.assertRaises(HypervisorError):
            client.login()


# --- El cliente ---------------------------------------------------------------------


class XcpNgClientTests(unittest.TestCase):
    def test_the_pool_hosts_come_out_with_their_state(self) -> None:
        """XAPI no distingue «apagado» de «en mantenimiento»: un host con
        `enabled` a falso se traduce a lo más honesto que admite el contrato."""
        client, _ = logged_in()

        hosts = {host["name"]: host for host in client.hosts()}

        self.assertEqual(set(hosts), {"xcp01.acme.local", "xcp02.acme.local"})
        self.assertEqual(hosts["xcp01.acme.local"]["power_state"], "POWERED_ON")
        self.assertEqual(hosts["xcp01.acme.local"]["connection_state"], "online")
        self.assertEqual(hosts["xcp02.acme.local"]["power_state"], "")
        self.assertEqual(hosts["xcp02.acme.local"]["connection_state"], "offline")

    def test_a_host_without_a_name_is_not_inventoried(self) -> None:
        client, _ = logged_in({"host.get_all_records": {"OpaqueRef:host-9": {"enabled": True}, **HOST_RECORDS}})

        self.assertEqual(len(client.hosts()), 2)

    def test_a_running_vm_comes_out_with_cpu_memory_disk_os_and_host(self) -> None:
        client, _ = logged_in()

        vms = {vm["name"]: vm for vm in client.virtual_machines()}
        vm = vms["srv-ficheros"]

        self.assertEqual(vm["id"], "9a1b2c3d-aaaa-4e5f-8a9b-000000000101")
        self.assertEqual(vm["status"], "running")
        self.assertEqual(vm["vcpus"], 4)
        self.assertEqual(vm["ram_gb"], 8)
        # Los dos discos sumados, 128 GiB + 64 GiB; el lector de CD no cuenta.
        self.assertEqual(vm["disk_gb"], 192)
        self.assertEqual(vm["operating_system"], "Ubuntu 22.04.3 LTS")
        self.assertEqual(vm["host"], "xcp01.acme.local")

    def test_a_halted_vm_has_no_host_and_no_os_but_keeps_its_disk(self) -> None:
        """`resident_on` de una apagada es `OpaqueRef:NULL`: no es un error,
        es que no está en ningún sitio. Y sin guest tools no hay sistema."""
        client, _ = logged_in()

        vms = {vm["name"]: vm for vm in client.virtual_machines()}
        vm = vms["srv-backup"]

        self.assertEqual(vm["status"], "stopped")
        self.assertEqual(vm["host"], "")
        self.assertEqual(vm["operating_system"], "")
        self.assertEqual(vm["ram_gb"], 4)
        self.assertEqual(vm["disk_gb"], 40)

    def test_templates_and_the_control_domain_are_not_machines(self) -> None:
        """XAPI devuelve todo lo que es un `VM`: las plantillas y el dom0
        también. Colarlos sería proponer dar de alta decenas de «máquinas»
        que nadie tiene -- ni la de fábrica que solo marca
        `is_default_template`."""
        client, _ = logged_in()

        names = {vm["name"] for vm in client.virtual_machines()}

        self.assertEqual(names, {"srv-ficheros", "srv-backup"})

    def test_broken_disk_calls_leave_zeros_and_never_raise(self) -> None:
        """Un hallazgo incompleto vale más que ninguno: si VBD o VDI fallan,
        las máquinas salen con 0 de disco y el barrido sigue."""
        for broken in ("VBD.get_all_records", "VDI.get_all_records"):
            with self.subTest(broken=broken):
                client, _ = logged_in(errors={broken: HypervisorError(f"403 en {broken}")})

                vms = client.virtual_machines()

                self.assertEqual(len(vms), 2)
                self.assertEqual({vm["disk_gb"] for vm in vms}, {0})

    def test_a_broken_guest_metrics_call_leaves_the_os_empty(self) -> None:
        client, _ = logged_in(
            errors={"VM_guest_metrics.get_all_records": HypervisorError("403 en VM_guest_metrics")}
        )

        vms = client.virtual_machines()

        self.assertEqual(len(vms), 2)
        self.assertEqual({vm["operating_system"] for vm in vms}, {""})

    def test_a_broken_host_call_leaves_the_machines_without_host(self) -> None:
        """Quedarse sin máquinas porque no se pueden listar los hosts sería
        cambiar un dato incompleto por ningún dato."""
        client, _ = logged_in(errors={"host.get_all_records": HypervisorError("403 en host")})

        vms = client.virtual_machines()

        self.assertEqual(len(vms), 2)
        self.assertEqual({vm["host"] for vm in vms}, {""})

    def test_paused_and_suspended_both_mean_suspended(self) -> None:
        """Para la bandeja da igual si la pausa vive en RAM o en disco: la
        máquina no está sirviendo."""
        records = {
            "OpaqueRef:vm-p": {"uuid": "u-p", "name_label": "pausada", "power_state": "Paused"},
            "OpaqueRef:vm-s": {"uuid": "u-s", "name_label": "suspendida", "power_state": "Suspended"},
        }
        client, _ = logged_in(
            {
                "VM.get_all_records": records,
                "host.get_all_records": {},
                "VBD.get_all_records": {},
                "VDI.get_all_records": {},
                "VM_guest_metrics.get_all_records": {},
            }
        )

        statuses = {vm["name"]: vm["status"] for vm in client.virtual_machines()}

        self.assertEqual(statuses, {"pausada": "suspended", "suspendida": "suspended"})

    def test_an_unknown_power_state_falls_back_to_running(self) -> None:
        client, _ = logged_in(
            {
                "VM.get_all_records": {"OpaqueRef:vm-x": {"uuid": "u-x", "name_label": "rara"}},
                "host.get_all_records": {},
                "VBD.get_all_records": {},
                "VDI.get_all_records": {},
                "VM_guest_metrics.get_all_records": {},
            }
        )

        vm = client.virtual_machines()[0]

        self.assertEqual(vm["status"], "running")
        self.assertEqual(vm["vcpus"], 0)
        self.assertEqual(vm["ram_gb"], 0)

    def test_a_giant_pool_is_capped_and_still_costs_five_calls(self) -> None:
        """El mismo tope que el vCenter, y además el coste no crece con las
        máquinas: `get_all_records` trae el lote entero, así que un pool de
        seiscientas VMs son las mismas cinco llamadas que uno de tres."""
        crowd = {
            f"OpaqueRef:vm-{index}": {"uuid": f"u-{index}", "name_label": f"maq-{index}", "power_state": "Running"}
            for index in range(MAX_DETAILED_VMS + 100)
        }
        client, fake = logged_in(
            {
                "VM.get_all_records": crowd,
                "host.get_all_records": {},
                "VBD.get_all_records": {},
                "VDI.get_all_records": {},
                "VM_guest_metrics.get_all_records": {},
            }
        )

        found = client.virtual_machines()

        self.assertEqual(len(found), MAX_DETAILED_VMS)
        # login + VM + host + pool + VBD + VDI + guest metrics + SR + VIF:
        # nueve, sea cual sea el pool.
        self.assertEqual(len(fake.calls), 9)

    def test_every_call_after_login_carries_the_session(self) -> None:
        client, fake = logged_in()

        client.hosts()
        client.virtual_machines()

        for method, params in fake.calls[1:]:
            self.assertEqual(params, [SESSION], f"{method} no llevó la sesión")

    def test_an_answer_with_a_shape_nobody_expected_gives_nothing(self) -> None:
        """La respuesta la escribe otro proceso; una forma inesperada no puede
        acabar en un `AttributeError` a mitad del barrido."""
        client, _ = logged_in(
            {
                "host.get_all_records": "no soy un diccionario",
                "VM.get_all_records": ["tampoco"],
                "VBD.get_all_records": {},
                "VDI.get_all_records": {},
                "VM_guest_metrics.get_all_records": {},
            }
        )

        self.assertEqual(client.hosts(), [])
        self.assertEqual(client.virtual_machines(), [])



class XcpNgPoolAndHardwareTests(unittest.TestCase):
    """El pool es el clúster de XCP-ng, y la BIOS dice qué caja es cada host."""

    def test_hosts_and_machines_carry_the_pool_name(self) -> None:
        client, _ = logged_in(
            {**XAPI_RESULTS, "pool.get_all_records": {"OpaqueRef:pool": {"name_label": "Pool CPD"}}}
        )

        self.assertEqual({host["cluster"] for host in client.hosts()}, {"Pool CPD"})
        self.assertEqual({vm["cluster"] for vm in client.virtual_machines()}, {"Pool CPD"})

    def test_a_pool_without_a_name_is_no_cluster(self) -> None:
        """Un host suelto también tiene pool, pero sin nombre."""
        client, _ = logged_in({**XAPI_RESULTS, "pool.get_all_records": {"OpaqueRef:pool": {"name_label": ""}}})

        self.assertEqual({host["cluster"] for host in client.hosts()}, {""})

    def test_a_pool_that_cannot_be_read_does_not_lose_the_hosts(self) -> None:
        client, _ = logged_in()  # sin `pool.get_all_records`: la llamada falla

        self.assertEqual(len(client.hosts()), 2)

    def test_the_bios_strings_fill_the_hardware(self) -> None:
        records = {
            ref: dict(record, bios_strings={
                "system-manufacturer": "HPE",
                "system-product-name": "ProLiant DL360 Gen10",
                "system-serial-number": "CZJ1234567",
            })
            for ref, record in HOST_RECORDS.items()
        }
        client, _ = logged_in({**XAPI_RESULTS, "host.get_all_records": records})

        host = client.hosts()[0]

        self.assertEqual(host["manufacturer"], "HPE")
        self.assertEqual(host["model"], "ProLiant DL360 Gen10")
        self.assertEqual(host["serial"], "CZJ1234567")

    def test_the_placeholders_of_a_lazy_bios_are_left_empty(self) -> None:
        """«To be filled by O.E.M.» no es un número de serie, y en la ficha
        parecería uno."""
        records = {
            ref: dict(record, bios_strings={"system-serial-number": "To Be Filled By O.E.M."})
            for ref, record in HOST_RECORDS.items()
        }
        client, _ = logged_in({**XAPI_RESULTS, "host.get_all_records": records})

        self.assertEqual(client.hosts()[0]["serial"], "")


class XcpNgNetworkAndDisksTests(unittest.TestCase):
    """El SR de cada disco y las tarjetas con lo que dicen las guest tools."""

    def test_disks_by_sr_and_cards_with_addresses(self) -> None:
        vm_ref = next(ref for ref, vm in VM_RECORDS.items() if not (
            vm.get("is_a_template") or vm.get("is_default_template") or vm.get("is_control_domain")
        ))
        metrics_ref = "OpaqueRef:gm-net"
        machines = {ref: dict(vm) for ref, vm in VM_RECORDS.items()}
        machines[vm_ref]["guest_metrics"] = metrics_ref
        results = {
            **XAPI_RESULTS,
            "VM.get_all_records": machines,
            "VBD.get_all_records": {"OpaqueRef:vbd-x": {"VM": vm_ref, "VDI": "OpaqueRef:vdi-x", "type": "Disk"}},
            "VDI.get_all_records": {"OpaqueRef:vdi-x": {"SR": "OpaqueRef:sr-1", "virtual_size": str(50 * 1024**3)}},
            "SR.get_all_records": {"OpaqueRef:sr-1": {"name_label": "NAS iSCSI"}},
            "VIF.get_all_records": {"OpaqueRef:vif-0": {"VM": vm_ref, "MAC": "aa:bb:cc:00:00:01", "device": "0"}},
            "VM_guest_metrics.get_all_records": {
                metrics_ref: {"networks": {"0/ip": "10.0.0.50", "0/ipv4/0": "10.0.0.50", "1/ip": "10.9.9.9"}}
            },
        }
        client, _ = logged_in(results)

        machine = next(vm for vm in client.virtual_machines() if vm["id"] in (machines[vm_ref].get("uuid"), vm_ref))

        self.assertEqual(machine["disks"], [{"datastore": "NAS iSCSI", "gb": 50}])
        self.assertEqual(
            machine["interfaces"], [{"name": "eth0", "mac": "aa:bb:cc:00:00:01", "ips": ["10.0.0.50"], "vlan": None}]
        )

    def test_without_the_vif_table_the_machines_still_arrive(self) -> None:
        client, _ = logged_in()

        machines = client.virtual_machines()

        self.assertTrue(machines)
        self.assertEqual({len(vm["interfaces"]) for vm in machines}, {0})


if __name__ == "__main__":
    unittest.main()
