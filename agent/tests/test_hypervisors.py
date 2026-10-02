"""vCenter y Proxmox, con la API fingida y ni una petición de verdad.

Las fixturas son las respuestas reales de las dos APIs REST: la de vSphere
Automation (7.0/8.0 devuelve la lista pelada, 6.7 la envuelve en `value`) y la
`/api2/json` de Proxmox. Lo que más importa aquí es lo de siempre: que un
hipervisor caído, una contraseña cambiada o una página de error en HTML anoten
una línea y devuelvan `[]` en vez de tumbar el barrido entero.
"""

from __future__ import annotations

import json
import ssl
import unittest
import urllib.error
import urllib.request
from typing import Any
from unittest import mock

from agent import hypervisor
from agent.collectors import hypervisors as hypervisors_collector
from agent.collectors.hypervisors import HypervisorCollector
from agent.hypervisor import HypervisorError, ProxmoxClient, VMwareClient

# --- Fixturas de vCenter ----------------------------------------------------------

VMWARE_TOKEN = "b4f2e9a1c7d84e0fa1c3e5b7d9f10246"

#: `GET /api/vcenter/host` en un vCenter 8: la lista, pelada.
VMWARE_HOSTS: list[dict[str, Any]] = [
    {
        "host": "host-16",
        "name": "esxi01.acme.local",
        "connection_state": "CONNECTED",
        "power_state": "POWERED_ON",
    },
    {
        "host": "host-22",
        "name": "esxi02.acme.local",
        "connection_state": "DISCONNECTED",
        "power_state": "POWERED_ON",
    },
]

#: `GET /api/vcenter/vm`: el resumen, sin discos ni sistema operativo.
VMWARE_VMS: list[dict[str, Any]] = [
    {
        "vm": "vm-101",
        "name": "srv-ficheros",
        "power_state": "POWERED_ON",
        "cpu_count": 4,
        "memory_size_MiB": 8192,
    },
    {
        "vm": "vm-102",
        "name": "srv-correo",
        "power_state": "POWERED_OFF",
        "cpu_count": 2,
        "memory_size_MiB": 4096,
    },
]

#: `GET /api/vcenter/vm/vm-101`: el detalle, con los discos indexados por su id.
VMWARE_VM_DETAIL: dict[str, Any] = {
    "name": "srv-ficheros",
    "power_state": "POWERED_ON",
    "guest_OS": "UBUNTU_64",
    "cpu": {"count": 4, "cores_per_socket": 1, "hot_add_enabled": False},
    "memory": {"size_MiB": 8192, "hot_add_enabled": False},
    "disks": {
        "2000": {
            "label": "Hard disk 1",
            "type": "SCSI",
            "capacity": 137438953472,
            "backing": {"type": "VMDK_FILE", "vmdk_file": "[datastore1] srv-ficheros/srv-ficheros.vmdk"},
        },
        "2001": {
            "label": "Hard disk 2",
            "type": "SCSI",
            "capacity": 68719476736,
            "backing": {"type": "VMDK_FILE", "vmdk_file": "[datastore1] srv-ficheros/srv-ficheros_1.vmdk"},
        },
    },
    "guest_identity": {
        "name": "UBUNTU_64",
        "host_name": "srv-ficheros",
        "full_name": {"id": "vm.guest.osfullname.UBUNTU_64", "default_message": "Ubuntu Linux (64-bit)"},
    },
}

#: El mismo detalle sin VMware Tools: solo queda el identificador de VMware.
VMWARE_VM_DETAIL_SIN_TOOLS: dict[str, Any] = {
    "guest_OS": "WINDOWS_SERVER_2019",
    "cpu": {"count": 2},
    "memory": {"size_MiB": 4096},
    "disks": {"2000": {"capacity": 42949672960}},
}

# --- Fixturas de Proxmox ----------------------------------------------------------

PROXMOX_TICKET: dict[str, Any] = {
    "data": {
        "ticket": "PVE:root@pam:65A1B2C3::abcdefghijklmnopqrstuvwxyz0123456789",
        "CSRFPreventionToken": "65A1B2C3:tHiSiSaToKeN",
        "username": "root@pam",
        "cap": {"vms": {"VM.Audit": 1}},
    }
}

PROXMOX_NODES: dict[str, Any] = {
    "data": [
        {
            "id": "node/pve01",
            "node": "pve01",
            "type": "node",
            "status": "online",
            "cpu": 0.043,
            "maxcpu": 8,
            "mem": 8589934592,
            "maxmem": 34359738368,
            "uptime": 4321098,
        },
        {
            "id": "node/pve02",
            "node": "pve02",
            "type": "node",
            "status": "offline",
            "maxcpu": 8,
            "uptime": 0,
        },
    ]
}

PROXMOX_RESOURCES: dict[str, Any] = {
    "data": [
        {
            "id": "qemu/100",
            "type": "qemu",
            "vmid": 100,
            "name": "srv-ficheros",
            "node": "pve01",
            "status": "running",
            "maxcpu": 4,
            "maxmem": 8589934592,
            "maxdisk": 137438953472,
            "uptime": 987654,
            "template": 0,
        },
        {
            "id": "lxc/201",
            "type": "lxc",
            "vmid": 201,
            "name": "proxy-web",
            "node": "pve01",
            "status": "stopped",
            "maxcpu": 2,
            "maxmem": 2147483648,
            "maxdisk": 8589934592,
            "template": 0,
        },
    ]
}


# --- Dobles -----------------------------------------------------------------------


class _Rest:
    """Una API REST de mentira: rutas a respuestas, y lo que se le preguntó."""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str, dict[str, str], Any]] = []

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        self.calls.append((method, path, dict(headers or {}), body))
        if path not in self.routes:
            raise HypervisorError(f"404 en {path}")
        answer = self.routes[path]
        if isinstance(answer, Exception):
            raise answer
        return answer


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


def rest_with(answer: Any, *, ca_file: str = "") -> tuple[hypervisor.RestClient, _FakeOpener]:
    client = hypervisor.RestClient("https://vc.acme.local:443", ca_file=ca_file)
    opener = _FakeOpener(answer)
    client._opener = opener  # type: ignore[attr-defined]
    return client, opener


# --- El cliente HTTP --------------------------------------------------------------


class RestClientTests(unittest.TestCase):
    def test_a_json_answer_comes_back_parsed(self) -> None:
        client, opener = rest_with(json.dumps(VMWARE_HOSTS).encode())

        self.assertEqual(client.request("GET", "/api/vcenter/host"), VMWARE_HOSTS)
        self.assertEqual(opener.requests[0].full_url, "https://vc.acme.local:443/api/vcenter/host")

    def test_an_html_error_page_is_not_mistaken_for_findings(self) -> None:
        """Un portal cautivo, un proxy o el propio hipervisor devolviendo su
        página de error. Sin esto, el bucle de arriba recorre una cadena y saca
        un hallazgo por cada letra."""
        client, _ = rest_with(b"<html><body>503 Service Unavailable</body></html>")

        with self.assertRaises(HypervisorError) as caught:
            client.request("GET", "/api/vcenter/vm")

        self.assertIn("no era JSON", str(caught.exception))

    def test_a_401_says_which_call_failed(self) -> None:
        error = urllib.error.HTTPError("https://vc.acme.local/api/session", 401, "Unauthorized", {}, None)
        client, _ = rest_with(error)

        with self.assertRaises(HypervisorError) as caught:
            client.request("POST", "/api/session")

        self.assertIn("401", str(caught.exception))
        self.assertIn("/api/session", str(caught.exception))
        error.close()  # `HTTPError` es un fichero: sin cerrarlo avisa al recogerlo

    def test_a_timeout_becomes_an_error_and_not_a_traceback(self) -> None:
        client, _ = rest_with(TimeoutError("timed out"))

        with self.assertRaises(HypervisorError):
            client.request("GET", "/api/vcenter/host")

    def test_a_certificate_that_does_not_verify_is_an_error_and_not_a_crash(self) -> None:
        """El vCenter de una pyme lleva certificado autofirmado. La salida es
        dar la CA, no desactivar la verificación: aquí solo se comprueba que el
        fallo se cuenta en vez de reventar el barrido."""
        client, _ = rest_with(ssl.SSLError("certificate verify failed"))

        with self.assertRaises(HypervisorError):
            client.request("GET", "/api/vcenter/host")

    def test_an_empty_body_is_none_and_not_a_crash(self) -> None:
        client, _ = rest_with(b"")

        self.assertIsNone(client.request("POST", "/api/session"))

    def test_a_redirect_is_refused_so_the_session_id_does_not_travel(self) -> None:
        """El manejador por defecto de `urllib` reenvía las cabeceras al destino
        nuevo, y entre ellas va el identificador de sesión del vCenter."""
        handler = hypervisor._NoRedirects()
        request = urllib.request.Request("https://vc.acme.local/api/vcenter/vm")

        with self.assertRaises(urllib.error.HTTPError) as caught:
            handler.redirect_request(request, None, 302, "Found", {}, "https://otro.sitio/")

        caught.exception.close()

    def test_the_json_headers_are_always_sent(self) -> None:
        client, opener = rest_with(b"{}")

        client.request("GET", "/api/vcenter/host", headers={"vmware-api-session-id": VMWARE_TOKEN})

        self.assertEqual(opener.requests[0].get_header("Accept"), "application/json")
        self.assertEqual(opener.requests[0].get_header("Vmware-api-session-id"), VMWARE_TOKEN)


# --- vCenter ----------------------------------------------------------------------


class VMwareTests(unittest.TestCase):
    def _client(self, routes: dict[str, Any]) -> tuple[VMwareClient, _Rest]:
        client = VMwareClient("vc.acme.local", "lector@vsphere.local", "s3cr3t")
        rest = _Rest(routes)
        client.rest = rest  # type: ignore[assignment]
        return client, rest

    def _logged_in(self, extra: dict[str, Any] | None = None) -> tuple[VMwareClient, _Rest]:
        routes: dict[str, Any] = {"/api/session": VMWARE_TOKEN}
        routes.update(extra or {})
        client, rest = self._client(routes)
        client.login()
        return client, rest

    def test_a_modern_vcenter_logs_in_through_the_new_path(self) -> None:
        client, rest = self._logged_in()

        self.assertEqual(client.token, VMWARE_TOKEN)
        self.assertEqual(client.prefix, "/api")
        self.assertIn("Authorization", rest.calls[0][2])

    def test_a_67_vcenter_falls_back_to_the_old_path(self) -> None:
        """Una pyme con soporte pagado sigue teniendo vCenters 6.7: dejarlos
        fuera por la ruta de la sesión es dejar fuera su CPD entero."""
        client, rest = self._client(
            {"/rest/com/vmware/cis/session": {"value": VMWARE_TOKEN}}
        )

        client.login()

        self.assertEqual(client.token, VMWARE_TOKEN)
        self.assertEqual(client.prefix, "/rest")

    def test_wrong_credentials_raise_and_never_echo_the_password(self) -> None:
        """El error acaba en el informe de la ejecución, que se guarda."""
        unauthorized = HypervisorError("401 en /api/session")
        client, _ = self._client(
            {"/api/session": unauthorized, "/rest/com/vmware/cis/session": unauthorized}
        )

        with self.assertRaises(HypervisorError) as caught:
            client.login()

        self.assertIn("401", str(caught.exception))
        self.assertNotIn("s3cr3t", str(caught.exception))

    def test_a_vcenter_that_answers_without_a_session_is_an_error(self) -> None:
        client, _ = self._client({"/api/session": {"value": None}, "/rest/com/vmware/cis/session": None})

        with self.assertRaises(HypervisorError):
            client.login()

    def test_the_esxi_hosts_come_out_with_their_names(self) -> None:
        client, _ = self._logged_in({"/api/vcenter/host": VMWARE_HOSTS})

        hosts = client.hosts()

        self.assertEqual([host["name"] for host in hosts], ["esxi01.acme.local", "esxi02.acme.local"])
        self.assertEqual(hosts[1]["connection_state"], "DISCONNECTED")

    def test_a_67_vcenter_wraps_its_lists_and_it_is_read_the_same(self) -> None:
        client, _ = self._client({"/rest/com/vmware/cis/session": {"value": VMWARE_TOKEN}})
        client.login()
        client.rest.routes["/rest/vcenter/host"] = {"value": VMWARE_HOSTS}  # type: ignore[attr-defined]

        self.assertEqual(len(client.hosts()), 2)

    def test_a_vm_comes_out_with_cpu_memory_disk_and_guest_os(self) -> None:
        client, _ = self._logged_in(
            {
                "/api/vcenter/vm": VMWARE_VMS,
                "/api/vcenter/vm/vm-101": VMWARE_VM_DETAIL,
                "/api/vcenter/vm/vm-102": VMWARE_VM_DETAIL_SIN_TOOLS,
            }
        )

        vms = {vm["id"]: vm for vm in client.virtual_machines()}

        self.assertEqual(vms["vm-101"]["name"], "srv-ficheros")
        self.assertEqual(vms["vm-101"]["status"], "running")
        self.assertEqual(vms["vm-101"]["vcpus"], 4)
        self.assertEqual(vms["vm-101"]["ram_gb"], 8)
        # Los dos discos sumados: 128 GiB + 64 GiB.
        self.assertEqual(vms["vm-101"]["disk_gb"], 192)
        self.assertEqual(vms["vm-101"]["operating_system"], "Ubuntu Linux (64-bit)")

    def test_a_powered_off_vm_is_not_reported_as_running(self) -> None:
        client, _ = self._logged_in(
            {
                "/api/vcenter/vm": VMWARE_VMS,
                "/api/vcenter/vm/vm-101": VMWARE_VM_DETAIL,
                "/api/vcenter/vm/vm-102": VMWARE_VM_DETAIL_SIN_TOOLS,
            }
        )

        vms = {vm["id"]: vm for vm in client.virtual_machines()}

        self.assertEqual(vms["vm-102"]["status"], "stopped")

    def test_without_vmware_tools_the_vmware_identifier_is_made_readable(self) -> None:
        """`WINDOWS_SERVER_2019` no es algo que se pueda enseñar en una ficha."""
        client, _ = self._logged_in(
            {
                "/api/vcenter/vm": VMWARE_VMS,
                "/api/vcenter/vm/vm-101": VMWARE_VM_DETAIL,
                "/api/vcenter/vm/vm-102": VMWARE_VM_DETAIL_SIN_TOOLS,
            }
        )

        vms = {vm["id"]: vm for vm in client.virtual_machines()}

        self.assertEqual(vms["vm-102"]["operating_system"], "Windows Server 2019")

    def test_a_vm_whose_detail_is_forbidden_still_comes_out(self) -> None:
        """El usuario configurado no siempre tiene permiso de lectura de
        detalle. La ficha con lo básico vale más que ningún hallazgo."""
        client, _ = self._logged_in({"/api/vcenter/vm": VMWARE_VMS})  # sin rutas de detalle: 404

        vms = {vm["id"]: vm for vm in client.virtual_machines()}

        self.assertEqual(vms["vm-101"]["vcpus"], 4)
        self.assertEqual(vms["vm-101"]["ram_gb"], 8)
        self.assertEqual(vms["vm-101"]["disk_gb"], 0)
        self.assertEqual(vms["vm-101"]["operating_system"], "")

    def test_a_vm_without_identifier_is_skipped_and_the_rest_survives(self) -> None:
        client, _ = self._logged_in(
            {
                "/api/vcenter/vm": [{"name": "sin-id"}, VMWARE_VMS[0]],
                "/api/vcenter/vm/vm-101": VMWARE_VM_DETAIL,
            }
        )

        self.assertEqual([vm["id"] for vm in client.virtual_machines()], ["vm-101"])

    def test_an_answer_that_is_not_a_list_gives_nothing_instead_of_raising(self) -> None:
        """La respuesta la escribe otro proceso; una forma inesperada no puede
        acabar en un `TypeError` a mitad del barrido."""
        client, _ = self._logged_in({"/api/vcenter/host": {"value": "vaya"}, "/api/vcenter/vm": "tampoco"})

        self.assertEqual(client.hosts(), [])
        self.assertEqual(client.virtual_machines(), [])

    def test_a_host_without_a_name_is_not_inventoried(self) -> None:
        client, _ = self._logged_in({"/api/vcenter/host": [{"host": "host-99"}, VMWARE_HOSTS[0]]})

        self.assertEqual([host["name"] for host in client.hosts()], ["esxi01.acme.local"])

    def test_a_giant_vcenter_is_capped_instead_of_eating_the_sweep(self) -> None:
        """Cada detalle es una petición más: sin tope, un cliente grande
        convierte un barrido de quince minutos en media hora de peticiones.

        Al presupuesto se suma el cruce de hosts: una petición para listarlos y
        una por cada uno, con su propio tope. Aquí no hay ruta de hosts, así
        que el cruce se queda en la que falla.
        """
        many = [{"vm": f"vm-{index}", "name": f"maq-{index}"} for index in range(hypervisor.MAX_DETAILED_VMS + 100)]
        client, rest = self._logged_in({"/api/vcenter/vm": many})

        found = client.virtual_machines()

        budget = hypervisor.MAX_DETAILED_VMS + 2 + 1 + hypervisor.MAX_HOSTS_CROSSED
        self.assertEqual(len(found), hypervisor.MAX_DETAILED_VMS)
        self.assertLessEqual(len(rest.calls), budget)

    def test_a_vcenter_with_hundreds_of_esxi_does_not_ask_about_all_of_them(self) -> None:
        """El cruce es una petición por host, así que también lleva tope."""
        crowd = [{"host": f"host-{index}", "name": f"esxi{index}"} for index in range(200)]
        client, rest = self._logged_in({"/api/vcenter/host": crowd, "/api/vcenter/vm": []})

        client.virtual_machines()

        asked = [call for call in rest.calls if "filter.hosts=" in call[1]]
        self.assertLessEqual(len(asked), hypervisor.MAX_HOSTS_CROSSED)

    def test_a_vm_without_memory_or_cpu_does_not_divide_by_a_none(self) -> None:
        client, _ = self._logged_in({"/api/vcenter/vm": [{"vm": "vm-9", "name": "rara", "memory_size_MiB": None}]})

        vm = client.virtual_machines()[0]

        self.assertEqual(vm["ram_gb"], 0)
        self.assertEqual(vm["vcpus"], 0)
        self.assertEqual(vm["status"], "running")


# --- Proxmox ----------------------------------------------------------------------


    def test_a_machine_comes_back_with_the_name_of_its_esxi(self) -> None:
        """Sin esto, ninguna máquina de un vCenter se colgaba de su servidor.

        vCenter no dice el host en `/vcenter/vm`, así que hay que cruzarlo
        preguntando por cada ESXi. Proxmox sí lo trae, y por eso el fallo solo
        aparecía con un vCenter delante -- y se llevaba por delante media
        respuesta a «¿de qué depende este servidor?».
        """
        client, _rest = self._logged_in(
            {
                "/api/vcenter/host": VMWARE_HOSTS,
                "/api/vcenter/vm": VMWARE_VMS,
                "/api/vcenter/vm?filter.hosts=host-16": [{"vm": "vm-101"}],
                "/api/vcenter/vm?filter.hosts=host-22": [{"vm": "vm-102"}],
                "/api/vcenter/vm/vm-101": VMWARE_VM_DETAIL,
            }
        )

        machines = {vm["name"]: vm for vm in client.virtual_machines()}

        self.assertEqual(machines["srv-ficheros"]["host"], "esxi01.acme.local")
        self.assertEqual(machines["srv-correo"]["host"], "esxi02.acme.local")

    def test_an_esxi_that_will_not_answer_does_not_lose_the_other_machines(self) -> None:
        """Un hallazgo incompleto vale más que ninguno."""
        client, _rest = self._logged_in(
            {
                "/api/vcenter/host": VMWARE_HOSTS,
                "/api/vcenter/vm": VMWARE_VMS,
                "/api/vcenter/vm?filter.hosts=host-16": [{"vm": "vm-101"}],
                # host-22 no está: preguntar por él lanza.
                "/api/vcenter/vm/vm-101": VMWARE_VM_DETAIL,
            }
        )

        machines = {vm["name"]: vm for vm in client.virtual_machines()}

        self.assertEqual(len(machines), 2)
        self.assertEqual(machines["srv-ficheros"]["host"], "esxi01.acme.local")
        self.assertEqual(machines["srv-correo"]["host"], "")

    def test_without_permission_to_list_hosts_the_machines_still_arrive(self) -> None:
        """El usuario configurado puede no tener lectura sobre los hosts.

        Quedarse sin máquinas por eso sería cambiar un dato incompleto por
        ningún dato.
        """
        client, _rest = self._logged_in(
            {
                # `/api/vcenter/host` no está: listar los hosts lanza.
                "/api/vcenter/vm": VMWARE_VMS,
                "/api/vcenter/vm/vm-101": VMWARE_VM_DETAIL,
            }
        )

        machines = client.virtual_machines()

        self.assertEqual(len(machines), 2)
        self.assertEqual({vm["host"] for vm in machines}, {""})


class ProxmoxTests(unittest.TestCase):
    def _client(self, routes: dict[str, Any], *, username: str = "lector@pve", secret: str = "s3cr3t"):
        client = ProxmoxClient("pve.acme.local", username, secret)
        rest = _Rest(routes)
        client.rest = rest  # type: ignore[assignment]
        return client, rest

    def test_an_api_token_needs_no_ticket_at_all(self) -> None:
        """Es la forma buena para un agente: se limita a solo lectura y caduca
        cuando se quiera, sin una sesión que renovar."""
        client, rest = self._client({}, username="agente@pve!inventario", secret="uuid-del-token")

        client.login()

        self.assertEqual(rest.calls, [])
        self.assertEqual(
            client.headers["Authorization"], "PVEAPIToken=agente@pve!inventario=uuid-del-token"
        )

    def test_a_password_login_keeps_only_the_read_cookie(self) -> None:
        """Sin `CSRFPreventionToken` no se puede escribir nada en el hipervisor,
        y este agente no escribe ni debe poder hacerlo."""
        client, _ = self._client({"/api2/json/access/ticket": PROXMOX_TICKET})

        client.login()

        self.assertIn("Cookie", client.headers)
        self.assertNotIn("CSRFPreventionToken", client.headers)

    def test_the_password_travels_in_the_body_and_not_in_the_path(self) -> None:
        client, rest = self._client({"/api2/json/access/ticket": PROXMOX_TICKET})

        client.login()

        method, path, _headers, body = rest.calls[0]
        self.assertEqual((method, path), ("POST", "/api2/json/access/ticket"))
        self.assertNotIn("s3cr3t", path)
        self.assertEqual(body, {"username": "lector@pve", "password": "s3cr3t"})

    def test_a_login_without_a_ticket_is_an_error_and_not_a_silent_pass(self) -> None:
        client, _ = self._client({"/api2/json/access/ticket": {"data": None}})

        with self.assertRaises(HypervisorError):
            client.login()

    def test_the_nodes_become_hosts(self) -> None:
        client, _ = self._client(
            {"/api2/json/access/ticket": PROXMOX_TICKET, "/api2/json/nodes": PROXMOX_NODES}
        )
        client.login()

        hosts = client.hosts()

        self.assertEqual([host["name"] for host in hosts], ["pve01", "pve02"])
        self.assertEqual(hosts[0]["power_state"], "POWERED_ON")
        self.assertEqual(hosts[1]["power_state"], "")

    def test_machines_and_containers_come_out_with_their_sizes(self) -> None:
        client, _ = self._client(
            {
                "/api2/json/access/ticket": PROXMOX_TICKET,
                "/api2/json/cluster/resources?type=vm": PROXMOX_RESOURCES,
            }
        )
        client.login()

        vms = {vm["id"]: vm for vm in client.virtual_machines()}

        self.assertEqual(vms["100"]["name"], "srv-ficheros")
        self.assertEqual(vms["100"]["status"], "running")
        self.assertEqual(vms["100"]["vcpus"], 4)
        self.assertEqual(vms["100"]["ram_gb"], 8)
        self.assertEqual(vms["100"]["disk_gb"], 128)
        self.assertEqual(vms["100"]["host"], "pve01")
        # Proxmox no dice qué hay dentro de una KVM; de un contenedor, sí.
        self.assertEqual(vms["100"]["operating_system"], "")
        self.assertEqual(vms["201"]["operating_system"], "Contenedor LXC")
        self.assertEqual(vms["201"]["status"], "stopped")

    def test_a_resource_without_vmid_is_skipped(self) -> None:
        client, _ = self._client(
            {
                "/api2/json/access/ticket": PROXMOX_TICKET,
                "/api2/json/cluster/resources?type=vm": {"data": [{"name": "rara"}, PROXMOX_RESOURCES["data"][0]]},
            }
        )
        client.login()

        self.assertEqual([vm["id"] for vm in client.virtual_machines()], ["100"])

    def test_an_answer_with_a_shape_nobody_expected_gives_nothing(self) -> None:
        client, _ = self._client(
            {
                "/api2/json/access/ticket": PROXMOX_TICKET,
                "/api2/json/nodes": {"data": "no soy una lista"},
            }
        )
        client.login()

        self.assertEqual(client.hosts(), [])


# --- El colector ------------------------------------------------------------------


class _FakeClient:
    """Un hipervisor de mentira. Se sustituye entero en `CLIENTS`."""

    instances: list["_FakeClient"] = []

    def __init__(self, host: str, username: str, secret: str, *, port: int = 0, ca_file: str = "") -> None:
        self.host = host
        self.username = username
        self.secret = secret
        self.port = port
        self.ca_file = ca_file
        self.login_error: Exception | None = None
        self._hosts: list[dict[str, Any]] = []
        self._vms: list[dict[str, Any]] = []
        _FakeClient.instances.append(self)

    def login(self) -> None:
        if self.login_error is not None:
            raise self.login_error

    def hosts(self) -> list[dict[str, Any]]:
        return self._hosts

    def virtual_machines(self) -> list[dict[str, Any]]:
        return self._vms


def client_factory(
    *,
    hosts: dict[str, list[dict[str, Any]]] | None = None,
    vms: dict[str, list[dict[str, Any]]] | None = None,
    login_errors: dict[str, Exception] | None = None,
) -> Any:
    def build(host: str, username: str, secret: str, *, port: int = 0, ca_file: str = "") -> _FakeClient:
        client = _FakeClient(host, username, secret, port=port, ca_file=ca_file)
        client._hosts = (hosts or {}).get(host, [])
        client._vms = (vms or {}).get(host, [])
        client.login_error = (login_errors or {}).get(host)
        return client

    return build


class HypervisorCollectorTests(unittest.TestCase):
    ESXI = [{"name": "esxi01.acme.local", "power_state": "POWERED_ON", "connection_state": "CONNECTED"}]
    VMS = [
        {
            "id": "vm-101",
            "name": "srv-ficheros",
            "status": "running",
            "vcpus": 4,
            "ram_gb": 8,
            "disk_gb": 192,
            "operating_system": "Ubuntu Linux (64-bit)",
            "host": "esxi01.acme.local",
        }
    ]

    def setUp(self) -> None:
        _FakeClient.instances = []

    def _ctx(self, credentials: list[dict[str, Any]] | None = None) -> dict:
        default = [
            {
                "kind": "vmware",
                "username": "lector@vsphere.local",
                "secret": "s3cr3t",
                "host": "vc.acme.local",
                "label": "vCenter de la sede",
            }
        ]
        return {"config": {"credentials": credentials if credentials is not None else default}, "env": None}

    def _collect(self, ctx: dict, *, factory: Any = None, resolve: Any = ""):
        build = factory or client_factory(hosts={"vc.acme.local": self.ESXI}, vms={"vc.acme.local": self.VMS})
        clients = {"vmware": build, "proxmox": build}
        resolver = resolve if callable(resolve) else (lambda name: resolve)
        with mock.patch.dict("agent.collectors.hypervisors.CLIENTS", clients, clear=True), \
             mock.patch("agent.collectors.hypervisors.net.resolve", resolver):
            return HypervisorCollector().collect(ctx)

    def test_without_any_hypervisor_configured_it_says_so_and_returns_nothing(self) -> None:
        ctx = self._ctx([])

        self.assertEqual(self._collect(ctx), [])
        self.assertTrue(any("Ajustes" in line for line in ctx["errors"]))

    def test_a_credential_without_an_address_names_itself_in_the_error(self) -> None:
        """Un vCenter no se descubre solo, se escribe. Si falta la dirección hay
        que decir **cuál** de las credenciales falla, no callarse."""
        ctx = self._ctx([{"kind": "vmware", "username": "u", "secret": "s", "label": "vCenter de la nave"}])

        self.assertEqual(self._collect(ctx), [])
        self.assertTrue(any("vCenter de la nave" in line for line in ctx["errors"]))

    def test_a_hypervisor_that_says_401_adds_a_line_and_does_not_kill_the_sweep(self) -> None:
        """Una contraseña cambiada en el vCenter no puede dejar sin barrido al
        Proxmox de al lado, ni al ping, ni al SNMP."""
        ctx = self._ctx(
            [
                {"kind": "vmware", "username": "u", "secret": "s", "host": "vc.acme.local"},
                {"kind": "proxmox", "username": "lector@pve", "secret": "s", "host": "pve.acme.local"},
            ]
        )
        factory = client_factory(
            hosts={"pve.acme.local": [{"name": "pve01"}]},
            login_errors={"vc.acme.local": HypervisorError("401 en /api/session")},
        )

        findings = self._collect(ctx, factory=factory, resolve="10.0.0.9")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].payload["hostname"], "pve01")
        self.assertTrue(any("401" in line for line in ctx["errors"]))

    def test_the_password_never_reaches_the_error_lines(self) -> None:
        ctx = self._ctx(
            [{"kind": "vmware", "username": "u", "secret": "ultrasecreta", "host": "vc.acme.local"}]
        )
        factory = client_factory(login_errors={"vc.acme.local": HypervisorError("401 en /api/session")})

        self._collect(ctx, factory=factory)

        self.assertNotIn("ultrasecreta", " ".join(ctx["errors"]))

    def test_an_unreachable_hypervisor_is_a_line_and_not_a_traceback(self) -> None:
        ctx = self._ctx()
        factory = client_factory(
            login_errors={"vc.acme.local": HypervisorError("[Errno 111] Connection refused")}
        )

        self.assertEqual(self._collect(ctx, factory=factory), [])
        self.assertTrue(any("vc.acme.local" in line for line in ctx["errors"]))

    def test_an_esxi_that_resolves_merges_with_the_row_the_sweep_left(self) -> None:
        """Un ESXi contesta al ping como cualquier otro: sin traducir el nombre
        a una dirección, este hallazgo y el del barrido son dos filas."""
        ctx = self._ctx()

        findings = self._collect(ctx, resolve="192.168.1.30")
        hosts = [finding for finding in findings if finding.kind == "host"]

        self.assertEqual(hosts[0].identity, {"ip": "192.168.1.30"})
        self.assertTrue(hosts[0].payload["is_virtualization_host"])
        self.assertEqual(hosts[0].payload["cluster"], "vc.acme.local")
        self.assertEqual(hosts[0].payload["platform"], "vmware")

    def test_an_esxi_that_does_not_resolve_falls_back_to_its_name(self) -> None:
        """Un CPD en otra VLAN donde el DNS del agente no llega: mejor una fila
        por nombre que ninguna."""
        ctx = self._ctx()

        hosts = [finding for finding in self._collect(ctx, resolve="") if finding.kind == "host"]

        self.assertEqual(hosts[0].identity, {"hostname": "esxi01.acme.local"})

    def test_a_vm_identity_survives_a_rename(self) -> None:
        """Renombrar una máquina virtual es un gesto de un segundo. Con el
        nombre dentro de la huella, cada renombrado abriría una fila nueva en la
        bandeja y dejaría la vieja huérfana."""
        ctx = self._ctx()

        vms = [finding for finding in self._collect(ctx) if finding.kind == "vm"]

        self.assertEqual(len(vms), 1)
        self.assertEqual(vms[0].identity, {"hypervisor": "vc.acme.local", "vm_id": "vm-101"})
        self.assertNotIn("srv-ficheros", str(vms[0].identity))
        self.assertEqual(vms[0].payload["name"], "srv-ficheros")
        self.assertEqual(vms[0].payload["host"], "esxi01.acme.local")

    def test_a_vm_without_sizes_comes_out_with_zeros_and_not_with_nones(self) -> None:
        """Lo que llega del hipervisor va tal cual al servidor: un `None` donde
        se espera un número rompe la fila en la bandeja, no aquí."""
        ctx = self._ctx()
        factory = client_factory(vms={"vc.acme.local": [{"id": "vm-9", "name": "rara"}]})

        vms = [finding for finding in self._collect(ctx, factory=factory) if finding.kind == "vm"]

        self.assertEqual(vms[0].payload["vcpus"], 0)
        self.assertEqual(vms[0].payload["ram_gb"], 0)
        self.assertEqual(vms[0].payload["disk_gb"], 0)
        self.assertEqual(vms[0].payload["status"], "")

    def test_the_company_ca_reaches_the_client(self) -> None:
        """La verificación de TLS no se desactiva: la salida ante un certificado
        autofirmado es dar la CA, y tiene que llegar hasta abajo."""
        ctx = self._ctx(
            [
                {
                    "kind": "vmware",
                    "username": "u",
                    "secret": "s",
                    "host": "vc.acme.local",
                    "ca_file": "/etc/ssl/acme-ca.pem",
                    "port": 8443,
                }
            ]
        )

        self._collect(ctx)

        self.assertEqual(_FakeClient.instances[0].ca_file, "/etc/ssl/acme-ca.pem")
        self.assertEqual(_FakeClient.instances[0].port, 8443)

    def test_a_hypervisor_does_not_need_the_sweep_to_have_run(self) -> None:
        """A diferencia de SSH y WinRM: un vCenter tiene dirección propia, así
        que un CPD donde el barrido no llega se inventaría igual."""
        ctx = self._ctx()

        self.assertTrue(self._collect(ctx))
        self.assertEqual(ctx.get("errors", []), [])


class RegistrationTests(unittest.TestCase):
    def test_the_collector_is_registered_under_its_name(self) -> None:
        self.assertEqual(HypervisorCollector.name, "hypervisors")

    def test_every_supported_platform_has_a_client_and_a_label(self) -> None:
        """Añadir un hipervisor es una entrada en cada sitio; olvidar la
        etiqueta sería un `KeyError` a mitad del barrido, no un aviso."""
        self.assertEqual(
            set(hypervisors_collector.CLIENTS), set(hypervisors_collector.KIND_LABELS)
        )


if __name__ == "__main__":
    unittest.main()
