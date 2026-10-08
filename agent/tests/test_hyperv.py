"""El cliente de Hyper-V, con `pywinrm` fingido y ni un Windows de verdad.

Las fixturas son el JSON que devuelve el guion de `agent/hyperv.py`
--`ConvertTo-Json -Compress`-- y las formas raras que puede tomar: la lista de
máquinas desenvuelta en un objeto suelto, un Windows que no es un Hyper-V, o
texto que no es JSON. Lo que más importa es lo de siempre en los clientes de
hipervisor: cada fallo es un `HypervisorError` con un mensaje que orienta,
nunca un traceback a mitad del barrido.
"""

from __future__ import annotations

import json
import unittest
from typing import Any
from unittest import mock

from agent import hyperv, winrm
from agent.hypervisor import HypervisorError

# --- Fixturas -------------------------------------------------------------------

#: Un host con dos máquinas, tal cual sale del guion: una encendida y una
#: apagada, con los tamaños en bytes como los da Hyper-V.
DOS_VMS: dict[str, Any] = {
    "hostname": "SRV-HV01",
    "has_hyperv": True,
    "vms": [
        {
            "id": "f0e1d2c3-b4a5-4968-8776-655443322110",
            "name": "srv-ficheros",
            "state": "Running",
            "vcpus": 4,
            "ram_bytes": 8589934592,
            "disk_bytes": 137438953472,
        },
        {
            "id": "0a1b2c3d-4e5f-4a6b-9c8d-7e6f5a4b3c2d",
            "name": "srv-copias",
            "state": "Off",
            "vcpus": 2,
            "ram_bytes": 4294967296,
            "disk_bytes": 68719476736,
        },
    ],
}

#: Un Windows normal al que alguien apuntó la credencial por error.
SIN_HYPERV: dict[str, Any] = {"hostname": "PORTATIL-05", "has_hyperv": False, "vms": []}

#: `ConvertTo-Json` con una sola máquina y sin el `@()`: el objeto llega suelto.
UNA_VM_DESENVUELTA: dict[str, Any] = {
    "hostname": "SRV-HV02",
    "has_hyperv": True,
    "vms": {
        "id": "11111111-2222-4333-8444-555566667777",
        "name": "srv-unico",
        "state": "Running",
        "vcpus": 2,
        "ram_bytes": 4294967296,
        "disk_bytes": 42949672960,
    },
}


def as_stdout(data: dict[str, Any]) -> bytes:
    """Lo que llega por `std_out`: bytes con el JSON comprimido de PowerShell."""
    return json.dumps(data, separators=(",", ":")).encode()


class _FakeResult:
    def __init__(self, status_code: int = 0, std_out: bytes = b"", std_err: bytes = b"") -> None:
        self.status_code = status_code
        self.std_out = std_out
        self.std_err = std_err


class _FakeSession:
    """La `Session` de `pywinrm`, con lo justo para el cliente."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.args = args
        self.kwargs = kwargs

    def run_ps(self, script: str) -> _FakeResult:  # pragma: no cover - se sustituye
        raise NotImplementedError


def fake_pywinrm(session_factory: Any) -> Any:
    """Un módulo `winrm` de PyPI de mentira, con la `Session` que se le pida."""
    module = mock.Mock()
    module.Session = session_factory
    return module


class HyperVClientTests(unittest.TestCase):
    def _client(self, **extra: Any) -> hyperv.HyperVClient:
        return hyperv.HyperVClient("srv-hv01.acme.local", "ACME\\svc", "s3cr3t", **extra)

    def _login(self, session_factory: Any, **extra: Any) -> hyperv.HyperVClient:
        client = self._client(**extra)
        with mock.patch("agent.winrm.AVAILABLE", True), \
             mock.patch("agent.winrm.pywinrm", fake_pywinrm(session_factory), create=True):
            client.login()
        return client

    # --- El camino bueno ----------------------------------------------------------

    def test_a_host_with_two_vms_comes_out_fully_mapped(self) -> None:
        """El contrato entero de una vez: el host como los de vCenter, y cada
        máquina con el `VMId` de huella, los tamaños en GB y su host puesto."""

        class Session(_FakeSession):
            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(DOS_VMS))

        client = self._login(Session)

        self.assertEqual(
            client.hosts(),
            [
                {
                    "name": "SRV-HV01",
                    "power_state": "POWERED_ON",
                    "connection_state": "online",
                    "cluster": "",
                    "manufacturer": "",
                    "model": "",
                    "serial": "",
                }
            ],
        )
        vms = {vm["id"]: vm for vm in client.virtual_machines()}
        encendida = vms["f0e1d2c3-b4a5-4968-8776-655443322110"]
        self.assertEqual(encendida["name"], "srv-ficheros")
        self.assertEqual(encendida["status"], "running")
        self.assertEqual(encendida["vcpus"], 4)
        self.assertEqual(encendida["ram_gb"], 8)
        self.assertEqual(encendida["disk_gb"], 128)
        self.assertEqual(encendida["operating_system"], "")
        self.assertEqual(encendida["host"], "SRV-HV01")
        apagada = vms["0a1b2c3d-4e5f-4a6b-9c8d-7e6f5a4b3c2d"]
        self.assertEqual(apagada["status"], "stopped")
        self.assertEqual(apagada["ram_gb"], 4)
        self.assertEqual(apagada["disk_gb"], 64)

    def test_login_asks_everything_once_and_the_getters_stay_off_the_network(self) -> None:
        """Una conexión WinRM tarda más en abrirse que en contestar: todo va en
        un solo PowerShell y las otras dos llamadas leen de lo cacheado."""
        calls: list[str] = []

        class Session(_FakeSession):
            def run_ps(self, script: str) -> _FakeResult:
                calls.append(script)
                return _FakeResult(0, as_stdout(DOS_VMS))

        client = self._login(Session)
        client.hosts()
        client.virtual_machines()
        client.virtual_machines()

        self.assertEqual(len(calls), 1)

    # --- Los errores que orientan ---------------------------------------------------

    def test_a_windows_without_hyperv_says_so_instead_of_reporting_zero_vms(self) -> None:
        """Apuntar la credencial a un Windows cualquiera es un error de
        configuración: hay que decirlo, no devolver un host vacío."""

        class Session(_FakeSession):
            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(SIN_HYPERV))

        with self.assertRaises(HypervisorError) as caught:
            self._login(Session)

        self.assertIn("no es un servidor de Hyper-V", str(caught.exception))
        self.assertIn("vmms", str(caught.exception))

    def test_without_pywinrm_login_raises_and_names_the_missing_library(self) -> None:
        client = self._client()
        with mock.patch("agent.winrm.AVAILABLE", False):
            with self.assertRaises(HypervisorError) as caught:
                client.login()

        self.assertIn("falta pywinrm", str(caught.exception))

    def test_a_failed_powershell_raises_with_the_stderr_and_tries_no_other_transport(self) -> None:
        """Se entró: el guion falló, que es otra cosa. Probar `basic` después
        sería un intento fallido más contra la política de bloqueo del dominio,
        y no arreglaría nada."""
        seen: list[str] = []

        class Session(_FakeSession):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                seen.append(kwargs["transport"])

            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(1, b"", "Get-VM : Acceso denegado".encode())

        with self.assertRaises(HypervisorError) as caught:
            self._login(Session)

        self.assertIn("Acceso denegado", str(caught.exception))
        self.assertEqual(seen, ["ntlm"])

    def test_output_that_is_not_json_is_an_error_and_not_a_traceback(self) -> None:
        """Un Windows viejo sin `ConvertTo-Json` devuelve texto suelto."""

        class Session(_FakeSession):
            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, b"System.Collections.Hashtable\r\n")

        with self.assertRaises(HypervisorError) as caught:
            self._login(Session)

        self.assertIn("no era JSON", str(caught.exception))

    def test_a_host_nobody_can_enter_is_a_hypervisor_error(self) -> None:
        class Session(_FakeSession):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                raise ConnectionRefusedError("[Errno 111] Connection refused")

        with self.assertRaises(HypervisorError) as caught:
            self._login(Session)

        self.assertIn("ConnectionRefused", str(caught.exception))

    def test_the_password_never_appears_in_the_error(self) -> None:
        """El error acaba en el informe de la ejecución, que se guarda y se
        enseña en pantalla. Una contraseña ahí es una contraseña filtrada."""

        class Session(_FakeSession):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                raise RuntimeError("no se pudo autenticar contra http://srv-hv01:5985/wsman")

        with self.assertRaises(HypervisorError) as caught:
            self._login(Session)

        self.assertNotIn("s3cr3t", str(caught.exception))

    # --- El bucle de transportes ----------------------------------------------------

    def test_a_transport_that_blows_up_falls_back_to_the_next(self) -> None:
        """Sin `requests_ntlm` instalado, `pywinrm` lanza al crear la sesión:
        el host tiene que entrar igual por `basic`, no quedarse sin mirar."""
        seen: list[str] = []

        class Session(_FakeSession):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                seen.append(kwargs["transport"])
                if kwargs["transport"] == "ntlm":
                    raise ImportError("No module named 'requests_ntlm'")

            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(DOS_VMS))

        client = self._login(Session)

        self.assertEqual(seen, ["ntlm", "basic"])
        self.assertEqual(len(client.virtual_machines()), 2)

    def test_tls_verification_is_never_switched_off(self) -> None:
        """Contra el 5986 con certificado autofirmado la salida correcta es dar
        la CA de la empresa, y tiene que llegar hasta la sesión."""
        captured: dict[str, Any] = {}

        class Session(_FakeSession):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                captured.update(kwargs)
                captured["endpoint"] = args[0]

            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(DOS_VMS))

        self._login(Session, port=5986, ca_file="/etc/ssl/acme-ca.pem")

        self.assertEqual(captured["server_cert_validation"], "validate")
        self.assertEqual(captured["ca_trust_path"], "/etc/ssl/acme-ca.pem")
        self.assertTrue(captured["endpoint"].startswith("https://"))

    def test_without_a_ca_the_path_is_none_and_not_an_empty_string(self) -> None:
        captured: dict[str, Any] = {}

        class Session(_FakeSession):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                captured.update(kwargs)

            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(DOS_VMS))

        self._login(Session)

        self.assertIsNone(captured["ca_trust_path"])

    # --- Las formas raras del JSON --------------------------------------------------

    def test_a_single_vm_unwrapped_by_convertto_json_still_comes_out(self) -> None:
        """`ConvertTo-Json` desenvuelve las listas de un elemento. El guion
        fuerza el array con `@()`, pero un objeto suelto no puede acabar en un
        `TypeError` a mitad del barrido."""

        class Session(_FakeSession):
            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(UNA_VM_DESENVUELTA))

        client = self._login(Session)
        vms = client.virtual_machines()

        self.assertEqual(len(vms), 1)
        self.assertEqual(vms[0]["name"], "srv-unico")
        self.assertEqual(vms[0]["host"], "SRV-HV02")

    def test_paused_and_saved_count_as_suspended_and_the_unknown_as_running(self) -> None:
        """`Saved` es una suspensión a disco. Lo desconocido cae en `running`
        por el criterio conservador de siempre: mejor avisar de una máquina que
        quizá corre que darla por apagada y que alguien la desenchufe."""
        answer = dict(DOS_VMS)
        answer["vms"] = [
            {"id": "aaaa", "name": "pausada", "state": "Paused"},
            {"id": "bbbb", "name": "guardada", "state": "Saved"},
            {"id": "cccc", "name": "rara", "state": "OffCritical"},
        ]

        class Session(_FakeSession):
            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(answer))

        client = self._login(Session)
        status = {vm["name"]: vm["status"] for vm in client.virtual_machines()}

        self.assertEqual(status, {"pausada": "suspended", "guardada": "suspended", "rara": "running"})

    def test_a_vm_without_sizes_comes_out_with_zeros_and_not_with_nones(self) -> None:
        """Lo que llega del hipervisor va tal cual al servidor: un `None` donde
        se espera un número rompe la fila en la bandeja, no aquí."""
        answer = dict(DOS_VMS)
        answer["vms"] = [{"id": "dddd", "name": "rara", "state": "Running", "ram_bytes": None}]

        class Session(_FakeSession):
            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(answer))

        vm = self._login(Session).virtual_machines()[0]

        self.assertEqual(vm["vcpus"], 0)
        self.assertEqual(vm["ram_gb"], 0)
        self.assertEqual(vm["disk_gb"], 0)

    def test_a_vm_without_identifier_is_skipped_and_the_rest_survives(self) -> None:
        answer = dict(DOS_VMS)
        answer["vms"] = [{"name": "sin-id", "state": "Running"}, DOS_VMS["vms"][0]]

        class Session(_FakeSession):
            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(answer))

        vms = self._login(Session).virtual_machines()

        self.assertEqual([vm["name"] for vm in vms], ["srv-ficheros"])

    def test_the_script_forces_the_array_and_checks_the_vmms_service(self) -> None:
        """Los dos detalles del guion que no se ven en los tests de arriba:
        sin el `@()` la lista de una máquina llega desenvuelta, y sin `vmms` no
        se distingue un Hyper-V vacío de un Windows que nunca lo fue."""
        self.assertIn("vms          = @($vms)", hyperv.SCRIPT)
        self.assertIn("Get-Service -Name 'vmms'", hyperv.SCRIPT)
        self.assertIn("ConvertTo-Json -Depth 4 -Compress", hyperv.SCRIPT)



class HyperVHardwareTests(unittest.TestCase):
    """Lo que WMI dice de la caja y el clúster de conmutación por error.

    Fabricante, modelo y serie son lo que hace falta para pedir un recambio y
    para que el catálogo ponga las fuentes de alimentación del servidor.
    """

    def _hosts(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        class Session(_FakeSession):
            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(data))

        client = hyperv.HyperVClient("srv-hv01.acme.local", "ACME\\svc", "s3cr3t")
        with mock.patch("agent.winrm.AVAILABLE", True), \
             mock.patch("agent.winrm.pywinrm", fake_pywinrm(Session), create=True):
            client.login()
        return client.hosts()

    def test_the_host_carries_its_hardware_and_cluster(self) -> None:
        data = {
            **DOS_VMS,
            "manufacturer": "Dell Inc.",
            "model": "PowerEdge R650",
            "serial": "7XK2Q53",
            "cluster": "CL-HV",
        }

        host = self._hosts(data)[0]

        self.assertEqual(host["manufacturer"], "Dell Inc.")
        self.assertEqual(host["model"], "PowerEdge R650")
        self.assertEqual(host["serial"], "7XK2Q53")
        self.assertEqual(host["cluster"], "CL-HV")

    def test_a_null_from_convertto_json_is_an_empty_text(self) -> None:
        host = self._hosts({**DOS_VMS, "manufacturer": None, "cluster": None})[0]

        self.assertEqual(host["manufacturer"], "")
        self.assertEqual(host["cluster"], "")

    def test_the_script_asks_wmi_and_only_asks_the_cluster_when_it_exists(self) -> None:
        """`Get-Cluster` solo está con la característica de clúster instalada:
        sin la comprobación, un Hyper-V suelto escribiría un error en cada
        barrido."""
        self.assertIn("Win32_ComputerSystem", hyperv.SCRIPT)
        self.assertIn("Win32_BIOS", hyperv.SCRIPT)
        self.assertIn("Get-Command -Name Get-Cluster", hyperv.SCRIPT)


if __name__ == "__main__":
    unittest.main()
