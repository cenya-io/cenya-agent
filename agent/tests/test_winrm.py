"""El colector WinRM y el transporte que hay debajo, sin `pywinrm` y sin red.

`pywinrm` es opcional a propósito, así que estos tests corren en una máquina
donde no está instalado: la librería se finge entera. Las fixturas son el JSON
que devuelve de verdad el PowerShell de `agent/winrm.py` --`ConvertTo-Json
-Compress`-- y las formas raras que toma en un Windows viejo.
"""

from __future__ import annotations

import json
import unittest
from typing import Any
from unittest import mock

from agent import winrm
from agent.collectors import winrm as winrm_collector
from agent.collectors.winrm import DOMAIN_ROLES, WinrmCollector, _interfaces, roles_of

# --- Fixturas -------------------------------------------------------------------

#: Un controlador de dominio Windows Server 2019, tal cual sale del script.
DC_2019: dict[str, Any] = {
    "hostname": "SRV-DC01",
    "domain": "acme.local",
    "in_domain": True,
    "domain_role": 5,
    "manufacturer": "Dell Inc.",
    "model": "PowerEdge R340",
    "serial": "7X8Y9Z1",
    "os": "Microsoft Windows Server 2019 Standard",
    "os_version": "10.0.17763",
    "hyperv": False,
    "interfaces": [
        {
            "name": "Intel(R) I210 Gigabit Network Connection",
            "mac": "B0-83-FE-11-22-33",
            "ip": "192.168.1.10",
        }
    ],
}

#: Un host de Hyper-V miembro del dominio, con dos tarjetas.
HYPERV_2022: dict[str, Any] = {
    "hostname": "SRV-HV01",
    "domain": "acme.local",
    "in_domain": True,
    "domain_role": 3,
    "manufacturer": "HPE",
    "model": "ProLiant DL360 Gen10",
    "serial": "CZJ1234ABC",
    "os": "Microsoft Windows Server 2022 Datacenter",
    "os_version": "10.0.20348",
    "hyperv": True,
    "interfaces": [
        {"name": "HPE Ethernet 1Gb 4-port 331i Adapter", "mac": "94-40-C9-AA-BB-CC", "ip": "192.168.1.11"},
        {"name": "Hyper-V Virtual Ethernet Adapter", "mac": "94-40-C9-AA-BB-CD", "ip": "10.10.0.11"},
    ],
}

#: Un portátil fuera del dominio: `in_domain` a falso y `domain` con el grupo de
#: trabajo dentro, que no es un dominio y no debe salir como tal.
PORTATIL_SUELTO: dict[str, Any] = {
    "hostname": "PORTATIL-05",
    "domain": "WORKGROUP",
    "in_domain": False,
    "domain_role": 0,
    "manufacturer": "LENOVO",
    "model": "20XW00ABSP",
    "serial": "PF3ABCDE",
    "os": "Microsoft Windows 11 Pro",
    "os_version": "10.0.22631",
    "hyperv": False,
    "interfaces": [{"name": "Intel(R) Wi-Fi 6 AX201 160MHz", "mac": "AC-12-03-DD-EE-FF", "ip": "192.168.1.99"}],
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
    """La `Session` de `pywinrm`, con lo justo para el módulo."""

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


# --- El JSON que vuelve -----------------------------------------------------------


class DecodeTests(unittest.TestCase):
    def test_the_json_of_a_real_windows_becomes_a_dictionary(self) -> None:
        decoded = winrm._decode(as_stdout(DC_2019))

        self.assertIsNotNone(decoded)
        assert decoded is not None
        self.assertEqual(decoded["hostname"], "SRV-DC01")
        self.assertEqual(decoded["domain_role"], 5)

    def test_a_windows_without_convertto_json_gives_nothing_instead_of_raising(self) -> None:
        """En un 2008 R2 sin `ConvertTo-Json` la salida es texto suelto. Tratarla
        como JSON lanzaría dentro del bucle del colector, no ahí abajo."""
        self.assertIsNone(winrm._decode(b"System.Collections.Hashtable\r\n"))

    def test_a_truncated_json_gives_nothing(self) -> None:
        self.assertIsNone(winrm._decode(b'{"hostname":"SRV-DC01","domain'))

    def test_an_empty_answer_gives_nothing(self) -> None:
        self.assertIsNone(winrm._decode(b""))
        self.assertIsNone(winrm._decode("   \r\n"))

    def test_output_that_cannot_be_decoded_does_not_raise(self) -> None:
        """La consola de un Windows en español no siempre llega en UTF-8; un
        `UnicodeDecodeError` aquí se llevaría por delante el barrido entero."""
        self.assertIsNone(winrm._decode(b"\xff\xfe no soy utf-8"))

    def test_a_json_list_is_not_accepted_as_a_record(self) -> None:
        """Si el script devolviera una lista, `data.get(...)` reventaría más
        arriba. Se descarta aquí, que es donde se sabe qué forma tiene."""
        self.assertIsNone(winrm._decode(b'[{"hostname":"SRV-DC01"}]'))
        self.assertIsNone(winrm._decode(b'"solo una cadena"'))


class EndpointTests(unittest.TestCase):
    def test_the_tls_port_goes_through_https(self) -> None:
        self.assertEqual(winrm.endpoint("srv", 5986), "https://srv:5986/wsman")

    def test_the_usual_port_is_the_default(self) -> None:
        self.assertEqual(winrm.endpoint("srv"), "http://srv:5985/wsman")
        self.assertEqual(winrm.endpoint("srv", 0), "http://srv:5985/wsman")


# --- La consulta ------------------------------------------------------------------


class QueryTests(unittest.TestCase):
    def _query(self, session_factory: Any, **extra: Any) -> winrm.Answer:
        with mock.patch("agent.winrm.AVAILABLE", True), \
             mock.patch("agent.winrm.pywinrm", fake_pywinrm(session_factory), create=True):
            return winrm.query(host="192.168.1.10", username="ACME\\svc", secret="s3cr3t", **extra)

    def test_without_pywinrm_it_answers_not_available_instead_of_raising(self) -> None:
        with mock.patch("agent.winrm.AVAILABLE", False):
            answer = winrm.query(host="192.168.1.10", username="u", secret="s")

        self.assertFalse(answer.connected)
        self.assertIn("pywinrm", answer.error)

    def test_a_windows_that_answers_gives_its_record(self) -> None:
        class Session(_FakeSession):
            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(DC_2019))

        answer = self._query(Session)

        self.assertTrue(answer.connected)
        assert answer.data is not None
        self.assertEqual(answer.data["hostname"], "SRV-DC01")

    def test_ntlm_is_tried_before_basic(self) -> None:
        """`basic` solo funciona si alguien lo habilitó a mano; un Windows de
        dominio acepta NTLM de fábrica. Al revés serían dos intentos fallidos
        de autenticación por equipo, que en un dominio bloquea cuentas."""
        seen: list[str] = []

        class Session(_FakeSession):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                seen.append(kwargs["transport"])

            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(DC_2019))

        self._query(Session)

        self.assertEqual(seen, ["ntlm"])
        self.assertEqual(winrm.TRANSPORTS[0], "ntlm")

    def test_a_transport_that_blows_up_falls_back_to_the_next(self) -> None:
        """Sin `requests_ntlm` instalado, `pywinrm` lanza al crear la sesión.
        Dejar el equipo sin mirar por eso es perder media red de Windows."""
        seen: list[str] = []

        class Session(_FakeSession):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                seen.append(kwargs["transport"])
                if kwargs["transport"] == "ntlm":
                    raise ImportError("No module named 'requests_ntlm'")

            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(PORTATIL_SUELTO))

        answer = self._query(Session)

        self.assertEqual(seen, ["ntlm", "basic"])
        self.assertTrue(answer.connected)

    def test_tls_verification_is_never_switched_off(self) -> None:
        """Contra el 5986 con certificado autofirmado la salida correcta es dar
        la CA de la empresa. Sin verificación, cualquiera en medio de la red se
        queda con la contraseña de administrador del dominio."""
        captured: dict[str, Any] = {}

        class Session(_FakeSession):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                captured.update(kwargs)
                captured["endpoint"] = args[0]

            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(DC_2019))

        self._query(Session, port=5986, ca_file="/etc/ssl/acme-ca.pem")

        self.assertEqual(captured["server_cert_validation"], "validate")
        self.assertEqual(captured["ca_trust_path"], "/etc/ssl/acme-ca.pem")
        self.assertTrue(captured["endpoint"].startswith("https://"))

    def test_without_a_ca_the_path_is_none_and_not_an_empty_string(self) -> None:
        """Una cadena vacía pasada como ruta de CA rompe el intento sin decir
        por qué; `None` significa «las CA del sistema», que es lo que se quiere.
        """
        captured: dict[str, Any] = {}

        class Session(_FakeSession):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                captured.update(kwargs)

            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(0, as_stdout(DC_2019))

        self._query(Session)

        self.assertIsNone(captured["ca_trust_path"])

    def test_a_powershell_that_failed_counts_as_connected_but_without_data(self) -> None:
        """Se entró: el guion falló, que es otra cosa. Probar el otro transporte
        no arreglaría nada y sería un intento fallido más contra el dominio."""
        seen: list[str] = []

        class Session(_FakeSession):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                super().__init__(*args, **kwargs)
                seen.append(kwargs["transport"])

            def run_ps(self, script: str) -> _FakeResult:
                return _FakeResult(1, b"", "Get-CimInstance : Acceso denegado".encode())

        answer = self._query(Session)

        self.assertTrue(answer.connected)
        self.assertIsNone(answer.data)
        self.assertEqual(seen, ["ntlm"])

    def test_a_host_nobody_can_enter_is_an_answer_and_not_an_exception(self) -> None:
        class Session(_FakeSession):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                raise ConnectionRefusedError("[Errno 111] Connection refused")

        answer = self._query(Session)

        self.assertFalse(answer.connected)
        self.assertIn("ConnectionRefused", answer.error)

    def test_the_password_never_appears_in_the_error(self) -> None:
        """El error acaba en el informe de la ejecución, que se guarda y se
        enseña en pantalla. Una contraseña ahí es una contraseña filtrada."""

        class Session(_FakeSession):
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                # Una librería descuidada podría meter el `auth` en su mensaje.
                raise RuntimeError("no se pudo autenticar contra http://192.168.1.10:5985/wsman")

        answer = self._query(Session)

        self.assertNotIn("s3cr3t", answer.error)


# --- Lo que se saca del registro --------------------------------------------------


class RolesTests(unittest.TestCase):
    def test_a_domain_controller_is_named(self) -> None:
        """Saber cuál es el controlador de dominio es media respuesta a «¿de qué
        depende esto?», que es la pregunta que vende el producto."""
        self.assertEqual(roles_of(DC_2019), [DOMAIN_ROLES[5]])

    def test_a_hyperv_host_is_named(self) -> None:
        self.assertEqual(roles_of(HYPERV_2022), ["host de Hyper-V"])

    def test_a_plain_member_server_claims_nothing(self) -> None:
        self.assertEqual(roles_of(PORTATIL_SUELTO), [])

    def test_a_role_that_is_not_a_number_does_not_raise(self) -> None:
        """El JSON lo escribe un PowerShell de un Windows cualquiera: `null` o
        una cadena en `domain_role` no pueden tumbar el barrido."""
        self.assertEqual(roles_of({"domain_role": None}), [])
        self.assertEqual(roles_of({"domain_role": "controlador"}), [])
        self.assertEqual(roles_of({}), [])
        self.assertEqual(roles_of({"domain_role": 99}), [])


class InterfaceNormalisationTests(unittest.TestCase):
    def test_windows_macs_are_written_the_way_the_rest_of_the_product_does(self) -> None:
        """Windows las da con guiones y en mayúsculas. Sin normalizar, la misma
        tarjeta vista por el barrido y por WinRM parecían dos."""
        found = _interfaces(DC_2019)

        self.assertEqual(found[0]["mac"], "b0:83:fe:11:22:33")
        self.assertEqual(found[0]["ip"], "192.168.1.10")

    def test_an_interfaces_field_that_is_not_a_list_does_not_kill_the_collector(self) -> None:
        """`ConvertTo-Json` de un array vacío no siempre da `[]`, y con una sola
        tarjeta algunas versiones lo desenvuelven en un objeto suelto."""
        self.assertEqual(_interfaces({"interfaces": None}), [])
        self.assertEqual(_interfaces({"interfaces": ""}), [])
        self.assertEqual(_interfaces({}), [])
        self.assertEqual(_interfaces({"interfaces": {"name": "NIC", "mac": "AA-BB"}}), [])

    def test_an_entry_without_a_name_is_dropped_and_the_rest_survives(self) -> None:
        data = {"interfaces": ["no soy un diccionario", {"mac": "AA-BB-CC-DD-EE-FF"}, {"name": "NIC1"}]}

        self.assertEqual([iface["name"] for iface in _interfaces(data)], ["NIC1"])


# --- El colector ------------------------------------------------------------------


class WinrmCollectorTests(unittest.TestCase):
    HOSTS = [
        {"ip": "192.168.1.10", "mac": "b0:83:fe:11:22:33"},
        {"ip": "192.168.1.11", "mac": "94:40:c9:aa:bb:cc"},
    ]

    def _ctx(self, **extra: Any) -> dict:
        ctx: dict[str, Any] = {
            "config": {"credentials": [{"kind": "winrm", "username": "ACME\\svc", "secret": "s3cr3t"}]},
            "env": None,
            "hosts": list(self.HOSTS),
        }
        ctx.update(extra)
        return ctx

    def _collect(
        self,
        ctx: dict,
        *,
        answers: dict[str, winrm.Answer] | None = None,
        listening: dict[int, list[str]] | None = None,
        asked: list[tuple[str, int]] | None = None,
    ):
        replies = answers if answers is not None else {"192.168.1.10": winrm.Answer(True, DC_2019)}
        open_ports = listening if listening is not None else {winrm.DEFAULT_PORT: list(replies)}

        def fake_listening(ips: list[str], port: int) -> list[str]:
            return [ip for ip in ips if ip in open_ports.get(port, [])]

        def fake_query(*, host: str, username: str, secret: str, port: int = 0, ca_file: str = "") -> winrm.Answer:
            if asked is not None:
                asked.append((host, port))
            return replies.get(host, winrm.Answer(False, None, "no se pudo conectar"))

        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", True), \
             mock.patch("agent.collectors.winrm.net.hosts_listening", fake_listening), \
             mock.patch("agent.collectors.winrm.winrm.query", fake_query):
            return WinrmCollector().collect(ctx)

    def test_without_pywinrm_it_reports_and_returns_nothing(self) -> None:
        ctx = self._ctx()
        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", False):
            self.assertEqual(WinrmCollector().collect(ctx), [])

        self.assertTrue(any("pywinrm" in line for line in ctx["errors"]))

    def test_running_before_the_sweep_complains_instead_of_going_quiet(self) -> None:
        """Sin `ctx["hosts"]` no hay a quién llamar; callarse marcaría la
        ejecución como correcta y sin un solo Windows en la bandeja."""
        ctx = self._ctx()
        ctx.pop("hosts")

        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", True):
            self.assertEqual(WinrmCollector().collect(ctx), [])

        self.assertTrue(any("barrido no ha corrido" in line for line in ctx["errors"]))

    def test_without_credentials_it_says_where_to_put_them(self) -> None:
        ctx = self._ctx(config={})
        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", True):
            self.assertEqual(WinrmCollector().collect(ctx), [])

        self.assertTrue(any("Ajustes" in line for line in ctx["errors"]))

    def test_a_sweep_that_found_nobody_is_not_an_error(self) -> None:
        ctx = self._ctx(hosts=[])
        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", True):
            self.assertEqual(WinrmCollector().collect(ctx), [])

        self.assertEqual(ctx.get("errors", []), [])

    def test_nobody_listening_on_either_port_is_not_an_error_either(self) -> None:
        """En una red de Linux nadie tiene el 5985 abierto: es lo normal."""
        ctx = self._ctx()

        self.assertEqual(self._collect(ctx, answers={}, listening={}), [])
        self.assertEqual(ctx.get("errors", []), [])

    def test_a_windows_that_answers_is_enriched_not_duplicated(self) -> None:
        """La identidad es la que dejó el barrido, así que la huella coincide y
        la bandeja enriquece esa fila en vez de estrenar otra."""
        ctx = self._ctx()

        findings = self._collect(ctx)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.kind, "host")
        self.assertEqual(finding.identity, {"mac": "b0:83:fe:11:22:33"})
        self.assertEqual(finding.payload["hostname"], "SRV-DC01")
        self.assertEqual(finding.payload["description"], "Microsoft Windows Server 2019 Standard 10.0.17763")
        self.assertEqual(finding.payload["domain"], "acme.local")
        self.assertEqual(finding.payload["roles"], [DOMAIN_ROLES[5]])
        self.assertEqual(finding.payload["serial"], "7X8Y9Z1")
        self.assertEqual(finding.payload["seen_by"], "winrm")

    def test_a_machine_outside_the_domain_does_not_claim_the_workgroup_as_one(self) -> None:
        """`Win32_ComputerSystem.Domain` trae «WORKGROUP» cuando no hay dominio.
        Guardarlo inventaría un dominio llamado WORKGROUP en el inventario."""
        ctx = self._ctx(hosts=[{"ip": "192.168.1.99", "mac": "ac:12:03:dd:ee:ff"}])

        findings = self._collect(ctx, answers={"192.168.1.99": winrm.Answer(True, PORTATIL_SUELTO)})

        self.assertEqual(findings[0].payload["domain"], "")

    def test_the_5986_only_host_is_asked_on_its_own_port(self) -> None:
        """Un Windows endurecido tiene el 5985 cerrado. Sin el segundo intento
        se queda fuera del inventario sin que nadie lo note."""
        asked: list[tuple[str, int]] = []
        ctx = self._ctx(hosts=[{"ip": "192.168.1.11", "mac": "94:40:c9:aa:bb:cc"}])

        findings = self._collect(
            ctx,
            answers={"192.168.1.11": winrm.Answer(True, HYPERV_2022)},
            listening={winrm.DEFAULT_TLS_PORT: ["192.168.1.11"]},
            asked=asked,
        )

        self.assertEqual(asked, [("192.168.1.11", winrm.DEFAULT_TLS_PORT)])
        self.assertEqual(findings[0].payload["roles"], ["host de Hyper-V"])

    def test_a_host_is_not_asked_twice_on_both_ports(self) -> None:
        """Con los dos puertos abiertos, preguntar por los dos son dos intentos
        de autenticación por equipo contra la política de bloqueo del dominio."""
        asked: list[tuple[str, int]] = []
        ctx = self._ctx(hosts=[{"ip": "192.168.1.10", "mac": "b0:83:fe:11:22:33"}])

        self._collect(
            ctx,
            listening={winrm.DEFAULT_PORT: ["192.168.1.10"], winrm.DEFAULT_TLS_PORT: ["192.168.1.10"]},
            asked=asked,
        )

        self.assertEqual(len(asked), 1)

    def test_the_first_credential_that_gets_in_stops_the_probing(self) -> None:
        """Un barrido cada quince minutos contra cien equipos con credenciales
        de más bloquea al usuario del dominio antes de la primera hora."""
        tried: list[str] = []

        def fake_query(*, host: str, username: str, secret: str, port: int = 0, ca_file: str = "") -> winrm.Answer:
            tried.append(username)
            if username == "ACME\\malo":
                return winrm.Answer(False, None, "401")
            return winrm.Answer(True, DC_2019)

        ctx = self._ctx(
            config={
                "credentials": [
                    {"kind": "winrm", "username": "ACME\\malo", "secret": "x"},
                    {"kind": "winrm", "username": "ACME\\svc", "secret": "y"},
                    {"kind": "winrm", "username": "ACME\\nunca", "secret": "z"},
                ]
            },
            hosts=[{"ip": "192.168.1.10", "mac": "b0:83:fe:11:22:33"}],
        )
        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", True), \
             mock.patch("agent.collectors.winrm.net.hosts_listening", return_value=["192.168.1.10"]), \
             mock.patch("agent.collectors.winrm.winrm.query", fake_query):
            findings = WinrmCollector().collect(ctx)

        self.assertEqual(len(findings), 1)
        self.assertNotIn("ACME\\nunca", tried)

    def test_a_windows_that_says_nothing_useful_leaves_no_row(self) -> None:
        """Entró pero el PowerShell no supo contestar (un 2008 R2 sin
        `ConvertTo-Json`): mejor ninguna fila que una ficha vacía."""
        ctx = self._ctx()

        findings = self._collect(ctx, answers={"192.168.1.10": winrm.Answer(True, None, "sin JSON")})

        self.assertEqual(findings, [])

    def test_the_secret_never_reaches_the_error_lines(self) -> None:
        ctx = self._ctx(config={"credentials": [{"kind": "winrm", "username": "u", "secret": "ultrasecreta"}]})
        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", False):
            WinrmCollector().collect(ctx)

        self.assertNotIn("ultrasecreta", " ".join(ctx.get("errors", [])))

    def test_a_credential_port_outside_the_two_defaults_is_never_probed(self) -> None:
        """FALLO REAL DEL COLECTOR -- este test está en rojo a propósito.

        Es el mismo fallo que el del puerto de SSH, en otro fichero: la
        credencial puede fijar un puerto y `winrm.query` lo respeta, pero el
        sondeo previo solo mira el 5985 y el 5986, así que un WinRM movido de
        sitio se cae de `targets` antes de que nadie lo intente. Ni hallazgo ni
        línea de error: el barrido sale «correcto» y vacío.
        """
        ctx = self._ctx(
            config={"credentials": [{"kind": "winrm", "username": "ACME\\svc", "secret": "s", "port": 5443}]},
            hosts=[{"ip": "192.168.1.10", "mac": "b0:83:fe:11:22:33"}],
        )

        findings = self._collect(
            ctx,
            answers={"192.168.1.10": winrm.Answer(True, DC_2019)},
            listening={5443: ["192.168.1.10"]},
        )

        self.assertEqual(len(findings), 1, "el puerto de la credencial se ignora en el sondeo previo")


class RegistrationTests(unittest.TestCase):
    def test_the_collector_is_registered_under_its_name(self) -> None:
        self.assertEqual(winrm_collector.WinrmCollector.name, "winrm")

    def test_both_service_ports_are_looked_at(self) -> None:
        self.assertEqual(winrm_collector.PORTS, (winrm.DEFAULT_PORT, winrm.DEFAULT_TLS_PORT))


if __name__ == "__main__":
    unittest.main()
