"""The agent, tested without a network: the client against a stub transport,
the collectors against themselves."""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado también bajo `unittest discover`

import contextlib
import http.server
import json
import os
import ssl
import tempfile
import threading
import unittest
import urllib.error
from unittest import mock

from agent import config
from agent import client as agent_client
from agent.client import MAX_BATCH_ITEMS, AgentClient, PushError
from agent.__main__ import MAX_INTERVAL_SECONDS, MIN_INTERVAL_SECONDS, _interval
from agent.collectors import all_collectors
from agent.collectors.local import LocalCollector

#: Un certificado autofirmado de mentira, solo para que `ssl.create_default_
#: context(cafile=...)` tenga algo válido que analizar. No protege nada.
_SELF_SIGNED_PEM = b"""-----BEGIN CERTIFICATE-----
MIIDBTCCAe2gAwIBAgIUJli8B3AnigJ/BxPs8mJRFrSxFvowDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHdGVzdC1jYTAeFw0yNjA4MjYwMjE2NTVaFw0zNjA4MjMw
MjE2NTVaMBIxEDAOBgNVBAMMB3Rlc3QtY2EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDGUVXpcVuRdfsi5k0XLYo9/z+tJQ/ZTzkBn7dGRWBAO/OFbTYd
3SDI/HvPJtlCFhUC27/cs9JAPE3IMhVWkL7d1X3cv1KteRYV0kpq1a0jrUSY+pS+
JnBOAQii/cCvxmgT4my1jPPbOvgOmBDQMaBTrtXGoWHfUS3y5vq2TxyihxqkxvsP
gud/FMXLybkvV9maYJecwIZ2J6AN0esr150PtTCjtT3yGDjWvfDUuAWnznCK2JcP
VsJRUJFaF4IjWGVnfWcNsQ2P0+fAm1Qx0FWY3EV0ozK2PSyBFX+Z1x6IYUyRAdDv
oWUvOBLH0+nhRL+0oE6jKv4V169xF2179narAgMBAAGjUzBRMB0GA1UdDgQWBBSr
1ms+L7Pf/frelzBmhqgkvBstKzAfBgNVHSMEGDAWgBSr1ms+L7Pf/frelzBmhqgk
vBstKzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCdSxxlQzx4
KKw7n3+V7cPOaTbW2HG7inJfjvgXHepXWu641Vwh8oHcsHucyXY0Vsil4vBPJQew
UZO4QG4G5cAwil9jOjLyTpevKZsS+RmNnPwcCEtaUttvgP7i0wZL4Xrp3U8Spd4b
GWl+tVZGU95sl8b20OQcQL8EtaxMTkCfRZr1lddn6WKCsF3oXYAprExgvHlCdK0k
/VW05f+Y9TLXQ8YCxSERNcn849TcwafUoSOvKWLAnStxXmuEuZtT0uQ/rKFv7pT/
QaSDrStMV2DpNMtvYF/M8l1b8La3vlsViVKXTU+Tf7VqowSeqF1nnGRonhfEO0hh
a2EzML7+47oN
-----END CERTIFICATE-----
"""

#: Certificado y clave de un servidor HTTPS de mentira, con `localhost` y
#: `127.0.0.1` como nombres válidos, para el apretón de manos de verdad de
#: `TlsIntegrationTests`. Autofirmado y sin ningún uso fuera de estos tests.
_TLS_CERT = b"""-----BEGIN CERTIFICATE-----
MIIC1DCCAbygAwIBAgIUAXcpLfybEZcSQpIYVmFgR+3v2/4wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgyNjAyMTgzMVoXDTM2MDgy
MzAyMTgzMVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA1c/gW+oCvisxwole9dZKyHYZqAYn4RkoZKmOvi5lx1P/
wwwaOtKhFHiSR2loiCnHzVGex7JSWpuc93dOEDJgtAuwuRgUHQ/39Rvc9jvJud7H
eQfxOUipHOMWQfh/EUkG19jxpsYKW+u9fgACzKHuyxAXW6ptz0wMbkcdA/MSmkUK
2nZtO/SuoSTU4vAouhT2nyrl/InuGkMhQ7oVy7r5a92YIOhLNS/OYP5M4Sf37Vo1
VlcwYv3cPE7l69QJOQby6Wv4972RaubwL53aBouUQAk0b1f8pSK8rmN+U6bFiwfx
51ZifAdwQdoz6PV8hfqOMk1YAaLgq8Lfk5J82aMrsQIDAQABox4wHDAaBgNVHREE
EzARgglsb2NhbGhvc3SHBH8AAAEwDQYJKoZIhvcNAQELBQADggEBAG0VfrVM4fKJ
aunlyTNPBuMjIaDjEXqQxVyEmgjTUDOyfEu8DCcyJtyr8VA/B46S4T/MuG1UABMV
LXE9rliKy1kyznAGjUZhI8v13b9hxw9n55WTEbVDkKmFFfp51MpHBKsHTz6dbCuV
zSw6/pt7ApT9SCEyKHqyFTunVIjUOWa3V1o9IQoQnU7EsxAxf1AV2SpTKydtPL+e
CmxljaeWGB3LAlZx8Nwk/MeEdFkMxLWvg0tLL6J6zP+7nkVexNsArExTEAos0dlX
3OEV1sw2PDUSMNEB4Vd0A6z3wLeaanpSRwh2mnd2qAX+hZELjK0Xngu7dUGPnPjV
C4vId3Rpxtc=
-----END CERTIFICATE-----
"""

_TLS_KEY = b"""-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDVz+Bb6gK+KzHC
iV711krIdhmoBifhGShkqY6+LmXHU//DDBo60qEUeJJHaWiIKcfNUZ7HslJam5z3
d04QMmC0C7C5GBQdD/f1G9z2O8m53sd5B/E5SKkc4xZB+H8RSQbX2PGmxgpb671+
AALMoe7LEBdbqm3PTAxuRx0D8xKaRQradm079K6hJNTi8Ci6FPafKuX8ie4aQyFD
uhXLuvlr3Zgg6Es1L85g/kzhJ/ftWjVWVzBi/dw8TuXr1Ak5BvLpa/j3vZFq5vAv
ndoGi5RACTRvV/ylIryuY35TpsWLB/HnVmJ8B3BB2jPo9XyF+o4yTVgBouCrwt+T
knzZoyuxAgMBAAECgf9zQZuv8HWKDb7FH0gRPXMSnJc3/BmDPgyINt67pkc3LBCz
E9MP4nryjgxMcoXm4J7UDyuIepfqP/hdbfKmyIFYjPS20kQFZpZDisGR+qjDiVP9
6koelwyShdd5uHrG1pbZxBh/zkHHS0zanybjKGeRDxuITlbjaBtLVwpNFrrwbUou
+q/M/4Hl8/rTTnCySvMWPzPfE8vbgHKTIylJ4kU0Rq0Q4E5e1IVfz7UBTtiEgz8Y
nUVnMDJHDbr3GI0P3zKpvTiptNHloncO1LbcFNFGHDXxEaekJ+8jMwA8OCYRVebz
wV5oclAGnHeFTLnTBMXF5ioxGqjqzspSPUzI0+kCgYEA/8xvwTIds+8slGColsBT
b4Qos4bGZzeQqTzbNhjtF92WFfUi6gpa/G9qNhLAbaMtWbAWJQqy8UFqx6RDLryt
OhpvYQEWCBm+QMX8zcBH/Taa3JP3fEBz4sAxuzQPR4oe32osaWDAfALKKV9OWR64
VsVFhVPlba+msXEweg1ruT8CgYEA1fr57V/CAHPl7XENkfhlbkkFXsMoUTWfWjQp
kP7HR2vf2LmWUAOfOXLRJ9em46gedH2zYKVagGB0zJ8Tmx7P9uOCX5DCd4CML/uh
eHFPUb2B2Z2kCFnnSougz02PXBRq+7G9yJJYKwWyX6BYxJCLT+2jw6ti02ixIOjS
BJu/bw8CgYEAhYuO4LcwaKs6g/B+s82PAc5mjWuUk3if7qsV6wVSar5FyArmAngL
jnUAZ2Cc0+B4IbXbqdUPHQNBIx9v76uTaJ06ftNZVDtUZ262EBkNvHXQnc4mS9k+
ZyheDlUckQXcHlnI++8GLvgp4TWfqsluBecR54yoX/5vMX5dh6sQDXMCgYEAh8yY
AMXc4Vysd1xgOFtkQ/Gjrtg8Jg3Z6+1e095dqj4T+f8OHgmua08q3hZGnAR+D4AW
7ycBoKeWeKYcUz3izdTlULEWObEjRvBzMXT32fBjEDCzgXlNCEpE7EtUyCNNIh9T
So9V1TfwVC/3Jgh14Wv3mp6SQYkXoMMhRjtx6pECgYA2bF/kGdaSXnJtZ5z2RQq2
KqI1z5K9+nm6UZ2V1AuHZyvWtZl8/vNfC/Rp4fTIr33sOi4XPfp91Qlhahc6rQqJ
W1kNQGibLzZtPbXTd3Aa0SiEh8cwlQgxy8Ozdfe7TaPrP43fI33UgJwlI2lfLHRB
5oyWjwghBXdZT6MSZpQnqg==
-----END PRIVATE KEY-----
"""


@contextlib.contextmanager
def _https_server():
    """Un servidor HTTPS de verdad en `localhost`, para probar el apretón de
    manos completo -- no solo que se construyó un `SSLContext` distinto.

    Da `(puerto, ruta_del_certificado)`: el certificado se necesita también
    fuera, para pasarlo como `ca_bundle` del lado del cliente.
    """
    cert_fd, cert_path = tempfile.mkstemp(suffix=".pem")
    key_fd, key_path = tempfile.mkstemp(suffix=".key")
    with os.fdopen(cert_fd, "wb") as f:
        f.write(_TLS_CERT)
    with os.fdopen(key_fd, "wb") as f:
        f.write(_TLS_KEY)

    class _Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            body = json.dumps({"ok": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:  # noqa: D102
            pass  # el ruido de cada petición no aporta nada a un test

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    server = http.server.HTTPServer(("localhost", 0), _Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], cert_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        os.unlink(cert_path)
        os.unlink(key_path)


class ConfigTests(unittest.TestCase):
    def test_missing_token_is_a_clear_error(self) -> None:
        with self.assertRaises(SystemExit):
            config.from_env({})

    def test_defaults(self) -> None:
        cfg = config.from_env({"NETINVENTORY_AGENT_TOKEN": "nia_x"})
        self.assertEqual(cfg.url, "http://localhost:8000")
        self.assertEqual(cfg.interval_seconds, 900)
        self.assertEqual(cfg.subnets, ())
        self.assertEqual(cfg.communities, ())
        self.assertEqual(cfg.ca_bundle, "")

    def test_a_ca_bundle_is_read_from_the_environment(self) -> None:
        cfg = config.from_env(
            {"NETINVENTORY_AGENT_TOKEN": "nia_x", "NETINVENTORY_CA_BUNDLE": "/certs/ca.pem"}
        )
        self.assertEqual(cfg.ca_bundle, "/certs/ca.pem")

    def test_url_and_interval_from_the_environment(self) -> None:
        cfg = config.from_env(
            {
                "NETINVENTORY_AGENT_TOKEN": "nia_x",
                "NETINVENTORY_URL": "https://inventario.local/",
                "NETINVENTORY_INTERVAL": "60",
            }
        )
        self.assertEqual(cfg.url, "https://inventario.local")  # trailing slash stripped
        self.assertEqual(cfg.interval_seconds, 60)

    def test_plain_http_to_a_remote_host_is_refused(self) -> None:
        """The heartbeat carries decrypted credentials; over http:// to
        anywhere that is not this machine they would cross the wire in the
        clear, so the agent refuses to start rather than leak quietly."""
        with self.assertRaises(SystemExit) as caught:
            config.from_env(
                {
                    "NETINVENTORY_AGENT_TOKEN": "nia_x",
                    "NETINVENTORY_URL": "http://inventario.example.com",
                }
            )
        self.assertIn("https", str(caught.exception))

    def test_https_to_a_remote_host_is_fine(self) -> None:
        cfg = config.from_env(
            {
                "NETINVENTORY_AGENT_TOKEN": "nia_x",
                "NETINVENTORY_URL": "https://inventario.example.com",
            }
        )
        self.assertEqual(cfg.url, "https://inventario.example.com")

    def test_plain_http_to_localhost_stays_allowed(self) -> None:
        for host in ("localhost", "127.0.0.1", "127.1.2.3", "[::1]"):
            with self.subTest(host=host):
                cfg = config.from_env(
                    {
                        "NETINVENTORY_AGENT_TOKEN": "nia_x",
                        "NETINVENTORY_URL": f"http://{host}:8000",
                    }
                )
                self.assertTrue(cfg.url.startswith("http://"))

    def test_the_escape_hatch_has_to_be_said_explicitly(self) -> None:
        cfg = config.from_env(
            {
                "NETINVENTORY_AGENT_TOKEN": "nia_x",
                "NETINVENTORY_URL": "http://inventario.example.com",
                "NETINVENTORY_INSECURE_HTTP": "1",
            }
        )
        self.assertEqual(cfg.url, "http://inventario.example.com")

    def test_subnets_and_communities_overrides_from_the_environment(self) -> None:
        cfg = config.from_env(
            {
                "NETINVENTORY_AGENT_TOKEN": "nia_x",
                "NETINVENTORY_SUBNETS": "192.168.1.0/24, 10.0.0.0/24",
                "NETINVENTORY_SNMP_COMMUNITIES": "privada\npublic",
            }
        )
        self.assertEqual(cfg.subnets, ("192.168.1.0/24", "10.0.0.0/24"))
        self.assertEqual(cfg.communities, ("privada", "public"))


class ClientTests(unittest.TestCase):
    def _response(self, body: dict, status: int = 200):
        raw = json.dumps(body).encode()
        message = mock.Mock()
        message.read.return_value = raw
        message.__enter__ = lambda s: s
        message.__exit__ = mock.Mock(return_value=False)
        message.status = status
        return message

    def test_heartbeat_posts_the_token_and_parses_the_answer(self) -> None:
        client = AgentClient("http://web:8000", "nia_test")
        with mock.patch("agent.client._OPENER.open", return_value=self._response({"ok": True, "interval_seconds": 300})) as call:
            answer = client.heartbeat(version="0.1.0", hostname="srv")

        request = call.call_args[0][0]
        self.assertEqual(request.get_header("Authorization"), "Bearer nia_test")
        self.assertEqual(request.full_url, "http://web:8000/api/agent/heartbeat/")
        self.assertEqual(answer["interval_seconds"], 300)

    def test_a_server_error_raises_push_error_with_the_detail(self) -> None:
        client = AgentClient("http://web:8000", "nia_test")
        error = urllib.error.HTTPError(
            "http://web:8000/api/agent/heartbeat/", 401, "Unauthorized", {}, None
        )
        error.fp = mock.Mock()
        error.read = lambda: b'{"error": "Token de agente no valido."}'
        with mock.patch("agent.client._OPENER.open", side_effect=error):
            with self.assertRaises(PushError) as ctx:
                client.heartbeat(version="0.1.0", hostname="srv")
        self.assertIn("401", str(ctx.exception))

    def test_a_network_failure_raises_push_error(self) -> None:
        client = AgentClient("http://web:8000", "nia_test")
        with mock.patch(
            "agent.client._OPENER.open",
            side_effect=urllib.error.URLError("connection refused"),
        ):
            with self.assertRaises(PushError):
                client.push_findings(run={}, items=[])


class CollectorTests(unittest.TestCase):
    def test_the_local_collector_reports_this_host(self) -> None:
        findings = LocalCollector().collect({})

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.kind, "host")
        self.assertTrue(finding.payload["hostname"])
        # Identity is the MAC when there is one, else the IP, else the hostname.
        self.assertTrue(finding.identity)

    def test_every_registered_collector_produces_valid_findings(self) -> None:
        ctx: dict = {"config": {}, "env": None}
        # No real network in a unit test: the sweep finds nothing alive.
        with mock.patch("agent.collectors.sweep.net.own_subnet", return_value="192.0.2.0/30"), \
             mock.patch("agent.collectors.sweep.net.sweep", return_value=[]), \
             mock.patch("agent.collectors.sweep.net.arp_table", return_value={}):
            for collector in all_collectors():
                for finding in collector.collect(ctx):
                    serialised = finding.as_json()
                    self.assertIn(serialised["kind"], {"host"})
                    self.assertIsInstance(serialised["identity"], dict)
                    self.assertIsInstance(serialised["payload"], dict)


if __name__ == "__main__":
    unittest.main()


class BatchingTests(unittest.TestCase):
    """Un barrido grande no cabe en un envío, y antes no entraba ninguno.

    El servidor rechaza más de `MAX_BATCH_ITEMS` de una vez. El agente empujaba
    todo junto, así que una red de más de quinientos equipos vivos daba un 400 y
    **no entraba nada, nunca**: se reintentaba el mismo lote cada quince minutos
    y el usuario solo veía una línea en la salida de error.
    """

    def setUp(self) -> None:
        self.client = AgentClient("http://web:8000", "nia_test")
        self.sent: list[dict] = []

    def _answer(self, request, timeout=None):  # noqa: ANN001
        body = json.loads(request.data.decode())
        self.sent.append(body)
        message = mock.Mock()
        message.read.return_value = json.dumps(
            {"ok": True, "run": "una-ejecucion", "created": len(body["items"]), "refreshed": 0}
        ).encode()
        message.__enter__ = lambda s: s
        message.__exit__ = mock.Mock(return_value=False)
        return message

    def push(self, count: int) -> dict:
        items = [{"kind": "host", "payload": {"ip": f"10.0.0.{n}"}} for n in range(count)]
        with mock.patch("agent.client._OPENER.open", side_effect=self._answer):
            return self.client.push_findings(run={"status": "ok"}, items=items)

    def test_a_sweep_that_fits_goes_in_one_push(self) -> None:
        result = self.push(10)

        self.assertEqual(len(self.sent), 1)
        self.assertEqual(result["created"], 10)

    def test_a_sweep_too_big_is_split_instead_of_refused(self) -> None:
        result = self.push(MAX_BATCH_ITEMS * 2 + 3)

        self.assertEqual(len(self.sent), 3)
        self.assertTrue(all(len(body["items"]) <= MAX_BATCH_ITEMS for body in self.sent))
        self.assertEqual(result["created"], MAX_BATCH_ITEMS * 2 + 3)

    def test_the_pieces_hang_off_one_run_and_not_three(self) -> None:
        """Si no, un barrido sale en la bandeja como tres barridos distintos."""
        self.push(MAX_BATCH_ITEMS + 1)

        self.assertNotIn("run_uuid", self.sent[0]["run"])
        self.assertEqual(self.sent[1]["run"]["run_uuid"], "una-ejecucion")

    def test_an_empty_sweep_still_reports_the_run(self) -> None:
        self.push(0)

        self.assertEqual(len(self.sent), 1)


class HardeningTests(unittest.TestCase):
    """Lo que el agente no debe creerse del otro lado del cable."""

    def setUp(self) -> None:
        self.client = AgentClient("http://web:8000", "nia_test")

    def test_a_redirect_never_carries_the_token_to_the_new_host(self) -> None:
        """El manejador por defecto reenvía `Authorization` sin mirar a dónde.

        Con la URL en HTTP --que es el valor por defecto-- cualquiera en medio
        podía contestar un 302 y quedarse con el token permanente del agente.
        """
        handler = agent_client._NoRedirects()

        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(
                mock.Mock(full_url="http://web:8000/api/agent/heartbeat/"),
                None, 302, "Found", {}, "http://el-de-enfrente/",
            )

    def test_without_a_ca_bundle_the_shared_opener_is_reused(self) -> None:
        """Es lo que deja a los demás tests interceptar `_OPENER.open` sin
        saber que `_opener_for` existe."""
        self.assertIs(self.client._opener, agent_client._OPENER)

    def test_a_ca_bundle_builds_an_opener_of_its_own(self) -> None:
        # `delete=False` y borrado a mano: en Windows, un segundo lector --aquí
        # dentro, `ssl.load_verify_locations`-- no puede abrir un fichero que su
        # propio escritor sigue teniendo cogido en exclusiva.
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "wb") as pem:
                pem.write(_SELF_SIGNED_PEM)
            with_ca = AgentClient("https://inventario.local", "nia_test", ca_bundle=path)
        finally:
            os.unlink(path)

        self.assertIsNot(with_ca._opener, agent_client._OPENER)

    def test_a_missing_ca_file_fails_at_startup_and_not_mid_sweep(self) -> None:
        """Un fichero que no existe tiene que fallar al construir el cliente,
        no la primera vez que se intenta empujar algo."""
        with self.assertRaises(FileNotFoundError):
            AgentClient("https://inventario.local", "nia_test", ca_bundle="/no/existe.pem")

    def test_the_ca_bundle_is_what_actually_lets_the_handshake_through(self) -> None:
        """No basta con que se construya un `SSLContext` distinto: tiene que
        ser el que hace que la conexión salga adelante de verdad.

        Un servidor HTTPS real con el certificado autofirmado de `_TLS_CERT`:
        sin decirle al cliente que se fíe de esa CA, el `CERTIFICATE_VERIFY_
        FAILED` de siempre; con `ca_bundle` apuntando a ella, la respuesta
        llega igual que si el certificado lo hubiera firmado alguien conocido.
        """
        with _https_server() as (port, cert_path):
            plain = AgentClient(f"https://localhost:{port}", "nia_test")
            with self.assertRaises(PushError) as ctx:
                plain.heartbeat(version="1", hostname="srv")
            self.assertIn("CERTIFICATE_VERIFY_FAILED", str(ctx.exception))

            trusting = AgentClient(f"https://localhost:{port}", "nia_test", ca_bundle=cert_path)
            answer = trusting.heartbeat(version="1", hostname="srv")

        self.assertEqual(answer, {"ok": True})

    def test_an_answer_that_is_not_an_object_does_not_kill_the_agent(self) -> None:
        message = mock.Mock()
        message.read.return_value = b'["esto no es un objeto"]'
        message.__enter__ = lambda s: s
        message.__exit__ = mock.Mock(return_value=False)

        with mock.patch("agent.client._OPENER.open", return_value=message):
            with self.assertRaises(PushError):
                self.client.heartbeat(version="1", hostname="srv")


class IntervalTests(unittest.TestCase):
    """El intervalo llega del servidor y del entorno; de ninguno hay que fiarse.

    Un cero martillea el servidor sin pausa y un negativo lanza `ValueError`
    desde `time.sleep`: los dos matarían al agente por un dato de fuera.
    """

    def test_a_sensible_value_survives(self) -> None:
        self.assertEqual(_interval(900, fallback=60), 900)

    def test_rubbish_falls_back(self) -> None:
        for value in ("900s", None, "", [], 0, -5):
            with self.subTest(valor=value):
                self.assertEqual(_interval(value, fallback=60), 60)

    def test_it_is_clamped_at_both_ends(self) -> None:
        self.assertEqual(_interval(5), MIN_INTERVAL_SECONDS)
        self.assertEqual(_interval(999_999_999), MAX_INTERVAL_SECONDS)


class BatchSizeTests(unittest.TestCase):
    """El troceo por bytes: contar solo elementos dejó de bastar cuando los
    hallazgos empezaron a llevar configuraciones dentro."""

    def test_small_items_still_batch_by_count(self) -> None:
        items = [{"kind": "host", "identity": {"ip": f"10.0.0.{n}"}} for n in range(1200)]

        batches = agent_client._batched(items)

        self.assertEqual([len(batch) for batch in batches], [500, 500, 200])

    def test_fat_items_batch_by_bytes_before_the_count(self) -> None:
        fat = {"kind": "config", "payload": {"config": "x" * 500_000}}

        batches = agent_client._batched([dict(fat) for _ in range(5)])

        self.assertTrue(all(len(batch) <= 3 for batch in batches))
        self.assertEqual(sum(len(batch) for batch in batches), 5)

    def test_nothing_still_pushes_one_empty_batch(self) -> None:
        self.assertEqual(agent_client._batched([]), [[]])
