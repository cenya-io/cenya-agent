"""«Confiar en este certificado» (08-10-2026): TLS fijado a una huella.

Contra un servidor HTTPS de verdad con un certificado autofirmado: sin huella
no se fía y cuenta qué certificado presentó; con la suya entra; con otra no
llega a mandar la petición, que es donde viajaría la contraseña.
"""

from __future__ import annotations

import datetime
import http.server
import json
import ssl
import tempfile
import threading
import unittest
from pathlib import Path

from agent import credentials as creds
from agent import hypervisor, tlspin

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError:  # pragma: no cover - el agente completo la trae
    x509 = None  # type: ignore[assignment]


def self_signed(folder: Path) -> tuple[Path, Path, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vcenter.acme.local")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_file = folder / "cert.pem"
    key_file = folder / "key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return cert_file, key_file, cert.public_bytes(serialization.Encoding.DER)


@unittest.skipIf(x509 is None, "sin cryptography")
class PinnedTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.folder = tempfile.TemporaryDirectory()
        cert_file, key_file, cls.der = self_signed(Path(cls.folder.name))
        cls.requests: list[str] = []
        seen = cls.requests

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                seen.append(self.path)
                body = json.dumps({"value": []}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: object) -> None:
                pass

        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        # A client that hangs up on purpose (wrong pin) is not an error here.
        cls.server.handle_error = lambda *args: None  # type: ignore[method-assign]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_file, key_file)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"https://localhost:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.folder.cleanup()

    def setUp(self) -> None:
        self.requests.clear()

    def test_without_a_pin_it_does_not_trust_it_and_says_which_certificate_it_was(self) -> None:
        client = hypervisor.RestClient(self.url)

        with self.assertRaises(hypervisor.HypervisorError) as caught:
            client.request("GET", "/api/vcenter/host")

        error = caught.exception
        self.assertTrue(error.unreachable)
        self.assertEqual(error.certificate["sha256"], tlspin.fingerprint(self.der))
        self.assertIn("vcenter.acme.local", error.certificate["subject"])
        self.assertRegex(error.certificate["not_after"], r"^\d{4}-\d{2}-\d{2}$")
        self.assertEqual(self.requests, [])

    def test_with_its_pin_it_gets_in(self) -> None:
        client = hypervisor.RestClient(self.url, tls_pin=tlspin.fingerprint(self.der))

        self.assertEqual(client.request("GET", "/api/vcenter/host"), {"value": []})
        self.assertEqual(self.requests, ["/api/vcenter/host"])

    def test_with_another_pin_the_request_never_leaves(self) -> None:
        client = hypervisor.RestClient(self.url, tls_pin="0" * 64)

        with self.assertRaises(hypervisor.HypervisorError) as caught:
            client.request("GET", "/api/session")

        self.assertTrue(caught.exception.unreachable)
        self.assertEqual(self.requests, [], "con otro certificado no se manda nada")
        # Lo cuenta igual: el certificado cambió y alguien tiene que decidir.
        self.assertEqual(caught.exception.certificate["sha256"], tlspin.fingerprint(self.der))


class PinValuesTests(unittest.TestCase):
    def test_a_pin_is_64_hex_with_or_without_colons(self) -> None:
        pin = "ab" * 32
        self.assertEqual(tlspin.clean_pin(pin.upper()), pin)
        self.assertEqual(tlspin.clean_pin(":".join(["AB"] * 32)), pin)
        self.assertEqual(tlspin.clean_pin("abc"), "")
        self.assertEqual(tlspin.clean_pin(None), "")

    def test_the_credential_carries_the_pin_to_its_client(self) -> None:
        credential = creds._one({"kind": "vmware", "username": "u", "host": "vc", "tls_pin": "AB" * 32}, 0)

        self.assertEqual(credential.tls_pin, "ab" * 32)
        self.assertEqual(creds.client_options({}, credential), {"ca_file": "", "tls_pin": "ab" * 32})

    def test_without_a_pin_the_client_options_are_the_old_ones(self) -> None:
        credential = creds._one({"kind": "vmware", "username": "u", "host": "vc"}, 0)

        self.assertEqual(creds.client_options({}, credential), {"ca_file": ""})


if __name__ == "__main__":
    unittest.main()
