"""The agent's second opinion on a certificate: Mozilla's roots.

On Windows, Python reads the system certificate store, and that store can make
OpenSSL refuse a good public certificate with «certificate has expired» while
the browser accepts it (first Windows install against Cenya Cloud, 01-10-2026).
`AgentClient` then tries once more, only when the certificate check failed,
against Mozilla's list. These tests keep the three promises that matter:

- it helps when it should (and keeps helping afterwards);
- it never helps when it must not: a company's own CA is the operator's
  decision, and a refused connection is not a certificate problem;
- it never switches verification off, which one real TLS test shows with a
  real handshake and a real certificate.
"""

from __future__ import annotations

import datetime
import http.server
import json
import pathlib
import ssl
import tempfile
import threading
import unittest
import urllib.error
from typing import Any
from unittest import mock

from agent import client as agent_client
from agent.client import AgentClient, PushError

EXPIRED = ssl.SSLCertVerificationError(10, "certificate verify failed: certificate has expired")


def certificate_error() -> urllib.error.URLError:
    return urllib.error.URLError(EXPIRED)


def response(body: dict[str, Any]) -> mock.Mock:
    message = mock.Mock()
    message.read.return_value = json.dumps(body).encode()
    message.__enter__ = lambda s: s
    message.__exit__ = mock.Mock(return_value=False)
    return message


def opener(*, answer: dict[str, Any] | None = None, error: Exception | None = None) -> mock.Mock:
    made = mock.Mock()
    if error is not None:
        made.open.side_effect = error
    else:
        made.open.return_value = response(answer or {"ok": True})
    return made


class FallbackTests(unittest.TestCase):
    def client(self, **kwargs: Any) -> AgentClient:
        # `_opener_for` would load the CA file named in `ca_bundle`; the tests
        # name one that does not exist, and replace the opener right after.
        with mock.patch("agent.client._opener_for", return_value=mock.Mock()):
            made = AgentClient("https://portal.example", "nia_test", **kwargs)
        made._opener = opener(error=certificate_error())
        return made

    def test_a_certificate_failure_is_retried_with_mozillas_roots_and_it_sticks(self) -> None:
        client = self.client()
        first = client._opener
        second = opener(answer={"ok": True, "interval_seconds": 300})

        with mock.patch("agent.client._fallback_opener", return_value=second):
            answer = client.heartbeat(version="0.10.2", hostname="pc")
            client.heartbeat(version="0.10.2", hostname="pc")

        self.assertEqual(answer["interval_seconds"], 300)
        self.assertEqual(first.open.call_count, 1, "the first opener is tried once, then dropped")
        self.assertEqual(second.open.call_count, 2)

    def test_the_second_try_carries_the_same_request(self) -> None:
        client = self.client()
        second = opener()
        with mock.patch("agent.client._fallback_opener", return_value=second):
            client.enroll(code="ABCD-EFGH-JKLM", hostname="pc", version="0.10.2")

        sent = second.open.call_args[0][0]
        self.assertEqual(sent.full_url, "https://portal.example/api/agent/enroll/")
        self.assertEqual(json.loads(sent.data)["code"], "ABCD-EFGH-JKLM")

    def test_a_companys_own_ca_is_never_second_guessed(self) -> None:
        client = self.client(ca_bundle="C:/empresa/ca.pem")
        with mock.patch("agent.client._fallback_opener") as fallback:
            with self.assertRaises(PushError) as caught:
                client.heartbeat(version="0.10.2", hostname="pc")
        fallback.assert_not_called()
        self.assertIn("certificate has expired", str(caught.exception))

    def test_a_refused_connection_is_not_a_certificate_problem(self) -> None:
        client = AgentClient("https://portal.example", "nia_test")
        client._opener = opener(error=urllib.error.URLError(ConnectionRefusedError("rechazada")))
        with mock.patch("agent.client._fallback_opener") as fallback:
            with self.assertRaises(PushError):
                client.heartbeat(version="0.10.2", hostname="pc")
        fallback.assert_not_called()

    def test_if_the_second_try_fails_too_the_first_error_is_the_one_reported(self) -> None:
        client = self.client()
        second = opener(error=urllib.error.URLError(ssl.SSLCertVerificationError(20, "unable to get local issuer certificate")))
        with mock.patch("agent.client._fallback_opener", return_value=second):
            with self.assertRaises(PushError) as caught:
                client.heartbeat(version="0.10.2", hostname="pc")
        self.assertIn("certificate has expired", str(caught.exception))
        self.assertNotIn("local issuer", str(caught.exception))

    def test_without_certifi_there_is_no_second_try_and_the_error_stays_honest(self) -> None:
        client = self.client()
        with mock.patch("agent.client._mozilla_roots", return_value=""):
            with self.assertRaises(PushError) as caught:
                client.heartbeat(version="0.10.2", hostname="pc")
        self.assertIn("certificate has expired", str(caught.exception))

    def test_a_server_error_after_the_handshake_is_the_servers_answer(self) -> None:
        client = self.client()
        error = urllib.error.HTTPError("https://portal.example/api/agent/enroll/", 400, "Bad Request", {}, None)
        error.fp = mock.Mock()
        error.read = lambda: b'{"error": "El codigo ya se uso."}'
        second = opener(error=error)

        with mock.patch("agent.client._fallback_opener", return_value=second):
            with self.assertRaises(PushError) as caught:
                client.enroll(code="X", hostname="pc", version="0.10.2")

        self.assertIn("400", str(caught.exception))
        self.assertIs(client._opener, second, "the handshake worked: keep the opener that worked")

    def test_mozillas_roots_exist_where_certifi_says(self) -> None:
        roots = agent_client._mozilla_roots()
        if not roots:
            self.skipTest("certifi no está instalado en este entorno")
        self.assertTrue(pathlib.Path(roots).is_file())
        self.assertIn("BEGIN CERTIFICATE", pathlib.Path(roots).read_text(encoding="ascii", errors="ignore"))


class RealHandshakeTests(unittest.TestCase):
    """A real HTTPS server, a real certificate, a real verification."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.x509.oid import NameOID
        except ImportError:  # pragma: no cover
            raise unittest.SkipTest("cryptography no está instalado en este entorno")

        cls.dir = tempfile.TemporaryDirectory()
        base = pathlib.Path(cls.dir.name)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        cls.cert_path = base / "cert.pem"
        key_path = base / "key.pem"
        cls.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 -- the name http.server asks for
                self.rfile.read(int(self.headers.get("Content-Length") or 0))
                body = json.dumps({"ok": True, "interval_seconds": 123}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        cls.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cls.cert_path), str(key_path))
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.url = f"https://localhost:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.dir.cleanup()

    def test_a_certificate_nobody_trusts_is_refused_when_no_root_vouches_for_it(self) -> None:
        client = AgentClient(self.url, "nia_test")
        with mock.patch("agent.client._mozilla_roots", return_value=""):
            with self.assertRaises(PushError) as caught:
                client.heartbeat(version="0.10.2", hostname="pc")
        self.assertIn("CERTIFICATE_VERIFY_FAILED", str(caught.exception))

    def test_the_second_opinion_accepts_what_its_roots_vouch_for_and_nothing_else(self) -> None:
        client = AgentClient(self.url, "nia_test")
        with mock.patch("agent.client._mozilla_roots", return_value=str(self.cert_path)):
            answer = client.heartbeat(version="0.10.2", hostname="pc")
        self.assertEqual(answer["interval_seconds"], 123)

        # And a list that does not hold this certificate still refuses it.
        other = tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False)
        self.addCleanup(pathlib.Path(other.name).unlink)
        other.write(self._unrelated_ca())
        other.close()
        stranger = AgentClient(self.url, "nia_test")
        with mock.patch("agent.client._mozilla_roots", return_value=other.name):
            with self.assertRaises(PushError):
                stranger.heartbeat(version="0.10.2", hostname="pc")

    @staticmethod
    def _unrelated_ca() -> bytes:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "otra ca")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM)


if __name__ == "__main__":
    unittest.main()
