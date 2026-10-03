"""The sealed envelope (spec 3.1): round trip, every tampering, the shared vectors, the capability."""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado y la carpeta del agente

import base64
import contextlib
import http.server
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from agent import about, identity, sealing
from agent.client import MAX_BUNDLE_BYTES, UPLOAD_TIMEOUT_SECONDS, AgentClient, PushError

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover - la librería es opcional
    HAVE_CRYPTO = False

VECTORS_PATH = Path(__file__).resolve().parents[2] / "docs" / "sealing-test-vectors.json"
AGENT = "6f1c1e0e-3b0a-4b8e-9a52-2f5d6c1d7a10"
OTHER_AGENT = "11111111-2222-4333-8444-555555555555"
SUBJECT = "cred-1"
SECRET = "CANARY-envelope-Pa55w0rd"


def vectors() -> dict[str, Any]:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


_KEYS: dict[str, Any] = {}


def key(name: str, bits: int = 3072):  # noqa: ANN201
    """Claves de prueba, generadas una vez por ejecución (generar RSA cuesta)."""
    if name not in _KEYS:
        if name == "agent":
            _KEYS[name] = serialization.load_pem_private_key(
                vectors()["private_key_pem_TEST_ONLY"].encode(), password=None
            )
        else:
            _KEYS[name] = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return _KEYS[name]


def pem(private) -> str:  # noqa: ANN001
    return (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )


def flip(b64: str, index: int = 0) -> str:
    raw = bytearray(base64.b64decode(b64))
    raw[index] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


@unittest.skipUnless(HAVE_CRYPTO, "sin cryptography")
class EnvelopeTests(unittest.TestCase):
    def seal(self, plaintext: dict | None = None, **kwargs: Any) -> dict:
        return sealing.seal_for(
            pem(key("agent")), plaintext or {"secret": SECRET}, agent_uuid=kwargs.get("agent", AGENT),
            subject_id=kwargs.get("subject", SUBJECT),
        )

    def open(self, envelope: Any, **kwargs: Any) -> dict:
        return sealing.open_envelope(
            envelope, agent_uuid=kwargs.get("agent", AGENT), subject_id=kwargs.get("subject", SUBJECT),
            private_key=kwargs.get("private_key", key("agent")),
        )

    def refused(self, envelope: Any, reason: str | None = None, **kwargs: Any) -> sealing.SealError:
        with self.assertRaises(sealing.SealError) as caught:
            self.open(envelope, **kwargs)
        if reason is not None:
            self.assertEqual(caught.exception.reason, reason)
        # Ni el secreto ni nada del sobre en el texto de la excepción.
        self.assertNotIn(SECRET, str(caught.exception))
        if isinstance(envelope, dict):
            for field in ("ek", "iv", "ct"):
                value = envelope.get(field)
                if isinstance(value, str) and len(value) > 8:
                    self.assertNotIn(value[:16], str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)
        return caught.exception

    def test_round_trip(self) -> None:
        plaintext = {"secret": SECRET, "priv_secret": "ñandú €"}
        self.assertEqual(self.open(self.seal(plaintext)), plaintext)

    def test_the_envelope_has_the_shape_of_the_spec(self) -> None:
        envelope = self.seal()
        self.assertEqual(set(envelope), {"v", "alg", "ek", "iv", "ct"})
        self.assertEqual((envelope["v"], envelope["alg"]), (1, "RSA-OAEP-256+A256GCM"))
        self.assertEqual(len(base64.b64decode(envelope["iv"], validate=True)), 12)
        self.assertEqual(len(base64.b64decode(envelope["ek"], validate=True)), 384)
        self.assertNotIn(SECRET, json.dumps(envelope))

    def test_two_seals_of_the_same_secret_differ(self) -> None:
        first, second = self.seal(), self.seal()
        self.assertNotEqual(first["iv"], second["iv"])
        self.assertNotEqual(first["ct"], second["ct"])

    def test_the_agent_uuid_is_canonicalised_on_both_sides(self) -> None:
        envelope = self.seal(agent=AGENT.upper())
        self.assertEqual(self.open(envelope, agent=AGENT)["secret"], SECRET)
        self.assertEqual(sealing.aad(AGENT.upper().replace("-", ""), "x"), f"cenya-seal-v1|{AGENT}|x".encode())

    def test_a_flipped_bit_anywhere_is_refused(self) -> None:
        envelope = self.seal()
        for field in ("ek", "iv", "ct"):
            for index in (0, -1):
                with self.subTest(field=field, index=index):
                    self.refused({**envelope, field: flip(envelope[field], index)}, "open")

    def test_another_agent_or_another_credential_is_refused(self) -> None:
        envelope = self.seal()
        self.refused(envelope, "open", agent=OTHER_AGENT)
        self.refused(envelope, "open", subject="cred-2")
        self.refused(envelope, "open", subject="cred-1 ")  # el id es opaco: sin recortar

    def test_another_key_is_refused(self) -> None:
        self.refused(self.seal(), "open", private_key=key("other"))

    def test_malformed_base64_is_refused(self) -> None:
        envelope = self.seal()
        self.assertTrue(envelope["ct"].endswith("="))  # que «sin relleno» quite algo de verdad
        cases = {
            "truncated": envelope["ct"][:-4],
            "no padding": envelope["ct"].rstrip("="),
            "whitespace": envelope["ct"][:8] + "\n" + envelope["ct"][8:],
            "url-safe": envelope["ek"].replace("+", "-").replace("/", "_"),
            "not text": 12345,
            "empty": "",
        }
        for name, value in cases.items():
            field = "ek" if name == "url-safe" else "ct"
            if name == "url-safe" and value == envelope["ek"]:
                continue  # sin + ni / no hay nada que cambiar
            with self.subTest(name):
                self.refused({**envelope, field: value})

    def test_wrong_sizes_are_refused(self) -> None:
        envelope = self.seal()
        self.refused({**envelope, "iv": base64.b64encode(os.urandom(16)).decode()}, "format")
        self.refused({**envelope, "ek": base64.b64encode(os.urandom(256)).decode()}, "format")
        self.refused({**envelope, "ct": base64.b64encode(os.urandom(8)).decode()}, "format")

    def test_unknown_version_or_algorithm_is_refused(self) -> None:
        envelope = self.seal()
        for version in (2, 0, "1", True, None):
            with self.subTest(version=version):
                self.refused({**envelope, "v": version}, "version")
        for alg in ("RSA-OAEP+A256GCM", "", None, "rsa-oaep-256+a256gcm"):
            with self.subTest(alg=alg):
                self.refused({**envelope, "alg": alg}, "alg")

    def test_huge_inputs_are_refused_before_decoding(self) -> None:
        envelope = self.seal()
        huge = "A" * (sealing.MAX_CT_CHARS + 4)
        with mock.patch("agent.sealing.base64.b64decode", side_effect=AssertionError("ni se decodifica")):
            self.refused({**envelope, "ct": huge}, "format")
            self.refused({**envelope, "ek": "A" * (sealing.MAX_EK_CHARS + 4)}, "format")
        self.refused(envelope, "subject", subject="x" * 500)

    def test_things_that_are_not_an_envelope_are_refused(self) -> None:
        for value in (None, [], "sobre", {"v": 1}, {}):
            with self.subTest(value=value):
                self.refused(value)

    def test_a_bad_agent_uuid_is_refused(self) -> None:
        for value in ("", "no-es-un-uuid", None):
            with self.subTest(value=value):
                self.refused(self.seal(), "agent", agent=value)

    def test_a_plaintext_that_is_not_a_json_object_is_refused(self) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        content_key, iv = AESGCM.generate_key(256), os.urandom(12)
        ct = AESGCM(content_key).encrypt(iv, b"[1, 2]", sealing.aad(AGENT, SUBJECT))
        ek = key("agent").public_key().encrypt(content_key, sealing._oaep())
        envelope = {"v": 1, "alg": sealing.ALG, "ek": base64.b64encode(ek).decode(),
                    "iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()}
        self.refused(envelope, "plaintext")

    def test_without_the_library_it_is_a_capability_not_a_crash(self) -> None:
        envelope = self.seal()
        with mock.patch("agent.sealing.available", return_value=False):
            self.refused(envelope, "unavailable")
            self.assertFalse(sealing.self_test())

    def test_without_a_key_nothing_opens(self) -> None:
        with mock.patch("agent.identity.private_key", return_value=None):
            with self.assertRaises(sealing.SealError) as caught:
                sealing.open_envelope(self.seal(), agent_uuid=AGENT, subject_id=SUBJECT)
        self.assertEqual(caught.exception.reason, "no_key")


@unittest.skipUnless(HAVE_CRYPTO, "sin cryptography")
class PublicKeyTests(unittest.TestCase):
    def test_a_good_key_is_accepted(self) -> None:
        self.assertEqual(sealing.load_public_key(pem(key("agent"))).key_size, 3072)

    def test_a_weak_key_is_refused(self) -> None:
        with self.assertRaises(sealing.SealError) as caught:
            sealing.seal_for(pem(key("weak", 2048)), {"secret": SECRET}, agent_uuid=AGENT, subject_id=SUBJECT)
        self.assertEqual(caught.exception.reason, "weak_key")

    def test_garbage_and_other_key_types_are_refused(self) -> None:
        ec_pem = (
            ec.generate_private_key(ec.SECP256R1())
            .public_key()
            .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )
        private_pem = vectors()["private_key_pem_TEST_ONLY"]
        for value in ("", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----", ec_pem, private_pem,
                      "x" * 10_000, None, 42):
            with self.subTest(value=str(value)[:30]):
                with self.assertRaises(sealing.SealError):
                    sealing.load_public_key(value)  # type: ignore[arg-type]


@unittest.skipUnless(HAVE_CRYPTO, "sin cryptography")
class VectorTests(unittest.TestCase):
    """El fichero que usará el servidor para demostrar que su lado cuadra con este."""

    def test_the_vector_envelope_opens_with_the_vector_key(self) -> None:
        data = vectors()
        opened = sealing.open_envelope(
            data["envelope"], agent_uuid=data["agent_uuid"], subject_id=data["subject_id"], private_key=key("agent")
        )
        self.assertEqual(opened, data["plaintext"])

    def test_the_documented_aad_and_plaintext_bytes_are_the_real_ones(self) -> None:
        data = vectors()
        aad = sealing.aad(data["agent_uuid"], data["subject_id"])
        self.assertEqual(aad.decode("utf-8"), data["aad_utf8"])
        self.assertEqual(aad.hex(), data["aad_hex"])
        raw = json.dumps(data["plaintext"], ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.assertEqual(base64.b64encode(raw).decode(), data["plaintext_utf8_b64"])

    def test_the_deterministic_aes_gcm_check(self) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        data = vectors()
        check = data["aes_gcm_check"]
        ct = AESGCM(bytes.fromhex(check["key_hex"])).encrypt(
            base64.b64decode(check["iv_b64"]), base64.b64decode(data["plaintext_utf8_b64"]),
            data["aad_utf8"].encode("utf-8"),
        )
        self.assertEqual(base64.b64encode(ct).decode(), check["ct_b64"])

    def test_the_vector_public_key_is_the_pair_of_the_private_one(self) -> None:
        self.assertEqual(vectors()["public_key_pem"].strip(), pem(key("agent")).strip())

    def test_the_file_documents_every_byte_level_choice(self) -> None:
        notes = " ".join(vectors()["notes"])
        for word in ("padding", "MGF1", "EMPTY label", "APPENDED", "UTF-8", "lowercase", "12 random bytes"):
            self.assertIn(word, notes)
        self.assertIn("TEST ONLY", vectors()["WARNING"])


@unittest.skipUnless(HAVE_CRYPTO, "sin cryptography")
class CapabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = tempfile.mkdtemp(prefix="cenya-sealing-")
        self.environ = {"CENYA_STATE_DIR": self.state}
        patcher = mock.patch.dict(os.environ, self.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        sealing._self_test_cache.clear()
        self.addCleanup(sealing._self_test_cache.clear)

    def test_no_key_no_capability(self) -> None:
        self.assertFalse(sealing.self_test())
        self.assertFalse(about.capabilities()["sealed_credentials"])

    def test_a_key_that_round_trips_is_the_capability(self) -> None:
        identity.ensure()
        self.assertTrue(sealing.self_test())
        self.assertTrue(about.capabilities()["sealed_credentials"])

    def test_a_key_that_does_not_round_trip_is_not(self) -> None:
        identity.ensure()
        with mock.patch("agent.sealing.open_envelope", side_effect=sealing.SealError("open")):
            self.assertFalse(sealing.self_test())

    def test_without_the_library_there_is_no_capability(self) -> None:
        identity.ensure()
        with mock.patch("agent.sealing.available", return_value=False):
            self.assertFalse(sealing.self_test())


class UploadTests(unittest.TestCase):
    """`upload_netbox_bundle` (spec 3.4) contra un servidor de mentira en 127.0.0.1."""

    @contextlib.contextmanager
    def serving(self, status: int = 200, answer: dict | None = None, location: str = ""):
        received: list[dict[str, Any]] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                received.append({"path": self.path, "headers": dict(self.headers), "body": body})
                data = json.dumps(answer or {"ok": True, "import": "imp-1"}).encode()
                self.send_response(status)
                if location:
                    self.send_header("Location", location)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args: object) -> None:
                pass

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{httpd.server_address[1]}", received
        finally:
            httpd.shutdown()
            httpd.server_close()
            thread.join(timeout=5)

    def test_the_bundle_goes_up_with_its_headers(self) -> None:
        bundle = {"devices": [{"name": "sw-ñ"} for _ in range(3000)], "sites": []}
        with self.serving() as (url, received):
            answer = AgentClient(url, "cya_token").upload_netbox_bundle(bundle, "order-7")
        self.assertEqual(answer, {"ok": True, "import": "imp-1"})
        (request,) = received
        self.assertEqual(request["path"], "/api/agent/v2/netbox-bundle/")
        headers = {name.lower(): value for name, value in request["headers"].items()}
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(headers["x-cenya-order"], "order-7")
        self.assertEqual(headers["authorization"], "Bearer cya_token")
        self.assertEqual(int(headers["content-length"]), len(request["body"]))
        self.assertNotIn("transfer-encoding", headers)
        self.assertEqual(json.loads(request["body"].decode("utf-8")), bundle)

    def test_without_an_order_there_is_no_order_header(self) -> None:
        with self.serving() as (url, received):
            AgentClient(url, "cya_token").upload_netbox_bundle({"sites": []})
        self.assertNotIn("x-cenya-order", {name.lower() for name in received[0]["headers"]})

    def test_a_bundle_over_the_limit_never_leaves_the_machine(self) -> None:
        client = AgentClient("http://127.0.0.1:9", "cya_token")
        with mock.patch("agent.client.MAX_BUNDLE_BYTES", 1000), \
             mock.patch.object(client, "_open", side_effect=AssertionError("ni se conecta")):
            with self.assertRaises(PushError) as caught:
                client.upload_netbox_bundle({"devices": [{"name": "x" * 2000}]}, "o")
        self.assertEqual(caught.exception.status, 413)
        self.assertEqual(MAX_BUNDLE_BYTES, 50 * 1024 * 1024)

    def test_the_upload_has_its_own_finite_timeout(self) -> None:
        client = AgentClient("http://127.0.0.1:9", "cya_token")
        seen: list[float] = []

        def fake_open(request: Any, timeout: float = 0) -> Any:
            seen.append(timeout)
            raise PushError("x")

        with mock.patch.object(client, "_open", side_effect=fake_open):
            with self.assertRaises(PushError):
                client.upload_netbox_bundle({"sites": []}, "o")
        self.assertEqual(seen, [UPLOAD_TIMEOUT_SECONDS])
        self.assertTrue(15 < UPLOAD_TIMEOUT_SECONDS <= 600)

    def test_a_redirect_is_not_followed(self) -> None:
        with self.serving(status=302, location="http://127.0.0.1:9/robado/") as (url, received):
            with self.assertRaises(PushError):
                AgentClient(url, "cya_token").upload_netbox_bundle({"sites": []}, "o")
        self.assertEqual(len(received), 1)

    def test_a_server_error_is_a_push_error_with_its_status(self) -> None:
        with self.serving(status=413, answer={"error": "Demasiado grande."}) as (url, _received):
            with self.assertRaises(PushError) as caught:
                AgentClient(url, "cya_token").upload_netbox_bundle({"sites": []}, "o")
        self.assertEqual(caught.exception.status, 413)

    def test_the_body_can_be_sent_twice(self) -> None:
        # `_open` reintenta con las raíces de Mozilla: el cuerpo tiene que volver entero.
        from agent.client import _JsonBody

        body = _JsonBody({"devices": [{"n": i} for i in range(20000)]})
        self.assertEqual(b"".join(body), b"".join(body))
        self.assertEqual(body.size(), len(b"".join(body)))


if __name__ == "__main__":
    unittest.main()
