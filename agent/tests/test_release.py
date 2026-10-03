"""Signed releases (`agent.release`): signature first, then the hash, and nothing on trust.

Every key here is a TEST key generated inside the test; no real key exists in
this repository.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import base64
import builtins
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent import release

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover - CI y el instalador la tienen
    Ed25519PrivateKey = None  # type: ignore[assignment,misc]


def public_line(key) -> str:  # noqa: ANN001
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def sign(key, data: bytes) -> str:  # noqa: ANN001
    return base64.b64encode(key.sign(data)).decode()


def manifest_bytes(version: str = "0.11.1", **files: bytes) -> bytes:
    entries = {
        name: {
            "url": f"https://example.invalid/{name}",
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
        for name, content in (files or {"windows": b"MZ installer"}).items()
    }
    return json.dumps({"version": version, "released": "2026-10-02T18:00:00Z", "files": entries}).encode()


@unittest.skipIf(Ed25519PrivateKey is None, "cryptography no está instalada")
class ManifestSignatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = Ed25519PrivateKey.generate()
        self.keys = [public_line(self.key)]

    def test_a_manifest_signed_by_a_known_key_is_accepted(self) -> None:
        data = manifest_bytes()

        manifest = release.verify_manifest(data, sign(self.key, data), self.keys)

        self.assertEqual(manifest["version"], "0.11.1")
        self.assertEqual(manifest["files"]["windows"]["size"], len(b"MZ installer"))

    def test_a_manifest_signed_by_an_unknown_key_is_refused(self) -> None:
        stranger = Ed25519PrivateKey.generate()
        data = manifest_bytes()

        with self.assertRaises(release.ReleaseError) as caught:
            release.verify_manifest(data, sign(stranger, data), self.keys)

        self.assertEqual(caught.exception.code, release.BAD_SIGNATURE)

    def test_a_good_signature_over_other_bytes_is_refused(self) -> None:
        # La firma buena de un manifiesto, pegada a otro: un byte distinto basta.
        signed = manifest_bytes("0.11.1")
        other = manifest_bytes("0.11.2")

        with self.assertRaises(release.ReleaseError) as caught:
            release.verify_manifest(other, sign(self.key, signed), self.keys)

        self.assertEqual(caught.exception.code, release.BAD_SIGNATURE)

    def test_a_garbage_or_missing_signature_is_refused_before_reading_the_json(self) -> None:
        data = b"{not json at all"
        for signature in ("", "!!!", base64.b64encode(b"short").decode(), "A" * 2000):
            with self.subTest(signature=signature[:10]):
                with self.assertRaises(release.ReleaseError) as caught:
                    release.verify_manifest(data, signature, self.keys)
                self.assertEqual(caught.exception.code, release.BAD_SIGNATURE)

    def test_without_any_key_nothing_is_verified(self) -> None:
        data = manifest_bytes()
        for keys in ([], [""], ["not a key"], [base64.b64encode(b"x" * 31).decode()]):
            with self.subTest(keys=keys):
                with self.assertRaises(release.ReleaseError) as caught:
                    release.verify_manifest(data, sign(self.key, data), keys)
                self.assertEqual(caught.exception.code, release.NO_KEYS)

    def test_a_broken_key_in_the_list_does_not_disable_the_good_one(self) -> None:
        data = manifest_bytes()

        manifest = release.verify_manifest(data, sign(self.key, data), ["garbage", *self.keys])

        self.assertEqual(manifest["version"], "0.11.1")

    def test_keys_may_be_pem_or_raw_base64(self) -> None:
        pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        der = base64.b64encode(
            self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        ).decode()
        data = manifest_bytes()
        for form in (pem, der, self.keys[0]):
            with self.subTest(form=form[:12]):
                self.assertEqual(release.verify_manifest(data, sign(self.key, data), [form])["version"], "0.11.1")

    def test_a_signed_manifest_with_a_bad_shape_is_still_refused(self) -> None:
        bad = [
            {"version": "../../x", "files": {}},
            {"version": "0.11.1", "files": {"windows": {"url": "http://evil.example/x.exe", "sha256": "0" * 64, "size": 1}}},
            {"version": "0.11.1", "files": {"windows": {"url": "https://x/y", "sha256": "nothex", "size": 1}}},
            {"version": "0.11.1", "files": {"windows": {"url": "https://x/y", "sha256": "0" * 64, "size": 10**12}}},
            {"version": "0.11.1"},
        ]
        for data in bad:
            raw = json.dumps(data).encode()
            with self.subTest(data=data):
                with self.assertRaises(release.ReleaseError) as caught:
                    release.verify_manifest(raw, sign(self.key, raw), self.keys)
                self.assertEqual(caught.exception.code, release.BAD_MANIFEST)


class NoCryptographyTests(unittest.TestCase):
    def test_without_cryptography_verification_fails_closed(self) -> None:
        real_import = builtins.__import__

        def no_crypto(name, *args, **kwargs):  # noqa: ANN001, ANN202
            if name.startswith("cryptography"):
                raise ImportError(name)
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=no_crypto):
            with self.assertRaises(release.ReleaseError) as caught:
                release.verify_manifest(b"{}", "AAAA", ["whatever"])

        self.assertEqual(caught.exception.code, release.NO_CRYPTO)


class FileHashTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="cenya-release-"))

    def entry(self, content: bytes) -> dict:
        return {"url": "https://x/y", "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}

    def test_the_file_the_manifest_describes_passes(self) -> None:
        path = self.dir / "a.exe"
        path.write_bytes(b"installer")

        release.verify_file(path, self.entry(b"installer"))

    def test_one_changed_byte_or_one_extra_byte_is_refused(self) -> None:
        for content in (b"installeR", b"installer!", b"installe"):
            with self.subTest(content=content):
                path = self.dir / "a.exe"
                path.write_bytes(content)
                with self.assertRaises(release.ReleaseError) as caught:
                    release.verify_file(path, self.entry(b"installer"))
                self.assertEqual(caught.exception.code, release.BAD_HASH)


class AllowedUrlTests(unittest.TestCase):
    def test_https_anywhere_and_plain_http_only_to_this_machine(self) -> None:
        self.assertTrue(release.allowed_url("https://github.com/x"))
        self.assertTrue(release.allowed_url("http://127.0.0.1:8765/releases"))
        self.assertTrue(release.allowed_url("http://localhost/x"))
        for url in ("http://github.com/x", "ftp://x/y", "file:///etc/passwd", "", "https://", "https://a b/c", None):
            with self.subTest(url=url):
                self.assertFalse(release.allowed_url(url))


if __name__ == "__main__":
    unittest.main()
