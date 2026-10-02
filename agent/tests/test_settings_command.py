"""``cenya-agent settings``: what the installer's /CA= (and a person) use before enrolling."""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import contextlib
import io
import json
import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import settings as local_settings
from agent import settings_command, store

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError:  # pragma: no cover
    x509 = None  # type: ignore[assignment]


def certificate(ca: bool = True) -> tuple[bytes, bytes]:
    """A throwaway self-signed certificate: (PEM, DER)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Prueba CA")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM), cert.public_bytes(serialization.Encoding.DER)


@unittest.skipIf(x509 is None, "cryptography no está instalada")
class SettingsCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = Path(tempfile.mkdtemp(prefix="cenya-settings-"))
        self.env = {"CENYA_STATE_DIR": str(self.state)}
        self.downloads = Path(tempfile.mkdtemp(prefix="cenya-downloads-"))

    def run_command(self, *args: str) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = settings_command.run(list(args), self.env)
        return code, out.getvalue() + err.getvalue()

    def test_the_ca_is_copied_into_the_protected_folder_and_that_copy_is_what_settings_names(self) -> None:
        pem, _der = certificate()
        source = self.downloads / "empresa.pem"
        source.write_bytes(pem)

        code, said = self.run_command("set", "ca_bundle", str(source))

        self.assertEqual(code, 0, said)
        copy = self.state / store.CA_FILE
        self.assertEqual(copy.read_bytes().replace(b"\r\n", b"\n"), pem)
        self.assertEqual(local_settings.load_file(self.env).ca_bundle, str(copy))
        # El original puede desaparecer o cambiar: el agente usa su copia.
        source.write_bytes(b"otra cosa")
        ssl.create_default_context(cafile=local_settings.load_file(self.env).ca_bundle)

    def test_a_der_certificate_or_a_self_signed_leaf_is_accepted_and_stored_as_pem(self) -> None:
        for name, content in (("der", certificate()[1]), ("leaf", certificate(ca=False)[0])):
            with self.subTest(name=name):
                source = self.downloads / f"{name}.cer"
                source.write_bytes(content)
                code, said = self.run_command("set", "ca_bundle", str(source))
                self.assertEqual(code, 0, said)
                self.assertIn(b"-----BEGIN CERTIFICATE-----", (self.state / store.CA_FILE).read_bytes())

    def test_something_that_is_not_a_certificate_changes_nothing(self) -> None:
        for content in (b"", b"hola", b"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n", b"\x00" * 100):
            with self.subTest(content=content[:10]):
                source = self.downloads / "falso.pem"
                source.write_bytes(content)
                code, said = self.run_command("set", "ca_bundle", str(source))
                self.assertEqual(code, 1)
                self.assertIn("no contiene ningún certificado", said)
                self.assertFalse((self.state / store.CA_FILE).exists())
                self.assertEqual(local_settings.load_file(self.env).ca_bundle, "")

    def test_a_missing_file_is_said_and_nothing_changes(self) -> None:
        code, said = self.run_command("set", "ca_bundle", str(self.downloads / "no-existe.pem"))

        self.assertEqual(code, 1)
        self.assertIn("No se pudo leer el certificado", said)

    def test_the_other_settings_are_kept(self) -> None:
        local_settings.save(local_settings.Settings(proxy_mode="none", language="de"), self.env)
        pem, _der = certificate()
        (self.downloads / "ca.pem").write_bytes(pem)

        self.assertEqual(self.run_command("set", "ca_bundle", str(self.downloads / "ca.pem"))[0], 0)

        saved = local_settings.load_file(self.env)
        self.assertEqual((saved.proxy_mode, saved.language), ("none", "de"))

    def test_unset_forgets_the_ca_and_deletes_the_copy(self) -> None:
        pem, _der = certificate()
        (self.downloads / "ca.pem").write_bytes(pem)
        self.run_command("set", "ca_bundle", str(self.downloads / "ca.pem"))

        code, _said = self.run_command("unset", "ca_bundle")

        self.assertEqual(code, 0)
        self.assertFalse((self.state / store.CA_FILE).exists())
        self.assertEqual(local_settings.load_file(self.env).ca_bundle, "")

    def test_auto_update_can_be_switched_off_and_on(self) -> None:
        self.assertEqual(self.run_command("set", "auto_update", "off")[0], 0)
        self.assertFalse(local_settings.load_file(self.env).auto_update)
        self.assertEqual(self.run_command("set", "auto_update", "on")[0], 0)
        self.assertTrue(local_settings.load_file(self.env).auto_update)
        self.assertEqual(self.run_command("set", "auto_update", "maybe")[0], 2)

    def test_anything_else_is_the_usage_line(self) -> None:
        for args in ((), ("set",), ("set", "proxy", "x"), ("get", "ca_bundle"), ("set", "ca_bundle")):
            with self.subTest(args=args):
                code, said = self.run_command(*args)
                self.assertEqual(code, 2)
                self.assertIn("cenya-agent settings set ca_bundle", said)

    def test_the_settings_file_stays_valid_json(self) -> None:
        pem, _der = certificate()
        (self.downloads / "ca.pem").write_bytes(pem)
        self.run_command("set", "ca_bundle", str(self.downloads / "ca.pem"))

        data = json.loads((self.state / "settings.json").read_text(encoding="utf-8"))
        self.assertEqual(data["ca_bundle"], str(self.state / store.CA_FILE))


if __name__ == "__main__":
    unittest.main()
