"""De dónde salen las credenciales y qué pasa cuando llegan mal escritas.

Es infraestructura compartida por tres colectores, así que un fallo aquí no se
nota en uno: se nota en el barrido entero y de forma silenciosa.
"""

from __future__ import annotations

import unittest

from agent import credentials as creds
from agent.config import Config, from_env


def env_with(**extra: str) -> dict[str, str]:
    return {"NETINVENTORY_AGENT_TOKEN": "nia_x", **extra}


class ParsingTests(unittest.TestCase):
    def test_the_server_list_wins_over_the_environment(self) -> None:
        env = Config(url="http://x", token="t", credentials=({"kind": "ssh", "username": "entorno"},))
        ctx = {"config": {"credentials": [{"kind": "ssh", "username": "servidor"}]}, "env": env}

        self.assertEqual([c.username for c in creds.for_kind(ctx, creds.SSH)], ["servidor"])

    def test_without_the_server_the_environment_serves(self) -> None:
        env = Config(url="http://x", token="t", credentials=({"kind": "ssh", "username": "entorno"},))

        self.assertEqual([c.username for c in creds.for_kind({"config": {}, "env": env}, creds.SSH)], ["entorno"])

    def test_nothing_configured_is_an_empty_list_and_not_a_crash(self) -> None:
        self.assertEqual(creds.for_kind({"config": {}, "env": None}, creds.SSH), [])

    def test_rubbish_entries_are_dropped_one_by_one(self) -> None:
        """El payload lo escribe otro proceso: una entrada mala no puede
        llevarse por delante las buenas que van detrás."""
        ctx = {
            "config": {
                "credentials": [
                    "no soy un diccionario",
                    {"kind": "ssh"},  # sin usuario
                    {"username": "sin-protocolo"},
                    {"kind": "ssh", "username": "buena", "port": "no-es-un-numero"},
                ]
            },
            "env": None,
        }

        found = creds.for_kind(ctx, creds.SSH)

        self.assertEqual([c.username for c in found], ["buena"])
        self.assertEqual(found[0].port, 0)

    def test_each_kind_only_sees_its_own(self) -> None:
        ctx = {
            "config": {
                "credentials": [
                    {"kind": "ssh", "username": "root"},
                    {"kind": "winrm", "username": "ACME\\admin"},
                    {"kind": "vmware", "username": "lector@vsphere.local", "host": "vc.local"},
                ]
            },
            "env": None,
        }

        self.assertEqual([c.username for c in creds.for_kind(ctx, creds.WINRM)], ["ACME\\admin"])
        self.assertEqual([c.host for c in creds.for_kind(ctx, creds.VMWARE)], ["vc.local"])

    def test_the_secret_never_shows_up_in_the_representation(self) -> None:
        """Un `print` o un volcado de excepción no puede escupir la contraseña:
        el agente corre desatendido y su salida acaba en un fichero de log."""
        credential = creds.Credential(kind="ssh", username="root", secret="ultrasecreta")

        self.assertNotIn("ultrasecreta", repr(credential))

    def test_a_v3_user_arrives_with_its_protocols_and_second_secret(self) -> None:
        ctx = {
            "config": {
                "credentials": [
                    {
                        "kind": "snmpv3",
                        "username": "lector",
                        "secret": "autenticada-larga",
                        "auth_protocol": "SHA256",  # el servidor manda minúsculas; esto blinda
                        "priv_protocol": "AES",
                        "priv_secret": "cifrada-larga",
                    }
                ]
            },
            "env": None,
        }

        (credential,) = creds.for_kind(ctx, creds.SNMPV3)

        self.assertEqual(credential.auth_protocol, "sha256")
        self.assertEqual(credential.priv_protocol, "aes")
        self.assertEqual(credential.priv_secret, "cifrada-larga")

    def test_neither_v3_secret_shows_up_in_the_representation(self) -> None:
        credential = creds.Credential(
            kind="snmpv3", username="lector", secret="auth-secreta", priv_secret="priv-secreta"
        )

        self.assertNotIn("auth-secreta", repr(credential))
        self.assertNotIn("priv-secreta", repr(credential))


class IdentTests(unittest.TestCase):
    """El `ident` es lo único de una credencial que la memoria guarda en disco."""

    def _ctx(self, *raw: dict) -> dict:
        return {"config": {"credentials": list(raw)}, "env": None}

    def test_the_servers_id_wins(self) -> None:
        (credential,) = creds.all_from(self._ctx({"id": "c1f0", "kind": "ssh", "username": "root"}))

        self.assertEqual(credential.ident, "c1f0")

    def test_without_an_id_it_is_derived_and_stable(self) -> None:
        raw = {"kind": "ssh", "username": "root", "host": "", "port": 2222, "label": "Switches"}

        first = creds.all_from(self._ctx(raw))[0].ident
        second = creds.all_from(self._ctx(dict(raw)))[0].ident

        self.assertTrue(first)
        self.assertEqual(first, second)

    def test_the_derived_ident_never_comes_from_the_secret(self) -> None:
        """Un hash de una contraseña corta se deshace con un diccionario: si el
        secreto entrara en el `ident`, la memoria en disco lo delataría."""
        one = creds.all_from(self._ctx({"kind": "ssh", "username": "root", "secret": "uno"}))[0]
        other = creds.all_from(self._ctx({"kind": "ssh", "username": "root", "secret": "otro-distinto"}))[0]

        self.assertEqual(one.ident, other.ident)
        self.assertNotIn("uno", one.ident)

    def test_two_identical_entries_in_different_positions_are_two_credentials(self) -> None:
        found = creds.all_from(self._ctx({"kind": "ssh", "username": "root"}, {"kind": "ssh", "username": "root"}))

        self.assertNotEqual(found[0].ident, found[1].ident)

    def test_a_community_is_remembered_by_its_number_never_its_value(self) -> None:
        community = creds.community("super-secreta", 3)

        self.assertEqual(community.ident, "community-3")
        self.assertNotIn("super-secreta", repr(community))

    def test_a_credential_built_by_hand_still_gets_an_ident(self) -> None:
        self.assertTrue(creds.Credential(kind="ssh", username="root").ident)


class ScopeTests(unittest.TestCase):
    def _one(self, scope: object) -> creds.Credential:
        return creds.all_from({"config": {"credentials": [{"kind": "ssh", "username": "u", "scope": scope}]}, "env": None})[0]

    def test_no_scope_means_everywhere(self) -> None:
        for scope in (None, {}, {"subnets": [], "hosts": []}, "rubbish"):
            with self.subTest(scope=scope):
                self.assertTrue(self._one(scope).covers("172.16.4.4"))

    def test_subnets_and_hosts(self) -> None:
        credential = self._one({"subnets": ["10.0.0.0/24"], "hosts": ["192.168.1.7"]})

        self.assertTrue(credential.covers("10.0.0.200"))
        self.assertTrue(creds.covers(credential, "192.168.1.7"))
        self.assertFalse(credential.covers("10.0.1.1"))
        self.assertFalse(credential.covers(""))

    def test_a_mistyped_scope_covers_nothing_rather_than_everything(self) -> None:
        """Quien acotó una credencial no quería que se probara fuera; una errata
        no puede convertir eso en probarla contra toda la red."""
        credential = self._one({"subnets": ["10.0.0.0/33"]})

        self.assertFalse(credential.covers("10.0.0.1"))

    def test_a_host_by_name(self) -> None:
        credential = self._one({"hosts": ["VC.acme.local"]})

        self.assertTrue(credential.covers("vc.acme.local"))
        self.assertFalse(credential.covers("10.0.0.1"))


class CaFileTests(unittest.TestCase):
    def test_the_credentials_own_ca_wins(self) -> None:
        env = Config(url="http://x", token="t", ca_bundle="/etc/ssl/empresa.pem")
        credential = creds.Credential(kind="vmware", username="u", ca_file="/etc/ssl/vcenter.pem")

        self.assertEqual(creds.ca_file_for({"env": env}, credential), "/etc/ssl/vcenter.pem")

    def test_without_one_the_company_ca_serves(self) -> None:
        env = Config(url="http://x", token="t", ca_bundle="/etc/ssl/empresa.pem")
        credential = creds.Credential(kind="vmware", username="u")

        self.assertEqual(creds.ca_file_for({"env": env}, credential), "/etc/ssl/empresa.pem")

    def test_without_any_it_is_empty_and_never_a_none(self) -> None:
        """Vacío significa «verifica con las CA del sistema». Un `None` que se
        cuele hasta `ssl.create_default_context` haría lo mismo, pero pasado a
        `pywinrm` como ruta rompería el intento sin decir por qué."""
        credential = creds.Credential(kind="vmware", username="u")

        self.assertEqual(creds.ca_file_for({"env": None}, credential), "")


class EnvironmentTests(unittest.TestCase):
    def test_the_json_of_the_environment_becomes_credentials(self) -> None:
        config = from_env(
            env_with(NETINVENTORY_CREDENTIALS='[{"kind": "ssh", "username": "root"}]')
        )

        self.assertEqual(config.credentials, ({"kind": "ssh", "username": "root"},))

    def test_a_broken_json_leaves_the_agent_running(self) -> None:
        """Morir aquí dejaría sin barrido también al ping y al SNMP, que no
        tienen ninguna culpa de una comilla mal puesta."""
        config = from_env(env_with(NETINVENTORY_CREDENTIALS="{esto no es json"))

        self.assertEqual(config.credentials, ())

    def test_a_json_that_is_not_a_list_is_ignored(self) -> None:
        config = from_env(env_with(NETINVENTORY_CREDENTIALS='{"kind": "ssh"}'))

        self.assertEqual(config.credentials, ())


if __name__ == "__main__":
    unittest.main()
