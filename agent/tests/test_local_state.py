"""What the agent keeps and says about itself on its own machine: the `about`,
the identity key, the local settings, the log, and how it gets out (proxy)."""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado y la carpeta del agente

import json
import os
import sys
import tempfile
import unittest
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from agent import about, identity, logs, settings, store
from agent import client as agent_client
from agent.client import AgentClient


class AboutTests(unittest.TestCase):
    def test_the_hash_does_not_depend_on_key_order(self) -> None:
        one = {"a": 1, "b": {"x": [1, 2], "y": "ñ"}}
        two = {"b": {"y": "ñ", "x": [1, 2]}, "a": 1}
        self.assertEqual(about.digest(one), about.digest(two))
        self.assertNotEqual(about.digest(one), about.digest({**one, "a": 2}))
        self.assertEqual(about.canonical(one), '{"a":1,"b":{"x":[1,2],"y":"ñ"}}'.encode())

    def test_build_has_every_field_of_the_spec(self) -> None:
        with mock.patch.object(about, "networks", return_value=[]):
            data = about.build(excluded_subnets=("10.9.0.0/16",), auto_update=False)
        self.assertEqual(
            set(data),
            {"hostname", "os", "python", "agent_version", "frozen", "networks", "capabilities", "excluded", "auto_update"},
        )
        self.assertEqual(
            set(data["capabilities"]), {"snmp", "ssh", "ssh_password", "winrm", "hypervisors", "sealed_credentials"}
        )
        self.assertEqual(data["excluded"], {"subnets": ["10.9.0.0/16"], "addresses": []})
        self.assertFalse(data["auto_update"])
        json.dumps(data)  # serializable tal cual

    def test_build_never_raises(self) -> None:
        with mock.patch.object(about.socket, "gethostname", side_effect=OSError("x")), mock.patch.object(
            about, "_windows_networks", side_effect=OSError("x")
        ), mock.patch.object(about, "_linux_networks", side_effect=OSError("x")), mock.patch.object(
            about, "capabilities", side_effect=RuntimeError("x")
        ):
            data = about.build()
        self.assertEqual((data["hostname"], data["networks"], data["capabilities"]), ("", [], {}))

    def test_a_capability_that_breaks_is_false_not_a_crash(self) -> None:
        with mock.patch("agent.identity.public_key", side_effect=RuntimeError("roto")):
            self.assertFalse(about.capabilities()["sealed_credentials"])

    def test_the_ssh_password_capability_prefers_the_new_attribute(self) -> None:
        from agent import ssh

        with mock.patch.object(ssh, "SSHPASS_AVAILABLE", False), mock.patch.object(
            ssh, "PASSWORD_AUTH_AVAILABLE", True, create=True
        ):
            self.assertTrue(about.capabilities()["ssh_password"])
        with mock.patch.object(ssh, "SSHPASS_AVAILABLE", True):
            if not hasattr(ssh, "PASSWORD_AUTH_AVAILABLE"):
                self.assertTrue(about.capabilities()["ssh_password"])

    def test_linux_networks_from_ip_json(self) -> None:
        output = json.dumps([
            {"ifname": "lo", "flags": ["LOOPBACK", "UP"], "address": "00:00:00:00:00:00",
             "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
            {"ifname": "eth0", "flags": ["UP"], "operstate": "UP", "address": "AA:BB:CC:DD:EE:FF",
             "addr_info": [{"family": "inet", "local": "192.168.1.10", "prefixlen": 24},
                           {"family": "inet6", "local": "fe80::1", "prefixlen": 64},
                           {"family": "inet", "local": "169.254.3.3", "prefixlen": 16}]},
            {"ifname": "eth1", "operstate": "DOWN", "address": "11:22:33:44:55:66",
             "addr_info": [{"family": "inet", "local": "10.0.0.1", "prefixlen": 8}]},
        ])
        self.assertEqual(
            about.parse_ip_json(output),
            [{"interface": "eth0", "address": "192.168.1.10", "cidr": "192.168.1.0/24", "mac": "aa:bb:cc:dd:ee:ff"}],
        )

    def test_rubbish_from_ip_is_no_networks(self) -> None:
        for output in ("", "no es json", "{}", "[1, 2]", '[{"addr_info": "x"}]'):
            self.assertEqual(about.parse_ip_json(output), [], output)

    def test_this_machine_gives_a_list_and_never_raises(self) -> None:
        rows = about.networks()
        self.assertIsInstance(rows, list)
        for row in rows:
            self.assertEqual(set(row), {"interface", "address", "cidr", "mac"})
        self.assertEqual(about.networks(), rows)  # mismo orden: mismo hash


class IdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = {"CENYA_STATE_DIR": tempfile.mkdtemp(prefix="cenya-identity-")}

    @unittest.skipUnless(identity.available(), "sin cryptography")
    def test_the_key_is_created_once_and_reused(self) -> None:
        self.assertEqual(identity.public_key(self.env), "")  # en marcha nunca se crea
        first = identity.ensure(self.env)
        self.assertTrue(first.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertLessEqual(len(first), 2000)  # el tope del servidor (spec 1.1)
        self.assertEqual(identity.ensure(self.env), first)
        self.assertEqual(identity.public_key(self.env), first)
        private = identity.path(self.env).read_text(encoding="ascii")
        self.assertIn("PRIVATE KEY", private)
        self.assertNotIn(private, first)

    @unittest.skipUnless(identity.available(), "sin cryptography")
    def test_the_key_is_rsa_3072(self) -> None:
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_public_key(identity.ensure(self.env).encode())
        self.assertEqual(key.key_size, 3072)

    @unittest.skipUnless(identity.available(), "sin cryptography")
    def test_the_key_gets_the_same_protection_as_the_token(self) -> None:
        with mock.patch.object(store, "write_protected", wraps=store.write_protected) as write:
            identity.ensure(self.env)
        write.assert_called_once()
        self.assertEqual(write.call_args.args[0], identity.path(self.env))
        if sys.platform != "win32":
            self.assertEqual(identity.path(self.env).stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(identity.available(), "sin cryptography")
    def test_a_key_that_cannot_be_protected_is_not_written(self) -> None:
        with mock.patch.object(store.sys, "platform", "win32"), mock.patch.object(
            store, "_restrict_windows", side_effect=OSError("acceso denegado")
        ):
            self.assertEqual(identity.ensure(self.env), "")
        self.assertFalse(identity.path(self.env).exists())
        self.assertEqual(list(Path(self.env["CENYA_STATE_DIR"]).iterdir()), [])

    @unittest.skipUnless(identity.available(), "sin cryptography")
    def test_a_broken_key_file_is_replaced(self) -> None:
        identity.path(self.env).write_text("basura", encoding="ascii")
        self.assertEqual(identity.public_key(self.env), "")
        self.assertTrue(identity.ensure(self.env).startswith("-----BEGIN PUBLIC KEY-----"))

    def test_without_cryptography_there_is_no_key_and_no_crash(self) -> None:
        with mock.patch.dict(sys.modules, {"cryptography": None, "cryptography.hazmat.primitives.asymmetric": None,
                                           "cryptography.hazmat.primitives": None}):
            self.assertFalse(identity.available())
            self.assertEqual(identity.ensure(self.env), "")
            self.assertEqual(identity.public_key(self.env), "")
            self.assertFalse(about.capabilities()["sealed_credentials"])
        self.assertFalse(identity.path(self.env).exists())


class StoreRefactorTests(unittest.TestCase):
    def test_write_protected_is_atomic_and_leaves_no_temporary(self) -> None:
        target = Path(tempfile.mkdtemp()) / "sub" / "x.json"
        store.write_protected(target, "uno")
        store.write_protected(target, b"dos")
        self.assertEqual(target.read_text(encoding="utf-8"), "dos")
        self.assertEqual([p.name for p in target.parent.iterdir()], ["x.json"])


class SettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = tempfile.mkdtemp(prefix="cenya-settings-")
        self.env = {"CENYA_STATE_DIR": self.dir}

    def write(self, content: str) -> None:
        Path(self.dir, settings.FILE_NAME).write_text(content, encoding="utf-8")

    def test_no_file_is_the_defaults(self) -> None:
        self.assertEqual(settings.load(self.env), settings.Settings())
        self.assertIsNone(settings.Settings().proxy)

    def test_a_broken_file_is_the_defaults(self) -> None:
        for content in ("{", "[]", "null", '"x"', "\x00\x01"):
            self.write(content)
            self.assertEqual(settings.load(self.env), settings.Settings(), content)

    def test_a_wrong_field_does_not_throw_away_the_others(self) -> None:
        self.write(json.dumps({
            "language": "de", "proxy": {"mode": "teletransporte"}, "gentleness_cap": "brutal",
            "excluded": {"subnets": ["10.0.0.0/8", "no-es-red"], "addresses": ["10.0.0.5", "x"]},
            "auto_update": "quizá", "notifications": "off", "paused_until": "2026-10-02T10:00:00+00:00",
        }))
        loaded = settings.load(self.env)
        self.assertEqual(loaded.language, "de")
        self.assertEqual(loaded.proxy_mode, "system")
        self.assertEqual(loaded.gentleness_cap, "")
        self.assertEqual(loaded.excluded_subnets, ("10.0.0.0/8",))
        self.assertEqual(loaded.excluded_addresses, ("10.0.0.5",))
        self.assertTrue(loaded.auto_update)
        self.assertFalse(loaded.notifications)
        self.assertEqual(loaded.paused_until, datetime(2026, 10, 2, 10, 0, tzinfo=timezone.utc))

    def test_the_environment_wins_over_the_file(self) -> None:
        self.write(json.dumps({"ca_bundle": "C:/fichero.pem", "proxy": {"mode": "none"}, "gentleness_cap": "normal"}))
        env = {**self.env, "CENYA_CA_BUNDLE": "C:/entorno.pem", "CENYA_PROXY": "http://proxy:3128",
               "CENYA_GENTLENESS_CAP": "gentle", "NETINVENTORY_EXCLUDED_ADDRESSES": "10.0.0.1, 10.0.0.2"}
        loaded = settings.load(env)
        self.assertEqual(loaded.ca_bundle, "C:/entorno.pem")
        self.assertEqual(loaded.proxy, ("manual", "http://proxy:3128"))
        self.assertEqual(loaded.gentleness_cap, "gentle")
        self.assertEqual(loaded.excluded_addresses, ("10.0.0.1", "10.0.0.2"))

    def test_proxy_modes(self) -> None:
        for raw, expected in (
            ({"mode": "system", "url": "http://x"}, None),
            ({"mode": "none"}, ("none", "")),
            ({"mode": "manual", "url": "http://u:p@proxy:8080"}, ("manual", "http://u:p@proxy:8080")),
            ({"mode": "manual", "url": ""}, None),
        ):
            self.write(json.dumps({"proxy": raw}))
            self.assertEqual(settings.load(self.env).proxy, expected, raw)
        self.assertEqual(settings.load({**self.env, "CENYA_PROXY": "none"}).proxy, ("none", ""))
        self.assertIsNone(settings.load({**self.env, "CENYA_PROXY": "system"}).proxy)

    def test_save_round_trips_and_keeps_unknown_fields(self) -> None:
        self.write(json.dumps({"language": "fr", "futuro": {"x": 1}}))
        current = settings.load_file(self.env)
        paused = datetime(2026, 10, 3, tzinfo=timezone.utc)
        from dataclasses import replace

        self.assertTrue(settings.save(replace(current, paused_until=paused), self.env))
        data = json.loads(Path(self.dir, settings.FILE_NAME).read_text(encoding="utf-8"))
        self.assertEqual(data["futuro"], {"x": 1})
        self.assertEqual(settings.load(self.env).paused_until, paused)
        self.assertEqual(settings.load(self.env).language, "fr")

    def test_save_never_raises(self) -> None:
        with mock.patch.object(store, "write_protected", side_effect=OSError("disco")):
            self.assertFalse(settings.save(settings.Settings(), self.env))


class ProxyTests(unittest.TestCase):
    def proxies(self, opener: urllib.request.OpenerDirector) -> dict | None:
        for handler in opener.handlers:
            if isinstance(handler, urllib.request.ProxyHandler):
                return handler.proxies
        return None

    def test_system_mode_is_the_shared_opener_of_always(self) -> None:
        self.assertIs(AgentClient("https://x", "t")._opener, agent_client._OPENER)
        self.assertIs(AgentClient("https://x", "t", proxy=None)._opener, agent_client._OPENER)

    def test_none_goes_direct_even_with_a_system_proxy(self) -> None:
        system = {"https": "http://proxy-del-sistema:8080"}
        with mock.patch("urllib.request.getproxies", return_value=system):
            # Lo que haría el modo «system» en esa máquina...
            self.assertEqual(self.proxies(urllib.request.build_opener(agent_client._NoRedirects)), system)
            # ...y lo que hace «none»: ningún proxy en la cadena.
            self.assertIsNone(self.proxies(AgentClient("https://x", "t", proxy=("none", ""))._opener))

    def test_manual_goes_through_the_proxy(self) -> None:
        manual = AgentClient("https://x", "t", proxy=("manual", "http://proxy:3128"))._opener
        self.assertEqual(self.proxies(manual), {"http": "http://proxy:3128", "https": "http://proxy:3128"})

    def test_a_proxy_keeps_the_no_redirects_rule(self) -> None:
        opener = AgentClient("https://x", "t", proxy=("manual", "http://proxy:3128"))._opener
        self.assertTrue(any(isinstance(h, agent_client._NoRedirects) for h in opener.handlers))

    def test_the_certificate_fallback_goes_through_the_same_proxy(self) -> None:
        client = AgentClient("https://x", "t", proxy=("none", ""))
        with mock.patch("agent.client._fallback_opener", return_value=None) as fallback, mock.patch.object(
            client, "_opener"
        ) as first:
            import ssl
            import urllib.error

            first.open.side_effect = urllib.error.URLError(ssl.SSLCertVerificationError(1, "expired"))
            with self.assertRaises(Exception):
                client.heartbeat(version="0.11.0", hostname="pc")
        fallback.assert_called_once_with(("none", ""))


#: La errata que encontró la revisión: una barra de menos. `urllib` lanzaba
#: `ValueError("proxy URL with no authority: '<esta URL>'")`, con la clave.
MISTYPED_PROXY = "https:/admin:S3cret@proxy:8080"


class ProxySecretTests(unittest.TestCase):
    """A mistyped proxy URL never reaches the log, the status file or the Event Log."""

    def test_a_mistyped_proxy_is_a_push_error_that_does_not_name_it(self) -> None:
        client = AgentClient("https://portal.example", "cya_x", proxy=("manual", MISTYPED_PROXY))

        with self.assertRaises(agent_client.PushError) as raised:
            client.checkin({"protocol": 2})

        text = str(raised.exception)
        self.assertNotIn("S3cret", text)
        self.assertNotIn("admin", text)
        self.assertIn("proxy", text)

    def test_urllibs_own_error_is_not_repeated_either(self) -> None:
        # Por si alguna URL pasa la comprobación y urllib la rechaza después.
        client = AgentClient("https://portal.example", "cya_x", proxy=("manual", "http://proxy:3128"))
        boom = ValueError(f"proxy URL with no authority: {MISTYPED_PROXY!r}")
        with mock.patch.object(client, "_opener") as opener:
            opener.open.side_effect = boom
            with self.assertRaises(agent_client.PushError) as raised:
                client.heartbeat(version="0.11.0", hostname="pc")
        self.assertNotIn("S3cret", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)

    def test_valid_and_invalid_proxy_urls(self) -> None:
        for url in ("http://proxy:3128", "http://ana:clave@proxy:3128", "proxy.local:3128", "https://[::1]:8443"):
            self.assertTrue(agent_client.proxy_url_is_valid(url), url)
        for url in (MISTYPED_PROXY, "", "http://", "http://proxy:puerto", "proxy /x", "https:/proxy:8080"):
            self.assertFalse(agent_client.proxy_url_is_valid(url), url)

    def test_the_scrubber_masks_a_password_even_without_a_scheme(self) -> None:
        message = f"Error inesperado: ValueError: proxy URL with no authority: {MISTYPED_PROXY!r}"
        self.assertNotIn("S3cret", logs.scrub(message))
        self.assertEqual(logs.scrub("admin:pa/ss@proxy:3128"), "***@proxy:3128")
        self.assertEqual(logs.scrub("usuario ana@empresa.es a las 12:30"), "usuario ana@empresa.es a las 12:30")

    def test_the_status_file_never_keeps_it(self) -> None:
        from agent import status

        target = Path(tempfile.mkdtemp(prefix="cenya-status-scrub-")) / "status.json"
        with mock.patch.dict(os.environ, {status.ENV_VAR: str(target)}):
            status.failed(f"Error inesperado: ValueError: proxy URL with no authority: {MISTYPED_PROXY!r}")
            status.task_finished(task="presence", created=0, refreshed=0, errors=[MISTYPED_PROXY], next_in=None)
        self.assertNotIn("S3cret", target.read_text(encoding="utf-8"))

    def test_what_the_agent_prints_never_keeps_it(self) -> None:
        from agent import __main__ as loop

        with mock.patch("builtins.print") as printed, mock.patch.object(loop.logs, "error") as logged:
            loop._say(f"[agente] {MISTYPED_PROXY}", error=True)
        self.assertNotIn("S3cret", str(printed.call_args))
        self.assertNotIn("S3cret", str(logged.call_args))


class LogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env = {"CENYA_STATE_DIR": tempfile.mkdtemp(prefix="cenya-logs-")}
        self.addCleanup(logs.close)

    def test_lines_land_in_the_state_folder(self) -> None:
        target = logs.setup(self.env)
        logs.info("[agente] hola")
        logs.error("[agente] adiós")
        logs.close()
        self.assertEqual(target, Path(self.env["CENYA_STATE_DIR"]) / "logs" / "agent.log")
        text = target.read_text(encoding="utf-8")
        self.assertIn("INFO [agente] hola", text)
        self.assertIn("ERROR [agente] adiós", text)

    def test_it_rotates_five_files_of_two_megabytes(self) -> None:
        logs.setup(self.env)
        handler = logs._logger().handlers[0]
        self.assertEqual((handler.maxBytes, handler.backupCount), (2 * 1024 * 1024, 4))

    def test_secrets_are_masked_as_a_last_net(self) -> None:
        self.assertEqual(logs.scrub("Authorization: Bearer cya_abc123"), "Authorization: Bearer ***")
        self.assertEqual(logs.scrub("proxy http://ana:secreto@proxy:3128"), "proxy http://***@proxy:3128")

    def test_without_a_writable_folder_nothing_raises(self) -> None:
        with mock.patch.object(logs.logging.handlers, "RotatingFileHandler", side_effect=OSError("no")):
            self.assertIsNone(logs.setup(self.env))
        logs.info("se pierde, sin más")


if __name__ == "__main__":
    unittest.main()
