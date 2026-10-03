"""Sealed credentials inside the agent (spec 3.2, 3.3): opening, counting, the three orders, hygiene.

La red entera es de mentira: ni un ping, ni un `ssh`, ni un paquete SNMP. Lo
que sí es de verdad es el cifrado (la clave de `docs/sealing-test-vectors.json`
hace de `identity.key`), la memoria, la cola, el registro y el HTTP.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado y la carpeta del agente

import contextlib
import http.server
import io
import json
import logging
import os
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from agent import credentials as creds
from agent import hypervisor, logs, net, orders, probe, sealing, snmp, ssh, status, store, tasks
from agent.client import AgentClient, PushError
from agent.collectors import tasking
from agent.collectors.snmp import SnmpCollector, snmp_credentials
from agent.config import Config
from agent.control import Control, Hooks, Shared
from agent.memory import Excluded, Memory
from agent.outbox import Outbox
from agent.runtime import Runtime
from agent.scheduler import Job
from agent.tests.test_control import FakeClient
from agent.tests.test_sealing import HAVE_CRYPTO, key, pem, vectors

AGENT = "6f1c1e0e-3b0a-4b8e-9a52-2f5d6c1d7a10"
NEW_AGENT = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
OTHER_AGENT = "11111111-2222-4333-8444-555555555555"
IP = "10.0.0.5"
MAC = "aa:bb:cc:dd:ee:05"

CANARIES = {
    "ssh": "CANARY-ssh-Zq81x",
    "community": "CANARY-community-Lm55k",
    "winrm": "CANARY-winrm-Pp09r",
    "v3auth": "CANARY-v3auth-Hh27t",
    "v3priv": "CANARY-v3priv-Gg64w",
    "vmware": "CANARY-vmware-Jj33q",
    "netbox": "CANARY-netbox-token-Ww71e",
}


def seal(ident: str, secret: str = "", priv: str = "", *, agent: str = AGENT, public: str | None = None) -> dict:
    plaintext = {"secret": secret}
    if priv:
        plaintext["priv_secret"] = priv
    return sealing.seal_for(public or vectors()["public_key_pem"], plaintext, agent_uuid=agent, subject_id=ident)


def sealed(kind: str, ident: str, secret: str = "", priv: str = "", **fields: Any) -> dict:
    entry = {"id": ident, "kind": kind, "name": fields.pop("name", ident), "username": "admin", "host": "", "port": 0,
             "key_file": "", "auth_protocol": "", "priv_protocol": "", "scope": {"subnets": [], "hosts": []}}
    entry.update(fields)
    entry["sealed"] = fields.get("sealed", seal(ident, secret, priv))
    return entry


class StateTestCase(unittest.TestCase):
    """Una carpeta de estado propia, con la clave de los vectores como `identity.key`."""

    def setUp(self) -> None:
        if not HAVE_CRYPTO:
            self.skipTest("sin cryptography")
        self.state = Path(tempfile.mkdtemp(prefix="cenya-sealed-"))
        self.environ = {"CENYA_STATE_DIR": str(self.state)}
        patcher = mock.patch.dict(os.environ, self.environ)
        patcher.start()
        self.addCleanup(patcher.stop)
        (self.state / "identity.key").write_text(vectors()["private_key_pem_TEST_ONLY"], encoding="ascii")

    def ctx(self, credentials: list[dict], **extra: Any) -> dict:
        ctx: dict[str, Any] = {
            "config": {"credentials": credentials, **extra.pop("config", {})},
            "env": None,
            creds.CTX_KEY: creds.Unsealer(extra.pop("agent", AGENT), self.environ),
            "errors": [],
        }
        ctx.update(extra)
        return ctx


# --- Abrir las credenciales ------------------------------------------------------------


class SealedConfigTests(StateTestCase):
    def test_a_mixed_config_of_legacy_and_sealed_entries_works(self) -> None:
        legacy = {"id": "old", "kind": "ssh", "username": "root", "secret": "en-claro"}
        ctx = self.ctx([legacy, sealed("ssh", "new", CANARIES["ssh"])], config={"communities": ["public2"]})
        found = {credential.ident: credential.secret for credential in creds.all_from(ctx)}
        self.assertEqual(found, {"old": "en-claro", "new": CANARIES["ssh"]})
        # Las comunidades de siempre siguen ahí, detrás.
        self.assertEqual([c.secret for c in snmp_credentials(ctx)], ["public2"])

    def test_snmpv3_opens_both_secrets(self) -> None:
        entry = sealed("snmpv3", "v3", CANARIES["v3auth"], CANARIES["v3priv"], auth_protocol="SHA", priv_protocol="AES")
        (credential,) = creds.all_from(self.ctx([entry]))
        self.assertEqual((credential.secret, credential.priv_secret), (CANARIES["v3auth"], CANARIES["v3priv"]))
        self.assertEqual((credential.auth_protocol, credential.priv_protocol), ("sha", "aes"))

    def test_the_snmp_kind_needs_no_username_and_no_other_kind_does(self) -> None:
        ctx = self.ctx([sealed("snmp", "c1", CANARIES["community"], username=""),
                        sealed("ssh", "s1", CANARIES["ssh"], username="")])
        found = creds.all_from(ctx)
        self.assertEqual([(c.kind, c.ident, c.username) for c in found], [("snmp", "c1", "")])
        self.assertTrue(found[0].from_server)

    def test_everything_opens_once_per_run_and_only_when_asked(self) -> None:
        ctx = self.ctx([sealed("ssh", "a", "1"), sealed("winrm", "b", "2"), sealed("snmp", "c", "3", username="")])
        with mock.patch("agent.sealing.open_envelope", wraps=sealing.open_envelope) as opened:
            self.assertEqual(opened.call_count, 0)  # nada se abre hasta que alguien pide credenciales
            for _ in range(3):
                creds.for_kind(ctx, creds.SSH)
                creds.for_kind(ctx, creds.WINRM)
                snmp_credentials(ctx)
            self.assertEqual(opened.call_count, 3)
            # Otra ejecución, otro `ctx`: se vuelve a abrir (nada se guardó entre medias).
            creds.all_from(self.ctx(ctx["config"]["credentials"]))
            self.assertEqual(opened.call_count, 6)

    def test_a_task_that_never_asks_for_credentials_opens_nothing(self) -> None:
        ctx = self.ctx([sealed("ssh", "a", "1", sealed={"v": 9})])

        class Quiet:
            name = "sweep"

            def collect(self, ctx: dict) -> list:
                return []

        with mock.patch("agent.tasks.all_collectors", return_value=[Quiet()]), \
             mock.patch("agent.sealing.open_envelope", side_effect=AssertionError("ni uno")):
            _items, entries, _stats = tasks.run_task("presence", ctx)
        self.assertEqual(entries, [])

    def test_unreadable_entries_are_skipped_and_counted_once_per_run(self) -> None:
        good = sealed("ssh", "good", CANARIES["ssh"])
        entries = [
            good,
            sealed("ssh", "tampered", "x", sealed={**seal("tampered", "x"), "ct": seal("other", "y")["ct"]}),
            sealed("winrm", "for-another-agent", "x", sealed=seal("for-another-agent", "x", agent=OTHER_AGENT)),
            sealed("winrm", "null", "x", sealed=None),
            sealed("snmp", "moved", "x", username="", sealed=seal("somewhere-else", "x")),
            {"id": "no-envelope", "kind": "winrm", "username": "admin"},  # sin sobre para este agente
            {"id": "key-file", "kind": "ssh", "username": "root", "key_file": "/k"},  # sin secreto: vale
        ]
        ctx = self.ctx(entries)

        class Greedy:
            def __init__(self, name: str) -> None:
                self.name = name

            def collect(self, ctx: dict) -> list:
                for _ in range(3):
                    creds.all_from(ctx)
                    snmp_credentials(ctx)
                return []

        with mock.patch("agent.tasks.all_collectors", return_value=[Greedy("snmp"), Greedy("ssh"), Greedy("winrm")]):
            _items, notes, _stats = tasks.run_task("inventory", ctx)
        (note,) = notes
        self.assertEqual((note.collector, note.code, note.params), ("credentials", "sealed_unreadable", {"count": 5}))
        self.assertEqual(sorted(c.ident for c in creds.all_from(ctx)), ["good", "key-file"])
        # Lo ilegible no se prueba con una contraseña vacía, ni se cambia por «public».
        self.assertEqual(snmp_credentials(ctx), [])

    def test_without_the_agent_uuid_nothing_opens(self) -> None:
        ctx = self.ctx([sealed("ssh", "a", "1")], agent="")
        self.assertEqual(creds.all_from(ctx), [])
        self.assertEqual(ctx[creds.CTX_KEY].unreadable, 1)

    def test_without_the_library_sealed_entries_are_unreadable_not_a_crash(self) -> None:
        ctx = self.ctx([sealed("ssh", "a", "1"), {"id": "old", "kind": "ssh", "username": "u", "secret": "s"}])
        with mock.patch("agent.sealing.available", return_value=False):
            self.assertEqual([c.ident for c in creds.all_from(ctx)], ["old"])
        self.assertEqual(ctx[creds.CTX_KEY].unreadable, 1)

    def test_no_plaintext_at_rest_nor_in_a_repr(self) -> None:
        ctx = self.ctx([sealed("ssh", "s1", CANARIES["ssh"]), sealed("snmp", "c1", CANARIES["community"], username="")])
        memory = Memory(self.state / "memory.json")
        memory.note_host(IP, MAC, datetime.now(timezone.utc))
        for credential in creds.all_from(ctx):
            memory.record_success(MAC, "ssh" if credential.kind == "ssh" else "snmp", credential, datetime.now(timezone.utc))
            self.assertNotIn(credential.secret, repr(credential))
        memory.save()
        on_disk = (self.state / "memory.json").read_text(encoding="utf-8")
        self.assertIn('"s1"', on_disk)
        self.assertIn('"c1"', on_disk)  # la comunidad sellada se recuerda por su id
        for canary in CANARIES.values():
            self.assertNotIn(canary, on_disk)
            self.assertNotIn(canary, repr(ctx[creds.CTX_KEY]))

    def test_credentials_ok_counts_hosts_per_server_credential(self) -> None:
        derived = {"kind": "ssh", "username": "local", "secret": "x"}  # sin id: no se informa
        ctx = self.ctx([sealed("ssh", "s1", "1"), derived])

        class Logs:
            name = "ssh"

            def collect(self, ctx: dict) -> list:
                server, local = creds.for_kind(ctx, creds.SSH)
                for ip in ("10.0.0.1", "10.0.0.2", "10.0.0.2"):
                    tasking.settle(ctx, ip, "", "ssh", server, attempted=True, full=True)
                tasking.settle(ctx, "10.0.0.3", "", "ssh", local, attempted=True, full=True)
                tasking.settle(ctx, "10.0.0.4", "", "ssh", None, attempted=True, full=True)
                return []

        with mock.patch("agent.tasks.all_collectors", return_value=[Logs()]):
            _items, _notes, stats = tasks.run_task("inventory", ctx)
        self.assertEqual(stats["credentials_ok"], {"s1": 2})

    def test_no_credentials_ok_when_nothing_logged_in(self) -> None:
        with mock.patch("agent.tasks.all_collectors", return_value=[]):
            _items, _notes, stats = tasks.run_task("inventory", self.ctx([]))
        self.assertNotIn("credentials_ok", stats)


class SnmpKindTests(StateTestCase):
    def snmp_ctx(self, credentials: list[dict], **config: Any) -> dict:
        memory = Memory.load(None)
        return self.ctx(credentials, config=config, task="inventory", hosts=[{"ip": IP, "mac": MAC}], memory=memory)

    def run_collector(self, ctx: dict) -> dict:
        seen: dict[str, Any] = {}

        def query_plan(plan: dict, **kwargs: Any) -> dict:
            seen.update(plan)
            data = {"name": "sw", "description": "", "interfaces": [], "addresses": {}}
            return {ip: (0, data) for ip in plan}

        with mock.patch.object(snmp, "AVAILABLE", True), mock.patch.object(snmp, "query_plan", side_effect=query_plan):
            SnmpCollector().collect(ctx)
        return seen

    def test_a_sealed_community_feeds_the_collector_and_is_remembered_by_its_id(self) -> None:
        ctx = self.snmp_ctx([sealed("snmp", "comm-1", CANARIES["community"], username="")])
        plan = self.run_collector(ctx)
        self.assertEqual(plan, {IP: [CANARIES["community"]]})  # sin «public» detrás
        self.assertEqual(ctx["memory"].remembered(MAC, "snmp"), "comm-1")
        self.assertEqual(tasking.credentials_ok(ctx), {"comm-1": 1})

    def test_legacy_communities_keep_working(self) -> None:
        ctx = self.snmp_ctx([], communities=["vieja"])
        self.assertEqual(self.run_collector(ctx), {IP: ["vieja"]})
        self.assertEqual(ctx["memory"].remembered(MAC, "snmp"), "community-1")

    def test_with_nothing_configured_public_is_still_the_default(self) -> None:
        self.assertEqual(self.run_collector(self.snmp_ctx([])), {IP: ["public"]})


# --- Los encargos ----------------------------------------------------------------------


class TestCredentialOrderTests(StateTestCase):
    def test_a_good_ssh_credential_logs_in_and_is_remembered_despite_the_daily_limit(self) -> None:
        memory = Memory.load(None)
        memory.note_host(IP, "", datetime.now(timezone.utc))
        memory.record_round_failed(IP, "ssh", datetime.now(timezone.utc))
        ctx = self.ctx([sealed("ssh", "s1", CANARIES["ssh"])], memory=memory)
        with mock.patch.object(probe, "_port_open", return_value=True), \
             mock.patch.object(probe.ssh, "run", return_value=ssh.Answer(connected=True)) as run:
            outcome, result, notes = orders.test_credential({"credential_id": "s1", "ip": IP}, ctx)
        self.assertEqual((outcome, result["ok"], result["line"]["code"]), ("done", True, "logged_in"))
        self.assertEqual(result["line"]["params"], {"username": "admin"})
        self.assertEqual(run.call_args.kwargs["secret"], CANARIES["ssh"])
        self.assertEqual(memory.remembered(IP, "ssh"), "s1")
        self.assertEqual(notes, [])
        self.assertNotIn(CANARIES["ssh"], json.dumps(result))

    def test_a_refused_login_is_done_and_not_ok(self) -> None:
        ctx = self.ctx([sealed("winrm", "w1", CANARIES["winrm"])])
        with mock.patch.object(probe, "_port_open", return_value=True), \
             mock.patch.object(probe.winrm, "query",
                               return_value=mock.Mock(connected=False, error=f"401 {CANARIES['winrm']}")):
            outcome, result, _notes = orders.test_credential({"credential_id": "w1", "ip": IP}, ctx)
        self.assertEqual((outcome, result["ok"], result["line"]["code"]), ("done", False, "none_worked"))
        self.assertNotIn(CANARIES["winrm"], json.dumps(result))

    def test_a_sealed_community_answers(self) -> None:
        ctx = self.ctx([sealed("snmp", "c1", CANARIES["community"], username="")])
        with mock.patch.object(probe.snmp, "AVAILABLE", True), \
             mock.patch.object(probe.snmp, "query_hosts", return_value={IP: {}}) as query:
            outcome, result, _notes = orders.test_credential({"credential_id": "c1", "ip": IP}, ctx)
        self.assertEqual((outcome, result["ok"], result["line"]["code"]), ("done", True, "answers"))
        self.assertEqual(query.call_args.args, ([IP], [CANARIES["community"]]))
        self.assertNotIn(CANARIES["community"], json.dumps(result))

    def test_an_excluded_address_is_refused_with_the_probe_code(self) -> None:
        ctx = self.ctx([sealed("ssh", "s1", "x")], excluded=Excluded(addresses=[IP]))
        with mock.patch.object(probe.ssh, "run", side_effect=AssertionError("ni se intenta")):
            outcome, result, notes = orders.test_credential({"credential_id": "s1", "ip": IP}, ctx)
        self.assertEqual((outcome, result["ok"]), ("failed", False))
        self.assertEqual((notes[0].collector, notes[0].code), ("probe", "excluded"))

    def test_refusals(self) -> None:
        entries = [sealed("ssh", "s1", "x", scope={"subnets": ["192.168.0.0/24"], "hosts": []}),
                   sealed("ssh", "broken", "x", sealed={"v": 1})]
        cases = [
            ({"credential_id": "nope", "ip": IP}, "unknown_credential"),
            ({"credential_id": "broken", "ip": IP}, "sealed_unreadable"),
            ({"credential_id": "s1", "ip": IP}, "out_of_scope"),
            ({"credential_id": "s1", "ip": "no-es-ip"}, "bad_address"),
            ({"credential_id": "s1"}, "bad_address"),
            ({}, "unknown_credential"),
        ]
        for params, code in cases:
            with self.subTest(code=code, params=params), \
                 mock.patch.object(probe.ssh, "run", side_effect=AssertionError("ni se intenta")):
                outcome, result, notes = orders.test_credential(params, self.ctx(entries))
                self.assertEqual((outcome, result["ok"], notes[0].code), ("failed", False, code))

    def test_a_hypervisor_is_tested_against_its_own_host(self) -> None:
        logins: list[tuple] = []

        class FakeVCenter:
            def __init__(self, host: str, username: str, secret: str, **kwargs: Any) -> None:
                logins.append((host, username, secret))
                self.secret = secret

            def login(self) -> None:
                if self.secret != CANARIES["vmware"]:
                    raise hypervisor.HypervisorError(f"rechazado: {self.secret}")

        memory = Memory.load(None)
        good = sealed("vmware", "vc", CANARIES["vmware"], host="vcenter.local")
        bad = sealed("vmware", "vc-bad", "otra-" + CANARIES["vmware"], host="vcenter.local")
        with mock.patch.dict("agent.collectors.hypervisors.CLIENTS", {"vmware": FakeVCenter}), \
             mock.patch.object(net, "resolve", return_value="10.0.0.50"):
            ok = orders.test_credential({"credential_id": "vc"}, self.ctx([good, bad], memory=memory))
            ko = orders.test_credential({"credential_id": "vc-bad", "ip": "1.2.3.4"}, self.ctx([good, bad]))
        self.assertEqual((ok[0], ok[1]["ok"], ok[1]["line"]["code"]), ("done", True, "logged_in"))
        self.assertEqual(logins[0], ("vcenter.local", "admin", CANARIES["vmware"]))
        self.assertEqual(memory.remembered("10.0.0.50", "vmware"), "vc")
        self.assertEqual((ko[0], ko[1]["ok"], ko[1]["line"]["code"]), ("done", False, "failed"))
        self.assertNotIn(CANARIES["vmware"], json.dumps(ko[1]))


class ResealOrderTests(StateTestCase):
    def test_reseal_closes_the_envelopes_for_the_new_agent(self) -> None:
        entries = [sealed("ssh", "s1", CANARIES["ssh"]),
                   sealed("snmpv3", "v3", CANARIES["v3auth"], CANARIES["v3priv"]),
                   sealed("ssh", "broken", "x", sealed=seal("otro-id", "x")),
                   {"id": "legacy", "kind": "ssh", "username": "u", "secret": "en-claro"}]
        params = {"agent": NEW_AGENT, "public_key": pem(key("other")),
                  "credential_ids": ["s1", "v3", "broken", "legacy", "nope", "s1"]}
        outcome, result, notes = orders.reseal(params, self.ctx(entries), agent_uuid=AGENT, environ=self.environ)
        self.assertEqual((outcome, notes), ("done", []))
        self.assertEqual(sorted(result["envelopes"]), ["s1", "v3"])
        self.assertEqual(result["missing"], ["broken", "legacy", "nope"])
        opened = sealing.open_envelope(result["envelopes"]["v3"], agent_uuid=NEW_AGENT, subject_id="v3",
                                       private_key=key("other"))
        self.assertEqual(opened, {"secret": CANARIES["v3auth"], "priv_secret": CANARIES["v3priv"]})
        # Ya no abre con la clave de este agente, ni con su uuid.
        with self.assertRaises(sealing.SealError):
            sealing.open_envelope(result["envelopes"]["s1"], agent_uuid=AGENT, subject_id="s1", private_key=key("other"))
        with self.assertRaises(sealing.SealError):
            sealing.open_envelope(result["envelopes"]["s1"], agent_uuid=NEW_AGENT, subject_id="s1",
                                  private_key=key("agent"))
        self.assertNotIn(CANARIES["ssh"], json.dumps(result))

    def test_bad_requests_are_refused_before_opening_anything(self) -> None:
        good = {"agent": NEW_AGENT, "public_key": pem(key("other")), "credential_ids": ["s1"]}
        cases = [
            ({**good, "public_key": pem(key("weak", 2048))}, "bad_public_key", {"reason": "weak_key"}),
            ({**good, "public_key": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"}, "bad_public_key",
             {"reason": "key"}),
            ({**good, "public_key": None}, "bad_public_key", {"reason": "key"}),
            ({**good, "agent": "no-es-uuid"}, "bad_agent", {}),
            ({**good, "credential_ids": "s1"}, "bad_params", {}),
            ({**good, "credential_ids": ["x"] * 1001}, "bad_params", {}),
        ]
        ctx = self.ctx([sealed("ssh", "s1", CANARIES["ssh"])])
        for params, code, extra in cases:
            with self.subTest(code=code, extra=extra), \
                 mock.patch("agent.sealing.open_envelope", side_effect=AssertionError("ni se abre")):
                outcome, result, notes = orders.reseal(params, ctx, agent_uuid=AGENT, environ=self.environ)
                self.assertEqual((outcome, result, notes[0].code), ("failed", {}, code))
                self.assertEqual(notes[0].params, extra)


class NetboxOrderTests(StateTestCase):
    ORDER = "ord-123"
    URL = "https://netbox.example.test"

    def params(self, **extra: Any) -> dict:
        token = {"secret": CANARIES["netbox"], "url": self.URL}
        base = {"url": self.URL, "verify_tls": True,
                "sealed_token": sealing.seal_for(vectors()["public_key_pem"], token, agent_uuid=AGENT,
                                                 subject_id=self.ORDER)}
        base.update(extra)
        return base

    def run_order(self, params: dict, *, fetch: Any = None, upload: Any = None, progress: Any = None) -> tuple:
        uploads: list[tuple] = []

        def default_fetch(url: str, token: str, verify_tls: bool = True, progress: Any = None) -> dict:
            from agent import netbox_export

            self.assertEqual(token, CANARIES["netbox"])
            for path in netbox_export.ENDPOINTS.values():
                progress(path)
            return {"devices": [{"name": "a"}, {"name": "b"}], "sites": [{"name": "s"}]}

        def default_upload(bundle: dict, order_id: str) -> dict:
            uploads.append((bundle, order_id))
            return {"ok": True, "import": "imp-9"}

        with mock.patch("agent.netbox_export.fetch_bundle", side_effect=fetch or default_fetch):
            outcome = orders.netbox_export(self.ORDER, params, self.ctx([]), agent_uuid=AGENT,
                                           upload=upload or default_upload, progress=progress, environ=self.environ)
        return outcome, uploads

    def test_the_export_reads_uploads_and_reports_by_collection(self) -> None:
        steps: list[tuple] = []
        (outcome, result, notes), uploads = self.run_order(self.params(), progress=lambda *a: steps.append(a))
        self.assertEqual((outcome, notes), ("done", []))
        self.assertEqual(result, {"import": "imp-9", "summary": {"devices": 2, "sites": 1}})
        self.assertEqual(uploads[0][1], self.ORDER)
        self.assertEqual(steps[0], ("sites", 0, 17))
        self.assertIn(("devices", 8, 17), steps)
        self.assertEqual(steps[-1], ("upload", 17, 17))

    def test_a_token_sealed_for_another_order_does_not_open(self) -> None:
        params = self.params(sealed_token=sealing.seal_for(
            vectors()["public_key_pem"], {"secret": CANARIES["netbox"]}, agent_uuid=AGENT, subject_id="otro-encargo"))
        (outcome, _result, notes), uploads = self.run_order(params, fetch=AssertionError("ni se lee"))
        self.assertEqual((outcome, notes[0].code, uploads), ("failed", "sealed_unreadable", []))

    def test_a_url_other_than_the_sealed_one_is_refused(self) -> None:
        (outcome, _result, notes), _ = self.run_order(self.params(url="https://evil.test/"),
                                                     fetch=AssertionError("ni se lee"))
        self.assertEqual((outcome, notes[0].code), ("failed", "url_mismatch"))

    def test_an_export_error_never_repeats_the_token(self) -> None:
        from agent.netbox_export import ExportError

        def fetch(url: str, token: str, **kwargs: Any) -> dict:
            raise ExportError(f"NetBox dijo algo raro sobre {token}")

        (outcome, _result, notes), uploads = self.run_order(self.params(), fetch=fetch)
        self.assertEqual((outcome, notes[0].code, uploads), ("failed", "export_failed", []))
        self.assertNotIn(CANARIES["netbox"], json.dumps([n.as_json() for n in notes]))
        self.assertIn("***", notes[0].params["detail"])

    def test_a_crash_is_reported_by_type_only(self) -> None:
        def fetch(url: str, token: str, **kwargs: Any) -> dict:
            raise ValueError(token)

        (outcome, _result, notes), _ = self.run_order(self.params(), fetch=fetch)
        self.assertEqual((outcome, notes[0].code, notes[0].params), ("failed", "crashed", {"error": "ValueError"}))
        self.assertNotIn(CANARIES["netbox"], str(notes[0]))

    def test_an_upload_failure_is_a_coded_failure(self) -> None:
        def upload(bundle: dict, order_id: str) -> dict:
            raise PushError("El servidor respondió 413: demasiado", status=413)

        (outcome, result, notes), _ = self.run_order(self.params(), upload=upload)
        self.assertEqual((outcome, notes[0].code, notes[0].params["status"]), ("failed", "upload_failed", 413))
        self.assertEqual(result["summary"], {"devices": 2, "sites": 1})

    def test_missing_url_or_envelope(self) -> None:
        for params, code in (({**self.params(), "url": ""}, "bad_url"), ({**self.params(), "sealed_token": None},
                                                                          "sealed_unreadable")):
            with self.subTest(code=code):
                (outcome, _result, notes), _ = self.run_order(params, fetch=AssertionError("ni se lee"))
                self.assertEqual((outcome, notes[0].code), ("failed", code))


# --- El canal de control y el bucle ------------------------------------------------------


class ControlSealedOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="cenya-control-sealed-"))
        self.client = FakeClient()
        self.calls: list[tuple] = []
        self.release = threading.Event()

    def control(self, **hooks: Any) -> Control:
        base = Hooks(
            about=lambda: {}, schedule=lambda now: [], local_pause=lambda: None, run_task=lambda job: None,
            config_changed=lambda etag: None, probe=lambda ip: {}, excluded=lambda ip: False, **hooks,
        )
        return Control(self.client, Shared(), Outbox(self.dir / "outbox"), base, report=False)

    @staticmethod
    def wait(ctl: Control) -> None:
        for thread in list(ctl.probe_threads):
            thread.join(timeout=5)

    def test_each_order_reaches_its_hook_and_is_answered(self) -> None:
        def hook(name: str):  # noqa: ANN202
            def call(order_id: str, params: dict) -> tuple:
                self.calls.append((name, order_id, params))
                return "done", {"from": name}, []
            return call

        ctl = self.control(test_credential=hook("t"), reseal=hook("r"), netbox_export=hook("n"))
        ctl.handle_order({"id": "o1", "kind": "test_credential", "params": {"credential_id": "c", "ip": IP}})
        ctl.handle_order({"id": "o2", "kind": "reseal", "params": {}})
        ctl.handle_order({"id": "o3", "kind": "netbox_export", "params": {}})
        self.wait(ctl)
        self.assertEqual(sorted(c[0] for c in self.calls), ["n", "r", "t"])
        answers = dict(self.client.order_answers)
        self.assertEqual(answers["o2"], {"status": "done", "result": {"from": "r"}, "notes": []})

    def test_without_hooks_the_new_orders_are_unsupported(self) -> None:
        ctl = self.control()
        for number, kind in enumerate(("test_credential", "reseal", "netbox_export")):
            ctl.handle_order({"id": f"o{number}", "kind": kind, "params": {}})
        self.assertEqual([body["status"] for _id, body in self.client.order_answers], ["unsupported"] * 3)

    def test_a_crashing_hook_answers_failed_without_its_message(self) -> None:
        def crash(order_id: str, params: dict) -> tuple:
            raise RuntimeError(CANARIES["ssh"])

        ctl = self.control(reseal=crash)
        ctl.handle_order({"id": "o1", "kind": "reseal", "params": {}})
        self.wait(ctl)
        ((_id, body),) = self.client.order_answers
        self.assertEqual((body["status"], body["notes"][0]["code"]), ("failed", "crashed"))
        self.assertNotIn(CANARIES["ssh"], json.dumps(body))

    def test_a_credential_test_waits_for_a_probe_of_the_same_ip(self) -> None:
        probe_started = threading.Event()

        def slow_probe(ip: str) -> dict:
            probe_started.set()
            self.release.wait(5)
            self.calls.append(("probe-end",))
            return {}

        def test(order_id: str, params: dict) -> tuple:
            self.calls.append(("test",))
            return "done", {}, []

        ctl = self.control(test_credential=test)
        ctl.hooks.probe = slow_probe
        ctl.handle_order({"id": "p1", "kind": "probe", "params": {"ip": IP}})
        self.assertTrue(probe_started.wait(5))
        ctl.handle_order({"id": "t1", "kind": "test_credential", "params": {"credential_id": "c", "ip": IP}})
        time.sleep(0.2)
        self.assertEqual(self.calls, [])  # espera su turno
        self.release.set()
        self.wait(ctl)
        self.assertEqual(self.calls, [("probe-end",), ("test",)])

    def test_the_checkin_can_tell_the_agent_its_uuid(self) -> None:
        ctl = self.control()
        ctl.apply({"agent": AGENT.upper()})
        self.assertEqual(ctl.shared.agent_uuid, AGENT)
        ctl.apply({"agent": {"uuid": NEW_AGENT}})
        self.assertEqual(ctl.shared.agent_uuid, NEW_AGENT)
        ctl.apply({"agent": "no-es-uuid"})
        ctl.apply({})
        self.assertEqual(ctl.shared.agent_uuid, NEW_AGENT)


class EnrollmentUuidTests(StateTestCase):
    def test_the_uuid_is_kept_with_the_enrolment(self) -> None:
        store.save(store.Enrollment(url="https://x.test", token="t", name="A", uuid=AGENT), self.environ)
        self.assertEqual(store.load(self.environ).uuid, AGENT)

    def test_an_old_enrolment_has_no_uuid(self) -> None:
        (self.state / "enrollment.json").write_text(json.dumps({"url": "https://x.test", "token": "t"}))
        self.assertEqual(store.load(self.environ).uuid, "")

    def test_enrolling_keeps_the_uuid_the_server_gave(self) -> None:
        from agent import enroll

        answer = {"ok": True, "token": "cya_t", "name": "A", "uuid": AGENT, "protocol": 2}
        with mock.patch("agent.enroll.AgentClient") as client, \
             mock.patch("agent.enroll.connection.parse", return_value=mock.Mock(url="https://x.test", code="C")), \
             mock.patch("agent.enroll.check_transport"), mock.patch("agent.enroll.identity.ensure", return_value=""):
            client.return_value.enroll.return_value = answer
            saved = enroll.redeem("cenya://x/C", self.environ)
        self.assertEqual(saved.uuid, AGENT)
        self.assertEqual(store.load(self.environ).uuid, AGENT)

    def test_the_runtime_starts_with_the_enrolled_uuid_and_puts_it_in_every_ctx(self) -> None:
        store.save(store.Enrollment(url="https://x.test", token="t", uuid=AGENT), self.environ)
        runtime = Runtime(AgentClient("http://127.0.0.1:9", "t"), Config(url="http://127.0.0.1:9", token="t"),
                          environ=self.environ, report=False)
        self.assertEqual(runtime.shared.agent_uuid, AGENT)
        ctx = runtime.build_ctx(Job("inventory"), {"credentials": [sealed("ssh", "s1", CANARIES["ssh"])]})
        self.assertEqual([c.secret for c in creds.all_from(ctx)], [CANARIES["ssh"]])
        self.assertIsNot(runtime.build_ctx(Job("inventory"), {})[creds.CTX_KEY], ctx[creds.CTX_KEY])


class RuntimeOrderTests(StateTestCase):
    def runtime(self) -> Runtime:
        runtime = Runtime(AgentClient("http://127.0.0.1:9", "t"), Config(url="http://127.0.0.1:9", token="t"),
                          environ=self.environ, report=False)
        runtime.shared.agent_uuid = AGENT
        return runtime

    def test_the_netbox_export_shows_its_progress_in_the_checkin_activity(self) -> None:
        from agent import netbox_export

        runtime = self.runtime()
        seen: list[dict] = []

        def fetch(url: str, token: str, verify_tls: bool = True, progress: Any = None) -> dict:
            for path in list(netbox_export.ENDPOINTS.values())[:3]:
                progress(path)
                seen.append(runtime.shared.activity_snapshot() or {})
            body, _hash = runtime.control.body(datetime.now(timezone.utc))
            seen.append({"state": body["state"]})
            return {"sites": []}

        token = sealing.seal_for(vectors()["public_key_pem"], {"secret": CANARIES["netbox"]}, agent_uuid=AGENT,
                                 subject_id="o1")
        with mock.patch("agent.netbox_export.fetch_bundle", side_effect=fetch), \
             mock.patch.object(runtime.client, "upload_netbox_bundle", return_value={"ok": True, "import": "i"}), \
             mock.patch("agent.runtime.about.build", return_value={}):
            outcome, result, _notes = runtime._netbox_export("o1", {"url": "https://nb.test", "sealed_token": token})
        self.assertEqual((outcome, result["import"]), ("done", "i"))
        self.assertEqual([(a["task"], a["step"], a["done"]) for a in seen[:3]],
                         [("netbox_export", "sites", 0), ("netbox_export", "racks", 1),
                          ("netbox_export", "device_types", 2)])
        self.assertEqual(seen[3], {"state": "running"})
        self.assertIsNone(runtime.shared.activity_snapshot())

    def test_a_running_task_keeps_the_activity(self) -> None:
        runtime = self.runtime()
        runtime.shared.set_activity({"task": "inventory", "step": "ssh"})

        def fetch(url: str, token: str, verify_tls: bool = True, progress: Any = None) -> dict:
            progress("/api/dcim/sites/")
            return {}

        token = sealing.seal_for(vectors()["public_key_pem"], {"secret": "t"}, agent_uuid=AGENT, subject_id="o1")
        with mock.patch("agent.netbox_export.fetch_bundle", side_effect=fetch), \
             mock.patch.object(runtime.client, "upload_netbox_bundle", return_value={"ok": True, "import": "i"}):
            runtime._netbox_export("o1", {"url": "https://nb.test", "sealed_token": token})
        self.assertEqual(runtime.shared.activity_snapshot(), {"task": "inventory", "step": "ssh"})

    def test_a_rejected_agent_does_nothing(self) -> None:
        runtime = self.runtime()
        runtime.shared.refusal = "unauthorized"
        with mock.patch("agent.orders.test_credential", side_effect=AssertionError("nada")), \
             mock.patch("agent.orders.reseal", side_effect=AssertionError("nada")), \
             mock.patch("agent.orders.netbox_export", side_effect=AssertionError("nada")):
            for call in (runtime._test_credential, runtime._reseal, runtime._netbox_export):
                outcome, _result, notes = call("o", {})
                self.assertEqual((outcome, notes[0].code), ("failed", "agent_refused"))


# --- Lo que el agente escribe y envía: ni un secreto -----------------------------------------


@contextlib.contextmanager
def recording_server(config: dict):
    """Un servidor del protocolo 2 que guarda los bytes de todo lo que recibe."""
    received: list[tuple[str, bytes]] = []
    lock = threading.Lock()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
            with lock:
                received.append((self.path, raw + json.dumps(dict(self.headers)).encode()))
            if self.path == "/api/agent/v2/checkin/":
                body = json.loads(raw or b"{}")
                answer: dict[str, Any] = {"ok": True, "protocol": 2, "config_etag": "e1", "checkin_seconds": 30,
                                          "agent": AGENT}
                if body.get("config_etag") != "e1":
                    answer["config"] = config
            elif self.path == "/api/agent/v2/netbox-bundle/":
                answer = {"ok": True, "import": "imp-1"}
            else:
                answer = {"ok": True, "created": 0, "refreshed": 0}
            data = json.dumps(answer).encode()
            self.send_response(200)
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


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


class CanaryTests(StateTestCase):
    """Credenciales con secretos reconocibles, una tarea y los tres encargos: ningún secreto sale."""

    def test_no_secret_leaves_its_envelope(self) -> None:
        store.save(store.Enrollment(url="http://x", token="cya_token", name="A"), self.environ)  # sin uuid: lo trae el checkin
        config = {
            "subnets": [],
            "tasks": {name: {"every_seconds": 0} for name in ("presence", "inventory", "configs", "ups", "hypervisors")},
            "credentials": [
                sealed("ssh", "s1", CANARIES["ssh"]),
                sealed("snmp", "c1", CANARIES["community"], username=""),
                sealed("winrm", "w1", CANARIES["winrm"]),
                sealed("snmpv3", "v3", CANARIES["v3auth"], CANARIES["v3priv"]),
                sealed("vmware", "vc", CANARIES["vmware"], host="vcenter.local"),
                sealed("ssh", "broken", "x", sealed={"v": 1}),
            ],
        }
        used: list[str] = []

        class Uses:
            def __init__(self, name: str, kinds: tuple[str, ...]) -> None:
                self.name, self.kinds = name, kinds

            def collect(self, ctx: dict) -> list:
                for credential in creds.all_from(ctx):
                    if credential.kind not in self.kinds:
                        continue
                    used.extend(s for s in (credential.secret, credential.priv_secret) if s)
                    tasking.settle(ctx, IP, MAC, self.name, credential, attempted=True, full=True)
                    # Un colector descuidado que mete la credencial en una nota: su repr no lleva nada.
                    ctx["errors"].append(f"{self.name}: probé {credential!r}")
                return []

        collectors = [Uses("snmp", ("snmp", "snmpv3")), Uses("ssh", ("ssh",)), Uses("winrm", ("winrm",)),
                      Uses("hypervisors", ("vmware",))]
        capture = _Capture()
        stdout, stderr = io.StringIO(), io.StringIO()
        logs.setup(self.environ)
        logging.getLogger(logs.LOGGER_NAME).addHandler(capture)
        self.addCleanup(logs.close)

        from agent import netbox_export

        def fetch(url: str, token: str, verify_tls: bool = True, progress: Any = None) -> dict:
            used.append(token)
            for path in netbox_export.ENDPOINTS.values():
                progress(path)
            return {"devices": [{"name": "sw1"}]}

        with recording_server(config) as (url, received), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
             mock.patch("agent.tasks.all_collectors", return_value=collectors), \
             mock.patch("agent.runtime.about.build", return_value={"hostname": "PRUEBA", "networks": []}), \
             mock.patch.object(probe, "_port_open", return_value=True), \
             mock.patch.object(probe.ssh, "run", side_effect=lambda **kw: used.append(kw["secret"]) or
                               ssh.Answer(connected=False, error=f"rechazada {kw['secret']}")), \
             mock.patch.object(probe.winrm, "query", side_effect=lambda **kw: used.append(kw["secret"]) or
                               mock.Mock(connected=False, error=f"401 {kw['secret']}")),              mock.patch.object(probe.snmp, "AVAILABLE", True),              mock.patch.object(probe.snmp, "query_hosts", return_value={}),              mock.patch("agent.netbox_export.fetch_bundle", side_effect=fetch),              mock.patch("agent.approvals.ResealApprovals.trusted", return_value=True):
            runtime = Runtime(AgentClient(url, "cya_token"), Config(url=url, token="cya_token"),
                              environ=self.environ, report=True)
            self.assertEqual(runtime.negotiate(), "v2")
            self.assertEqual(runtime.shared.agent_uuid, AGENT)
            runtime._hosts = [{"ip": IP, "mac": MAC}]
            run = runtime.run_job(Job("inventory"))
            hypervisors_run = runtime.run_job(Job("hypervisors"))
            nb_token = sealing.seal_for(vectors()["public_key_pem"], {"secret": CANARIES["netbox"]},
                                        agent_uuid=AGENT, subject_id="ord-nb")
            for order in (
                {"id": "ord-test", "kind": "test_credential", "params": {"credential_id": "s1", "ip": IP}},
                {"id": "ord-reseal", "kind": "reseal", "params": {"agent": NEW_AGENT, "public_key": pem(key("other")),
                                                                  "credential_ids": ["s1", "c1", "w1", "v3", "vc"]}},
                {"id": "ord-nb", "kind": "netbox_export",
                 "params": {"url": "https://netbox.example.test", "sealed_token": nb_token}},
                {"id": "ord-probe", "kind": "probe", "params": {"ip": IP}},
            ):
                runtime.control.handle_order(order)
            for thread in list(runtime.control.probe_threads):
                thread.join(timeout=10)
            runtime.control.checkin_once()
            logs.close()

        # Los secretos se usaron de verdad (si no, la prueba no probaría nada).
        for name in ("ssh", "community", "winrm", "v3auth", "v3priv", "vmware", "netbox"):
            self.assertIn(CANARIES[name], used, name)
        self.assertEqual(run["stats"]["credentials_ok"], {"s1": 1, "c1": 1, "w1": 1, "v3": 1})
        self.assertEqual(hypervisors_run["stats"]["credentials_ok"], {"vc": 1})
        self.assertIn("sealed_unreadable", [n["code"] for n in run["notes"]])
        paths = [path for path, _ in received]
        self.assertIn("/api/agent/v2/netbox-bundle/", paths)
        reseal_body = next(raw for path, raw in received if path.endswith("/ord-reseal/result/"))
        self.assertIn(b'"envelopes"', reseal_body)

        emitted: list[tuple[str, bytes]] = [(f"http {path}", raw) for path, raw in received]
        for file in self.state.rglob("*"):
            if file.is_file() and file.name != "identity.key":
                emitted.append((str(file), file.read_bytes()))
        status_file = status.path()
        if status_file is not None and status_file.exists():
            emitted.append(("status.json", status_file.read_bytes()))
        emitted.append(("log records", "\n".join(capture.lines).encode()))
        emitted.append(("stdout/stderr", (stdout.getvalue() + stderr.getvalue()).encode()))
        self.assertTrue(any("agent.log" in name for name, _ in emitted))
        for name, data in emitted:
            for canary in CANARIES.values():
                self.assertNotIn(canary.encode(), data, f"{canary} en {name}")


if __name__ == "__main__":
    unittest.main()
