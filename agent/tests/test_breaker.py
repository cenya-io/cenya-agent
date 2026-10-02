"""The credential circuit breaker (spec 2.3): a wrong password cannot lock a domain account.

The per-host memory is not enough: ONE wrong domain credential tried against
fifty Windows hosts is fifty failed logons in a single inventory. These tests
count every authentication attempt a fake login receives:

* an *unproven* credential (never worked) gets at most 3 failed
  authentications in total, across hosts and threads, then it is suspended;
* "could not connect" costs nothing;
* a success proves it (and lifts a suspension); a new configuration (etag)
  or 24 h lift it too;
* a *proven* credential that fails on 3 hosts where it was the remembered one
  is suspended too: its password has probably changed;
* the suspension is said once per run, by name, never by secret.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import tempfile
import threading
import time
import unittest
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from agent import credentials as creds
from agent import hypervisor, memory, ssh, winrm
from agent.collectors import tasking
from agent.collectors.hypervisors import HypervisorCollector
from agent.collectors.ssh import SshCollector
from agent.collectors.winrm import WinrmCollector
from agent.memory import AUTH_FAILED, OK, UNREACHABLE, Memory

T0 = datetime(2026, 10, 2, 9, 0, tzinfo=timezone.utc)
HOSTS = [{"ip": f"10.1.0.{n}", "mac": f"02:00:00:00:00:{n:02x}"} for n in range(1, 51)]


def cred(name: str, kind: str = "winrm") -> dict:
    return {"id": f"id-{name}", "kind": kind, "username": name, "secret": f"clave-de-{name}", "label": f"Cuenta {name}"}


class MemoryBreakerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mem = Memory.load(None)

    def fail(self, ident: str = "x", host: str = "h", *, remembered: bool = False, at: datetime = T0) -> bool | None:
        attempt = self.mem.reserve(ident, at, host_key=host, remembered=remembered, wait=0)
        if attempt is None:
            return None
        return self.mem.finish(attempt, AUTH_FAILED, at)

    def test_an_unproven_credential_gets_three_failures_in_total(self) -> None:
        self.assertEqual([self.fail(host=f"h{n}") for n in range(5)], [False, False, True, None, None])
        self.assertTrue(self.mem.suspended("x", T0))
        self.assertEqual(self.mem.failures("x"), 3)

    def test_could_not_connect_costs_nothing(self) -> None:
        for _ in range(10):
            attempt = self.mem.reserve("x", T0, wait=0)
            self.memory_finish(attempt, UNREACHABLE)
        self.assertEqual([self.fail(host=f"h{n}") for n in range(3)], [False, False, True])

    def memory_finish(self, attempt: memory.Attempt | None, outcome: str) -> None:
        self.assertIsNotNone(attempt)
        self.mem.finish(attempt, outcome, T0)

    def test_a_success_proves_it_and_lifts_the_suspension(self) -> None:
        for n in range(3):
            self.fail(host=f"h{n}")
        self.assertIsNone(self.mem.reserve("x", T0, wait=0))
        # Una persona lo pide («Analizar»): una vez, aunque esté suspendida.
        explicit = self.mem.reserve("x", T0, explicit=True, wait=0)
        self.memory_finish(explicit, OK)

        self.assertFalse(self.mem.suspended("x", T0))
        # Probada: ya no la limita el cupo de las que nunca entraron.
        self.assertEqual([self.fail(host=f"otro{n}") for n in range(10)], [False] * 10)

    def test_a_new_configuration_lifts_it(self) -> None:
        for n in range(3):
            self.fail(host=f"h{n}")
        self.mem.credentials_changed("etag-nuevo")
        self.assertFalse(self.mem.suspended("x", T0))
        self.assertEqual(self.fail(), False)

    def test_twenty_four_hours_lift_it(self) -> None:
        for n in range(3):
            self.fail(host=f"h{n}")
        later = T0 + memory.SUSPENSION
        self.assertFalse(self.mem.suspended("x", later))
        self.assertIsNotNone(self.mem.reserve("x", later, wait=0))

    def test_a_proven_credential_failing_where_it_used_to_work_is_suspended(self) -> None:
        self.memory_finish(self.mem.reserve("x", T0, wait=0), OK)
        later = T0 + timedelta(hours=6)
        # Contra equipos donde nunca entró (un Linux suelto), no cuenta.
        self.assertEqual([self.fail(host=f"suelto{n}", at=later) for n in range(5)], [False] * 5)
        # Contra los suyos, tres equipos distintos y se suspende.
        results = [self.fail(host=f"dc{n % 3}", remembered=True, at=later) for n in range(4)]
        self.assertEqual(results, [False, False, True, None])
        self.assertEqual(self.mem.failures("x"), 3)

    def test_it_survives_a_restart_and_a_broken_record_is_no_record(self) -> None:
        path = Path(tempfile.mkdtemp(prefix="cenya-breaker-")) / "memory.json"
        mem = Memory.load(path)
        for n in range(3):
            attempt = mem.reserve("x", T0, host_key=f"h{n}", wait=0)
            mem.finish(attempt, AUTH_FAILED, T0)
        mem.save()

        self.assertTrue(Memory.load(path).suspended("x", T0))
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("clave", text)
        path.write_text(text.replace('"failures": 3', '"failures": "muchos"'), encoding="utf-8")
        self.assertEqual(Memory.load(path).failures("x"), 0)
        path.write_text('{"credentials": {"x": "basura"}, "hosts": []}', encoding="utf-8")
        self.assertFalse(Memory.load(path).suspended("x", T0))

    def test_ten_threads_cannot_exceed_three_failures(self) -> None:
        tried = Counter()
        lock = threading.Lock()

        def worker(n: int) -> None:
            attempt = self.mem.reserve("x", T0, host_key=f"h{n}", wait=5)
            if attempt is None:
                return
            with lock:
                tried["x"] += 1
            time.sleep(0.02)
            self.mem.finish(attempt, AUTH_FAILED, T0)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual(tried["x"], 3)


class FakeWinrm:
    """`winrm.query` with a count of every authentication attempt it receives."""

    def __init__(self, good: dict[str, set[str]] | None = None, unreachable: set[str] = frozenset()) -> None:
        self.good = good or {}
        self.unreachable = set(unreachable)
        self.auth_attempts: Counter = Counter()
        self.connect_failures = 0
        self.lock = threading.Lock()

    def __call__(self, *, host: str, username: str, secret: str, port: int = 0, ca_file: str = "") -> winrm.Answer:
        time.sleep(0.005)
        with self.lock:
            if host in self.unreachable:
                self.connect_failures += 1
                return winrm.Answer(False, None, "Failed to establish a new connection", unreachable=True)
            self.auth_attempts[username] += 1
        if host in self.good.get(username, set()):
            return winrm.Answer(True, {"hostname": host})
        return winrm.Answer(False, None, "InvalidCredentialsError: the specified credentials were rejected")


class CollectorBreakerTests(unittest.TestCase):
    def collect(self, fake: FakeWinrm, credentials: list[dict], mem: Memory | None = None) -> dict:
        ctx = {
            "config": {"credentials": credentials},
            "task": "inventory",
            "hosts": [dict(h) for h in HOSTS],
            "memory": mem or Memory.load(None),
            "workers": {"login": 10, "ping": 10, "snmp": 10},
            "errors": [],
        }
        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", True), \
             mock.patch("agent.collectors.winrm.net.hosts_listening", lambda ips, port, **kw: list(ips)), \
             mock.patch("agent.collectors.winrm.winrm.query", fake):
            ctx["findings"] = WinrmCollector().collect(ctx)
        return ctx

    def suspended_notes(self, ctx: dict) -> list:
        return [note for note in ctx["errors"] if getattr(note, "code", "") == "credential_suspended"]

    def test_three_wrong_credentials_against_fifty_hosts_with_ten_workers(self) -> None:
        fake = FakeWinrm()

        ctx = self.collect(fake, [cred("ana"), cred("bea"), cred("cris")])

        self.assertEqual(dict(fake.auth_attempts), {"ana": 3, "bea": 3, "cris": 3})
        notes = self.suspended_notes(ctx)
        self.assertEqual(sorted(note.params["name"] for note in notes), ["Cuenta ana", "Cuenta bea", "Cuenta cris"])
        self.assertTrue(all(note.params["failures"] == 3 for note in notes))
        self.assertTrue(all(note.collector == "winrm" for note in notes))
        for note in notes:
            self.assertNotIn("clave-de", str(note))

    def test_hosts_that_do_not_answer_do_not_spend_the_budget(self) -> None:
        # 48 apagados y 2 que dicen que no: si «no contesta» gastara cupo, la
        # credencial quedaría suspendida y casi todos se saltarían.
        fake = FakeWinrm(unreachable={h["ip"] for h in HOSTS[:48]})

        ctx = self.collect(fake, [cred("ana")])

        self.assertEqual(fake.connect_failures, 48)
        self.assertEqual(fake.auth_attempts["ana"], 2)
        self.assertEqual(self.suspended_notes(ctx), [])

    def test_a_good_credential_is_not_starved_by_the_breaker(self) -> None:
        """Mientras las tres primeras están en vuelo, las demás esperan su
        resultado en vez de saltarse el equipo: con una credencial buena, todos
        los equipos se inventarían."""
        fake = FakeWinrm(good={"ana": {h["ip"] for h in HOSTS}})

        ctx = self.collect(fake, [cred("ana")])

        self.assertEqual(len(ctx["findings"]), 50)
        self.assertEqual(self.suspended_notes(ctx), [])

    def test_the_suspension_holds_in_the_next_run_and_is_said_once_per_run(self) -> None:
        mem = Memory.load(None)
        self.collect(FakeWinrm(), [cred("ana")], mem)
        fake = FakeWinrm()

        ctx = self.collect(fake, [cred("ana")], mem)

        self.assertEqual(fake.auth_attempts["ana"], 0)
        self.assertEqual(len(self.suspended_notes(ctx)), 1)

    def test_a_changed_etag_gives_it_another_chance(self) -> None:
        mem = Memory.load(None)
        self.collect(FakeWinrm(), [cred("ana")], mem)
        mem.credentials_changed("otra-configuracion")
        fake = FakeWinrm(good={"ana": {h["ip"] for h in HOSTS}})

        ctx = self.collect(fake, [cred("ana")], mem)

        self.assertEqual(len(ctx["findings"]), 50)

    def test_a_proven_domain_credential_whose_password_changed(self) -> None:
        mem = Memory.load(None)
        good = FakeWinrm(good={"ana": {h["ip"] for h in HOSTS}})
        self.collect(good, [cred("ana")], mem)  # entra en todos: queda recordada en cada uno
        changed = FakeWinrm()  # seis horas después, le han cambiado la clave en el dominio

        with mock.patch("agent.collectors.tasking.now", return_value=datetime.now(timezone.utc) + timedelta(hours=6)):
            ctx = self.collect(changed, [cred("ana")], mem)

        self.assertEqual(changed.auth_attempts["ana"], 3)
        self.assertEqual([n.params["failures"] for n in self.suspended_notes(ctx)], [3])

    def test_a_proven_credential_is_not_limited_where_it_never_worked(self) -> None:
        """Una credencial de dominio que falla contra los equipos que no son
        del dominio no bloquea nada: no se suspende."""
        mem = Memory.load(None)
        domain = {h["ip"] for h in HOSTS[:10]}
        self.collect(FakeWinrm(good={"ana": domain}), [cred("ana")], mem)
        fake = FakeWinrm(good={"ana": domain})

        ctx = self.collect(fake, [cred("ana")], mem)

        self.assertEqual(self.suspended_notes(ctx), [])
        self.assertEqual(len(ctx["findings"]), 10)


class SshBreakerTests(unittest.TestCase):
    def test_a_wrong_ssh_credential_is_tried_three_times_in_total(self) -> None:
        attempts = Counter()
        lock = threading.Lock()

        def fake_run(*, host: str, username: str, secret: str = "", port: int = 0, key_file: str = "", command: str) -> ssh.Answer:
            with lock:
                attempts[username] += 1
            return ssh.Answer(False, error=f"{username}@{host}: Permission denied (password).")

        ctx = {
            "config": {"credentials": [cred("root", "ssh")]},
            "task": "inventory",
            "hosts": [dict(h) for h in HOSTS],
            "memory": Memory.load(None),
            "workers": {"login": 10, "ping": 10},
            "errors": [],
        }
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", lambda ips, port, **kw: list(ips)), \
             mock.patch("agent.collectors.ssh.ssh.run", fake_run):
            SshCollector().collect(ctx)

        self.assertEqual(attempts["root"], 3)
        self.assertEqual([n.code for n in ctx["errors"] if n.code == "credential_suspended"], ["credential_suspended"])

    def test_what_ssh_says_decides_whether_it_counts(self) -> None:
        cases = {
            "ssh: connect to host 10.0.0.5 port 22: Connection refused": "unreachable",
            "ssh: connect to host 10.0.0.5 port 22: Connection timed out": "unreachable",
            "ssh: Could not resolve hostname x: Name or service not known": "unreachable",
            "Host key verification failed.": "unreachable",
            "root@10.0.0.5: Permission denied (password).": "auth_failed",
            "Connection closed by 10.0.0.5 port 22": "auth_failed",  # ante la duda, cuenta
            "": "auth_failed",
        }
        for stderr, expected in cases.items():
            with self.subTest(stderr=stderr):
                answer = ssh.Answer(False, error=stderr, unreachable=ssh.before_auth(stderr))
                self.assertEqual(ssh.outcome(answer), expected)


class WinrmClassificationTests(unittest.TestCase):
    def test_what_pywinrm_raises_decides_whether_it_counts(self) -> None:
        class InvalidCredentialsError(Exception):
            pass

        class ConnectTimeout(Exception):
            pass

        cases = [
            (InvalidCredentialsError("the specified credentials were rejected by the server"), False),
            (Exception("HTTPConnectionPool: Max retries exceeded (Failed to establish a new connection: refused)"), True),
            (ConnectTimeout("timed out"), True),
            (Exception("SSLError: certificate verify failed"), True),
            (Exception("WinRMTransportError 500 algo raro"), False),  # ante la duda, cuenta
        ]
        for exc, before in cases:
            with self.subTest(exc=str(exc)):
                self.assertEqual(winrm.before_auth(exc), before)

    def test_a_rejected_password_is_not_repeated_by_basic(self) -> None:
        class InvalidCredentialsError(Exception):
            pass

        sessions = []

        class Session:
            def __init__(self, *args, **kwargs) -> None:  # noqa: ANN002, ANN003
                sessions.append(kwargs["transport"])

            def run_ps(self, script: str):  # noqa: ANN201
                raise InvalidCredentialsError("the specified credentials were rejected by the server")

        fake = mock.Mock(Session=Session)
        with mock.patch("agent.winrm.AVAILABLE", True), mock.patch("agent.winrm.pywinrm", fake, create=True):
            answer = winrm.query(host="10.0.0.5", username="ACME\\ana", secret="mala")

        self.assertEqual(sessions, ["ntlm"])
        self.assertEqual(winrm.outcome(answer), "auth_failed")


class HypervisorBreakerTests(unittest.TestCase):
    def test_a_vcenter_that_keeps_refusing_is_suspended_after_three_runs(self) -> None:
        logins = Counter()

        class Refusing:
            def __init__(self, host: str, username: str, secret: str, **kwargs) -> None:  # noqa: ANN003
                self.username = username

            def login(self) -> None:
                logins[self.username] += 1
                raise hypervisor.HypervisorError("401 en /api/session", status=401)

        mem = Memory.load(None)
        notes = []
        for _ in range(5):
            ctx = {"config": {"credentials": [cred("vc", "vmware") | {"host": "vc.acme.local"}]},
                   "memory": mem, "errors": []}
            with mock.patch.dict("agent.collectors.hypervisors.CLIENTS", {"vmware": Refusing}):
                HypervisorCollector().collect(ctx)
            notes.extend(n for n in ctx["errors"] if getattr(n, "code", "") == "credential_suspended")

        self.assertEqual(logins["vc"], 3)
        self.assertEqual(len(notes), 3)  # una por ejecución mientras dura: la que suspende y las dos siguientes

    def test_an_unreachable_vcenter_is_not_a_failed_login(self) -> None:
        self.assertEqual(hypervisor.login_outcome(hypervisor.HypervisorError("refused", unreachable=True)), "unreachable")
        self.assertEqual(hypervisor.login_outcome(hypervisor.HypervisorError("401 en /api/session", status=401)), "auth_failed")
        self.assertEqual(hypervisor.login_outcome(hypervisor.HypervisorError("no es Hyper-V", logged_in=True)), "ok")
        self.assertEqual(hypervisor.login_outcome(None), "ok")


class ProbeBreakerTests(unittest.TestCase):
    def test_a_person_may_try_a_suspended_credential_once_and_a_success_lifts_it(self) -> None:
        from agent import probe

        mem = Memory.load(None)
        for n in range(3):
            attempt = mem.reserve("id-root", T0, host_key=f"h{n}", wait=0)
            mem.finish(attempt, AUTH_FAILED, T0)
        self.assertTrue(mem.suspended("id-root", T0))
        tried = []

        def fake_run(**kwargs) -> ssh.Answer:  # noqa: ANN003
            tried.append(kwargs["username"])
            return ssh.Answer(True, output="")

        ctx = {"config": {"credentials": [cred("root", "ssh")]}, "memory": mem, "errors": []}
        with mock.patch.object(probe, "_port_open", return_value=True), mock.patch.object(probe.ssh, "run", fake_run):
            line = probe._ssh_line("10.0.0.5", ctx)

        self.assertEqual(tried, ["root"])
        self.assertEqual(line.code, "logged_in")
        self.assertFalse(mem.suspended("id-root", datetime.now(timezone.utc)))


class LoginsWithoutMemoryTests(unittest.TestCase):
    def test_without_memory_it_just_tries(self) -> None:
        logins = tasking.Logins({}, "ssh", "ssh", "10.0.0.5")
        credential = creds.Credential(kind="ssh", username="u", secret="s")

        self.assertEqual(logins.run(credential, lambda: "hecho", lambda result: "auth_failed"), "hecho")
        self.assertFalse(logins.skipped)


if __name__ == "__main__":
    unittest.main()
