"""The agent updates itself (`agent.update`): decisions, downloads, and the security invariants.

Everything runs against throwaway HTTP servers on 127.0.0.1, in temporary
folders, with a TEST Ed25519 key generated here. Nothing is ever executed: the
launcher is a list that records what would have been run.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import base64
import contextlib
import hashlib
import http.server
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from agent import release, store, update
from agent.update import Offer, Updater

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover
    Ed25519PrivateKey = None  # type: ignore[assignment,misc]

AGENT_DIR = Path(update.__file__).resolve().parent
NEEDS_CRYPTO = unittest.skipIf(Ed25519PrivateKey is None, "cryptography no está instalada")


# --- Un servidor de mentira ------------------------------------------------------------


class Site:
    """Lo que sirve un servidor de prueba: ruta -> (código, cabeceras, cuerpo), y lo que le pidieron."""

    def __init__(self) -> None:
        self.routes: dict[str, tuple[int, dict[str, str], bytes]] = {}
        self.seen: list[tuple[str, dict[str, str]]] = []
        self.lock = threading.Lock()

    def add(self, path: str, body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> None:
        self.routes[path] = (status, headers or {}, body)

    def paths(self) -> list[str]:
        with self.lock:
            return [path for path, _headers in self.seen]


@contextlib.contextmanager
def serving(site: Site):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            with site.lock:
                site.seen.append((self.path, dict(self.headers)))
            status, headers, body = site.routes.get(self.path, (404, {}, b"no"))
            self.send_response(status)
            headers = {"Content-Length": str(len(body)), **headers}
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def public_line(key) -> str:  # noqa: ANN001
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def entry(url: str, content: bytes) -> dict:
    return {"url": url, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}


class Clock:
    def __init__(self) -> None:
        self.now = 1_000_000.0

    def __call__(self) -> float:
        return self.now


# --- Decisiones puras ----------------------------------------------------------------------


class VersionTests(unittest.TestCase):
    def test_only_strictly_newer_versions_are_newer(self) -> None:
        self.assertTrue(update.is_newer("0.11.1", "0.11.0"))
        self.assertTrue(update.is_newer("0.11.0.1", "0.11.0"))
        self.assertTrue(update.is_newer("0.12.0", "0.11.9"))
        self.assertTrue(update.is_newer("0.11.10", "0.11.9"))
        self.assertFalse(update.is_newer("0.11.0", "0.11.0"))
        self.assertFalse(update.is_newer("0.11", "0.11.0"))
        self.assertFalse(update.is_newer("0.10.9", "0.11.0"))

    def test_anything_that_is_not_a_version_is_never_newer(self) -> None:
        for bad in ("", "1", "0.11.1-beta", "../0.12.0", "0.11.1\n", None, 12, "1.2.3.4.5"):
            with self.subTest(bad=bad):
                self.assertFalse(update.is_newer(bad, "0.0.1"))

    def test_the_offer_is_read_strictly(self) -> None:
        self.assertEqual(update.parse_offer({"version": "0.11.1"}), Offer("0.11.1"))
        self.assertEqual(update.parse_offer({"version": "0.11.1", "explicit": True}), Offer("0.11.1", True))
        self.assertEqual(update.parse_offer({"version": "0.11.1", "explicit": "yes"}), Offer("0.11.1", False))
        for value in (None, {}, {"version": "latest"}, {"version": "../x"}, "0.11.1", []):
            with self.subTest(value=value):
                self.assertIsNone(update.parse_offer(value))


class DecideTests(unittest.TestCase):
    def decide(self, offer: Offer | None, **overrides) -> update.Decision:  # noqa: ANN003
        arguments = dict(
            current="0.11.0", auto_update=True, failed=set(), retry_after={}, now=100.0, in_progress=False,
            platform="windows",
        )
        arguments.update(overrides)
        return update.decide(offer, **arguments)

    def test_a_newer_version_with_auto_update_goes(self) -> None:
        self.assertTrue(self.decide(Offer("0.11.1")).go)

    def test_a_downgrade_or_the_same_version_is_refused(self) -> None:
        for version in ("0.11.0", "0.10.9", "0.9.99"):
            with self.subTest(version=version):
                decision = self.decide(Offer(version, explicit=True))
                self.assertFalse(decision.go)
                self.assertEqual(decision.reason, update.NOT_NEWER)

    def test_a_version_that_was_rolled_back_is_never_tried_again_even_if_asked_explicitly(self) -> None:
        decision = self.decide(Offer("0.11.1", explicit=True), failed={"0.11.1"})
        self.assertEqual(decision, update.Decision(False, "failed_before"))

    def test_auto_update_off_waits_for_an_explicit_order(self) -> None:
        self.assertEqual(self.decide(Offer("0.11.1"), auto_update=False).reason, "auto_update_off")
        self.assertTrue(self.decide(Offer("0.11.1", explicit=True), auto_update=False).go)

    def test_after_a_passing_failure_it_waits_unless_explicit(self) -> None:
        retry = {"0.11.1": 200.0}
        self.assertEqual(self.decide(Offer("0.11.1"), retry_after=retry).reason, "waiting_retry")
        self.assertTrue(self.decide(Offer("0.11.1"), retry_after=retry, now=201.0).go)
        self.assertTrue(self.decide(Offer("0.11.1", explicit=True), retry_after=retry).go)

    def test_nothing_starts_while_an_update_is_in_progress_or_without_a_platform(self) -> None:
        self.assertEqual(self.decide(Offer("0.11.1"), in_progress=True).reason, "in_progress")
        self.assertEqual(self.decide(Offer("0.11.1"), platform=None).reason, update.UNSUPPORTED)
        self.assertEqual(self.decide(None).reason, "no_offer")

    def test_the_manifest_must_be_exactly_the_requested_newer_version(self) -> None:
        update.check_manifest({"version": "0.11.1"}, requested="0.11.1", current="0.11.0")
        with self.assertRaises(release.ReleaseError) as caught:
            update.check_manifest({"version": "0.11.2"}, requested="0.11.1", current="0.11.0")
        self.assertEqual(caught.exception.code, update.WRONG_VERSION)
        with self.assertRaises(release.ReleaseError) as caught:
            update.check_manifest({"version": "0.10.0"}, requested="0.10.0", current="0.11.0")
        self.assertEqual(caught.exception.code, update.NOT_NEWER)


class FileNameTests(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = Path(tempfile.mkdtemp(prefix="cenya-names-")) / "updates"
        self.folder.mkdir()

    def test_local_names_are_built_from_the_version_never_from_a_url(self) -> None:
        self.assertEqual(update.download_name("0.11.1", "windows"), "cenya-agent-0.11.1.exe")
        self.assertEqual(update.download_name("0.11.1", "linux"), "cenya-agent-0.11.1.tar.gz")
        self.assertEqual(update.download_name("0.11.1", "install.sh"), "install-0.11.1.sh")

    def test_no_name_can_escape_the_downloads_folder(self) -> None:
        for version in ("../../0.11.1", "0.11.1/..", "..\\0.11.1", "0.11.1\0"):
            with self.subTest(version=version), self.assertRaises(release.ReleaseError):
                update.download_name(version, "windows")
        for name in ("..", ".", "../x.exe", "..\\x.exe", "a/b", "C:x", ""):
            with self.subTest(name=name), self.assertRaises(release.ReleaseError):
                update.inside(self.folder, name)
        self.assertEqual(update.inside(self.folder, "cenya-agent-0.11.1.exe").parent, self.folder)

    def test_the_installer_command_line_is_the_contracts(self) -> None:
        args = update.installer_arguments(Path("C:/x/cenya-agent-0.11.1.exe"), log=Path("C:/x/setup.log"), watchdog=90)
        self.assertEqual(args[1:5], ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/UPDATE"])
        self.assertIn("/WATCHDOGSECONDS=90", args)
        self.assertNotIn("/WATCHDOGSECONDS=90", update.installer_arguments(Path("x.exe"), log=Path("l"), watchdog=None))

    def test_the_watchdog_override_is_bounded(self) -> None:
        self.assertIsNone(update.watchdog_seconds({}))
        self.assertEqual(update.watchdog_seconds({"CENYA_UPDATE_WATCHDOG_SECONDS": "5"}), update.MIN_WATCHDOG_SECONDS)
        self.assertEqual(update.watchdog_seconds({"CENYA_UPDATE_WATCHDOG_SECONDS": "90"}), 90)
        self.assertIsNone(update.watchdog_seconds({"CENYA_UPDATE_WATCHDOG_SECONDS": "x"}))

    def test_only_an_allowed_url_replaces_the_releases_location(self) -> None:
        self.assertEqual(update.releases_url({}), update.RELEASES_URL)
        self.assertEqual(update.releases_url({"CENYA_RELEASES_URL": "http://127.0.0.1:9/r/"}), "http://127.0.0.1:9/r")
        self.assertEqual(update.releases_url({"CENYA_RELEASES_URL": "http://evil.example/r"}), update.RELEASES_URL)


class StartupStateTests(unittest.TestCase):
    def test_the_new_version_starts_as_installing_until_its_first_checkin(self) -> None:
        state, mark = update.startup_state(current="0.11.1", pending={"from": "0.11.0", "to": "0.11.1"}, failed=set())
        self.assertEqual(state, update.state("installing", "0.11.1"))
        self.assertIsNone(mark)

    def test_the_restored_version_reports_update_failed(self) -> None:
        state, mark = update.startup_state(current="0.11.0", pending={"from": "0.11.0", "to": "0.11.1"}, failed={"0.11.1"})
        self.assertEqual(state, update.state("failed", "0.11.1", update.UPDATE_FAILED))
        self.assertIsNone(mark)

    def test_an_installer_that_never_replaced_anything_is_written_down_as_failed(self) -> None:
        state, mark = update.startup_state(current="0.11.0", pending={"from": "0.11.0", "to": "0.11.1"}, failed=set())
        self.assertEqual(state, update.state("failed", "0.11.1", update.INSTALL_FAILED))
        self.assertEqual(mark, "0.11.1")

    def test_without_anything_pending_it_is_idle_or_remembers_the_last_failure(self) -> None:
        self.assertEqual(update.startup_state(current="0.11.0", pending=None, failed=set())[0], update.state("idle"))
        state, _ = update.startup_state(current="0.11.0", pending=None, failed={"0.11.1", "0.11.2"})
        self.assertEqual(state, update.state("failed", "0.11.2", update.UPDATE_FAILED))


# --- El actualizador de punta a punta --------------------------------------------------------


@NEEDS_CRYPTO
class UpdaterTestCase(unittest.TestCase):
    current = "0.11.0"
    target = "0.11.1"

    def setUp(self) -> None:
        self.state_dir = Path(tempfile.mkdtemp(prefix="cenya-update-"))
        self.key = Ed25519PrivateKey.generate()
        self.keys = [public_line(self.key)]
        self.launched: list[list[str]] = []
        self.said: list[str] = []
        self.clock = Clock()
        self.github = Site()
        self.server = Site()
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        self.github_url = stack.enter_context(serving(self.github))
        self.server_url = stack.enter_context(serving(self.server))
        self.installer = b"MZ" + os.urandom(64 * 1024)

    def updater(self, *, platform: str = "windows", keys: list[str] | None = None, client: object = None,
                busy=lambda: False, environ: dict | None = None) -> Updater:  # noqa: ANN001
        env = {"CENYA_RELEASES_URL": f"{self.github_url}/releases", **(environ or {})}
        return Updater(
            self.state_dir,
            client=client,
            keys=self.keys if keys is None else keys,
            current=self.current,
            platform=platform,
            environ=env,
            launcher=self.launched.append,
            clock=self.clock,
            busy=busy,
            say=self.said.append,
        )

    def publish(self, version: str | None = None, *, files: dict[str, bytes] | None = None, signer=None,
                site: Site | None = None) -> bytes:  # noqa: ANN001
        """Pone en el «GitHub» de prueba el manifiesto firmado, su firma y los ficheros."""
        version = version or self.target
        site = site or self.github
        files = files if files is not None else {"windows": self.installer}
        names = {"windows": f"Cenya-Agent-Setup-{version}.exe", "linux": f"cenya-agent-{version}.tar.gz",
                 "install.sh": "install.sh"}
        base = f"/releases/agent-v{version}"
        entries = {}
        for kind, content in files.items():
            path = f"{base}/{names[kind]}"
            site.add(path, content)
            entries[kind] = entry(f"{self.github_url}{path}", content)
        manifest = json.dumps({"version": version, "released": "2026-10-02T18:00:00Z", "files": entries}).encode()
        signature = base64.b64encode((signer or self.key).sign(manifest))
        site.add(f"{base}/latest.json", manifest)
        site.add(f"{base}/latest.json.sig", signature)
        return manifest

    def updates(self) -> Path:
        return self.state_dir / "updates"

    def downloaded(self) -> list[str]:
        if not self.updates().is_dir():
            return []
        return sorted(p.name for p in self.updates().iterdir() if p.name.endswith((".exe", ".tar.gz", ".part")))


class WindowsUpdateTests(UpdaterTestCase):
    def test_a_signed_newer_version_is_downloaded_verified_and_launched_in_update_mode(self) -> None:
        self.publish()
        updater = self.updater()

        self.assertTrue(updater.run(Offer(self.target)))

        self.assertEqual(len(self.launched), 1)
        args = self.launched[0]
        installer = Path(args[0])
        self.assertEqual(installer.parent, self.updates())
        self.assertEqual(installer.read_bytes(), self.installer)
        self.assertEqual(args[1:5], ["/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/UPDATE"])
        self.assertEqual(updater.state()["state"], "installing")
        self.assertEqual(updater.state()["version"], self.target)
        self.assertTrue(updater.holding(), "no task may start while the installer replaces the agent")
        pending = json.loads((self.updates() / "pending.json").read_text())
        self.assertEqual((pending["from"], pending["to"]), (self.current, self.target))

    def test_a_tampered_installer_is_deleted_reported_and_never_launched(self) -> None:
        self.publish()
        path = f"/releases/agent-v{self.target}/Cenya-Agent-Setup-{self.target}.exe"
        tampered = self.installer[:-1] + bytes([self.installer[-1] ^ 0xFF])
        self.github.add(path, tampered)
        updater = self.updater()

        self.assertFalse(updater.run(Offer(self.target)))

        self.assertEqual(self.launched, [])
        self.assertEqual(self.downloaded(), [])
        state = updater.state()
        self.assertEqual((state["state"], state["error"]), ("failed", release.BAD_HASH))
        self.assertEqual((state["note"]["collector"], state["note"]["code"]), ("update", "bad_hash"))
        self.assertFalse(updater.holding())
        # Un fallo que puede ser pasajero: se reintenta, pero no en el acto.
        self.assertEqual(updater._retry_after[self.target], self.clock.now + update.RETRY_SECONDS)

    def test_a_manifest_signed_by_another_key_downloads_nothing(self) -> None:
        self.publish(signer=Ed25519PrivateKey.generate())
        updater = self.updater()

        self.assertFalse(updater.run(Offer(self.target)))

        self.assertEqual(updater.state()["error"], release.BAD_SIGNATURE)
        self.assertFalse(any(p.endswith(".exe") for p in self.github.paths()))
        self.assertEqual(self.launched, [])

    def test_a_manifest_of_another_version_is_refused(self) -> None:
        manifest = self.publish("0.11.2")
        base = f"/releases/agent-v{self.target}"
        self.github.add(f"{base}/latest.json", manifest)
        self.github.add(f"{base}/latest.json.sig", base64.b64encode(self.key.sign(manifest)))

        self.assertFalse(self.updater().run(Offer(self.target)))

        self.assertEqual(self.launched, [])
        self.assertEqual(self.downloaded(), [])

    def test_a_signed_downgrade_is_refused(self) -> None:
        self.publish("0.10.9")

        updater = self.updater()
        self.assertFalse(updater.run(Offer("0.10.9")))

        self.assertEqual(updater.state()["error"], update.NOT_NEWER)
        self.assertEqual(self.launched, [])

    def test_without_keys_nothing_is_even_asked_for(self) -> None:
        self.publish()
        updater = self.updater(keys=[])

        self.assertFalse(updater.run(Offer(self.target)))

        self.assertEqual(updater.state()["error"], release.NO_KEYS)
        self.assertEqual(self.github.paths(), [])

    def test_a_download_bigger_than_the_manifest_says_is_cut_and_refused(self) -> None:
        self.publish()
        path = f"/releases/agent-v{self.target}/Cenya-Agent-Setup-{self.target}.exe"
        # Cuerpo más grande y sin anunciarlo: el tope del manifiesto lo corta.
        self.github.add(path, self.installer + b"x" * 4096, headers={"Content-Length": str(len(self.installer) + 4096)})
        updater = self.updater()

        self.assertFalse(updater.run(Offer(self.target)))

        self.assertEqual(updater.state()["error"], release.BAD_HASH)
        self.assertEqual(self.downloaded(), [])

    def test_the_file_being_downloaded_is_inside_the_protected_folder_and_closed_to_others(self) -> None:
        self.publish()
        seen: dict[str, object] = {}
        real = store.private_temp

        def spy(folder: Path, **kwargs):  # noqa: ANN003, ANN202
            fd, path = real(folder, **kwargs)
            seen["folder"], seen["path"] = folder, path
            if sys.platform == "win32":
                seen["sddl"] = store._backend().read_sddl(path)
            else:
                seen["mode"] = os.stat(path).st_mode & 0o777
                seen["folder_mode"] = os.stat(folder).st_mode & 0o777
            return fd, path

        with mock.patch.object(update.store, "private_temp", side_effect=spy):
            self.assertTrue(self.updater().run(Offer(self.target)))

        self.assertEqual(seen["folder"], self.updates())
        self.assertEqual(Path(seen["path"]).parent, self.updates())
        if sys.platform == "win32":
            sddl = str(seen["sddl"])
            self.assertIn("D:P", sddl, "the temporary file must not inherit anything")
            for broad in (";BU)", ";WD)", ";AU)", ";IU)"):
                self.assertNotIn(broad, sddl)
        else:
            self.assertEqual(seen["mode"], 0o600)
            self.assertEqual(seen["folder_mode"], 0o700)

    def test_it_waits_for_the_task_in_progress_and_holds_new_ones(self) -> None:
        self.publish()
        answers = iter([True, True, False])
        holding: list[bool] = []
        updater = None

        def busy() -> bool:
            holding.append(updater.holding())
            return next(answers)

        updater = self.updater(busy=busy)
        with mock.patch.object(update, "IDLE_POLL_SECONDS", 0.01):
            self.assertTrue(updater.run(Offer(self.target)))

        self.assertEqual(holding, [True, True, True])
        self.assertEqual(len(self.launched), 1)

    def test_the_file_is_checked_again_right_before_it_is_launched(self) -> None:
        self.publish()
        target = None
        answers = iter([True, False])

        def busy() -> bool:
            # Mientras «termina una tarea», alguien cambia el fichero descargado.
            if target is not None and next(answers):
                target.write_bytes(b"MZ evil")
                return True
            return False

        updater = self.updater(busy=lambda: busy())
        real_stream = update.stream_to

        def remember(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
            nonlocal target
            target = real_stream(*args, **kwargs)
            return target

        with mock.patch.object(update, "stream_to", side_effect=remember), mock.patch.object(update, "IDLE_POLL_SECONDS", 0.01):
            self.assertFalse(updater.run(Offer(self.target)))

        self.assertEqual(self.launched, [])
        self.assertEqual(updater.state()["error"], release.BAD_HASH)

    def test_when_github_fails_it_uses_its_own_server_and_verifies_the_same(self) -> None:
        manifest = self.publish(site=Site())  # nada en «GitHub»
        client = SimpleNamespace(base_url=self.server_url, token="cya_secreto")
        self.server.add(
            "/api/agent/v2/installer/",
            self.installer,
            headers={
                "X-Cenya-Version": self.target,
                "X-Cenya-Sha256": hashlib.sha256(self.installer).hexdigest(),
                "X-Cenya-Manifest": base64.b64encode(manifest).decode(),
                "X-Cenya-Manifest-Signature": base64.b64encode(self.key.sign(manifest)).decode(),
            },
        )

        self.assertTrue(self.updater(client=client).run(Offer(self.target)))

        self.assertEqual(Path(self.launched[0][0]).read_bytes(), self.installer)
        path, headers = self.server.seen[0]
        self.assertEqual(path, "/api/agent/v2/installer/")
        self.assertEqual(headers.get("Authorization"), "Bearer cya_secreto")
        # A GitHub no se le manda nunca el token.
        self.assertFalse(any("Authorization" in h for _p, h in self.github.seen))

    def test_the_bearer_token_never_follows_a_redirect(self) -> None:
        elsewhere = Site()
        with serving(elsewhere) as elsewhere_url:
            self.server.add(
                "/api/agent/v2/installer/", b"", status=302, headers={"Location": f"{elsewhere_url}/steal"}
            )
            client = SimpleNamespace(base_url=self.server_url, token="cya_secreto")
            updater = self.updater(client=client)

            self.assertFalse(updater.run(Offer(self.target)))

        self.assertEqual(elsewhere.seen, [], "the redirect must not be followed at all")
        self.assertEqual(updater.state()["error"], update.DOWNLOAD_FAILED)
        self.assertEqual(self.launched, [])

    def test_a_public_download_follows_a_redirect_only_to_an_allowed_url_and_without_a_token(self) -> None:
        manifest = self.publish()
        moved = f"/releases/agent-v{self.target}/Cenya-Agent-Setup-{self.target}.exe"
        self.github.add(moved, b"", status=302, headers={"Location": f"{self.github_url}/storage/x.exe"})
        self.github.add("/storage/x.exe", self.installer)

        self.assertTrue(self.updater().run(Offer(self.target)))
        self.assertIn("/storage/x.exe", self.github.paths())

        # Y a una URL en claro hacia fuera, no.
        self.launched.clear()
        self.github.add(moved, b"", status=302, headers={"Location": "http://example.invalid/x.exe"})
        self.state_dir = Path(tempfile.mkdtemp(prefix="cenya-update-"))
        updater = self.updater()
        self.assertFalse(updater.run(Offer(self.target)))
        self.assertEqual(self.launched, [])
        self.assertTrue(manifest)


class LifecycleTests(UpdaterTestCase):
    def test_the_first_good_checkin_leaves_the_healthy_marker_the_watchdog_looks_for(self) -> None:
        updater = self.updater()
        updater.startup()

        updater.offer(None)

        self.assertTrue((self.updates() / f"healthy-{self.current}").is_file())
        self.assertEqual(updater.state()["state"], "idle")

    def test_an_offer_starts_the_update_in_the_background(self) -> None:
        self.publish()
        updater = self.updater()

        updater.offer({"version": self.target})
        updater._thread.join(timeout=30)

        self.assertEqual(len(self.launched), 1)

    def test_the_new_version_reports_installing_until_its_first_checkin_then_idle(self) -> None:
        self.updates().mkdir(parents=True)
        (self.updates() / "pending.json").write_text(json.dumps({"from": "0.10.9", "to": self.current}))
        updater = self.updater()

        updater.startup()
        self.assertEqual(updater.state()["state"], "installing")
        updater.offer(None)

        self.assertEqual(updater.state(), update.state("idle", self.current))
        self.assertFalse((self.updates() / "pending.json").exists())

    def test_the_restored_version_reports_update_failed_and_never_tries_that_version_again(self) -> None:
        self.updates().mkdir(parents=True)
        (self.updates() / "pending.json").write_text(json.dumps({"from": self.current, "to": self.target}))
        (self.updates() / f"failed-{self.target}").write_text("")
        self.publish()
        updater = self.updater()

        updater.startup()
        updater.offer({"version": self.target, "explicit": True})

        state = updater.state()
        self.assertEqual((state["state"], state["version"], state["error"]), ("failed", self.target, "update_failed"))
        self.assertEqual(state["note"]["code"], "update_failed")
        self.assertIsNone(updater._thread)
        self.assertEqual(self.github.paths(), [])

    def test_an_installer_that_replaced_nothing_gets_one_more_try_and_then_it_is_final(self) -> None:
        self.updates().mkdir(parents=True)
        (self.updates() / "pending.json").write_text(json.dumps({"from": self.current, "to": self.target}))

        first = self.updater()
        first.startup()
        self.assertEqual(first.state()["state"], "idle")
        self.assertTrue((self.updates() / f"retried-{self.target}").exists())
        self.assertFalse((self.updates() / f"failed-{self.target}").exists())
        self.assertFalse((self.updates() / "pending.json").exists())

        (self.updates() / "pending.json").write_text(json.dumps({"from": self.current, "to": self.target}))
        second = self.updater()
        second.startup()
        self.assertEqual(second.state()["error"], update.INSTALL_FAILED)
        self.assertTrue((self.updates() / f"failed-{self.target}").exists())

    def test_leftovers_of_older_versions_are_cleaned_at_start(self) -> None:
        self.updates().mkdir(parents=True)
        for name in ("cenya-agent-0.10.0.exe", ".dl-abc.part", "failed-0.10.5", "healthy-0.10.0",
                     f"healthy-{self.current}", "failed-0.11.5"):
            (self.updates() / name).write_text("x")

        self.updater().startup()

        self.assertEqual(sorted(p.name for p in self.updates().iterdir()), ["failed-0.11.5", f"healthy-{self.current}"])

    def test_an_installer_that_never_replaced_the_agent_is_given_up_after_a_while(self) -> None:
        self.publish()
        updater = self.updater()
        self.assertTrue(updater.run(Offer(self.target)))

        updater.offer({"version": self.target})
        self.assertEqual(updater.state()["state"], "installing")
        self.clock.now += update.INSTALL_TIMEOUT_SECONDS + 1
        updater.offer({"version": self.target})

        self.assertEqual(updater.state()["error"], update.INSTALL_FAILED)
        self.assertFalse(updater.holding())
        self.assertTrue((self.updates() / f"failed-{self.target}").exists())
        self.assertEqual(self.downloaded(), [])

    def test_once_never_updates_nor_reports(self) -> None:
        updater = Updater(self.state_dir, keys=self.keys, enabled=False, launcher=self.launched.append)

        updater.startup()
        updater.offer({"version": "99.0.0", "explicit": True})

        self.assertIsNone(updater.state())
        self.assertFalse(self.updates().exists())


class LinuxUpdateTests(UpdaterTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.archive = b"\x1f\x8b fake tarball " + os.urandom(1024)
        self.script = b"#!/bin/sh\necho update\n"

    def publish_linux(self) -> None:
        self.publish(files={"linux": self.archive, "install.sh": self.script})

    def test_the_unprivileged_agent_only_leaves_a_request_with_everything_root_must_recheck(self) -> None:
        self.publish_linux()
        updater = self.updater(platform="linux")

        self.assertTrue(updater.run(Offer(self.target)))

        self.assertEqual(self.launched, [], "the agent never runs the installer itself on Linux")
        request = json.loads((self.updates() / "request.json").read_text())
        self.assertEqual(request["version"], self.target)
        for kind in ("linux", "install.sh", "manifest", "signature"):
            with self.subTest(kind=kind):
                self.assertTrue((self.updates() / update.download_name(self.target, kind)).is_file())

    def test_root_reverifies_and_runs_the_verified_install_script(self) -> None:
        self.publish_linux()
        self.assertTrue(self.updater(platform="linux").run(Offer(self.target)))
        calls: list[list[str]] = []

        def fake_run(command, check):  # noqa: ANN001, ANN202
            calls.append(command)
            # Lo que se ejecuta es la copia verificada, no lo que dejó el agente.
            self.assertEqual(Path(command[1]).read_bytes(), self.script)
            self.assertNotEqual(Path(command[1]).parent, self.updates())
            return SimpleNamespace(returncode=0)

        code = update.apply_request(self.state_dir, keys=self.keys, current=self.current, run=fake_run)

        self.assertEqual(code, 0)
        self.assertEqual(calls[0][0], "/bin/sh")
        self.assertEqual(calls[0][2:4], ["--update", "--archive"])
        self.assertEqual(calls[0][-2:], ["--version", self.target])
        self.assertFalse((self.updates() / "request.json").exists())

    def test_root_refuses_what_the_agent_user_changed_after_verifying(self) -> None:
        self.publish_linux()
        self.assertTrue(self.updater(platform="linux").run(Offer(self.target)))
        (self.updates() / update.download_name(self.target, "install.sh")).write_bytes(b"#!/bin/sh\nrm -rf /\n")
        ran: list[object] = []

        code = update.apply_request(self.state_dir, keys=self.keys, current=self.current, run=lambda *a, **k: ran.append(a))

        self.assertEqual(code, 1)
        self.assertEqual(ran, [])
        result = json.loads((self.updates() / "result.json").read_text())
        self.assertEqual(result, {"version": self.target, "error": "bad_hash"})

    def test_root_refuses_a_request_signed_by_a_key_it_does_not_trust(self) -> None:
        self.publish_linux()
        self.assertTrue(self.updater(platform="linux").run(Offer(self.target)))
        other = [public_line(Ed25519PrivateKey.generate())]

        code = update.apply_request(self.state_dir, keys=other, current=self.current, run=mock.Mock())

        self.assertEqual(code, 1)
        self.assertEqual(json.loads((self.updates() / "result.json").read_text())["error"], "bad_signature")

    def test_root_refuses_a_downgrade_even_if_signed(self) -> None:
        self.publish_linux()
        self.assertTrue(self.updater(platform="linux").run(Offer(self.target)))
        runner = mock.Mock()

        code = update.apply_request(self.state_dir, keys=self.keys, current="0.12.0", run=runner)

        self.assertEqual(code, 1)
        runner.assert_not_called()

    def test_without_a_request_root_does_nothing(self) -> None:
        self.assertEqual(update.apply_request(self.state_dir, keys=self.keys, run=mock.Mock()), 0)

    def test_the_agent_reads_why_root_refused(self) -> None:
        self.publish_linux()
        updater = self.updater(platform="linux")
        self.assertTrue(updater.run(Offer(self.target)))
        (self.updates() / "result.json").write_text(json.dumps({"version": self.target, "error": "bad_signature"}))

        updater.offer(None)

        self.assertEqual(updater.state()["error"], "bad_signature")
        self.assertFalse(updater.holding())

    @unittest.skipIf(sys.platform == "win32", "enlaces simbólicos sin privilegios: POSIX")
    def test_root_does_not_follow_a_link_planted_in_the_downloads_folder(self) -> None:
        self.publish_linux()
        self.assertTrue(self.updater(platform="linux").run(Offer(self.target)))
        planted = self.updates() / update.download_name(self.target, "linux")
        planted.unlink()
        planted.symlink_to("/etc/passwd")

        code = update.apply_request(self.state_dir, keys=self.keys, current=self.current, run=mock.Mock())

        self.assertEqual(code, 1)


@NEEDS_CRYPTO
class InstallScriptVerifierTests(unittest.TestCase):
    """The small verifier inside install.sh says what agent/release.py says."""

    SCRIPT = AGENT_DIR / "deploy" / "install.sh"

    def verifier(self) -> str:
        text = self.SCRIPT.read_text(encoding="utf-8")
        return re.search(r"<<'PY'\n(.*?)\nPY\n", text, re.S).group(1)

    def run_verifier(self, manifest: bytes, signature: bytes, keys: str) -> subprocess.CompletedProcess:
        folder = Path(tempfile.mkdtemp(prefix="cenya-installsh-"))
        (folder / "latest.json").write_bytes(manifest)
        (folder / "latest.json.sig").write_bytes(signature)
        (folder / "verify.py").write_text(self.verifier(), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(folder / "verify.py"), str(folder / "latest.json"), str(folder / "latest.json.sig"), keys],
            capture_output=True, text=True, check=False,
        )

    def manifest(self) -> bytes:
        archive = b"tarball"
        return json.dumps({
            "version": "0.11.1",
            "files": {"linux": entry("https://github.com/x/cenya-agent-0.11.1.tar.gz", archive)},
        }).encode()

    def test_a_signed_manifest_yields_what_the_script_needs(self) -> None:
        key = Ed25519PrivateKey.generate()
        data = self.manifest()

        done = self.run_verifier(data, base64.b64encode(key.sign(data)), public_line(key))

        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("M_VERSION='0.11.1'", done.stdout)
        self.assertIn(f"M_SHA='{hashlib.sha256(b'tarball').hexdigest()}'", done.stdout)

    def test_another_key_or_other_bytes_are_refused(self) -> None:
        key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        data = self.manifest()
        for signature, keys in (
            (base64.b64encode(other.sign(data)), public_line(key)),
            (base64.b64encode(key.sign(data + b" ")), public_line(key)),
            (b"", public_line(key)),
        ):
            with self.subTest(keys=keys[:6]):
                done = self.run_verifier(data, signature, keys)
                self.assertNotEqual(done.returncode, 0)
                self.assertNotIn("M_VERSION", done.stdout)

    def test_the_script_is_posix_sh_and_strict(self) -> None:
        text = self.SCRIPT.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("#!/bin/sh\n"))
        self.assertIn("\nset -eu\n", text)
        self.assertNotIn("\r", text)
        self.assertRegex(text, r"(?m)^RELEASE_KEYS=''$")
        for bashism in ("[[", "function ", "local ", "source ", "$'", "<<<", "pipefail"):
            with self.subTest(bashism=bashism):
                self.assertNotIn(bashism, text)

    @unittest.skipIf(shutil.which("sh") is None, "sin sh en esta máquina")
    def test_sh_parses_it(self) -> None:
        done = subprocess.run(["sh", "-n", str(self.SCRIPT)], capture_output=True, text=True, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)


if __name__ == "__main__":
    unittest.main()
