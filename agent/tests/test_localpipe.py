"""The local channel over its real transport: a named pipe on Windows, a Unix socket elsewhere.

Every test uses a pipe name (or socket path) of its own, never the service's:
this machine may have a real agent running. What can be checked without
administrator rights is checked as the user running the tests -- reads work,
acts are refused unless that user is elevated -- and the end-to-end test of
``connect`` and ``disconnect`` stands in for the elevated caller by replacing
the identification, which is said where it happens.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma, carpeta de estado y nombre de pipe de prueba

import contextlib
import http.server
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from typing import Any
from unittest import mock

from agent import localops, localpipe, store
from agent.localapi import Admission, Caller, Dispatcher
from agent.localclient import Channel, ChannelError

WINDOWS = sys.platform == "win32"
UNIX = hasattr(socket, "AF_UNIX") and not WINDOWS


def may_act_here() -> bool:
    """Lo que el servicio de prueba tiene que decidir de quien corre los tests.

    Windows: solo si la consola está elevada. Linux: siempre, porque el
    cliente es la misma cuenta que el «servicio» (`SO_PEERCRED`, uid propio).
    """
    if WINDOWS:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return True


def unique_environ() -> dict[str, str]:
    """Un nombre de pipe y una ruta de socket solo para este test."""
    folder = tempfile.mkdtemp(prefix="cenya-sock-")
    return {
        localpipe.PIPE_ENV_VAR: f"CenyaAgentTest-{uuid.uuid4().hex}",
        localpipe.SOCKET_ENV_VAR: str(Path(folder) / "agent.sock"),
    }


def echo_dispatcher() -> Dispatcher:
    return Dispatcher({
        "status": lambda args, caller: {"admin": caller.admin, "who": caller.who},
        "pause": lambda args, caller: {"paused": True},
        "probe": lambda args, caller: time.sleep(float(args.get("sleep", 0))) or {"slept": True},
    })


@unittest.skipUnless(WINDOWS or UNIX, "sin transporte local en esta plataforma")
class TransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environ = unique_environ()
        self.assertNotEqual(localpipe.pipe_name(self.environ), localpipe.DEFAULT_PIPE_NAME)

    def serve(self, dispatcher: Dispatcher | None = None, admission: Admission | None = None) -> Any:
        server = localpipe.serve(dispatcher or echo_dispatcher(), environ=self.environ, admission=admission)
        self.assertIsNotNone(server)
        self.addCleanup(server.close)
        return server

    def channel(self) -> Channel:
        channel = Channel(environ=self.environ)
        self.addCleanup(channel.close)
        return channel

    def test_a_round_trip_says_who_is_calling(self) -> None:
        self.serve()
        data = self.channel().call("status")
        self.assertEqual(data["admin"], may_act_here())
        if WINDOWS:
            self.assertTrue(data["who"].startswith("S-1-5-"), data)  # la suplantación funcionó
        else:
            self.assertEqual(data["who"], f"uid:{os.geteuid()}")

    def test_acting_needs_an_administrator(self) -> None:
        self.serve()
        if may_act_here():
            self.assertEqual(self.channel().call("pause"), {"paused": True})
        else:
            with self.assertRaises(ChannelError) as refused:
                self.channel().call("pause")
            self.assertEqual(refused.exception.code, "forbidden")

    def test_garbage_does_not_end_the_conversation(self) -> None:
        self.serve()
        conn = localpipe.connect(environ=self.environ)
        self.addCleanup(conn.close)
        conn.send(b'esto no es json\n{"id": 5, "op": "status"}\n', 5)
        answers: list[dict] = []
        buffer = b""
        deadline = time.monotonic() + 10
        while len(answers) < 2 and time.monotonic() < deadline:
            try:
                buffer += conn.recv(1.0)
            except TimeoutError:
                continue
            *lines, buffer = buffer.split(b"\n")
            answers += [json.loads(line) for line in lines if line]
        self.assertEqual([(a["id"], a["ok"]) for a in answers], [(None, False), (5, True)])

    def test_a_stuck_client_does_not_block_another(self) -> None:
        self.serve()
        stuck = localpipe.connect(environ=self.environ)
        self.addCleanup(stuck.close)
        stuck.send(b'{"id": 1, "op": "sta', 5)  # y no acaba nunca
        silent = localpipe.connect(environ=self.environ)  # ni dice nada
        self.addCleanup(silent.close)
        started = time.monotonic()
        self.assertIn("admin", self.channel().call("status"))
        self.assertLess(time.monotonic() - started, 5)

    def test_a_slow_operation_does_not_block_another_client(self) -> None:
        dispatcher = Dispatcher({
            "status": lambda args, caller: {"ok": 1},
            "probe": lambda args, caller: time.sleep(3) or {"slept": True},
        })
        server = self.serve(dispatcher)
        # El que espera es un administrador de mentira: aquí no se prueba el permiso.
        slow_result: list[Any] = []
        with mock.patch.object(server, "_identify", lambda *a: Caller(admin=True, who="x"), create=True), mock.patch(
            "agent.localpipe._identify_pipe_client", lambda *a: Caller(admin=True, who="x")
        ):
            slow = threading.Thread(target=lambda: slow_result.append(Channel(environ=self.environ).call("probe")), daemon=True)
            slow.start()
            time.sleep(0.3)
            started = time.monotonic()
            self.assertEqual(self.channel().call("status"), {"ok": 1})
            self.assertLess(time.monotonic() - started, 2)
            slow.join(10)
        self.assertEqual(slow_result, [{"slept": True}])

    def test_several_clients_at_once(self) -> None:
        self.serve()
        results: list[Any] = []

        def ask() -> None:
            with Channel(environ=self.environ) as channel:
                results.append(channel.call("status"))

        threads = [threading.Thread(target=ask) for _ in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(15)
        self.assertEqual(len(results), 6)

    def test_over_the_cap_a_client_is_told_busy(self) -> None:
        self.serve(admission=Admission(total=1))
        first = self.channel()
        first.call("status")  # ocupa el único hueco
        with self.assertRaises(ChannelError) as refused:
            self.channel().call("status", timeout=5)
        self.assertEqual(refused.exception.code, "busy")

    def test_without_a_service_the_client_says_so(self) -> None:
        with self.assertRaises(ChannelError) as missing:
            Channel(environ=self.environ)
        self.assertEqual(missing.exception.code, "service_down")

    def test_a_name_already_taken_is_not_served(self) -> None:
        self.serve()
        self.assertIsNone(localpipe.serve(echo_dispatcher(), environ=self.environ))


class NameTests(unittest.TestCase):
    def test_the_name_can_be_changed_and_tests_never_use_the_real_one(self) -> None:
        self.assertEqual(localpipe.pipe_name({}), "\\\\.\\pipe\\CenyaAgent")
        self.assertEqual(localpipe.pipe_name({"CENYA_PIPE_NAME": "Otro"}), "\\\\.\\pipe\\Otro")
        self.assertNotEqual(localpipe.pipe_name(), localpipe.DEFAULT_PIPE_NAME)
        self.assertEqual(localpipe.socket_path({"CENYA_STATE_DIR": "/var/lib/cenya-agent"}), Path("/var/lib/cenya-agent/agent.sock"))


# --- De punta a punta: `main` con el canal, un servidor de mentira y un cambio de identidad ---


class Portal:
    """Un portal de mentira del protocolo 2 que apunta qué token llega en cada petición."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []
        self.lock = threading.Lock()

    def tokens(self, path: str) -> list[str]:
        with self.lock:
            return [token for p, token in self.seen if p == path]


@contextlib.contextmanager
def portal_serving(portal: Portal):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            token = (self.headers.get("Authorization") or "").removeprefix("Bearer ")
            with portal.lock:
                portal.seen.append((self.path, token))
            off = {task: {"every_seconds": 0} for task in ("presence", "inventory", "configs", "ups", "hypervisors")}
            answer = {"ok": True, "protocol": 2, "checkin_seconds": 10, "config_etag": "e1", "config": {"tasks": off}}
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
        yield httpd.server_address[1]
    finally:
        httpd.shutdown()
        httpd.server_close()


def wait_for(condition: Any, seconds: float = 15) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


@unittest.skipUnless(WINDOWS or UNIX, "sin transporte local en esta plataforma")
class MainWithChannelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.state = tempfile.mkdtemp(prefix="cenya-main-")
        environ = {"CENYA_STATE_DIR": self.state, **unique_environ()}
        for patcher in (
            mock.patch.dict(os.environ, environ),
            mock.patch("agent.runtime.about.build", return_value={"hostname": "PRUEBA"}),
            # Quien llama por el canal es «administrador»: en esta máquina no
            # hay derechos para serlo de verdad (lo de verdad, en TransportTests).
            mock.patch("agent.localpipe._identify_pipe_client", lambda *a: Caller(admin=True, who="admin-de-prueba")),
            mock.patch.object(localpipe.SocketServer, "_identify", lambda self, client: Caller(admin=True, who="admin-de-prueba")),
            mock.patch("builtins.print"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        for name in ("CENYA_AGENT_TOKEN", "CENYA_URL", "CENYA_CONNECTION"):
            os.environ.pop(name, None)

    def test_connect_restarts_the_agent_with_the_new_identity_and_disconnect_leaves_it_waiting(self) -> None:
        from agent import __main__ as loop

        class Redeemer:
            def __init__(self, base_url: str, token: str, **kwargs: Any) -> None:
                pass

            def enroll(self, **kwargs: Any) -> dict:
                return {"ok": True, "token": "cya_SEGUNDO", "name": "Segundo"}

        portal = Portal()
        stop = threading.Event()
        with portal_serving(portal) as port, mock.patch("agent.enroll.AgentClient", Redeemer), mock.patch(
            "agent.enroll.identity.ensure", return_value=""
        ), mock.patch("agent.enroll.about.build", return_value={}):
            store.save(store.Enrollment(f"http://127.0.0.1:{port}", "cya_PRIMERO", "Primero"))
            main = threading.Thread(target=loop.main, kwargs={"argv": [], "stop_event": stop}, daemon=True)
            main.start()
            self.addCleanup(lambda: (stop.set(), main.join(15)))
            self.assertTrue(wait_for(lambda: "cya_PRIMERO" in portal.tokens("/api/agent/v2/checkin/")))
            self.assertTrue(wait_for(lambda: self._status().get("enrolled")))

            with Channel() as channel:
                answer = channel.call("connect", {"connection": f"cenya+http://127.0.0.1:{port}/K7QF-9M2X-4TQN"})
            self.assertEqual(answer["name"], "Segundo")
            self.assertTrue(wait_for(lambda: "cya_SEGUNDO" in portal.tokens("/api/agent/v2/checkin/")))
            self.assertTrue(wait_for(lambda: self._status().get("name") == "Segundo"))
            first_after = len(portal.tokens("/api/agent/v2/checkin/"))
            time.sleep(0.5)
            later = portal.tokens("/api/agent/v2/checkin/")[first_after:]
            self.assertNotIn("cya_PRIMERO", later)  # la sesión de antes ya no habla

            with Channel() as channel:
                gone = channel.call("disconnect")
            self.assertTrue(gone["told_server"])
            self.assertEqual(portal.tokens("/api/agent/v2/goodbye/"), ["cya_SEGUNDO"])
            self.assertTrue(wait_for(lambda: self._status().get("enrolled") is False))
            self.assertIsNone(store.load())

            stop.set()
            main.join(15)
            self.assertFalse(main.is_alive())

    def test_an_unenrolled_service_stays_up_and_is_connected_through_the_channel(self) -> None:
        # Un equipo recién instalado: sin enrolamiento, el servicio no sale --
        # sirve el canal, dice por qué no trabaja y espera a un `connect`.
        from agent import __main__ as loop

        class Redeemer:
            def __init__(self, base_url: str, token: str, **kwargs: Any) -> None:
                pass

            def enroll(self, **kwargs: Any) -> dict:
                return {"ok": True, "token": "cya_NUEVO", "name": "Nuevo"}

        portal = Portal()
        stop = threading.Event()
        with portal_serving(portal) as port, mock.patch("agent.enroll.AgentClient", Redeemer), mock.patch(
            "agent.enroll.identity.ensure", return_value=""
        ), mock.patch("agent.enroll.about.build", return_value={}):
            main = threading.Thread(target=loop.main, kwargs={"argv": [], "stop_event": stop}, daemon=True)
            main.start()
            self.addCleanup(lambda: (stop.set(), main.join(15)))
            self.assertTrue(wait_for(lambda: self._status().get("enrollment", {}).get("state") == "not_enrolled"))
            status = self._status()
            self.assertFalse(status["enrolled"])
            self.assertEqual(status["connection"]["state"], "not_enrolled")
            self.assertIn("no está enrolado", status["enrollment"]["message"])
            self.assertTrue(main.is_alive())
            self.assertEqual(portal.seen, [])  # sin identidad no se llama a nadie

            with Channel() as channel:
                answer = channel.call("connect", {"connection": f"cenya+http://127.0.0.1:{port}/K7QF-9M2X-4TQN"})
            self.assertEqual(answer["name"], "Nuevo")
            self.assertTrue(wait_for(lambda: "cya_NUEVO" in portal.tokens("/api/agent/v2/checkin/")))
            self.assertTrue(wait_for(lambda: self._status().get("enrollment", {}).get("state") == "enrolled"))

            stop.set()
            main.join(15)
            self.assertFalse(main.is_alive())

    def test_an_enrolment_set_aside_as_untrusted_is_said_and_the_service_waits(self) -> None:
        from agent import __main__ as loop

        stop = threading.Event()
        with mock.patch("agent.store.untrusted_enrollment", return_value=True):
            main = threading.Thread(target=loop.main, kwargs={"argv": [], "stop_event": stop}, daemon=True)
            main.start()
            self.addCleanup(lambda: (stop.set(), main.join(15)))
            self.assertTrue(wait_for(lambda: self._status().get("enrollment", {}).get("state") == "untrusted"))
            self.assertIn("no es de fiar", self._status()["enrollment"]["message"])
            stop.set()
            main.join(15)
            self.assertFalse(main.is_alive())

    def _status(self) -> dict:
        try:
            with Channel() as channel:
                return channel.call("status")
        except (ChannelError, OSError):
            return {}


if __name__ == "__main__":
    unittest.main()
