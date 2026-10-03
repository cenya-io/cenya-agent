"""The console commands that talk to the service: against a channel in memory, and with no service.

The service side is a `Dispatcher` with canned handlers, reached through an
in-memory connection that behaves like the pipe (lines in, lines out): what is
tested is what the person at the console reads and the exit code a script
gets.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from agent import localclient, localpipe, logs
from agent.localapi import Caller, Dispatcher, OpError, encode

ADMIN = Caller(admin=True, who="admin")
USER = Caller(admin=False, who="user")


class InMemory:
    """Una conexión que lleva cada línea al despachador y devuelve su respuesta."""

    def __init__(self, dispatcher: Dispatcher, caller: Caller) -> None:
        self.dispatcher, self.caller = dispatcher, caller
        self.pending = b""

    def send(self, data: bytes, timeout: float) -> None:
        for line in data.splitlines():
            self.pending += encode(self.dispatcher.handle_line(line, self.caller))

    def recv(self, timeout: float) -> bytes:
        data, self.pending = self.pending, b""
        if not data:
            raise TimeoutError
        return data

    def close(self) -> None:
        pass


def soon(hours: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


STATUS = {
    "version": "0.11.0", "enrolled": True, "protocol": "v2", "portal": "https://portal.example", "name": "CPD",
    "connection": {"state": "ok", "at": soon(0)}, "state": "running",
    "activity": {"task": "inventory", "step": "ssh", "done": 14, "total": 37},
    "schedule": [{"task": "presence", "every_seconds": 300, "last_finished_at": soon(-0.1), "last_status": "ok", "next_at": soon(0.1)},
                 {"task": "configs", "every_seconds": 0, "last_finished_at": None, "last_status": None, "next_at": None}],
    "pause": {"local": None, "server": None, "until": None}, "outbox": 2, "update": {"version": "0.11.1"}, "local": {},
}


class ConsoleCase(unittest.TestCase):
    def setUp(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.out: list[str] = []
        self.err: list[str] = []
        self.caller = ADMIN
        self.handlers: dict[str, Any] = {
            "status": lambda args, caller: STATUS,
            "run": lambda args, caller: {"queued": args["task"], "waiting_for": ""},
            "pause": lambda args, caller: {"paused_until": soon(args["seconds"] / 3600), "server_paused_until": None},
            "resume": lambda args, caller: {"paused_until": None, "server_paused_until": soon(3)},
            "log": lambda args, caller: {"lines": [f"linea {n}" for n in range(args.get("lines", 5))], "cursor": "1:10"},
            "test_connection": lambda args, caller: {"ok": True, "steps": [{"step": "dns", "ok": True, "message": "bien"}]},
            "connect": lambda args, caller: {"name": "Oficina", "portal": "https://otro.example", "restarting": True},
            "disconnect": lambda args, caller: {"told_server": True, "message": "Se ha avisado al servidor."},
        }

    def connect(self, environ: Any = None, timeout: float = 5.0) -> InMemory:
        def recorded(op: str):  # noqa: ANN202
            def handler(args: dict, caller: Caller) -> Any:
                self.calls.append((op, dict(args)))
                return self.handlers[op](args, caller)

            return handler

        return InMemory(Dispatcher({op: recorded(op) for op in self.handlers}), self.caller)

    def run_command(self, *args: str, connect: Any = None) -> int:
        return localclient.run(list(args), connect=connect or self.connect, out=self.out.append, err=self.err.append)

    def no_service(self, environ: Any = None, timeout: float = 5.0) -> Any:
        raise localpipe.Unavailable("not_running")


class CommandTests(ConsoleCase):
    def test_status_reads_like_a_sentence(self) -> None:
        self.assertEqual(self.run_command("status"), 0)
        text = "\n".join(self.out)
        self.assertIn("Conectado como «CPD» a https://portal.example (protocolo 2).", text)
        self.assertIn("Conexión: correcta", text)
        self.assertIn("trabajando en inventory (ssh 14/37)", text)
        self.assertIn("presence: cada 5 minutos", text)
        self.assertNotIn("configs", text)  # apagada, no se enseña
        self.assertIn("2 envíos pendientes", text)
        self.assertIn("0.11.1", text)

    def test_status_when_not_enrolled_and_as_an_ordinary_user(self) -> None:
        self.caller = USER
        self.handlers["status"] = lambda args, caller: {"version": "0.11.0", "enrolled": False}
        self.assertEqual(self.run_command("status"), 0)
        self.assertIn("cenya-agent connect", "\n".join(self.out))

    def test_run_pause_and_resume(self) -> None:
        self.assertEqual(self.run_command("run", "presence"), 0)
        self.assertEqual(self.run_command("pause", "--hours", "2"), 0)
        self.assertEqual(self.run_command("pause"), 0)
        self.assertEqual(self.run_command("resume"), 0)
        self.assertEqual(self.calls, [("run", {"task": "presence"}), ("pause", {"seconds": 7200}), ("pause", {"seconds": 3600}), ("resume", {})])
        self.assertIn("se puso desde la web", "\n".join(self.out))

    def test_acting_without_rights_says_how_to_get_them(self) -> None:
        self.caller = USER
        self.assertEqual(self.run_command("pause"), localclient.NOT_ALLOWED)
        self.assertIn("administrador" if os.name == "nt" else "root", "\n".join(self.err))
        self.assertEqual(self.calls, [])

    def test_a_refusal_is_printed_with_its_fields(self) -> None:
        def refuse(args: dict, caller: Caller) -> Any:
            raise OpError("invalid", "Tarea desconocida.", fields={"task": "no existe"})

        self.handlers["run"] = refuse
        self.assertEqual(self.run_command("run", "todo"), localclient.FAILED)
        self.assertEqual(self.err, ["Tarea desconocida.", "  task: no existe"])

    def test_logs(self) -> None:
        self.assertEqual(self.run_command("logs", "-n", "3"), 0)
        self.assertEqual(self.out, ["linea 0", "linea 1", "linea 2"])
        self.assertEqual(self.calls, [("log", {"lines": 3})])

    def test_doctor_is_the_connection_test_plus_the_selftest(self) -> None:
        with mock.patch("agent.selftest.report", return_value={}), mock.patch("agent.selftest.complete", return_value=True):
            self.assertEqual(self.run_command("doctor"), 0)
        self.assertIn("dns: bien", "\n".join(self.out))
        self.handlers["test_connection"] = lambda args, caller: {"ok": False, "steps": [{"step": "tls", "ok": False, "message": "caducado"}]}
        with mock.patch("agent.selftest.report", return_value={}), mock.patch("agent.selftest.complete", return_value=True):
            self.assertEqual(self.run_command("doctor"), localclient.FAILED)

    def test_connect_and_disconnect_through_the_service(self) -> None:
        self.assertEqual(self.run_command("connect", "cenya://otro.example/K7QF-9M2X-4TQN"), 0)
        self.assertEqual(self.calls[-1], ("connect", {"connection": "cenya://otro.example/K7QF-9M2X-4TQN"}))
        self.assertIn("Oficina", self.out[-1])
        self.assertEqual(self.run_command("disconnect"), 0)
        self.assertEqual(self.out[-1], "Se ha avisado al servidor.")

    def test_usage(self) -> None:
        for args in ([], ["frobnicate"], ["run"], ["pause", "--hours", "x"], ["pause", "--hours", "-1"], ["logs", "-n", "0"],
                     ["status", "de", "más"], ["connect"]):
            with self.subTest(args=args):
                self.assertEqual(self.run_command(*args), localclient.USAGE)


class NoServiceTests(ConsoleCase):
    def test_each_command_says_plainly_that_the_service_is_not_running(self) -> None:
        for args in (["status"], ["run", "presence"], ["pause"], ["resume"], ["disconnect"]):
            with self.subTest(args=args):
                self.err.clear()
                self.assertEqual(self.run_command(*args, connect=self.no_service), localclient.NO_SERVICE)
                self.assertIn("no está en marcha", self.err[0])

    def test_connect_falls_back_to_enrolling_from_the_console(self) -> None:
        with mock.patch("agent.enroll.run", return_value=0) as enroll:
            code = self.run_command("connect", "cenya://otro.example/K7QF-9M2X-4TQN", "--force", connect=self.no_service)
        self.assertEqual(code, 0)
        enroll.assert_called_once_with(["cenya://otro.example/K7QF-9M2X-4TQN", "--force"], None)

    def test_connect_never_falls_back_when_someone_else_holds_the_channel(self) -> None:
        def untrusted(environ: Any = None, timeout: float = 5.0) -> Any:
            raise localpipe.Unavailable("untrusted")

        with mock.patch("agent.enroll.run") as enroll:
            self.assertEqual(self.run_command("connect", "cenya://x/K7QF-9M2X-4TQN", connect=untrusted), localclient.NO_SERVICE)
        enroll.assert_not_called()
        self.assertIn("otro programa", self.err[0])

    def test_logs_fall_back_to_the_file_when_it_can_be_read(self) -> None:
        state = tempfile.mkdtemp(prefix="cenya-console-")
        with mock.patch.dict(os.environ, {"CENYA_STATE_DIR": state}):
            path = logs.path()
            path.parent.mkdir(parents=True)
            path.write_text("una\ndos\ntres\n", encoding="utf-8")
            self.assertEqual(self.run_command("logs", "-n", "2", connect=self.no_service), 0)
            self.assertEqual(self.out, ["dos", "tres"])
            path.unlink()
            self.assertEqual(self.run_command("logs", connect=self.no_service), localclient.NO_SERVICE)

    def test_doctor_without_a_service_tests_from_the_console(self) -> None:
        state = tempfile.mkdtemp(prefix="cenya-console-")
        with mock.patch.dict(os.environ, {"CENYA_STATE_DIR": state}), mock.patch(
            "agent.selftest.report", return_value={}
        ), mock.patch("agent.selftest.complete", return_value=True):
            self.assertEqual(self.run_command("doctor", connect=self.no_service), localclient.FAILED)
        self.assertIn("no está enrolado", "\n".join(self.err))

    def test_the_agent_command_line_hands_these_commands_to_the_client(self) -> None:
        from agent import __main__ as loop

        for command in localclient.COMMANDS:
            with self.subTest(command=command), mock.patch.object(localclient, "run", return_value=3) as run:
                with self.assertRaises(SystemExit) as raised:
                    loop.main([command, "x"])
                self.assertEqual(raised.exception.code, 3)
                run.assert_called_once_with([command, "x"])


class StatusLinesTests(unittest.TestCase):
    def test_every_connection_state_has_a_sentence(self) -> None:
        for state in ("ok", "error", "refused", "read_only", "unknown"):
            with self.subTest(state=state):
                lines = localclient.status_lines({**STATUS, "connection": {"state": state, "error": "x"}})
                self.assertTrue(any(line.startswith("Conexión:") for line in lines))

    def test_a_pause_is_shown(self) -> None:
        lines = localclient.status_lines({**STATUS, "activity": None, "pause": {"until": soon(1)}})
        self.assertTrue(any("en pausa hasta las" in line for line in lines))


if __name__ == "__main__":
    unittest.main()
