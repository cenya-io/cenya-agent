"""The local channel's protocol (spec 4), with no pipe and no socket.

Framing, limits, the permission matrix and the conversation loop are pure
enough to be driven byte by byte: what is tested here holds for any
transport.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import json
import threading
import time
import unittest

from agent import localapi
from agent.localapi import (
    ADMIN_READ,
    ACT,
    ANONYMOUS,
    OPERATIONS,
    READ,
    TOO_LONG,
    Admission,
    Caller,
    Dispatcher,
    LineBuffer,
    OpError,
    encode,
    may,
    parse_request,
    posix_may_act,
    serve_connection,
)
from agent.localpipe import groups_grant_admin, pipe_sddl, trusted_pipe_owner

ADMIN = Caller(admin=True, who="S-1-5-21-1-2-3-500")
USER = Caller(admin=False, who="S-1-5-21-1-2-3-1001")


class FramingTests(unittest.TestCase):
    def test_lines_are_cut_at_newlines_even_across_chunks(self) -> None:
        buffer = LineBuffer(limit=100)
        self.assertEqual(buffer.feed(b'{"op":"st'), [])
        self.assertTrue(buffer.partial)
        self.assertEqual(buffer.feed(b'atus"}\n{"op":"log"}\r\n'), [b'{"op":"status"}', b'{"op":"log"}'])
        self.assertFalse(buffer.partial)

    def test_blank_lines_are_ignored(self) -> None:
        self.assertEqual(LineBuffer().feed(b"\n\r\n  \n"), [])

    def test_a_line_over_the_limit_is_reported_once_and_skipped_to_its_end(self) -> None:
        buffer = LineBuffer(limit=10)
        self.assertEqual(buffer.feed(b"x" * 8), [])
        self.assertEqual(buffer.feed(b"y" * 8), [TOO_LONG])
        self.assertEqual(buffer.feed(b"z" * 50), [])  # sigue tirando lo que queda de esa línea
        self.assertEqual(buffer.feed(b'zz\n{"a":1}\n'), [b'{"a":1}'])

    def test_a_complete_long_line_in_one_chunk_does_not_poison_the_next(self) -> None:
        buffer = LineBuffer(limit=10)
        self.assertEqual(buffer.feed(b"a" * 20 + b"\nok\n"), [TOO_LONG, b"ok"])

    def test_the_buffer_never_holds_more_than_its_limit(self) -> None:
        buffer = LineBuffer(limit=1000)
        for _ in range(100):
            buffer.feed(b"q" * 999)
            self.assertLessEqual(len(buffer._pending), 1000)


class RequestParsingTests(unittest.TestCase):
    def test_a_good_request(self) -> None:
        request = parse_request(b'{"id": 7, "op": "status", "args": {"x": 1}}')
        self.assertEqual((request.id, request.op, request.args), (7, "status", {"x": 1}))

    def test_args_may_be_missing_or_null(self) -> None:
        self.assertEqual(parse_request(b'{"id": "a", "op": "status"}').args, {})
        self.assertEqual(parse_request(b'{"op": "status", "args": null}').args, {})

    def test_malformed_input_is_an_error_answer_never_an_exception(self) -> None:
        cases = {
            b"no es json": "bad_request",
            b"\xff\xfe": "bad_request",
            b"[1, 2]": "bad_request",
            b'{"id": 1}': "bad_request",
            b'{"id": 1, "op": 3}': "bad_request",
            b'{"id": [1], "op": "status"}': "bad_request",
            b'{"id": true, "op": "status"}': "bad_request",
            b'{"id": 1, "op": "status", "args": [1]}': "bad_request",
            b"[" * 100000: "bad_request",
        }
        for line, code in cases.items():
            with self.subTest(line=line[:30]):
                answer = parse_request(line)
                self.assertIsInstance(answer, dict)
                self.assertEqual((answer["ok"], answer["error"]), (False, code))
                self.assertTrue(answer["message"])

    def test_the_id_comes_back_when_it_can(self) -> None:
        self.assertEqual(parse_request(b'{"id": 9, "args": {}}')["id"], 9)

    def test_an_answer_too_big_becomes_an_error_line(self) -> None:
        big = encode({"id": 1, "ok": True, "data": "x" * (localapi.MAX_RESPONSE_BYTES + 10)})
        decoded = json.loads(big)
        self.assertEqual((decoded["id"], decoded["error"]), (1, "too_large"))
        self.assertTrue(big.endswith(b"\n"))
        self.assertEqual(big.count(b"\n"), 1)

    def test_answers_are_one_utf8_line(self) -> None:
        line = encode({"id": 1, "ok": True, "data": {"name": "Año\nnuevo"}})
        self.assertEqual(line.count(b"\n"), 1)
        self.assertEqual(json.loads(line.decode("utf-8"))["data"]["name"], "Año\nnuevo")


class PermissionTests(unittest.TestCase):
    def test_the_table_is_the_spec(self) -> None:
        reads = {"status", "about", "settings.get"}
        self.assertEqual({op for op, kind in OPERATIONS.items() if kind == ADMIN_READ}, {"log"})
        acts = {"run", "pause", "resume", "settings.set", "probe", "test_connection", "connect", "disconnect",
                "netbox.export", "support_bundle", "check_update", "reseal.decide"}
        self.assertEqual({op for op, kind in OPERATIONS.items() if kind == READ}, reads)
        self.assertEqual({op for op, kind in OPERATIONS.items() if kind == ACT}, acts)

    def test_matrix(self) -> None:
        for op, kind in OPERATIONS.items():
            with self.subTest(op=op):
                self.assertTrue(may(op, ADMIN))
                self.assertEqual(may(op, USER), kind == READ)
                self.assertEqual(may(op, ANONYMOUS), kind == READ)

    def test_an_unknown_operation_is_allowed_to_nobody(self) -> None:
        self.assertFalse(may("format_disk", ADMIN))
        self.assertFalse(may("", ADMIN))

    def test_linux_root_or_the_service_account_may_act(self) -> None:
        self.assertTrue(posix_may_act(0, 999))
        self.assertTrue(posix_may_act(999, 999))
        self.assertFalse(posix_may_act(1000, 999))
        self.assertFalse(posix_may_act(None, 999))
        self.assertFalse(posix_may_act(-1, -1))  # sin uid conocido, nadie

    def test_windows_admin_means_the_group_enabled_not_deny_only(self) -> None:
        admins = "S-1-5-32-544"
        self.assertTrue(groups_grant_admin([("S-1-1-0", 7), (admins, 0xF)]))  # elevado
        self.assertFalse(groups_grant_admin([(admins, 0x10)]))  # UAC sin elevar: solo para denegar
        self.assertFalse(groups_grant_admin([(admins, 0x14)]))  # habilitado pero solo para denegar
        self.assertFalse(groups_grant_admin([(admins, 0x0)]))  # deshabilitado
        self.assertFalse(groups_grant_admin([("S-1-5-32-545", 0x7)]))  # Usuarios
        self.assertFalse(groups_grant_admin([]))

    def test_a_client_only_talks_to_a_pipe_owned_by_system_admins_or_itself(self) -> None:
        me = "S-1-5-21-1-2-3-1001"
        self.assertTrue(trusted_pipe_owner("S-1-5-18", me))
        self.assertTrue(trusted_pipe_owner("S-1-5-32-544", me))
        self.assertTrue(trusted_pipe_owner(me, me))
        self.assertFalse(trusted_pipe_owner("S-1-5-21-9-9-9-1002", me))
        self.assertFalse(trusted_pipe_owner("", ""))

    def test_the_pipe_never_lets_users_create_instances_nor_the_network_in(self) -> None:
        sddl = pipe_sddl("S-1-5-21-1-2-3-1001")
        self.assertTrue(sddl.startswith("D:P(D;;GA;;;NU)"))
        user_ace = [ace for ace in sddl.split(")") if ace.endswith(";;;AU")][0]
        rights = int(user_ace.split(";")[2], 16)
        self.assertFalse(rights & 0x4, "FILE_CREATE_PIPE_INSTANCE")
        self.assertFalse(rights & 0x40000000, "GENERIC_WRITE")
        self.assertFalse(rights & 0xC0000, "WRITE_DAC / WRITE_OWNER")
        self.assertTrue(rights & 0x1 and rights & 0x2)  # leer y escribir datos
        self.assertIn("(A;;GA;;;S-1-5-21-1-2-3-1001)", sddl)
        self.assertNotIn("S-1-5-18)", pipe_sddl("S-1-5-18").replace("(A;;GA;;;SY)", ""))


class DispatcherTests(unittest.TestCase):
    def make(self, **handlers) -> Dispatcher:  # noqa: ANN003
        return Dispatcher(handlers)

    def test_a_handler_answers_with_its_data(self) -> None:
        dispatcher = self.make(status=lambda args, caller: {"seen": args, "admin": caller.admin})
        answer = dispatcher.handle_line(b'{"id": 3, "op": "status", "args": {"a": 1}}', USER)
        self.assertEqual(answer, {"id": 3, "ok": True, "data": {"seen": {"a": 1}, "admin": False}})

    def test_every_act_is_refused_to_a_reader_before_its_handler_runs(self) -> None:
        called: list[str] = []
        handlers = {op: (lambda op: lambda args, caller: called.append(op))(op) for op in OPERATIONS}
        dispatcher = Dispatcher(handlers)
        for op, kind in OPERATIONS.items():
            with self.subTest(op=op):
                answer = dispatcher.handle_line(json.dumps({"id": 1, "op": op}).encode(), USER)
                if kind in (ACT, ADMIN_READ):
                    self.assertEqual((answer["ok"], answer["error"]), (False, "forbidden"))
                else:
                    self.assertTrue(answer["ok"])
        self.assertEqual(sorted(called), sorted(op for op, kind in OPERATIONS.items() if kind == READ))

    def test_unknown_and_unimplemented_operations(self) -> None:
        dispatcher = self.make()
        self.assertEqual(dispatcher.handle_line(b'{"id":1,"op":"rm -rf"}', ADMIN)["error"], "unknown_op")
        self.assertEqual(dispatcher.handle_line(b'{"id":1,"op":"status"}', ADMIN)["error"], "unavailable")
        with self.assertRaises(ValueError):
            Dispatcher({"not_in_table": lambda a, c: None})

    def test_a_coded_refusal_carries_its_details(self) -> None:
        def handler(args, caller):  # noqa: ANN001, ANN202
            raise OpError("invalid", "Mal.", fields={"proxy": "no"})

        answer = self.make(**{"settings.set": handler}).handle_line(b'{"id":1,"op":"settings.set"}', ADMIN)
        self.assertEqual(answer, {"id": 1, "ok": False, "error": "invalid", "message": "Mal.", "details": {"fields": {"proxy": "no"}}})

    def test_a_crashing_handler_is_an_answer_that_does_not_repeat_its_text(self) -> None:
        def handler(args, caller):  # noqa: ANN001, ANN202
            raise RuntimeError(f"fallo con {args['token']}")

        answer = self.make(**{"netbox.export": handler}).handle_line(
            b'{"id":1,"op":"netbox.export","args":{"token":"nbt_SECRETO"}}', ADMIN
        )
        self.assertEqual(answer["error"], "internal")
        self.assertIn("RuntimeError", answer["message"])
        self.assertNotIn("nbt_SECRETO", json.dumps(answer))


class FakeConnection:
    """Una conexión de mentira: lo que el «cliente» manda, a trozos y con pausas."""

    def __init__(self, chunks: list[bytes | float | None]) -> None:
        #: bytes = llega eso; float = silencio de esos segundos; None = el cliente cierra.
        self.chunks = list(chunks)
        self.sent: list[dict] = []
        self.closed = False

    def recv(self, timeout: float) -> bytes:
        if not self.chunks:
            time.sleep(timeout)
            raise TimeoutError
        item = self.chunks[0]
        if item is None:
            return b""
        if isinstance(item, float):
            nap = min(item, timeout)
            time.sleep(nap)
            if item - nap > 1e-6:
                self.chunks[0] = item - nap
            else:
                self.chunks.pop(0)
            raise TimeoutError
        self.chunks.pop(0)
        return item

    def send(self, data: bytes, timeout: float) -> None:
        for line in data.splitlines():
            self.sent.append(json.loads(line))

    def close(self) -> None:
        self.closed = True


class ConversationTests(unittest.TestCase):
    def dispatcher(self) -> Dispatcher:
        return Dispatcher({"status": lambda args, caller: {"who": caller.who}, "pause": lambda a, c: {"ok": 1}})

    def test_a_conversation_survives_garbage_and_oversized_lines(self) -> None:
        conn = FakeConnection([
            b'{"id":1,"op":"status"}\nbasura\n',
            b"x" * (localapi.MAX_REQUEST_BYTES + 5) + b"\n",
            b'{"id":2,"op":"pause"}\n',
            None,
        ])
        serve_connection(conn, self.dispatcher(), lambda: USER)
        self.assertEqual([(a["id"], a["ok"], a.get("error")) for a in conn.sent],
                         [(1, True, None), (None, False, "bad_request"), (None, False, "too_large"), (2, False, "forbidden")])
        self.assertTrue(conn.closed)

    def test_identity_is_asked_once_after_the_first_read(self) -> None:
        asked: list[int] = []

        def identify() -> Caller:
            asked.append(1)
            return USER

        conn = FakeConnection([b'{"id":1,"op":"status"}\n', b'{"id":2,"op":"status"}\n', None])
        serve_connection(conn, self.dispatcher(), identify)
        self.assertEqual(asked, [1])
        self.assertEqual(conn.sent[0]["data"], {"who": USER.who})

    def test_an_identification_that_fails_can_only_read(self) -> None:
        def identify() -> Caller:
            raise OSError("no se pudo suplantar")

        conn = FakeConnection([b'{"id":1,"op":"pause"}\n', None])
        serve_connection(conn, self.dispatcher(), identify)
        self.assertEqual(conn.sent[0]["error"], "forbidden")

    def test_a_client_that_says_nothing_is_dropped(self) -> None:
        conn = FakeConnection([])
        started = time.monotonic()
        serve_connection(conn, self.dispatcher(), lambda: USER, first_line_seconds=0.2)
        self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(conn.closed)

    def test_a_request_that_never_finishes_arriving_is_dropped(self) -> None:
        conn = FakeConnection([b'{"id":1,', 5.0, b'"op":"status"}\n'])
        started = time.monotonic()
        serve_connection(conn, self.dispatcher(), lambda: USER, line_seconds=0.3)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(conn.sent, [])

    def test_an_idle_client_is_dropped_after_its_answers(self) -> None:
        conn = FakeConnection([b'{"id":1,"op":"status"}\n'])
        serve_connection(conn, self.dispatcher(), lambda: USER, idle_seconds=0.3)
        self.assertEqual(len(conn.sent), 1)
        self.assertTrue(conn.closed)

    def test_a_client_that_does_not_read_its_answer_is_dropped(self) -> None:
        class NotReading(FakeConnection):
            def send(self, data: bytes, timeout: float) -> None:
                raise TimeoutError

        conn = NotReading([b'{"id":1,"op":"status"}\n', b'{"id":2,"op":"status"}\n'])
        serve_connection(conn, self.dispatcher(), lambda: USER)
        self.assertTrue(conn.closed)

    def test_stop_ends_the_conversation_promptly(self) -> None:
        stop = threading.Event()
        conn = FakeConnection([])
        thread = threading.Thread(target=serve_connection, args=(conn, self.dispatcher(), lambda: USER),
                                  kwargs={"stop": stop, "first_line_seconds": 60}, daemon=True)
        thread.start()
        stop.set()
        thread.join(timeout=3)
        self.assertFalse(thread.is_alive())

    def test_one_caller_cannot_take_every_slot(self) -> None:
        admission = Admission(total=4, per_caller=2)
        for _ in range(2):
            self.assertTrue(admission.claim(USER))
        conn = FakeConnection([b'{"id":1,"op":"status"}\n', None])
        serve_connection(conn, self.dispatcher(), lambda: USER, admission=admission)
        self.assertEqual(conn.sent[0]["error"], "busy")
        # Otro usuario sí entra, y su hueco se devuelve al irse.
        other = FakeConnection([b'{"id":1,"op":"status"}\n', None])
        serve_connection(other, self.dispatcher(), lambda: ADMIN, admission=admission)
        self.assertTrue(other.sent[0]["ok"])
        self.assertTrue(admission.claim(ADMIN) and admission.claim(ADMIN))

    def test_readers_never_take_the_slots_kept_for_admins(self) -> None:
        admission = Admission(total=8, per_caller=8, reserve=2)
        readers = [Caller(admin=False, who=f"S-1-5-21-{n}") for n in range(8)]
        self.assertEqual(sum(admission.claim(reader) for reader in readers), 6)
        self.assertTrue(admission.claim(ADMIN) and admission.claim(ADMIN))
        self.assertFalse(admission.claim(ADMIN))

    def test_admission_counts_connections(self) -> None:
        admission = Admission(total=2, pending=2)
        self.assertTrue(admission.enter() and admission.enter())
        self.assertFalse(admission.enter())
        admission.leave()
        self.assertTrue(admission.enter())


if __name__ == "__main__":
    unittest.main()
