"""The local channel client (agent/app/channel.py) against the fake service.

Over the real transport of the platform: a named pipe on Windows (needs
pywin32), a Unix socket elsewhere. Always on a random name: never the pipe of
an agent installed on the machine running the tests.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - entorno de pruebas (canal falso, estado temporal)

import importlib.util
import os
import sys
import threading
import time
import unittest
from unittest import mock

from agent.app import channel, fake_server

if sys.platform == "win32":
    HAS_TRANSPORT = importlib.util.find_spec("win32file") is not None
else:
    HAS_TRANSPORT = hasattr(__import__("socket"), "AF_UNIX")


class AddressTests(unittest.TestCase):
    def test_the_environment_points_the_client_elsewhere(self) -> None:
        if sys.platform == "win32":
            self.assertEqual(channel.default_address({channel.ADDRESS_ENV_VAR: r"\\.\pipe\x"}), r"\\.\pipe\x")
        else:
            self.assertEqual(channel.default_address({channel.SOCKET_ENV_VAR: "/tmp/x.sock"}), "/tmp/x.sock")
        self.assertTrue(channel.address_overridden())  # agent/tests lo fija: nunca el de verdad

    def test_the_tests_never_default_to_the_real_pipe(self) -> None:
        self.assertFalse(channel.is_default_address(channel.default_address()))

    def test_the_real_pipe_is_recognised(self) -> None:
        self.assertTrue(channel.is_default_address(r"\\.\PIPE\CenyaAgent"))
        self.assertFalse(channel.is_default_address(channel.random_pipe_name()))

    def test_the_fake_server_refuses_the_real_pipe(self) -> None:
        with self.assertRaises(ValueError):
            fake_server.FakeServer(fake_server.FakeAgent("idle"), channel.DEFAULT_PIPE)


@unittest.skipUnless(HAS_TRANSPORT, "sin transporte local en esta plataforma")
class OverTheRealTransportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.agent = fake_server.FakeAgent("running", speed=20)
        self.server = fake_server.FakeServer(self.agent).start()
        self.client = channel.ChannelClient(self.server.address)

    def tearDown(self) -> None:
        self.client.close()
        self.server.stop()

    def test_status_round_trip(self) -> None:
        data = self.client.request("status")
        self.assertEqual(data["state"], "running")
        self.assertEqual(data["activity"]["task"], "inventory")

    def test_connections_are_reused(self) -> None:
        for _ in range(5):
            self.client.request("status")
        self.assertLessEqual(len(self.client._idle), 1)

    def test_errors_carry_the_service_code_and_message(self) -> None:
        with self.assertRaises(channel.ChannelError) as caught:
            self.client.request("no.such.op")
        self.assertEqual(caught.exception.code, "unknown_op")
        self.assertTrue(caught.exception.message)

    def test_acting_without_permission_is_forbidden(self) -> None:
        self.server.admin = False
        with self.assertRaises(channel.ChannelError) as caught:
            self.client.request("run", {"task": "presence"})
        self.assertEqual(caught.exception.code, channel.FORBIDDEN)
        self.assertEqual(self.client.request("status")["state"], "running")  # leer, sí

    def test_a_long_operation_does_not_block_status(self) -> None:
        self.agent.speed = 2.0  # ~4 s de exportación
        done = threading.Event()

        def export() -> None:
            self.client.request("netbox.export", {"url": "https://nb", "token": "t", "send": True})
            done.set()

        threading.Thread(target=export, daemon=True).start()
        time.sleep(0.3)
        started = time.monotonic()
        status = self.client.request("status")
        self.assertLess(time.monotonic() - started, 1.0)
        # Como el servicio de verdad: el avance de lo largo va en `local`.
        self.assertEqual(status["local"]["netbox_export"]["state"], "running")
        self.assertTrue(done.wait(15))

    def test_nobody_listening_is_service_down(self) -> None:
        with self.assertRaises(channel.ChannelError) as caught:
            channel.ChannelClient(channel.random_pipe_name()).request("status")
        self.assertEqual(caught.exception.code, channel.SERVICE_DOWN)


class _Conn:
    def __init__(self, script: list[object]) -> None:
        self.script = script
        self.sent: list[bytes] = []
        self.closed = False

    def send(self, data: bytes, timeout: float) -> None:
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        self.sent.append(data)

    def read_line(self, timeout: float) -> bytes:
        step = self.script.pop(0)
        if isinstance(step, Exception):
            raise step
        if callable(step):
            return step(self.sent[-1])
        return step  # type: ignore[return-value]

    def close(self) -> None:
        self.closed = True


def _echo_ok(sent: bytes) -> bytes:
    import json

    return json.dumps({"id": json.loads(sent)["id"], "ok": True, "data": {"x": 1}}).encode()


class RetryRulesTests(unittest.TestCase):
    def _client(self, connections: list[_Conn]) -> channel.ChannelClient:
        pending = list(connections)
        return channel.ChannelClient("unused", opener=lambda address, timeout: pending.pop(0))

    def test_a_dead_pooled_connection_is_replaced_for_a_read(self) -> None:
        dead = _Conn([None, _echo_ok, channel.ChannelError(channel.BROKEN)])
        fresh = _Conn([None, _echo_ok])
        client = self._client([dead, fresh])
        client.request("status")  # deja `dead` en la reserva
        self.assertEqual(client.request("status"), {"x": 1})
        self.assertTrue(dead.closed)

    def test_an_action_that_may_have_been_delivered_is_never_repeated(self) -> None:
        first = _Conn([None, _echo_ok, None, channel.ChannelError(channel.BROKEN)])
        never = _Conn([None, _echo_ok])
        client = self._client([first, never])
        client.request("status")
        with self.assertRaises(channel.ChannelError):
            client.request("run", {"task": "presence"})
        self.assertEqual(never.sent, [])

    def test_an_action_that_never_left_is_retried(self) -> None:
        first = _Conn([None, _echo_ok, channel.ChannelError(channel.BROKEN)])
        fresh = _Conn([None, _echo_ok])
        client = self._client([first, fresh])
        client.request("status")
        self.assertEqual(client.request("run", {"task": "presence"}), {"x": 1})

    def test_late_answers_to_other_requests_are_skipped(self) -> None:
        conn = _Conn([None, b'{"id": 999, "ok": true, "data": {}}', _echo_ok])
        self.assertEqual(self._client([conn]).request("status"), {"x": 1})

    def test_an_answer_to_the_connection_is_an_error_not_a_hang(self) -> None:
        # Demasiadas conexiones: el servicio contesta sin `id` y cierra.
        conn = _Conn([None, b'{"id": null, "ok": false, "error": "busy", "message": "x"}'])
        with self.assertRaises(channel.ChannelError) as caught:
            self._client([conn]).request("status")
        self.assertEqual(caught.exception.code, "busy")

    def test_a_refusal_keeps_the_connection_and_its_details(self) -> None:
        import json

        def refuse(sent: bytes) -> bytes:
            message_id = json.loads(sent)["id"]
            return json.dumps({"id": message_id, "ok": False, "error": "invalid", "message": "m", "details": {"fields": {"proxy": "p"}}}).encode()

        conn = _Conn([None, refuse, None, _echo_ok])
        client = self._client([conn])
        with self.assertRaises(channel.ChannelError) as caught:
            client.request("settings.set", {"proxy": {}})
        self.assertEqual(caught.exception.details, {"fields": {"proxy": "p"}})
        self.assertFalse(conn.closed)
        self.assertEqual(client.request("status"), {"x": 1})

    def test_only_the_service_or_oneself_owns_the_pipe(self) -> None:
        self.assertTrue(channel.trusted_pipe_owner("S-1-5-18", "S-1-5-21-1"))
        self.assertTrue(channel.trusted_pipe_owner("S-1-5-32-544", "S-1-5-21-1"))
        self.assertTrue(channel.trusted_pipe_owner("S-1-5-21-1", "S-1-5-21-1"))
        self.assertFalse(channel.trusted_pipe_owner("S-1-5-21-2", "S-1-5-21-1"))
        self.assertFalse(channel.trusted_pipe_owner("", ""))

    def test_the_pipe_is_opened_as_the_service_allows(self) -> None:
        # GENERIC_READ | FILE_WRITE_DATA: con GENERIC_WRITE, Windows lo negaría.
        self.assertEqual(channel.CLIENT_ACCESS, 0x80000002)

    def test_a_short_pipe_name_gets_its_prefix(self) -> None:
        if sys.platform != "win32":
            self.skipTest("solo Windows")
        self.assertEqual(channel.default_address({channel.ADDRESS_ENV_VAR: "Otro"}), r"\\.\pipe\Otro")

    def test_garbage_is_a_bad_response(self) -> None:
        conn = _Conn([None, b"not json"])
        with self.assertRaises(channel.ChannelError) as caught:
            self._client([conn]).request("status")
        self.assertEqual(caught.exception.code, channel.BAD_RESPONSE)

    def test_the_arguments_travel_only_down_the_channel(self) -> None:
        conn = _Conn([None, _echo_ok])
        with mock.patch("logging.Logger._log") as logged:
            self._client([conn]).request("netbox.export", {"token": "s3cret"})
        self.assertIn(b"s3cret", conn.sent[0])
        logged.assert_not_called()


if __name__ == "__main__":
    unittest.main()
