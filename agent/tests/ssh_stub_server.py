"""A just-enough SSH server to see what a real ``ssh`` client sends as a password.

No SSH server could be assumed on the machine that wrote this (Windows without
administrator rights has no ``sshd``), and a mock of ``subprocess`` proves
nothing about OpenSSH's askpass mechanism. So this speaks the actual protocol
(RFC 4253/4252/4254, curve25519 + ed25519 + aes128-ctr + hmac-sha2-256) well
enough for one real ``ssh`` binary to authenticate by password and run one
``exec`` request, and it **records the exact bytes of every password it was
offered**. That is the observable the tests need: not "the helper printed
something" but "the server received exactly this secret".

It is test code only. It needs the ``cryptography`` package, which the agent
does not (and must not) depend on, so the tests that use it skip themselves
when it is missing. Binds to 127.0.0.1 on an ephemeral port, serves in a
thread, and ``close()`` leaves nothing running.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket
import struct
import threading
from dataclasses import dataclass, field

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    AVAILABLE = False

BANNER = b"SSH-2.0-cenya_test_server"


def _string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _mpint(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b""
    if raw and raw[0] & 0x80:
        raw = b"\x00" + raw
    return _string(raw)


def _name_list(*names: str) -> bytes:
    return _string(",".join(names).encode())


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def byte(self) -> int:
        self.pos += 1
        return self.data[self.pos - 1]

    def uint32(self) -> int:
        self.pos += 4
        return struct.unpack(">I", self.data[self.pos - 4 : self.pos])[0]

    def string(self) -> bytes:
        size = self.uint32()
        self.pos += size
        return self.data[self.pos - size : self.pos]


@dataclass
class Attempt:
    """One authentication attempt as the server saw it."""

    username: str
    method: str
    password: bytes | None = None


@dataclass
class _Transport:
    sock: socket.socket
    send_seq: int = 0
    recv_seq: int = 0
    encryptor: object = None
    decryptor: object = None
    mac_send: bytes = b""
    mac_recv: bytes = b""
    buffer: bytearray = field(default_factory=bytearray)

    def read_exact(self, size: int) -> bytes:
        while len(self.buffer) < size:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            self.buffer += chunk
        data = bytes(self.buffer[:size])
        del self.buffer[:size]
        return data

    def send(self, payload: bytes) -> None:
        block = 16 if self.encryptor else 8
        padding = block - ((5 + len(payload)) % block)
        if padding < 4:
            padding += block
        packet = struct.pack(">IB", 1 + len(payload) + padding, padding) + payload + os.urandom(padding)
        if self.encryptor:
            mac = hmac.new(self.mac_send, struct.pack(">I", self.send_seq) + packet, hashlib.sha256).digest()
            packet = self.encryptor.update(packet) + mac  # type: ignore[attr-defined]
        self.send_seq = (self.send_seq + 1) & 0xFFFFFFFF
        self.sock.sendall(packet)

    def receive(self) -> bytes:
        if self.decryptor:
            head = self.decryptor.update(self.read_exact(4))  # type: ignore[attr-defined]
            size = struct.unpack(">I", head)[0]
            body = self.decryptor.update(self.read_exact(size))  # type: ignore[attr-defined]
            packet = head + body
            mac = self.read_exact(32)
            expected = hmac.new(self.mac_recv, struct.pack(">I", self.recv_seq) + packet, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected):
                raise ConnectionError("bad mac")
        else:
            head = self.read_exact(4)
            size = struct.unpack(">I", head)[0]
            packet = head + self.read_exact(size)
        self.recv_seq = (self.recv_seq + 1) & 0xFFFFFFFF
        padding = packet[4]
        return packet[5 : len(packet) - padding]


class StubSshServer:
    """Accepts password ``expected`` for any user; echoes ``output`` to an exec.

    ``methods`` is what it offers, in order: ``password`` and/or
    ``keyboard-interactive`` (one prompt, "Password: "), which is what Cisco
    IOS, a PAM Linux or a FortiGate offer. Every request is recorded in
    ``attempts``, including the ``none`` probe a client sends first to learn
    the methods (it carries no secret and is not a failed login).
    """

    def __init__(
        self,
        *,
        expected: bytes | None = None,
        output: bytes = b"hello-from-stub\n",
        methods: tuple[str, ...] = ("password",),
    ) -> None:
        self.expected = expected
        self.output = output
        self.methods = methods
        self.attempts: list[Attempt] = []
        self.errors: list[str] = []
        self._host_key = ed25519.Ed25519PrivateKey.generate()
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self._listener.settimeout(0.2)
        self.port: int = self._listener.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)
        self._listener.close()

    def __enter__(self) -> "StubSshServer":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except (socket.timeout, OSError):
                continue
            conn.settimeout(10)
            try:
                self._session(conn)
            except (ConnectionError, OSError, struct.error, IndexError) as exc:
                self.errors.append(f"{type(exc).__name__}: {exc}")
            finally:
                conn.close()

    # -- protocol ---------------------------------------------------------------

    def _session(self, sock: socket.socket) -> None:
        transport = _Transport(sock)
        sock.sendall(BANNER + b"\r\n")
        client_banner = b""
        while not client_banner.endswith(b"\n"):
            client_banner += transport.read_exact(1)
        client_banner = client_banner.rstrip(b"\r\n")

        kexinit = (
            bytes([20])
            + os.urandom(16)
            + _name_list("curve25519-sha256")
            + _name_list("ssh-ed25519")
            + _name_list("aes128-ctr")
            + _name_list("aes128-ctr")
            + _name_list("hmac-sha2-256")
            + _name_list("hmac-sha2-256")
            + _name_list("none")
            + _name_list("none")
            + _name_list()
            + _name_list()
            + bytes([0])
            + struct.pack(">I", 0)
        )
        transport.send(kexinit)
        client_kexinit = transport.receive()
        init = transport.receive()
        reader = _Reader(init)
        if reader.byte() != 30:
            raise ConnectionError("expected KEX_ECDH_INIT")
        client_public = reader.string()

        private = x25519.X25519PrivateKey.generate()
        server_public = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(client_public))
        secret = int.from_bytes(shared, "big")
        host_blob = _string(b"ssh-ed25519") + _string(
            self._host_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        exchange_hash = hashlib.sha256(
            _string(client_banner)
            + _string(BANNER)
            + _string(client_kexinit)
            + _string(kexinit)
            + _string(host_blob)
            + _string(client_public)
            + _string(server_public)
            + _mpint(secret)
        ).digest()
        signature = _string(b"ssh-ed25519") + _string(self._host_key.sign(exchange_hash))
        transport.send(bytes([31]) + _string(host_blob) + _string(server_public) + _string(signature))
        transport.send(bytes([21]))
        if transport.receive() != bytes([21]):
            raise ConnectionError("expected NEWKEYS")

        def derive(letter: bytes, size: int) -> bytes:
            return hashlib.sha256(_mpint(secret) + exchange_hash + letter + exchange_hash).digest()[:size]

        transport.decryptor = Cipher(algorithms.AES(derive(b"C", 16)), modes.CTR(derive(b"A", 16))).decryptor()
        transport.encryptor = Cipher(algorithms.AES(derive(b"D", 16)), modes.CTR(derive(b"B", 16))).encryptor()
        transport.mac_recv = derive(b"E", 32)
        transport.mac_send = derive(b"F", 32)

        self._authenticate(transport)
        self._channel(transport)

    def _authenticate(self, transport: _Transport) -> None:
        request = transport.receive()
        reader = _Reader(request)
        if reader.byte() != 5:
            raise ConnectionError("expected SERVICE_REQUEST")
        transport.send(bytes([6]) + _string(reader.string()))
        while True:
            reader = _Reader(transport.receive())
            if reader.byte() != 50:
                raise ConnectionError("expected USERAUTH_REQUEST")
            username = reader.string().decode("utf-8", "replace")
            reader.string()  # service
            method = reader.string().decode()
            attempt = Attempt(username=username, method=method)
            self.attempts.append(attempt)
            if method == "password" and method in self.methods:
                reader.byte()  # "change password" flag
                attempt.password = reader.string()
            elif method == "keyboard-interactive" and method in self.methods:
                # USERAUTH_INFO_REQUEST: nombre, instrucción, idioma, un prompt sin eco.
                transport.send(
                    bytes([60]) + _string(b"") + _string(b"") + _string(b"")
                    + struct.pack(">I", 1) + _string(b"Password: ") + bytes([0])
                )
                reply = _Reader(transport.receive())
                if reply.byte() != 61:
                    raise ConnectionError("expected USERAUTH_INFO_RESPONSE")
                attempt.password = reply.string() if reply.uint32() else b""
            if attempt.password is not None and self.expected is not None and attempt.password == self.expected:
                transport.send(bytes([52]))
                return
            transport.send(bytes([51]) + _name_list(*self.methods) + bytes([0]))

    def failed_logins(self) -> list[Attempt]:
        """What a lockout policy counts: every attempt that carried a secret and failed."""
        return [a for a in self.attempts if a.password is not None and a.password != self.expected]

    def _channel(self, transport: _Transport) -> None:
        remote_channel = 0
        while True:
            reader = _Reader(transport.receive())
            kind = reader.byte()
            if kind == 90:  # CHANNEL_OPEN
                reader.string()
                remote_channel = reader.uint32()
                transport.send(
                    bytes([91]) + struct.pack(">IIII", remote_channel, 0, 2097152, 32768)
                )
            elif kind == 98:  # CHANNEL_REQUEST
                reader.uint32()
                name = reader.string()
                want_reply = reader.byte()
                if name == b"exec":
                    if want_reply:
                        transport.send(bytes([99]) + struct.pack(">I", remote_channel))
                    transport.send(bytes([94]) + struct.pack(">I", remote_channel) + _string(self.output))
                    transport.send(
                        bytes([98])
                        + struct.pack(">I", remote_channel)
                        + _string(b"exit-status")
                        + bytes([0])
                        + struct.pack(">I", 0)
                    )
                    transport.send(bytes([96]) + struct.pack(">I", remote_channel))
                    transport.send(bytes([97]) + struct.pack(">I", remote_channel))
                elif want_reply:
                    transport.send(bytes([99]) + struct.pack(">I", remote_channel))
            elif kind == 97:  # CHANNEL_CLOSE
                return
            elif kind == 1:  # DISCONNECT
                return
            # Window adjusts, EOF, global requests and the rest: nothing to say.
