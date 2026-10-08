"""The credential-less fingerprint collector: parsers on hand-built bytes, and
the probes against throwaway servers on 127.0.0.1. No real network."""

from __future__ import annotations

import base64
import os
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from agent.collectors import RUN_ORDER, all_collectors
from agent.collectors import fingerprint as fp
from agent.collectors.fingerprint import FingerprintCollector
from agent.tasks import TASK_COLLECTORS

CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIBzjCCAXSgAwIBAgIUUC3wXHcgL6LFRckbxCn0HVB6SsYwCgYIKoZIzj0EAwIw
KjEZMBcGA1UEAwwQcHZlMS5leGFtcGxlLmxhbjENMAsGA1UECgwEVGVzdDAgFw0y
NjEwMDgxOTMyMDdaGA8yMTI2MDkxNDE5MzIwN1owKjEZMBcGA1UEAwwQcHZlMS5l
eGFtcGxlLmxhbjENMAsGA1UECgwEVGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABNrms0ZO5EqtCsE3L3jCcywJwkTHJ08y3twZiTFIPX7RsT8AVRu8fXRSk5EQ
7IVQBj6d/4fDxxXPIJyN4WPFl/KjdjB0MB0GA1UdDgQWBBTZn5jZtiBq4q3yWHOR
2tbeTbl6uDAfBgNVHSMEGDAWgBTZn5jZtiBq4q3yWHOR2tbeTbl6uDAPBgNVHRMB
Af8EBTADAQH/MCEGA1UdEQQaMBiCEHB2ZTEuZXhhbXBsZS5sYW6CBHB2ZTEwCgYI
KoZIzj0EAwIDSAAwRQIgO4cpmOE+0gOP/51O5eI4QmO6W6b7hGeT5Q9Aem0NCwIC
IQCTB9hU1COargv9HePRbJAbxIAM7sdUastxzfnO5buPCw==
-----END CERTIFICATE-----
"""


def av(av_id: int, text: str) -> bytes:
    raw = text.encode("utf-16-le")
    return struct.pack("<HH", av_id, len(raw)) + raw


def challenge(version: tuple[int, int, int] | None = (10, 0, 20348), **names: str) -> bytes:
    """An NTLMSSP CHALLENGE built by hand, as a server would send it."""
    ids = {"nb_name": 1, "nb_domain": 2, "dns_name": 3, "dns_domain": 4, "dns_tree": 5}
    info = b"".join(av(ids[key], value) for key, value in names.items())
    info += struct.pack("<HHQ", 7, 8, 132000000000000000)  # MsvAvTimestamp
    info += struct.pack("<HH", 0, 0)  # MsvAvEOL
    flags = 0x00000001 | 0x00800000 | (0x02000000 if version else 0)
    target = "ACME".encode("utf-16-le")
    head = fp.NTLM_SIGNATURE + struct.pack("<IHHII", 2, len(target), len(target), 56, flags)
    head += struct.pack("<Q", 0x1122334455667788) + struct.pack("<Q", 0)
    head += struct.pack("<HHI", len(info), len(info), 56 + len(target))
    major, minor, build = version or (0, 0, 0)
    head += struct.pack("<BBH3xB", major, minor, build, 15)
    return head + target + info


class ParserTests(unittest.TestCase):
    def test_challenge_names_domain_and_version(self) -> None:
        blob = challenge(
            nb_name="SRV01", nb_domain="ACME", dns_name="srv01.acme.lan", dns_domain="acme.lan", dns_tree="acme.lan"
        )
        self.assertEqual(
            fp.parse_ntlm_challenge(blob),
            {
                "os_version": "10.0.20348",
                "nb_name": "SRV01",
                "nb_domain": "ACME",
                "dns_name": "srv01.acme.lan",
                "dns_domain": "acme.lan",
                "dns_tree": "acme.lan",
            },
        )

    def test_challenge_found_inside_a_wrapper(self) -> None:
        blob = b"\xa1\x82\x01\x00junk" + challenge(nb_name="SRV01")
        self.assertEqual(fp.parse_ntlm_challenge(blob)["nb_name"], "SRV01")

    def test_challenge_without_version_flag_or_with_zero_build(self) -> None:
        self.assertNotIn("os_version", fp.parse_ntlm_challenge(challenge(None, nb_name="NAS")))
        self.assertNotIn("os_version", fp.parse_ntlm_challenge(challenge((6, 1, 0), nb_name="NAS")))

    def test_garbage_gives_nothing_and_never_raises(self) -> None:
        whole = challenge(nb_name="SRV01")
        for blob in (b"", b"NTLMSSP\x00", b"x" * 100, whole[:30], whole[:60]):
            self.assertIsInstance(fp.parse_ntlm_challenge(blob), dict)
        self.assertEqual(fp.parse_ntlm_challenge(b""), {})
        # A type 1 message is not a challenge.
        self.assertEqual(fp.parse_ntlm_challenge(fp.ntlm_negotiate()), {})

    def test_negotiate_is_type_1(self) -> None:
        message = fp.ntlm_negotiate()
        self.assertEqual(struct.unpack_from("<I", message, 8)[0], 1)
        self.assertEqual(len(message), 40)

    def test_windows_builds(self) -> None:
        self.assertEqual(fp.windows_name("6.1.7601"), "Windows 7 / Server 2008 R2")
        self.assertEqual(fp.windows_name("10.0.17763"), "Windows 10 1809 / Server 2019")
        self.assertEqual(fp.windows_name("10.0.20348"), "Windows Server 2022")
        self.assertEqual(fp.windows_name("10.0.22631"), "Windows 11 22H2/23H2")
        self.assertEqual(fp.windows_name("10.0.26100"), "Windows 11 24H2 / Server 2025")
        self.assertEqual(fp.windows_name("10.0.99999"), "Windows (build 10.0.99999)")
        self.assertEqual(fp.windows_name("nonsense"), "")

    def test_ssh_banner_and_distro(self) -> None:
        found = fp.parse_ssh_banner("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")
        self.assertEqual(found, {"ssh_banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", "distro": "Ubuntu"})
        self.assertEqual(fp.parse_ssh_banner("SSH-2.0-dropbear_2022.83"), {"ssh_banner": "SSH-2.0-dropbear_2022.83"})
        self.assertEqual(fp.parse_ssh_banner("HTTP/1.1 400 Bad request"), {})
        self.assertEqual(len(fp.parse_ssh_banner("SSH-2.0-" + "x" * 500)["ssh_banner"]), 200)

    def test_panels_by_title_and_certificate(self) -> None:
        self.assertEqual(fp.recognise_panel("pve1 - Proxmox Virtual Environment"), "Proxmox VE")
        self.assertEqual(fp.recognise_panel("VMware ESXi"), "VMware ESXi")
        self.assertEqual(fp.recognise_panel("", "", "Integrated Dell Remote Access Controller"), "iDRAC")
        self.assertEqual(fp.recognise_panel("Synology DiskStation"), "Synology DSM")
        self.assertEqual(fp.recognise_panel("UniFi OS"), "UniFi")
        self.assertEqual(fp.recognise_panel("Welcome to nginx!"), "")

    def test_page_title(self) -> None:
        self.assertEqual(fp.page_title(b"<html><TITLE>\n QNAP Turbo NAS </title>"), "QNAP Turbo NAS")
        self.assertEqual(fp.page_title(b"<html>no title"), "")

    def test_certificate(self) -> None:
        der = base64.b64decode("".join(CERT_PEM.splitlines()[1:-1]))
        self.assertEqual(
            fp.parse_certificate(der),
            {"cn": "pve1.example.lan", "san": ["pve1.example.lan", "pve1"], "issuer": "pve1.example.lan"},
        )
        self.assertEqual(fp.parse_certificate(b"\x30\x03abc"), {})
        self.assertEqual(fp.parse_certificate(b""), {})


def serve_once(handler) -> tuple[int, threading.Thread]:
    """A one-connection TCP server on 127.0.0.1; ``handler(conn)`` talks to it."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(5)

    def run() -> None:
        try:
            conn, _ = listener.accept()
            with conn:
                handler(conn)
        except OSError:
            pass
        finally:
            listener.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return listener.getsockname()[1], thread


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def smb_server(conn: socket.socket, seen: list[bytes], *, status: int = 0xC0000016, reply: bytes = b"") -> None:
    """Enough of SMB2 to answer the two requests the probe makes. Everything it
    receives goes into ``seen`` so a test can prove no AUTHENTICATE came."""
    for command in (0, 1):
        size = int.from_bytes(conn.recv(4)[1:], "big")
        data = b""
        while len(data) < size:
            data += conn.recv(size - len(data))
        seen.append(data)
        header = (
            b"\xfeSMB"
            + struct.pack("<HHIHHIIQIIQ", 64, 1, status if command else 0, command, 1, 1, 0, command, 0, 0, 0)
            + b"\x00" * 16
        )
        body = struct.pack("<HHH", 65, 0, 0x0311) + b"\x00" * 58 if command == 0 else struct.pack("<HHHH", 9, 0, 72, 0) + reply
        packet = header + body
        conn.sendall(b"\x00" + len(packet).to_bytes(3, "big") + packet)
    conn.settimeout(0.5)
    try:
        extra = conn.recv(4096)
        if extra:
            seen.append(extra)
    except OSError:
        pass


class ProbeTests(unittest.TestCase):
    def test_closed_ports_are_silent(self) -> None:
        port = closed_port()
        self.assertEqual(fp.probe_ssh("127.0.0.1", port, timeout=0.5), {})
        self.assertEqual(fp.probe_smb("127.0.0.1", port, timeout=0.5), {})
        self.assertEqual(fp.probe_rdp("127.0.0.1", port, timeout=0.5), {})
        self.assertEqual(fp.probe_https("127.0.0.1", port, timeout=0.5), {})

    def test_ssh_banner_is_read_and_nothing_sent(self) -> None:
        received: list[bytes] = []

        def handler(conn: socket.socket) -> None:
            conn.sendall(b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n")
            conn.settimeout(0.5)
            try:
                received.append(conn.recv(100))
            except OSError:
                pass

        port, thread = serve_once(handler)
        found = fp.probe_ssh("127.0.0.1", port, timeout=2)
        thread.join(3)
        self.assertEqual(found["distro"], "Debian")
        self.assertEqual([chunk for chunk in received if chunk], [])

    def test_smb_reads_the_challenge_and_sends_no_authenticate(self) -> None:
        seen: list[bytes] = []
        blob = challenge(nb_name="SRV01", nb_domain="ACME", dns_name="srv01.acme.lan")
        port, thread = serve_once(lambda conn: smb_server(conn, seen, reply=blob))
        found = fp.probe_smb("127.0.0.1", port, timeout=2)
        thread.join(3)
        self.assertEqual(found["nb_name"], "SRV01")
        self.assertEqual(found["os_version"], "10.0.20348")
        self.assertEqual(len(seen), 2, "only NEGOTIATE and the first SESSION_SETUP, nothing after")
        # The only NTLM message sent is a type 1 (NEGOTIATE).
        self.assertEqual(seen[1].count(fp.NTLM_SIGNATURE), 1)
        start = seen[1].find(fp.NTLM_SIGNATURE)
        self.assertEqual(struct.unpack_from("<I", seen[1], start + 8)[0], 1)

    def test_smb_refusing_the_login_start_is_silent(self) -> None:
        port, thread = serve_once(lambda conn: smb_server(conn, [], status=0xC000006D))
        self.assertEqual(fp.probe_smb("127.0.0.1", port, timeout=2), {})
        thread.join(3)

    def test_smb_garbage_is_silent(self) -> None:
        port, thread = serve_once(lambda conn: conn.sendall(b"HTTP/1.1 400 nope\r\n\r\n"))
        self.assertEqual(fp.probe_smb("127.0.0.1", port, timeout=1), {})
        thread.join(3)

    def test_rdp_without_tls_is_silent(self) -> None:
        def handler(conn: socket.socket) -> None:
            conn.recv(100)
            reply = bytes([14, 0xD0, 0, 0, 0, 0, 0]) + struct.pack("<BBHI", 2, 0, 8, 0)
            conn.sendall(b"\x03\x00" + (4 + len(reply)).to_bytes(2, "big") + reply)

        port, thread = serve_once(handler)
        self.assertEqual(fp.probe_rdp("127.0.0.1", port, timeout=2), {})
        thread.join(3)


@unittest.skipUnless(shutil.which("openssl"), "needs openssl to mint a throwaway certificate")
class HttpsTests(unittest.TestCase):
    def _server(self, body: bytes) -> tuple[int, threading.Thread, tempfile.TemporaryDirectory]:
        folder = tempfile.TemporaryDirectory()
        key, crt = Path(folder.name, "k.pem"), Path(folder.name, "c.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                "-keyout", str(key), "-out", str(crt), "-days", "2", "-subj", "/CN=pve1.example.lan",
            ],
            check=True,
            capture_output=True,
            env={**os.environ, "MSYS_NO_PATHCONV": "1"},
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(crt), str(key))

        def handler(conn: socket.socket) -> None:
            with context.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1000)
                tls.sendall(b"HTTP/1.0 200 OK\r\n\r\n" + body)

        port, thread = serve_once(handler)
        return port, thread, folder

    def test_panel_is_recognised_and_html_is_not_kept(self) -> None:
        port, thread, folder = self._server(b"<html><title>pve1 - Proxmox Virtual Environment</title>secret body</html>")
        found = fp.probe_https("127.0.0.1", port, timeout=3)
        thread.join(3)
        folder.cleanup()
        self.assertEqual(found["panel"], "Proxmox VE")
        self.assertEqual(found["cn"], "pve1.example.lan")
        self.assertNotIn("secret", repr(found))

    def test_unknown_page_sends_only_the_certificate(self) -> None:
        port, thread, folder = self._server(b"<html><title>Welcome to nginx!</title></html>")
        found = fp.probe_https("127.0.0.1", port, timeout=3)
        thread.join(3)
        folder.cleanup()
        self.assertNotIn("panel", found)
        self.assertEqual(found["cn"], "pve1.example.lan")


class AssemblyTests(unittest.TestCase):
    def test_a_windows_server(self) -> None:
        smb = {"os_version": "10.0.17763", "nb_name": "SRV01", "dns_name": "srv01.acme.lan", "dns_domain": "acme.lan"}
        fingerprint, hostname, os_hint = fp.assemble({445: smb, 3389: {"cert_cn": "srv01.acme.lan"}, 22: {}})
        self.assertEqual(hostname, "SRV01")
        self.assertEqual(os_hint, "Windows 10 1809 / Server 2019")
        self.assertEqual(fingerprint["smb"]["nb_name"], "SRV01")
        self.assertEqual(fingerprint["rdp"], {"cert_cn": "srv01.acme.lan"})

    def test_no_empty_keys_and_nothing_means_nothing(self) -> None:
        self.assertEqual(fp.assemble({22: {}, 445: {}, 3389: {}, 443: {}}), ({}, "", ""))
        fingerprint, _, _ = fp.assemble({22: {"ssh_banner": "SSH-2.0-x"}, 443: {"panel": "UniFi", "cn": ""}})
        self.assertEqual(fingerprint, {"ssh_banner": "SSH-2.0-x", "panel": "UniFi"})

    def test_linux_gets_its_distro_as_the_os_hint(self) -> None:
        _, hostname, os_hint = fp.assemble({22: {"ssh_banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3", "distro": "Ubuntu"}})
        self.assertEqual((hostname, os_hint), ("", "Ubuntu"))


class CollectorTests(unittest.TestCase):
    def test_runs_after_the_sweep_and_before_the_credentialed_ones(self) -> None:
        names = [collector.name for collector in all_collectors()]
        self.assertEqual(names, list(RUN_ORDER))
        self.assertLess(names.index("sweep"), names.index("fingerprint"))
        for later in ("snmp", "ssh", "winrm"):
            self.assertLess(names.index("fingerprint"), names.index(later))
        self.assertIn("fingerprint", TASK_COLLECTORS["inventory"])

    def test_without_the_sweep_it_is_silent(self) -> None:
        ctx: dict = {}
        self.assertEqual(FingerprintCollector().collect(ctx), [])
        self.assertEqual(ctx.get("errors", []), [])

    def test_closed_ports_give_no_finding_and_no_notes(self) -> None:
        ctx = {"hosts": [{"ip": "127.0.0.1", "mac": ""}]}
        with mock.patch.object(fp, "PORTS", (closed_port(), closed_port())):
            self.assertEqual(FingerprintCollector().collect(ctx), [])
        self.assertEqual(ctx.get("errors", []), [])

    def test_a_finding_per_host_with_the_sweep_identity(self) -> None:
        def fake(ip: str, port: int):
            if ip == "10.0.0.5" and port == fp.PORT_SMB:
                return ip, port, {"nb_name": "SRV01", "os_version": "10.0.20348"}
            return ip, port, {}

        ctx = {"hosts": [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:01"}, {"ip": "10.0.0.6", "mac": ""}]}
        with mock.patch.object(fp, "_probe", side_effect=fake):
            findings = FingerprintCollector().collect(ctx)
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual((finding.kind, finding.identity), ("host", {"mac": "aa:bb:cc:dd:ee:01"}))
        self.assertEqual(finding.payload["hostname"], "SRV01")
        self.assertEqual(finding.payload["os"], "Windows Server 2022")
        self.assertEqual(finding.payload["seen_by"], "fingerprint")
        self.assertNotIn("description", finding.payload)

    def test_excluded_hosts_are_never_touched(self) -> None:
        calls: list[str] = []
        ctx = {"hosts": [{"ip": "10.0.0.5", "mac": ""}], "excluded": {"10.0.0.5"}}
        with mock.patch.object(fp, "_probe", side_effect=lambda ip, port: calls.append(ip) or (ip, port, {})):
            FingerprintCollector().collect(ctx)
        self.assertEqual(calls, [])

    def test_a_probe_that_raises_costs_nothing(self) -> None:
        ctx = {"hosts": [{"ip": "10.0.0.5", "mac": ""}]}
        with mock.patch.object(fp, "probe_smb", side_effect=RuntimeError("boom")), \
             mock.patch.object(fp, "probe_ssh", return_value={}), \
             mock.patch.object(fp, "probe_rdp", return_value={}), \
             mock.patch.object(fp, "probe_https", return_value={}):
            self.assertEqual(FingerprintCollector().collect(ctx), [])


if __name__ == "__main__":
    unittest.main()
