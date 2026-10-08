"""The UDP probes of the fingerprint collector (NetBIOS, SSDP/UPnP, mDNS):
parsers on hand-built bytes, then each probe against a throwaway UDP server on
127.0.0.1. Ports are always ephemeral; nothing depends on the machine."""

from __future__ import annotations

import http.server
import socket
import struct
import threading
import unittest
from unittest import mock

from agent.collectors import fingerprint as fp
from agent.collectors.fingerprint import FingerprintCollector

NAS_XML = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
    <friendlyName>DS220 (nas01)</friendlyName>
    <manufacturer>Synology</manufacturer>
    <modelName>DS220+</modelName>
    <modelNumber>DS220+</modelNumber>
    <serialNumber>2010Q9N123456</serialNumber>
    <deviceList><device><friendlyName>inner</friendlyName></device></deviceList>
  </device>
</root>"""

PRINTER_XML = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device>
  <deviceType>urn:schemas-upnp-org:device:Printer:1</deviceType>
  <friendlyName>HP LaserJet M404</friendlyName>
  <manufacturer>HP</manufacturer><modelName>LaserJet Pro M404dn</modelName>
</device></root>"""


def nbstat_response(names: list[tuple[str, int, int]], mac: bytes, *, question: bool = True) -> bytes:
    """An NBSTAT reply as Windows/Samba send it: ``(name, suffix, flags)`` entries."""
    query = fp.netbios_query()
    head = struct.pack(">HHHHHH", fp._NBSTAT_ID, 0x8400, 1 if question else 0, 1, 0, 0)
    echoed = query[12:] if question else b""
    # The answer's name is a pointer to the question (0xC00C) when it was echoed.
    owner = b"\xc0\x0c" if question else query[12:-4]
    body = bytes([len(names)])
    for name, suffix, flags in names:
        body += struct.pack(">15sBH", name.ljust(15).encode(), suffix, flags)
    body += mac + b"\x00" * 40  # unit id + the rest of the statistics
    return head + echoed + owner + struct.pack(">HHIH", 0x21, 1, 0, len(body)) + body


def dns_message(records: list[bytes], *, questions: bytes = b"") -> bytes:
    return struct.pack(">HHHHHH", 1, 0x8400, 1 if questions else 0, len(records), 0, 0) + questions + b"".join(records)


def rr(owner: bytes, rtype: int, rdata: bytes) -> bytes:
    return owner + struct.pack(">HHIH", rtype, 1, 120, len(rdata)) + rdata


def udp_server(reply) -> tuple[int, threading.Thread]:
    """A one-shot UDP responder on 127.0.0.1; ``reply(datagram) -> list[bytes]``."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(5)

    def run() -> None:
        try:
            data, sender = sock.recvfrom(4096)
            for packet in reply(data):
                sock.sendto(packet, sender)
        except OSError:
            pass
        finally:
            sock.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return sock.getsockname()[1], thread


def silent_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class NetbiosTests(unittest.TestCase):
    NAMES = [("NAS01", 0x00, 0x0400), ("WORKGROUP", 0x00, 0x8400), ("NAS01", 0x20, 0x0400)]

    def test_query_is_the_standard_nbstat_for_the_wildcard(self) -> None:
        query = fp.netbios_query()
        self.assertEqual(len(query), 50)
        self.assertEqual(query[12], 0x20)
        self.assertEqual(query[13:15], b"CK")  # "*" first-level encoded
        self.assertEqual(query[-4:], b"\x00\x21\x00\x01")

    def test_three_names_and_the_mac(self) -> None:
        found = fp.parse_nbstat(nbstat_response(self.NAMES, bytes.fromhex("0011223344aa")))
        self.assertEqual(found, {"name": "NAS01", "workgroup": "WORKGROUP", "mac": "00:11:22:33:44:aa"})

    def test_reply_without_echoed_question(self) -> None:
        found = fp.parse_nbstat(nbstat_response(self.NAMES, bytes(6), question=False))
        self.assertEqual(found, {"name": "NAS01", "workgroup": "WORKGROUP"})  # zero MAC dropped

    def test_junk_and_foreign_ids_give_nothing(self) -> None:
        good = nbstat_response(self.NAMES, bytes(6))
        for blob in (b"", b"\x00" * 7, good[:30], b"\xff" * 80, b"\x00\x01" + good[2:]):
            self.assertEqual(fp.parse_nbstat(blob), {})

    def test_probe_against_a_fake_responder(self) -> None:
        port, thread = udp_server(lambda q: [nbstat_response(self.NAMES, bytes.fromhex("0011223344aa"))])
        found = fp.probe_netbios("127.0.0.1", port, timeout=2)
        thread.join(3)
        self.assertEqual(found["name"], "NAS01")

    def test_silence(self) -> None:
        self.assertEqual(fp.probe_netbios("127.0.0.1", silent_udp_port(), timeout=0.3), {})


class UpnpTests(unittest.TestCase):
    def test_nas_description(self) -> None:
        found = fp.parse_upnp_description(NAS_XML)
        self.assertEqual(
            found,
            {
                "device_type": "urn:schemas-upnp-org:device:Basic:1",
                "friendly_name": "DS220 (nas01)",
                "manufacturer": "Synology",
                "model": "DS220+",
                "model_number": "DS220+",
                "serial": "2010Q9N123456",
            },
        )

    def test_printer_without_a_serial(self) -> None:
        found = fp.parse_upnp_description(PRINTER_XML)
        self.assertEqual(found["manufacturer"], "HP")
        self.assertEqual(found["model"], "LaserJet Pro M404dn")
        self.assertNotIn("serial", found)

    def test_entities_and_garbage_are_refused(self) -> None:
        bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><root><device><friendlyName>&a;</friendlyName></device></root>'
        for blob in (bomb, b"not xml", b"", b"<root/>", b"<root><device></device></root>"):
            self.assertEqual(fp.parse_upnp_description(blob), {})

    def test_location_only_for_the_same_ip_over_http(self) -> None:
        self.assertEqual(fp.same_host_location("http://10.0.0.5:5000/desc.xml?x=1", "10.0.0.5"), (5000, "/desc.xml?x=1"))
        self.assertEqual(fp.same_host_location("http://10.0.0.5", "10.0.0.5"), (80, "/"))
        for url in (
            "http://10.0.0.99:5000/desc.xml",  # another host: SSRF
            "http://localhost/desc.xml",  # a name could resolve anywhere
            "https://10.0.0.5/desc.xml",
            "file:///etc/passwd",
            "ftp://10.0.0.5/x",
            "",
        ):
            self.assertIsNone(fp.same_host_location(url, "10.0.0.5"), url)

    def _http(self, xml: bytes, *, status: int = 200) -> tuple[http.server.HTTPServer, int]:
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(status)
                self.end_headers()
                self.wfile.write(xml)

            def log_message(self, *args) -> None:
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server, server.server_address[1]

    def _ssdp_reply(self, location: str) -> list[bytes]:
        return [f"HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLOCATION: {location}\r\nSERVER: Linux UPnP/1.0\r\nST: upnp:rootdevice\r\n\r\n".encode()]

    def test_probe_end_to_end(self) -> None:
        server, http_port = self._http(NAS_XML)
        seen: list[bytes] = []
        port, thread = udp_server(lambda q: seen.append(q) or self._ssdp_reply(f"http://127.0.0.1:{http_port}/desc.xml"))
        try:
            found = fp.probe_ssdp("127.0.0.1", port, timeout=2)
        finally:
            server.shutdown()
        thread.join(3)
        self.assertEqual(found["manufacturer"], "Synology")
        self.assertIn(b"M-SEARCH", seen[0])
        self.assertIn(b"upnp:rootdevice", seen[0])

    def test_location_to_another_ip_is_never_fetched(self) -> None:
        port, thread = udp_server(lambda q: self._ssdp_reply("http://127.0.0.2:8080/desc.xml"))
        with mock.patch.object(fp, "_fetch_description") as fetch:
            found = fp.probe_ssdp("127.0.0.1", port, timeout=2)
        thread.join(3)
        self.assertEqual(found, {})
        fetch.assert_not_called()

    def test_oversized_description_is_dropped(self) -> None:
        server, http_port = self._http(NAS_XML + b" " * (fp.UPNP_XML_MAX + 10))
        try:
            data = fp._fetch_description("127.0.0.1", http_port, "/", 2)
        finally:
            server.shutdown()
        self.assertEqual(data, b"")

    def test_http_error_and_silence(self) -> None:
        server, http_port = self._http(NAS_XML, status=404)
        try:
            self.assertEqual(fp._fetch_description("127.0.0.1", http_port, "/", 2), b"")
        finally:
            server.shutdown()
        self.assertEqual(fp.probe_ssdp("127.0.0.1", silent_udp_port(), timeout=0.3), {})


def name(text: str) -> bytes:
    return fp.dns_encode_name(text)


class MdnsTests(unittest.TestCase):
    def _apple(self) -> list[bytes]:
        q = name("_device-info._tcp.local") + struct.pack(">HH", 12, 1)
        instance = b"\x07Mac-Pro" + b"\xc0\x0c"  # "Mac-Pro" + pointer to _device-info._tcp.local
        device_info = dns_message(
            [
                rr(b"\xc0\x0c", 12, instance),
                rr(instance, 16, b"\x14model=MacBookPro18,3\x0aosxvers=23"),
            ],
            questions=q,
        )
        services = dns_message(
            [
                rr(name("_services._dns-sd._udp.local"), 12, name("_smb._tcp.local")),
                rr(name("_services._dns-sd._udp.local"), 12, name("_airplay._tcp.local")),
                rr(name("_services._dns-sd._udp.local"), 12, name("_smb._tcp.local")),
            ]
        )
        return [device_info, services]

    def test_model_hostname_and_services(self) -> None:
        found = fp.parse_mdns(self._apple())
        self.assertEqual(found["model"], "MacBookPro18,3")
        self.assertEqual(found["hostname"], "Mac-Pro")
        self.assertEqual(found["services"], ["smb", "airplay"])

    def test_srv_target_wins_over_instance_names(self) -> None:
        srv = rr(name("nas._http._tcp.local"), 33, struct.pack(">HHH", 0, 0, 5000) + name("diskstation.local"))
        found = fp.parse_mdns([dns_message([srv]), *self._apple()])
        self.assertEqual(found["hostname"], "diskstation")

    def test_avahi_workstation_instance_loses_its_mac(self) -> None:
        ptr = rr(name("_workstation._tcp.local"), 12, name("pi4 [dc:a6:32:01:02:03]._workstation._tcp.local"))
        self.assertEqual(fp.parse_mdns([dns_message([ptr])]), {"hostname": "pi4"})

    def test_services_are_capped(self) -> None:
        many = [rr(name("_services._dns-sd._udp.local"), 12, name(f"_s{i}._tcp.local")) for i in range(40)]
        self.assertEqual(len(fp.parse_mdns([dns_message(many)])["services"]), fp.MDNS_SERVICES_MAX)

    def test_compression_loops_are_cut(self) -> None:
        # A name that points to itself, and two pointers pointing at each other.
        header = struct.pack(">HHHHHH", 1, 0x8400, 0, 1, 0, 0)
        selfloop = header + b"\xc0\x0c" + struct.pack(">HHIH", 12, 1, 0, 2) + b"\xc0\x0c"
        with self.assertRaises(ValueError):
            fp.dns_read_name(selfloop, 12)
        pair = header + b"\xc0\x0e\xc0\x0c"
        with self.assertRaises(ValueError):
            fp.dns_read_name(pair, 12)
        self.assertEqual(fp.parse_mdns([selfloop, pair]), {})

    def test_a_bad_packet_does_not_spoil_a_good_one(self) -> None:
        self.assertEqual(fp.parse_mdns([b"\xff" * 5, b"", *self._apple()])["model"], "MacBookPro18,3")

    def test_probe_sends_three_standard_questions(self) -> None:
        received: list[bytes] = []
        apple = self._apple()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(5)

        def run() -> None:
            try:
                for _ in range(3):
                    data, sender = sock.recvfrom(4096)
                    received.append(data)
                for packet in apple:
                    sock.sendto(packet, sender)
            except OSError:
                pass

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        found = fp.probe_mdns("127.0.0.1", sock.getsockname()[1], timeout=2)
        thread.join(3)
        sock.close()
        self.assertEqual(len(received), 3)
        for packet, question in zip(received, fp.MDNS_QUESTIONS):
            self.assertIn(name(question), packet)
        self.assertEqual(found["model"], "MacBookPro18,3")

    def test_silence(self) -> None:
        self.assertEqual(fp.probe_mdns("127.0.0.1", silent_udp_port(), timeout=0.3), {})


class AssemblyAndCollectorTests(unittest.TestCase):
    def test_blocks_hostname_hint_and_no_top_level_identity(self) -> None:
        fingerprint, hostname, _ = fp.assemble(
            {
                fp.PORT_NETBIOS: {"name": "NAS01", "workgroup": "WORKGROUP", "mac": ""},
                fp.PORT_SSDP: {"manufacturer": "Synology", "model": "DS220+", "serial": ""},
                fp.PORT_MDNS: {"hostname": "nas01", "services": ["smb"]},
            }
        )
        self.assertEqual(fingerprint["netbios"], {"name": "NAS01", "workgroup": "WORKGROUP"})
        self.assertEqual(fingerprint["upnp"], {"manufacturer": "Synology", "model": "DS220+"})
        self.assertEqual(fingerprint["mdns"], {"hostname": "nas01", "services": ["smb"]})
        self.assertEqual(hostname, "NAS01")

    def test_smb_name_outranks_the_udp_hints(self) -> None:
        _, hostname, _ = fp.assemble({fp.PORT_SMB: {"nb_name": "SRV01"}, fp.PORT_NETBIOS: {"name": "OTHER"}})
        self.assertEqual(hostname, "SRV01")

    def test_finding_never_carries_manufacturer_model_serial(self) -> None:
        def fake(ip: str, port: int):
            return ip, port, {"manufacturer": "Synology", "model": "DS220+", "serial": "X"} if port == fp.PORT_SSDP else {}

        ctx = {"hosts": [{"ip": "10.0.0.5", "mac": ""}]}
        with mock.patch.object(fp, "_probe", side_effect=fake):
            (finding,) = FingerprintCollector().collect(ctx)
        for key in ("manufacturer", "model", "serial"):
            self.assertNotIn(key, finding.payload)
        self.assertEqual(finding.payload["fingerprint"]["upnp"]["model"], "DS220+")
        self.assertEqual(finding.payload["seen_by"], "fingerprint")

    def test_everything_closed_returns_nothing_and_no_errors(self) -> None:
        ctx = {"hosts": [{"ip": "127.0.0.1", "mac": ""}]}
        ports = {fp.PORT_NETBIOS: silent_udp_port(), fp.PORT_SSDP: silent_udp_port(), fp.PORT_MDNS: silent_udp_port()}

        def quick(ip: str, port: int):
            probes = {fp.PORT_NETBIOS: fp.probe_netbios, fp.PORT_SSDP: fp.probe_ssdp, fp.PORT_MDNS: fp.probe_mdns}
            return ip, port, probes[port](ip, ports[port], timeout=0.3)

        with mock.patch.object(fp, "PORTS", ()), mock.patch.object(fp, "_probe", side_effect=quick):
            self.assertEqual(FingerprintCollector().collect(ctx), [])
        self.assertEqual(ctx.get("errors", []), [])

    def test_a_udp_probe_that_raises_costs_nothing(self) -> None:
        ctx = {"hosts": [{"ip": "10.0.0.5", "mac": ""}]}
        with mock.patch.object(fp, "PORTS", ()), \
             mock.patch.object(fp, "probe_netbios", side_effect=RuntimeError("boom")), \
             mock.patch.object(fp, "probe_ssdp", return_value={}), \
             mock.patch.object(fp, "probe_mdns", return_value={}):
            self.assertEqual(FingerprintCollector().collect(ctx), [])


if __name__ == "__main__":
    unittest.main()
