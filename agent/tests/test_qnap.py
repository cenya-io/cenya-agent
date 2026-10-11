"""QNAP: su ficha, sus direcciones y su inventario iSCSI (`agent/storage_arrays.py`),
y el volcado para afinarlo con un equipo real (`agent/qnap_dump.py`).

QNAP no publica su API. Las respuestas de aquí tienen la forma que dan sus CGI
según lo que se conoce (`qnapstats`, el paquete de QNAP para VMware); el lector
del iSCSI no da por hechos los nombres de los campos, y estos tests fijan que
lea igual dos formas distintas de escribir lo mismo.
"""

from __future__ import annotations

import base64
import io
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from unittest import mock

from agent import credentials as creds
from agent import qnap_dump, storage_arrays
from agent.collectors.hypervisors import CLIENTS, KIND_LABELS
from agent.hypervisor import HypervisorError

LOGIN_OK = (
    '<?xml version="1.0" encoding="UTF-8" ?><QDocRoot version="1.0">'
    "<authPassed><![CDATA[1]]></authPassed><authSid><![CDATA[s3ss10n]]></authSid>"
    "<isAdmin><![CDATA[1]]></isAdmin></QDocRoot>"
)
LOGIN_BAD = '<QDocRoot version="1.0"><authPassed><![CDATA[0]]></authPassed><errorValue>-1</errorValue></QDocRoot>'
LOGIN_2FA = '<QDocRoot version="1.0"><authPassed><![CDATA[0]]></authPassed><need2SV><![CDATA[1]]></need2SV></QDocRoot>'
SYSINFO = (
    '<QDocRoot version="1.0"><model><displayModelName><![CDATA[TS-873A]]></displayModelName></model>'
    "<firmware><version><![CDATA[5.1.4]]></version><build><![CDATA[20231128]]></build></firmware>"
    "<func><ownContent><root><server_name><![CDATA[nas-cpd]]></server_name>"
    "<serial_number><![CDATA[Q21XB12345]]></serial_number><nic_cnt>2</nic_cnt>"
    "<eth_ip1><![CDATA[10.0.0.20]]></eth_ip1><eth_ip2><![CDATA[10.0.30.20]]></eth_ip2>"
    "</root></ownContent></func></QDocRoot>"
)
# Una forma: destinos y LUN en filas, el LUN dice a qué destino va.
ISCSI_ROWS = (
    '<QDocRoot version="1.0"><iSCSITargetList>'
    "<targetInfo><targetIndex>0</targetIndex><targetName>vmfs</targetName>"
    "<targetIQN>iqn.2004-04.com.qnap:ts-873a:iscsi.vmfs.abc123</targetIQN>"
    "<targetInitiators><initiatorIQN>iqn.1998-01.com.vmware:esxi01-1234</initiatorIQN>"
    "<initiatorIQN>iqn.1998-01.com.vmware:esxi02-5678</initiatorIQN></targetInitiators></targetInfo>"
    "<targetInfo><targetIndex>1</targetIndex><targetName>backup</targetName>"
    "<targetIQN>iqn.2004-04.com.qnap:ts-873a:iscsi.backup.def456</targetIQN></targetInfo>"
    "</iSCSITargetList><iSCSILUNList>"
    "<LUNInfo><LUNIndex>0</LUNIndex><LUNName>LUN-VMFS-01</LUNName><LUNCapacity>2199023255552</LUNCapacity>"
    "<LUNNumber>0</LUNNumber><LUNTargetList><targetIndex>0</targetIndex></LUNTargetList></LUNInfo>"
    "</iSCSILUNList></QDocRoot>"
)
# Otra forma: el destino con otros nombres y sin LUN que se puedan leer.
ISCSI_OTHER = (
    "<QDocRoot><targets><row><targetId>7</targetId><targetAlias>solo-destino</targetAlias>"
    "<iqn>iqn.2004-04.com.qnap:tvs:iscsi.solo.999</iqn></row></targets></QDocRoot>"
)


class _Rest:
    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str, Any]] = []

    def text(self, method: str, path: str, *, headers: dict | None = None, body: dict | None = None) -> str:
        self.calls.append((method, path, body))
        base = path.split("?", 1)[0]
        answer = self.routes.get(base)
        if answer is None:
            raise HypervisorError(f"404 en {base}", status=404)
        if isinstance(answer, Exception):
            raise answer
        return answer


def client(routes: dict[str, Any]) -> tuple[storage_arrays.QNAPClient, _Rest]:
    found = storage_arrays.QNAPClient("nas-cpd.acme.local", "cenya", "s3cr3t<&>")
    rest = _Rest(routes)
    found.rest = rest  # type: ignore[assignment]
    return found, rest


ROUTES = {
    "/cgi-bin/authLogin.cgi": LOGIN_OK,
    "/cgi-bin/management/manaRequest.cgi": SYSINFO,
    "/cgi-bin/disk/iscsi_portal_setting.cgi": ISCSI_ROWS,
    "/cgi-bin/authLogout.cgi": "<QDocRoot/>",
}


class LoginTests(unittest.TestCase):
    def test_the_password_goes_in_base64_and_the_session_is_kept(self) -> None:
        qnap, rest = client(ROUTES)

        qnap.login()

        self.assertEqual(qnap.sid, "s3ss10n")
        body = rest.calls[0][2]
        self.assertEqual(base64.b64decode(body["pwd"]).decode(), "s3cr3t<&>")
        self.assertEqual(body["user"], "cenya")

    def test_a_wrong_password_is_a_401(self) -> None:
        qnap, _ = client({**ROUTES, "/cgi-bin/authLogin.cgi": LOGIN_BAD})

        with self.assertRaises(HypervisorError) as caught:
            qnap.login()

        self.assertEqual(caught.exception.status, 401)

    def test_two_factor_is_said_not_retried(self) -> None:
        qnap, rest = client({**ROUTES, "/cgi-bin/authLogin.cgi": LOGIN_2FA})

        with self.assertRaises(HypervisorError) as caught:
            qnap.login()

        self.assertIn("doble factor", str(caught.exception))
        self.assertEqual(len(rest.calls), 1)

    def test_html_instead_of_xml_is_an_error_not_a_crash(self) -> None:
        qnap, _ = client({**ROUTES, "/cgi-bin/authLogin.cgi": "<html><body>portal cautivo"})

        with self.assertRaises(HypervisorError):
            qnap.login()


class HostTests(unittest.TestCase):
    def setUp(self) -> None:
        qnap, self.rest = client(ROUTES)
        qnap.login()
        self.host = qnap.hosts()[0]

    def test_the_array_with_its_model_serial_firmware_and_addresses(self) -> None:
        self.assertEqual(self.host["name"], "nas-cpd")
        self.assertEqual(self.host["manufacturer"], "QNAP")
        self.assertEqual((self.host["model"], self.host["serial"]), ("TS-873A", "Q21XB12345"))
        self.assertEqual(self.host["os"], "QTS 5.1.4 20231128")
        self.assertEqual(self.host["addresses"], ["10.0.0.20", "10.0.30.20"])
        self.assertFalse(self.host["is_virtualization_host"])

    def test_each_lun_with_its_target_number_size_and_initiators(self) -> None:
        volumes = {v["name"]: v for v in self.host["storage_volumes"]}

        self.assertEqual(
            volumes["LUN-VMFS-01"],
            {
                "name": "LUN-VMFS-01",
                "protocol": "iscsi",
                "gb": 2048,
                "target_iqn": "iqn.2004-04.com.qnap:ts-873a:iscsi.vmfs.abc123",
                "lun": 0,
                "initiators": ["iqn.1998-01.com.vmware:esxi01-1234", "iqn.1998-01.com.vmware:esxi02-5678"],
            },
        )

    def test_a_target_without_readable_luns_still_comes_out(self) -> None:
        """Basta su IQN para fundir con esta la cabina que un ESXi creó por él."""
        volumes = {v["name"]: v for v in self.host["storage_volumes"]}

        self.assertEqual(volumes["backup"]["target_iqn"], "iqn.2004-04.com.qnap:ts-873a:iscsi.backup.def456")

    def test_the_session_travels_in_every_call_and_is_closed(self) -> None:
        paths = [path for _method, path, _body in self.rest.calls[1:]]
        self.assertTrue(all("sid=s3ss10n" in path for path in paths))
        self.assertTrue(paths[-1].startswith("/cgi-bin/authLogout.cgi"))


class ReaderTests(unittest.TestCase):
    def test_other_names_for_the_same_things_are_read_too(self) -> None:
        volumes = storage_arrays.qnap_volumes(ET.fromstring(ISCSI_OTHER))

        self.assertEqual(len(volumes), 1)
        self.assertEqual(volumes[0]["name"], "solo-destino")
        self.assertEqual(volumes[0]["target_iqn"], "iqn.2004-04.com.qnap:tvs:iscsi.solo.999")

    def test_without_permission_for_iscsi_the_array_still_enters(self) -> None:
        qnap, _ = client({k: v for k, v in ROUTES.items() if k != "/cgi-bin/disk/iscsi_portal_setting.cgi"})
        qnap.login()

        host = qnap.hosts()[0]

        self.assertEqual(host["model"], "TS-873A")
        self.assertNotIn("storage_volumes", host)

    def test_a_size_in_another_unit_is_left_empty_not_absurd(self) -> None:
        xml = ISCSI_ROWS.replace("<LUNCapacity>2199023255552</LUNCapacity>", "<LUNCapacity>2048</LUNCapacity>")

        volumes = {v["name"]: v for v in storage_arrays.qnap_volumes(ET.fromstring(xml))}

        self.assertEqual(volumes["LUN-VMFS-01"]["gb"], 0)

    def test_the_qnap_is_one_more_array_for_the_collector(self) -> None:
        self.assertIs(CLIENTS[creds.QNAP], storage_arrays.QNAPClient)
        self.assertEqual(KIND_LABELS[creds.QNAP], "qnap")


class DumpTests(unittest.TestCase):
    def _run(self, routes: dict[str, Any], *extra: str) -> tuple[int, str, Path]:
        rest = _Rest(routes)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "dump.txt"
            real = storage_arrays.QNAPClient

            def fake(*args: Any, **kwargs: Any) -> storage_arrays.QNAPClient:
                made = real(*args, **kwargs)
                made.rest = rest  # type: ignore[assignment]
                return made

            with mock.patch.object(storage_arrays, "QNAPClient", side_effect=fake), mock.patch(
                "sys.stderr", io.StringIO()
            ), mock.patch("sys.stdout", io.StringIO()):
                code = qnap_dump.run(
                    ["nas-cpd.acme.local", "cenya", "--output", str(output), *extra],
                    environ={qnap_dump.PASSWORD_ENV_VAR: "s3cr3t"},
                )
            text = output.read_text(encoding="utf-8") if output.exists() else ""
        return code, text, output

    def test_every_call_is_written_without_the_session(self) -> None:
        code, text, _ = self._run({**ROUTES, "/cgi-bin/management/manaRequest.cgi": SYSINFO + "<!-- sid s3ss10n -->"})

        self.assertEqual(code, 0)
        for name in storage_arrays.QNAP_CALLS:
            self.assertIn(f"===== {name}:", text)
        self.assertIn("TS-873A", text)
        self.assertIn("iqn.2004-04.com.qnap:ts-873a:iscsi.vmfs.abc123", text)
        self.assertNotIn("s3ss10n", text)
        self.assertNotIn("s3cr3t", text)

    def test_a_rejected_login_writes_nothing(self) -> None:
        code, text, _ = self._run({**ROUTES, "/cgi-bin/authLogin.cgi": LOGIN_BAD})

        self.assertEqual(code, 1)
        self.assertEqual(text, "")

    def test_wrong_arguments_say_how_to_use_it(self) -> None:
        with mock.patch("sys.stderr", io.StringIO()) as err:
            self.assertEqual(qnap_dump.run(["solo-una-cosa"], environ={}), 2)
        self.assertIn("qnap-dump", err.getvalue())


if __name__ == "__main__":
    unittest.main()
