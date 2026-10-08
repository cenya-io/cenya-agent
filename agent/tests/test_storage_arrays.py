"""Cabinas con API: Synology DSM y TrueNAS (`agent/storage_arrays.py`).

Lo que sale de aquí es lo que el servidor convierte en volúmenes con RAID y
disco reales, presentaciones a los hosts y la fusión de la cabina provisional
que creó un hipervisor. Si una forma de respuesta se lee mal, el volumen llega
sin IQN y la fusión no ocurre: dos fichas para la misma caja.
"""

from __future__ import annotations

import unittest
from typing import Any
from unittest import mock

from agent import credentials as creds
from agent import storage_arrays
from agent.collectors.hypervisors import CLIENTS, HypervisorCollector
from agent.hypervisor import HypervisorError


class _Rest:
    def __init__(self, routes: dict[tuple[str, str], Any]) -> None:
        self.routes = routes
        self.calls: list[tuple[str, str, dict, Any]] = []

    def request(self, method: str, path: str, *, headers: dict | None = None, body: dict | None = None) -> Any:
        self.calls.append((method, path, dict(headers or {}), body))
        key = (path, (body or {}).get("api", "")) if body else (path, "")
        if key not in self.routes:
            raise HypervisorError(f"404 en {path}", status=404)
        answer = self.routes[key]
        if isinstance(answer, Exception):
            raise answer
        return answer


SYNO_ROUTES = {
    ("/webapi/auth.cgi", "SYNO.API.Auth"): {"success": True, "data": {"sid": "abc"}},
    ("/webapi/entry.cgi", "SYNO.DSM.Info"): {
        "success": True,
        "data": {"model": "RS1221+", "serial": "21A0XYZ", "version_string": "DSM 7.2.1-69057"},
    },
    ("/webapi/entry.cgi", "SYNO.Core.ISCSI.LUN"): {
        "success": True,
        "data": {
            "luns": [
                {"uuid": "u-1", "name": "LUN-VMFS-01", "size": 2 * 1024**4, "location": "/volume1"},
                {"uuid": "u-2", "name": "LUN-SUELTA", "size": 100 * 1024**3, "location": "/volume2"},
            ]
        },
    },
    ("/webapi/entry.cgi", "SYNO.Core.ISCSI.Target"): {
        "success": True,
        "data": {
            "targets": [
                {
                    "iqn": "iqn.2000-01.com.synology:nas01.Target-1.abc",
                    "mapped_luns": [{"lun_uuid": "u-1", "mapping_index": 1}],
                    "acls": [
                        {"iqn": "iqn.2000-01.com.synology:default.acl", "permission": "none"},
                        {"iqn": "iqn.1998-01.com.vmware:esxi01-1a2b", "permission": "rw"},
                    ],
                    "connected_sessions": [{"iqn": "iqn.1998-01.com.vmware:esxi02-3c4d", "ip": "10.0.30.12"}],
                }
            ]
        },
    },
    ("/webapi/entry.cgi", "SYNO.Storage.CGI.Storage"): {
        "success": True,
        "data": {
            "volumes": [{"vol_path": "/volume1", "pool_path": "reuse_1"}],
            "storagePools": [{"id": "reuse_1", "device_type": "raid_6", "disks": ["sata1", "sata2"]}],
            "disks": [{"id": "sata1", "diskType": "SATA", "isSsd": True}, {"id": "sata2", "diskType": "SATA", "isSsd": True}],
        },
    },
}


class SynologyTests(unittest.TestCase):
    def _client(self, routes: dict) -> tuple[storage_arrays.SynologyClient, _Rest]:
        client = storage_arrays.SynologyClient("nas01.acme.local", "lector", "s3cr3t")
        rest = _Rest(routes)
        client.rest = rest  # type: ignore[assignment]
        return client, rest

    def test_the_password_travels_in_the_body_and_never_in_the_path(self) -> None:
        client, rest = self._client(SYNO_ROUTES)

        client.login()

        method, path, _headers, body = rest.calls[0]
        self.assertEqual((method, path), ("POST", "/webapi/auth.cgi"))
        self.assertEqual(body["passwd"], "s3cr3t")
        self.assertEqual(client.sid, "abc")

    def test_a_refused_login_is_an_auth_failure(self) -> None:
        client, _ = self._client({("/webapi/auth.cgi", "SYNO.API.Auth"): {"success": False, "error": {"code": 400}}})

        with self.assertRaises(HypervisorError) as caught:
            client.login()

        self.assertEqual(caught.exception.status, 401)
        self.assertNotIn("s3cr3t", str(caught.exception))

    def test_the_array_comes_with_its_luns_raid_disks_and_acl(self) -> None:
        client, _ = self._client(SYNO_ROUTES)
        client.login()

        host = client.hosts()[0]

        self.assertEqual((host["manufacturer"], host["model"], host["serial"]), ("Synology", "RS1221+", "21A0XYZ"))
        self.assertFalse(host["is_virtualization_host"])
        self.assertIn("Synology", host["description"])
        lun = host["storage_volumes"][0]
        self.assertEqual(
            lun,
            {
                "name": "LUN-VMFS-01",
                "protocol": "iscsi",
                "gb": 2048,
                "target_iqn": "iqn.2000-01.com.synology:nas01.Target-1.abc",
                "lun": 1,
                "raid": "raid_6",
                "disk": "ssd",
                "initiators": ["iqn.1998-01.com.vmware:esxi01-1a2b", "iqn.1998-01.com.vmware:esxi02-3c4d"],
            },
        )
        self.assertEqual(host["storage_volumes"][1]["target_iqn"], "")
        self.assertEqual(client.virtual_machines(), [])

    def test_a_call_dsm_refuses_leaves_that_data_empty(self) -> None:
        routes = {k: v for k, v in SYNO_ROUTES.items() if k[1] != "SYNO.Storage.CGI.Storage"}
        client, _ = self._client(routes)
        client.login()

        lun = client.hosts()[0]["storage_volumes"][0]

        self.assertEqual((lun["raid"], lun["disk"]), ("", ""))
        self.assertEqual(lun["target_iqn"], "iqn.2000-01.com.synology:nas01.Target-1.abc")


TN_ROUTES = {
    ("/api/v2.0/system/info", ""): {
        "version": "TrueNAS-SCALE-24.10.2",
        "hostname": "truenas",
        "system_product": "TrueNAS-M40",
        "system_serial": "A1-12345",
        "system_manufacturer": "iXsystems",
    },
    ("/api/v2.0/iscsi/global", ""): {"basename": "iqn.2005-10.org.freenas.ctl"},
    ("/api/v2.0/iscsi/target", ""): [{"id": 1, "name": "vmware", "groups": [{"portal": 1, "initiator": 1}]}],
    ("/api/v2.0/iscsi/extent", ""): [{"id": 1, "name": "vm-lun", "type": "DISK", "disk": "zvol/tank/vm-lun"}],
    ("/api/v2.0/iscsi/targetextent", ""): [{"target": 1, "extent": 1, "lunid": 0}],
    ("/api/v2.0/iscsi/initiator", ""): [{"id": 1, "initiators": ["iqn.1998-01.com.vmware:esxi01-1a2b"]}],
    ("/api/v2.0/pool", ""): [
        {"name": "tank", "topology": {"data": [{"type": "RAIDZ2", "children": [{"disk": "sda"}, {"disk": "sdb"}]}]}}
    ],
    ("/api/v2.0/disk", ""): [{"name": "sda", "type": "HDD"}, {"name": "sdb", "type": "SSD"}],
    ("/api/v2.0/sharing/nfs", ""): [{"path": "/mnt/tank/backups", "hosts": ["10.0.0.11"]}],
    ("/api/v2.0/interface", ""): [
        {"name": "eno1", "aliases": [{"type": "INET", "address": "192.168.1.30", "netmask": 24}]},
        {"name": "eno2", "aliases": [], "state": {"aliases": [{"type": "INET", "address": "10.0.30.6"}, {"type": "LINK", "address": "aa:bb"}]}},
    ],
    ("/api/v2.0/pool/dataset?type=VOLUME", ""): [{"id": "tank/vm-lun", "volsize": {"parsed": 500 * 1024**3}}],
}


class TrueNASTests(unittest.TestCase):
    def _client(self, routes: dict) -> tuple[storage_arrays.TrueNASClient, _Rest]:
        client = storage_arrays.TrueNASClient("truenas.acme.local", "", "1-clave")
        rest = _Rest(routes)
        client.rest = rest  # type: ignore[assignment]
        return client, rest

    def test_the_api_key_travels_as_a_bearer_header(self) -> None:
        client, rest = self._client(TN_ROUTES)

        client.login()

        self.assertEqual(rest.calls[0][2]["Authorization"], "Bearer 1-clave")

    def test_the_array_with_its_extents_shares_and_addresses(self) -> None:
        client, _ = self._client(TN_ROUTES)
        client.login()

        host = client.hosts()[0]

        self.assertEqual((host["manufacturer"], host["model"], host["serial"]), ("iXsystems", "TrueNAS-M40", "A1-12345"))
        self.assertEqual(host["addresses"], ["192.168.1.30", "10.0.30.6"])
        lun, nfs = host["storage_volumes"]
        self.assertEqual(
            lun,
            {
                "name": "vm-lun",
                "protocol": "iscsi",
                "gb": 500,
                "target_iqn": "iqn.2005-10.org.freenas.ctl:vmware",
                "lun": 0,
                "raid": "RAIDZ2",
                "disk": "hybrid",
                "initiators": ["iqn.1998-01.com.vmware:esxi01-1a2b"],
            },
        )
        self.assertEqual(nfs["export"], "/mnt/tank/backups")
        self.assertEqual(nfs["clients"], ["10.0.0.11"])
        self.assertEqual(nfs["raid"], "RAIDZ2")

    def test_a_401_is_an_auth_failure(self) -> None:
        client, _ = self._client({("/api/v2.0/system/info", ""): HypervisorError("401 en /api/v2.0/system/info", status=401)})

        with self.assertRaises(HypervisorError):
            client.login()

    def test_without_iscsi_or_pools_the_array_still_comes_out(self) -> None:
        client, _ = self._client({("/api/v2.0/system/info", ""): TN_ROUTES[("/api/v2.0/system/info", "")]})
        client.login()

        host = client.hosts()[0]

        self.assertEqual(host["model"], "TrueNAS-M40")
        self.assertNotIn("storage_volumes", host)


class CollectorTests(unittest.TestCase):
    """Las cabinas pasan por el mismo colector que los hipervisores."""

    def test_both_are_in_the_table_and_a_truenas_credential_needs_no_user(self) -> None:
        self.assertIn(creds.SYNOLOGY, CLIENTS)
        self.assertIn(creds.TRUENAS, CLIENTS)
        parsed = creds.all_from({"config": {"credentials": [{"kind": "truenas", "secret": "k", "host": "truenas"}]}})
        self.assertEqual([c.kind for c in parsed], ["truenas"])

    def test_the_array_finding_is_an_array_with_its_volumes(self) -> None:
        class Fake:
            def __init__(self, *args: Any, **kwargs: Any) -> None:
                pass

            def login(self) -> None:
                pass

            def hosts(self) -> list[dict[str, Any]]:
                return [
                    storage_arrays._array_host(
                        "nas01", "Synology", ip="192.168.1.20", storage_volumes=[{"name": "v", "protocol": "iscsi"}]
                    )
                ]

            def virtual_machines(self) -> list[dict[str, Any]]:
                return []

        ctx = {"config": {"credentials": [{"kind": "synology", "username": "u", "secret": "s", "host": "nas01"}]}, "env": None}
        with mock.patch.dict("agent.collectors.hypervisors.CLIENTS", {"synology": Fake}, clear=True), \
             mock.patch("agent.collectors.hypervisors.net.resolve", lambda name: ""):
            found = HypervisorCollector().collect(ctx)

        payload = found[0].payload
        self.assertEqual(found[0].identity, {"ip": "192.168.1.20"})
        self.assertFalse(payload["is_virtualization_host"])
        self.assertEqual(payload["description"], "Cabina de discos Synology")
        self.assertEqual(payload["storage_volumes"], [{"name": "v", "protocol": "iscsi"}])


if __name__ == "__main__":
    unittest.main()
