"""The Active Directory collector: the PowerShell runner and DNS are mocked, so
no domain, no PowerShell and no network are needed."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

from agent.collectors import RUN_ORDER, all_collectors
from agent.collectors import directory as ad
from agent.collectors.directory import DirectoryCollector
from agent.tasks import TASK_COLLECTORS

NOW = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)


def filetime(moment: datetime) -> int:
    return int((moment.timestamp() * 1e7)) + 116444736000000000


def row(name: str, **extra) -> dict:
    base = {
        "name": name,
        "dnshostname": f"{name.lower()}.acme.lan",
        "operatingsystem": "Windows Server 2022 Standard",
        "operatingsystemversion": "10.0 (20348)",
        "lastlogontimestamp": filetime(NOW - timedelta(days=2)),
        "useraccountcontrol": 4096,
        "spn": [],
    }
    base.update(extra)
    return base


SAMPLE = [
    row("DC01", useraccountcontrol=532480),  # SERVER_TRUST_ACCOUNT | WORKSTATION_TRUST_ACCOUNT bits
    row("SQL01", spn=["MSSQLSvc/sql01.acme.lan:1433", "MSSQLSvc/sql01.acme.lan"]),
    row("OLD01", lastlogontimestamp=filetime(NOW - timedelta(days=200))),
    row("OFF01", useraccountcontrol=4096 | 2),
    row("GHOST", operatingsystem="", dnshostname=""),
    row("Ñandú-PC", operatingsystem="Windows 11 Pro", dnshostname="ñandú-pc.acme.lan"),
]


class ParsingTests(unittest.TestCase):
    def test_filetime_conversion(self) -> None:
        self.assertEqual(ad.filetime_to_datetime(116444736000000000), datetime(1970, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(ad.filetime_to_datetime(filetime(NOW)), NOW)
        for junk in (0, -5, None, "x", 2**63):
            self.assertIsNone(ad.filetime_to_datetime(junk))

    def test_roles_by_spn_and_account_flag(self) -> None:
        self.assertEqual(ad.roles_for(8192, []), ["dc"])
        self.assertEqual(ad.roles_for(4096, ["MSSQLSvc/x:1433"]), ["sql"])
        self.assertEqual(ad.roles_for(4096, ["exchangeMDB/x"]), ["exchange"])
        self.assertEqual(ad.roles_for(4096, ["exchangeRFR/x"]), ["exchange"])
        self.assertEqual(ad.roles_for(4096, ["Microsoft Virtual System Migration Service/x"]), ["hyperv"])
        self.assertEqual(ad.roles_for(4096, ["Hyper-V Replica Service/x"]), ["hyperv"])
        self.assertEqual(ad.roles_for(8192, ["HTTP/x", "MSSQLSvc/x", "Hyper-V Replica Service/x"]), ["dc", "sql", "hyperv"])
        self.assertEqual(ad.roles_for(4096, ["HTTP/x", "WSMAN/x"]), [])

    def test_filters(self) -> None:
        names = [c["name"] for c in ad.parse_computers(json.dumps(SAMPLE), now=NOW)]
        self.assertEqual(sorted(names), ["DC01", "SQL01", "Ñandú-PC"])  # stale, disabled and empty ones are gone

    def test_dc_flag_from_real_uac(self) -> None:
        dc = [c for c in ad.parse_computers(json.dumps(SAMPLE), now=NOW) if c["name"] == "DC01"][0]
        self.assertEqual(dc["roles"], ["dc"])

    def test_bad_json_and_shapes(self) -> None:
        for raw in (None, "", "   ", "not json", "42", '"x"', "[1, 2]", "[]"):
            self.assertEqual(ad.parse_computers(raw, now=NOW), [], raw)

    def test_single_object_is_accepted(self) -> None:
        # ConvertTo-Json unwraps one-element arrays on older PowerShell.
        self.assertEqual(len(ad.parse_computers(json.dumps(row("A")), now=NOW)), 1)

    def test_never_logged_on_is_kept_without_a_date(self) -> None:
        computers = ad.parse_computers(json.dumps([row("NEW", lastlogontimestamp=0)]), now=NOW)
        self.assertEqual(len(computers), 1)
        self.assertIsNone(computers[0]["last_logon"])


class RunnerTests(unittest.TestCase):
    def test_the_script_is_a_constant_and_asks_for_enabled_computers_only(self) -> None:
        self.assertIn("(!(userAccountControl:1.1.2:=2))", ad.POWERSHELL_SCRIPT)
        self.assertIn("PageSize = 500", ad.POWERSHELL_SCRIPT)
        self.assertIn("GetComputerDomain", ad.POWERSHELL_SCRIPT)

    def test_no_powershell_is_silence(self) -> None:
        with mock.patch.object(ad, "_powershell_path", return_value=None):
            self.assertIsNone(ad.run_powershell())

    def test_timeout_and_failures_are_none(self) -> None:
        import subprocess

        with mock.patch.object(ad, "_powershell_path", return_value="ps"):
            with mock.patch.object(ad.subprocess, "run", side_effect=subprocess.TimeoutExpired("ps", 60)):
                self.assertIsNone(ad.run_powershell())
            with mock.patch.object(ad.subprocess, "run", side_effect=OSError):
                self.assertIsNone(ad.run_powershell())
            failed = mock.Mock(returncode=1, stdout=b"[]")
            with mock.patch.object(ad.subprocess, "run", return_value=failed):
                self.assertIsNone(ad.run_powershell())
            huge = mock.Mock(returncode=0, stdout=b"x" * (ad.MAX_OUTPUT_BYTES + 1))
            with mock.patch.object(ad.subprocess, "run", return_value=huge):
                self.assertIsNone(ad.run_powershell())

    def test_output_decoded_as_utf8_with_bom(self) -> None:
        ok = mock.Mock(returncode=0, stdout="\ufeff[\"Ñ\"]".encode("utf-8"))
        with mock.patch.object(ad, "_powershell_path", return_value="ps"), mock.patch.object(ad.subprocess, "run", return_value=ok):
            self.assertEqual(ad.run_powershell(), '["Ñ"]')


ADDRESSES = {"dc01.acme.lan": "10.0.0.2", "sql01.acme.lan": "10.0.0.3", "ñandú-pc.acme.lan": "10.0.0.9"}


def fake_resolve(name: str, timeout: float = 0) -> str:
    return ADDRESSES.get(name, "")


class CollectorTests(unittest.TestCase):
    def test_order_and_task(self) -> None:
        names = [c.name for c in all_collectors()]
        self.assertEqual(names, list(RUN_ORDER))
        self.assertEqual(names.index("directory"), names.index("fingerprint") + 1)
        self.assertLess(names.index("directory"), names.index("snmp"))
        self.assertIn("directory", TASK_COLLECTORS["inventory"])

    def test_findings_only_for_hosts_alive_in_the_sweep(self) -> None:
        ctx = {"hosts": [{"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:02"}, {"ip": "10.0.0.3", "mac": ""}]}
        # The collector reads the real clock, so the sample is relative to today.
        sample = [
            row("DC01", useraccountcontrol=8192 | 4096, lastlogontimestamp=filetime(datetime.now(timezone.utc) - timedelta(days=1))),
            row("SQL01", spn=["MSSQLSvc/sql01.acme.lan"], lastlogontimestamp=filetime(datetime.now(timezone.utc) - timedelta(days=3))),
            row("Ñandú-PC", operatingsystem="Windows 11 Pro", dnshostname="ñandú-pc.acme.lan"),  # alive in AD, dead in the sweep
        ]
        with (
            mock.patch.object(ad.sys, "platform", "win32"),
            mock.patch.object(ad, "run_powershell", return_value=json.dumps(sample)),
            mock.patch.object(ad, "resolve_ipv4", side_effect=fake_resolve),
        ):
            findings = DirectoryCollector().collect(ctx)
        self.assertEqual(len(findings), 2)
        by_ip = {f.payload["ip"]: f for f in findings}
        dc = by_ip["10.0.0.2"]
        self.assertEqual(dc.kind, "host")
        self.assertEqual(dc.identity, {"mac": "aa:bb:cc:dd:ee:02"})
        self.assertEqual(dc.payload["seen_by"], "directory")
        self.assertEqual(dc.payload["hostname"], "dc01")
        self.assertEqual(dc.payload["os"], "Windows Server 2022 Standard")
        self.assertEqual(dc.payload["directory"]["roles"], ["dc"])
        self.assertEqual(dc.payload["directory"]["os_version"], "10.0 (20348)")
        self.assertEqual(dc.payload["directory"]["dns_name"], "dc01.acme.lan")
        self.assertRegex(dc.payload["directory"]["last_logon"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        sql = by_ip["10.0.0.3"]
        self.assertEqual(sql.identity, {"ip": "10.0.0.3"})  # the sweep had no MAC
        self.assertNotIn("mac", sql.payload)
        self.assertEqual(sql.payload["directory"]["roles"], ["sql"])
        self.assertNotIn("os_version", dc.payload)  # only inside the directory dict

    def test_accents_survive_and_no_empty_keys(self) -> None:
        sample = [row("Ñandú-PC", operatingsystem="Windows 11 Pro", operatingsystemversion="", lastlogontimestamp=0)]
        ctx = {"hosts": [{"ip": "10.0.0.9", "mac": ""}]}
        with (
            mock.patch.object(ad.sys, "platform", "win32"),
            mock.patch.object(ad, "run_powershell", return_value=json.dumps(sample)),
            mock.patch.object(ad, "resolve_ipv4", side_effect=fake_resolve),
        ):
            (finding,) = DirectoryCollector().collect(ctx)
        self.assertEqual(finding.payload["hostname"], "ñandú-pc")
        self.assertEqual(finding.payload["directory"], {"dns_name": "ñandú-pc.acme.lan"})

    def test_dns_failure_gives_nothing(self) -> None:
        ctx = {"hosts": [{"ip": "10.0.0.2", "mac": ""}]}
        sample = [row("DC01", lastlogontimestamp=filetime(datetime.now(timezone.utc)))]
        with (
            mock.patch.object(ad.sys, "platform", "win32"),
            mock.patch.object(ad, "run_powershell", return_value=json.dumps(sample)),
            mock.patch.object(ad, "resolve_ipv4", return_value=""),
        ):
            self.assertEqual(DirectoryCollector().collect(ctx), [])

    def test_not_windows_is_silent_and_does_not_even_run_powershell(self) -> None:
        ctx = {"hosts": [{"ip": "10.0.0.2", "mac": ""}]}
        with mock.patch.object(ad.sys, "platform", "linux"), mock.patch.object(ad, "run_powershell") as runner:
            self.assertEqual(DirectoryCollector().collect(ctx), [])
        runner.assert_not_called()
        self.assertEqual(ctx.get("errors", []), [])

    def test_no_sweep_or_no_live_hosts_is_silent(self) -> None:
        with mock.patch.object(ad.sys, "platform", "win32"), mock.patch.object(ad, "run_powershell") as runner:
            self.assertEqual(DirectoryCollector().collect({}), [])
            self.assertEqual(DirectoryCollector().collect({"hosts": []}), [])
        runner.assert_not_called()

    def test_no_powershell_or_invalid_json_is_silent(self) -> None:
        ctx = {"hosts": [{"ip": "10.0.0.2", "mac": ""}]}
        for output in (None, "garbage", "[]"):
            with mock.patch.object(ad.sys, "platform", "win32"), mock.patch.object(ad, "run_powershell", return_value=output):
                self.assertEqual(DirectoryCollector().collect(ctx), [])
        self.assertEqual(ctx.get("errors", []), [])

    def test_a_crash_inside_never_escapes(self) -> None:
        ctx = {"hosts": [{"ip": "10.0.0.2", "mac": ""}]}
        with mock.patch.object(ad.sys, "platform", "win32"), mock.patch.object(ad, "run_powershell", side_effect=RuntimeError):
            self.assertEqual(DirectoryCollector().collect(ctx), [])

    def test_excluded_hosts_are_not_reported(self) -> None:
        sample = [row("DC01", lastlogontimestamp=filetime(datetime.now(timezone.utc)))]
        ctx = {"hosts": [{"ip": "10.0.0.2", "mac": ""}], "excluded": {"10.0.0.2"}}
        with (
            mock.patch.object(ad.sys, "platform", "win32"),
            mock.patch.object(ad, "run_powershell", return_value=json.dumps(sample)),
            mock.patch.object(ad, "resolve_ipv4", side_effect=fake_resolve),
        ):
            self.assertEqual(DirectoryCollector().collect(ctx), [])

    def test_resolve_rejects_nothing_and_non_ipv4(self) -> None:
        self.assertEqual(ad.resolve_ipv4(""), "")
        with mock.patch.object(ad.socket, "getaddrinfo", side_effect=OSError):
            self.assertEqual(ad.resolve_ipv4("x.acme.lan"), "")
        with mock.patch.object(ad.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("10.1.2.3", 0))]):
            self.assertEqual(ad.resolve_ipv4("x.acme.lan"), "10.1.2.3")


if __name__ == "__main__":
    unittest.main()
