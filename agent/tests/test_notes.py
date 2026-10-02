"""Tests for the agent's structured notes.

Collector notes and «Analizar» reports go to the server as codes, so the web can
write them in each viewer's language (``core/agent_notes.py``). On this side
what matters: the Spanish text is exactly what it always was (old servers show
it), the codes travel with it, and no secret ever becomes a parameter.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado también bajo `unittest discover`

import json
import unittest
from unittest import mock

from agent import notes, probe
from agent.collectors.ssh import SshCollector
from agent.collectors.winrm import WinrmCollector
from agent.config import Config
from agent.tests.test_probe import ctx_with


class NoteTests(unittest.TestCase):
    def test_a_note_is_still_its_spanish_text(self) -> None:
        note = notes.collector_note("ssh", "no_credentials", "no hay credenciales")

        self.assertEqual(note, "ssh: no hay credenciales")
        self.assertIsInstance(note, str)
        self.assertEqual(json.dumps([note]), '["ssh: no hay credenciales"]')

    def test_it_carries_its_code_and_parameters(self) -> None:
        note = notes.collector_note("hypervisors", "failed", "vc: 401", host="vc", detail="401", ignored=None)

        self.assertEqual(
            note.as_json(),
            {"collector": "hypervisors", "code": "failed", "params": {"host": "vc", "detail": "401"}, "text": "hypervisors: vc: 401"},
        )

    def test_a_loose_text_travels_without_code(self) -> None:
        self.assertEqual(notes.to_json("algo imprevisto"), {"collector": "", "code": "", "params": {}, "text": "algo imprevisto"})


class RealCollectorsTests(unittest.TestCase):
    def test_collectors_keep_their_text_and_add_their_code(self) -> None:
        ctx = {"config": {}, "env": None, "hosts": []}
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True):
            SshCollector().collect(ctx)
        with mock.patch("agent.collectors.winrm.winrm.AVAILABLE", True):
            WinrmCollector().collect(ctx)

        self.assertEqual(
            [(n.collector, n.code) for n in ctx["errors"]], [("ssh", "no_credentials"), ("winrm", "no_credentials")]
        )
        self.assertEqual(ctx["errors"][0], "ssh: no hay credenciales SSH configuradas (Ajustes -> Agentes -> Barrido)")


class SweepPushesNotesTests(unittest.TestCase):
    def _sweep(self, collectors: list) -> dict:
        from agent import __main__ as loop

        client = mock.Mock()
        client.heartbeat.return_value = {"interval_seconds": 900, "config": {}}
        client.push_findings.return_value = {"created": 0, "refreshed": 0}
        with mock.patch.object(loop, "all_collectors", return_value=collectors), mock.patch("builtins.print"):
            loop.sweep(client, Config(url="http://localhost:8000", token="t"), report=False)
        return client.push_findings.call_args.kwargs["run"]

    def test_the_run_carries_the_old_text_and_the_notes(self) -> None:
        collector = mock.Mock()
        collector.name = "ssh"
        collector.collect.side_effect = lambda ctx: ctx.setdefault("errors", []).append(
            notes.collector_note("ssh", "no_credentials", "no hay credenciales")
        ) or []

        run = self._sweep([collector])

        self.assertEqual(run["error"], "ssh: no hay credenciales")
        self.assertEqual(
            run["notes"], [{"collector": "ssh", "code": "no_credentials", "params": {}, "text": "ssh: no hay credenciales"}]
        )
        json.dumps(run)  # viaja como JSON

    def test_a_collector_that_blows_up_becomes_a_crashed_note(self) -> None:
        collector = mock.Mock()
        collector.name = "snmp"
        collector.collect.side_effect = KeyError("ifIndex")

        run = self._sweep([collector])

        self.assertEqual(run["notes"][0]["code"], "crashed")
        self.assertEqual(run["notes"][0]["collector"], "snmp")
        self.assertEqual(run["notes"][0]["params"]["detail"], "KeyError: 'ifIndex'")


class ProbeCodesTests(unittest.TestCase):
    def test_the_report_keeps_its_lines_and_adds_codes(self) -> None:
        ctx = ctx_with(communities=["super-secreta", "otra"])
        with mock.patch.object(probe.snmp, "AVAILABLE", True), mock.patch.object(
            probe.snmp, "query_hosts", side_effect=[{}, {"10.0.0.9": {}}]
        ), mock.patch.object(probe.socket, "create_connection", side_effect=OSError("refused")):
            report = probe.report_for("10.0.0.9", ctx)

        self.assertEqual(report["snmp"], "contesta con la comunidad nº 2")
        self.assertEqual(report["ssh"], "puerto 22 cerrado")
        self.assertEqual(
            report["codes"],
            {
                "snmp": {"code": "answers_community", "params": {"index": 2}},
                "ssh": {"code": "closed", "params": {"port": 22}},
                "winrm": {"code": "closed", "params": {"ports": "5985/5986"}},
            },
        )
        # Ni la comunidad ni nada suyo en ningún sitio del informe.
        self.assertNotIn("super-secreta", json.dumps(report))

    def test_a_check_that_blows_up_leaves_a_coded_line(self) -> None:
        ctx = ctx_with()
        with mock.patch.object(probe, "_snmp_line", side_effect=RuntimeError("x")), mock.patch.object(
            probe, "_ssh_line", return_value=notes.probe_note("ssh", "none_worked", "puerto abierto; ninguna credencial entró")
        ), mock.patch.object(probe, "_winrm_line", return_value="un texto sin código"):
            report = probe.report_for("10.0.0.9", ctx)

        self.assertEqual(report["codes"]["snmp"], {"code": "check_failed", "params": {"error": "RuntimeError"}})
        self.assertEqual(report["codes"]["winrm"], {"code": "", "params": {}})
        self.assertEqual(report["winrm"], "un texto sin código")


if __name__ == "__main__":
    unittest.main()
