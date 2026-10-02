"""El sondeo dirigido, con la red entera fingida.

Lo que estas pruebas fijan por encima de todo: **ningún secreto en el
informe** -- una comunidad SNMP es una credencial y se cita por su número,
nunca por su valor -- y que un protocolo que revienta deja su línea de
disculpa en vez de tumbar el informe entero.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado también bajo `unittest discover`

import unittest
from unittest import mock

from agent import probe
from agent.config import Config


def ctx_with(**config) -> dict:
    return {"config": config, "env": None}


def no_ports_open(*args, **kwargs):  # noqa: ANN001 - hace de socket.create_connection
    raise OSError("refused")


class SnmpLineTests(unittest.TestCase):
    def test_an_answer_names_the_community_by_number_never_by_value(self) -> None:
        ctx = ctx_with(communities=["super-secreta", "publica-vieja"])
        with mock.patch.object(probe.snmp, "AVAILABLE", True), \
             mock.patch.object(probe.snmp, "query_hosts", side_effect=[{}, {"10.0.0.9": {}}]):
            line = probe._snmp_line("10.0.0.9", ctx)

        self.assertEqual(line, "contesta con la comunidad nº 2")
        self.assertNotIn("super-secreta", line)
        self.assertNotIn("publica-vieja", line)

    def test_a_v3_user_is_cited_by_name(self) -> None:
        ctx = ctx_with(credentials=[{"kind": "snmpv3", "username": "lector"}])
        with mock.patch.object(probe.snmp, "AVAILABLE", True), \
             mock.patch.object(probe.snmp, "query_hosts", return_value={"10.0.0.9": {}}):
            line = probe._snmp_line("10.0.0.9", ctx)

        self.assertIn("«lector»", line)

    def test_silence_says_what_to_check(self) -> None:
        ctx = ctx_with(communities=["x"])
        with mock.patch.object(probe.snmp, "AVAILABLE", True), \
             mock.patch.object(probe.snmp, "query_hosts", return_value={}):
            line = probe._snmp_line("10.0.0.9", ctx)

        self.assertIn("no contesta", line)

    def test_without_pysnmp_the_line_says_so(self) -> None:
        with mock.patch.object(probe.snmp, "AVAILABLE", False):
            self.assertIn("pysnmp", probe._snmp_line("10.0.0.9", ctx_with()))


class SshLineTests(unittest.TestCase):
    def test_a_closed_port_is_the_whole_answer(self) -> None:
        with mock.patch.object(probe.socket, "create_connection", side_effect=no_ports_open):
            self.assertEqual(probe._ssh_line("10.0.0.9", ctx_with()), "puerto 22 cerrado")

    def test_open_without_credentials_asks_for_them(self) -> None:
        with mock.patch.object(probe, "_port_open", return_value=True):
            line = probe._ssh_line("10.0.0.9", ctx_with())

        self.assertIn("sin credenciales SSH", line)

    def test_the_credential_that_enters_is_named(self) -> None:
        ctx = ctx_with(credentials=[
            {"kind": "ssh", "username": "malo", "secret": "x"},
            {"kind": "ssh", "username": "bueno", "secret": "y"},
        ])
        answers = [probe.ssh.Answer(connected=False, error="denegado"),
                   probe.ssh.Answer(connected=True, output="")]
        with mock.patch.object(probe, "_port_open", return_value=True), \
             mock.patch.object(probe.ssh, "run", side_effect=answers):
            line = probe._ssh_line("10.0.0.9", ctx)

        self.assertIn("«bueno»", line)

    def test_nobody_entering_is_said_without_secrets(self) -> None:
        ctx = ctx_with(credentials=[{"kind": "ssh", "username": "root", "secret": "clarisima"}])
        with mock.patch.object(probe, "_port_open", return_value=True), \
             mock.patch.object(probe.ssh, "run", return_value=probe.ssh.Answer(connected=False)):
            line = probe._ssh_line("10.0.0.9", ctx)

        self.assertIn("ninguna credencial entró", line)
        self.assertNotIn("clarisima", line)


class WinrmLineTests(unittest.TestCase):
    def test_both_ports_closed(self) -> None:
        with mock.patch.object(probe, "_port_open", return_value=False):
            self.assertIn("cerrados", probe._winrm_line("10.0.0.9", ctx_with()))

    def test_an_entering_credential_is_named_with_its_port(self) -> None:
        ctx = ctx_with(credentials=[{"kind": "winrm", "username": "ACME\\admin", "secret": "x"}])
        with mock.patch.object(probe, "_port_open", side_effect=[True]), \
             mock.patch.object(probe.winrm, "query", return_value=probe.winrm.Answer(connected=True, data={})):
            line = probe._winrm_line("10.0.0.9", ctx)

        self.assertIn("entró con «ACME\\admin»", line)
        self.assertIn("5985", line)

    def test_a_rejection_keeps_the_error_short_and_secretless(self) -> None:
        ctx = ctx_with(credentials=[{"kind": "winrm", "username": "admin", "secret": "larguisima"}])
        with mock.patch.object(probe, "_port_open", side_effect=[True]), \
             mock.patch.object(probe.winrm, "query",
                               return_value=probe.winrm.Answer(connected=False, error="E" * 300)):
            line = probe._winrm_line("10.0.0.9", ctx)

        self.assertIn("ninguna credencial entró", line)
        self.assertLess(len(line), 200)
        self.assertNotIn("larguisima", line)


class ReportTests(unittest.TestCase):
    def test_a_blowing_check_leaves_its_line_instead_of_killing_the_report(self) -> None:
        with mock.patch.object(probe, "_snmp_line", side_effect=RuntimeError("bum")), \
             mock.patch.object(probe, "_ssh_line", return_value="puerto 22 cerrado"), \
             mock.patch.object(probe, "_winrm_line", return_value="puertos 5985/5986 cerrados"):
            report = probe.report_for("10.0.0.9", ctx_with())

        self.assertIn("no se pudo comprobar", report["snmp"])
        self.assertEqual(report["ssh"], "puerto 22 cerrado")
        self.assertIn("at", report)

    def test_the_servers_orders_become_findings_by_ip(self) -> None:
        ctx = ctx_with(probe_ips=["10.0.0.9", "", "10.0.0.7"])
        with mock.patch.object(probe, "report_for", return_value={"snmp": "x", "at": "t"}):
            items = probe.findings_for(ctx)

        self.assertEqual([item["identity"] for item in items], [{"ip": "10.0.0.9"}, {"ip": "10.0.0.7"}])
        self.assertTrue(all(item["payload"]["probe_report"] for item in items))
        self.assertTrue(all(item["kind"] == "host" for item in items))

    def test_the_probe_ceiling_holds(self) -> None:
        ctx = ctx_with(probe_ips=[f"10.0.0.{i}" for i in range(1, 60)])
        with mock.patch.object(probe, "report_for", return_value={"at": "t"}):
            items = probe.findings_for(ctx)

        self.assertEqual(len(items), probe.MAX_PROBES)

    def test_no_orders_no_work(self) -> None:
        self.assertEqual(probe.findings_for(ctx_with()), [])



class NapTests(unittest.TestCase):
    """La siesta a sorbos: es lo que hace posibles los dos botones."""

    def _client(self, answers):
        client = mock.Mock()
        client.heartbeat.side_effect = answers
        return client

    def test_sweep_now_breaks_the_nap(self) -> None:
        from agent.__main__ import _nap

        client = self._client([{"interval_seconds": 900, "sweep_now": False},
                               {"interval_seconds": 900, "sweep_now": True}])
        with mock.patch("agent.__main__.time.sleep") as slept:
            _nap(client, interval=900)

        # Dos sorbos de 60 s y fuera: no se durmió los 900.
        self.assertEqual(slept.call_count, 2)

    def test_a_probe_order_also_wakes_it(self) -> None:
        from agent.__main__ import _nap

        client = self._client([
            {"interval_seconds": 900, "sweep_now": False, "config": {"probe_ips": ["10.0.0.9"]}},
        ])
        with mock.patch("agent.__main__.time.sleep") as slept:
            _nap(client, interval=900)

        self.assertEqual(slept.call_count, 1)

    def test_a_dead_server_does_not_wake_or_kill_the_nap(self) -> None:
        from agent.__main__ import _nap

        client = self._client([ConnectionError("caído")] * 14)
        with mock.patch("agent.__main__.time.sleep") as slept:
            result = _nap(client, interval=900)

        # 900 / 60 = 15 sorbos completos; el último no pregunta (ya toca barrer).
        self.assertEqual(slept.call_count, 15)
        self.assertEqual(result, 900)

    def test_the_server_can_shrink_the_interval_mid_nap(self) -> None:
        from agent.__main__ import _nap

        client = self._client([{"interval_seconds": 60, "sweep_now": False}] * 5)
        with mock.patch("agent.__main__.time.sleep") as slept:
            result = _nap(client, interval=900)

        self.assertEqual(result, 60)
        # El primer sorbo revela el intervalo nuevo (60): ya está cumplido.
        self.assertEqual(slept.call_count, 1)

if __name__ == "__main__":
    unittest.main()
