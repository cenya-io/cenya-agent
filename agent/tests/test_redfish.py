"""Redfish: la tarjeta de control remoto cuenta su servidor.

Lo que se fija aquí:

* La lectura pura: el *service tag* de Dell sale de ``SKU``; el estado de cada
  fuente con las palabras de `agent/power.py`; las MAC de las tarjetas de red.
* Solo se siguen enlaces de la propia tarjeta.
* El certificado se fija la primera vez, y uno distinto no recibe la contraseña.
* El colector solo entra en las IP marcadas como tarjeta, con el
  cortacircuitos de siempre, y sin credenciales lo dice.
* «Probar» devuelve una línea con código, nunca un secreto.
"""

from __future__ import annotations

import unittest
from unittest import mock

from agent import credentials as creds
from agent import orders, redfish
from agent.collectors import tasking
from agent.collectors.redfish import CARDS, RedfishCollector, mark_card
from agent.memory import Memory

IP = "10.0.9.21"
MAC = "d0:94:66:00:00:21"
SECRET = "calvin-de-fabrica"
PIN = "a" * 64
OTHER_PIN = "b" * 64

#: Las respuestas de un iDRAC9 de un PowerEdge R640, recortadas a lo que se lee.
IDRAC = {
    "/redfish/v1/": {
        "RedfishVersion": "1.11.0",
        "Systems": {"@odata.id": "/redfish/v1/Systems"},
        "Managers": {"@odata.id": "/redfish/v1/Managers"},
        "Chassis": {"@odata.id": "/redfish/v1/Chassis"},
    },
    "/redfish/v1/Systems": {"Members": [{"@odata.id": "/redfish/v1/Systems/System.Embedded.1"}]},
    "/redfish/v1/Systems/System.Embedded.1": {
        "Manufacturer": "Dell Inc.",
        "Model": "PowerEdge R640",
        "SerialNumber": "CNIVC0087Q00E1",
        "SKU": "1234ABC",
        "HostName": "esx01.acme.local",
        "PowerState": "On",
        "EthernetInterfaces": {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces"},
    },
    "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces": {
        "Members": [
            {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/NIC.Integrated.1-1-1"},
            {"@odata.id": "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/NIC.Integrated.1-2-1"},
            {"@odata.id": "https://otro.sitio/redfish/v1/robar"},
        ]
    },
    "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/NIC.Integrated.1-1-1": {
        "Id": "NIC.Integrated.1-1-1",
        "MACAddress": "B0:26:28:AA:BB:01",
    },
    "/redfish/v1/Systems/System.Embedded.1/EthernetInterfaces/NIC.Integrated.1-2-1": {
        "Id": "NIC.Integrated.1-2-1",
        "PermanentMACAddress": "b0-26-28-aa-bb-02",
    },
    "/redfish/v1/Managers": {"Members": [{"@odata.id": "/redfish/v1/Managers/iDRAC.Embedded.1"}]},
    "/redfish/v1/Managers/iDRAC.Embedded.1": {"FirmwareVersion": "7.00.00.00"},
    "/redfish/v1/Chassis": {"Members": [{"@odata.id": "/redfish/v1/Chassis/System.Embedded.1"}]},
    "/redfish/v1/Chassis/System.Embedded.1": {"Power": {"@odata.id": "/redfish/v1/Chassis/System.Embedded.1/Power"}},
    "/redfish/v1/Chassis/System.Embedded.1/Power": {
        "PowerSupplies": [
            {"Name": "PS1 Status", "Model": "PWR SPLY,750W", "PowerCapacityWatts": 750,
             "LineInputVoltage": 230, "Status": {"State": "Enabled", "Health": "OK"}},
            {"Name": "PS2 Status", "Model": "PWR SPLY,750W", "PowerCapacityWatts": 750,
             "LineInputVoltage": 0, "Status": {"State": "Enabled", "Health": "Critical"}},
        ]
    },
}


def fake_fetch(responses: dict, asked: list | None = None):
    def fetch(path: str) -> dict:
        if asked is not None:
            asked.append(path)
        if path not in responses:
            raise redfish.RedfishError(redfish.UNREACHABLE, "404")
        return responses[path]

    return fetch


def credential(ident: str = "cred-rf", **extra: str) -> creds.Credential:
    return creds._one({"kind": "redfish", "username": "root", "secret": SECRET, "id": ident, **extra}, 0)


class ReadingTests(unittest.TestCase):
    def test_dell_gives_its_service_tag_from_the_sku(self) -> None:
        self.assertEqual(
            redfish.identity(IDRAC["/redfish/v1/Systems/System.Embedded.1"]),
            {"manufacturer": "Dell Inc.", "model": "PowerEdge R640", "serial": "1234ABC"},
        )

    def test_the_others_give_their_serial_number(self) -> None:
        system = {"Manufacturer": "HPE", "Model": "ProLiant DL380 Gen10", "SerialNumber": "CZJ1234567", "SKU": "868703-B21"}
        self.assertEqual(redfish.identity(system)["serial"], "CZJ1234567")

    def test_each_supply_state_in_the_words_of_power(self) -> None:
        cases = [
            ({"Status": {"State": "Enabled", "Health": "OK"}}, "ok"),
            ({"Status": {"State": "Enabled", "Health": "Critical"}, "LineInputVoltage": 0}, "no_input"),
            ({"Status": {"State": "Enabled", "Health": "Critical"}, "LineInputVoltage": 230}, "failed"),
            ({"Status": {"State": "Absent"}}, "absent"),
            ({"Status": {"State": "UnavailableOffline"}}, "off"),
            ({}, ""),
        ]
        for raw, expected in cases:
            self.assertEqual(redfish.supply_status(raw), expected, raw)

    def test_the_card_takes_its_name_from_what_was_known_or_its_maker(self) -> None:
        self.assertEqual(redfish.card_name("Dell Inc."), "iDRAC")
        self.assertEqual(redfish.card_name("HPE"), "iLO")
        self.assertEqual(redfish.card_name("Supermicro"), "BMC")
        self.assertEqual(redfish.card_name("Supermicro", "iLO"), "iLO")
        self.assertEqual(redfish.card_name("Supermicro", "<inventado>"), "BMC")


class CollectTests(unittest.TestCase):
    def test_everything_the_contract_promises(self) -> None:
        asked: list = []

        data = redfish.collect(fake_fetch(IDRAC, asked), "iDRAC")

        self.assertEqual(data["serial"], "1234ABC")
        self.assertEqual(data["os"], "iDRAC 7.00.00.00")
        self.assertEqual(data["redfish"]["card"], "iDRAC")
        self.assertEqual(data["redfish"]["hostname"], "esx01.acme.local")
        self.assertEqual(
            data["redfish"]["nics"],
            [
                {"name": "NIC.Integrated.1-1-1", "mac": "b0:26:28:aa:bb:01"},
                {"name": "NIC.Integrated.1-2-1", "mac": "b0:26:28:aa:bb:02"},
            ],
        )
        self.assertEqual(
            [(s["name"], s["status"], s.get("capacity_w")) for s in data["power_supplies"]],
            [("PS1 Status", "ok", 750), ("PS2 Status", "no_input", 750)],
        )
        self.assertFalse(any("otro.sitio" in path for path in asked))

    def test_what_is_optional_may_fail_without_losing_the_server(self) -> None:
        trimmed = {path: body for path, body in IDRAC.items() if "Managers" not in path and "Chassis" not in path}

        data = redfish.collect(fake_fetch(trimmed))

        self.assertEqual(data["model"], "PowerEdge R640")
        self.assertNotIn("power_supplies", data)
        self.assertEqual(data["os"], "iDRAC")

    def test_a_web_that_is_not_redfish_says_so(self) -> None:
        with self.assertRaises(redfish.RedfishError) as caught:
            redfish.collect(fake_fetch({"/redfish/v1/": {"hola": "mundo"}}))
        self.assertEqual(caught.exception.code, redfish.NOT_REDFISH)


class PinTests(unittest.TestCase):
    def test_the_first_time_the_certificate_it_presents_is_pinned(self) -> None:
        with mock.patch.object(redfish.tlspin, "describe", return_value={"sha256": PIN}), mock.patch.object(
            redfish, "_opener_fetch", return_value=fake_fetch(IDRAC)
        ) as opener:
            answer = redfish.read(IP, "root", SECRET)

        self.assertTrue(answer.connected)
        self.assertEqual(answer.pin, PIN)
        self.assertEqual(opener.call_args.args[3], PIN)

    def test_with_a_pin_nobody_asks_for_the_certificate_again(self) -> None:
        with mock.patch.object(redfish.tlspin, "describe") as describe, mock.patch.object(
            redfish, "_opener_fetch", return_value=fake_fetch(IDRAC)
        ):
            redfish.read(IP, "root", SECRET, pin=PIN)

        describe.assert_not_called()

    def test_another_certificate_is_untrusted_and_the_password_does_not_leave(self) -> None:
        def mismatch(path: str) -> dict:
            raise redfish.RedfishError(redfish.CERTIFICATE_CHANGED)

        with mock.patch.object(redfish, "_opener_fetch", return_value=mismatch):
            answer = redfish.read(IP, "root", SECRET, pin=PIN)

        self.assertFalse(answer.connected)
        self.assertEqual(answer.code, redfish.CERTIFICATE_CHANGED)
        self.assertIsNotNone(answer.certificate)
        self.assertEqual(redfish.outcome(answer), "unreachable")

    def test_the_memory_keeps_the_first_pin_only(self) -> None:
        memory = Memory(None)
        memory.remember_pin(MAC, "redfish", PIN)
        memory.remember_pin(MAC, "redfish", OTHER_PIN)
        memory.remember_pin(MAC, "redfish", "no-es-una-huella")

        self.assertEqual(memory.pin_for(MAC, "redfish"), PIN)


class CollectorTests(unittest.TestCase):
    def ctx(self, **extra: object) -> dict:
        ctx: dict = {
            "config": {"credentials": []},
            "env": None,
            "task": "inventory",
            "hosts": [{"ip": IP, "mac": MAC}, {"ip": "10.0.0.5", "mac": ""}],
            "memory": Memory(None),
        }
        ctx.update(extra)
        return ctx

    def test_without_cards_it_does_nothing(self) -> None:
        with mock.patch.object(redfish, "read") as read:
            self.assertEqual(RedfishCollector().collect(self.ctx()), [])
        read.assert_not_called()

    def test_only_the_marked_cards_are_asked(self) -> None:
        ctx = self.ctx()
        mark_card(ctx, IP, "iDRAC")
        answer = redfish.Answer(connected=True, data=redfish.collect(fake_fetch(IDRAC), "iDRAC"), pin=PIN)

        with mock.patch.object(creds, "for_kind", return_value=[credential()]), mock.patch.object(
            redfish, "read", return_value=answer
        ) as read:
            findings = RedfishCollector().collect(ctx)

        self.assertEqual([call.args[0] for call in read.call_args_list], [IP])
        self.assertEqual(len(findings), 1)
        finding = findings[0].as_json()
        self.assertEqual(finding["identity"], {"mac": MAC})
        self.assertEqual(finding["payload"]["seen_by"], "redfish")
        self.assertEqual(finding["payload"]["redfish"]["card"], "iDRAC")
        self.assertNotIn(SECRET, str(finding))
        self.assertEqual(ctx["memory"].pin_for(MAC, "redfish"), PIN)
        self.assertEqual(tasking.attempts(ctx), [{"ip": IP, "protocol": "redfish", "code": "ok", "credential": "cred-rf"}])

    def test_without_credentials_it_says_so(self) -> None:
        ctx = self.ctx()
        mark_card(ctx, IP, "iLO")

        self.assertEqual(RedfishCollector().collect(ctx), [])
        self.assertEqual([note.code for note in ctx["errors"]], ["no_credentials"])
        self.assertEqual(tasking.attempts(ctx), [{"ip": IP, "protocol": "redfish", "code": "no_credentials"}])

    def test_a_wrong_password_stops_at_the_breaker_and_is_recorded(self) -> None:
        ctx = self.ctx()
        mark_card(ctx, IP, "iDRAC")
        refused = redfish.Answer(connected=False, code=redfish.AUTH_FAILED, pin=PIN)

        with mock.patch.object(creds, "for_kind", return_value=[credential()]), mock.patch.object(
            redfish, "read", return_value=refused
        ):
            self.assertEqual(RedfishCollector().collect(ctx), [])

        self.assertEqual(tasking.attempts(ctx)[0]["code"], "auth_failed")

    def test_a_changed_certificate_does_not_try_the_next_password(self) -> None:
        ctx = self.ctx()
        mark_card(ctx, IP, "iDRAC")
        changed = redfish.Answer(connected=False, code=redfish.CERTIFICATE_CHANGED, certificate={"sha256": ""})

        with mock.patch.object(creds, "for_kind", return_value=[credential("a"), credential("b")]), mock.patch.object(
            redfish, "read", return_value=changed
        ) as read:
            RedfishCollector().collect(ctx)

        self.assertEqual(read.call_count, 1)
        self.assertEqual(tasking.attempts(ctx)[0]["code"], "tls_untrusted")

    def test_a_card_out_of_scope_is_not_touched(self) -> None:
        ctx = self.ctx()
        mark_card(ctx, IP, "iDRAC")

        with mock.patch.object(
            creds, "for_kind", return_value=[credential(scope={"subnets": ["192.168.0.0/24"]})]
        ), mock.patch.object(redfish, "read") as read:
            RedfishCollector().collect(ctx)

        read.assert_not_called()

    def test_the_mark_keeps_the_first_name(self) -> None:
        ctx: dict = {}
        mark_card(ctx, IP, "iDRAC")
        mark_card(ctx, IP, "iLO")
        self.assertEqual(ctx[CARDS], {IP: "iDRAC"})


class TestCredentialTests(unittest.TestCase):
    def test_probar_answers_with_a_code_and_never_the_secret(self) -> None:
        ctx = {"config": {"credentials": []}, "memory": Memory(None)}
        answer = redfish.Answer(connected=True, data={}, pin=PIN)

        with mock.patch.object(creds, "find", return_value=(credential(), True)), mock.patch.object(
            redfish, "read", return_value=answer
        ):
            status, result, _notes = orders.test_credential({"credential_id": "cred-rf", "ip": IP}, ctx)

        self.assertTrue(result["ok"])
        self.assertEqual(result["line"]["protocol"], "redfish")
        self.assertEqual(result["line"]["code"], "logged_in")
        self.assertNotIn(SECRET, str(result))

    def test_a_refused_login_is_a_line_too(self) -> None:
        ctx = {"config": {"credentials": []}}
        refused = redfish.Answer(connected=False, code=redfish.AUTH_FAILED)

        with mock.patch.object(creds, "find", return_value=(credential(), True)), mock.patch.object(
            redfish, "read", return_value=refused
        ):
            _status, result, _notes = orders.test_credential({"credential_id": "cred-rf", "ip": IP}, ctx)

        self.assertFalse(result["ok"])
        self.assertEqual(result["line"]["code"], "auth_failed")


if __name__ == "__main__":
    unittest.main()
