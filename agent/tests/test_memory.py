"""La memoria del agente y las exclusiones (`agent/memory.py`).

Lo que se fija aquí, por encima de todo: la memoria **nunca lanza** (falta,
está rota, no se puede escribir: da igual), **nunca guarda un secreto**, y
`order_for` es lo que evita que el agente sume intentos fallidos contra un
Directorio Activo cada pocos minutos.

Todo en carpetas temporales: en esta máquina hay un agente de verdad enrolado
y su carpeta de estado no se toca.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado también bajo `unittest discover`

import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import credentials as creds
from agent.memory import FORGET_AFTER, ROUND_COOLDOWN, Excluded, Memory

T0 = datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)


def credential(username: str, *, ident: str = "", secret: str = "s", **scope) -> creds.Credential:
    return creds.Credential(
        kind="ssh",
        username=username,
        secret=secret,
        ident=ident or f"id-{username}",
        scope=creds.Scope(subnets=tuple(scope.get("subnets", ())), hosts=tuple(scope.get("hosts", ()))),
    )


A, B, C = credential("a"), credential("b"), credential("c")


class TempDirTest(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory(prefix="cenya-memory-test-")
        self.addCleanup(self._dir.cleanup)
        self.path = Path(self._dir.name) / "memory.json"


class DiskTests(TempDirTest):
    def test_a_round_trip_keeps_hosts_flags_successes_and_failures(self) -> None:
        memory = Memory.load(self.path)
        memory.credentials_changed("etag-1")
        memory.note_host("10.0.0.5", "AA-BB-CC-DD-EE-01", T0)
        memory.flag("aa:bb:cc:dd:ee:01", ups=True, identity_mac="aa:bb:cc:dd:ee:99")
        memory.note_host("10.0.0.6", "aa:bb:cc:dd:ee:02", T0)
        memory.flag("aa:bb:cc:dd:ee:02", config_family="cisco", identity_mac="aa:bb:cc:dd:ee:02")
        memory.record_success("aa:bb:cc:dd:ee:02", "ssh", B, T0)
        memory.record_round_failed("aa:bb:cc:dd:ee:01", "snmp", T0)
        memory.save()

        again = Memory.load(self.path)

        self.assertEqual(again.ups_hosts(), [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:01", "identity_mac": "aa:bb:cc:dd:ee:99"}])
        self.assertEqual(
            again.config_hosts(),
            [{"ip": "10.0.0.6", "mac": "aa:bb:cc:dd:ee:02", "family": "cisco", "identity_mac": "aa:bb:cc:dd:ee:02"}],
        )
        self.assertEqual(again.order_for("aa:bb:cc:dd:ee:02", "ssh", [A, B, C], T0), [B, A, C])
        self.assertEqual(again.order_for("aa:bb:cc:dd:ee:01", "snmp", [A, B], T0 + timedelta(hours=1)), [])
        # El etag también vuelve: el mismo etag no borra la ronda fallida.
        again.credentials_changed("etag-1")
        self.assertEqual(again.order_for("aa:bb:cc:dd:ee:01", "snmp", [A], T0 + timedelta(hours=1)), [])

    def test_a_missing_file_is_an_empty_memory(self) -> None:
        memory = Memory.load(self.path)

        self.assertEqual(memory.ups_hosts(), [])
        self.assertTrue(memory.note_host("10.0.0.5", "", T0))

    def test_a_corrupt_file_is_an_empty_memory_not_a_crash(self) -> None:
        for garbage in ("{esto no es json", "[1, 2, 3]", '"texto"', '{"hosts": "no"}', '{"hosts": {"x": 7}}'):
            with self.subTest(garbage=garbage):
                self.path.write_text(garbage, encoding="utf-8")
                memory = Memory.load(self.path)
                self.assertEqual(memory.config_hosts(), [])
                self.assertTrue(memory.note_host("10.0.0.5", "", T0))

    def test_odd_fields_inside_a_good_file_are_cleaned_one_by_one(self) -> None:
        self.path.write_text(
            json.dumps(
                {
                    "hosts": {
                        "10.0.0.5": {"ip": "10.0.0.5", "last_seen": T0.isoformat(), "ups": "sí", "creds": {"ssh": 3}},
                        "10.0.0.6": {"ip": "10.0.0.6", "last_seen": T0.isoformat(), "ups": True},
                    }
                }
            ),
            encoding="utf-8",
        )

        memory = Memory.load(self.path)

        # «sí» no es True: solo un booleano de verdad marca un SAI.
        self.assertEqual([host["ip"] for host in memory.ups_hosts()], ["10.0.0.6"])
        self.assertEqual(memory.order_for("10.0.0.5", "ssh", [A], T0), [A])

    def test_save_never_raises_even_where_it_cannot_write(self) -> None:
        blocker = Path(self._dir.name) / "soy-un-fichero"
        blocker.write_text("x", encoding="utf-8")
        memory = Memory.load(blocker / "memory.json")  # su «carpeta» es un fichero
        memory.note_host("10.0.0.5", "", T0)

        memory.save()  # no lanza

        self.assertFalse((blocker / "memory.json").exists())

    def test_save_leaves_no_temporary_files_behind(self) -> None:
        memory = Memory.load(self.path)
        memory.note_host("10.0.0.5", "", T0)
        memory.save()
        memory.save()

        self.assertEqual(sorted(p.name for p in Path(self._dir.name).iterdir()), ["memory.json"])

    def test_without_a_path_it_lives_only_in_memory(self) -> None:
        memory = Memory.load(None)
        memory.note_host("10.0.0.5", "", T0)
        memory.save()  # no-op

        self.assertFalse(memory.note_host("10.0.0.5", "", T0))

    def test_nothing_secret_ever_reaches_the_disk(self) -> None:
        """De una credencial solo su `ident`. Una comunidad SNMP **es** un
        secreto: se recuerda por su número."""
        ssh = creds.all_from(
            {"config": {"credentials": [{"kind": "ssh", "username": "root", "secret": "ContraseñaSSH-1"}]}, "env": None}
        )[0]
        v3 = creds.Credential(kind="snmpv3", username="lector", secret="AuthV3-secreta", priv_secret="PrivV3-secreta")
        community = creds.community("ComunidadSecreta", 2)
        memory = Memory.load(self.path)
        memory.note_host("10.0.0.5", "aa:bb:cc:dd:ee:01", T0)
        memory.record_success("aa:bb:cc:dd:ee:01", "ssh", ssh, T0)
        memory.record_success("aa:bb:cc:dd:ee:01", "snmp", community, T0)
        memory.record_success("10.0.0.7", "snmp", v3, T0)
        memory.save()

        on_disk = self.path.read_text(encoding="utf-8")

        for secret in ("ContraseñaSSH-1", "AuthV3-secreta", "PrivV3-secreta", "ComunidadSecreta"):
            self.assertNotIn(secret, on_disk)
        self.assertIn("community-2", on_disk)
        self.assertIn(ssh.ident, on_disk)


class HostTests(unittest.TestCase):
    def test_note_host_says_whether_it_is_new(self) -> None:
        memory = Memory.load(None)

        self.assertTrue(memory.note_host("10.0.0.5", "aa:bb:cc:dd:ee:01", T0))
        self.assertFalse(memory.note_host("10.0.0.5", "aa:bb:cc:dd:ee:01", T0))
        # La misma MAC con otra IP es el mismo equipo.
        self.assertFalse(memory.note_host("10.0.0.99", "aa:bb:cc:dd:ee:01", T0))
        self.assertTrue(memory.note_host("10.0.0.6", "", T0))

    def test_a_host_first_seen_without_a_mac_keeps_what_it_learnt_when_the_mac_arrives(self) -> None:
        memory = Memory.load(None)
        memory.note_host("10.0.0.5", "", T0)
        memory.record_success("10.0.0.5", "ssh", B, T0)

        self.assertFalse(memory.note_host("10.0.0.5", "aa:bb:cc:dd:ee:01", T0))
        self.assertEqual(memory.key_for("10.0.0.5", ""), "aa:bb:cc:dd:ee:01")
        self.assertEqual(memory.order_for("aa:bb:cc:dd:ee:01", "ssh", [A, B], T0), [B, A])

    def test_a_host_unseen_for_thirty_days_is_forgotten(self) -> None:
        memory = Memory.load(None)
        memory.note_host("10.0.0.5", "aa:bb:cc:dd:ee:01", T0)
        memory.flag("aa:bb:cc:dd:ee:01", ups=True)
        memory.note_host("10.0.0.6", "", T0 + timedelta(days=20))

        memory.note_host("10.0.0.6", "", T0 + FORGET_AFTER + timedelta(minutes=1))

        self.assertEqual(memory.ups_hosts(), [])
        self.assertTrue(memory.note_host("10.0.0.5", "aa:bb:cc:dd:ee:01", T0 + FORGET_AFTER + timedelta(minutes=2)))
        self.assertFalse(memory.note_host("10.0.0.6", "", T0 + FORGET_AFTER + timedelta(minutes=3)))

    def test_flags_can_be_cleared_and_none_leaves_them_alone(self) -> None:
        memory = Memory.load(None)
        memory.note_host("10.0.0.5", "", T0)
        memory.flag("10.0.0.5", ups=True, config_family="cisco")

        memory.flag("10.0.0.5", identity_mac="AA-BB-CC-DD-EE-01")
        self.assertEqual(memory.ups_hosts()[0]["identity_mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(memory.config_hosts()[0]["family"], "cisco")

        memory.flag("10.0.0.5", ups=False, config_family="")
        self.assertEqual((memory.ups_hosts(), memory.config_hosts()), ([], []))


class OrderTests(unittest.TestCase):
    KEY = "aa:bb:cc:dd:ee:01"

    def setUp(self) -> None:
        self.memory = Memory.load(None)
        self.memory.note_host("10.0.0.5", self.KEY, T0)

    def test_with_nothing_known_every_credential_in_its_order(self) -> None:
        self.assertEqual(self.memory.order_for(self.KEY, "ssh", [A, B, C], T0), [A, B, C])

    def test_the_one_that_worked_goes_first(self) -> None:
        self.memory.record_success(self.KEY, "ssh", C, T0)

        self.assertEqual(self.memory.order_for(self.KEY, "ssh", [A, B, C], T0), [C, A, B])
        self.assertEqual(self.memory.remembered(self.KEY, "ssh"), "id-c")
        # Por protocolo: lo que entró por SSH no dice nada de WinRM.
        self.assertEqual(self.memory.order_for(self.KEY, "winrm", [A, B, C], T0), [A, B, C])

    def test_no_second_full_round_within_a_day(self) -> None:
        self.memory.record_round_failed(self.KEY, "ssh", T0)

        self.assertEqual(self.memory.order_for(self.KEY, "ssh", [A, B, C], T0 + timedelta(hours=23)), [])
        self.assertEqual(
            self.memory.order_for(self.KEY, "ssh", [A, B, C], T0 + ROUND_COOLDOWN + timedelta(seconds=1)),
            [A, B, C],
        )

    def test_after_a_failed_round_only_the_remembered_one_is_tried(self) -> None:
        self.memory.record_success(self.KEY, "ssh", B, T0)
        self.memory.record_round_failed(self.KEY, "ssh", T0 + timedelta(hours=1))

        self.assertEqual(self.memory.order_for(self.KEY, "ssh", [A, B, C], T0 + timedelta(hours=2)), [B])

    def test_a_success_after_a_failed_round_puts_itself_first_and_leaves_the_veto(self) -> None:
        """Un acierto (de un sondeo, por ejemplo) no reabre la ronda: con la
        que entró delante, las demás pueden esperar a que pase el día."""
        self.memory.record_round_failed(self.KEY, "ssh", T0)
        self.memory.record_success(self.KEY, "ssh", B, T0 + timedelta(hours=1))

        self.assertEqual(self.memory.order_for(self.KEY, "ssh", [A, B], T0 + timedelta(hours=2)), [B])
        self.assertEqual(self.memory.order_for(self.KEY, "ssh", [A, B], T0 + ROUND_COOLDOWN + timedelta(hours=1)), [B, A])

    def test_scope_filters_before_anything_else(self) -> None:
        elsewhere = credential("fuera", subnets=["192.168.0.0/16"])
        here = credential("dentro", subnets=["10.0.0.0/24"])
        by_host = credential("por-host", hosts=["10.0.0.5"])
        self.memory.record_success(self.KEY, "ssh", elsewhere, T0)  # recordada, pero fuera de alcance

        order = self.memory.order_for(self.KEY, "ssh", [elsewhere, here, by_host, A], T0)

        self.assertEqual(order, [here, by_host, A])

    def test_a_scoped_credential_is_not_tried_on_a_host_without_a_known_address(self) -> None:
        here = credential("dentro", subnets=["10.0.0.0/24"])

        self.assertEqual(self.memory.order_for("aa:bb:cc:00:00:99", "ssh", [here, A], T0), [A])

    def test_a_new_etag_allows_a_new_round_but_keeps_the_successes(self) -> None:
        self.memory.credentials_changed("etag-1")
        self.memory.record_success(self.KEY, "ssh", B, T0)
        self.memory.record_round_failed(self.KEY, "ssh", T0)
        self.memory.record_round_failed("10.0.0.9", "winrm", T0)

        self.memory.credentials_changed("etag-1")  # el mismo: nada cambia
        self.assertEqual(self.memory.order_for(self.KEY, "ssh", [A, B], T0 + timedelta(hours=1)), [B])

        self.memory.credentials_changed("etag-2")
        self.assertEqual(self.memory.order_for(self.KEY, "ssh", [A, B], T0 + timedelta(hours=1)), [B, A])
        self.assertEqual(self.memory.order_for("10.0.0.9", "winrm", [A], T0 + timedelta(hours=1)), [A])

    def test_naive_and_aware_dates_do_not_blow_up(self) -> None:
        self.memory.record_round_failed(self.KEY, "ssh", T0.replace(tzinfo=None))

        self.assertEqual(self.memory.order_for(self.KEY, "ssh", [A], T0 + timedelta(hours=1)), [])


class ThreadSafetyTests(unittest.TestCase):
    def test_many_threads_at_once_lose_nothing_and_raise_nothing(self) -> None:
        """Un `probe` corre en su propio hilo mientras una tarea escribe."""
        with tempfile.TemporaryDirectory(prefix="cenya-memory-test-") as folder:
            memory = Memory.load(Path(folder) / "memory.json")
            failures: list[BaseException] = []

            def work(worker: int) -> None:
                try:
                    for index in range(50):
                        ip = f"10.{worker}.0.{index}"
                        memory.note_host(ip, "", T0)
                        memory.record_success(ip, "ssh", A, T0)
                        memory.flag(ip, ups=index % 2 == 0)
                        memory.order_for(ip, "ssh", [A, B], T0)
                        memory.ups_hosts()
                        if index % 10 == 0:
                            memory.save()
                except BaseException as exc:  # noqa: BLE001
                    failures.append(exc)

            threads = [threading.Thread(target=work, args=(worker,)) for worker in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            memory.save()

            self.assertEqual(failures, [])
            self.assertEqual(len(memory.ups_hosts()), 8 * 25)
            self.assertEqual(len(Memory.load(Path(folder) / "memory.json").ups_hosts()), 8 * 25)


class ExcludedTests(unittest.TestCase):
    def test_subnets_and_addresses(self) -> None:
        excluded = Excluded(subnets=["10.0.5.0/24"], addresses=["192.168.1.7"])

        self.assertIn("10.0.5.20", excluded)
        self.assertIn("192.168.1.7", excluded)
        self.assertNotIn("10.0.6.1", excluded)
        self.assertNotIn("192.168.1.8", excluded)

    def test_rubbish_entries_exclude_nothing_and_break_nothing(self) -> None:
        excluded = Excluded(subnets=["no-es-una-red", ""], addresses=["  "])

        self.assertNotIn("10.0.0.1", excluded)
        self.assertNotIn("", excluded)
        self.assertNotIn(None, excluded)

    def test_it_round_trips_as_the_about_shape(self) -> None:
        excluded = Excluded(["10.0.5.0/24"], ["10.0.0.1"])

        self.assertEqual(excluded.as_dict(), {"subnets": ["10.0.5.0/24"], "addresses": ["10.0.0.1"]})


if __name__ == "__main__":
    unittest.main()
