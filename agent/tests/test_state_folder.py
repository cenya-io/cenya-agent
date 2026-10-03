"""The state folder is protected on every start, and what a stranger left is not trusted.

Three layers:

* the judgement -- "was this folder protected?" -- as a pure function of an
  SDDL string, so it runs on Linux CI too;
* real ACLs on Windows, in temporary folders: an open folder with planted
  files, a folder Users may write into, and the layout the 0.10.x installer
  leaves (which must keep its enrolment);
* POSIX modes, skipped on Windows.

Nothing here touches the real ``%ProgramData%\\Cenya``.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from agent import config, store

ME = "S-1-5-21-1111-2222-3333-1001"
STRANGER = "S-1-5-21-1111-2222-3333-1077"

#: Lo que hereda una carpeta nueva dentro de %ProgramData% (leído en una máquina
#: real con `icacls C:\ProgramData /save` y su herencia).
PROGRAMDATA_CHILD = (
    "O:S-1-5-21-1111-2222-3333-1077D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)"
    "(A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)"
)
#: Lo que deja `lock_status_directory` desde la 0.10.x (pywin32 lo escribe así).
LOCK_LAYOUT = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1200a9;;;OW)"

NOW = datetime(2026, 10, 2, 9, 30, tzinfo=timezone.utc)
SUFFIX = ".untrusted-20261002T093000Z"


class JudgementTests(unittest.TestCase):
    def test_a_folder_inheriting_programdata_is_not_protected(self) -> None:
        self.assertFalse(store.sddl_is_protected(PROGRAMDATA_CHILD, ME))

    def test_the_layout_of_the_0_10_installer_is_protected(self) -> None:
        self.assertTrue(store.sddl_is_protected(LOCK_LAYOUT, ME))
        # Con OWNER RIGHTS, el dueño puede ser cualquiera: quien la creó antes
        # de instalar ya no puede reescribir la DACL.
        self.assertTrue(store.sddl_is_protected(LOCK_LAYOUT.replace("O:BA", f"O:{STRANGER}"), ME))

    def test_what_the_agent_writes_itself_is_protected(self) -> None:
        for sddl in (
            store.folder_sddl(ME, top=True),
            store.folder_sddl("", top=True, owner=True),
            "O:" + ME + store.folder_sddl(ME, top=True),
        ):
            with self.subTest(sddl=sddl):
                self.assertTrue(store.sddl_is_protected(sddl, ME))

    def test_a_protected_dacl_that_lets_a_broad_group_write_is_not_protected(self) -> None:
        for ace in (
            "(A;OICI;0x1301bf;;;BU)",  # Usuarios: modificar
            "(A;OICI;FA;;;S-1-5-32-545)",
            "(A;;GW;;;WD)",  # Todos
            "(A;OICI;FA;;;AU)",  # Usuarios autentificados
            "(A;CI;DC;;;IU)",  # INTERACTIVE: crear ficheros
            "(A;OICI;FA;;;S-1-5-21-1111-2222-3333-513)",  # Usuarios del dominio
            "(A;OICIIO;WD;;;BU)",  # aunque sea solo para lo que se cree dentro
            "(A;;ZZ;;;BU)",  # derechos que no se entienden: peligrosos
        ):
            with self.subTest(ace=ace):
                self.assertFalse(store.sddl_is_protected(f"O:BAD:P(A;OICI;FA;;;SY){ace}", ME))

    def test_reading_is_not_writing(self) -> None:
        self.assertTrue(store.sddl_is_protected("O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FR;;;BU)(A;;0x1200a9;;;WD)", ME))

    def test_a_stranger_owner_without_owner_rights_can_reopen_it(self) -> None:
        self.assertFalse(store.sddl_is_protected(f"O:{STRANGER}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", ME))
        self.assertTrue(store.sddl_is_protected(f"O:{ME}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", ME))

    def test_what_cannot_be_read_is_not_protected(self) -> None:
        for sddl in ("", "basura", "O:BA", "O:BAD:NO_ACCESS_CONTROL", "D:AI(A;;FA;;;SY)", "D:P(A;;FA)"):
            with self.subTest(sddl=sddl):
                self.assertFalse(store.sddl_is_protected(sddl, ME))

    def test_the_acls_name_groups_by_sid_and_give_users_only_the_status_file(self) -> None:
        folder = store.folder_sddl(ME, top=True)
        self.assertIn("(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + ME + ")", folder)
        # Usuarios: la carpeta (sin herencia), para que el icono lea status.json.
        self.assertIn("(A;;0x1200a9;;;BU)", folder)
        self.assertNotIn("OICI;0x1200a9;;;BU", folder)
        self.assertNotIn("BU", store.file_sddl(ME))
        self.assertIn("(A;;0x1200a9;;;BU)", store.file_sddl(ME, readers=True))
        # SYSTEM o un administrador elevado no se nombran a sí mismos.
        self.assertNotIn("S-1-5-18", store.file_sddl("S-1-5-18"))
        self.assertTrue(store.file_sddl(owner=True).startswith("O:BAD:P"))

    def test_posix_judgement(self) -> None:
        self.assertTrue(store.posix_is_protected(0o40700, 1000, 1000))
        self.assertTrue(store.posix_is_protected(0o40755, 0, 1000))
        self.assertFalse(store.posix_is_protected(0o40777, 1000, 1000))
        self.assertFalse(store.posix_is_protected(0o40770, 1000, 1000))
        self.assertFalse(store.posix_is_protected(0o40700, 1077, 1000))

    def test_the_line_for_a_person_names_what_was_moved(self) -> None:
        securing = store.Securing(Path("C:/PD/Cenya"), False, ("settings.json" + SUFFIX,), SUFFIX)
        line = store.moved_line(securing)
        self.assertIn("settings.json" + SUFFIX, line)
        self.assertIn(str(Path("C:/PD/Cenya")), line)
        self.assertEqual(store.moved_line(store.Securing(Path("x"), True)), "")


def _plant(folder: Path) -> None:
    """Lo que un usuario cualquiera podría dejar en una carpeta abierta."""
    (folder / "settings.json").write_text('{"proxy": {"mode": "manual", "url": "http://evil:3128"}}', encoding="utf-8")
    (folder / "identity.key").write_text("-----BEGIN PRIVATE KEY-----\nnot ours\n", encoding="ascii")
    (folder / "memory.json").write_text("{}", encoding="utf-8")
    (folder / "enrollment.json").write_text('{"url": "https://evil", "token": "t"}', encoding="utf-8")
    (folder / "outbox").mkdir()
    (folder / "outbox" / "forged-1.json").write_text("{}", encoding="utf-8")
    # Lo que SYSTEM ejecuta al volver atrás una actualización (Windows).
    (folder / "previous").mkdir()
    (folder / "previous" / "update-watchdog.cmd").write_text("@echo planted", encoding="ascii")


@unittest.skipUnless(sys.platform == "win32", "ACL de Windows")
class WindowsAclTests(unittest.TestCase):
    backend_class: type = store._Pywin32Backend

    def setUp(self) -> None:
        try:
            self.backend = self.backend_class()
        except Exception as exc:  # noqa: BLE001
            self.skipTest(f"sin {self.backend_class.__name__}: {exc}")
        patcher = mock.patch.object(store, "_backend", return_value=self.backend)
        patcher.start()
        self.addCleanup(patcher.stop)
        # mkdtemp ya crea una carpeta protegida (Python 3.12+); la del agente se
        # crea dentro sin modo, y hereda, como una nueva en %ProgramData%.
        self.parent = Path(tempfile.mkdtemp(prefix="cenya-state-acl-"))
        self.addCleanup(shutil.rmtree, self.parent, ignore_errors=True)
        self.folder = self.parent / "Cenya"
        os.mkdir(self.folder)
        self.me = self.backend.runner_sid()

    def sddl(self, target: Path) -> str:
        return self.backend.read_sddl(target)

    def assert_moved_aside(self, securing: store.Securing) -> None:
        self.assertFalse(securing.trusted)
        for name in ("settings.json", "identity.key", "memory.json", "enrollment.json", "outbox", "previous"):
            self.assertFalse((self.folder / name).exists(), name)
            self.assertTrue((self.folder / f"{name}{SUFFIX}").exists(), name)
        # Apartado, nunca borrado.
        self.assertTrue((self.folder / f"outbox{SUFFIX}" / "forged-1.json").exists())

    def test_an_open_folder_has_its_contents_moved_aside_and_is_protected(self) -> None:
        self.assertFalse(store.sddl_is_protected(self.sddl(self.folder), self.me))
        _plant(self.folder)

        securing = store.secure_state_dir(folder=self.folder, now=NOW)

        self.assert_moved_aside(securing)
        after = self.sddl(self.folder)
        self.assertTrue(store.sddl_is_protected(after, self.me), after)
        self.assertIn("D:P", after)
        self.assertNotIn("OICI;0x1200a9;;;BU", after)

    def test_a_folder_users_may_write_into_is_not_trusted(self) -> None:
        self.backend.write_sddl(self.folder, f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{self.me})(A;OICI;0x1301bf;;;BU)")
        _plant(self.folder)

        securing = store.secure_state_dir(folder=self.folder, now=NOW)

        self.assert_moved_aside(securing)
        self.assertNotIn("0x1301bf;;;BU", self.sddl(self.folder))

    def test_the_enrolment_found_in_an_open_folder_is_not_used(self) -> None:
        _plant(self.folder)
        environ = {"CENYA_STATE_DIR": str(self.folder)}

        store.secure_state_dir(environ, now=NOW)

        self.assertIsNone(store.load(environ))
        with self.assertRaises(SystemExit) as raised:
            config.from_env(environ)
        self.assertIn("--force", str(raised.exception.code))
        self.assertIn(str(self.folder), str(raised.exception.code))

    def test_a_protected_folder_is_trusted_and_its_files_lose_users_read(self) -> None:
        self.backend.write_sddl(self.folder, store.folder_sddl(self.me, top=True))
        store.write_protected(self.folder / "enrollment.json", '{"url": "https://portal", "token": "cya_x"}')
        (self.folder / "memory.json").write_text("{}", encoding="utf-8")
        (self.folder / "status.json").write_text("{}", encoding="utf-8")

        securing = store.secure_state_dir(folder=self.folder, now=NOW)

        self.assertTrue(securing.trusted)
        self.assertEqual(securing.moved, ())
        self.assertEqual(store.load({"CENYA_STATE_DIR": str(self.folder)}).token, "cya_x")
        memory_acl = self.sddl(self.folder / "memory.json")
        self.assertIn("D:P", memory_acl)
        self.assertNotIn("BU", memory_acl)
        # El icono de bandeja sigue pudiendo leer el estado.
        self.assertIn("0x1200a9;;;BU", self.sddl(self.folder / "status.json"))

    def test_status_writes_keep_the_file_readable_by_users(self) -> None:
        store.secure_state_dir(folder=self.folder, now=NOW)
        from agent import status

        target = self.folder / "status.json"
        with mock.patch.dict(os.environ, {status.ENV_VAR: str(target)}):
            status.write(state="durmiendo")
            status.write(state="barriendo")

        self.assertIn("0x1200a9;;;BU", self.sddl(target))

    def test_a_folder_that_cannot_be_protected_refuses_and_moves_nothing(self) -> None:
        _plant(self.folder)
        with mock.patch.object(store, "_apply", side_effect=OSError("acceso denegado")):
            with self.assertRaises(store.StoreError) as raised:
                store.secure_state_dir(folder=self.folder, now=NOW)

        self.assertIn(str(self.folder), str(raised.exception))
        self.assertTrue((self.folder / "settings.json").exists())

    def test_a_new_folder_is_created_protected_and_trusted(self) -> None:
        fresh = self.parent / "nueva" / "Cenya"

        securing = store.secure_state_dir(folder=fresh, now=NOW)

        self.assertTrue(securing.trusted)
        self.assertTrue(store.sddl_is_protected(self.sddl(fresh), self.me))


@unittest.skipUnless(sys.platform == "win32", "ACL de Windows")
class WindowsAclCtypesTests(WindowsAclTests):
    """The same, without pywin32: what a plain ``pip install`` on Windows uses."""

    backend_class = store._CtypesBackend


@unittest.skipUnless(sys.platform == "win32", "ACL de Windows")
class UpgradeFromTheInstallerLayoutTests(unittest.TestCase):
    """An agent installed with the 0.10.x installer keeps its enrolment.

    The folder gets exactly what `lock_status_directory` wrote then: SYSTEM and
    Administrators full control, Users and OWNER RIGHTS read, inherited by
    everything. Once applied, a non-administrator (who runs these tests) can
    read but no longer delete what is inside: the few bytes stay in %TEMP%.
    """

    def test_that_layout_is_trusted_and_the_enrolment_survives(self) -> None:
        backend = store._backend()
        folder = Path(tempfile.mkdtemp(prefix="cenya-test-layout-")) / "Cenya"
        os.mkdir(folder)
        store.write_protected(folder / "enrollment.json", '{"url": "https://portal", "token": "cya_kept"}')
        backend.write_sddl(folder, LOCK_LAYOUT.replace("O:BA", ""))
        # El fichero hereda lo de la carpeta, como cuando lo escribía la 0.10.x.
        backend.write_sddl(folder / "enrollment.json", "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)")
        self.assertTrue(store.sddl_is_protected(backend.read_sddl(folder), backend.runner_sid()))

        securing = store.secure_state_dir(folder=folder, now=NOW)

        self.assertTrue(securing.trusted)
        self.assertEqual(securing.moved, ())
        self.assertEqual(store.load({"CENYA_STATE_DIR": str(folder)}).token, "cya_kept")


@unittest.skipIf(sys.platform == "win32", "permisos POSIX")
class PosixModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.parent = Path(tempfile.mkdtemp(prefix="cenya-state-posix-"))
        self.addCleanup(shutil.rmtree, self.parent, ignore_errors=True)
        self.folder = self.parent / "cenya-agent"
        self.folder.mkdir()

    def mode(self, target: Path) -> int:
        return os.stat(target).st_mode & 0o777

    def test_a_world_writable_folder_has_its_contents_moved_aside(self) -> None:
        os.chmod(self.folder, 0o777)
        _plant(self.folder)

        securing = store.secure_state_dir(folder=self.folder, now=NOW)

        self.assertFalse(securing.trusted)
        self.assertTrue((self.folder / f"settings.json{SUFFIX}").exists())
        self.assertFalse((self.folder / "enrollment.json").exists())
        self.assertEqual(self.mode(self.folder), 0o700)

    def test_a_private_folder_is_trusted_and_tightened(self) -> None:
        os.chmod(self.folder, 0o755)
        (self.folder / "memory.json").write_text("{}", encoding="utf-8")
        (self.folder / "logs").mkdir()
        (self.folder / "logs" / "agent.log").write_text("x", encoding="utf-8")
        os.chmod(self.folder / "memory.json", 0o644)

        securing = store.secure_state_dir(folder=self.folder, now=NOW)

        self.assertTrue(securing.trusted)
        self.assertEqual(self.mode(self.folder), 0o700)
        self.assertEqual(self.mode(self.folder / "memory.json"), 0o600)
        self.assertEqual(self.mode(self.folder / "logs"), 0o700)
        self.assertEqual(self.mode(self.folder / "logs" / "agent.log"), 0o600)

    def test_a_new_folder_is_born_private(self) -> None:
        fresh = self.parent / "x" / "cenya-agent"

        self.assertTrue(store.secure_state_dir(folder=fresh, now=NOW).trusted)
        self.assertEqual(self.mode(fresh), 0o700)


class StartupTests(unittest.TestCase):
    """Every way in secures the folder before reading anything from it."""

    def test_enroll_secures_first_and_refuses_when_it_cannot(self) -> None:
        environ = {"CENYA_STATE_DIR": tempfile.mkdtemp(prefix="cenya-enroll-secure-")}
        from agent import enroll

        with mock.patch.object(store, "secure_state_dir", side_effect=store.StoreError("no se puede")) as secure, \
             mock.patch.object(store, "load") as load, mock.patch("builtins.print"):
            code = enroll.run(["cenya://portal/K7QF-9M2X-4TQN"], environ)

        self.assertEqual(code, 1)
        secure.assert_called_once()
        load.assert_not_called()

    def test_the_agent_does_not_start_when_the_folder_cannot_be_protected(self) -> None:
        from agent import __main__ as loop

        with mock.patch.object(loop.store, "secure_state_dir", side_effect=store.StoreError("no se puede")), \
             mock.patch.object(loop.enroll, "ensure_enrolled") as ensure, mock.patch("builtins.print"):
            with self.assertRaises(SystemExit):
                loop.main(["--once"])

        ensure.assert_not_called()


if __name__ == "__main__":
    unittest.main()
