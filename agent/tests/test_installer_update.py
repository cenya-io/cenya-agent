"""The installer's new duties, checked as text: nothing here can run Inno Setup, cmd or systemd.

Like `test_installer_packaging.py`, these read the packaging files and pin what
must hold between them and the agent's code: the connection in the file name
(and a Python mirror of the Pascal base32 decoder, checked against the
standard library), ``/CA=``, ``/UPDATE`` with its backup and watchdog, goodbye
on uninstall, the Linux units and ``install.sh``, the release tooling and the
workflow. What CI must still prove for real is listed in ``smoke-test.ps1``.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado y fija el idioma

import base64
import contextlib
import io
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent import release, update
from agent.tests.test_installer_packaging import ISS, pascal_routine

AGENT_DIR = Path(update.__file__).resolve().parent
PACKAGING = AGENT_DIR / "packaging"
DEPLOY = AGENT_DIR / "deploy"
WATCHDOG = PACKAGING / "update-watchdog.cmd"
SMOKE = (PACKAGING / "smoke-test.ps1").read_text(encoding="utf-8-sig")
STUB = (PACKAGING / "ci_stub_server.py").read_text(encoding="utf-8")
WORKFLOW = (AGENT_DIR.parent / ".github" / "workflows" / "agent-installer.yml").read_text(encoding="utf-8")
CONTRACT_NAME = re.compile(r"_([a-z2-7]{16,})( \(\d+\))?\.exe$")


def pascal_base32_decode(value: str) -> str | None:
    """Line by line, what `Base32Decode` in cenya-agent.iss does (None = Result False)."""
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    decoded, buffer, bits = "", 0, 0
    if not value:
        return None
    for char in value:
        index = alphabet.find(char) + 1  # Pos(): 1-based, 0 si no está
        if index == 0:
            return None
        buffer = (buffer << 5) | (index - 1)
        bits += 5
        if bits >= 8:
            bits -= 8
            decoded += chr((buffer >> bits) & 0xFF)
            buffer &= (1 << bits) - 1
    if bits >= 5 or buffer != 0:
        return None
    return decoded


def pascal_name_payload(name: str) -> str | None:
    """What `InstallerNameConnection` extracts from a file name, before decoding."""
    if len(name) < 5 or name[-4:].lower() != ".exe":
        return None
    name = name[:-4]
    if name.endswith(")"):
        p = len(name) - 1  # índices de Pascal: 1-based
        while p > 0 and name[p - 1].isdigit() and "0" <= name[p - 1] <= "9":
            p -= 1
        if p < len(name) - 1 and p >= 2 and name[p - 1] == "(" and name[p - 2] == " ":
            name = name[: p - 2]
        else:
            return None
    position = name.rfind("_")
    if position < 0:
        return None
    payload = name[position + 1 :]
    return payload if len(payload) >= 16 else None


def b32(text: str) -> str:
    return base64.b32encode(text.encode()).decode().rstrip("=").lower()


class ConnectionInTheFileNameTests(unittest.TestCase):
    def test_the_pascal_decoder_is_the_one_mirrored_here(self) -> None:
        routine = pascal_routine("function Base32Decode")
        self.assertIn("Alphabet := 'abcdefghijklmnopqrstuvwxyz234567';", routine)
        self.assertIn("Buffer := (Buffer shl 5) or (Index - 1);", routine)
        self.assertIn("Decoded := Decoded + Chr((Buffer shr Bits) and $FF);", routine)
        self.assertIn("Buffer := Buffer and ((1 shl Bits) - 1);", routine)
        self.assertIn("if (Bits >= 5) or (Buffer <> 0) then", routine)

    def test_the_decoder_agrees_with_rfc_4648_on_every_length(self) -> None:
        samples = [
            "cenya://portal.example.com/K7QF-9M2X-4TQN",
            "cenya+http://localhost:8765/TEST-TEST-TEST",
            "cenya://[2001:db8::1]:8443/ABCD-EFGH-IJKL",
        ] + ["cenya://h/" + "x" * n for n in range(0, 9)]
        for text in samples:
            with self.subTest(text=text):
                self.assertEqual(pascal_base32_decode(b32(text)), text)

    def test_the_decoder_refuses_what_rfc_4648_refuses(self) -> None:
        good = b32("cenya://portal.example.com/K7QF-9M2X-4TQN")
        bad = [
            good.upper(),  # mayúsculas: el contrato dice minúsculas
            good + "=",  # relleno
            good[:-1] + "1",  # fuera del alfabeto
            good + "a",  # longitud imposible (sobran 5 o más bits)
            "",
        ]
        # Bits finales que no son cero: otra forma de escribir lo mismo.
        last = "abcdefghijklmnopqrstuvwxyz234567".index(good[-1])
        bad.append(good[:-1] + "abcdefghijklmnopqrstuvwxyz234567"[last | 1] if not last & 1 else good[:-1] + good[-1])
        for value in bad[:-1] + ([bad[-1]] if bad[-1] != good else []):
            with self.subTest(value=value[-6:]):
                self.assertIsNone(pascal_base32_decode(value))

    def test_the_name_parser_finds_exactly_what_the_contract_regex_finds(self) -> None:
        payload = b32("cenya://portal.example.com/K7QF-9M2X-4TQN")
        names = [
            f"Cenya-Agent-Setup-0.11.0_{payload}.exe",
            f"Cenya-Agent-Setup-0.11.0_{payload} (1).exe",
            f"Cenya-Agent-Setup-0.11.0_{payload} (12).exe",
            "Cenya-Agent-Setup-0.11.0.exe",
            f"Cenya-Agent-Setup-0.11.0_{payload} ().exe",
            f"Cenya-Agent-Setup-0.11.0_{payload}(1).exe",
            "Cenya-Agent-Setup-0.11.0_short.exe",
            "cenya-agent-0.11.1.exe",
        ]
        for name in names:
            with self.subTest(name=name):
                match = CONTRACT_NAME.search(name)
                expected = match.group(1) if match else None
                found = pascal_name_payload(name)
                if found is not None and expected is None:
                    # El de Pascal deja pasar mayúsculas o símbolos al decodificador, que los rechaza.
                    self.assertIsNone(pascal_base32_decode(found))
                else:
                    self.assertEqual(found, expected)

    def test_the_payload_is_validated_like_any_connection_before_use(self) -> None:
        routine = pascal_routine("function InstallerNameConnection")
        self.assertIn("ExpandConstant('{srcexe}')", routine)
        self.assertIn("Base32Decode(Payload, Decoded)", routine)
        self.assertIn("if LooksLikeConnection(Decoded) then", routine)

    def test_connection_param_wins_over_the_name_and_an_enrolled_machine_ignores_both(self) -> None:
        chosen = pascal_routine("function ChosenConnection")
        order = [chosen.index(marker) for marker in (
            "FileExists(EnrollmentFile)", "Result := ConnectionParam", "Result := InstallerNameConnection",
            "Result := Trim(ConnectionPage.Values[0])")]
        self.assertEqual(order, sorted(order))

    def test_the_connection_page_is_optional_now(self) -> None:
        needs = pascal_routine("function NeedsConnection")
        self.assertIn("InstallerNameConnection = ''", needs)
        self.assertIn("not IsUpdateMode", needs)
        click = pascal_routine("function NextButtonClick")
        self.assertIn("(Connection <> '') and (not LooksLikeConnection(Connection))", click)
        self.assertIn("en blanco", re.search(r"^spanish\.ConnectionDescription=(.*)$", ISS, re.M).group(1))


class CaCertificateTests(unittest.TestCase):
    def test_ca_is_applied_by_the_agent_before_enrolling(self) -> None:
        post = pascal_routine("procedure CurStepChanged")
        self.assertLess(post.index("ApplyCa(Ca, Reason)"), post.index("EnrollAgent(Connection, Reason)"))
        apply = pascal_routine("function ApplyCa")
        self.assertIn("'settings set ca_bundle \"' + Path + '\"'", apply)
        self.assertIn("ExecAndCaptureOutput(", apply)
        self.assertIn("Pos('\"', Path) > 0", apply)
        main = (AGENT_DIR / "__main__.py").read_text(encoding="utf-8")
        self.assertIn('["settings"]', main)

    def test_ca_comes_from_the_command_line_or_the_page(self) -> None:
        chosen = pascal_routine("function ChosenCa")
        self.assertIn("{param:CA|}", chosen)
        self.assertIn("ConnectionPage.Values[1]", chosen)
        self.assertIn("ConnectionPage.Add(CustomMessage('CaLabel'), False);", ISS)

    def test_a_ca_that_cannot_be_applied_has_its_own_exit_code(self) -> None:
        self.assertIn("FailDeployment(23,", ISS)
        self.assertIn("23", ISS.split("[Setup]")[0])


class UninstallTests(unittest.TestCase):
    def test_goodbye_runs_after_stopping_and_before_removing_the_service(self) -> None:
        section = ISS.split("[UninstallRun]")[1].split("[UninstallDelete]")[0]
        stop = section.index('Parameters: "--wait 60 stop"')
        goodbye = section.index('Parameters: "goodbye"')
        remove = section.index('Parameters: "remove"')
        self.assertLess(stop, goodbye)
        self.assertLess(goodbye, remove)
        self.assertIn('Filename: "{app}\\cenya-agent.exe"; Parameters: "goodbye"', section)

    def test_an_unfinished_watchdog_does_not_survive_the_agent(self) -> None:
        section = ISS.split("[UninstallRun]")[1].split("[UninstallDelete]")[0]
        self.assertIn('/Delete /TN ""{#WatchdogTask}"" /F', section)


class UpdateModeTests(unittest.TestCase):
    def test_the_agent_launches_exactly_what_the_installer_understands(self) -> None:
        args = update.installer_arguments(Path("x.exe"), log=Path("l"), watchdog=90)
        self.assertIn("/UPDATE", args)
        self.assertIn("CompareText(ParamStr(I), '/UPDATE') = 0", pascal_routine("function IsUpdateMode"))
        self.assertIn("{param:WATCHDOGSECONDS|600}", pascal_routine("function WatchdogSeconds"))

    def test_nothing_is_replaced_before_the_backup_and_the_watchdog_exist(self) -> None:
        prepare = pascal_routine("function PrepareToInstall")
        self.assertLess(prepare.index("StopRunningAgent"), prepare.index("BackupPrevious"))
        self.assertLess(prepare.index("BackupPrevious"), prepare.index("CreateWatchdog"))
        # Si algo falla, el servicio de siempre vuelve a arrancar y Inno no sigue.
        self.assertEqual(prepare.count("RunService('--wait 60 start')"), 2)
        self.assertIn("FileExists(EnrollmentFile)", prepare)

    def test_the_backup_is_never_half_made(self) -> None:
        backup = pascal_routine("function BackupPrevious")
        self.assertIn("robocopy.exe", backup)
        self.assertIn("app.partial", backup)
        self.assertIn("ResultCode >= 8", backup)
        self.assertLess(backup.index("Exec("), backup.index("RenameFile(Partial, Target)"))

    def test_the_watchdog_task_is_one_shot_as_system_and_survives_a_reboot(self) -> None:
        create = pascal_routine("function CreateWatchdog")
        self.assertIn("ExtractTemporaryFile('update-watchdog.cmd')", create)
        self.assertIn("DeleteFile(StateDir + '\\updates\\healthy-{#AppVersion}')", create)
        for needle in ("<RegistrationTrigger>", "<BootTrigger>", "<UserId>S-1-5-18</UserId>",
                       "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"):
            with self.subTest(needle=needle):
                self.assertIn(needle, create)
        # La marca «installing» antes de crear la tarea; se quita siempre al final.
        self.assertLess(create.index("'\\installing'"), create.index("schtasks.exe"))
        self.assertIn("DeleteFile(PreviousDir + '\\installing')", pascal_routine("procedure DeinitializeSetup"))
        self.assertIn('Source: "update-watchdog.cmd"; Flags: dontcopy', ISS)

    def test_the_watchdog_script_and_the_agent_agree_on_the_markers(self) -> None:
        text = WATCHDOG.read_text(encoding="ascii")
        self.assertIn(f'set "MARKERS=%STATE%\\{update.FOLDER}"', text)
        self.assertIn(f'"%MARKERS%\\{update.HEALTHY_PREFIX}%TO%"', text)
        self.assertIn(f'"%MARKERS%\\{update.FAILED_PREFIX}%TO%"', text)
        self.assertIn('if not exist "%PREV%\\installing" goto poll_start', text)

    def test_the_watchdog_restores_then_starts_then_removes_itself_last(self) -> None:
        text = WATCHDOG.read_text(encoding="ascii")
        rollback = text.split(":rollback", 1)[1].split(":restore_failed", 1)[0]
        steps = [rollback.index(s) for s in ("net stop CenyaAgent", "robocopy", "failed-%TO%", "net start CenyaAgent",
                                             "schtasks /Delete")]
        self.assertEqual(steps, sorted(steps))
        self.assertIn("/MIR", rollback)
        # Si la restauración falla, la tarea NO se borra: se reintenta al arrancar.
        failed = text.split(":restore_failed", 1)[1].split(":no_backup", 1)[0]
        self.assertNotIn("schtasks /Delete", failed)

    def test_the_watchdog_script_is_plain_cmd(self) -> None:
        raw = WATCHDOG.read_bytes()
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"), "a BOM breaks the first line of a .cmd")
        self.assertTrue(raw.isascii())
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""), "cmd needs CRLF to find its labels")
        self.assertNotIn(b"timeout ", raw.lower().replace(b"rem `timeout`", b""))

    def test_the_task_name_and_the_uninstall_key_are_the_same_everywhere(self) -> None:
        self.assertIn('#define WatchdogTask "Cenya Agent update watchdog"', ISS)
        self.assertIn('set "TASK=Cenya Agent update watchdog"', WATCHDOG.read_text(encoding="ascii"))
        self.assertIn('$watchdogTask = "Cenya Agent update watchdog"', SMOKE)
        guid = re.search(r"AppId=\{\{([0-9A-F-]+)\}", ISS).group(1)
        self.assertIn(f"{{{guid}}}_is1", ISS)
        self.assertIn(f"{{{guid}}}_is1", WATCHDOG.read_text(encoding="ascii"))


class SpecAndBuildTests(unittest.TestCase):
    def test_the_frozen_build_carries_the_updater_and_the_app(self) -> None:
        spec = (PACKAGING / "cenya-agent.spec").read_text(encoding="utf-8")
        for module in ("agent.update", "agent.release", "agent.release_keys", "agent.settings_command"):
            with self.subTest(module=module):
                self.assertIn(f'"{module}"', spec)
        self.assertIn('name="cenya-agent-app"', spec)
        self.assertNotIn("PENDIENTE (fase 5)", spec)

    def test_a_test_key_can_never_reach_the_published_installer(self) -> None:
        build = (PACKAGING / "build.ps1").read_text(encoding="utf-8-sig")
        self.assertIn("if (($Version -or $ExtraReleaseKey) -and -not $OutputDir)", build)
        finally_block = build.split("finally {", 1)[1]
        self.assertIn("WriteAllBytes($initFile, $originalInit)", finally_block)
        self.assertIn("WriteAllBytes($keysFile, $originalKeys)", finally_block)
        # El flujo comprueba que lo que se publica acepta solo las claves del repositorio.
        self.assertIn("El que se publica lleva exactamente las claves de agent/release_keys.py", WORKFLOW)

    def test_the_repository_ships_no_release_key(self) -> None:
        from agent.release_keys import PUBLIC_KEYS

        self.assertEqual(PUBLIC_KEYS, [], "the owner pastes the public key; nobody else adds one")


class WorkflowTests(unittest.TestCase):
    def test_a_tag_publishes_the_contract_files_signed_when_the_secret_exists(self) -> None:
        release_job = WORKFLOW.split("\n  release:\n", 1)[1]
        self.assertIn("startsWith(github.ref, 'refs/tags/agent-v')", release_job)
        for needle in ("latest.json", "latest.json.sig", "install.sh", "Cenya-Agent-Setup-", "cenya-agent-${version}.tar.gz",
                       "CENYA_RELEASE_SIGNING_KEY", "::error", "embed-keys", "release_key.py verify"):
            with self.subTest(needle=needle):
                self.assertIn(needle, release_job)

    def test_ci_tests_the_update_with_a_throwaway_key(self) -> None:
        self.assertIn("release_key.py generate --private-out", WORKFLOW)
        self.assertEqual(WORKFLOW.count("-ExtraReleaseKey $public"), 3)
        self.assertIn("-TestKey $env:TEST_KEY", WORKFLOW)
        self.assertIn("shellcheck --shell=sh agent/deploy/install.sh", WORKFLOW)

    def test_the_smoke_test_covers_every_new_path(self) -> None:
        for needle in ("Cenya-Agent-Setup-{0}_{1}.exe", '"/CA=$ca"', "bad_hash", "update_failed", "explicit = $true",
                       "/api/agent/v2/goodbye/", "healthy-$next", "failed-$broken", "TaskExists"):
            with self.subTest(needle=needle):
                self.assertIn(needle, SMOKE)

    def test_the_stub_speaks_protocol_2_and_serves_releases_and_the_installer(self) -> None:
        client = (AGENT_DIR / "client.py").read_text(encoding="utf-8")
        for path in re.findall(r'"(/api/agent/v2/[a-z]+/)"', client):
            with self.subTest(path=path):
                self.assertIn(path, STUB)
        self.assertIn(update.SERVER_INSTALLER_PATH, STUB)
        for header in ("X-Cenya-Version", "X-Cenya-Sha256", "X-Cenya-Manifest", "X-Cenya-Manifest-Signature"):
            with self.subTest(header=header):
                self.assertIn(header, STUB)
                self.assertIn(header, (AGENT_DIR / "update.py").read_text(encoding="utf-8")) if header != "X-Cenya-Version" else None


class LinuxFilesTests(unittest.TestCase):
    def unit(self, name: str) -> str:
        return (DEPLOY / name).read_text(encoding="utf-8")

    def test_the_service_runs_unprivileged_with_only_what_ping_needs(self) -> None:
        unit = self.unit("cenya-agent.service")
        for line in ("User=cenya-agent", "StateDirectory=cenya-agent", "StateDirectoryMode=0700",
                     "AmbientCapabilities=CAP_NET_RAW", "CapabilityBoundingSet=CAP_NET_RAW", "NoNewPrivileges=yes",
                     "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes",
                     "Environment=CENYA_STATE_DIR=/var/lib/cenya-agent",
                     "ExecStart=/opt/cenya-agent/current/bin/cenya-agent"):
            with self.subTest(line=line):
                self.assertIn(f"\n{line}\n", unit)
        self.assertNotIn("DynamicUser", unit)

    def test_no_unit_asks_for_a_token_any_more(self) -> None:
        for path in DEPLOY.glob("cenya-agent*"):
            with self.subTest(unit=path.name):
                self.assertNotIn("AGENT_TOKEN", path.read_text(encoding="utf-8"))

    def test_the_update_units_watch_the_request_the_agent_writes(self) -> None:
        self.assertIn(f"PathExists=/var/lib/cenya-agent/{update.FOLDER}/{update.REQUEST_FILE}", self.unit("cenya-agent-update.path"))
        self.assertIn("update apply-request /var/lib/cenya-agent", self.unit("cenya-agent-update.service"))
        self.assertIn('["update"]', (AGENT_DIR / "__main__.py").read_text(encoding="utf-8"))

    def test_install_sh_installs_these_units_and_keeps_the_rules(self) -> None:
        script = (DEPLOY / "install.sh").read_text(encoding="utf-8")
        for unit in ("cenya-agent.service", "cenya-agent-update.path", "cenya-agent-update.service"):
            with self.subTest(unit=unit):
                self.assertIn(f'"$SRC/deploy/{unit}"', script)
        self.assertIn("run_as_agent goodbye", script.split("uninstall() {", 1)[1].split("\n}\n", 1)[0])
        self.assertIn("healthy-$next", script)
        # La marca de «falló» la deja el usuario del agente, no root (revisión de seguridad).
        self.assertIn('mark_as_agent "$next"', script)
        self.assertIn('failed-$2', script)
        # El vigilante queda puesto antes de cambiar de versión.
        main = script.split("main() {", 1)[1]
        self.assertLess(main.index("install_watchdog"), main.index('switch_current "$PREFIX/$VERSION"'))
        for line in DEPLOY.glob("*"):
            if line.suffix in (".sh", ".service", ".path"):
                with self.subTest(file=line.name):
                    self.assertNotIn(b"\r", line.read_bytes())


class ReleaseToolTests(unittest.TestCase):
    """`packaging/release_key.py`, with a TEST key in a temporary folder."""

    def setUp(self) -> None:
        try:
            import cryptography  # noqa: F401
        except ImportError:  # pragma: no cover
            self.skipTest("cryptography no está instalada")
        import importlib.util

        spec = importlib.util.spec_from_file_location("release_key", PACKAGING / "release_key.py")
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)
        self.dir = Path(tempfile.mkdtemp(prefix="cenya-release-tool-"))

    def call(self, *args: str, env: dict | None = None) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with mock.patch.dict(os.environ, env or {}):
                return self.tool.main(list(args))

    def test_generate_sign_manifest_and_verify_round_trip_with_the_agents_own_code(self) -> None:
        self.assertEqual(self.call("generate", "--private-out", str(self.dir / "k.pem"),
                                   "--public-out", str(self.dir / "k.pub")), 0)
        public = (self.dir / "k.pub").read_text().strip()
        for name, content in (("Cenya-Agent-Setup-0.11.1.exe", b"MZ"), ("cenya-agent-0.11.1.tar.gz", b"tgz"),
                              ("install.sh", b"#!/bin/sh\n")):
            (self.dir / name).write_bytes(content)
        self.assertEqual(self.call(
            "manifest", "--version", "0.11.1", "--base-url", "https://github.com/x/releases/download/agent-v0.11.1",
            "--windows", str(self.dir / "Cenya-Agent-Setup-0.11.1.exe"), "--linux", str(self.dir / "cenya-agent-0.11.1.tar.gz"),
            "--install-sh", str(self.dir / "install.sh"), "--out", str(self.dir / "latest.json")), 0)
        secret = (self.dir / "k.pem").read_text()
        self.assertEqual(self.call("sign", str(self.dir / "latest.json"), env={"CENYA_RELEASE_SIGNING_KEY": secret}), 0)

        manifest = release.verify_manifest(
            (self.dir / "latest.json").read_bytes(), (self.dir / "latest.json.sig").read_bytes(), [public]
        )

        raw = json.loads((self.dir / "latest.json").read_text())
        self.assertEqual(raw["url"], manifest["files"]["windows"]["url"])
        self.assertEqual(raw["sha256"], manifest["files"]["windows"]["sha256"])
        self.assertEqual(set(manifest["files"]), {"windows", "linux", "install.sh"})
        self.assertEqual(manifest["files"]["linux"]["url"],
                         "https://github.com/x/releases/download/agent-v0.11.1/cenya-agent-0.11.1.tar.gz")
        self.assertEqual(self.call("verify", str(self.dir / "latest.json"), str(self.dir / "latest.json.sig"),
                                   "--key", public), 0)

    def test_sign_without_the_secret_refuses(self) -> None:
        (self.dir / "latest.json").write_text("{}")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CENYA_RELEASE_SIGNING_KEY", None)
            self.assertEqual(self.call("sign", str(self.dir / "latest.json")), 2)
        self.assertFalse((self.dir / "latest.json.sig").exists())

    def test_embed_keys_writes_the_keys_into_install_sh(self) -> None:
        self.call("generate", "--private-out", str(self.dir / "k.pem"), "--public-out", str(self.dir / "k.pub"))
        public = (self.dir / "k.pub").read_text().strip()

        self.assertEqual(self.call("embed-keys", str(DEPLOY / "install.sh"), str(self.dir / "install.sh"), "--key", public), 0)

        text = (self.dir / "install.sh").read_text(encoding="utf-8")
        self.assertIn(f"\nRELEASE_KEYS='{public}'\n", text)
        self.assertNotIn("\r", text)


if __name__ == "__main__":
    unittest.main()
