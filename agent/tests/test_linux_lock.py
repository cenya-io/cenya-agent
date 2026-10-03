"""install.sh runs pip as root: it installs only what has a hash (security review, 03-10-2026).

Text checks over ``deploy/requirements-linux.txt``, ``deploy/install.sh`` and the
workflow. That the lock matches ``pyproject.toml`` and really installs is
proved in CI (``lock_linux.py --check`` and a real install on Ubuntu).
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado y fija el idioma

import re
import unittest
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent.parent
LOCK = (AGENT_DIR / "deploy" / "requirements-linux.txt").read_text(encoding="utf-8")
SCRIPT = (AGENT_DIR / "deploy" / "install.sh").read_text(encoding="utf-8")
PYPROJECT = (AGENT_DIR / "pyproject.toml").read_text(encoding="utf-8")
WORKFLOW = (AGENT_DIR.parent / ".github" / "workflows" / "agent-installer.yml").read_text(encoding="utf-8")
BEGIN, END = "# BEGIN verify-requirements\n", "# END verify-requirements\n"


def entries(text: str) -> list[str]:
    """One string per requirement, continuation lines included, comments out."""
    found: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.strip().startswith("#"):
            continue
        if line[0].isspace():
            found[-1] += "\n" + line.strip()
        else:
            found.append(line)
    return found


def name(entry: str) -> str:
    return re.split(r"[<>=!~;\s\[]", entry, maxsplit=1)[0].lower().replace("_", "-")


def shell_commands(script: str) -> list[str]:
    """The script's commands with their backslash continuations joined, comments out."""
    commands: list[str] = []
    pending = ""
    for line in script.splitlines():
        if not pending and line.lstrip().startswith("#"):
            continue
        pending += " " + line.strip()
        if pending.endswith("\\"):
            pending = pending[:-1]
            continue
        commands.append(pending.strip())
        pending = ""
    return commands


class LockFileTests(unittest.TestCase):
    def test_every_requirement_is_pinned_with_hashes(self) -> None:
        found = entries(LOCK)
        self.assertGreater(len(found), 5)
        for entry in found:
            with self.subTest(package=name(entry)):
                self.assertRegex(entry.split("\n", 1)[0], r"^[A-Za-z0-9_.-]+==[^ ;]+( ;.*)? \\$")
                self.assertRegex(entry, r"--hash=sha256:[0-9a-f]{64}")
                for line in entry.split("\n")[1:]:
                    self.assertRegex(line, r"^--hash=sha256:[0-9a-f]{64}( \\)?$")

    def test_it_covers_every_linux_dependency_of_completo_and_the_build_backend(self) -> None:
        completo = PYPROJECT.split("completo = [", 1)[1].split("]", 1)[0]
        wanted = {name(spec) for spec in re.findall(r'"([^"]+)"', completo) if "win32" not in spec}
        wanted.add("setuptools")  # --no-build-isolation: the backend comes from the lock too
        self.assertLessEqual(wanted, {name(entry) for entry in entries(LOCK)})

    def test_windows_only_packages_stay_out(self) -> None:
        names = {name(entry) for entry in entries(LOCK)}
        for package in ("pywin32", "pywebview", "pythonnet", "clr-loader", "sspilib", "bottle", "proxy-tools"):
            with self.subTest(package=package):
                self.assertNotIn(package, names)
        for entry in entries(LOCK):
            self.assertNotRegex(entry.split("\n", 1)[0], r"; sys_platform == 'win32' \\$")

    def test_it_says_how_to_regenerate_it(self) -> None:
        self.assertIn("python agent/packaging/lock_linux.py", LOCK)
        self.assertTrue((AGENT_DIR / "packaging" / "lock_linux.py").is_file())


class InstallShTests(unittest.TestCase):
    def test_nothing_is_ever_installed_without_hashes(self) -> None:
        installs = [command for command in shell_commands(SCRIPT) if re.search(r"\bpip\b.* install\b", command)]
        self.assertEqual(len(installs), 3, installs)  # cryptography to verify, the lock, the agent
        for command in installs:
            for part in re.split(r"&&|\|\|", command):
                if " install " not in part:
                    continue
                with self.subTest(command=part.strip()[:80]):
                    self.assertIn("--require-hashes", part)
                    self.assertIn("--no-deps", part)
                    self.assertRegex(part, r" -r \"\$[A-Z]+/")

    def test_the_lock_and_the_agent_come_from_the_verified_archive(self) -> None:
        body = SCRIPT.split("install_version() {", 1)[1].split("\n}\n", 1)[0]
        self.assertLess(body.index('tar -xzf "$ARCHIVE"'), body.index("pip\" install"))
        self.assertIn('-r "$SRC/deploy/requirements-linux.txt"', body)
        self.assertIn('[ -f "$SRC/deploy/requirements-linux.txt" ] ||', body)
        # El agente: con la huella del archivo, sin índice y sin aislar la construcción.
        self.assertIn("cenya-agent @ file://%s --hash=sha256:%s", body)
        self.assertIn('"$(file_sha256 "$ARCHIVE")"', body)
        self.assertIn("--no-build-isolation --no-index", body)
        # Solo ruedas desde PyPI: ningún setup.py ajeno corre como root.
        self.assertEqual(SCRIPT.count("--only-binary :all:"), 2)

    def test_the_verify_block_is_cryptography_exactly_as_in_the_lock(self) -> None:
        block = SCRIPT.split(BEGIN, 1)[1].split(END, 1)[0]
        in_block = entries(block)
        self.assertIn("cryptography", {name(entry) for entry in in_block})
        lock = {name(entry): entry for entry in entries(LOCK)}
        for entry in in_block:
            with self.subTest(package=name(entry)):
                self.assertEqual(entry, lock[name(entry)])
        verify = SCRIPT.split("verify_manifest() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("<<'REQ'\n" + BEGIN, verify)
        self.assertNotIn("cryptography>=", verify)


class WorkflowTests(unittest.TestCase):
    def test_ci_fails_on_a_stale_lock_and_installs_it_for_real(self) -> None:
        tests_job = WORKFLOW.split("\n  tests:\n", 1)[1].split("\n  windows:\n", 1)[0]
        self.assertIn("python agent/packaging/lock_linux.py --check", tests_job)
        self.assertIn("-r agent/deploy/requirements-linux.txt", tests_job)
        self.assertIn("--no-build-isolation --no-index", tests_job)
        self.assertIn("# BEGIN verify-requirements", tests_job)

    def test_the_release_archive_carries_the_lock(self) -> None:
        # git archive HEAD:agent: lo que está en agent/deploy viaja en el .tar.gz firmado.
        self.assertIn("HEAD:agent", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
