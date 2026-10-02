"""CI check: the installed ssh.exe + askpass really log in with a password.

``smoke-test.ps1`` runs this against the files the installer put on disk, not
against anything built from source: the bundled ``openssh\\ssh.exe`` (with the
DLLs the installer copied next to it) and the installed ``cenya-agent-askpass.exe``.
It starts the stub SSH server of the test-suite on 127.0.0.1, logs in with a few
awkward passwords through ``agent.ssh``'s own command line and environment, and
fails unless the server received every password byte for byte.

Needs ``cryptography`` (test-only, never a dependency of the agent) and the
repository on ``sys.path`` (run it from the repository root). Exit codes: 0 all
good, 1 a login failed or a password arrived altered, 2 prerequisites missing.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

PASSWORDS = [
    "plain",
    "with space",
    "it's \"quoted\"",
    "100% %PATH% !bang! ^caret",
    "a&b|c <in> >out",
    "ñandú-€-日本語",
    "trailing\\",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh", required=True, help="path to the bundled ssh.exe")
    parser.add_argument("--askpass", required=True, help="path to the installed cenya-agent-askpass.exe")
    args = parser.parse_args()

    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from agent import ssh
    from agent.tests import ssh_stub_server

    if not ssh_stub_server.AVAILABLE:
        print("SKIP: the `cryptography` package is not installed")
        return 2
    version = ssh.detect_version(args.ssh)
    print(f"ssh: {args.ssh} -> {version}")
    if version is None or version < ssh.MIN_ASKPASS_VERSION:
        print("FAIL: the bundled ssh does not run or is older than 8.4")
        return 1

    failures = 0
    with tempfile.TemporaryDirectory(prefix="cenya-ssh-check-") as tmp, ssh_stub_server.StubSshServer() as server:
        config = Path(tmp) / "ssh_config"
        config.write_text("", encoding="utf-8")
        for password in PASSWORDS:
            server.attempts.clear()
            server.expected = password.encode("utf-8")
            argv = ssh.argv_for(host="127.0.0.1", username="tester", port=server.port, with_password=True, askpass=True, command="true")
            argv[0] = args.ssh
            argv[1:1] = [
                "-F", str(config),
                "-o", f"UserKnownHostsFile={Path(tmp) / 'known_hosts'}",
                "-o", "GlobalKnownHostsFile=" + os.devnull,
            ]  # fmt: skip
            environment = dict(os.environ)
            environment.update(
                {"SSH_ASKPASS": args.askpass, "SSH_ASKPASS_REQUIRE": "force", ssh.SECRET_ENV: password}
            )
            result = subprocess.run(argv, capture_output=True, text=True, env=environment, timeout=60)
            received = [a.password for a in server.attempts if a.method == "password"]
            ok = result.returncode == 0 and received == [password.encode("utf-8")]
            print(f"  {'ok  ' if ok else 'FAIL'} password #{PASSWORDS.index(password)} ({len(password)} chars) exit={result.returncode}")
            if not ok:
                failures += 1
                print("       stderr:", (result.stderr or "").strip().splitlines()[:3])
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
