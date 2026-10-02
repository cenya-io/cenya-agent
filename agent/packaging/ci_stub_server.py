"""A stand-in for the Cenya portal (and for GitHub's releases), for the installer's smoke test in CI.

The smoke test installs the agent for real (a Windows service, as
administrator) and has to see it enrol, check in, update itself, roll back and
say goodbye. Standing up Django and PostgreSQL on the runner for that would test
the server, which already has its own suite; this answers the endpoints the
agent uses and writes down what it was asked, so the test can check it.

    python ci_stub_server.py --port 8765 --log requests.jsonl --releases DIR
    python ci_stub_server.py make-ca ca.pem        # a throwaway CA for /CA=

What it speaks:

* protocol 1 (enroll, heartbeat, findings) and protocol 2 (``v2/checkin``,
  ``v2/results``, ``v2/orders/<id>/result``, ``v2/goodbye``);
* ``GET /releases/agent-v<version>/<file>``: what GitHub serves, from
  ``DIR/<version>/<file>`` (``latest.json``, its ``.sig``, the installer);
* ``GET /api/agent/v2/installer/``: the installer of the version on offer, with
  the manifest and its signature in the headers (contract, section 3);
* ``POST /ci/state``: what the test changes while it runs -- the version the
  check-in offers (``offer``, ``explicit``), the versions whose check-in it
  refuses (``refuse``: a "broken" release that never gets a good check-in) and
  ``tamper`` (every installer it serves has one byte changed).

Only the standard library (``make-ca`` also needs ``cryptography``), and not
meant for anything but a test: one fixed code, one fixed token.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CODE = "TESTTESTTEST"
TOKEN = "cya_citest"

_RELEASE_PATH = re.compile(r"^/releases/agent-v(\d+(?:\.\d+){1,3})/([A-Za-z0-9._-]+)$")
_ORDER_PATH = re.compile(r"^/api/agent/v2/orders/[^/]+/result/$")


class State:
    lock = threading.Lock()
    offer: dict | None = None
    refuse: set[str] = set()
    tamper = False
    releases = Path(".")


class Handler(BaseHTTPRequestHandler):
    log_path = ""
    protocol_version = "HTTP/1.1"

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    def _send(self, status: int, payload: dict, headers: dict | None = None) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def _send_bytes(self, data: bytes, headers: dict | None = None) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def _record(self, **extra: object) -> None:
        line = json.dumps({"path": self.path, "at": datetime.now(timezone.utc).isoformat(), **extra})
        with State.lock, open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def _authorised(self) -> bool:
        return self.headers.get("Authorization") == f"Bearer {TOKEN}"

    # --- Lo que pide el agente -------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802 - nombre fijado por http.server
        body = self._body()
        authorised = self._authorised()
        if self.path == "/ci/state":
            with State.lock:
                if "offer" in body:
                    State.offer = body["offer"] if isinstance(body["offer"], dict) else None
                if "refuse" in body:
                    State.refuse = {str(v) for v in body.get("refuse") or []}
                if "tamper" in body:
                    State.tamper = bool(body["tamper"])
            self._record(ok=True, state=body)
            self._send(200, {"ok": True})
        elif self.path == "/api/agent/enroll/":
            code = "".join(ch for ch in str(body.get("code", "")).upper() if ch.isalnum())
            ok = code == CODE
            self._record(ok=ok, hostname=body.get("hostname", ""))
            if ok:
                self._send(200, {"ok": True, "token": TOKEN, "name": body.get("hostname") or "ci", "uuid": "ci", "protocol": 2})
            else:
                self._send(401, {"error": "Código de enrolamiento no válido, caducado o ya usado."})
        elif self.path == "/api/agent/v2/checkin/":
            version = str(body.get("agent_version") or "")
            with State.lock:
                refused = version in State.refuse
                offer = dict(State.offer) if State.offer else None
            self._record(ok=authorised and not refused, version=version, update_state=body.get("update_state"))
            if not authorised:
                self._send(401, {"error": "Token de agente no válido."})
                return
            if refused:
                # Una versión «rota»: nunca consigue un checkin bueno.
                self._send(503, {"error": "Versión rechazada por la prueba."})
                return
            self._send(
                200,
                {
                    "ok": True,
                    "protocol": 2,
                    "server_time": datetime.now(timezone.utc).isoformat(),
                    "checkin_seconds": 10,
                    "config_etag": "ci",
                    # Lo justo para que el agente trabaje sin tardar: él mismo
                    # y nada más, una vez por hora.
                    "config": {
                        "subnets": ["127.0.0.1/32"],
                        "communities": [],
                        "credentials": [],
                        "capture_configs": False,
                        "tasks": {
                            "presence": {"every_seconds": 3600},
                            "inventory": {"every_seconds": 0},
                            "configs": {"every_seconds": 0},
                            "ups": {"every_seconds": 0},
                            "hypervisors": {"every_seconds": 0},
                        },
                    },
                    "need_about": False,
                    "orders": [],
                    "paused_until": None,
                    "update": offer,
                },
            )
        elif self.path == "/api/agent/v2/results/":
            self._record(ok=authorised, items=len(body.get("items") or []))
            if not authorised:
                self._send(401, {"error": "Token de agente no válido."})
                return
            self._send(200, {"ok": True, "created": 0, "refreshed": 0})
        elif _ORDER_PATH.match(self.path):
            self._record(ok=authorised)
            self._send(200 if authorised else 401, {"ok": authorised})
        elif self.path == "/api/agent/v2/goodbye/":
            self._record(ok=authorised, reason=body.get("reason", ""))
            self._send(200 if authorised else 401, {"ok": authorised})
        elif self.path == "/api/agent/heartbeat/":
            self._record(ok=authorised, version=body.get("version", ""))
            if not authorised:
                self._send(401, {"error": "Token de agente no válido."})
                return
            # Un barrido de un solo equipo: lo justo para que el bucle del
            # agente dé su primera vuelta entera sin tardar minutos.
            self._send(
                200,
                {
                    "ok": True,
                    "interval_seconds": 60,
                    "sweep_now": False,
                    "config": {
                        "subnets": ["127.0.0.1/32"],
                        "communities": [],
                        "credentials": [],
                        "capture_configs": False,
                        "probe_ips": [],
                    },
                },
            )
        elif self.path == "/api/agent/findings/":
            self._record(ok=authorised, items=len(body.get("items") or []))
            if not authorised:
                self._send(401, {"error": "Token de agente no válido."})
                return
            self._send(200, {"ok": True, "run": "ci", "created": 0, "refreshed": 0})
        else:
            self._send(404, {"error": "no existe"})

    # --- Lo que se descarga ----------------------------------------------------

    def _release_file(self, version: str, name: str) -> bytes | None:
        target = State.releases / version / name
        if not target.is_file():
            return None
        data = target.read_bytes()
        if State.tamper and name.endswith(".exe") and data:
            # Un byte cambiado, mismo tamaño: solo la huella puede pillarlo.
            data = data[:-1] + bytes([data[-1] ^ 0xFF])
        return data

    def do_GET(self) -> None:  # noqa: N802
        match = _RELEASE_PATH.match(self.path)
        if match:
            data = self._release_file(match.group(1), match.group(2))
            self._record(ok=data is not None, tamper=State.tamper)
            if data is None:
                self._send(404, {"error": "no existe"})
            else:
                self._send_bytes(data)
            return
        if self.path == "/api/agent/v2/installer/":
            authorised = self._authorised()
            with State.lock:
                version = str((State.offer or {}).get("version") or "")
            folder = State.releases / version
            exe = next(iter(sorted(folder.glob("*.exe"))), None) if version and folder.is_dir() else None
            self._record(ok=authorised and exe is not None, version=version)
            if not authorised:
                self._send(401, {"error": "Token de agente no válido."})
                return
            if exe is None:
                self._send(404, {"error": "no hay instalador"})
                return
            manifest = (folder / "latest.json").read_bytes()
            signature = (folder / "latest.json.sig").read_text(encoding="ascii").strip()
            data = self._release_file(version, exe.name) or b""
            self._send_bytes(
                data,
                {
                    "X-Cenya-Version": version,
                    "X-Cenya-Sha256": hashlib.sha256(exe.read_bytes()).hexdigest(),
                    "X-Cenya-Manifest": base64.b64encode(manifest).decode("ascii"),
                    "X-Cenya-Manifest-Signature": signature,
                },
            )
            return
        if self.path == "/ci/state":
            with State.lock:
                self._send(200, {"offer": State.offer, "refuse": sorted(State.refuse), "tamper": State.tamper})
            return
        self._send(404, {"error": "no existe"})

    def log_message(self, *_args: object) -> None:  # silencio: el registro es el JSONL
        return


def make_ca(path: str) -> None:
    """A throwaway self-signed CA certificate (PEM), for the installer's /CA= test."""
    from datetime import timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Cenya CI test CA")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    Path(path).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    if sys.argv[1:2] == ["make-ca"]:
        make_ca(sys.argv[2])
        return
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--log", required=True)
    parser.add_argument("--releases", default="")
    args = parser.parse_args()
    Handler.log_path = args.log
    if args.releases:
        State.releases = Path(args.releases)
    open(args.log, "a", encoding="utf-8").close()
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
