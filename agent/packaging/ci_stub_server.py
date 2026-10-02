"""A stand-in for the Cenya portal, for the installer's smoke test in CI.

The smoke test installs the agent for real (a Windows service, as
administrator) and has to see it enrol and send its heartbeat. Standing up
Django and PostgreSQL on the runner for that would test the server, which
already has its own suite; this answers the three endpoints the agent uses and
writes down what it was asked, so the test can check it.

    python ci_stub_server.py --port 8765 --log requests.jsonl

Only the standard library, and not meant for anything but a test: it accepts one
fixed code and hands out one fixed token.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

CODE = "TESTTESTTEST"
TOKEN = "cya_citest"


class Handler(BaseHTTPRequestHandler):
    log_path = ""

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return {}

    def _send(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _record(self, **extra: object) -> None:
        with open(self.log_path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"path": self.path, **extra}) + "\n")

    def do_POST(self) -> None:  # noqa: N802 - nombre fijado por http.server
        body = self._body()
        authorised = self.headers.get("Authorization") == f"Bearer {TOKEN}"
        if self.path == "/api/agent/enroll/":
            code = "".join(ch for ch in str(body.get("code", "")).upper() if ch.isalnum())
            ok = code == CODE
            self._record(ok=ok, hostname=body.get("hostname", ""))
            if ok:
                self._send(200, {"ok": True, "token": TOKEN, "name": body.get("hostname") or "ci", "uuid": "ci"})
            else:
                self._send(401, {"error": "Código de enrolamiento no válido, caducado o ya usado."})
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

    def log_message(self, *_args: object) -> None:  # silencio: el registro es el JSONL
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()
    Handler.log_path = args.log
    open(args.log, "a", encoding="utf-8").close()
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
