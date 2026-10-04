"""The photos of a NetBox that only shows them to a signed-in person.

A real NetBox (04-10-2026) answered «la página no existe» for every photo when
asked with the API token -- its /media/ is only for a session -- and the
export came out with 49 photo addresses and no photo, silently. Now the
summary says how many photos arrived and why the others did not, and
``--photos-user`` signs in the way a browser does, only for the photos.

Run against a real HTTP server that behaves like that NetBox: a login form
with its CSRF token, a session cookie, photos only for the session, the API
only for the token. Nothing is mocked between the exporter and the socket.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import contextlib
import http.server
import io
import json
import tempfile
import threading
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

from agent import netbox_export

TOKEN = "token-de-api"
USER, PASSWORD = "eduardo", "la-contraseña-de-verdad"
PHOTO = b"\x89PNG\r\n\x1a\n" + b"x" * 64
CSRF = "csrf-del-formulario"
SESSION = "sesion-abierta"


class StrictNetBox(http.server.BaseHTTPRequestHandler):
    """Photos for a session, the API for a token, nothing for anyone else."""

    log: list[str] = []

    def log_message(self, *args: object) -> None:  # silence
        pass

    def _send(self, code: int, body: bytes = b"", headers: dict[str, str] | None = None) -> None:
        self.send_response(code)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _signed_in(self) -> bool:
        return f"sessionid={SESSION}" in (self.headers.get("Cookie") or "")

    def do_GET(self) -> None:  # noqa: N802
        type(self).log.append(f"GET {self.path}")
        if self.path.startswith("/api/"):
            if self.headers.get("Authorization") != f"Token {TOKEN}":
                return self._send(403)
            if self.path.startswith("/api/dcim/device-types/"):
                host = f"http://{self.headers['Host']}"
                rows = [
                    {"id": 1, "model": "A", "front_image": f"{host}/media/a.png", "rear_image": ""},
                    {"id": 2, "model": "B", "front_image": f"{host}/media/b.png", "rear_image": ""},
                ]
                return self._send(200, json.dumps({"results": rows, "next": None}).encode())
            return self._send(200, json.dumps({"results": [], "next": None}).encode())
        if self.path.startswith("/media/"):
            return self._send(200, PHOTO) if self._signed_in() else self._send(404, b"<html>no existe</html>")
        if self.path == "/login/":
            form = f'<form><input type="hidden" name="csrfmiddlewaretoken" value="{CSRF}"></form>'.encode()
            return self._send(200, form, {"Set-Cookie": "csrftoken=cookie-csrf; Path=/"})
        if self.path == "/logout/":
            return self._send(302, headers={"Location": "/login/"})
        return self._send(404)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        form = urllib.parse.parse_qs(self.rfile.read(length).decode())
        type(self).log.append(f"POST {self.path}")
        if self.path != "/login/":
            return self._send(404)
        good = (
            form.get("csrfmiddlewaretoken") == [CSRF]
            and form.get("username") == [USER]
            and form.get("password") == [PASSWORD]
            and "csrftoken=cookie-csrf" in (self.headers.get("Cookie") or "")
        )
        if good:
            return self._send(302, headers={"Location": "/", "Set-Cookie": f"sessionid={SESSION}; Path=/"})
        return self._send(200, b"<form>otra vez</form>")


class PhotosTests(unittest.TestCase):
    def setUp(self) -> None:
        StrictNetBox.log = []
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), StrictNetBox)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.output = Path(tempfile.mkdtemp()) / "netbox.json"

    def run_export(self, *extra: str, password: str | None = None) -> tuple[int, str, str]:
        env = {netbox_export.TOKEN_ENV_VAR: TOKEN}
        if password is not None:
            env[netbox_export.PASSWORD_ENV_VAR] = password
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            with mock.patch("sys.stdin", None):
                code = netbox_export.run([self.base, "--output", str(self.output), *extra], environ=env)
        return code, out.getvalue(), err.getvalue()

    def photos_in_file(self) -> int:
        bundle = json.loads(self.output.read_text(encoding="utf-8"))
        return sum(1 for row in bundle["device_types"] if row.get("front_image_data"))

    def test_without_a_session_it_says_why_the_photos_are_missing_and_what_to_do(self) -> None:
        code, out, _ = self.run_export()

        self.assertEqual(code, 0)
        self.assertEqual(self.photos_in_file(), 0)
        self.assertIn("Fotos de los modelos: 0 de 2.", out)
        self.assertIn("2 fotos no se pudieron bajar: tu NetBox solo enseña las fotos con la sesión iniciada", out)
        self.assertIn("--photos-user", out)

    def test_with_a_session_every_photo_arrives(self) -> None:
        code, out, err = self.run_export("--photos-user", USER, password=PASSWORD)

        self.assertEqual(code, 0, err)
        self.assertEqual(self.photos_in_file(), 2)
        self.assertIn("Fotos de los modelos: 2 de 2.", out)
        self.assertNotIn("no se pudieron", out)

    def test_the_session_is_closed_and_the_token_never_rides_along_to_the_photos(self) -> None:
        self.run_export("--photos-user", USER, password=PASSWORD)

        self.assertIn("GET /logout/", StrictNetBox.log)
        self.assertLess(StrictNetBox.log.index("POST /login/"), StrictNetBox.log.index("GET /media/a.png"))

    def test_the_password_is_never_in_the_file_nor_on_screen(self) -> None:
        _, out, err = self.run_export("--photos-user", USER, password=PASSWORD)

        self.assertNotIn(PASSWORD, self.output.read_text(encoding="utf-8"))
        self.assertNotIn(PASSWORD, out + err)

    def test_a_wrong_password_stops_before_anything_is_written(self) -> None:
        code, _, err = self.run_export("--photos-user", USER, password="otra")

        self.assertEqual(code, 1)
        self.assertIn("NetBox no aceptó ese usuario y contraseña.", err)
        self.assertFalse(self.output.exists())

    def test_without_a_terminal_a_missing_password_is_a_message(self) -> None:
        code, _, err = self.run_export("--photos-user", USER)

        self.assertEqual(code, 2)
        self.assertIn(netbox_export.PASSWORD_ENV_VAR, err)

    def test_the_bundle_keeps_its_format(self) -> None:
        """Contract with the server: the same collections, nothing added."""
        self.run_export("--photos-user", USER, password=PASSWORD)

        bundle = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(set(bundle), set(netbox_export.ENDPOINTS))


class SummaryTests(unittest.TestCase):
    def test_nothing_to_say_when_no_model_has_a_photo(self) -> None:
        self.assertEqual(netbox_export.photo_summary(netbox_export.PhotoStats(), signed_in=False), [])

    def test_a_login_page_served_with_200_counts_as_needing_a_session(self) -> None:
        self.assertTrue(netbox_export._looks_like_a_page(b"  <!DOCTYPE html><html>login</html>"))
        self.assertFalse(netbox_export._looks_like_a_page(PHOTO))


if __name__ == "__main__":
    unittest.main()


class TokenHeaderTests(unittest.TestCase):
    """A token as a person pastes it: NetBox's «Copy» brings the word in front,
    and NetBox 4.5's v2 tokens (``nbt_…``) go with ``Bearer``. The same rule
    as the server's ``core.netbox.authorization``."""

    def test_v1_and_v2_tokens(self) -> None:
        cases = {
            "abc123": "Token abc123",
            "  abc123\n": "Token abc123",
            "Token abc123": "Token abc123",
            "token abc123": "Token abc123",
            '"abc123"': "Token abc123",
            "nbt_key.secret": "Bearer nbt_key.secret",
            "Bearer nbt_key.secret": "Bearer nbt_key.secret",
            "Token nbt_key.secret": "Bearer nbt_key.secret",
        }
        for pasted, header in cases.items():
            with self.subTest(pasted=pasted):
                self.assertEqual(netbox_export.authorization(pasted), header)

    def test_a_pasted_prefix_still_reads_the_api(self) -> None:
        StrictNetBox.log = []
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), StrictNetBox)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        bundle = netbox_export.fetch_bundle(f"http://127.0.0.1:{server.server_address[1]}", f"Token {TOKEN}")
        self.assertEqual(len(bundle["device_types"]), 2)
