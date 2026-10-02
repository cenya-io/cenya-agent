"""Tests for `cenya-agent export-netbox`: reading a NetBox from inside the network.

The properties that matter: the bundle comes out whole (every page of every
collection, photos included), the token never travels anywhere but the NetBox
the person typed and is never written to the file, and every failure is a
sentence that says what to do -- this runs in a console on a customer's
machine, where a stack trace helps nobody.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - idioma y carpeta de estado de prueba

import contextlib
import io
import json
import ssl
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from agent import __main__ as agent_main
from agent import netbox_export

BASE = "https://netbox.oficina.local"
TOKEN = "token-secretisimo"


class _Response(io.BytesIO):
    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class FakeNetBox:
    """An opener that answers by URL and records what it was asked for."""

    def __init__(self, pages: dict[str, object] | None = None, error: BaseException | None = None) -> None:
        self.pages = pages or {}
        self.error = error
        self.requests: list[tuple[str, str | None]] = []

    def open(self, request, timeout: float = 0) -> _Response:  # noqa: ANN001
        self.requests.append((request.full_url, request.get_header("Authorization")))
        if self.error is not None:
            raise self.error
        if request.full_url in self.pages:
            body = self.pages[request.full_url]
            return _Response(body if isinstance(body, bytes) else json.dumps(body).encode())
        # Toda colección que el test no menciona existe y está vacía.
        if "/api/" in request.full_url:
            return _Response(json.dumps({"results": [], "next": None}).encode())
        raise urllib.error.URLError("404")


def page(path: str) -> str:
    return f"{BASE}{path}?limit={netbox_export.PAGE_SIZE}"


def fetch(fake: FakeNetBox, **kwargs: object) -> dict:
    with mock.patch.object(netbox_export, "_client", return_value=fake):
        return netbox_export.fetch_bundle(BASE, TOKEN, **kwargs)


class FetchTests(unittest.TestCase):
    def test_every_collection_is_in_the_bundle(self) -> None:
        bundle = fetch(FakeNetBox())

        self.assertEqual(set(bundle), set(netbox_export.ENDPOINTS))

    def test_every_page_is_read_and_next_stays_on_the_typed_host(self) -> None:
        """A NetBox behind a proxy announces another host in `next`: the typed one is kept."""
        sites = netbox_export.ENDPOINTS["sites"]
        fake = FakeNetBox(
            {
                page(sites): {"results": [{"id": 1}], "next": f"http://interno:8000{sites}?limit=200&offset=200"},
                f"{BASE}{sites}?limit=200&offset=200": {"results": [{"id": 2}], "next": None},
            }
        )

        bundle = fetch(fake)

        self.assertEqual([row["id"] for row in bundle["sites"]], [1, 2])
        self.assertTrue(all(url.startswith(BASE) for url, _auth in fake.requests))

    def test_photos_travel_in_the_bundle_only_from_the_same_host(self) -> None:
        types = netbox_export.ENDPOINTS["device_types"]
        fake = FakeNetBox(
            {
                page(types): {
                    "results": [
                        {"id": 1, "front_image": f"{BASE}/media/front.png", "rear_image": "https://otro.example/rear.png"}
                    ],
                    "next": None,
                },
                f"{BASE}/media/front.png": b"\x89PNG-foto",
            }
        )

        row = fetch(fake)["device_types"][0]

        self.assertIn("front_image_data", row)
        self.assertNotIn("rear_image_data", row)
        self.assertNotIn("https://otro.example/rear.png", [url for url, _auth in fake.requests])

    def test_a_rejected_token_says_how_to_make_one(self) -> None:
        error = urllib.error.HTTPError(BASE, 403, "Forbidden", {}, None)  # type: ignore[arg-type]

        with self.assertRaises(netbox_export.ExportError) as caught:
            fetch(FakeNetBox(error=error))

        self.assertIn("solo lectura", str(caught.exception))

    def test_a_bad_certificate_points_to_insecure(self) -> None:
        reason = ssl.SSLCertVerificationError("certificate has expired")
        reason.verify_message = "certificate has expired"

        with self.assertRaises(netbox_export.ExportError) as caught:
            fetch(FakeNetBox(error=urllib.error.URLError(reason)))

        self.assertIn("--insecure", str(caught.exception))

    def test_a_connect_timeout_is_said_in_words(self) -> None:
        with self.assertRaises(netbox_export.ExportError) as caught:
            fetch(FakeNetBox(error=urllib.error.URLError(TimeoutError("timed out"))))

        self.assertIn("no respondió", str(caught.exception))

    def test_a_url_without_scheme_is_refused_before_any_request(self) -> None:
        fake = FakeNetBox()
        with mock.patch.object(netbox_export, "_client", return_value=fake):
            with self.assertRaises(netbox_export.ExportError):
                netbox_export.fetch_bundle("netbox.oficina.local", TOKEN)

        self.assertEqual(fake.requests, [])

    def test_redirects_are_not_followed(self) -> None:
        handler = next(h for h in netbox_export._client(True).handlers if isinstance(h, netbox_export._NoRedirects))

        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://otro.example/"))


class CommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = Path(tempfile.mkdtemp(prefix="cenya-netbox-export-"))
        self.output = self.folder / "export.json"

    def run_command(self, args: list[str], environ: dict | None = None, fake: FakeNetBox | None = None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(netbox_export, "_client", return_value=fake or FakeNetBox()):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = netbox_export.run(args, environ=environ or {})
        return code, out.getvalue(), err.getvalue()

    def test_it_writes_the_bundle_and_says_where(self) -> None:
        fake = FakeNetBox({page(netbox_export.ENDPOINTS["sites"]): {"results": [{"id": 7}], "next": None}})

        code, out, _err = self.run_command(
            [BASE, "--output", str(self.output)], environ={netbox_export.TOKEN_ENV_VAR: TOKEN}, fake=fake
        )

        self.assertEqual(code, 0)
        bundle = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual(bundle["sites"], [{"id": 7}])
        self.assertIn(str(self.output.resolve()), out)
        self.assertIn(("" + page(netbox_export.ENDPOINTS["sites"]), f"Token {TOKEN}"), fake.requests)

    def test_the_token_is_never_in_the_file_nor_on_screen(self) -> None:
        code, out, err = self.run_command(
            [BASE, "-o", str(self.output)], environ={netbox_export.TOKEN_ENV_VAR: TOKEN}
        )

        self.assertEqual(code, 0)
        self.assertNotIn(TOKEN, self.output.read_text(encoding="utf-8"))
        self.assertNotIn(TOKEN, out + err)

    def test_the_token_is_asked_for_without_echo(self) -> None:
        with mock.patch.object(netbox_export.sys, "stdin") as stdin, mock.patch.object(
            netbox_export.getpass, "getpass", return_value=TOKEN
        ) as asked:
            stdin.isatty.return_value = True
            code, _out, _err = self.run_command([BASE, "-o", str(self.output)])

        self.assertEqual(code, 0)
        asked.assert_called_once()

    def test_without_a_terminal_a_missing_token_is_a_message(self) -> None:
        with mock.patch.object(netbox_export.sys, "stdin") as stdin:
            stdin.isatty.return_value = False
            code, _out, err = self.run_command([BASE, "-o", str(self.output)])

        self.assertEqual(code, 2)
        self.assertIn(netbox_export.TOKEN_ENV_VAR, err)
        self.assertFalse(self.output.exists())

    def test_without_url_it_shows_the_usage(self) -> None:
        code, _out, err = self.run_command([])

        self.assertEqual(code, 2)
        self.assertIn("export-netbox", err)

    def test_a_failure_is_one_sentence_and_no_file(self) -> None:
        error = urllib.error.URLError(TimeoutError("timed out"))
        code, _out, err = self.run_command(
            [BASE, "-o", str(self.output)], environ={netbox_export.TOKEN_ENV_VAR: TOKEN}, fake=FakeNetBox(error=error)
        )

        self.assertEqual(code, 1)
        self.assertIn("no respondió", err)
        self.assertNotIn("Traceback", err)
        self.assertFalse(self.output.exists())

    def test_insecure_turns_off_verification_for_this_run(self) -> None:
        with mock.patch.object(netbox_export, "fetch_bundle", return_value={}) as fetched:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                netbox_export.run(
                    [BASE, "--insecure", "-o", str(self.output)], environ={netbox_export.TOKEN_ENV_VAR: TOKEN}
                )

        self.assertFalse(fetched.call_args.kwargs["verify_tls"])


class EntryPointTests(unittest.TestCase):
    def test_export_netbox_runs_without_being_enrolled(self) -> None:
        """Exporting talks to the NetBox only: nobody has to enrol the agent first."""
        with mock.patch.object(netbox_export, "run", return_value=0) as ran, mock.patch.object(
            agent_main.enroll, "ensure_enrolled"
        ) as enrolled:
            with self.assertRaises(SystemExit) as caught:
                agent_main.main(["export-netbox", BASE])

        self.assertEqual(caught.exception.code, 0)
        ran.assert_called_once_with([BASE])
        enrolled.assert_not_called()


if __name__ == "__main__":
    unittest.main()
