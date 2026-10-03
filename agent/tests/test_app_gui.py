"""The page and the window's options (agent/app/main.py): offline, no socket.

The parts that need pywebview skip cleanly without it (CI on Linux has no
desktop and does not install the `gui` extra).
"""

from __future__ import annotations

import agent.tests  # noqa: F401

import importlib.util
import re
import tomllib
import unittest
from pathlib import Path

from agent.app import main

HAS_WEBVIEW = importlib.util.find_spec("webview") is not None
AGENT_DIR = Path(main.__file__).resolve().parent.parent


class PageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.page = main.build_page()

    def test_everything_is_inlined(self) -> None:
        self.assertNotIn('<link rel="stylesheet"', self.page)
        self.assertNotIn("<script src=", self.page)
        self.assertIn("<style>", self.page)
        self.assertEqual(self.page.count("<script>"), 2)

    def test_nothing_is_loaded_from_anywhere(self) -> None:
        self.assertIn("Content-Security-Policy", self.page)
        self.assertIn("connect-src 'none'", self.page)
        self.assertIsNone(re.search(r"""(src|href)\s*=\s*["']?(https?:)?//""", self.page))
        self.assertNotIn("@import", self.page)
        self.assertNotIn("url(http", self.page)

    def test_no_emoji_in_the_interface(self) -> None:
        for path in (main.UI_DIR).glob("*.*"):
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(re.search("[\U0001F300-\U0001FAFF☀-➿]", text), path.name)

    def test_the_page_never_writes_html_from_data(self) -> None:
        script = (main.UI_DIR / "app.js").read_text(encoding="utf-8")
        # Solo los iconos (constantes) entran como HTML.
        self.assertEqual(sorted(set(re.findall(r"(\w+)\.innerHTML\s*=\s*(\w+)", script))), [("logo", "brandTileSvg"), ("t", "iconSvg")])

    def test_lucide_licence_ships_with_the_icons(self) -> None:
        self.assertTrue((main.UI_DIR / "LUCIDE-LICENSE.txt").is_file())


class PackagingTests(unittest.TestCase):
    def test_the_page_travels_as_package_data(self) -> None:
        pyproject = tomllib.loads((AGENT_DIR / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertIn("agent.app", pyproject["tool"]["setuptools"]["packages"])
        patterns = pyproject["tool"]["setuptools"]["package-data"]["agent.app"]
        for path in main.UI_DIR.iterdir():
            self.assertTrue(any(Path("ui", path.name).match(p) for p in patterns), path.name)
        self.assertEqual(pyproject["project"]["gui-scripts"]["cenya-agent-app"], "agent.app.main:main")
        self.assertIn("gui", pyproject["project"]["optional-dependencies"])


class WindowOptionsTests(unittest.TestCase):
    def test_no_url_means_no_server(self) -> None:
        options = main.window_options("<html></html>", object(), dark=True)
        self.assertIsNone(options["url"])
        self.assertTrue(options["html"])
        self.assertFalse(main.START_OPTIONS["http_server"])
        self.assertEqual(main.START_OPTIONS["gui"], "edgechromium")

    @unittest.skipUnless(HAS_WEBVIEW, "pywebview no está instalado")
    def test_pywebview_agrees_it_needs_no_server(self) -> None:
        from webview import http, util

        options = main.window_options("<html></html>", object(), dark=False)
        self.assertFalse(util.is_local_url(options["url"]))
        self.assertFalse(util.is_app(options["url"]))
        self.assertIsNone(http.global_server)
        main.assert_no_server()

    @unittest.skipUnless(HAS_WEBVIEW, "pywebview no está instalado")
    def test_the_guard_trips_if_a_server_appears(self) -> None:
        from unittest import mock

        from webview import http

        with mock.patch.object(http, "global_server", object()):
            with self.assertRaises(RuntimeError):
                main.assert_no_server()

    def test_arguments(self) -> None:
        options = main.parse_args(["--section", "netbox", "--elevated", "--unknown"])
        self.assertEqual(options.section, "netbox")
        self.assertTrue(options.elevated)
        self.assertFalse(options.assume_admin)


if __name__ == "__main__":
    unittest.main()
