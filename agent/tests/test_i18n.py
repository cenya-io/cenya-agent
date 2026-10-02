"""Tests for the agent's translation catalogues.

They fail while any text marked in the code (`_t`, `_tn`) is missing from a
catalogue, left untranslated or fuzzy, or translated with its placeholders
changed -- the same failures the web guards against, and the ones that do not
show until someone opens the icon in that language.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - fija idioma y fichero de estado también bajo `unittest discover`

import ast
import gettext
import io
import os
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from agent import i18n, status

AGENT_DIR = Path(i18n.__file__).resolve().parent
REPO_ROOT = AGENT_DIR.parent
LANGUAGES = ("en", "de", "fr", "pt_BR")
PLACEHOLDER = re.compile(r"%\((\w+)\)[sdif]")


def marked_in_code() -> set[str | tuple[str, str]]:
    """Todo lo que el código pasa a `_t`/`_tn`, leído del código mismo."""
    found: set[str | tuple[str, str]] = set()
    # También la aplicación de escritorio (agent/app): sus textos son del mismo dominio.
    for path in [*AGENT_DIR.glob("*.py"), *(AGENT_DIR / "app").glob("*.py")]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                continue
            args = node.args
            if node.func.id == "_t" and args and isinstance(args[0], ast.Constant):
                found.add(args[0].value)
            elif node.func.id == "_tn" and len(args) >= 2 and all(isinstance(a, ast.Constant) for a in args[:2]):
                found.add((args[0].value, args[1].value))
    return found


def catalog(lang: str) -> list[dict]:
    path = AGENT_DIR / "translations" / lang / "LC_MESSAGES" / f"{i18n.DOMAIN}.po"
    return i18n.parse_po(path.read_text(encoding="utf-8"))


def key(entry: dict) -> str | tuple[str, str]:
    return (entry["msgid"], entry["msgid_plural"]) if entry["msgid_plural"] is not None else entry["msgid"]


class InLanguage:
    """Fija el idioma del agente dentro de un bloque `with`."""

    def __init__(self, language: str, locale_dir: Path | None = None) -> None:
        self.language = language
        self.locale_dir = locale_dir

    def __enter__(self) -> None:
        self._patches = [mock.patch.dict(os.environ, {i18n.LANGUAGE_ENV_VAR: self.language})]
        if self.locale_dir is not None:
            self._patches.append(mock.patch.object(i18n, "LOCALE_DIR", self.locale_dir))
        for patch in self._patches:
            patch.start()
        i18n._translation.cache_clear()

    def __exit__(self, *exc: object) -> None:
        for patch in reversed(self._patches):
            patch.stop()
        i18n._translation.cache_clear()


class CatalogCompletenessTests(unittest.TestCase):
    def test_every_marked_text_is_in_every_catalogue_and_nothing_stale(self) -> None:
        code = marked_in_code()
        self.assertGreater(len(code), 20)  # si esto baja a cero, el escáner se ha roto
        for lang in LANGUAGES:
            with self.subTest(lang=lang):
                in_catalog = {key(e) for e in catalog(lang) if e["msgid"]}
                self.assertEqual(sorted(map(str, code - in_catalog)), [], "sin traducir (falta en el .po)")
                self.assertEqual(sorted(map(str, in_catalog - code)), [], "sobra en el .po (ya no está en el código)")

    def test_the_template_matches_the_code_too(self) -> None:
        pot = i18n.parse_po((AGENT_DIR / "translations" / f"{i18n.DOMAIN}.pot").read_text(encoding="utf-8"))
        self.assertEqual({key(e) for e in pot if e["msgid"]}, marked_in_code())

    def test_nothing_is_empty_or_fuzzy(self) -> None:
        for lang in LANGUAGES:
            for entry in catalog(lang):
                if not entry["msgid"]:
                    continue
                with self.subTest(lang=lang, msgid=entry["msgid"]):
                    self.assertNotIn("fuzzy", entry["flags"])
                    self.assertTrue(entry["msgstr"] and all(entry["msgstr"]))
                    expected_forms = 2 if entry["msgid_plural"] is not None else 1
                    self.assertEqual(len(entry["msgstr"]), expected_forms)

    def test_placeholders_survive_translation(self) -> None:
        """Uno renombrado o perdido revienta con KeyError al pintar, solo en ese idioma."""
        for lang in LANGUAGES:
            for entry in catalog(lang):
                if not entry["msgid"]:
                    continue
                sources = [entry["msgid"], entry["msgid_plural"] or entry["msgid"]]
                for form, text in enumerate(entry["msgstr"]):
                    with self.subTest(lang=lang, msgid=entry["msgid"], form=form):
                        wanted = set(PLACEHOLDER.findall(sources[min(form, 1)]))
                        self.assertEqual(set(PLACEHOLDER.findall(text)), wanted)

    def test_plural_rules_match_the_web_catalogues(self) -> None:
        """Mismo idioma, misma regla de plural que la aplicación web."""
        for lang in LANGUAGES:
            with self.subTest(lang=lang):
                ours = gettext.GNUTranslations(io.BytesIO(i18n.compile_mo(catalog(lang))))
                web_po = REPO_ROOT / "locale" / lang / "LC_MESSAGES" / "django.po"
                if not web_po.exists():
                    self.skipTest("sin catálogos web en este checkout")
                web_rule = re.search(r'Plural-Forms: ([^\\"]+)', web_po.read_text(encoding="utf-8")).group(1).strip()
                self.assertEqual(ours.info()["plural-forms"].strip().rstrip(";"), web_rule.rstrip(";"))

    def test_the_catalogues_ship_in_the_package(self) -> None:
        """Sin esto, un agente instalado con pip no tendría traducciones, y nadie lo notaría."""
        pyproject = tomllib.loads((AGENT_DIR / "pyproject.toml").read_text(encoding="utf-8"))
        data = pyproject["tool"]["setuptools"]["package-data"]["agent"]
        self.assertIn(f"translations/*/LC_MESSAGES/{i18n.DOMAIN}.po", data)

    def test_django_translation_commands_leave_the_agent_alone(self) -> None:
        """Visto en el proyecto: con los catálogos en `agent/locale`, el
        `makemessages` de la web adoptó esa carpeta y dejó dentro `django.po`
        vacíos y `.mo` sueltos. Dos reglas lo evitan, y aquí se vigilan."""
        self.assertEqual(
            [str(p.relative_to(AGENT_DIR)) for p in AGENT_DIR.rglob("locale") if p.is_dir()],
            [],
            "Django toma cualquier carpeta llamada «locale» por suya",
        )
        # Y ninguna llamada a gettext/ngettext/_ con un literal: Django la
        # extraería a los catálogos de la web, donde nadie la usaría.
        django_keywords = re.compile(r"""\b(?:gettext|ngettext|pgettext|gettext_lazy|_)\(\s*["']""")
        offenders = [
            f"{path.relative_to(AGENT_DIR)}:{number}"
            for path in AGENT_DIR.rglob("*.py")
            if "__pycache__" not in path.parts
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if django_keywords.search(line)
        ]
        self.assertEqual(offenders, [])


class CompilerTests(unittest.TestCase):
    def test_fuzzy_and_empty_entries_stay_in_spanish(self) -> None:
        po = (
            'msgid ""\nmsgstr ""\n"Content-Type: text/plain; charset=UTF-8\\n"\n'
            '"Plural-Forms: nplurals=2; plural=(n != 1);\\n"\n\n'
            'msgid "Ver estado"\nmsgstr "View status"\n\n'
            '#, fuzzy\nmsgid "En marcha"\nmsgstr "Running maybe"\n\n'
            'msgid "Arrancando"\nmsgstr ""\n'
        )
        translation = gettext.GNUTranslations(io.BytesIO(i18n.compile_mo(i18n.parse_po(po))))
        # Por un alias y no llamando a gettext con el texto escrito ahí mismo: el
        # makemessages de la web extraería esos literales a sus catálogos (ver
        # el test de arriba).
        lookup = translation.gettext
        originals = ("Ver estado", "En marcha", "Arrancando")

        self.assertEqual([lookup(text) for text in originals], ["View status", "En marcha", "Arrancando"])

    def test_multiline_strings_and_escapes(self) -> None:
        po = 'msgid ""\nmsgstr ""\n\nmsgid ""\n"uno:\\n"\n"%(x)s \\"dos\\""\nmsgstr ""\n"one:\\n"\n"%(x)s \\"two\\""\n'
        entry = i18n.parse_po(po)[1]

        self.assertEqual(entry["msgid"], 'uno:\n%(x)s "dos"')
        self.assertEqual(entry["msgstr"], ['one:\n%(x)s "two"'])

    def test_context_is_refused_rather_than_silently_ignored(self) -> None:
        with self.assertRaises(ValueError):
            i18n.parse_po('msgctxt "menú"\nmsgid "Abrir"\nmsgstr "Open"\n')

    def test_the_compiled_catalogues_equal_what_msgfmt_produces(self) -> None:
        msgfmt = shutil.which("msgfmt")
        if not msgfmt:
            self.skipTest("msgfmt no está instalado (en CI sí)")
        for lang in LANGUAGES:
            with self.subTest(lang=lang), tempfile.TemporaryDirectory() as tmp:
                po = AGENT_DIR / "translations" / lang / "LC_MESSAGES" / f"{i18n.DOMAIN}.po"
                mo = Path(tmp) / "reference.mo"
                subprocess.run([msgfmt, "--check", "-o", str(mo), str(po)], check=True, capture_output=True)
                with mo.open("rb") as handle:
                    reference = gettext.GNUTranslations(handle)
                ours = gettext.GNUTranslations(io.BytesIO(i18n.compile_mo(catalog(lang))))
                # La cabecera no se compara tal cual: msgfmt quita campos como
                # POT-Creation-Date al compilar. De ella solo importa el plural.
                self.assertEqual(
                    {k: v for k, v in ours._catalog.items() if k != ""},
                    {k: v for k, v in reference._catalog.items() if k != ""},
                )
                self.assertEqual([ours.plural(n) for n in range(5)], [reference.plural(n) for n in range(5)])


class LanguageChoiceTests(unittest.TestCase):
    def test_each_language_gets_its_own_words(self) -> None:
        expected = {
            "en": "View status",
            "de": "Status anzeigen",
            "fr": "Voir l'état",
            "pt_BR": "Ver status",
            "es": "Ver estado",
        }
        for language, text in expected.items():
            with self.subTest(language=language), InLanguage(language):
                self.assertEqual(i18n._t("Ver estado"), text)

    def test_regional_variants_find_their_language(self) -> None:
        cases = {
            "de_AT": "Status anzeigen",  # la lengua sin la región
            "en_GB": "View status",
            "pt_PT": "Ver status",  # Portugal lee el catálogo de Brasil antes que el castellano
            "ja_JP": "Ver estado",  # sin catálogo: castellano, nunca un fallo
        }
        for language, text in cases.items():
            with self.subTest(language=language), InLanguage(language):
                self.assertEqual(i18n._t("Ver estado"), text)

    def test_plurals_follow_each_language_rule(self) -> None:
        with InLanguage("fr"):
            # En francés el cero es singular.
            self.assertEqual(i18n._tn("%(n)d hallazgo nuevo", "%(n)d hallazgos nuevos", 0) % {"n": 0}, "0 nouvelle découverte")
            self.assertEqual(i18n._tn("%(n)d hallazgo nuevo", "%(n)d hallazgos nuevos", 2) % {"n": 2}, "2 nouvelles découvertes")
        with InLanguage("de"):
            self.assertEqual(i18n._tn("hace %(n)d día", "hace %(n)d días", 1) % {"n": 1}, "vor 1 Tag")
            self.assertEqual(i18n._tn("hace %(n)d día", "hace %(n)d días", 3) % {"n": 3}, "vor 3 Tagen")

    def test_a_broken_catalogue_falls_back_to_spanish(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "de" / "LC_MESSAGES" / f"{i18n.DOMAIN}.po"
            broken.parent.mkdir(parents=True)
            broken.write_text('msgid "Ver estado"\nmsgstr no-es-una-cadena\n', encoding="utf-8")
            with InLanguage("de", locale_dir=Path(tmp)):
                self.assertEqual(i18n._t("Ver estado"), "Ver estado")

    def test_the_status_window_speaks_the_session_language(self) -> None:
        now = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)
        data = {
            "state": "durmiendo",
            "updated_at": (now - timedelta(seconds=30)).isoformat(),
            "last_sweep_finished_at": (now - timedelta(minutes=5)).isoformat(),
            "last_sweep_created": 1,
            "last_sweep_refreshed": 14,
            "last_sweep_notes": ["ssh: sin credenciales"],
            "last_contact_ok_at": (now - timedelta(seconds=30)).isoformat(),
        }
        with InLanguage("de"):
            health = status.describe(data, now, status.SERVICE_RUNNING)
            tip = status.tooltip(health)

        self.assertEqual(health.headline, "Läuft")
        self.assertEqual(tip, "Cenya Agent: Läuft")
        self.assertIn("vor 5 Minuten", health.details[0])
        self.assertEqual(health.details[1], "1 neuer Fund, 14 bereits bekannt.")
        self.assertIn("1 Hinweis", health.details[2])


if __name__ == "__main__":
    unittest.main()
