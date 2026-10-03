"""Translation for the few texts of the agent that a person reads on screen.

Until the tray icon, nothing the agent said was meant for a person at a desk:
log lines and collector notes that the web shows as they come. The tray is
different -- it talks to whoever sits at that Windows machine -- and the
project rule is that such text is marked for translation the moment it is
written, never "later".

It is stdlib ``gettext`` with its own domain, ``cenya-agent``, and not
Django's: the agent does not run Django, and its language is the one of the
Windows session it is shown in, not the web user's preference. The marker is
``_t`` / ``_tn`` rather than ``_`` on purpose, so that the server's
``manage.py makemessages`` does not sweep these strings into the web catalogs
where nothing would ever use them.

**The ``.po`` files are loaded as they are, compiled in memory at start-up.**
There are no ``.mo`` files: the project does not commit compiled catalogues
(``.gitignore``), and an agent installed with ``pip install ./agent`` has no
step where anything would compile them -- so a ``.mo`` would either be missing
or out of date. Compiling a catalogue of forty strings takes a millisecond, and
the ``.po`` stays the only thing to keep right. The result is a standard
``gettext.GNUTranslations``, so plurals follow each file's ``Plural-Forms``.

Updating the catalogues after adding or changing a ``_t``/``_tn`` text::

    xgettext -L Python --from-code=UTF-8 -k_t -k_tn:1,2 --no-wrap \\
        -o agent/translations/cenya-agent.pot agent/*.py agent/app/*.py
    msgmerge --update --no-wrap --backup=none \\
        agent/translations/<lang>/LC_MESSAGES/cenya-agent.po \\
        agent/translations/cenya-agent.pot

then translate what came out empty or ``fuzzy``. ``agent/tests/test_i18n.py``
fails while any text in the code is missing from a catalogue, untranslated,
fuzzy, or with its placeholders changed. Terms follow ``locale/GLOSARIO.md``,
the same as the web.

**The folder is ``translations``, never ``locale``.** Django's ``makemessages``
and ``compilemessages`` walk the whole project and adopt any directory named
``locale`` as one of theirs: with the catalogues in ``agent/locale``, running
the web's translation routine left empty ``django.po`` and stray ``.mo`` files
inside the agent. For the same reason nothing in the agent calls ``gettext``
with a literal -- Django would extract it into the web catalogues.

Spanish is the source language, as in the rest of the product: a language with
no catalogue gets Spanish, never a crash.
"""

from __future__ import annotations

import ast
import gettext
import io
import locale
import os
import struct
import sys
from functools import lru_cache
from pathlib import Path

DOMAIN = "cenya-agent"
#: `translations` y no `locale`: ver el docstring del módulo.
LOCALE_DIR = Path(__file__).resolve().parent / "translations"


#: Para fijar el idioma a mano (`en`, `pt_BR`...), por encima del de la sesión:
#: quien tiene Windows en un idioma y prefiere el icono en otro, y los tests,
#: que no pueden depender del idioma de la máquina en que corren.
LANGUAGE_ENV_VAR = "CENYA_LANGUAGE"
#: El nombre de antes de llamarse Cenya.
LEGACY_LANGUAGE_ENV_VAR = "NETINVENTORY_LANGUAGE"


def _session_languages() -> list[str]:
    """El idioma de la sesión que ve el texto: el de la interfaz de Windows."""
    forced = (os.environ.get(LANGUAGE_ENV_VAR) or os.environ.get(LEGACY_LANGUAGE_ENV_VAR) or "").strip()
    if forced:
        return [forced, forced.split("_")[0]]
    if sys.platform == "win32":
        try:
            import ctypes

            lcid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
            name = locale.windows_locale.get(lcid, "")
        except (AttributeError, OSError):
            name = ""
    else:
        name = locale.getlocale()[0] or ""
    if not name:
        return []
    return [name, name.split("_")[0]]


def accept_language() -> str:
    """El idioma del agente como cabecera `Accept-Language`, o vacío si no lo sabe.

    Para que el servidor conteste sus errores («Token de agente no válido.») en
    el idioma de quien los va a leer aquí, igual que el resto de lo que dice el
    agente. `pt_BR` pasa a `pt-BR`; la lengua sola, con menos peso, cubre a un
    servidor que tenga `pt` pero no la variante. Sin idioma conocido no se
    manda nada y el servidor usa el suyo.
    """
    tags: list[str] = []
    for name in _session_languages():
        tag = name.split(".")[0].replace("_", "-")
        if tag and tag not in tags:
            tags.append(tag)
    return ", ".join(tag if index == 0 else f"{tag};q=0.8" for index, tag in enumerate(tags))


def catalog_path(languages: list[str], locale_dir: Path | None = None) -> Path | None:
    """El `.po` que toca para esos idiomas, en orden de preferencia.

    Primero el nombre exacto (`pt_BR`), luego la lengua (`de` para `de_AT`), y
    por último cualquier variante de la misma lengua: un Windows en portugués de
    Portugal lee el catálogo de Brasil, que para esa persona es mucho mejor que
    el castellano de respaldo.
    """
    # Al llamar y no al definir: un valor por defecto se fijaría al importar.
    locale_dir = LOCALE_DIR if locale_dir is None else locale_dir

    def po(name: str) -> Path:
        return locale_dir / name / "LC_MESSAGES" / f"{DOMAIN}.po"

    for name in languages:
        if po(name).is_file():
            return po(name)
    for name in languages:
        language = name.split("_")[0]
        if po(language).is_file():
            return po(language)
        variants = sorted(locale_dir.glob(f"{language}_*/LC_MESSAGES/{DOMAIN}.po"))
        if variants:
            return variants[0]
    return None


# --- Leer un .po -----------------------------------------------------------------


def parse_po(text: str) -> list[dict]:
    """Las entradas de un `.po`: `msgid`, `msgid_plural`, `msgstr` (lista) y `flags`.

    Lo justo para los catálogos de este paquete: cadenas en varias líneas,
    escapes de C, plurales y banderas (`fuzzy`, `python-format`). Sin `msgctxt`,
    que el agente no usa: una entrada con contexto se rechaza en vez de
    ignorarse en silencio.
    """
    entries: list[dict] = []
    current: dict | None = None
    field: tuple[str, int] | None = None
    flags: set[str] = set()

    def finish() -> None:
        nonlocal current, flags
        if current is not None:
            current["flags"] = flags
            entries.append(current)
        current, flags = None, set()

    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            finish()
            field = None
            continue
        if line.startswith("#,"):
            if current is not None and current["msgstr"]:
                finish()
            flags |= {flag.strip() for flag in line[2:].split(",") if flag.strip()}
            continue
        if line.startswith("#"):
            continue
        if line.startswith("msgctxt"):
            raise ValueError(f"línea {number}: msgctxt no está soportado en los catálogos del agente")
        keyword, _, rest = line.partition(" ")
        if keyword.startswith('"'):
            if current is None or field is None:
                raise ValueError(f"línea {number}: cadena suelta fuera de una entrada")
            name, index = field
            value = ast.literal_eval(line)
            if name == "msgstr":
                current["msgstr"][index] += value
            else:
                current[name] += value
            continue
        value = ast.literal_eval(rest.strip())
        if keyword == "msgid":
            if current is not None and current["msgstr"]:
                finish()
            current = {"msgid": value, "msgid_plural": None, "msgstr": {}}
            field = ("msgid", 0)
        elif keyword == "msgid_plural" and current is not None:
            current["msgid_plural"] = value
            field = ("msgid_plural", 0)
        elif keyword.startswith("msgstr") and current is not None:
            index = int(keyword[7:-1]) if keyword.startswith("msgstr[") else 0
            current["msgstr"][index] = value
            field = ("msgstr", index)
        else:
            raise ValueError(f"línea {number}: no se entiende {keyword!r}")
    finish()
    for entry in entries:
        entry["msgstr"] = [entry["msgstr"][i] for i in sorted(entry["msgstr"])]
    return entries


def compile_mo(entries: list[dict]) -> bytes:
    """Un `.mo` en memoria, con las mismas reglas que `msgfmt`.

    Las entradas `fuzzy` y las que no tienen traducción se quedan fuera: gettext
    las ignora igual, y así el texto sale en castellano en vez de vacío. La
    cabecera (`msgid ""`) sí entra, fuzzy o no, porque de ella salen las reglas
    del plural.
    """
    pairs: dict[bytes, bytes] = {}
    for entry in entries:
        is_header = entry["msgid"] == ""
        if not is_header and ("fuzzy" in entry["flags"] or not all(entry["msgstr"])):
            continue
        key = entry["msgid"]
        if entry["msgid_plural"] is not None:
            key += "\0" + entry["msgid_plural"]
        pairs[key.encode("utf-8")] = "\0".join(entry["msgstr"]).encode("utf-8")

    keys = sorted(pairs)
    header_size = 7 * 4
    table_size = len(keys) * 8
    offset = header_size + 2 * table_size
    originals, translations, blob = [], [], b""
    for key in keys:
        originals.append((len(key), offset + len(blob)))
        blob += key + b"\0"
    for key in keys:
        value = pairs[key]
        translations.append((len(value), offset + len(blob)))
        blob += value + b"\0"
    out = struct.pack("<7I", 0x950412DE, 0, len(keys), header_size, header_size + table_size, 0, 0)
    out += b"".join(struct.pack("<2I", *pair) for pair in originals)
    out += b"".join(struct.pack("<2I", *pair) for pair in translations)
    return out + blob


def _translation() -> gettext.NullTranslations:
    """El catálogo del idioma vigente *ahora*.

    La caché va por idioma y carpeta, no una sola para siempre: con una sola,
    el primer idioma resuelto se quedaba aunque luego cambiara
    `CENYA_LANGUAGE` -- visto en los tests, donde uno que vaciaba el
    entorno dejaba el inglés de la interfaz de Windows puesto para los demás.
    """
    return _translation_for(tuple(_session_languages()), LOCALE_DIR)


@lru_cache(maxsize=8)
def _translation_for(languages: tuple[str, ...], locale_dir: Path) -> gettext.NullTranslations:
    path = catalog_path(list(languages), locale_dir)
    if path is None:
        return gettext.NullTranslations()
    try:
        entries = parse_po(path.read_text(encoding="utf-8"))
        return gettext.GNUTranslations(io.BytesIO(compile_mo(entries)))
    except (OSError, ValueError, SyntaxError):
        # Un catálogo roto no puede dejar sin icono a nadie: castellano.
        return gettext.NullTranslations()


#: Para quien necesite descartar lo cargado (un catálogo editado en caliente).
_translation.cache_clear = _translation_for.cache_clear  # type: ignore[attr-defined]


def _t(message: str) -> str:
    return _translation().gettext(message)


def _tn(singular: str, plural: str, n: int) -> str:
    return _translation().ngettext(singular, plural, n)
