"""Exporting a NetBox from inside the network: `cenya-agent export-netbox`.

For the NetBox the Cenya server cannot reach -- always the case in Cenya Cloud
when the NetBox lives on the customer's LAN. The agent already runs on a
machine that sees it, so it reads the NetBox there and writes the same bundle
the server builds when it reads one itself; the person uploads that file in
Ajustes -> Importar, «NetBox, desde un fichero».

    cenya-agent export-netbox https://netbox.midominio.local

**This file also works on its own**, outside the agent, with nothing but
Python: the import page offers it for download for whoever has no agent
installed (``python cenya-netbox-export.py https://netbox.midominio.local``).
That is why it uses only the standard library and imports nothing from the
agent except, when it is there, the translations.

Same hard rules as the server's reader (``core/netbox.py``):

* The token is asked for without echo, used for the export and forgotten. It
  is never written anywhere, the file included.
* Redirects are not followed: urllib would forward the ``Authorization``
  header to wherever the redirect points.
* Every request has a timeout and every collection a cap.
* The ``next`` link and the elevation photos are only fetched from the host
  the person typed.

**The bundle format is a contract with the server**: same collections, same
image fields, same caps. ``core/tests/test_netbox_export_contract.py`` fails if
the two drift apart.
"""

from __future__ import annotations

import base64
import getpass
import http.cookiejar
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

try:
    from agent.i18n import _t, _tn
except ImportError:  # Downloaded on its own: no catalogues, so Spanish.

    def _t(message: str) -> str:
        return message

    def _tn(singular: str, plural: str, n: int) -> str:
        return singular if n == 1 else plural


#: NetBox collections read, in dependency order. Must match core/netbox.py.
ENDPOINTS: dict[str, str] = {
    "sites": "/api/dcim/sites/",
    "racks": "/api/dcim/racks/",
    "device_types": "/api/dcim/device-types/",
    "interface_templates": "/api/dcim/interface-templates/",
    "console_port_templates": "/api/dcim/console-port-templates/",
    "power_port_templates": "/api/dcim/power-port-templates/",
    "power_outlet_templates": "/api/dcim/power-outlet-templates/",
    "front_port_templates": "/api/dcim/front-port-templates/",
    "devices": "/api/dcim/devices/",
    "interfaces": "/api/dcim/interfaces/",
    "power_ports": "/api/dcim/power-ports/",
    "power_outlets": "/api/dcim/power-outlets/",
    "front_ports": "/api/dcim/front-ports/",
    "cables": "/api/dcim/cables/",
    "vlans": "/api/ipam/vlans/",
    "prefixes": "/api/ipam/prefixes/",
    "ip_addresses": "/api/ipam/ip-addresses/",
}

PAGE_SIZE = 200
TIMEOUT_SECONDS = 15
MAX_PER_COLLECTION = 20_000
#: Elevation photos travel inside the bundle, in base64, next to their model.
IMAGE_FIELDS: tuple[tuple[str, str], ...] = (
    ("front_image", "front_image_data"),
    ("rear_image", "rear_image_data"),
)
MAX_IMAGE_BYTES = 2 * 1024 * 1024
#: The server refuses uploads over 50 MB: past this, photos are left out
#: rather than producing a file the product itself would reject.
MAX_IMAGES_BYTES = 24 * 1024 * 1024

DEFAULT_FILENAME = "netbox-export.json"
TOKEN_ENV_VAR = "CENYA_NETBOX_TOKEN"
PASSWORD_ENV_VAR = "CENYA_NETBOX_PASSWORD"
#: Answers that mean «this photo is only for a signed-in person»: a NetBox with
#: LOGIN_REQUIRED hides /media/ (404, or a redirect to the login page) from an
#: API token, which only opens /api/. Seen on a real NetBox on 04-10-2026: 49
#: photo addresses and not one photo, with nothing said about it.
NEEDS_LOGIN_CODES = frozenset({301, 302, 303, 307, 308, 401, 403, 404})
LOGIN_PAGE_MAX_BYTES = 512 * 1024


class ExportError(Exception):
    """Anything that stops the export, phrased for the person running it."""


class PhotoStats:
    """What happened to the elevation photos, for the summary at the end.

    The bundle format does not change -- it is a contract with the server --
    so this travels beside it rather than inside it.
    """

    def __init__(self) -> None:
        self.wanted = 0
        self.got = 0
        #: Refused the way a NetBox refuses someone who has not signed in.
        self.needs_login = 0
        #: Timeouts, oversized files, a dead network: not a question of login.
        self.other = 0
        #: The size budget ran out and the rest were not asked for.
        self.capped = 0


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """A 302 is answered, not followed: the token must never travel onwards."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


def _client(verify_tls: bool) -> urllib.request.OpenerDirector:
    """The opener. Without verification only when the person asked for it.

    Proxies from the environment are ignored: the NetBox is on the LAN, and a
    corporate proxy would either not reach it or see the token.
    """
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        _NoRedirects(),
    )


def _timeout_message() -> str:
    return _t("NetBox no respondió en %(seconds)s segundos. ¿Es esa la URL y llega la red hasta allí?") % {
        "seconds": TIMEOUT_SECONDS
    }


def authorization(token: str) -> str:
    """The ``Authorization`` header for a token as a person pastes it.

    NetBox's own «Copy» button copies the whole header value («Token abc…»),
    so the word in front is dropped instead of being sent twice -- NetBox then
    answers 401 and the person is told a good token is wrong. NetBox 4.5 also
    issues v2 tokens, ``nbt_<key>.<secret>``, which go with ``Bearer``; the v1
    ones keep ``Token``. Same rule as the server's ``core.netbox.authorization``.
    """
    value = token.strip().strip("\"'").strip()
    for prefix in ("token ", "bearer "):
        if value.lower().startswith(prefix):
            value = value[len(prefix):].strip()
            break
    scheme = "Bearer" if value.startswith("nbt_") else "Token"
    return f"{scheme} {value}"


def _get_page(client: urllib.request.OpenerDirector, url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Authorization": authorization(token), "Accept": "application/json"})
    try:
        with client.open(request, timeout=TIMEOUT_SECONDS) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise ExportError(
                _t("NetBox rechazó el token. Crea uno de solo lectura en tu NetBox (Admin → API tokens) y prueba de nuevo.")
            ) from exc
        if exc.code in (301, 302, 307, 308):
            raise ExportError(
                _t(
                    "NetBox respondió con una redirección (¿falta o sobra «https» o una barra al final de la URL?). "
                    "No se siguen redirecciones con un token."
                )
            ) from exc
        raise ExportError(_t("NetBox respondió %(code)s.") % {"code": exc.code}) from exc
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            raise ExportError(
                _t(
                    "El certificado de ese NetBox no es válido (%(reason)s). Si es un NetBox de tu red con "
                    "certificado autofirmado o caducado, añade --insecure y vuelve a intentarlo."
                )
                % {"reason": exc.reason.verify_message or exc.reason}
            ) from exc
        if isinstance(exc.reason, TimeoutError):
            raise ExportError(_timeout_message()) from exc
        raise ExportError(_t("No se pudo hablar con NetBox: %(reason)s") % {"reason": exc.reason}) from exc
    except TimeoutError as exc:
        raise ExportError(_timeout_message()) from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ExportError(_t("La respuesta de NetBox no es JSON. ¿Es esa la URL de NetBox?")) from exc


def _next_on_same_host(base_url: str, next_url: object) -> str | None:
    """The next page, on the host the person typed (see core/netbox.py)."""
    if not next_url or not isinstance(next_url, str):
        return None
    base = urllib.parse.urlsplit(base_url)
    following = urllib.parse.urlsplit(next_url)
    return urllib.parse.urlunsplit((base.scheme, base.netloc, following.path, following.query, ""))


def _fetch_collection(client: urllib.request.OpenerDirector, base_url: str, path: str, token: str) -> list[dict]:
    url: str | None = f"{base_url}{path}?limit={PAGE_SIZE}"
    results: list[dict] = []
    while url:
        page = _get_page(client, url, token)
        batch = page.get("results") if isinstance(page, dict) else None
        if not isinstance(batch, list):
            raise ExportError(_t("La respuesta de %(path)s no tiene la forma esperada.") % {"path": path})
        results.extend(batch)
        if len(results) > MAX_PER_COLLECTION:
            raise ExportError(
                _t(
                    "%(path)s tiene más de %(max)s objetos. Esta importación está pensada para "
                    "inventarios de pyme; hablemos antes de traer eso."
                )
                % {"path": path, "max": MAX_PER_COLLECTION}
            )
        url = _next_on_same_host(base_url, page.get("next"))
    return results


def _fetch_image(
    client: urllib.request.OpenerDirector, url: str, token: str, stats: PhotoStats | None = None
) -> bytes | None:
    """A photo's bytes, or nothing. A missing photo never stops the export,
    but it is counted, with whether it looks like a question of signing in."""
    headers = {"Authorization": authorization(token)} if token else {}
    request = urllib.request.Request(url, headers=headers)
    try:
        with client.open(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_IMAGE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        if stats is not None:
            if exc.code in NEEDS_LOGIN_CODES:
                stats.needs_login += 1
            else:
                stats.other += 1
        return None
    except (urllib.error.URLError, OSError, ValueError):
        if stats is not None:
            stats.other += 1
        return None
    if 0 < len(raw) <= MAX_IMAGE_BYTES and not _looks_like_a_page(raw):
        return raw
    if stats is not None:
        # An HTML page where a photo was asked for is a login page served with
        # a 200: the same refusal as a 404, said differently.
        if _looks_like_a_page(raw):
            stats.needs_login += 1
        else:
            stats.other += 1
    return None


def _looks_like_a_page(raw: bytes) -> bool:
    head = raw[:512].lstrip().lower()
    return head.startswith((b"<!doctype html", b"<html"))


def _attach_images(
    client: urllib.request.OpenerDirector,
    base_url: str,
    rows: list[dict],
    token: str,
    stats: PhotoStats | None = None,
) -> None:
    """Download each model's photos into the bundle. ``client`` may be a
    signed-in session (see ``login_session``); then the token is not sent."""
    stats = stats if stats is not None else PhotoStats()
    host = urllib.parse.urlsplit(base_url).netloc
    spent = 0
    for row in rows:
        for source_field, target_field in IMAGE_FIELDS:
            url = str(row.get(source_field) or "").strip()
            if not url or urllib.parse.urlsplit(url).netloc != host:
                continue
            stats.wanted += 1
            if spent >= MAX_IMAGES_BYTES:
                stats.capped += 1
                continue
            raw = _fetch_image(client, url, token, stats)
            if raw is None:
                continue
            spent += len(raw)
            stats.got += 1
            row[target_field] = base64.b64encode(raw).decode("ascii")


def login_session(base_url: str, username: str, password: str, verify_tls: bool = True) -> urllib.request.OpenerDirector:
    """A NetBox web session, for the photos and nothing else.

    A NetBox that requires a login hides /media/ from API tokens, so the photos
    are fetched the way a browser would: the login form, its CSRF token, the
    password once. Nothing is kept: the password is not stored, and the session
    cookie lives in this opener and dies with the process (``logout`` ends it
    on the server too).
    """
    base_url = base_url.strip().rstrip("/")
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(jar),
        _NoRedirects(),
    )
    login_url = f"{base_url}/login/"
    try:
        with opener.open(urllib.request.Request(login_url), timeout=TIMEOUT_SECONDS) as response:
            page = response.read(LOGIN_PAGE_MAX_BYTES).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        raise ExportError(
            _t("No se pudo abrir la página de inicio de sesión de NetBox (%(code)s).") % {"code": exc.code}
        ) from exc
    except (urllib.error.URLError, OSError) as exc:
        raise ExportError(_t("No se pudo hablar con NetBox: %(reason)s") % {"reason": exc}) from exc
    match = re.search(r'name="csrfmiddlewaretoken"\s+value="([^"]+)"', page)
    if not match:
        raise ExportError(_t("No se encontró el formulario de inicio de sesión de NetBox."))
    form = urllib.parse.urlencode(
        {"csrfmiddlewaretoken": match.group(1), "username": username, "password": password, "next": "/"}
    ).encode()
    request = urllib.request.Request(
        login_url,
        data=form,
        headers={"Referer": login_url, "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS):
            # A 200 is the form again: the credentials were not accepted.
            pass
    except urllib.error.HTTPError as exc:
        location = exc.headers.get("Location", "") if exc.headers else ""
        if exc.code in (302, 303) and "/login" not in location:
            return opener
        raise ExportError(_t("NetBox no aceptó ese usuario y contraseña.")) from exc
    raise ExportError(_t("NetBox no aceptó ese usuario y contraseña."))


def logout(base_url: str, session: urllib.request.OpenerDirector) -> None:
    """End the photo session on the server. Best effort: it expires anyway."""
    try:
        session.open(urllib.request.Request(f"{base_url.strip().rstrip('/')}/logout/"), timeout=TIMEOUT_SECONDS)
    except (urllib.error.URLError, OSError, ValueError):
        pass


def fetch_bundle(
    base_url: str,
    token: str,
    verify_tls: bool = True,
    progress: Any = None,
    photo_session: urllib.request.OpenerDirector | None = None,
    photo_stats: PhotoStats | None = None,
) -> dict[str, list[dict]]:
    """The whole NetBox as one bundle. ``progress(path)`` is told each collection."""
    base_url = base_url.strip().rstrip("/")
    if not base_url.startswith(("http://", "https://")):
        raise ExportError(_t("La URL tiene que empezar por http:// o https://."))
    if not urllib.parse.urlsplit(base_url).hostname:
        raise ExportError(_t("La URL no dice a qué servidor conectarse."))
    client = _client(verify_tls)
    bundle: dict[str, list[dict]] = {}
    for name, path in ENDPOINTS.items():
        if progress is not None:
            progress(path)
        bundle[name] = _fetch_collection(client, base_url, path, token)
    if photo_session is not None:
        _attach_images(photo_session, base_url, bundle["device_types"], "", photo_stats)
    else:
        _attach_images(client, base_url, bundle["device_types"], token, photo_stats)
    return bundle


# --- La línea de comandos ------------------------------------------------------


def _usage(prog: str) -> str:
    return _t("Uso: %(prog)s URL [--output FICHERO] [--insecure] [--photos-user USUARIO]") % {"prog": prog}


def run(args: list[str], prog: str = "cenya-agent export-netbox", environ: Any = None) -> int:
    """The command. Returns the process exit code: 0 done, 1 failed, 2 misused."""
    env = os.environ if environ is None else environ
    verify_tls = True
    output = Path.home() / DEFAULT_FILENAME
    photos_user = ""
    positional: list[str] = []
    rest = iter(args)
    for arg in rest:
        if arg == "--insecure":
            verify_tls = False
        elif arg == "--photos-user":
            photos_user = next(rest, "").strip()
            if not photos_user:
                print(_usage(prog), file=sys.stderr)
                return 2
        elif arg in ("--output", "-o"):
            value = next(rest, "")
            if not value:
                print(_usage(prog), file=sys.stderr)
                return 2
            output = Path(value).expanduser()
        elif arg in ("--help", "-h"):
            print(_usage(prog))
            return 0
        else:
            positional.append(arg)
    # Un segundo argumento es el token, para quien lo lance desde un script;
    # a mano es mejor que lo pregunte: así no se queda en el historial.
    if not positional or len(positional) > 2:
        print(_usage(prog), file=sys.stderr)
        return 2
    url = positional[0]
    token = positional[1] if len(positional) == 2 else (env.get(TOKEN_ENV_VAR) or "").strip()
    if not token:
        if sys.stdin is None or not sys.stdin.isatty():
            print(
                _t("Falta el token de NetBox: pásalo en la variable %(var)s.") % {"var": TOKEN_ENV_VAR},
                file=sys.stderr,
            )
            return 2
        token = getpass.getpass(_t("Token de solo lectura de NetBox (no se muestra al escribirlo): ")).strip()
        if not token:
            print(_t("Sin token no se puede leer NetBox."), file=sys.stderr)
            return 2

    def progress(path: str) -> None:
        print(_t("Leyendo %(path)s…") % {"path": path}, file=sys.stderr, flush=True)

    # The photos of a NetBox that requires a login: a web session, opened with
    # a password that is asked for, used once and never written anywhere.
    session = None
    if photos_user:
        password = (env.get(PASSWORD_ENV_VAR) or "").strip()
        if not password:
            if sys.stdin is None or not sys.stdin.isatty():
                print(
                    _t("Falta la contraseña de NetBox: pásala en la variable %(var)s.") % {"var": PASSWORD_ENV_VAR},
                    file=sys.stderr,
                )
                return 2
            password = getpass.getpass(
                _t("Contraseña de %(user)s en NetBox, solo para las fotos (no se muestra ni se guarda): ")
                % {"user": photos_user}
            )
        try:
            session = login_session(url, photos_user, password, verify_tls=verify_tls)
        except ExportError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        finally:
            password = ""

    stats = PhotoStats()
    try:
        bundle = fetch_bundle(
            url, token, verify_tls=verify_tls, progress=progress, photo_session=session, photo_stats=stats
        )
    except ExportError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        if session is not None:
            logout(url, session)
    try:
        output.write_text(json.dumps(bundle, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        print(
            _t("No se pudo escribir %(path)s: %(error)s") % {"path": output, "error": exc.strerror or exc},
            file=sys.stderr,
        )
        return 1
    total = sum(len(rows) for rows in bundle.values())
    print(
        _tn(
            "Exportado %(n)d objeto a %(path)s.",
            "Exportados %(n)d objetos a %(path)s.",
            total,
        )
        % {"n": total, "path": output.resolve()}
    )
    for line in photo_summary(stats, signed_in=session is not None):
        print(line)
    print(_t("Súbelo en Cenya: Ajustes → Importar → «NetBox, desde un fichero»."))
    return 0


def photo_summary(stats: PhotoStats, signed_in: bool, in_app: bool = False) -> list[str]:
    """What happened to the photos, said always: a silent miss is what made a
    whole catalogue arrive without a single picture. ``in_app`` words the way
    out for the agent's window, which has a box to tick instead of a flag."""
    if not stats.wanted:
        return []
    lines = [
        _tn(
            "Fotos de los modelos: %(got)d de %(wanted)d.",
            "Fotos de los modelos: %(got)d de %(wanted)d.",
            stats.wanted,
        )
        % {"got": stats.got, "wanted": stats.wanted}
    ]
    if stats.needs_login and not signed_in and in_app:
        lines.append(
            _tn(
                "%(n)d foto no se pudo bajar: tu NetBox solo enseña las fotos con la sesión iniciada, y el token "
                "solo abre la API. Repite marcando «Bajar también las fotos con un usuario de NetBox».",
                "%(n)d fotos no se pudieron bajar: tu NetBox solo enseña las fotos con la sesión iniciada, y el "
                "token solo abre la API. Repite marcando «Bajar también las fotos con un usuario de NetBox».",
                stats.needs_login,
            )
            % {"n": stats.needs_login}
        )
    elif stats.needs_login and not signed_in:
        lines.append(
            _tn(
                "%(n)d foto no se pudo bajar: tu NetBox solo enseña las fotos con la sesión iniciada, y el token "
                "solo abre la API. Repite con --photos-user TU_USUARIO.",
                "%(n)d fotos no se pudieron bajar: tu NetBox solo enseña las fotos con la sesión iniciada, y el "
                "token solo abre la API. Repite con --photos-user TU_USUARIO.",
                stats.needs_login,
            )
            % {"n": stats.needs_login}
        )
    elif stats.needs_login:
        lines.append(
            _tn(
                "%(n)d foto no se pudo bajar ni con la sesión iniciada: ¿puede ese usuario ver los modelos?",
                "%(n)d fotos no se pudieron bajar ni con la sesión iniciada: ¿puede ese usuario ver los modelos?",
                stats.needs_login,
            )
            % {"n": stats.needs_login}
        )
    if stats.other:
        lines.append(
            _tn(
                "%(n)d foto no se pudo bajar por la red, el tiempo o el tamaño.",
                "%(n)d fotos no se pudieron bajar por la red, el tiempo o el tamaño.",
                stats.other,
            )
            % {"n": stats.other}
        )
    if stats.capped:
        lines.append(
            _tn(
                "%(n)d foto se quedó fuera para que el fichero no pase del tamaño que acepta Cenya.",
                "%(n)d fotos se quedaron fuera para que el fichero no pase del tamaño que acepta Cenya.",
                stats.capped,
            )
            % {"n": stats.capped}
        )
    return lines


if __name__ == "__main__":
    prog = f"python {Path(sys.argv[0]).name}"
    raise SystemExit(run(sys.argv[1:], prog=prog))
