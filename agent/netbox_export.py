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
import json
import os
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


class ExportError(Exception):
    """Anything that stops the export, phrased for the person running it."""


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


def _get_page(client: urllib.request.OpenerDirector, url: str, token: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Authorization": f"Token {token}", "Accept": "application/json"})
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


def _fetch_image(client: urllib.request.OpenerDirector, url: str, token: str) -> bytes | None:
    """A photo's bytes, or nothing. A missing photo never stops the export."""
    request = urllib.request.Request(url, headers={"Authorization": f"Token {token}"})
    try:
        with client.open(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_IMAGE_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return raw if 0 < len(raw) <= MAX_IMAGE_BYTES else None


def _attach_images(client: urllib.request.OpenerDirector, base_url: str, rows: list[dict], token: str) -> None:
    host = urllib.parse.urlsplit(base_url).netloc
    spent = 0
    for row in rows:
        for source_field, target_field in IMAGE_FIELDS:
            url = str(row.get(source_field) or "").strip()
            if not url or urllib.parse.urlsplit(url).netloc != host:
                continue
            if spent >= MAX_IMAGES_BYTES:
                return
            raw = _fetch_image(client, url, token)
            if raw is None:
                continue
            spent += len(raw)
            row[target_field] = base64.b64encode(raw).decode("ascii")


def fetch_bundle(base_url: str, token: str, verify_tls: bool = True, progress: Any = None) -> dict[str, list[dict]]:
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
    _attach_images(client, base_url, bundle["device_types"], token)
    return bundle


# --- La línea de comandos ------------------------------------------------------


def _usage(prog: str) -> str:
    return _t("Uso: %(prog)s URL [--output FICHERO] [--insecure]") % {"prog": prog}


def run(args: list[str], prog: str = "cenya-agent export-netbox", environ: Any = None) -> int:
    """The command. Returns the process exit code: 0 done, 1 failed, 2 misused."""
    env = os.environ if environ is None else environ
    verify_tls = True
    output = Path.home() / DEFAULT_FILENAME
    positional: list[str] = []
    rest = iter(args)
    for arg in rest:
        if arg == "--insecure":
            verify_tls = False
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

    try:
        bundle = fetch_bundle(url, token, verify_tls=verify_tls, progress=progress)
    except ExportError as exc:
        print(str(exc), file=sys.stderr)
        return 1
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
    print(_t("Súbelo en Cenya: Ajustes → Importar → «NetBox, desde un fichero»."))
    return 0


if __name__ == "__main__":
    prog = f"python {Path(sys.argv[0]).name}"
    raise SystemExit(run(sys.argv[1:], prog=prog))
