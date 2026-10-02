"""Talking to the server: two POSTs, nothing more.

Standard library only. The agent as a whole now needs `pysnmp` for the SNMP
collector, but this door to the server does not: keeping it on the stdlib is
what lets a client run the agent from a plain `python -m agent` when installing
anything is a problem.

**No se siguen redirecciones.** El manejador por defecto de `urllib` reenvía
las cabeceras al destino nuevo sin comprobar que sea el mismo servidor, y entre
esas cabeceras va el `Authorization: Bearer`. Un 302 de alguien en medio se
llevaría el token permanente del agente. Una API no redirige; si lo hace, es
que algo va mal y parar es la respuesta correcta.
"""

from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
from typing import Any

from agent.i18n import _t, accept_language

#: Lo que se enseña de una respuesta de error que no es la del servidor (un
#: proxy, un portal cautivo): el principio, que suele bastar para reconocerla.
ERROR_BODY_PREVIEW = 300


def _error_detail(body: str) -> str:
    """El motivo de un error del servidor, sin el sobre JSON.

    El servidor contesta `{"error": "Token de agente no válido."}`: lo que le
    importa a una persona es la frase, no las llaves ni la «á» escapada como
    `\\u00e1`, que es como llegaba al Visor de eventos y al icono. Cualquier otra
    cosa (una página de un proxy) va tal cual, recortada.
    """
    try:
        data = json.loads(body)
    except ValueError:
        return body.strip()[:ERROR_BODY_PREVIEW]
    if isinstance(data, dict) and isinstance(data.get("error"), str) and data["error"].strip():
        return data["error"].strip()[:ERROR_BODY_PREVIEW]
    return body.strip()[:ERROR_BODY_PREVIEW]

TIMEOUT_SECONDS = 15

#: Lo que el servidor acepta de una vez (`core.discovery.MAX_BATCH_ITEMS`). El
#: agente no puede importarlo --no tiene Django-- así que se repite aquí, y el
#: troceo de `push_findings` se apoya en este número.
MAX_BATCH_ITEMS = 500

#: Techo de bytes por lote, por debajo del DATA_UPLOAD_MAX_MEMORY_SIZE de
#: Django (2,5 MB por defecto). Contar solo elementos dejó de bastar cuando
#: los hallazgos empezaron a llevar configuraciones dentro: cinco copias de
#: 500 KB en un lote de «solo cinco elementos» eran un 400 asegurado.
MAX_BATCH_BYTES = 1_500_000


def _batched(items: list[dict[str, Any]], max_bytes: int = MAX_BATCH_BYTES) -> list[list[dict[str, Any]]]:
    """Trozos que respetan el máximo de elementos **y** el de bytes."""
    batches: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    current_bytes = 0
    for item in items:
        size = len(json.dumps(item, ensure_ascii=False).encode())
        if current and (len(current) >= MAX_BATCH_ITEMS or current_bytes + size > max_bytes):
            batches.append(current)
            current, current_bytes = [], 0
        current.append(item)
        current_bytes += size
    if current:
        batches.append(current)
    return batches or [[]]


class PushError(Exception):
    """The server could not be reached or refused the push."""


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Cualquier redirección es un error, no algo que seguir con el token puesto."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102, ANN001
        raise urllib.error.HTTPError(
            req.full_url, code, f"El servidor redirigió a {newurl}; no se sigue.", headers, fp
        )


_OPENER = urllib.request.build_opener(_NoRedirects)


def _opener_for(ca_bundle: str) -> urllib.request.OpenerDirector:
    """El abridor de peticiones: el de siempre, o uno con una CA propia.

    Un certificado autofirmado es lo normal en la red de una pyme, y hasta
    ahora la única salida ante un `CERTIFICATE_VERIFY_FAILED` era desactivar la
    verificación de TLS entera -- justo lo que nunca se quiere hacer. Con la CA
    de la empresa, la conexión sigue verificada de punta a punta; solo cambia
    quién firma el certificado que se acepta.

    Sin `ca_bundle` se reutiliza el abridor de siempre y no uno nuevo: es lo
    que deja a los tests seguir interceptando `_OPENER.open` sin saber que
    existe esta función.
    """
    if not ca_bundle:
        return _OPENER
    context = ssl.create_default_context(cafile=ca_bundle)
    return urllib.request.build_opener(_NoRedirects, urllib.request.HTTPSHandler(context=context))


def _mozilla_roots() -> str:
    """The list of public root CAs that ships with the agent, or "" without it.

    `certifi` is Mozilla's list, the same one browsers on Linux and macOS use.
    It is optional on purpose: the plain `python -m agent` install has no
    dependencies, and there the fallback below simply does not exist.
    """
    try:
        import certifi
    except ImportError:
        return ""
    path = certifi.where()
    return path if os.path.exists(path) else ""


def _fallback_opener() -> urllib.request.OpenerDirector | None:
    """An opener that trusts Mozilla's roots instead of the operating system's."""
    roots = _mozilla_roots()
    if not roots:
        return None
    return _opener_for(roots)


def _is_certificate_failure(exc: urllib.error.URLError) -> bool:
    """A connection that got as far as the certificate and did not trust it."""
    return not isinstance(exc, urllib.error.HTTPError) and isinstance(exc.reason, ssl.SSLCertVerificationError)


class AgentClient:
    def __init__(self, base_url: str, token: str, *, ca_bundle: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self._opener = _opener_for(ca_bundle)
        # Only without a CA of the company's own. With one, that is the answer
        # the operator chose, and a second opinion would undo it.
        self._may_fall_back = not ca_bundle

    def _open(self, request: urllib.request.Request) -> Any:
        """Open the request, trusting what the operating system trusts.

        On Windows, Python reads the system certificate store, which keeps old
        certificates around (expired cross-signed roots, intermediates left by
        earlier chains). OpenSSL can choose one of those and refuse a perfectly
        good Let's Encrypt certificate with «certificate has expired», while the
        browser and PowerShell, which build the chain their own way, accept it.
        Seen on the first Windows install against Cenya Cloud (01-10-2026): the
        same machine enrolled at once with Mozilla's list.

        So, only when the *certificate check* fails, one more try against
        Mozilla's roots. Verification is never switched off, and a company's own
        CA (`ca_bundle`) is never second-guessed. If the second try fails too,
        the first error is the one reported: it names the real problem.
        """
        try:
            return self._opener.open(request, timeout=TIMEOUT_SECONDS)
        except urllib.error.URLError as exc:
            if not (self._may_fall_back and _is_certificate_failure(exc)):
                raise
            fallback = _fallback_opener()
            if fallback is None:
                raise
            try:
                response = fallback.open(request, timeout=TIMEOUT_SECONDS)
            except urllib.error.HTTPError:
                # The handshake worked: the server's own answer is the answer.
                self._opener, self._may_fall_back = fallback, False
                raise
            except (urllib.error.URLError, TimeoutError, OSError):
                raise exc from None
            self._opener, self._may_fall_back = fallback, False
            return response

    def heartbeat(self, *, version: str, hostname: str) -> dict[str, Any]:
        return self._post("/api/agent/heartbeat/", {"version": version, "hostname": hostname})

    def push_findings(self, *, run: dict[str, Any], items: list[dict[str, Any]]) -> dict[str, Any]:
        """Empuja los hallazgos, troceados a lo que el servidor admite.

        Sin trocear, una red de más de quinientos equipos vivos daba un 400 y
        **no entraba nada, nunca**: el agente reintentaba el mismo lote cada
        quince minutos y el usuario solo veía una línea en la salida de error.

        La ejecución se declara en el primer trozo y los siguientes cuelgan de
        ella, así que la bandeja sigue enseñando un barrido y no cinco.
        """
        batches = _batched(items)
        created = refreshed = 0
        answer: dict[str, Any] = {}
        run_uuid = ""
        for batch in batches:
            body = {**run, "run_uuid": run_uuid} if run_uuid else run
            answer = self._post("/api/agent/findings/", {"run": body, "items": batch})
            run_uuid = str(answer.get("run") or "")
            created += int(answer.get("created") or 0)
            refreshed += int(answer.get("refreshed") or 0)
        return {**answer, "created": created, "refreshed": refreshed, "batches": len(batches)}

    def enroll(self, *, code: str, hostname: str, version: str) -> dict[str, Any]:
        """Trade a one-time code for the permanent token. The only call with no token."""
        return self._post(
            "/api/agent/enroll/",
            {"code": code, "hostname": hostname, "version": version},
            authenticated=False,
        )

    def _post(self, path: str, payload: dict[str, Any], *, authenticated: bool = True) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = f"Bearer {self.token}"
        # El servidor traduce sus errores según la petición: con esto, un
        # «Token de agente no válido.» llega en el idioma del agente.
        language = accept_language()
        if language:
            headers["Accept-Language"] = language
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        try:
            with self._open(request) as response:
                answer = json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace") if exc.fp else ""
            detail = _error_detail(body) or str(exc.reason)
            # `detail` lo escribe el servidor, ya en el idioma que se le pidió.
            raise PushError(
                _t("El servidor respondió %(code)s: %(detail)s") % {"code": exc.code, "detail": detail}
            ) from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise PushError(_t("No se pudo hablar con el servidor: %(error)s") % {"error": exc}) from exc
        if not isinstance(answer, dict):
            # Un proxy o un portal cautivo puede devolver 200 con cualquier
            # cosa. Sin esto, el `answer.get(...)` de arriba lanza
            # `AttributeError` y mata el proceso del agente.
            raise PushError(_t("El servidor respondió algo que no es un objeto JSON."))
        return answer
