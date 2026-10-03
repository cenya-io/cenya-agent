"""Talking to the server: a handful of POSTs, nothing more.

Protocol 1 (the 0.10.x agents) is a heartbeat and a push of findings; protocol
2 (``docs/agente-v2-nucleo.md``) adds the control channel (``checkin``), one
result per task, the answers to orders and the goodbye. Both stay here: an
agent 0.11 talking to a server that only knows protocol 1 falls back to it.

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
import urllib.parse
import urllib.request
from typing import Any

from agent.i18n import _t, accept_language
from agent.logs import scrub

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

#: Lo más que acepta `v2/netbox-bundle/` (spec 3.4). Se comprueba antes de
#: abrir la conexión: subir 60 MB para oír un 413 es una hora de una línea lenta.
MAX_BUNDLE_BYTES = 50 * 1024 * 1024
#: Cada operación de la subida (conectar, cada escritura, la respuesta) puede
#: esperar esto. Generoso --el servidor valida el paquete entero antes de
#: contestar-- pero con fin: una subida colgada no puede retener el encargo.
UPLOAD_TIMEOUT_SECONDS = 300
#: De cuánto en cuánto se escribe el JSON en la conexión.
_UPLOAD_CHUNK = 64 * 1024

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


#: El protocolo más alto que habla este agente (docs/agente-v2-nucleo.md).
PROTOCOL = 2


def result_parts(run: dict[str, Any], items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The bodies of `v2/results`: same `run` in all, `part` from 1, `final` on the last."""
    batches = _batched(items)
    return [
        {"run": run, "items": batch, "part": number, "final": number == len(batches)}
        for number, batch in enumerate(batches, start=1)
    ]


class PushError(Exception):
    """The server could not be reached or refused the push.

    `status` is the HTTP code when the server did answer (`None` when it could
    not be reached): the protocol-2 loop needs to tell «this door does not
    exist» (404, a server that only speaks protocol 1) from «the network is
    down», and the outbox «this will never be accepted» (400) from «later».
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status
        #: Lo que no llegó a enviarse de un resultado troceado (`push_results`).
        self.remaining: list[dict[str, Any]] = []


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Cualquier redirección es un error, no algo que seguir con el token puesto."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102, ANN001
        raise urllib.error.HTTPError(
            req.full_url, code, f"El servidor redirigió a {newurl}; no se sigue.", headers, fp
        )


_OPENER = urllib.request.build_opener(_NoRedirects)

#: Cómo salir a internet (`settings.json`, `agent/settings.py`). `system` es lo
#: de siempre: urllib lee el proxy del sistema (variables y, en Windows, el
#: registro). `none` sale directo aunque el sistema diga otra cosa; `manual`,
#: por el proxy que se indique.
PROXY_SYSTEM = "system"
PROXY_NONE = "none"
PROXY_MANUAL = "manual"


def proxy_url_is_valid(url: str) -> bool:
    """Si `url` es algo que `urllib` sabrá usar como proxy.

    ``http://[usuario:clave@]servidor:puerto`` o solo ``servidor:puerto``. Una
    errata como ``https:/admin:S3cret@proxy:8080`` hacía que `urllib` lanzara
    un `ValueError` **con la URL dentro**, contraseña incluida, que acababa en
    el registro, en `status.json` y en el Visor de eventos.
    """
    url = (url or "").strip()
    if not url or any(char.isspace() for char in url):
        return False
    if "://" in url:
        parts = urllib.parse.urlsplit(url)
        try:
            parts.port  # noqa: B018 - un puerto que no es un número lanza aquí
        except ValueError:
            return False
        return bool(parts.scheme) and bool(parts.hostname)
    return "/" not in url


def _proxy_problem() -> str:
    return _t(
        "La dirección del proxy no es válida: revisa el ajuste «proxy» (settings.json o CENYA_PROXY). "
        "No se muestra aquí porque puede llevar una contraseña."
    )


def _proxy_handler(proxy: tuple[str, str] | None) -> urllib.request.ProxyHandler | None:
    """El manejador de proxy para ese modo, o `None` para el del sistema."""
    if not proxy:
        return None
    mode, url = proxy
    if mode == PROXY_NONE:
        return urllib.request.ProxyHandler({})
    if mode == PROXY_MANUAL and url:
        return urllib.request.ProxyHandler({"http": url, "https": url})
    return None


def _opener_for(ca_bundle: str, proxy: tuple[str, str] | None = None) -> urllib.request.OpenerDirector:
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
    handler = _proxy_handler(proxy)
    if not ca_bundle and handler is None:
        return _OPENER
    handlers: list = [_NoRedirects]
    if handler is not None:
        handlers.append(handler)
    if ca_bundle:
        context = ssl.create_default_context(cafile=ca_bundle)
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


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


def _fallback_opener(proxy: tuple[str, str] | None = None) -> urllib.request.OpenerDirector | None:
    """An opener that trusts Mozilla's roots instead of the operating system's.

    Through the same proxy as the first try: a second opinion on the
    certificate, not a second way out of the network.
    """
    roots = _mozilla_roots()
    if not roots:
        return None
    return _opener_for(roots, proxy)


def _is_certificate_failure(exc: urllib.error.URLError) -> bool:
    """A connection that got as far as the certificate and did not trust it."""
    return not isinstance(exc, urllib.error.HTTPError) and isinstance(exc.reason, ssl.SSLCertVerificationError)


class AgentClient:
    def __init__(
        self, base_url: str, token: str, *, ca_bundle: str = "", proxy: tuple[str, str] | None = None
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        #: `(modo, url)` de `agent/settings.py`; `None` es el proxy del sistema.
        #: La URL puede llevar usuario y contraseña: no se escribe en ningún sitio.
        #: Un proxy manual mal escrito no se usa ni se nombra: cada petición
        #: falla con una frase que no lo cita (`_proxy_problem`).
        self._bad_proxy = bool(proxy and proxy[0] == PROXY_MANUAL and not proxy_url_is_valid(proxy[1]))
        if self._bad_proxy:
            proxy = (PROXY_NONE, "")
        self._proxy = proxy
        self._opener = _opener_for(ca_bundle, proxy) if proxy else _opener_for(ca_bundle)
        # Only without a CA of the company's own. With one, that is the answer
        # the operator chose, and a second opinion would undo it.
        self._may_fall_back = not ca_bundle

    def reconfigure(self, *, ca_bundle: str = "", proxy: tuple[str, str] | None = None) -> None:
        """A new CA bundle or proxy without a new client: whoever holds this one sees it at once.

        Lo usa el canal local (`settings.set`) para aplicar el cambio sin
        reiniciar. Lanza si la CA no se puede cargar, antes de tocar nada.
        """
        fresh = AgentClient(self.base_url, self.token, ca_bundle=ca_bundle, proxy=proxy)
        self._bad_proxy, self._proxy = fresh._bad_proxy, fresh._proxy
        self._opener, self._may_fall_back = fresh._opener, fresh._may_fall_back

    def _open(self, request: urllib.request.Request, timeout: float = TIMEOUT_SECONDS) -> Any:
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
            return self._opener.open(request, timeout=timeout)
        except urllib.error.URLError as exc:
            if not (self._may_fall_back and _is_certificate_failure(exc)):
                raise
            fallback = _fallback_opener(self._proxy) if self._proxy else _fallback_opener()
            if fallback is None:
                raise
            try:
                response = fallback.open(request, timeout=timeout)
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

    def enroll(
        self,
        *,
        code: str,
        hostname: str,
        version: str,
        public_key: str = "",
        about: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Trade a one-time code for the permanent token. The only call with no token.

        `protocol`, `public_key` and `about` are protocol 2 (spec 1.1); a server
        that does not know them ignores them, and one that does not answer
        `protocol` is taken as protocol 1.
        """
        payload: dict[str, Any] = {"code": code, "hostname": hostname, "version": version, "protocol": PROTOCOL}
        if public_key:
            payload["public_key"] = public_key
        if about:
            payload["about"] = about
        return self._post("/api/agent/enroll/", payload, authenticated=False)

    # --- Protocolo 2 (docs/agente-v2-nucleo.md, sección 1) ----------------------

    def checkin(self, body: dict[str, Any]) -> dict[str, Any]:
        """The control channel (spec 1.2). A 404 means the server speaks protocol 1."""
        return self._post("/api/agent/v2/checkin/", body)

    def post_result_part(self, body: dict[str, Any]) -> dict[str, Any]:
        """One already-built piece of a result (spec 1.6): what the outbox resends."""
        return self._post("/api/agent/v2/results/", body)

    def push_results(self, *, run: dict[str, Any], items: list[dict[str, Any]]) -> dict[str, Any]:
        """The result of a task, in as many pieces as the limits require.

        Every piece carries the same `run` (and so the same `run.id`, which is
        what makes resending one harmless). If a piece fails, the `PushError`
        carries in `remaining` that piece and the ones after it, ready for the
        outbox: what went up stays up.
        """
        parts = result_parts(run, items)
        created = refreshed = 0
        answer: dict[str, Any] = {}
        for index, body in enumerate(parts):
            try:
                answer = self.post_result_part(body)
            except PushError as exc:
                exc.remaining = parts[index:]
                raise
            created += int(answer.get("created") or 0)
            refreshed += int(answer.get("refreshed") or 0)
        return {**answer, "created": created, "refreshed": refreshed, "batches": len(parts)}

    def answer_order(self, order_id: str, body: dict[str, Any]) -> dict[str, Any]:
        """Answer an order (spec 1.3). The id goes quoted: it comes from the server."""
        return self._post(f"/api/agent/v2/orders/{urllib.parse.quote(order_id, safe='')}/result/", body)

    def goodbye(self, reason: str = "uninstall") -> dict[str, Any]:
        """Tell the server this agent is going away; its token stops working (spec 1.7)."""
        return self._post("/api/agent/v2/goodbye/", {"reason": reason})

    def upload_netbox_bundle(self, bundle: dict, order_id: str | None = None) -> dict[str, Any]:
        """Upload what was read from a NetBox (spec 3.4). Returns ``{"ok": true, "import": "<uuid>"}``.

        El paquete puede rondar los 50 MB: no se construye dos veces en
        memoria. El JSON se escribe a trozos directamente en la conexión, y
        para saber su tamaño (el `Content-Length`, y el tope antes de enviar
        nada) se recorre una vez sin guardarlo. Dos pasadas de CPU a cambio de
        no tener a la vez el diccionario, el texto y los bytes.
        """
        body = _JsonBody(bundle)
        size = body.size()
        if size > MAX_BUNDLE_BYTES:
            raise PushError(
                _t("Lo leído de NetBox ocupa %(mb)s MB y el servidor admite %(max)s MB como mucho.")
                % {"mb": size // (1024 * 1024), "max": MAX_BUNDLE_BYTES // (1024 * 1024)},
                status=413,
            )
        extra = {"Content-Length": str(size)}
        if order_id:
            extra["X-Cenya-Order"] = str(order_id)
        return self._send("/api/agent/v2/netbox-bundle/", body, extra=extra, timeout=UPLOAD_TIMEOUT_SECONDS)

    def _post(self, path: str, payload: dict[str, Any], *, authenticated: bool = True) -> dict[str, Any]:
        return self._send(path, json.dumps(payload).encode(), authenticated=authenticated)

    def _send(
        self,
        path: str,
        data: Any,
        *,
        authenticated: bool = True,
        extra: dict[str, str] | None = None,
        timeout: float = TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        if self._bad_proxy:
            raise PushError(_proxy_problem())
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Authorization"] = f"Bearer {self.token}"
        # El servidor traduce sus errores según la petición: con esto, un
        # «Token de agente no válido.» llega en el idioma del agente.
        language = accept_language()
        if language:
            headers["Accept-Language"] = language
        headers.update(extra or {})
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with self._open(request, timeout) as response:
                answer = json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace") if exc.fp else ""
            detail = _error_detail(body) or str(exc.reason)
            # `detail` lo escribe el servidor, ya en el idioma que se le pidió.
            raise PushError(
                _t("El servidor respondió %(code)s: %(detail)s") % {"code": exc.code, "detail": detail},
                status=exc.code,
            ) from exc
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise PushError(_t("No se pudo hablar con el servidor: %(error)s") % {"error": scrub(str(exc))}) from exc
        except ValueError as exc:
            # `urllib` mete en el texto la URL que no entiende, y si es la del
            # proxy lleva su contraseña: no se repite, ni siquiera tapada.
            if self._proxy and self._proxy[0] == PROXY_MANUAL:
                raise PushError(_proxy_problem()) from None
            raise PushError(_t("No se pudo hablar con el servidor: %(error)s") % {"error": scrub(str(exc))}) from None
        if not isinstance(answer, dict):
            # Un proxy o un portal cautivo puede devolver 200 con cualquier
            # cosa. Sin esto, el `answer.get(...)` de arriba lanza
            # `AttributeError` y mata el proceso del agente.
            raise PushError(_t("El servidor respondió algo que no es un objeto JSON."))
        return answer


class _JsonBody:
    """A JSON document written to the connection in pieces, as many times as asked.

    `http.client` acepta como cuerpo cualquier iterable de bytes. Cada
    `__iter__` vuelve a codificar desde el principio: si la primera conexión
    falla al validar el certificado y `_open` reintenta con las raíces de
    Mozilla, el cuerpo vuelve a estar entero.
    """

    def __init__(self, document: Any) -> None:
        self._document = document

    def __iter__(self):  # noqa: ANN204
        encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"))
        pending: list[bytes] = []
        size = 0
        for piece in encoder.iterencode(self._document):
            data = piece.encode("utf-8")
            pending.append(data)
            size += len(data)
            if size >= _UPLOAD_CHUNK:
                yield b"".join(pending)
                pending, size = [], 0
        if pending:
            yield b"".join(pending)

    def size(self) -> int:
        return sum(len(chunk) for chunk in self)
