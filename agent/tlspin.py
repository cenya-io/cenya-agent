"""«Confiar en este certificado»: TLS fijado a una huella, como `known_hosts` en SSH.

El vCenter de una pyme casi siempre lleva un certificado que firma su propia
autoridad (la VMCA) o la de la empresa, y el equipo del agente no la conoce.
Desactivar la verificación sigue sin ser una salida: cualquiera en medio de la
red se quedaría con la contraseña del vCenter. La salida es la de SSH:

1. Si la verificación falla, el agente lee el certificado que le presentaron
   (sin mandar nada más) y lo cuenta: su huella SHA-256, quién lo emite y
   hasta cuándo vale (`describe`).
2. La persona lo ve en la web y decide confiar; el servidor devuelve la huella
   con la credencial (`tls_pin`).
3. Con huella, la conexión acepta **ese certificado y ningún otro**: se
   comprueba nada más terminar el saludo TLS, antes de mandar la petición, así
   que con otro certificado la contraseña no sale (`PinnedHTTPSHandler`).

Decidido el 08-10-2026. Para vCenter, Proxmox y XCP-ng (urllib); WinRM y
Hyper-V van por `requests` y siguen con la CA (`ca_file`).
"""

from __future__ import annotations

import hashlib
import http.client
import re
import socket
import ssl
import urllib.parse
import urllib.request
from typing import Any

PIN_RE = re.compile(r"^[0-9a-f]{64}$")
TIMEOUT_SECONDS = 10


class PinMismatch(ssl.SSLError):
    """El certificado presentado no es el de la huella guardada."""


def fingerprint(der: bytes) -> str:
    """SHA-256 del certificado en DER, en hexadecimal en minúsculas."""
    return hashlib.sha256(der).hexdigest()


def clean_pin(value: Any) -> str:
    """Una huella con forma (64 hexadecimales), o vacío. Admite los «:» de la pantalla."""
    text = str(value or "").strip().lower().replace(":", "")
    return text if PIN_RE.match(text) else ""


def _unverified_context() -> ssl.SSLContext:
    """Sin cadena ni nombre: lo que se comprueba es la huella, después del saludo."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args: Any, pin: str, **kwargs: Any) -> None:
        kwargs["context"] = _unverified_context()
        super().__init__(*args, **kwargs)
        self._pin = pin

    def connect(self) -> None:
        super().connect()
        der = self.sock.getpeercert(binary_form=True) or b""
        if fingerprint(der) != self._pin:
            self.sock.close()
            self.sock = None
            raise PinMismatch("el certificado no es el que se marcó como de confianza")


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    """Un `HTTPSHandler` que solo habla con el certificado de esa huella."""

    def __init__(self, pin: str) -> None:
        super().__init__(context=_unverified_context())
        self._pin = pin

    def https_open(self, req: urllib.request.Request) -> Any:
        pin = self._pin

        def connection(host: str, **kwargs: Any) -> PinnedHTTPSConnection:
            kwargs.pop("context", None)
            return PinnedHTTPSConnection(host, pin=pin, **kwargs)

        return self.do_open(connection, req)


def https_handler(ca_file: str = "", pin: str = "") -> urllib.request.HTTPSHandler:
    """El manejador HTTPS de un cliente: fijado si hay huella; si no, el de siempre."""
    if pin:
        return PinnedHTTPSHandler(pin)
    return urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file or None))


def is_untrusted(error: BaseException | None) -> bool:
    """El fallo es de confianza en el certificado (no de red ni de contraseña)."""
    seen = 0
    while error is not None and seen < 5:
        if isinstance(error, (ssl.SSLCertVerificationError, PinMismatch)):
            return True
        reason = getattr(error, "reason", None)
        if isinstance(reason, BaseException) and reason is not error:
            error = reason
        else:
            error = error.__cause__ or error.__context__
        seen += 1
    return False


def describe(url: str) -> dict[str, str] | None:
    """El certificado que presenta ese servidor: huella, sujeto, emisor y caducidad.

    Solo el saludo TLS, sin mandar ninguna petición. `None` si ni eso se puede.
    Sujeto, emisor y caducidad salen de `cryptography` si está (lo está en el
    agente completo, que la usa para los sobres); si no, solo la huella.
    """
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    if not host:
        return None
    port = parts.port or 443
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as raw:
            with _unverified_context().wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True) or b""
    except (OSError, ValueError):
        return None
    if not der:
        return None
    info = {"sha256": fingerprint(der), "subject": "", "issuer": "", "not_after": ""}
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
        info["subject"] = cert.subject.rfc4514_string()[:200]
        info["issuer"] = cert.issuer.rfc4514_string()[:200]
        after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        info["not_after"] = after.strftime("%Y-%m-%d")
    except Exception:  # noqa: BLE001 - sin cryptography, o un certificado raro: basta la huella
        pass
    return info
