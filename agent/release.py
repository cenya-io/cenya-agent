"""Signed releases: the manifest, its signature, and the files it names (spec, section 1).

Verifying is always the same three steps, in this order, and nothing skips one:

1. **The signature of the manifest** (``latest.json``), Ed25519 over its exact
   bytes, by one of the keys in `agent.release_keys`. Nothing in the manifest is
   even parsed before that: an unsigned text is not data, it is noise.
2. **The manifest says the hash** (and the size) of each file.
3. **The downloaded file matches that hash.** A hash on its own proves nothing:
   whoever changes the file changes the hash next to it.

Ed25519 needs the optional ``cryptography`` library (already in the
``windows`` and ``completo`` extras, so in the Windows installer and in what
``install.sh`` installs). Without it, or without any key configured, every
verification **fails closed** with its code (`NO_CRYPTO`, `NO_KEYS`): no
update, said plainly, never an update on trust.

This is the one module that knows how; the updater (`agent.update`), the
Linux root helper and the release tooling (``packaging/release_key.py``) all
call it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

#: Un manifiesto son unos cientos de bytes; esto es para no leer un disparate.
MAX_MANIFEST_BYTES = 64 * 1024
#: Una firma Ed25519 son 64 bytes: 88 caracteres en base64.
MAX_SIGNATURE_BYTES = 1024
#: El tope de cualquier fichero de una versión. El instalador de Windows ronda
#: los 30 MB; el doble de holgura de sobra, y una descarga nunca llena el disco.
MAX_FILE_BYTES = 300 * 1024 * 1024

#: «0.11.0», o hasta cuatro números (las compilaciones de prueba de CI llevan un
#: cuarto). Solo cifras y puntos: una versión acaba dentro de un nombre de
#: fichero (`agent.update.download_name`) y nunca puede traer una barra.
#: `\Z` y no `$`: `$` acepta un salto de línea final, y «0.11.1\n» acabaría
#: dentro de un nombre de fichero.
VERSION_RE = re.compile(r"^\d{1,6}(\.\d{1,6}){1,3}\Z")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}\Z")

#: Los ficheros que puede nombrar un manifiesto (`files`).
FILE_KEYS = ("windows", "linux", "install.sh")

#: Códigos (nota `update` / código): los lee el servidor y los traduce la web.
BAD_SIGNATURE = "bad_signature"
BAD_HASH = "bad_hash"
BAD_MANIFEST = "bad_manifest"
NO_KEYS = "no_keys"
NO_CRYPTO = "no_crypto"


class ReleaseError(Exception):
    """A release that cannot be trusted. `code` is one of the codes above."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _crypto() -> Any:
    """The pieces of `cryptography` this needs, or `NO_CRYPTO`."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise ReleaseError(NO_CRYPTO, "cryptography no está instalada") from exc
    return InvalidSignature, serialization, Ed25519PublicKey


def load_public_keys(keys: Iterable[str]) -> list[Any]:
    """The valid Ed25519 public keys among `keys` (PEM, base64 DER or raw base64).

    Una entrada que no es una clave Ed25519 válida se salta: una mal pegada no
    puede desactivar las buenas. Sin ninguna válida, `NO_KEYS`.
    """
    _invalid, serialization, ed25519_public_key = _crypto()
    parsed: list[Any] = []
    for entry in keys:
        text = str(entry or "").strip()
        if not text:
            continue
        try:
            if "BEGIN PUBLIC KEY" in text:
                key = serialization.load_pem_public_key(text.encode("ascii"))
            else:
                raw = base64.b64decode(text, validate=True)
                key = (
                    ed25519_public_key.from_public_bytes(raw)
                    if len(raw) == 32
                    else serialization.load_der_public_key(raw)
                )
        except (ValueError, TypeError, binascii.Error, UnicodeEncodeError):
            continue
        if isinstance(key, ed25519_public_key):
            parsed.append(key)
    if not parsed:
        raise ReleaseError(NO_KEYS, "no hay ninguna clave pública de publicación configurada")
    return parsed


def key_fingerprint(key: Any) -> str:
    """A short, stable name for a public key: the start of the SHA-256 of its raw bytes."""
    _invalid, serialization, _cls = _crypto()
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def allowed_url(url: object) -> bool:
    """HTTPS anywhere; plain HTTP only to this same machine (the CI stub, a test).

    El manifiesto está firmado, así que esto no es lo que protege el contenido:
    es que una descarga del agente no salga nunca en claro por la red.
    """
    if not isinstance(url, str) or not url or any(char.isspace() for char in url):
        return False
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        return False
    if parts.scheme == "https" and host:
        return True
    return parts.scheme == "http" and (host == "localhost" or host == "::1" or host.startswith("127."))


def _file_entry(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseError(BAD_MANIFEST, "una entrada de files no es un objeto")
    url, sha256, size = value.get("url"), value.get("sha256"), value.get("size")
    if not allowed_url(url):
        raise ReleaseError(BAD_MANIFEST, "una URL del manifiesto no es https")
    if not isinstance(sha256, str) or not _SHA256_RE.match(sha256):
        raise ReleaseError(BAD_MANIFEST, "una huella del manifiesto no es un SHA-256")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_FILE_BYTES:
        raise ReleaseError(BAD_MANIFEST, "un tamaño del manifiesto no es válido")
    return {"url": url, "sha256": sha256, "size": size}


def parse_manifest(data: object) -> dict[str, Any]:
    """The manifest, checked field by field. Only call it on bytes already verified."""
    if not isinstance(data, dict):
        raise ReleaseError(BAD_MANIFEST, "el manifiesto no es un objeto JSON")
    version = data.get("version")
    if not isinstance(version, str) or not VERSION_RE.match(version):
        raise ReleaseError(BAD_MANIFEST, "la versión del manifiesto no es válida")
    raw_files = data.get("files")
    if not isinstance(raw_files, dict):
        raise ReleaseError(BAD_MANIFEST, "el manifiesto no trae files")
    files = {name: _file_entry(raw_files[name]) for name in FILE_KEYS if name in raw_files}
    return {
        "version": version,
        "released": str(data.get("released") or ""),
        "url": str(data.get("url") or ""),
        "sha256": str(data.get("sha256") or ""),
        "files": files,
    }


def _signature(signature_b64: str | bytes) -> bytes:
    text = signature_b64.decode("ascii", "replace") if isinstance(signature_b64, bytes) else str(signature_b64)
    if len(text) > MAX_SIGNATURE_BYTES:
        raise ReleaseError(BAD_SIGNATURE, "la firma es demasiado larga")
    try:
        signature = base64.b64decode("".join(text.split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ReleaseError(BAD_SIGNATURE, "la firma no es base64") from exc
    if len(signature) != 64:
        raise ReleaseError(BAD_SIGNATURE, "la firma no tiene el tamaño de una firma Ed25519")
    return signature


def verify_manifest(manifest_bytes: bytes, signature_b64: str | bytes, keys: Iterable[str]) -> dict[str, Any]:
    """Check the signature of `manifest_bytes` with `keys`, then parse it. Raises `ReleaseError`.

    Primero las claves (sin ninguna no hay nada que hacer), después la firma
    sobre los bytes exactos, y solo entonces se lee el JSON.
    """
    invalid_signature, _serialization, _cls = _crypto()
    public_keys = load_public_keys(keys)
    if not isinstance(manifest_bytes, bytes) or len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise ReleaseError(BAD_MANIFEST, "el manifiesto es demasiado grande")
    signature = _signature(signature_b64)
    for key in public_keys:
        try:
            key.verify(signature, manifest_bytes)
        except invalid_signature:
            continue
        break
    else:
        raise ReleaseError(BAD_SIGNATURE, "la firma no es de ninguna clave conocida")
    try:
        data = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReleaseError(BAD_MANIFEST, "el manifiesto no es JSON") from exc
    return parse_manifest(data)


def file_entry(manifest: dict[str, Any], name: str) -> dict[str, Any]:
    """The `files[name]` entry of a verified manifest, or `BAD_MANIFEST`."""
    entry = (manifest.get("files") or {}).get(name)
    if not isinstance(entry, dict):
        raise ReleaseError(BAD_MANIFEST, f"el manifiesto no trae el fichero {name}")
    return entry


def sha256_file(path: Path, max_bytes: int = MAX_FILE_BYTES) -> tuple[str, int]:
    """The SHA-256 (hex) and size of a file, read in pieces, never past `max_bytes` + 1."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                break
            digest.update(chunk)
    return digest.hexdigest(), size


def verify_file(path: Path, entry: dict[str, Any]) -> None:
    """Raise `BAD_HASH` unless `path` has exactly the size and SHA-256 of `entry`."""
    expected_size = int(entry["size"])
    digest, size = sha256_file(path, expected_size)
    if size != expected_size or not hmac.compare_digest(digest, str(entry["sha256"])):
        raise ReleaseError(BAD_HASH, "el fichero no coincide con el manifiesto")
