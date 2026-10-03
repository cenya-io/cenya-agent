"""Sealed credentials: secrets the server keeps but cannot open (spec 3.1).

The browser encrypts every secret with **this agent's** public key (the one it
sent when it enrolled, `agent/identity.py`) before the secret ever reaches the
server. The server stores an *envelope* it cannot open; only this agent's
private key, ``identity.key`` in the protected state folder, opens it.

Hybrid encryption with what every browser ships (WebCrypto) and the
`cryptography` library here, and nothing hand-rolled:

1. A random AES-256 key ``K`` and a random 12-byte ``iv``.
2. ``ct`` = AES-256-GCM(``K``, ``iv``, plaintext, AAD), the 16-byte tag
   appended at the end (as WebCrypto and ``AESGCM`` return it).
3. ``ek`` = RSA-OAEP(SHA-256, MGF1-SHA-256, empty label) of ``K`` with the
   agent's public key.

    {"v": 1, "alg": "RSA-OAEP-256+A256GCM", "ek": "<b64>", "iv": "<b64>", "ct": "<b64>"}

Standard base64 with padding. The plaintext is UTF-8 JSON with only the secret
fields (``{"secret": "...", "priv_secret": "..."}``). The AAD ties the envelope
to its owner and to its credential, so it cannot be moved elsewhere::

    cenya-seal-v1|<agent uuid, lowercase with hyphens>|<credential id or order id>

Every byte-level choice is also written down in ``docs/sealing-test-vectors.json``
for the server's two implementations (WebCrypto and Python).

**Anything wrong is one exception, `SealError`, never a crash and never a
message with key material or plaintext in it.** Its `reason` is a short code
for tests and logs ("format", "version", "key", "open"...), not a sentence.

`cryptography` is optional, as for the identity key: without it sealing is
simply not available (`available()`), which is a capability the agent reports
in its `about`, not an error.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import threading
import uuid
from collections.abc import Mapping
from typing import Any

VERSION = 1
ALG = "RSA-OAEP-256+A256GCM"
AAD_PREFIX = "cenya-seal-v1"
IV_BYTES = 12
KEY_BYTES = 32
TAG_BYTES = 16
#: La clave más corta que se acepta para sellar (`seal_for`): la del agente es
#: de 3072 bits (spec 1.1), y re-sellar para una más débil rebajaría la
#: protección de todo lo que se mueva a ella.
MIN_RSA_BITS = 3072
#: La más larga: más allá es un PEM que alguien fabricó para hacer trabajar al
#: agente (una clave de 64 kbit tarda minutos en cada operación).
MAX_RSA_BITS = 8192
#: Topes antes de decodificar nada. Un sobre de verdad lleva unos cientos de
#: bytes; lo que pase de esto se rechaza sin tocarlo.
MAX_EK_CHARS = 4 * ((MAX_RSA_BITS // 8 + 2) // 3)
MAX_CT_BYTES = 64 * 1024
MAX_CT_CHARS = 4 * ((MAX_CT_BYTES + 2) // 3)
MAX_SUBJECT_CHARS = 200
MAX_PUBLIC_KEY_CHARS = 4000


class SealError(Exception):
    """An envelope that cannot be opened or made. Never carries key material or plaintext.

    `reason` es un código corto («format», «version», «open»...). El texto es
    siempre el mismo y no cita nada de lo que llegó: un sobre lo escribe otro,
    y repetir en un registro un trozo de lo que venía es justo lo que no puede
    pasar con un secreto.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(f"sealed credential refused ({reason})")
        self.reason = reason


def available() -> bool:
    """Whether this installation can seal and open at all: `cryptography` importable."""
    try:
        from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: F401
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except ImportError:
        return False
    return True


def aad(agent_uuid: str, subject_id: str) -> bytes:
    """La AAD exacta, en bytes UTF-8: ``cenya-seal-v1|<uuid>|<id>``."""
    return f"{AAD_PREFIX}|{canonical_uuid(agent_uuid)}|{_subject(subject_id)}".encode("utf-8")


def canonical_uuid(value: str) -> str:
    """El uuid del agente tal como va en la AAD: minúsculas y con guiones (36 caracteres).

    Django escribe los `UUIDField` así, y WebCrypto no normaliza nada: si un
    lado pusiera mayúsculas o quitara los guiones, la etiqueta no cuadraría y
    el sobre no abriría nunca. Se fija aquí y en el fichero de vectores.
    """
    if not isinstance(value, str) or not value.strip():
        raise SealError("agent")
    try:
        return str(uuid.UUID(value.strip()))
    except (ValueError, AttributeError, TypeError):
        raise SealError("agent") from None


def _subject(value: str) -> str:
    # El id de la credencial es opaco y va tal cual (sin recortar ni pasar a
    # minúsculas): lo pone el servidor y es el mismo texto que viaja en `id`.
    if not isinstance(value, str) or not value or len(value) > MAX_SUBJECT_CHARS:
        raise SealError("subject")
    return value


def _b64(value: Any, *, max_chars: int) -> bytes:
    """Base64 estándar con relleno, estricto: nada de espacios, de URL-safe ni de relleno que falte."""
    if not isinstance(value, str) or not value or len(value) > max_chars or len(value) % 4:
        raise SealError("format")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise SealError("format") from None


def _encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# --- Claves -----------------------------------------------------------------------


def load_public_key(pem: str):  # noqa: ANN201 - el tipo es de una librería opcional
    """A public key someone handed us (``reseal``), checked: RSA, 3072 to 8192 bits, well formed."""
    if not available():
        raise SealError("unavailable")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    if not isinstance(pem, str) or not pem.strip() or len(pem) > MAX_PUBLIC_KEY_CHARS:
        raise SealError("key")
    try:
        key = serialization.load_pem_public_key(pem.strip().encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError):
        raise SealError("key") from None
    except Exception:  # noqa: BLE001 - `UnsupportedAlgorithm` y compañía: una clave rara no tumba nada
        raise SealError("key") from None
    if not isinstance(key, rsa.RSAPublicKey):
        raise SealError("key")
    if not MIN_RSA_BITS <= key.key_size <= MAX_RSA_BITS:
        raise SealError("weak_key")
    if key.public_numbers().e != 65537:
        # Lo que generan WebCrypto, `cryptography` y OpenSSL. Un exponente
        # distinto no es inseguro por sí solo, pero nadie lo produce sin querer.
        raise SealError("key")
    return key


def _oaep():  # noqa: ANN202
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    # MGF1 con SHA-256 y sin etiqueta: es lo que hace WebCrypto con
    # {name: "RSA-OAEP", hash: "SHA-256"} y sin `label`.
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def own_private_key(environ: Mapping[str, str] | None = None):  # noqa: ANN201
    """This agent's private key (`agent/identity.py`), or `None` without one."""
    if not available():
        return None
    from agent import identity

    return identity.private_key(environ)


# --- Abrir y cerrar ------------------------------------------------------------------


def open_envelope(
    envelope: dict,
    *,
    agent_uuid: str,
    subject_id: str,
    private_key: Any = None,
    environ: Mapping[str, str] | None = None,
) -> dict:
    """The plaintext of an envelope sealed for this agent and this subject. `SealError` otherwise.

    `private_key` lets a caller that opens several envelopes load the key once
    (`agent.credentials.Unsealer`); without it, it is read from the state folder.
    """
    if not available():
        raise SealError("unavailable")
    if not isinstance(envelope, dict):
        raise SealError("format")
    version = envelope.get("v")
    # `True == 1` en Python: un `"v": true` no es la versión 1.
    if isinstance(version, bool) or version != VERSION:
        raise SealError("version")
    if envelope.get("alg") != ALG:
        raise SealError("alg")
    label = aad(agent_uuid, subject_id)
    key = private_key if private_key is not None else own_private_key(environ)
    if key is None:
        raise SealError("no_key")
    limits = (("ek", MAX_EK_CHARS), ("iv", 24), ("ct", MAX_CT_CHARS))
    # Primero los tamaños de los tres, después decodificar: algo enorme se
    # rechaza sin haber gastado nada en lo que venía antes.
    for name, limit in limits:
        value = envelope.get(name)
        if not isinstance(value, str) or not value or len(value) > limit:
            raise SealError("format")
    ek, iv, ct = (_b64(envelope.get(name), max_chars=limit) for name, limit in limits)
    if len(iv) != IV_BYTES or len(ek) != key.key_size // 8 or not TAG_BYTES <= len(ct) <= MAX_CT_BYTES + TAG_BYTES:
        raise SealError("format")

    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        content_key = key.decrypt(ek, _oaep())
    except Exception:  # noqa: BLE001 - `ValueError` de OAEP; cualquier otra cosa, igual: no abre
        raise SealError("open") from None
    if len(content_key) != KEY_BYTES:
        raise SealError("open")
    try:
        raw = AESGCM(content_key).decrypt(iv, ct, label)
    except InvalidTag:
        raise SealError("open") from None
    except Exception:  # noqa: BLE001
        raise SealError("open") from None
    finally:
        del content_key
    try:
        plaintext = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SealError("plaintext") from None
    if not isinstance(plaintext, dict) or not all(isinstance(name, str) for name in plaintext):
        raise SealError("plaintext")
    return plaintext


def seal_for(public_key_pem: str, plaintext: dict, *, agent_uuid: str, subject_id: str) -> dict:
    """An envelope only the holder of that public key, as that agent, can open for that subject."""
    key = load_public_key(public_key_pem)
    if not isinstance(plaintext, dict):
        raise SealError("plaintext")
    label = aad(agent_uuid, subject_id)
    try:
        raw = json.dumps(plaintext, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        raise SealError("plaintext") from None
    if len(raw) > MAX_CT_BYTES:
        raise SealError("plaintext")

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    content_key = AESGCM.generate_key(bit_length=KEY_BYTES * 8)
    iv = os.urandom(IV_BYTES)
    try:
        ct = AESGCM(content_key).encrypt(iv, raw, label)
        ek = key.encrypt(content_key, _oaep())
    finally:
        del content_key
    return {"v": VERSION, "alg": ALG, "ek": _encode(ek), "iv": _encode(iv), "ct": _encode(ct)}


# --- La prueba de que funciona -------------------------------------------------------

_SELF_TEST_UUID = "00000000-0000-4000-8000-000000000000"
_SELF_TEST_SUBJECT = "self-test"
_self_test_lock = threading.Lock()
_self_test_cache: dict[str, bool] = {}


def self_test(environ: Mapping[str, str] | None = None) -> bool:
    """`about.capabilities.sealed_credentials`: key on disk, library present, and a round trip that works.

    Sella con la propia clave pública y abre con la privada. Se recuerda por
    clave (el `about` se recalcula cada pocos minutos y una operación RSA no
    es gratis); una clave nueva vuelve a probarse. Nunca lanza.
    """
    try:
        if not available():
            return False
        from agent import identity

        key = identity.private_key(environ)
        if key is None:
            return False
        public = identity.public_pem(key)
        with _self_test_lock:
            if public in _self_test_cache:
                return _self_test_cache[public]
        probe = {"secret": base64.b64encode(os.urandom(18)).decode("ascii")}
        envelope = seal_for(public, probe, agent_uuid=_SELF_TEST_UUID, subject_id=_SELF_TEST_SUBJECT)
        opened = open_envelope(
            envelope, agent_uuid=_SELF_TEST_UUID, subject_id=_SELF_TEST_SUBJECT, private_key=key
        )
        ok = isinstance(opened.get("secret"), str) and hmac.compare_digest(
            opened["secret"].encode("utf-8"), probe["secret"].encode("utf-8")
        )
    except Exception:  # noqa: BLE001 - una capacidad que no funciona es `false`, no un fallo
        return False
    with _self_test_lock:
        _self_test_cache[public] = ok
    return ok
