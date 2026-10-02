"""The agent's own key pair: what will let the server seal credentials for it.

Protocol 2 sends a public key when the agent enrols (spec 1.1). In phase 3 the
server will use it to seal the discovery credentials so that only this agent
can open them; until then it only travels and is stored. The private half never
leaves the machine and lives next to the token, with the same protection
(`agent.store.write_protected`): readable only by SYSTEM, the Administrators
and whoever enrolled on Windows, ``0600`` on Linux.

RSA-3072 with the `cryptography` library (Apache-2.0 OR BSD-3-Clause), which is
an **optional** dependency: the plain ``pip install ./agent`` has none. Without
it there is no key, the enrolment goes without `public_key`, and the agent says
``sealed_credentials: false`` in its `about` -- the server keeps sending
credentials the protocol-1 way. Nothing here ever raises into the caller.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from pathlib import Path

from agent import store

FILE_NAME = "identity.key"
KEY_BITS = 3072
PUBLIC_EXPONENT = 65537

# Generar la clave cuesta un segundo largo; dos hilos que la pidieran a la vez
# la crearían dos veces y la segunda pisaría a la primera.
_LOCK = threading.Lock()


def available() -> bool:
    """Si esta instalación puede tener clave: `cryptography` importable."""
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: F401
    except ImportError:
        return False
    return True


def path(environ: Mapping[str, str] | None = None) -> Path:
    return store.state_dir(environ) / FILE_NAME


def _load_private(target: Path):  # noqa: ANN202 - el tipo es de una librería opcional
    """La clave guardada, o `None` si no hay, no se lee o no es RSA."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        return None
    try:
        key = serialization.load_pem_private_key(target.read_bytes(), password=None)
    except (OSError, ValueError, TypeError):
        return None
    return key if isinstance(key, rsa.RSAPrivateKey) else None


def _public_pem(key) -> str:  # noqa: ANN001
    from cryptography.hazmat.primitives import serialization

    return (
        key.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode("ascii")
    )


def public_key(environ: Mapping[str, str] | None = None) -> str:
    """The public key already on disk (PEM), or "" -- never creates one.

    What the running agent uses: creating a key is the enrolment's job, and a
    key nobody told the server about is no use to anyone.
    """
    if not available():
        return ""
    key = _load_private(path(environ))
    return _public_pem(key) if key is not None else ""


def ensure(environ: Mapping[str, str] | None = None) -> str:
    """The public key, creating and saving the pair the first time. "" if it cannot.

    A key that exists is reused, never replaced: the server may already have
    sealed something for it. A broken file is replaced (nothing can be opened
    with it anyway), and a key that cannot be *protected* is not written --
    the same rule as the token: better no key than one any user can read.
    """
    if not available():
        return ""
    with _LOCK:
        target = path(environ)
        key = _load_private(target)
        if key is not None:
            return _public_pem(key)
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import rsa

            key = rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=KEY_BITS)
            pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            store.write_protected(target, pem)
        except Exception:  # noqa: BLE001 - sin clave se enrola igual, como un agente 0.10
            return ""
        return _public_pem(key)
