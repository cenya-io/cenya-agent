"""The release signing key and the manifest: what the owner runs once, and what CI runs per tag.

    python agent/packaging/release_key.py generate
        Genera un par Ed25519. La privada (PEM PKCS8) sale por la salida
        estándar UNA vez: se pega como secreto CENYA_RELEASE_SIGNING_KEY del
        repositorio y no se guarda en ningún otro sitio. La pública es una
        línea para agent/release_keys.py (y la configuración del servidor).
        Con --private-out/--public-out las escribe en ficheros: solo para la
        clave de PRUEBA que el flujo de CI genera y tira en cada ejecución.

    python agent/packaging/release_key.py sign <fichero>
        Firma los bytes exactos de <fichero> con la clave de la variable
        CENYA_RELEASE_SIGNING_KEY y deja <fichero>.sig (base64 estándar).

    python agent/packaging/release_key.py manifest --version 0.11.0 --base-url URL \
        [--windows EXE] [--linux TAR.GZ] [--install-sh SH] --out latest.json
        El manifiesto de docs/agente-v2-instalacion.md, sección 1.

    python agent/packaging/release_key.py embed-keys <install.sh> <salida> [--key LINEA ...]
        Copia install.sh con las claves públicas de agent/release_keys.py (y las
        --key) dentro, para que la primera instalación en Linux verifique.

    python agent/packaging/release_key.py verify <latest.json> <latest.json.sig> [--key LINEA ...]
        Lo mismo que hará el agente, con las mismas funciones (agent/release.py).

Solo biblioteca estándar y `cryptography`. Nunca imprime la clave privada salvo
en `generate` sin --private-out, que es justo para eso.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from agent import release  # noqa: E402

SECRET_VARIABLE = "CENYA_RELEASE_SIGNING_KEY"
#: La línea de install.sh que se sustituye por las claves.
KEYS_LINE = re.compile(r"^RELEASE_KEYS='[^'\n]*'$", re.M)


def _serialization():  # noqa: ANN202
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return serialization, Ed25519PrivateKey


def public_line(public_key) -> str:  # noqa: ANN001
    """The one-line form: the raw 32-byte Ed25519 public key in standard base64."""
    serialization, _ = _serialization()
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def generate(private_out: str = "", public_out: str = "") -> int:
    serialization, private_cls = _serialization()
    key = private_cls.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")
    line = public_line(key.public_key())
    if private_out:
        fd = os.open(private_out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as handle:
            handle.write(pem)
    else:
        print(f"# Clave PRIVADA: pégala entera como secreto {SECRET_VARIABLE} y no la guardes en ningún otro sitio.")
        print(pem, end="")
    if public_out:
        Path(public_out).write_text(line + "\n", encoding="ascii")
    else:
        print("# Clave PÚBLICA: esta línea va en agent/release_keys.py (PUBLIC_KEYS) y en el servidor.")
        print(line)
    return 0


def sign(path: str) -> int:
    serialization, private_cls = _serialization()
    pem = os.environ.get(SECRET_VARIABLE, "").strip()
    if not pem:
        print(f"Falta la variable {SECRET_VARIABLE}.", file=sys.stderr)
        return 2
    key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(key, private_cls):
        print(f"{SECRET_VARIABLE} no es una clave Ed25519.", file=sys.stderr)
        return 2
    data = Path(path).read_bytes()
    signature = base64.b64encode(key.sign(data)).decode("ascii")
    Path(path + ".sig").write_text(signature, encoding="ascii")
    print(f"Firmado: {path}.sig (clave pública {public_line(key.public_key())})")
    return 0


def _entry(path: str, url: str) -> dict:
    data = Path(path).read_bytes()
    return {"url": url, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}


def manifest(args: argparse.Namespace) -> int:
    base = args.base_url.rstrip("/")
    files: dict[str, dict] = {}
    for key, path in (("windows", args.windows), ("linux", args.linux), ("install.sh", args.install_sh)):
        if path:
            files[key] = _entry(path, f"{base}/{Path(path).name}")
    released = args.released or datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    data: dict = {"version": args.version, "released": released}
    if "windows" in files:
        # Lo de primer nivel se conserva: lo leen quienes ya lo leían.
        data["url"], data["sha256"] = files["windows"]["url"], files["windows"]["sha256"]
    data["files"] = files
    # Que lo que se publica lo acepte el mismo lector que usará el agente.
    release.parse_manifest(data)
    Path(args.out).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Manifiesto: {args.out} ({', '.join(files) or 'sin ficheros'})")
    return 0


def _keys(extra: list[str] | None) -> list[str]:
    from agent.release_keys import PUBLIC_KEYS

    return [*PUBLIC_KEYS, *(extra or [])]


def embed_keys(source: str, out: str, extra: list[str] | None) -> int:
    lines: list[str] = []
    try:
        lines = [public_line(key) for key in release.load_public_keys(_keys(extra))]
    except release.ReleaseError as exc:
        if exc.code != release.NO_KEYS:
            raise
    text = Path(source).read_text(encoding="utf-8")
    if not KEYS_LINE.search(text):
        print(f"{source} no tiene la línea RELEASE_KEYS='' que sustituir.", file=sys.stderr)
        return 2
    # Base64 estándar: letras, cifras, + / =. Nada que pueda romper la comilla.
    replaced = KEYS_LINE.sub(lambda _m: f"RELEASE_KEYS='{' '.join(lines)}'", text, count=1)
    with open(out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(replaced)
    print(f"{out}: {len(lines)} clave(s) pública(s) dentro.")
    return 0


def verify(manifest_path: str, signature_path: str, extra: list[str] | None) -> int:
    try:
        data = release.verify_manifest(
            Path(manifest_path).read_bytes(), Path(signature_path).read_bytes(), _keys(extra)
        )
    except release.ReleaseError as exc:
        print(f"NO verifica: {exc.code} ({exc.detail})", file=sys.stderr)
        return 1
    print(f"Verifica: versión {data['version']}, ficheros {', '.join(data['files'])}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate")
    gen.add_argument("--private-out", default="")
    gen.add_argument("--public-out", default="")
    sig = sub.add_parser("sign")
    sig.add_argument("file")
    man = sub.add_parser("manifest")
    man.add_argument("--version", required=True)
    man.add_argument("--base-url", required=True)
    man.add_argument("--released", default="")
    man.add_argument("--windows", default="")
    man.add_argument("--linux", default="")
    man.add_argument("--install-sh", default="")
    man.add_argument("--out", required=True)
    emb = sub.add_parser("embed-keys")
    emb.add_argument("source")
    emb.add_argument("out")
    emb.add_argument("--key", action="append")
    ver = sub.add_parser("verify")
    ver.add_argument("manifest")
    ver.add_argument("signature")
    ver.add_argument("--key", action="append")
    args = parser.parse_args(argv)
    if args.command == "generate":
        return generate(args.private_out, args.public_out)
    if args.command == "sign":
        return sign(args.file)
    if args.command == "manifest":
        return manifest(args)
    if args.command == "embed-keys":
        return embed_keys(args.source, args.out, args.key)
    return verify(args.manifest, args.signature, args.key)


if __name__ == "__main__":
    raise SystemExit(main())
