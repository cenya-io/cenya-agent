"""The public halves of the keys that sign the agent's releases (spec, section 1).

The agent updates itself only to a release whose manifest (``latest.json``) is
signed by one of these keys: **with this list empty there is no automatic
update at all**, and the agent says so instead of trusting a download. A list,
not one key, so that a key can be rotated: the next version ships with the old
and the new key, the one after that with the new key only.

Each entry is either the PEM ``-----BEGIN PUBLIC KEY-----`` block or the raw
32-byte Ed25519 public key in standard base64 (the one-line form). An entry
that is not a valid Ed25519 public key is ignored, and ``cenya-agent selftest``
counts only the valid ones (``release_keys``), so a bad paste shows up there.

Cómo se genera el par (lo hace el dueño del repositorio, una vez, en su máquina,
nunca en CI ni en una conversación):

    python agent/packaging/release_key.py generate

Imprime dos cosas, y cada mitad va a un sitio distinto:

* **La privada** (PEM PKCS8) se pega entera como secreto del repositorio en
  GitHub, Settings → Secrets and variables → Actions, con el nombre
  ``CENYA_RELEASE_SIGNING_KEY``. No se guarda en ningún fichero ni en ningún
  otro sitio: si se pierde, se genera otra y se rota.
* **La pública** es una línea en base64 que se pega aquí abajo, en
  ``PUBLIC_KEYS``, y también en la configuración del servidor (que verifica lo
  mismo antes de servir un instalador).

Sin el secreto, el flujo de publicación publica sin firma y lo avisa; sin
ninguna clave aquí, los agentes no se actualizan solos.
"""

from __future__ import annotations

PUBLIC_KEYS: list[str] = [
    # "<44 caracteres en base64, terminados en =>",  <- la línea que imprime `release_key.py generate`
]
