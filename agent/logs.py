"""The agent's own log: ``logs/agent.log`` in the state folder (spec 2.6).

Until now what the agent said went to a console, to `docker logs` or, as a
Windows service, to the Event Viewer -- and nowhere a person could open with a
text editor or attach to a support ticket. This keeps the same human lines in a
file, rotated at 2 MB with four old copies (five files, 10 MB at most), so it
can run for years on a machine nobody watches.

**Never a secret.** Only what the loop already prints goes in, plus the task
lines of protocol 2; no token, credential or community is ever handed to these
functions. As a last net, anything that looks like ``Bearer <token>`` or a
``user:password@`` in a URL is masked before it is written.

Nothing here raises: a log that cannot be written (a read-only disk, a folder
the service cannot create) costs the log, never the agent.
"""

from __future__ import annotations

import logging
import logging.handlers
import re
import threading
from collections.abc import Mapping
from pathlib import Path

from agent import store

FOLDER = "logs"
FILE_NAME = "agent.log"
MAX_BYTES = 2 * 1024 * 1024
#: Cuatro copias viejas más la vigente: los cinco ficheros de la especificación.
BACKUP_COUNT = 4

LOGGER_NAME = "cenya.agent"

_BEARER = re.compile(r"(Bearer\s+)\S+", re.IGNORECASE)
_URL_CREDENTIALS = re.compile(r"(\w+://)[^/@\s:]+:[^/@\s]+@")
#: `usuario:clave@` también sin `://` delante: una URL mal escrita
#: (``https:/admin:S3cret@proxy:8080``) la trae así, y `urllib` la repite
#: entera en su error. La clave puede llevar barras; el usuario, no.
_BARE_CREDENTIALS = re.compile(r"(^|[\s'\"(=,;/\\])[^\s'\"@/:\\]+:(?!//)[^\s'\"@]+@")

_lock = threading.Lock()
_configured_for: Path | None = None


def path(environ: Mapping[str, str] | None = None) -> Path:
    return store.state_dir(environ) / FOLDER / FILE_NAME


def scrub(text: str) -> str:
    """Lo que nunca puede acabar en el registro, tapado por si alguien lo pasó."""
    text = _BEARER.sub(r"\1***", text)
    text = _URL_CREDENTIALS.sub(r"\1***@", text)
    return _BARE_CREDENTIALS.sub(r"\1***@", text)


def _logger() -> logging.Logger:
    logger = logging.getLogger(LOGGER_NAME)
    # Solo a su fichero: sin esto, un `logging.basicConfig` de quien importe
    # el agente lo repetiría todo por la consola, donde ya se imprimió.
    logger.propagate = False
    logger.setLevel(logging.INFO)
    return logger


def setup(environ: Mapping[str, str] | None = None) -> Path | None:
    """Abre (o reabre en otra carpeta) el fichero del registro. Nunca lanza.

    Devuelve la ruta, o `None` si no se pudo abrir: el agente sigue sin él.
    """
    global _configured_for
    target = path(environ)
    with _lock:
        logger = _logger()
        if _configured_for == target and logger.handlers:
            return target
        close()
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            handler = logging.handlers.RotatingFileHandler(
                target, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT, encoding="utf-8", delay=True
            )
        except Exception:  # noqa: BLE001 - sin registro, pero con agente
            return None
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
        _configured_for = target
        return target


def close() -> None:
    """Suelta el fichero (Windows no deja borrar uno abierto: tests, desinstalar)."""
    global _configured_for
    logger = _logger()
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # noqa: BLE001
            pass
    _configured_for = None


def info(text: str) -> None:
    _write(logging.INFO, text)


def error(text: str) -> None:
    _write(logging.ERROR, text)


def _write(level: int, text: str) -> None:
    try:
        logger = _logger()
        if logger.handlers:
            logger.log(level, scrub(str(text)))
    except Exception:  # noqa: BLE001 - el registro es una comodidad
        pass
