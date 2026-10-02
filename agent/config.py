"""Configuration, from the environment and what enrolment saved.

The agent is configured where it runs. The token comes from the environment
(``CENYA_AGENT_TOKEN``) or, normally, from the protected store that enrolment
filled (`agent.store`): nobody copies it. Everything else is an optional
variable. ``NETINVENTORY_*`` -- the names before the product was called Cenya --
are still read wherever a ``CENYA_*`` one is not set, so an agent installed
earlier keeps working untouched.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from agent import store
from agent.i18n import _t

DEFAULT_URL = "http://localhost:8000"
DEFAULT_INTERVAL_SECONDS = 900


def setting(env: Any, name: str, default: str = "") -> str:
    """``CENYA_<name>``, else the older ``NETINVENTORY_<name>``, else `default`."""
    for prefix in ("CENYA_", "NETINVENTORY_"):
        value = str(env.get(prefix + name, "") or "").strip()
        if value:
            return value
    return default


def _is_local_host(host: str) -> bool:
    return host == "localhost" or host == "::1" or host.startswith("127.")


def check_transport(url: str, env: dict[str, str]) -> None:
    """Refuse plain HTTP to anywhere that is not this same machine.

    The heartbeat carries the organization's discovery credentials decrypted;
    over http:// they would cross the network in the clear. Localhost is fine
    (development, or an agent on the server itself), and a deliberate
    CENYA_INSECURE_HTTP=1 exists for tests -- but it has to be said,
    never stumbled into.
    """
    parts = urlsplit(url)
    if parts.scheme != "http" or _is_local_host(parts.hostname or ""):
        return
    if setting(env, "INSECURE_HTTP").lower() in {"1", "true", "yes", "on"}:
        return
    raise SystemExit(
        _t(
            "La dirección del portal es http:// hacia %(host)s: el latido lleva "
            "las credenciales de descubrimiento y viajarían en claro. Usa https:// "
            "(con CENYA_CA_BUNDLE si el certificado es propio) o, solo para "
            "pruebas, CENYA_INSECURE_HTTP=1."
        )
        % {"host": parts.hostname}
    )


@dataclass(frozen=True)
class Config:
    url: str
    token: str
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS
    # Environment overrides for what the server would otherwise dictate in the
    # heartbeat: useful for standalone runs and tests.
    subnets: tuple[str, ...] = ()
    communities: tuple[str, ...] = ()
    #: Juegos de credenciales para SSH, WinRM y los hipervisores, en el mismo
    #: formato en que los manda el servidor. Solo para pruebas standalone: en un
    #: despliegue de verdad se escriben en Ajustes y viajan cifradas hasta el
    #: latido, que es lo que evita que acaben en el `docker-compose.yml` de la
    #: empresa y de ahí en su repositorio.
    credentials: tuple[dict[str, Any], ...] = ()
    #: Un certificado propio de la empresa, para cuando `url` es HTTPS con un
    #: certificado autofirmado -- lo normal en la red de una pyme. Sin esto la
    #: única salida era desactivar la verificación de TLS entera, que es
    #: exactamente lo que no se quiere hacer nunca.
    ca_bundle: str = ""
    #: Guardar copia de la configuración de los equipos de red por SSH. Lo
    #: normal es decidirlo en Ajustes (viaja en el latido); esto es el valor
    #: para ejecuciones standalone y el respaldo si el servidor no dice nada.
    capture_configs: bool = True


def _list(raw: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in raw.replace("\n", ",").split(",") if part.strip())


def _credentials(raw: str) -> tuple[dict[str, Any], ...]:
    """La lista JSON de la variable de entorno, o nada.

    Un JSON mal escrito **no puede tumbar el arranque**: el agente se queda sin
    esas credenciales y los colectores que las necesitan lo dicen en su línea de
    error, que es lo mismo que pasa cuando no hay ninguna configurada. Morir
    aquí dejaría sin barrido también al ping y al SNMP, que no tienen la culpa.
    """
    raw = raw.strip()
    if not raw:
        return ()
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return ()
    if not isinstance(parsed, list):
        return ()
    return tuple(item for item in parsed if isinstance(item, dict))


def from_env(environ: dict[str, str] | None = None) -> Config:
    env = os.environ if environ is None else environ
    token = setting(env, "AGENT_TOKEN")
    url = setting(env, "URL")
    if not token:
        # Lo que dejó el enrolamiento. La URL de la entorno, si la hay, manda
        # (un portal que cambió de dirección no obliga a enrolar de nuevo).
        enrolled = store.load(env)
        if enrolled is not None:
            token = enrolled.token
            url = url or enrolled.url
    if not token and store.untrusted_enrollment(env):
        # Lo apartó `store.secure_state_dir`: estaba en una carpeta donde
        # cualquier usuario podía escribir, así que no se sabe de quién es.
        raise SystemExit(
            _t(
                "El enrolamiento de este agente estaba en una carpeta sin proteger (%(path)s) y no "
                "es de fiar: se ha apartado sin usarlo. Enrola el equipo de nuevo: "
                "cenya-agent enroll <cadena> --force"
            )
            % {"path": store.state_dir(env)}
        )
    if not token:
        raise SystemExit(
            _t(
                "Este agente no está enrolado. En Ajustes → Agentes genera una cadena de "
                "conexión y ejecuta: cenya-agent enroll <cadena>"
            )
        )
    try:
        interval = int(setting(env, "INTERVAL", str(DEFAULT_INTERVAL_SECONDS)))
    except ValueError:
        interval = DEFAULT_INTERVAL_SECONDS
    url = (url or DEFAULT_URL).rstrip("/")
    check_transport(url, dict(env))
    return Config(
        url=url,
        token=token,
        interval_seconds=interval,
        subnets=_list(setting(env, "SUBNETS")),
        communities=_list(setting(env, "SNMP_COMMUNITIES")),
        credentials=_credentials(setting(env, "CREDENTIALS")),
        ca_bundle=setting(env, "CA_BUNDLE"),
        capture_configs=setting(env, "CAPTURE_CONFIGS").lower() not in {"0", "false", "no", "off"},
    )
