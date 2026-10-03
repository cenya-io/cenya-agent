"""Local settings: what the person at the agent's machine decides (spec 2.6).

Everything else comes from the server. These are the few things that belong to
the machine and its network rather than to the inventory: how to get out to
the internet (a proxy, a company CA), which addresses nobody touches, how hard
the agent may push, a pause. They live in ``settings.json`` in the state
folder, every field optional.

Three rules:

* **A broken file is the defaults, never a crash.** Field by field: a wrong
  value in one field does not throw away the others.
* **``CENYA_*`` variables win over the file**, as everywhere else in the agent
  (``NETINVENTORY_*`` too, where no ``CENYA_*`` is set): a container or a
  script configures the agent from its environment.
* **Saved atomically and protected** like the token (`agent.store`): a proxy
  URL may carry a password.
"""

from __future__ import annotations

import ipaddress
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent import store
from agent.config import setting

FILE_NAME = "settings.json"

PROXY_MODES = ("system", "manual", "none")
GENTLENESS_LEVELS = ("gentle", "normal", "fast")

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}

#: Una pausa local «hasta que la reanude» (spec 4, `pause` con `indefinite`).
#: Dentro del agente es una fecha más (la más lejana que se puede escribir),
#: para que comparar y elegir la más tardía de dos pausas siga siendo comparar
#: fechas; en `settings.json`, en el checkin y en el canal se escribe como lo
#: que es: ``"indefinite"`` / ``indefinite: true``, nunca como el año 9999.
PAUSE_INDEFINITE = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
INDEFINITE = "indefinite"


def is_indefinite(moment: datetime | None) -> bool:
    return moment is not None and moment >= PAUSE_INDEFINITE


def pause_text(moment: datetime | None) -> str | None:
    """Cómo se guarda una pausa: ISO, ``"indefinite"`` o `None`."""
    if moment is None:
        return None
    return INDEFINITE if is_indefinite(moment) else moment.isoformat()


@dataclass(frozen=True)
class Settings:
    language: str = ""
    ca_bundle: str = ""
    proxy_mode: str = "system"
    #: Puede llevar usuario y contraseña: nunca se imprime ni va en el `about`.
    proxy_url: str = ""
    excluded_subnets: tuple[str, ...] = ()
    excluded_addresses: tuple[str, ...] = ()
    #: «gentle» o «normal» bajan la suavidad que diga el servidor; vacío, nada.
    gentleness_cap: str = ""
    auto_update: bool = True
    notifications: bool = True
    #: La pausa local, puesta en esta máquina (spec 1.2). `None`: sin pausa.
    paused_until: datetime | None = None
    extra: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @property
    def proxy(self) -> tuple[str, str] | None:
        """Lo que entiende `AgentClient(proxy=...)`: `None` es el del sistema."""
        if self.proxy_mode == "none":
            return ("none", "")
        if self.proxy_mode == "manual" and self.proxy_url:
            return ("manual", self.proxy_url)
        return None

    def as_json(self) -> dict[str, Any]:
        return {
            **self.extra,
            "language": self.language,
            "ca_bundle": self.ca_bundle,
            "proxy": {"mode": self.proxy_mode, "url": self.proxy_url},
            "excluded": {"subnets": list(self.excluded_subnets), "addresses": list(self.excluded_addresses)},
            "gentleness_cap": self.gentleness_cap,
            "auto_update": self.auto_update,
            "notifications": self.notifications,
            "paused_until": pause_text(self.paused_until),
        }


def path(environ: Mapping[str, str] | None = None) -> Path:
    return store.state_dir(environ) / FILE_NAME


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _flag(value: object, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in _TRUE:
            return True
        if lowered in _FALSE:
            return False
    return default


def _networks(values: object) -> tuple[str, ...]:
    """Las subredes que se entienden; lo que no es una red se descarta."""
    if isinstance(values, str):
        values = values.replace("\n", ",").split(",")
    if not isinstance(values, list | tuple):
        return ()
    kept: list[str] = []
    for value in values:
        try:
            kept.append(str(ipaddress.ip_network(str(value).strip(), strict=False)))
        except ValueError:
            continue
    return tuple(kept)


def _addresses(values: object) -> tuple[str, ...]:
    if isinstance(values, str):
        values = values.replace("\n", ",").split(",")
    if not isinstance(values, list | tuple):
        return ()
    kept: list[str] = []
    for value in values:
        try:
            kept.append(str(ipaddress.ip_address(str(value).strip())))
        except ValueError:
            continue
    return tuple(kept)


def _moment(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    if value.strip().lower() == INDEFINITE:
        return PAUSE_INDEFINITE
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _proxy(value: object) -> tuple[str, str]:
    if not isinstance(value, dict):
        return "system", ""
    mode = _text(value.get("mode")).lower()
    url = _text(value.get("url"))
    if mode not in PROXY_MODES:
        mode = "system"
    return mode, url


def from_json(data: object) -> Settings:
    """Lo que se entienda de `data`; lo demás, su valor por defecto."""
    if not isinstance(data, dict):
        return Settings()
    excluded = data.get("excluded") if isinstance(data.get("excluded"), dict) else {}
    mode, url = _proxy(data.get("proxy"))
    cap = _text(data.get("gentleness_cap")).lower()
    known = {"language", "ca_bundle", "proxy", "excluded", "gentleness_cap", "auto_update", "notifications", "paused_until"}
    return Settings(
        language=_text(data.get("language")),
        ca_bundle=_text(data.get("ca_bundle")),
        proxy_mode=mode,
        proxy_url=url,
        excluded_subnets=_networks(excluded.get("subnets")),
        excluded_addresses=_addresses(excluded.get("addresses")),
        gentleness_cap=cap if cap in GENTLENESS_LEVELS else "",
        auto_update=_flag(data.get("auto_update"), True),
        notifications=_flag(data.get("notifications"), True),
        paused_until=_moment(data.get("paused_until")),
        # Lo que escriba una versión más nueva se conserva al guardar.
        extra={key: value for key, value in data.items() if key not in known},
    )


def _from_environment(base: Settings, env: Mapping[str, str]) -> Settings:
    """Las variables `CENYA_*` que haya, por encima del fichero."""
    changes: dict[str, Any] = {}
    if language := setting(env, "LANGUAGE"):
        changes["language"] = language
    if ca_bundle := setting(env, "CA_BUNDLE"):
        changes["ca_bundle"] = ca_bundle
    if proxy := setting(env, "PROXY"):
        # `system`, `none` o la URL del proxy, que es el modo manual.
        lowered = proxy.lower()
        if lowered in ("system", "none"):
            changes.update(proxy_mode=lowered, proxy_url="")
        else:
            changes.update(proxy_mode="manual", proxy_url=proxy)
    if subnets := setting(env, "EXCLUDED_SUBNETS"):
        changes["excluded_subnets"] = _networks(subnets)
    if addresses := setting(env, "EXCLUDED_ADDRESSES"):
        changes["excluded_addresses"] = _addresses(addresses)
    if (cap := setting(env, "GENTLENESS_CAP").lower()) in GENTLENESS_LEVELS:
        changes["gentleness_cap"] = cap
    if auto_update := setting(env, "AUTO_UPDATE"):
        changes["auto_update"] = _flag(auto_update, base.auto_update)
    if notifications := setting(env, "NOTIFICATIONS"):
        changes["notifications"] = _flag(notifications, base.notifications)
    return replace(base, **changes) if changes else base


def load_file(environ: Mapping[str, str] | None = None) -> Settings:
    """Solo el fichero, sin el entorno: lo que hay que reescribir al guardar."""
    try:
        data = json.loads(path(environ).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return Settings()
    return from_json(data)


def load(environ: Mapping[str, str] | None = None) -> Settings:
    """Los ajustes vigentes: el fichero y, por encima, el entorno. Nunca lanza."""
    env = os.environ if environ is None else environ
    try:
        return _from_environment(load_file(env), env)
    except Exception:  # noqa: BLE001 - unos ajustes rotos son los de por defecto
        return Settings()


def save(settings: Settings, environ: Mapping[str, str] | None = None) -> bool:
    """Guarda los ajustes de golpe y protegidos. `False` si no se pudo; nunca lanza.

    Ojo con guardar lo que devuelve `load`: llevaría dentro las variables de
    entorno, que pasarían a ser del fichero. Para cambiar un campo se parte de
    `load_file`.
    """
    try:
        store.write_protected(path(environ), json.dumps(settings.as_json(), ensure_ascii=False, indent=1))
    except Exception:  # noqa: BLE001
        return False
    return True
