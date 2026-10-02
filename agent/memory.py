"""What the agent remembers between tasks, and what it must never touch.

Two small things, both local to the machine the agent runs on:

* ``Memory`` -- which hosts it has seen, which of them are UPSes or network
  devices worth a config copy, and **which credential worked where**. It
  exists so the agent stops knocking on every door with every key every few
  minutes: today that is noise in the customer's auth logs and, against an
  Active Directory, locked accounts.
* ``Excluded`` -- addresses a person on that machine said are off limits.

La memoria es **prescindible**. Si el fichero falta o está roto se empieza de
cero y no pasa nada peor que una ronda de credenciales de más; por eso aquí
nada lanza nunca, ni al leer ni al escribir. Y **no guarda secretos**: de una
credencial solo su `ident` (el `id` del servidor, o uno derivado que no sale
del secreto). Una comunidad SNMP se recuerda por su número, nunca por su valor.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from agent import store
from agent.credentials import Credential

#: Un equipo que no se ve en este tiempo se olvida.
FORGET_AFTER = timedelta(days=30)
#: Tras una ronda completa fallida contra un equipo y protocolo, solo se vuelve
#: a probar la credencial recordada hasta que pase esto. Un día: lo bastante
#: para no sumar intentos fallidos cada pocos minutos, lo bastante corto para
#: que un equipo nuevo con credencial nueva no espere una semana.
ROUND_COOLDOWN = timedelta(hours=24)

# --- El cortacircuitos de credenciales (spec 2.3) --------------------------------
#
# La memoria por equipo no basta contra un dominio: UNA credencial equivocada
# probada contra cincuenta Windows son cincuenta inicios de sesión fallidos de
# la misma cuenta en un solo inventario, y el Directorio Activo la bloquea. Este
# límite es global, por credencial (`ident`, nunca el secreto).

#: Intentos fallidos en total, entre todos los equipos, que se le consienten a
#: una credencial que nunca ha entrado («sin probar») antes de suspenderla.
UNPROVEN_FAILURES = 3
#: Equipos distintos donde una credencial que ya entró (y era la recordada)
#: falla antes de suspenderla: lo probable es que le hayan cambiado la clave.
CHANGED_PASSWORD_HOSTS = 3
#: Cuánto dura una suspensión si nadie toca las credenciales.
SUSPENSION = timedelta(hours=24)
#: Una credencial que entró hace menos de esto no se frena en los equipos donde
#: es la recordada. Pasado este tiempo, mientras no vuelva a entrar, solo
#: `CHANGED_PASSWORD_HOSTS` intentos a la vez en esos equipos: si le cambiaron
#: la clave, no hay diez fallos en vuelo cuando llega el tercero.
PROVEN_TRUST = timedelta(hours=1)
#: Lo más que un hilo espera su turno antes de dejarlo (y saltarse esa
#: credencial en ese equipo). Cada intento tiene su propio tope de tiempo, así
#: que esperar más de esto es que algo va muy mal.
MAX_WAIT_SECONDS = 300.0

#: Cómo acabó un intento de entrar (`Memory.finish`).
OK = "ok"
AUTH_FAILED = "auth_failed"
UNREACHABLE = "unreachable"

VERSION = 1


def _utc(moment: datetime) -> datetime:
    """Una fecha con zona. Una sin zona se toma por UTC: comparar las dos
    clases lanza `TypeError`, y eso aquí no puede pasar."""
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def _iso(moment: datetime) -> str:
    return _utc(moment).isoformat()


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return _utc(datetime.fromisoformat(value))
    except ValueError:
        return None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _mac(value: str | None) -> str:
    return (value or "").strip().lower().replace("-", ":")


def _text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _blank() -> dict[str, Any]:
    return {
        "ip": "",
        "mac": "",
        "last_seen": "",
        "ups": False,
        "identity_mac": "",
        "config_family": "",
        "creds": {},
    }


def _clean_entry(raw: Any) -> dict[str, Any] | None:
    """Una entrada leída del disco, con cada campo de su tipo o vacío.

    El fichero lo puede haber tocado cualquiera (o una versión futura del
    agente): una entrada rara se arregla o se tira, nunca revienta la carga.
    """
    if not isinstance(raw, dict):
        return None
    entry = _blank()
    entry["ip"] = _text(raw.get("ip"))
    entry["mac"] = _mac(_text(raw.get("mac")))
    entry["last_seen"] = _text(raw.get("last_seen"))
    entry["ups"] = raw.get("ups") is True
    entry["identity_mac"] = _mac(_text(raw.get("identity_mac")))
    entry["config_family"] = _text(raw.get("config_family"))
    creds = raw.get("creds")
    if isinstance(creds, dict):
        for protocol, record in creds.items():
            if isinstance(protocol, str) and isinstance(record, dict):
                entry["creds"][protocol] = {
                    "ok": _text(record.get("ok")),
                    "ok_at": _text(record.get("ok_at")),
                    "failed_at": _text(record.get("failed_at")),
                }
    return entry


def _blank_credential() -> dict[str, Any]:
    return {"proven": False, "failures": 0, "hosts": [], "suspended_at": "", "ok_at": "", "seen_at": ""}


def _clean_credential(raw: Any) -> dict[str, Any] | None:
    """Un registro del cortacircuitos leído del disco; lo raro, fuera."""
    if not isinstance(raw, dict):
        return None
    record = _blank_credential()
    record["proven"] = raw.get("proven") is True
    failures = raw.get("failures")
    record["failures"] = failures if isinstance(failures, int) and not isinstance(failures, bool) and failures > 0 else 0
    hosts = raw.get("hosts")
    record["hosts"] = sorted({h for h in hosts if isinstance(h, str) and h}) if isinstance(hosts, list) else []
    for name in ("suspended_at", "ok_at", "seen_at"):
        record[name] = _text(raw.get(name)) if _parse(raw.get(name)) else ""
    return record


@dataclass
class Attempt:
    """Un intento de entrar reservado con `Memory.reserve`: se cierra con `finish`."""

    ident: str
    host_key: str
    remembered: bool
    explicit: bool
    #: Ocupa uno de los intentos de una credencial sin probar.
    budget: bool = False
    #: Ocupa uno de los intentos a la vez en equipos donde es la recordada.
    throttled: bool = False


class Memory:
    """Hosts seen, their flags, and the credential that worked on each.

    Thread-safe: a ``probe`` order runs in its own thread while a task runs,
    and both write here.
    """

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path is not None else None
        self._lock = threading.RLock()
        #: Para que quien espera turno en `reserve` se entere de cada `finish`.
        self._turns = threading.Condition(self._lock)
        self._etag = ""
        self._hosts: dict[str, dict[str, Any]] = {}
        #: El cortacircuitos, por `ident` (sin secretos). Se guarda en disco.
        self._credentials: dict[str, dict[str, Any]] = {}
        #: Los intentos en vuelo, por `ident`: solo en memoria, nunca en disco.
        self._pending: dict[str, list[int]] = {}
        #: El último «ahora» que nos han dicho. Sirve para fechar lo que se
        #: crea sin fecha (`flag`) con el mismo reloj que el resto.
        self._clock: datetime | None = None

    # --- disco ------------------------------------------------------------------

    @classmethod
    def load(cls, path: Path | None) -> "Memory":
        """La memoria guardada, o una vacía. Nunca lanza."""
        memory = cls(path)
        if path is None:
            return memory
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001 - falta, está roto o no se puede leer: de cero
            return memory
        if not isinstance(raw, dict):
            return memory
        memory._etag = _text(raw.get("etag"))
        hosts = raw.get("hosts")
        if isinstance(hosts, dict):
            for key, value in hosts.items():
                entry = _clean_entry(value)
                if isinstance(key, str) and key and entry is not None:
                    memory._hosts[key] = entry
        credentials = raw.get("credentials")
        if isinstance(credentials, dict):
            for ident, value in credentials.items():
                record = _clean_credential(value)
                if isinstance(ident, str) and ident and record is not None:
                    memory._credentials[ident] = record
        return memory

    def detach(self) -> "Memory":
        """Deja de estar atada a su fichero: lo que aprenda ya no se guarda.

        Para `--once`, que corre a mano quizá junto al servicio: lee lo que el
        servicio sabe, pero no pisa su `memory.json` con lo de una prueba.
        """
        self._path = None
        return self

    def save(self) -> None:
        """Escribe el fichero de forma atómica. Nunca lanza.

        Primero a un temporal en la misma carpeta y después `os.replace`: un
        corte de luz a mitad deja el fichero viejo entero o el nuevo entero,
        nunca medio JSON. Y si algo falla da igual: la memoria es prescindible.
        """
        if self._path is None:
            return
        try:
            with self._lock:
                payload = json.dumps(self._snapshot(), ensure_ascii=False, sort_keys=True, indent=1)
            # Con la protección del token (`agent.store`): no guarda secretos,
            # pero dice qué equipos hay y con qué credencial entra en cada uno.
            store.write_protected(self._path, payload)
        except Exception:  # noqa: BLE001 - un disco lleno no tumba una tarea
            pass

    def _snapshot(self) -> dict[str, Any]:
        return {
            "version": VERSION,
            "etag": self._etag,
            "hosts": {key: json.loads(json.dumps(entry)) for key, entry in self._hosts.items()},
            "credentials": {ident: json.loads(json.dumps(record)) for ident, record in self._credentials.items()},
        }

    # --- reloj y claves -----------------------------------------------------------

    def _tick(self, now: datetime) -> datetime:
        now = _utc(now)
        if self._clock is None or now > self._clock:
            self._clock = now
        return now

    def _now(self) -> datetime:
        return self._clock or datetime.now(timezone.utc)

    def _prune(self, now: datetime) -> None:
        """Olvida los equipos que no se ven desde hace `FORGET_AFTER`.

        Una entrada sin fecha legible se tira también: no hay forma de saber
        si sigue siendo verdad.
        """
        limit = now - FORGET_AFTER
        for key in [k for k, entry in self._hosts.items() if (_parse(entry["last_seen"]) or limit) <= limit]:
            del self._hosts[key]
        # Las credenciales que nadie ha usado en ese tiempo, igual (ya no
        # están en la configuración); nunca una con intentos en vuelo.
        for ident in [
            i for i, record in self._credentials.items()
            if (_parse(record["seen_at"]) or limit) <= limit and not any(self._pending.get(i, (0, 0)))
        ]:
            del self._credentials[ident]

    def _find(self, ip: str, mac: str) -> str | None:
        """La clave con la que ya se conoce ese equipo, si se conoce."""
        if mac and mac in self._hosts:
            return mac
        if ip and ip in self._hosts:
            return ip
        if ip:
            for key, entry in self._hosts.items():
                if entry["ip"] == ip and (not mac or not entry["mac"] or entry["mac"] == mac):
                    return key
        return None

    def key_for(self, ip: str, mac: str = "") -> str:
        """La `host_key` de ese equipo: la MAC si se conoce (aquí o en la
        memoria), si no la IP. Así un equipo del que esta vez el ARP no dio la
        MAC sigue siendo el mismo que ya estaba apuntado."""
        mac = _mac(mac)
        with self._lock:
            known = self._find(ip, mac)
            if known is not None and (not mac or known == mac):
                return known
        return mac or ip

    def _entry(self, host_key: str) -> dict[str, Any]:
        entry = self._hosts.get(host_key)
        if entry is None:
            entry = _blank()
            if _is_ip(host_key):
                entry["ip"] = host_key
            elif ":" in host_key:
                entry["mac"] = host_key
            entry["last_seen"] = _iso(self._now())
            self._hosts[host_key] = entry
        return entry

    # --- equipos ------------------------------------------------------------------

    def note_host(self, ip: str, mac: str, now: datetime) -> bool:
        """Apunta que ese equipo está vivo. ``True`` si la memoria no lo conocía."""
        mac = _mac(mac)
        ip = (ip or "").strip()
        if not ip and not mac:
            return False
        with self._lock:
            now = self._tick(now)
            self._prune(now)
            known = self._find(ip, mac)
            if known is None:
                key = mac or ip
                entry = _blank()
                new = True
            else:
                entry = self._hosts.pop(known)
                # Un equipo que se apuntó por IP (el ARP no dio su MAC) y ahora
                # llega con ella pasa a su clave buena sin perder lo aprendido.
                key = mac or known
                new = False
            entry["ip"] = ip or entry["ip"]
            entry["mac"] = mac or entry["mac"]
            entry["last_seen"] = _iso(now)
            self._hosts[key] = entry
            return new

    def flag(
        self,
        host_key: str,
        *,
        ups: bool | None = None,
        config_family: str | None = None,
        identity_mac: str | None = None,
    ) -> None:
        """Marca lo que se ha aprendido de un equipo. ``None`` = no tocar."""
        if not host_key:
            return
        with self._lock:
            entry = self._entry(host_key)
            if ups is not None:
                entry["ups"] = bool(ups)
            if config_family is not None:
                entry["config_family"] = config_family
            if identity_mac is not None:
                entry["identity_mac"] = _mac(identity_mac)

    def ups_hosts(self) -> list[dict]:
        """Los que contestaron a la UPS-MIB: ``[{"ip","mac","identity_mac"}]``."""
        with self._lock:
            return [
                {"ip": entry["ip"], "mac": entry["mac"], "identity_mac": entry["identity_mac"]}
                for entry in self._hosts.values()
                if entry["ups"] and entry["ip"]
            ]

    def config_hosts(self) -> list[dict]:
        """Los equipos de red en los que SSH ya entró: ``[{"ip","mac","family"}]``.

        Llevan además ``identity_mac``, la identidad con la que el inventario
        los presentó: la copia tiene que colgar del mismo equipo.
        """
        with self._lock:
            return [
                {
                    "ip": entry["ip"],
                    "mac": entry["mac"],
                    "family": entry["config_family"],
                    "identity_mac": entry["identity_mac"],
                }
                for entry in self._hosts.values()
                if entry["config_family"] and entry["ip"]
            ]

    # --- credenciales -------------------------------------------------------------

    def order_for(
        self, host_key: str, protocol: str, credentials: list[Credential], now: datetime
    ) -> list[Credential]:
        """Qué credenciales probar contra ese equipo, y en qué orden.

        1. Fuera las que tienen alcance y no cubren el equipo.
        2. Primero la que entró la última vez.
        3. Las demás **solo** si no ha habido ya una ronda completa fallida
           contra ese equipo y protocolo en las últimas `ROUND_COOLDOWN`.

        Una lista vacía significa «no intentes nada», y no es un error.
        """
        with self._lock:
            now = self._tick(now)
            entry = self._hosts.get(host_key)
            # Contra qué se comprueba el alcance: la IP apuntada; si no hay, la
            # propia clave (una IP, o el nombre de un vCenter tal como se
            # escribió). Una MAC sin IP no cubre ningún alcance: ante la duda,
            # no se prueba.
            target = (entry["ip"] if entry else "") or host_key
            in_scope = [credential for credential in credentials if credential.scope.covers(target)]
            record = (entry or {}).get("creds", {}).get(protocol) or {}
            remembered = record.get("ok", "")
            first_index = next(
                (index for index, credential in enumerate(in_scope) if remembered and credential.ident == remembered),
                None,
            )
            first = [in_scope[first_index]] if first_index is not None else []
            rest = [credential for index, credential in enumerate(in_scope) if index != first_index]
            failed_at = _parse(record.get("failed_at"))
            if failed_at is not None and now - failed_at < ROUND_COOLDOWN:
                rest = []
            return first + rest

    def remembered(self, host_key: str, protocol: str) -> str:
        """El `ident` de la credencial que entró la última vez, o ""."""
        with self._lock:
            entry = self._hosts.get(host_key) or {}
            return (entry.get("creds", {}).get(protocol) or {}).get("ok", "")

    def record_success(self, host_key: str, protocol: str, credential: Credential, now: datetime) -> None:
        """Esa credencial entró: la próxima vez se prueba la primera.

        No borra una ronda fallida reciente: con la recordada delante, las
        demás pueden esperar a que pase el día igual. Y así un sondeo
        («Analizar»), que apunta sus aciertos aquí, no toca el veto de 24 h.
        """
        if not host_key:
            return
        with self._lock:
            now = self._tick(now)
            entry = self._entry(host_key)
            record = entry["creds"].setdefault(protocol, {"ok": "", "ok_at": "", "failed_at": ""})
            record["ok"] = credential.ident
            record["ok_at"] = _iso(now)
            entry["last_seen"] = _iso(now)

    def record_round_failed(self, host_key: str, protocol: str, now: datetime) -> None:
        """Ninguna credencial entró en toda una ronda. Lo que entró antes
        **se sigue recordando**: un tropiezo de red no puede dejar un equipo
        sin inventario un día entero; la recordada se seguirá probando."""
        if not host_key:
            return
        with self._lock:
            now = self._tick(now)
            entry = self._entry(host_key)
            record = entry["creds"].setdefault(protocol, {"ok": "", "ok_at": "", "failed_at": ""})
            record["failed_at"] = _iso(now)

    def credentials_changed(self, etag: str) -> None:
        """Alguien ha tocado las credenciales: las rondas fallidas se olvidan
        (merecen otra), los aciertos no."""
        etag = etag or ""
        with self._lock:
            if etag == self._etag:
                return
            for entry in self._hosts.values():
                for record in entry["creds"].values():
                    record["failed_at"] = ""
            # Y el cortacircuitos: las suspensiones y las cuentas de fallos se
            # levantan. Lo que entró sigue «probado»: el `id` del servidor
            # cambia cuando cambia la credencial, y una que nunca entró sigue
            # sin probar; un cambio de etag por otra cosa (la agenda) no puede
            # dejar una credencial de dominio buena con el límite de tres.
            for record in self._credentials.values():
                record.update(failures=0, hosts=[], suspended_at="")
            self._etag = etag
            self._turns.notify_all()

    # --- el cortacircuitos (spec 2.3) ----------------------------------------------

    def _credential(self, ident: str, now: datetime) -> dict[str, Any]:
        record = self._credentials.get(ident)
        if record is None:
            record = self._credentials[ident] = _blank_credential()
        record["seen_at"] = _iso(now)
        suspended = _parse(record["suspended_at"])
        if suspended is not None and now - suspended >= SUSPENSION:
            # Pasado el día, otra oportunidad entera.
            record.update(failures=0, hosts=[], suspended_at="")
        return record

    def _in_flight(self, ident: str) -> list[int]:
        """[intentos sin probar en vuelo, intentos frenados en vuelo]."""
        return self._pending.setdefault(ident, [0, 0])

    def suspended(self, ident: str, now: datetime) -> bool:
        """Whether that credential is suspended right now."""
        with self._lock:
            return bool(self._credential(ident, _utc(now))["suspended_at"])

    def failures(self, ident: str) -> int:
        """The failures that count for that credential's suspension (for its note)."""
        with self._lock:
            record = self._credentials.get(ident) or _blank_credential()
            return len(record["hosts"]) if record["proven"] else record["failures"]

    def reserve(
        self,
        ident: str,
        now: datetime,
        *,
        host_key: str = "",
        remembered: bool = False,
        explicit: bool = False,
        wait: float = MAX_WAIT_SECONDS,
    ) -> Attempt | None:
        """Ask before trying a credential. `None`: do not try it now.

        Hay que pedirlo **antes** de cada intento y cerrarlo con `finish`
        después: así el límite se cumple con diez hilos a la vez. Mientras los
        intentos que ocupan el cupo están en vuelo, los demás **esperan** su
        resultado en vez de saltarse el equipo: si uno entra, la credencial
        queda probada y todos siguen; si fallan, queda suspendida y los que
        esperaban reciben `None`.

        `explicit` es una persona que lo pide (`probe`, `test_credential`):
        puede probar una suspendida, una vez, y si entra la levanta.
        """
        now = _utc(now)
        deadline = time.monotonic() + max(0.0, wait)
        with self._turns:
            while True:
                record = self._credential(ident, now)
                pending = self._in_flight(ident)
                attempt = Attempt(ident, host_key, remembered, explicit)
                if explicit:
                    return attempt
                if record["suspended_at"]:
                    return None
                if not record["proven"]:
                    if record["failures"] + pending[0] < UNPROVEN_FAILURES:
                        pending[0] += 1
                        attempt.budget = True
                        return attempt
                else:
                    ok_at = _parse(record["ok_at"])
                    trusted = ok_at is not None and now - ok_at < PROVEN_TRUST
                    if not remembered or trusted:
                        return attempt
                    if len(record["hosts"]) + pending[1] < CHANGED_PASSWORD_HOSTS:
                        pending[1] += 1
                        attempt.throttled = True
                        return attempt
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._turns.wait(min(remaining, 1.0))

    def finish(self, attempt: Attempt, outcome: str, now: datetime) -> bool:
        """Close a reserved attempt. Returns whether this suspended the credential.

        `outcome`: `OK`, `AUTH_FAILED` (el equipo contestó y no la aceptó), o
        `UNREACHABLE` (no se llegó a autenticar: equipo apagado, puerto
        cerrado, tiempo agotado antes de pedir la clave). Lo último no gasta
        nada: se devuelve el cupo.
        """
        now = _utc(now)
        with self._turns:
            record = self._credential(attempt.ident, now)
            pending = self._in_flight(attempt.ident)
            if attempt.budget:
                pending[0] = max(0, pending[0] - 1)
            if attempt.throttled:
                pending[1] = max(0, pending[1] - 1)
            suspended_now = False
            if outcome == OK:
                record.update(proven=True, failures=0, hosts=[], suspended_at="", ok_at=_iso(now))
            elif outcome == AUTH_FAILED:
                if not record["proven"]:
                    record["failures"] += 1
                    limit_reached = record["failures"] >= UNPROVEN_FAILURES
                else:
                    if attempt.remembered and attempt.host_key and attempt.host_key not in record["hosts"]:
                        record["hosts"] = sorted([*record["hosts"], attempt.host_key])
                    limit_reached = len(record["hosts"]) >= CHANGED_PASSWORD_HOSTS
                if limit_reached and not record["suspended_at"]:
                    record["suspended_at"] = _iso(now)
                    suspended_now = True
            self._turns.notify_all()
            return suspended_now


class Excluded:
    """Lo que no se toca: ni ping, ni consulta, ni sondeo.

    ``ip in excluded``. Una entrada ilegible se ignora (no excluye nada): la
    escribe una persona en un fichero de ajustes, y una errata no puede tumbar
    el agente.
    """

    def __init__(self, subnets: Iterable[str] = (), addresses: Iterable[str] = ()) -> None:
        self.subnets: tuple[str, ...] = tuple(str(item).strip() for item in subnets or () if str(item).strip())
        self.addresses: tuple[str, ...] = tuple(
            str(item).strip() for item in addresses or () if str(item).strip()
        )
        self._networks = []
        for subnet in self.subnets:
            try:
                self._networks.append(ipaddress.ip_network(subnet, strict=False))
            except ValueError:
                continue
        self._exact: set[str] = set()
        for address in self.addresses:
            try:
                self._exact.add(str(ipaddress.ip_address(address)))
            except ValueError:
                self._exact.add(address.lower())

    def __contains__(self, ip: object) -> bool:
        if not isinstance(ip, str) or not ip.strip():
            return False
        ip = ip.strip()
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return ip.lower() in self._exact
        if str(address) in self._exact:
            return True
        return any(address.version == network.version and address in network for network in self._networks)

    def as_dict(self) -> dict[str, list[str]]:
        return {"subnets": list(self.subnets), "addresses": list(self.addresses)}

    def __repr__(self) -> str:
        return f"Excluded(subnets={list(self.subnets)!r}, addresses={list(self.addresses)!r})"
