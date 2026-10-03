"""A scripted service that speaks the local channel (spec 4), for development and tests.

It stands in for the service so the window can be looked at in every state
without a real agent -- and, above all, without ever touching the real pipe of
the agent installed on the machine::

    python -m agent.app.fake_server --scenario running
    # prints the pipe name; then, in another console:
    set CENYA_PIPE_NAME=<that name>
    python -m agent.app --assume-admin

Scenarios: ``idle``, ``running`` (a task with progress), ``paused``,
``paused_indefinitely``, ``not_enrolled`` (the service is up, waiting for
``connect``), ``untrusted`` (its old enrolment was set aside as unsafe),
``offline`` (the portal does not answer), ``rejected`` (the portal revoked the
agent), ``update`` (a new version is on offer), ``forbidden`` (every action is
refused, as for a user who is not an elevated administrator) and ``down``
(nothing listens: the service is not running). State changes as it would:
running a task advances it, pausing pauses, connecting enrols, disconnecting
un-enrols.

**Only the answers are scripted.** Requests go through the real transport
(`agent.localpipe`: the same pipe flags, security descriptor and per-client
deadlines as the service) and the real dispatcher (`agent.localapi`: the same
operation table, permission rule, error codes and framing); the scripted part
is the handlers, which raise `OpError` exactly like `agent.localops`. The
answers have the shapes of `agent/localops.py`, and
`agent/tests/test_app_fake_server.py` checks every key of every scripted
answer against the real service's answer to the same request, so they cannot
drift apart unnoticed.

It never keeps or repeats the NetBox token: it checks it and drops it, like
the real one.
"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import os
import socket
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agent import localclient as channel
from agent import localpipe
from agent.localapi import BUSY, EXCLUDED, FAILED, INVALID, NOT_ENROLLED, UNAVAILABLE, Caller, Dispatcher, OpError, Request

SCENARIOS = (
    "idle",
    "running",
    "paused",
    "paused_indefinitely",
    "not_enrolled",
    "untrusted",
    "offline",
    "rejected",
    "update",
    "reseal",
    "forbidden",
    "down",
)

TASKS = ("presence", "inventory", "configs", "ups", "hypervisors")
TASK_EVERY = {"presence": 300, "inventory": 21600, "configs": 86400, "ups": 300, "hypervisors": 3600}
TASK_STEPS = {
    "presence": ("local", "sweep"),
    "inventory": ("snmp", "ssh", "winrm"),
    "configs": ("ssh",),
    "ups": ("snmp",),
    "hypervisors": ("hypervisors",),
}
NETBOX_COLLECTIONS = (
    ("dcim/sites", 3),
    ("dcim/racks", 9),
    ("dcim/device-types", 41),
    ("dcim/devices", 214),
    ("dcim/interfaces", 1830),
    ("dcim/cables", 412),
    ("ipam/vlans", 18),
    ("ipam/prefixes", 27),
    ("ipam/ip-addresses", 603),
)
PORTAL = "https://demo.cenya.cloud"
MAX_PAUSE = timedelta(days=30)
#: Como `agent.settings.PAUSE_INDEFINITE`: la pausa «hasta que se reanude».
INDEFINITE = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment else None


def _log_line(at: datetime, level: str, text: str) -> str:
    """Una línea como las escribe `agent/logs.py`: fecha, nivel y texto."""
    return f"{at.astimezone().strftime('%Y-%m-%d %H:%M:%S')},000 {level} {text}"


class FakeAgent:
    """El estado del servicio falso y lo que contesta a cada operación."""

    def __init__(
        self,
        scenario: str = "idle",
        *,
        clock: Callable[[], datetime] | None = None,
        speed: float = 1.0,
        workdir: Path | None = None,
    ) -> None:
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario!r}")
        self.scenario = scenario
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.speed = speed
        self.workdir = workdir or Path(tempfile.mkdtemp(prefix="cenya-fake-"))
        self._lock = threading.RLock()
        now = self._clock()
        self.enrolled = scenario not in ("not_enrolled", "untrusted")
        #: Sin identidad, por qué (como `status.enrollment` del servicio).
        self.enrollment: dict[str, str] = {"state": "enrolled", "message": ""}
        if scenario == "not_enrolled":
            self.enrollment = {
                "state": "not_enrolled",
                "message": "Este agente no está enrolado. En Ajustes → Agentes genera una cadena de conexión y ejecuta: cenya-agent enroll <cadena>",
            }
        elif scenario == "untrusted":
            self.enrollment = {
                "state": "untrusted",
                "message": "El enrolamiento de este agente estaba en una carpeta sin proteger (C:\\ProgramData\\Cenya) y no es de fiar: se ha apartado sin usarlo. Enrola el equipo de nuevo: cenya-agent enroll <cadena> --force",
            }
        self.portal = PORTAL if self.enrolled else ""
        self.name = "SRV-OFICINA" if self.enrolled else ""
        self.refusal: str | None = {"rejected": "unauthorized"}.get(scenario)
        if scenario == "offline":
            self.last_checkin: dict[str, Any] = {
                "at": _iso(now - timedelta(seconds=20)),
                "ok": False,
                "status": None,
                "error": "No se pudo hablar con el servidor: <urlopen error timed out>",
            }
        elif scenario == "rejected":
            self.last_checkin = {"at": _iso(now - timedelta(seconds=40)), "ok": False, "status": 401, "error": "Token de agente no válido."}
        elif self.enrolled:
            self.last_checkin = {"at": _iso(now - timedelta(seconds=12)), "ok": True, "status": None, "error": ""}
        else:
            self.last_checkin = {}
        #: El último checkin bueno, que se conserva mientras fallan los siguientes.
        self.last_ok_at: str | None = None
        if scenario in ("offline", "rejected"):
            self.last_ok_at = _iso(now - timedelta(hours=3, minutes=12))
        elif self.last_checkin.get("ok"):
            self.last_ok_at = self.last_checkin["at"]
        self.update: dict[str, Any] | None = {"version": "0.11.1"} if scenario == "update" else None
        self.updater: dict[str, Any] = {"state": "idle", "version": "0.11.0", "error": ""}
        #: Otro agente pide las credenciales selladas (`agent.approvals`).
        self.reseal_requests: list[dict[str, Any]] = []
        if scenario == "reseal":
            self.reseal_requests = [
                {
                    "id": "7c1e2b8a-4d1f-4a7e-9a55-2f0d6b3c9e10",
                    "agent": "4b9d6f0e-2a71-4c3b-8e5d-9f1a2c7b6e43",
                    "agent_name": "SRV-ALMACEN",
                    "fingerprint": "3F2A 91C4 7B0D E615 2A9F 0C3E 88B1 D4F7 6E02 5A19 C3B8 7F41 0D9E 2B6A 5C17 E8F3",
                    "count": 7,
                    "received_at": _iso(now - timedelta(minutes=2)),
                }
            ]
        self.server_pause: datetime | None = None
        self.settings: dict[str, Any] = {
            "language": "",
            "ca_bundle": "",
            "proxy": {"mode": "system", "url": ""},
            "excluded": {"subnets": ["192.168.1.0/28"], "addresses": ["192.168.1.200"]},
            "gentleness_cap": "",
            "auto_update": True,
            "notifications": True,
            "paused_until": _iso(now + timedelta(minutes=48)) if scenario == "paused" else None,
            "paused_indefinitely": scenario == "paused_indefinitely",
        }
        self.schedule: dict[str, dict[str, Any]] = {}
        if self.enrolled:
            ages = {"presence": 3, "inventory": 95, "configs": 600, "ups": 2, "hypervisors": 31}
            results = {"presence": "ok", "inventory": "partial", "configs": "ok", "ups": "ok", "hypervisors": "error"}
            for task in TASKS:
                finished = now - timedelta(minutes=ages[task])
                self.schedule[task] = {
                    "task": task,
                    "every_seconds": TASK_EVERY[task],
                    "last_finished_at": _iso(finished),
                    "last_status": results[task],
                    "next_at": _iso(finished + timedelta(seconds=TASK_EVERY[task])),
                }
        # Las cifras de la última ejecución de cada tarea (`status.last_run`).
        self.last_run: dict[str, dict[str, Any]] = {}
        if self.enrolled:
            figures = {
                "presence": (41, 1, 41, 1, 40, 0),
                "inventory": (None, None, 112, 3, 109, 2),
                "configs": (None, None, 14, 0, 14, 0),
                "ups": (None, None, 2, 0, 2, 0),
                "hypervisors": (None, None, 0, None, None, 1),
            }
            for task, (alive, new, sent, created, refreshed, notes) in figures.items():
                finished = self.schedule[task]["last_finished_at"]
                self.last_run[task] = {
                    "task": task,
                    "trigger": "schedule",
                    "started_at": finished,
                    "finished_at": finished,
                    "status": self.schedule[task]["last_status"],
                    "hosts_alive": alive,
                    "new_hosts": new,
                    "sent": sent,
                    "delivered": created is not None,
                    "created": created,
                    "refreshed": refreshed,
                    "notes": notes,
                }
        self.activity: dict[str, Any] | None = None
        self.local: dict[str, dict[str, Any]] = {}
        self._activity_started: float | None = None
        self._queue: list[str] = []
        self._log: list[str] = []
        self._last_log_tick = time.monotonic()
        self._seed_log(now)
        if scenario == "running":
            self._start_task("inventory", offset=14 * 0.6 / speed)

    # --- Registro -------------------------------------------------------------

    def _add_log(self, level: str, text: str, at: datetime | None = None) -> None:
        self._log.append(_log_line(at or self._clock(), level, text))
        del self._log[:-2000]

    def _seed_log(self, now: datetime) -> None:
        if not self.enrolled:
            self._add_log("INFO", "[agente] Este agente no está enrolado: esperando una cadena de conexión.", now)
            return
        lines = [
            (180, "INFO", "[agente] Conectado a https://demo.cenya.cloud con el protocolo 2."),
            (175, "INFO", "[agente] Tarea presence: 41 equipos vivos, 1 nuevo."),
            (174, "INFO", "[agente] Tarea presence enviada: 1 nuevo, 40 ya conocidos"),
            (120, "INFO", "[agente] Tarea inventory: empieza con 41 equipos."),
            (96, "WARNING", "[agente] Tarea inventory: SSH 192.168.1.20, ninguna credencial entró."),
            (95, "INFO", "[agente] Tarea inventory enviada: 3 nuevos, 38 ya conocidos"),
            (31, "ERROR", "[agente] Tarea hypervisors: vCenter 192.168.1.30, el certificado no es válido."),
            (3, "INFO", "[agente] Tarea presence enviada: 0 nuevos, 41 ya conocidos"),
        ]
        for minutes, level, text in lines:
            self._add_log(level, text, now - timedelta(minutes=minutes))
        if self.last_checkin and not self.last_checkin.get("ok"):
            self._add_log("ERROR", "[agente] " + str(self.last_checkin.get("error")), now)

    # --- Tareas ---------------------------------------------------------------

    def _start_task(self, task: str, offset: float = 0.0) -> None:
        self.activity = {
            "task": task,
            "run_id": str(uuid.uuid4()),
            "step": TASK_STEPS[task][0],
            "done": 0,
            "total": 37 if task == "inventory" else 41 if task == "presence" else 6,
            "started_at": _iso(self._clock()),
        }
        self._activity_started = time.monotonic() - offset
        self._add_log("INFO", f"[agente] Tarea {task}: empieza.")

    def _paused_until(self) -> datetime | None:
        if self.settings.get("paused_indefinitely"):
            return INDEFINITE
        local = self.settings.get("paused_until")
        local_until = datetime.fromisoformat(local) if local else None
        candidates = [moment for moment in (local_until, self.server_pause) if moment]
        until = max(candidates) if candidates else None
        return until if until and until > self._clock() else None

    def _tick(self) -> None:
        """Avanza la tarea en curso según el tiempo pasado."""
        now = self._clock()
        if time.monotonic() - self._last_log_tick > 4 / self.speed and self.activity:
            self._last_log_tick = time.monotonic()
            self._add_log("INFO", f"[agente] Tarea {self.activity['task']}: {self.activity['step']} {self.activity['done']}/{self.activity['total']}")
        if not self.activity or self._activity_started is None:
            if not self.activity and self._queue:
                self._start_task(self._queue.pop(0))
            return
        elapsed = (time.monotonic() - self._activity_started) * self.speed
        total = self.activity["total"]
        done = min(total, int(elapsed / 0.6))
        steps = TASK_STEPS[self.activity["task"]]
        self.activity["done"] = done
        self.activity["step"] = steps[min(len(steps) - 1, done * len(steps) // max(1, total))]
        if done >= total:
            task = self.activity["task"]
            entry = self.schedule.setdefault(task, {"task": task, "every_seconds": TASK_EVERY[task]})
            entry.update(last_finished_at=_iso(now), last_status="ok", next_at=_iso(now + timedelta(seconds=TASK_EVERY[task])))
            self.last_run[task] = {
                "task": task,
                "trigger": "order",
                "started_at": self.activity.get("started_at"),
                "finished_at": _iso(now),
                "status": "ok",
                "hosts_alive": 41 if task == "presence" else None,
                "new_hosts": 0 if task == "presence" else None,
                "sent": total,
                "delivered": True,
                "created": 0,
                "refreshed": total,
                "notes": 0,
            }
            self._add_log("INFO", f"[agente] Tarea {task} enviada: 0 nuevos, {total} ya conocidos")
            self.activity = None
            self._activity_started = None
            if self._queue:
                self._start_task(self._queue.pop(0))

    # --- Operaciones ----------------------------------------------------------

    def handlers(self) -> dict[str, Any]:
        """La tabla de `agent.localapi.Dispatcher`: cada operación de la especificación, guionizada."""

        def wrap(name: str) -> Any:
            method = getattr(self, "op_" + name.replace(".", "_"))

            def handler(args: dict[str, Any], caller: Caller) -> Any:
                with self._lock:
                    self._tick()
                return method(args, caller.admin) if name == "status" else method(args)

            return handler

        return {name: wrap(name) for name in channel.OPERATIONS}

    def dispatcher(self, admin: Callable[[], bool] | None = None) -> Dispatcher:
        """El despachador de verdad con estos manejadores; `admin` dice si quien llama puede actuar."""
        return ScriptedDispatcher(self.handlers(), lambda: (admin() if admin else True) and self.scenario != "forbidden")

    def handle(self, request: dict[str, Any], *, admin: bool = True) -> dict[str, Any]:
        """Una petición ya decodificada y su respuesta, por el despachador de verdad (para pruebas en memoria)."""
        line = json.dumps(request, ensure_ascii=False).encode("utf-8")
        return self.dispatcher(lambda: admin).handle_line(line, Caller(admin=admin, who="memory"))

    def _need_enrolled(self) -> None:
        if not self.enrolled:
            raise OpError(NOT_ENROLLED, "Este agente no está enrolado: conéctalo con una cadena de Ajustes → Agentes.")

    def op_status(self, args: dict, may_act: bool = True) -> dict:
        with self._lock:
            data: dict[str, Any] = {
                "version": "0.11.0",
                "pid": os.getpid(),
                "enrolled": self.enrolled,
                "protocol": "v2" if self.enrolled else None,
                "portal": self.portal,
                "name": self.name,
                "may_act": may_act,
                "enrollment": dict(self.enrollment),
                "local": copy.deepcopy(self.local),
                "log_folder": str(self.workdir / "logs"),
            }
            if not self.enrolled:
                data["connection"] = {"state": "not_enrolled"}
                return data
            if self.refusal:
                state = "refused" if self.refusal == "unauthorized" else "read_only"
            elif not self.last_checkin:
                state = "unknown"
            else:
                state = "ok" if self.last_checkin.get("ok") else "error"
            until = self._paused_until()
            indefinite = until == INDEFINITE
            data["connection"] = {"state": state, **self.last_checkin, "last_ok_at": self.last_ok_at}
            data.update(
                {
                    "state": "running" if self.activity else ("paused" if until else "idle"),
                    "activity": copy.deepcopy(self.activity),
                    "schedule": [copy.deepcopy(self.schedule[t]) for t in TASKS if t in self.schedule],
                    "queued": [{"task": task, "trigger": "order"} for task in self._queue],
                    "pause": {
                        "local": self.settings.get("paused_until"),
                        "server": _iso(self.server_pause),
                        "until": None if indefinite else _iso(until),
                        "indefinite": indefinite,
                    },
                    "refusal": self.refusal,
                    "has_config": True,
                    "checkin_seconds": 30,
                    "last_checkin": dict(self.last_checkin),
                    "last_ok_at": self.last_ok_at,
                    "outbox": 2 if self.last_checkin and not self.last_checkin.get("ok") else 0,
                    "update": copy.deepcopy(self.update),
                    "updater": dict(self.updater),
                    "gentleness": "gentle" if self.settings.get("gentleness_cap") == "gentle" else "normal",
                    "last_run": copy.deepcopy(self.last_run),
                    "identity": {"server_has_key": True, "problem": None},
                    "reseal_requests": copy.deepcopy(self.reseal_requests),
                }
            )
            return data

    def op_log(self, args: dict) -> dict:
        lines = args.get("lines", 200)
        if isinstance(lines, bool) or not isinstance(lines, int) or lines < 1:
            raise OpError(INVALID, "«lines» tiene que ser un número entero positivo.")
        after = args.get("after")
        if after is not None and not isinstance(after, str):
            raise OpError(INVALID, "«after» tiene que ser el cursor de una respuesta anterior.")
        with self._lock:
            size = len(self._log)
            start = int(after.split(":", 1)[1]) if after and after.startswith("fake:") and after.split(":", 1)[1].isdigit() else 0
            rows = self._log[start:size] if after else self._log[-min(lines, 2000):]
            return {"lines": rows[-min(lines, 2000):], "cursor": f"fake:{size}"}

    def op_about(self, args: dict) -> dict:
        return {
            "hostname": "SRV-OFICINA",
            "os": {"system": "Windows", "release": "2022Server", "version": "10.0.20348"},
            "python": "3.12.10",
            "agent_version": "0.11.0",
            "frozen": True,
            "networks": [
                {"interface": "Ethernet", "address": "192.168.1.10", "cidr": "192.168.1.0/24", "mac": "aa:bb:cc:dd:ee:ff"},
                {"interface": "Gestión", "address": "10.20.0.4", "cidr": "10.20.0.0/22", "mac": "aa:bb:cc:dd:ee:01"},
            ],
            "capabilities": {"snmp": True, "ssh": True, "ssh_password": True, "winrm": True, "hypervisors": True, "sealed_credentials": True},
            "excluded": copy.deepcopy(self.settings["excluded"]),
            "auto_update": self.settings["auto_update"],
        }

    def op_settings_get(self, args: dict) -> dict:
        with self._lock:
            data = copy.deepcopy(self.settings)
        url = data["proxy"]["url"]
        data["proxy"]["has_credentials"] = "@" in url
        if "@" in url:
            scheme, _, rest = url.partition("://")
            data["proxy"]["url"] = f"{scheme}://***@{rest.rsplit('@', 1)[1]}" if rest else "***@" + url.rsplit("@", 1)[1]
        data["locked"] = []
        return data

    def op_settings_set(self, args: dict) -> dict:
        problems: dict[str, str] = {}
        changes: dict[str, Any] = {}
        for key, value in args.items():
            if key == "excluded" and isinstance(value, dict):
                merged = dict(self.settings["excluded"])
                for kind, check in (("subnets", ipaddress.ip_network), ("addresses", ipaddress.ip_address)):
                    if kind in value:
                        bad = []
                        for item in value[kind]:
                            try:
                                check(str(item)) if kind == "addresses" else check(str(item), strict=False)
                            except ValueError:
                                bad.append(str(item))
                        if bad:
                            problems["excluded"] = "No son redes ni direcciones válidas: " + ", ".join(bad[:10])
                        merged[kind] = [str(v) for v in value[kind]]
                changes["excluded"] = merged
            elif key == "proxy" and isinstance(value, dict):
                proxy = dict(self.settings["proxy"])
                proxy.update({k: v for k, v in value.items() if k in ("mode", "url")})
                if proxy["mode"] == "manual" and not str(proxy.get("url") or "").startswith(("http://", "https://")):
                    problems["proxy"] = "La dirección del proxy no es válida."
                changes["proxy"] = proxy
            elif key == "ca_bundle" and value and not str(value).lower().endswith((".pem", ".crt", ".cer")):
                problems["ca_bundle"] = "Ese fichero no parece un certificado."
            elif key in self.settings and key not in ("paused_until", "paused_indefinitely"):
                changes[key] = value
            else:
                problems[key] = "Ajuste desconocido."
        if problems:
            raise OpError(INVALID, "Hay ajustes que no son válidos; no se ha cambiado nada.", fields=problems)
        if not changes:
            raise OpError(INVALID, "No hay nada que cambiar.")
        with self._lock:
            self.settings.update(changes)
            self._add_log("INFO", "[agente] Ajustes locales cambiados desde esta máquina: " + ", ".join(sorted(args)) + ".")
        return {"saved": sorted(args), "applied": sorted(args), "overridden_by_environment": [], "restart_required": [], "settings": self.op_settings_get({})}

    def op_run(self, args: dict) -> dict:
        task = args.get("task")
        if task not in TASKS:
            raise OpError(INVALID, "Tarea desconocida. Las tareas son: " + ", ".join(TASKS) + ".")
        self._need_enrolled()
        if self.refusal == "unauthorized":
            raise OpError(UNAVAILABLE, "El servidor ha rechazado a este agente: no se empieza ninguna tarea.")
        with self._lock:
            if self.activity:
                self._queue.insert(0, task)
            else:
                self._start_task(task)
        return {"queued": task, "waiting_for": ""}

    def op_pause(self, args: dict) -> dict:
        now = self._clock()
        if args.get("indefinite") is True:
            if args.get("until") is not None or args.get("seconds") is not None:
                raise OpError(INVALID, "Una pausa sin plazo no lleva «until» ni «seconds».")
            with self._lock:
                self.settings.update(paused_until=None, paused_indefinitely=True)
                self._add_log("INFO", "[agente] En pausa desde esta máquina hasta que se reanude.")
            return {"paused_until": None, "indefinite": True, "server_paused_until": _iso(self.server_pause)}
        if args.get("until") is not None:
            try:
                until = datetime.fromisoformat(str(args["until"]).replace("Z", "+00:00"))
            except ValueError:
                raise OpError(INVALID, "«until» tiene que ser una fecha ISO 8601.") from None
            if until.tzinfo is None:
                until = until.replace(tzinfo=timezone.utc)
        elif args.get("seconds") is not None:
            until = now + timedelta(seconds=float(args["seconds"]))
        else:
            raise OpError(INVALID, "Falta «until» o «seconds».")
        if until <= now:
            raise OpError(INVALID, "Esa hora ya ha pasado.")
        if until - now > MAX_PAUSE:
            raise OpError(INVALID, "Una pausa con hora no puede durar más de 30 días; para pararlo sin plazo, pausa hasta que lo reanudes.")
        with self._lock:
            self.settings.update(paused_until=until.isoformat(), paused_indefinitely=False)
            self._add_log("INFO", f"[agente] En pausa desde esta máquina hasta {until.isoformat()}.")
        return {"paused_until": until.isoformat(), "indefinite": False, "server_paused_until": _iso(self.server_pause)}

    def op_resume(self, args: dict) -> dict:
        with self._lock:
            self.settings.update(paused_until=None, paused_indefinitely=False)
            self._add_log("INFO", "[agente] Pausa local levantada desde esta máquina.")
        return {"paused_until": None, "indefinite": False, "server_paused_until": _iso(self.server_pause)}

    def _sleep(self, seconds: float) -> None:
        time.sleep(seconds / self.speed)

    def op_probe(self, args: dict) -> dict:
        try:
            ip = str(ipaddress.ip_address(str(args.get("ip") or "").strip()))
        except ValueError:
            raise OpError(INVALID, "La dirección no es válida.") from None
        self._need_enrolled()
        if ip in self.settings["excluded"]["addresses"]:
            raise OpError(EXCLUDED, "Esa dirección está excluida en este agente: no se sondea.")
        with self._lock:
            self.local["probe"] = {"state": "running", "ip": ip, "started_at": _iso(self._clock())}
        self._sleep(2.0)
        with self._lock:
            self.local["probe"].update(state="done", finished_at=_iso(self._clock()))
        report = {
            "snmp": "contesta con la comunidad nº 1: Cisco IOS Software, C2960X",
            "ssh": "puerto abierto, ninguna credencial entró (2 probadas)",
            "winrm": "puerto cerrado",
            "codes": {},
            "at": _iso(self._clock()),
        }
        return {"ip": ip, "report": report}

    def op_test_connection(self, args: dict) -> dict:
        self._need_enrolled()
        self._sleep(1.5)
        host = self.portal.split("://", 1)[-1]

        def step(name: str, ok: bool, code: str, message: str) -> dict:
            return {"step": name, "ok": ok, "code": code, "params": {}, "message": message}

        steps = [step("dns", True, "ok", f"El nombre {host} se resuelve.")]
        if self.last_checkin and not self.last_checkin.get("ok") and not self.refusal:
            steps.append(step("tcp", False, "timeout", f"El puerto 443 de {host} no contesta."))
        else:
            steps.append(step("tcp", True, "ok", f"El puerto 443 de {host} acepta conexiones."))
            steps.append(step("tls", True, "ok", "El certificado del portal es válido."))
            if self.refusal == "unauthorized":
                steps.append(step("checkin", False, "unauthorized", "El servidor rechaza el token de este agente: hay que enrolarlo de nuevo."))
            else:
                steps.append(step("checkin", True, "ok", "El servidor acepta a este agente."))
        return {"ok": all(s["ok"] for s in steps), "steps": steps, "portal": self.portal}

    def op_connect(self, args: dict) -> dict:
        raw = args.get("connection")
        if not raw and args.get("code") and args.get("portal"):
            raw = "cenya://" + str(args["portal"]).split("://", 1)[-1].rstrip("/") + "/" + str(args["code"])
        if not isinstance(raw, str) or not raw.strip() or len(raw) > 500:
            raise OpError(INVALID, "Falta la cadena de conexión (la de Ajustes → Agentes).")
        text = raw.strip()
        if not text.startswith(("cenya://", "cenya+http://")):
            raise OpError(FAILED, "La cadena de conexión no es válida: debe parecerse a cenya://portal.midominio.com/XXXX-XXXX-XXXX.")
        self._sleep(1.0)
        with self._lock:
            host = text.split("://", 1)[1].split("/", 1)[0]
            self.__init__("idle", clock=self._clock, speed=self.speed, workdir=self.workdir)  # type: ignore[misc]
            self.portal = f"https://{host}"
            self._add_log("INFO", f"[agente] Conectado desde esta máquina como «SRV-OFICINA» en {self.portal}.")
        return {"name": self.name, "portal": self.portal, "restarting": True}

    def op_disconnect(self, args: dict) -> dict:
        self._sleep(0.8)
        with self._lock:
            told = True if self.enrolled else None
            self.__init__("not_enrolled", clock=self._clock, speed=self.speed, workdir=self.workdir)  # type: ignore[misc]
            self._add_log("INFO", "[agente] Desconectado desde esta máquina.")
        message = "Se ha avisado al servidor: este agente queda dado de baja." if told else "Este agente no estaba conectado a ningún servidor."
        return {"told_server": told, "removed": ["enrollment.json", "identity.key"], "message": message}

    def op_netbox_export(self, args: dict) -> dict:
        token = args.pop("token", None)  # se usa y se olvida
        url = args.get("url")
        if not isinstance(url, str) or not url.strip():
            raise OpError(INVALID, "Falta la URL de NetBox.")
        if not isinstance(token, str) or not token.strip():
            raise OpError(INVALID, "Falta el token de NetBox.")
        send = bool(args.get("send"))
        if send:
            self._need_enrolled()
        bad = token == "bad"
        token = None
        total = len(NETBOX_COLLECTIONS)
        with self._lock:
            if self.local.get("netbox_export", {}).get("state") == "running":
                raise OpError(BUSY, "Ya hay una exportación de NetBox en marcha.")
            self.local["netbox_export"] = {"state": "running", "step": "", "done": 0, "total": total, "finished": [], "started_at": _iso(self._clock())}
        if bad:
            self._sleep(0.8)
            with self._lock:
                self.local["netbox_export"].update(state="failed", finished_at=_iso(self._clock()))
            raise OpError(FAILED, "NetBox rechazó el token. Crea uno de solo lectura en tu NetBox (Admin → API tokens) y prueba de nuevo.")
        summary: dict[str, int] = {}
        for index, (path, count) in enumerate(NETBOX_COLLECTIONS):
            with self._lock:
                self.local["netbox_export"].update(step=path, done=index, finished=[name for name, _ in NETBOX_COLLECTIONS[:index]])
            self._sleep(0.9)
            summary[path.split("/", 1)[1].replace("-", "_")] = count
        with self._lock:
            self.local["netbox_export"].update(state="done", done=total, finished_at=_iso(self._clock()))
        if send:
            import_id = str(uuid.uuid4())
            from agent.localops import review_url

            return {"import": import_id, "summary": summary, "review_url": review_url(self.portal, {"import": import_id})}
        target = Path(str(args.get("path") or self.workdir / "netbox-export.json"))
        target.write_text(json.dumps({"fake": True, "summary": summary}), encoding="utf-8")
        return {"path": str(target), "summary": summary, "objects": sum(summary.values())}

    def op_support_bundle(self, args: dict) -> dict:
        target = Path(str(args.get("path") or self.workdir / "cenya-soporte.zip"))
        self._sleep(1.0)
        target.write_bytes(b"PK\x05\x06" + b"\x00" * 18)  # un zip vacío
        return {"path": str(target)}

    def op_reseal_decide(self, args: dict) -> dict:
        self._need_enrolled()
        request_id, allow = args.get("id"), args.get("allow")
        if not isinstance(request_id, str) or not isinstance(allow, bool):
            raise OpError(INVALID, "Hacen falta «id» (el de la petición) y «allow» (true o false).")
        with self._lock:
            before = len(self.reseal_requests)
            self.reseal_requests = [r for r in self.reseal_requests if r["id"] != request_id]
            if len(self.reseal_requests) == before:
                raise OpError(INVALID, "Esa petición ya no está pendiente (se contestó o caducó).")
        return {"id": request_id, "allowed": allow}

    def op_check_update(self, args: dict) -> dict:
        self._need_enrolled()
        self._sleep(1.2)
        failing = bool(self.last_checkin) and not self.last_checkin.get("ok")
        with self._lock:
            if not failing:
                self.last_checkin = {"at": _iso(self._clock()), "ok": True, "status": None, "error": ""}
                self.last_ok_at = self.last_checkin["at"]
            update = copy.deepcopy(self.update)
        return {
            "current": "0.11.0",
            "offered": (update or {}).get("version"),
            "update": update,
            "checked": not failing,
            "pending": False,
            "error": str(self.last_checkin.get("error") or "") if failing else "",
            "checked_at": self.last_checkin.get("at"),
            "last_ok_at": self.last_ok_at,
            "updater": dict(self.updater),
            "auto_update": bool(self.settings.get("auto_update")),
        }


# --- Transporte -------------------------------------------------------------------


class ScriptedDispatcher(Dispatcher):
    """The real dispatcher, with the caller's right to act decided by the scenario.

    Lo único que se cambia es *quién* llama: el transporte de verdad
    identifica al usuario de la sesión (que en desarrollo no suele estar
    elevado), y para revisar pantallas hace falta poder elegir. Qué puede
    cada uno lo sigue decidiendo `agent.localapi.may`.
    """

    def __init__(self, handlers: dict[str, Any], admin: Callable[[], bool]) -> None:
        super().__init__(handlers)
        self._admin = admin

    def handle(self, request: Request, caller: Caller) -> dict[str, Any]:
        return super().handle(request, Caller(admin=self._admin(), who=caller.who))


class FakeServer:
    """Sirve un `FakeAgent` por el transporte de verdad: *named pipe* en Windows, socket Unix fuera.

    Nunca escucha en un puerto de red. Se niega a servir el nombre del canal
    de verdad: un servidor falso ahí se haría pasar por el servicio.
    """

    def __init__(self, agent: FakeAgent, address: str | None = None, *, admin: bool = True) -> None:
        self.agent = agent
        self.address = address or channel.random_pipe_name()
        if sys.platform == "win32" and not self.address.startswith(channel.PIPE_PREFIX):
            # Un nombre suelto («CenyaAgentDev-x») es un pipe, como en `--pipe` de la ventana.
            self.address = channel.PIPE_PREFIX + self.address
        if channel.is_default_address(self.address):
            raise ValueError("the fake server never serves the real agent's pipe")
        self.admin = admin
        self._server: Any = None

    def start(self) -> "FakeServer":
        dispatcher = self.agent.dispatcher(lambda: self.admin)
        if self.address.startswith("\\\\"):
            server: Any = localpipe.PipeServer(self.address, dispatcher)
        else:
            server = localpipe.SocketServer(Path(self.address), dispatcher)
        if not server.start():
            raise RuntimeError(f"cannot serve {self.address}")
        self._server = server
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None

    def __enter__(self) -> "FakeServer":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()


def _variable() -> str:
    return channel.ADDRESS_ENV_VAR if sys.platform == "win32" else channel.SOCKET_ENV_VAR


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m agent.app.fake_server", description="Servicio falso del canal local, para desarrollo.")
    parser.add_argument("--scenario", choices=SCENARIOS, default="idle")
    parser.add_argument("--pipe", default="", help="nombre del canal (por defecto, uno al azar)")
    parser.add_argument("--not-admin", action="store_true", help="contesta forbidden a toda acción")
    parser.add_argument("--speed", type=float, default=1.0)
    options = parser.parse_args(argv)
    address = options.pipe or channel.random_pipe_name()
    if options.scenario == "down":
        print(f"Escenario «down»: no se sirve nada. {_variable()}={address}", flush=True)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            return 0
    agent = FakeAgent(options.scenario, speed=options.speed)
    with FakeServer(agent, address, admin=not options.not_admin):
        print(f"{_variable()}={address}", flush=True)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
