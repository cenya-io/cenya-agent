"""A scripted service that speaks the local channel (spec 4), for development and tests.

It stands in for the service so the window can be looked at in every state
without a real agent -- and, above all, without ever touching the real pipe of
the agent installed on the machine::

    python -m agent.app.fake_server --scenario running
    # prints the pipe name; then, in another console:
    set CENYA_PIPE_NAME=<that name>
    python -m agent.app --assume-admin

Scenarios: ``idle``, ``running`` (a task with progress), ``paused``,
``not_enrolled`` (a service that answers but has no enrolment), ``offline``
(the portal does not answer), ``rejected`` (the portal revoked the agent),
``forbidden`` (every action is refused, as for a user who is not an elevated
administrator) and ``down`` (nothing listens: the service is not running; with
``CENYA_STATE_DIR`` pointing at an empty folder the window also knows there is
no enrolment, which is how an unenrolled service looks today: it exits at
start-up). State changes as it would: running a task advances it, pausing
pauses, connecting enrols, disconnecting un-enrols.

**The answers have the shapes of the real service** (``agent/localapi.py`` and
``agent/localops.py``, built in parallel): the same operation table, error
codes (``invalid``, ``not_enrolled``, ``busy``, ``unavailable``, ``excluded``,
``failed``, ``forbidden``, ``unknown_op``), ``status`` with ``name``,
``connection`` (``state``: ok | error | refused | read_only | unknown |
not_enrolled, plus the last check-in's ``at``, ``ok``, ``status``, ``error``),
``pause`` {local, server, until}, ``queued``, ``refusal``, ``has_config``,
``last_checkin``, ``may_act`` and ``local`` (the progress of the long local
operations: ``netbox_export``, ``probe``); ``log`` with raw lines and an
opaque ``cursor``; ``probe`` -> ``{"ip", "report"}``; ``test_connection`` steps
``dns``, ``tcp``, ``tls``, ``checkin`` with ``message``; ``settings.set`` ->
``{"saved", "applied", "settings"}`` and ``details.fields`` on ``invalid``;
``check_update`` -> ``{"current", "offered", "update", "checked_at"}``.

Three fields are **proposed, not yet in the real service**, because the window
needs them (see the report of the desktop application): ``last_run`` in
``status`` (the counters of the last task), ``log_folder`` in ``status`` and
``review_url`` in the answer of ``netbox.export`` with ``send``. The window
works without them, with less.

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

from agent.app import channel

SCENARIOS = ("idle", "running", "paused", "not_enrolled", "offline", "rejected", "forbidden", "down")

#: Las operaciones que actúan: sin administrador, `forbidden` (spec 4).
ACT_OPS = frozenset(
    {
        "run",
        "pause",
        "resume",
        "settings.set",
        "probe",
        "test_connection",
        "connect",
        "disconnect",
        "netbox.export",
        "support_bundle",
        "check_update",
    }
)
READ_OPS = frozenset({"status", "log", "about", "settings.get"})

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


def _iso(moment: datetime | None) -> str | None:
    return moment.isoformat() if moment else None


def _log_line(at: datetime, level: str, text: str) -> str:
    """Una línea como las escribe `agent/logs.py`: fecha, nivel y texto."""
    return f"{at.astimezone().strftime('%Y-%m-%d %H:%M:%S')},000 {level} {text}"


class _Refused(Exception):
    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


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
        self.enrolled = scenario != "not_enrolled"
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
            self.last_checkin = {"at": _iso(now - timedelta(seconds=12)), "ok": True, "status": 200, "error": ""}
        else:
            self.last_checkin = {}
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
        # Propuesto: las cifras de la última tarea (el servicio de verdad aún no las da).
        self.last_run: dict[str, Any] | None = (
            {
                "task": "presence",
                "finished_at": _iso(now - timedelta(minutes=3)),
                "status": "ok",
                "stats": {"hosts_alive": 41, "new_hosts": 1, "items": 41},
                "created": 1,
                "refreshed": 40,
            }
            if self.enrolled
            else None
        )
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
            self.last_run = {
                "task": task,
                "finished_at": _iso(now),
                "status": "ok",
                "stats": {"hosts_alive": 41, "new_hosts": 0, "items": total},
                "created": 0,
                "refreshed": total,
            }
            self._add_log("INFO", f"[agente] Tarea {task} enviada: 0 nuevos, {total} ya conocidos")
            self.activity = None
            self._activity_started = None
            if self._queue:
                self._start_task(self._queue.pop(0))

    # --- Operaciones ----------------------------------------------------------

    def handle(self, request: dict[str, Any], *, admin: bool = True) -> dict[str, Any]:
        """Una petición del canal y su respuesta, como `agent.localapi.Dispatcher`."""
        message_id = request.get("id")
        op = str(request.get("op") or "")
        args = request.get("args") if isinstance(request.get("args"), dict) else {}
        handler = getattr(self, "op_" + op.replace(".", "_"), None)
        if op not in ACT_OPS | READ_OPS or handler is None:
            return {"id": message_id, "ok": False, "error": "unknown_op", "message": f"Operación desconocida: {op[:60]}"}
        may_act = admin and self.scenario != "forbidden"
        if op in ACT_OPS and not may_act:
            return {"id": message_id, "ok": False, "error": "forbidden", "message": "Esta operación solo la puede hacer un administrador."}
        try:
            with self._lock:
                self._tick()
            data = handler(args, may_act) if op == "status" else handler(args)
        except _Refused as exc:
            answer: dict[str, Any] = {"id": message_id, "ok": False, "error": exc.code, "message": exc.message}
            if exc.details:
                answer["details"] = exc.details
            return answer
        return {"id": message_id, "ok": True, "data": data}

    def _need_enrolled(self) -> None:
        if not self.enrolled:
            raise _Refused("not_enrolled", "Este agente no está enrolado: conéctalo con una cadena de Ajustes → Agentes.")

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
                "local": copy.deepcopy(self.local),
                "log_folder": str(self.workdir / "logs"),  # propuesto
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
            data["connection"] = {"state": state, **self.last_checkin}
            data.update(
                {
                    "state": "running" if self.activity else ("paused" if until else "idle"),
                    "activity": copy.deepcopy(self.activity),
                    "schedule": [copy.deepcopy(self.schedule[t]) for t in TASKS if t in self.schedule],
                    "queued": [{"task": task, "trigger": "order"} for task in self._queue],
                    "pause": {"local": self.settings.get("paused_until"), "server": _iso(self.server_pause), "until": _iso(until)},
                    "refusal": self.refusal,
                    "has_config": True,
                    "checkin_seconds": 30,
                    "last_checkin": dict(self.last_checkin),
                    "outbox": 2 if self.last_checkin and not self.last_checkin.get("ok") else 0,
                    "update": {"version": "0.11.1"},
                    "last_run": copy.deepcopy(self.last_run),  # propuesto
                }
            )
            return data

    def op_log(self, args: dict) -> dict:
        lines = args.get("lines", 200)
        if isinstance(lines, bool) or not isinstance(lines, int) or lines < 1:
            raise _Refused("invalid", "«lines» tiene que ser un número entero positivo.")
        after = args.get("after")
        if after is not None and not isinstance(after, str):
            raise _Refused("invalid", "«after» tiene que ser el cursor de una respuesta anterior.")
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
            elif key in self.settings:
                changes[key] = value
            else:
                problems[key] = "Ajuste desconocido."
        if problems:
            raise _Refused("invalid", "Hay ajustes que no son válidos; no se ha cambiado nada.", fields=problems)
        if not changes:
            raise _Refused("invalid", "No hay nada que cambiar.")
        with self._lock:
            self.settings.update(changes)
            self._add_log("INFO", "[agente] Ajustes locales cambiados desde esta máquina: " + ", ".join(sorted(args)) + ".")
        return {"saved": sorted(args), "applied": sorted(args), "overridden_by_environment": [], "restart_required": [], "settings": self.op_settings_get({})}

    def op_run(self, args: dict) -> dict:
        task = args.get("task")
        if task not in TASKS:
            raise _Refused("invalid", "Tarea desconocida. Las tareas son: " + ", ".join(TASKS) + ".")
        self._need_enrolled()
        if self.refusal == "unauthorized":
            raise _Refused("unavailable", "El servidor ha rechazado a este agente: no se empieza ninguna tarea.")
        with self._lock:
            if self.activity:
                self._queue.insert(0, task)
            else:
                self._start_task(task)
        return {"queued": task, "waiting_for": ""}

    def op_pause(self, args: dict) -> dict:
        now = self._clock()
        if args.get("until") is not None:
            try:
                until = datetime.fromisoformat(str(args["until"]).replace("Z", "+00:00"))
            except ValueError:
                raise _Refused("invalid", "«until» tiene que ser una fecha ISO 8601.") from None
            if until.tzinfo is None:
                until = until.replace(tzinfo=timezone.utc)
        elif args.get("seconds") is not None:
            until = now + timedelta(seconds=float(args["seconds"]))
        else:
            raise _Refused("invalid", "Falta «until» o «seconds».")
        if until <= now:
            raise _Refused("invalid", "Esa hora ya ha pasado.")
        if until - now > MAX_PAUSE:
            raise _Refused("invalid", "Una pausa no puede durar más de 30 días.")
        with self._lock:
            self.settings["paused_until"] = until.isoformat()
            self._add_log("INFO", f"[agente] En pausa desde esta máquina hasta {until.isoformat()}.")
        return {"paused_until": until.isoformat(), "server_paused_until": _iso(self.server_pause)}

    def op_resume(self, args: dict) -> dict:
        with self._lock:
            self.settings["paused_until"] = None
            self._add_log("INFO", "[agente] Pausa local levantada desde esta máquina.")
        return {"paused_until": None, "server_paused_until": _iso(self.server_pause)}

    def _sleep(self, seconds: float) -> None:
        time.sleep(seconds / self.speed)

    def op_probe(self, args: dict) -> dict:
        try:
            ip = str(ipaddress.ip_address(str(args.get("ip") or "").strip()))
        except ValueError:
            raise _Refused("invalid", "La dirección no es válida.") from None
        self._need_enrolled()
        if ip in self.settings["excluded"]["addresses"]:
            raise _Refused("excluded", "Esa dirección está excluida en este agente: no se sondea.")
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
            raise _Refused("invalid", "Falta la cadena de conexión (la de Ajustes → Agentes).")
        text = raw.strip()
        if not text.startswith(("cenya://", "cenya+http://")):
            raise _Refused("failed", "La cadena de conexión no es válida: debe parecerse a cenya://portal.midominio.com/XXXX-XXXX-XXXX.")
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
            raise _Refused("invalid", "Falta la URL de NetBox.")
        if not isinstance(token, str) or not token.strip():
            raise _Refused("invalid", "Falta el token de NetBox.")
        send = bool(args.get("send"))
        if send:
            self._need_enrolled()
        bad = token == "bad"
        token = None
        total = len(NETBOX_COLLECTIONS)
        with self._lock:
            if self.local.get("netbox_export", {}).get("state") == "running":
                raise _Refused("busy", "Ya hay una exportación de NetBox en marcha.")
            self.local["netbox_export"] = {"state": "running", "step": "", "done": 0, "total": total, "started_at": _iso(self._clock())}
        if bad:
            self._sleep(0.8)
            with self._lock:
                self.local["netbox_export"].update(state="failed", finished_at=_iso(self._clock()))
            raise _Refused("failed", "NetBox rechazó el token. Crea uno de solo lectura en tu NetBox (Admin → API tokens) y prueba de nuevo.")
        summary: dict[str, int] = {}
        for index, (path, count) in enumerate(NETBOX_COLLECTIONS):
            with self._lock:
                self.local["netbox_export"].update(step=path, done=index)
            self._sleep(0.9)
            summary[path.split("/", 1)[1].replace("-", "_")] = count
        with self._lock:
            self.local["netbox_export"].update(state="done", done=total, finished_at=_iso(self._clock()))
        if send:
            import_id = str(uuid.uuid4())
            # `review_url` es propuesto: el servicio de verdad solo devuelve `import`.
            return {"import": import_id, "summary": summary, "review_url": f"{self.portal}/settings/import/netbox/{import_id}/"}
        target = Path(str(args.get("path") or self.workdir / "netbox-export.json"))
        target.write_text(json.dumps({"fake": True, "summary": summary}), encoding="utf-8")
        return {"path": str(target), "summary": summary, "objects": sum(summary.values())}

    def op_support_bundle(self, args: dict) -> dict:
        target = Path(str(args.get("path") or self.workdir / "cenya-soporte.zip"))
        self._sleep(1.0)
        target.write_bytes(b"PK\x05\x06" + b"\x00" * 18)  # un zip vacío
        return {"path": str(target)}

    def op_check_update(self, args: dict) -> dict:
        self._need_enrolled()
        return {"current": "0.11.0", "offered": "0.11.1", "update": {"version": "0.11.1"}, "checked_at": self.last_checkin.get("at")}


# --- Transporte -------------------------------------------------------------------


class FakeServer:
    """Sirve un `FakeAgent` en un canal: *named pipe* en Windows, socket Unix fuera.

    Nunca escucha en un puerto de red. Se niega a servir el nombre del canal
    de verdad: un servidor falso ahí se haría pasar por el servicio.
    """

    def __init__(self, agent: FakeAgent, address: str | None = None, *, admin: bool = True) -> None:
        self.agent = agent
        self.address = address or channel.random_pipe_name()
        if channel.is_default_address(self.address):
            raise ValueError("the fake server never serves the real agent's pipe")
        self.admin = admin
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._listener: socket.socket | None = None

    def start(self) -> "FakeServer":
        target = self._serve_pipe if self.address.startswith("\\\\") else self._serve_unix
        self._thread = threading.Thread(target=target, name="fake-channel", daemon=True)
        self._thread.start()
        self._ready.wait(5)
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(5)
        if not self.address.startswith("\\\\"):
            try:
                os.unlink(self.address)
            except OSError:
                pass

    def __enter__(self) -> "FakeServer":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    def _answer(self, raw: bytes) -> bytes:
        try:
            request = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return b'{"id": null, "ok": false, "error": "bad_request"}\n'
        if not isinstance(request, dict):
            return b'{"id": null, "ok": false, "error": "bad_request"}\n'
        reply = self.agent.handle(request, admin=self.admin)
        return (json.dumps(reply, ensure_ascii=False) + "\n").encode("utf-8")

    # Unix --------------------------------------------------------------------

    def _serve_unix(self) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            os.unlink(self.address)
        except OSError:
            pass
        listener.bind(self.address)
        listener.listen(8)
        listener.settimeout(0.2)
        self._listener = listener
        self._ready.set()
        while not self._stop.is_set():
            try:
                conn, _ = listener.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                break
            threading.Thread(target=self._unix_client, args=(conn,), daemon=True).start()

    def _unix_client(self, conn: socket.socket) -> None:
        buffer = b""
        conn.settimeout(0.5)
        with conn:
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(65536)
                except (TimeoutError, socket.timeout):
                    continue
                except OSError:
                    return
                if not chunk:
                    return
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if line.strip():
                        try:
                            conn.sendall(self._answer(line))
                        except OSError:
                            return

    # Windows -----------------------------------------------------------------

    def _serve_pipe(self) -> None:
        import pywintypes
        import win32event
        import win32file
        import win32pipe
        import winerror

        first = True
        while not self._stop.is_set():
            open_mode = win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED
            if first:
                open_mode |= 0x00080000  # FILE_FLAG_FIRST_PIPE_INSTANCE
            handle = win32pipe.CreateNamedPipe(
                self.address,
                open_mode,
                win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT
                | 0x00000008,  # PIPE_REJECT_REMOTE_CLIENTS: nunca desde otra máquina
                win32pipe.PIPE_UNLIMITED_INSTANCES,
                65536,
                65536,
                0,
                None,
            )
            first = False
            self._ready.set()
            overlapped = pywintypes.OVERLAPPED()
            overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
            try:
                rc = win32pipe.ConnectNamedPipe(handle, overlapped)
            except pywintypes.error:
                win32file.CloseHandle(handle)
                continue
            if rc == winerror.ERROR_PIPE_CONNECTED:
                win32event.SetEvent(overlapped.hEvent)
            while not self._stop.is_set():
                if win32event.WaitForSingleObject(overlapped.hEvent, 200) == win32event.WAIT_OBJECT_0:
                    break
            if self._stop.is_set():
                try:
                    win32file.CancelIo(handle)
                except pywintypes.error:
                    pass
                win32file.CloseHandle(handle)
                return
            threading.Thread(target=self._pipe_client, args=(handle,), daemon=True).start()

    def _pipe_client(self, handle: Any) -> None:
        import pywintypes
        import win32event
        import win32file
        import win32pipe

        buffer = b""
        try:
            while not self._stop.is_set():
                overlapped = pywintypes.OVERLAPPED()
                overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
                read_buffer = win32file.AllocateReadBuffer(65536)
                try:
                    win32file.ReadFile(handle, read_buffer, overlapped)
                except pywintypes.error:
                    return
                while not self._stop.is_set():
                    if win32event.WaitForSingleObject(overlapped.hEvent, 200) == win32event.WAIT_OBJECT_0:
                        break
                if self._stop.is_set():
                    return
                try:
                    count = win32file.GetOverlappedResult(handle, overlapped, True)
                except pywintypes.error:
                    return
                if count == 0:
                    return
                buffer += bytes(read_buffer[:count])
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line.strip():
                        continue
                    answer = self._answer(line)
                    write = pywintypes.OVERLAPPED()
                    write.hEvent = win32event.CreateEvent(None, True, False, None)
                    try:
                        win32file.WriteFile(handle, answer, write)
                        win32file.GetOverlappedResult(handle, write, True)
                    except pywintypes.error:
                        return
        finally:
            try:
                win32pipe.DisconnectNamedPipe(handle)
            except pywintypes.error:
                pass
            win32file.CloseHandle(handle)


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
