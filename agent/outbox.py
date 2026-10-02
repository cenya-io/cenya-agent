"""The outbox: what could not be sent yet, kept on disk until it can (spec 2.6).

Protocol 2 pushes each task's result as soon as the task ends, and answers each
order as soon as it is taken. When the server is not there (a network cut, a
restart, a portal in maintenance) none of that is thrown away: it waits here,
one file per piece, and goes up **in the order it was queued** after the next
check-in that works. The next task never waits for it.

The rules:

* **Results only.** The bodies of ``v2/results`` and of order answers. Never
  the configuration, never a credential: nothing in here needs protecting
  more than the inventory itself.
* **Bounded.** 50 MB and 24 h. What does not fit or is too old is dropped,
  oldest first, and that is said with a note (``outbox_dropped``) that rides
  on the next result: a gap in the inventory nobody explains is worse than the
  gap.
* **Crash-safe.** Every file lands whole (temporary file + ``os.replace``). A
  leftover temporary or a file that does not parse is ignored and removed, never
  sent half.
* **No duplicates.** A piece is named by what it is (``<run_id>-<part>.json``,
  ``order-<id>.json``): queuing the same one twice replaces it. And the server
  is idempotent by ``run.id`` anyway, so a piece sent whose deletion failed is
  harmless when it goes again.
* **Never raises.** Like the status file: a full disk costs the queue, not the
  agent.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from agent.notes import Note, collector_note

FOLDER = "outbox"
MAX_BYTES = 50 * 1024 * 1024
MAX_AGE = timedelta(hours=24)

KIND_RESULT = "result"
KIND_ORDER = "order"

_SAFE = re.compile(r"[^A-Za-z0-9_.-]")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _safe(value: str) -> str:
    """Un trozo de nombre de fichero a partir de algo que manda el servidor.

    Un `id` es un UUID y pasa tal cual; cualquier otra cosa (una barra, dos
    puntos, algo larguísimo) se convierte en su huella, que sigue siendo
    estable: el mismo id da siempre el mismo fichero.
    """
    value = str(value)
    if value and len(value) <= 80 and not _SAFE.search(value) and value not in (".", ".."):
        return value
    return sha256(value.encode("utf-8", "replace")).hexdigest()[:32]


def result_name(run_id: str, part: int) -> str:
    return f"{_safe(run_id)}-{int(part)}.json"


def order_name(order_id: str) -> str:
    return f"order-{_safe(order_id)}.json"


@dataclass(frozen=True)
class Entry:
    """Un envío pendiente, tal como está en disco."""

    path: Path
    kind: str
    body: dict[str, Any]
    queued_at: datetime
    seq: int
    size: int
    order_id: str = ""


class Outbox:
    def __init__(
        self,
        folder: Path,
        *,
        max_bytes: int = MAX_BYTES,
        max_age: timedelta = MAX_AGE,
        clock: Callable[[], datetime] = _now,
    ) -> None:
        self.folder = folder
        self.max_bytes = max_bytes
        self.max_age = max_age
        self._clock = clock
        self._lock = threading.RLock()
        self._seq = 0
        self._notes: list[Note] = []
        with self._lock:
            self._sweep_leftovers()
            self._seq = max((entry.seq for entry in self._entries()), default=0)

    # --- Poner -----------------------------------------------------------------

    def put_result(self, body: dict[str, Any]) -> bool:
        run = body.get("run") or {}
        return self._put(result_name(str(run.get("id") or ""), int(body.get("part") or 1)), KIND_RESULT, body)

    def put_order_answer(self, order_id: str, body: dict[str, Any]) -> bool:
        return self._put(order_name(order_id), KIND_ORDER, body, order_id=order_id)

    def _put(self, name: str, kind: str, body: dict[str, Any], *, order_id: str = "") -> bool:
        with self._lock:
            try:
                self._seq += 1
                envelope = {
                    "kind": kind,
                    "order_id": order_id,
                    "queued_at": self._clock().isoformat(),
                    "seq": self._seq,
                    "body": body,
                }
                data = json.dumps(envelope, ensure_ascii=False).encode("utf-8")
                if len(data) > self.max_bytes:
                    self._drop_note(1, "size")
                    return False
                self.folder.mkdir(parents=True, exist_ok=True)
                target = self.folder / name
                fd, tmp_name = tempfile.mkstemp(dir=self.folder, prefix=".out-", suffix=".tmp")
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(data)
                    os.replace(tmp_name, target)
                except BaseException:
                    Path(tmp_name).unlink(missing_ok=True)
                    raise
            except Exception:  # noqa: BLE001 - un disco lleno cuesta la cola, no el agente
                self._drop_note(1, "write")
                return False
            self._enforce(keep=target)
            return target.exists()

    # --- Mirar -----------------------------------------------------------------

    def count(self) -> int:
        with self._lock:
            return len(self._entries())

    def order_ids(self) -> set[str]:
        """Los encargos cuya respuesta espera aquí: ya atendidos, no repetirlos."""
        with self._lock:
            return {entry.order_id for entry in self._entries() if entry.kind == KIND_ORDER and entry.order_id}

    def take_notes(self) -> list[Note]:
        """Lo descartado desde la última vez, como notas para el siguiente resultado."""
        with self._lock:
            notes, self._notes = self._notes, []
            return notes

    # --- Vaciar ----------------------------------------------------------------

    def drain(
        self,
        send: Callable[[Entry], object],
        *,
        is_permanent: Callable[[Exception], bool] = lambda exc: False,
    ) -> int:
        """Envía en orden; para en el primer fallo pasajero. Devuelve cuántos salieron.

        Un fallo «permanente» (el servidor dice que eso nunca lo aceptará: un
        400, un encargo que ya no existe) se tira con su nota en vez de tapar
        la cola para siempre.
        """
        sent = 0
        with self._lock:
            self._enforce()
            entries = self._entries()
        for entry in entries:
            try:
                send(entry)
            except Exception as exc:  # noqa: BLE001
                if is_permanent(exc):
                    with self._lock:
                        self._remove(entry.path)
                        self._drop_note(1, "rejected")
                    continue
                break
            with self._lock:
                self._remove(entry.path)
            sent += 1
        return sent

    # --- Por dentro --------------------------------------------------------------

    def _entries(self) -> list[Entry]:
        """Lo pendiente, en el orden en que se puso. Lo ilegible se quita."""
        try:
            paths = [p for p in self.folder.iterdir() if p.suffix == ".json"]
        except OSError:
            return []
        entries: list[Entry] = []
        broken = 0
        for item in paths:
            entry = self._read(item)
            if entry is None:
                if self._remove(item):
                    broken += 1
                continue
            entries.append(entry)
        if broken:
            self._drop_note(broken, "corrupt")
        entries.sort(key=lambda e: (e.queued_at, e.seq, e.path.name))
        return entries

    @staticmethod
    def _read(item: Path) -> Entry | None:
        try:
            raw = item.read_bytes()
            data = json.loads(raw.decode("utf-8"))
            queued = datetime.fromisoformat(str(data["queued_at"]))
            if queued.tzinfo is None:
                queued = queued.replace(tzinfo=timezone.utc)
            kind = str(data["kind"])
            body = data["body"]
            if kind not in (KIND_RESULT, KIND_ORDER) or not isinstance(body, dict):
                return None
            return Entry(
                path=item,
                kind=kind,
                body=body,
                queued_at=queued,
                seq=int(data.get("seq") or 0),
                size=len(raw),
                order_id=str(data.get("order_id") or ""),
            )
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _enforce(self, keep: Path | None = None) -> None:
        """Los topes: primero lo caducado, luego lo más viejo hasta que quepa."""
        try:
            entries = self._entries()
            limit = self._clock() - self.max_age
            expired = [e for e in entries if e.queued_at < limit and e.path != keep]
            for entry in expired:
                self._remove(entry.path)
            if expired:
                self._drop_note(len(expired), "age")
            gone = {e.path for e in expired}
            alive = [e for e in entries if e.path not in gone]
            total = sum(e.size for e in alive)
            dropped = 0
            for entry in alive:
                if total <= self.max_bytes:
                    break
                if entry.path == keep:
                    continue
                self._remove(entry.path)
                total -= entry.size
                dropped += 1
            if dropped:
                self._drop_note(dropped, "size")
        except Exception:  # noqa: BLE001
            pass

    def _sweep_leftovers(self) -> None:
        """Temporales de una escritura que no terminó (un corte de luz): fuera."""
        try:
            for item in self.folder.glob(".out-*.tmp"):
                item.unlink(missing_ok=True)
        except OSError:
            pass

    @staticmethod
    def _remove(item: Path) -> bool:
        try:
            item.unlink(missing_ok=True)
        except OSError:
            return False
        return True

    def _drop_note(self, count: int, reason: str) -> None:
        self._notes.append(
            collector_note(
                "outbox",
                "outbox_dropped",
                f"se descartaron {count} envíos pendientes ({reason})",
                count=count,
                reason=reason,
            )
        )


class NullOutbox:
    """An outbox that holds nothing and touches no folder: ``--once``'s.

    `--once` es alguien probando a mano, quizá con el servicio corriendo en la
    misma máquina. La cola de verdad es del servicio: abrirla aquí borraba sus
    temporales a medio escribir (`_sweep_leftovers`) y la vaciaba contra el
    servidor en el primer checkin. `--once` entrega en el acto o falla.
    """

    folder = None

    def put_result(self, body: dict[str, Any]) -> bool:
        return False

    def put_order_answer(self, order_id: str, body: dict[str, Any]) -> bool:
        return False

    def count(self) -> int:
        return 0

    def order_ids(self) -> set[str]:
        return set()

    def take_notes(self) -> list[Note]:
        return []

    def drain(self, send: Callable[[Entry], object], **_kwargs: Any) -> int:
        return 0
