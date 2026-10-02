"""The outbox: what waits on disk until the server answers again."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from agent import outbox as ob
from agent.client import PushError
from agent.control import is_permanent
from agent.outbox import Outbox

T0 = datetime(2026, 10, 2, 9, 0, tzinfo=timezone.utc)


def part(run_id: str, number: int, filler: int = 0) -> dict:
    return {"run": {"id": run_id}, "items": [{"x": "y" * filler}] if filler else [], "part": number, "final": True}


class Clock:
    def __init__(self) -> None:
        self.now = T0

    def __call__(self) -> datetime:
        return self.now


class OutboxTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = Path(tempfile.mkdtemp(prefix="cenya-outbox-")) / "outbox"
        self.clock = Clock()

    def box(self, **kwargs) -> Outbox:  # noqa: ANN003
        return Outbox(self.folder, clock=self.clock, **kwargs)

    def drain_all(self, box: Outbox) -> list[dict]:
        sent: list[dict] = []
        box.drain(lambda entry: sent.append(entry.body))
        return sent


class OrderAndDuplicatesTests(OutboxTestCase):
    def test_entries_go_out_in_the_order_they_were_queued(self) -> None:
        box = self.box()
        box.put_result(part("zzz", 1))
        self.clock.now += timedelta(seconds=1)
        box.put_order_answer("aaa", {"status": "done"})
        self.clock.now += timedelta(seconds=1)
        box.put_result(part("mmm", 2))
        sent = self.drain_all(box)
        self.assertEqual(sent, [part("zzz", 1), {"status": "done"}, part("mmm", 2)])
        self.assertEqual(box.count(), 0)

    def test_the_same_piece_twice_is_one_piece(self) -> None:
        box = self.box()
        box.put_result(part("r", 1))
        box.put_result(part("r", 1))
        box.put_order_answer("o", {"status": "done"})
        box.put_order_answer("o", {"status": "done"})
        self.assertEqual(box.count(), 2)
        self.assertEqual(sorted(p.name for p in self.folder.iterdir()), ["order-o.json", "r-1.json"])

    def test_the_order_survives_a_restart(self) -> None:
        box = self.box()
        for number in range(1, 6):
            box.put_result(part("r", number))  # mismo instante: manda el número de serie
        again = self.box()
        again.put_result(part("s", 1))
        self.assertEqual([body.get("part") for body in self.drain_all(again)], [1, 2, 3, 4, 5, 1])

    def test_a_transient_failure_stops_the_drain_and_keeps_the_rest(self) -> None:
        box = self.box()
        for number in (1, 2, 3):
            box.put_result(part("r", number))
        calls = []

        def send(entry) -> None:  # noqa: ANN001
            calls.append(entry.body["part"])
            if entry.body["part"] == 2:
                raise PushError("caído")

        self.assertEqual(box.drain(send, is_permanent=is_permanent), 1)
        self.assertEqual(calls, [1, 2])
        self.assertEqual([b["part"] for b in self.drain_all(box)], [2, 3])

    def test_a_permanent_refusal_is_dropped_with_a_note(self) -> None:
        box = self.box()
        box.put_result(part("r", 1))
        box.put_result(part("r", 2))

        def send(entry) -> None:  # noqa: ANN001
            if entry.body["part"] == 1:
                raise PushError("400", status=400)

        self.assertEqual(box.drain(send, is_permanent=is_permanent), 1)
        self.assertEqual(box.count(), 0)
        note = box.take_notes()[0]
        self.assertEqual((note.code, note.params["reason"]), ("outbox_dropped", "rejected"))
        self.assertEqual(box.take_notes(), [])

    def test_order_ids_waiting_are_known(self) -> None:
        box = self.box()
        box.put_order_answer("o-1", {"status": "done"})
        box.put_result(part("r", 1))
        self.assertEqual(box.order_ids(), {"o-1"})

    def test_ids_from_the_server_cannot_escape_the_folder(self) -> None:
        box = self.box()
        box.put_order_answer("../../etc/passwd", {"status": "done"})
        box.put_result(part("a/b\\c:d", 1))
        names = [p.name for p in self.folder.iterdir()]
        self.assertEqual(len(names), 2)
        self.assertTrue(all("/" not in n and "\\" not in n and ".." not in n for n in names))
        self.assertEqual(box.order_ids(), {"../../etc/passwd"})


class CapsTests(OutboxTestCase):
    def test_what_is_older_than_a_day_is_dropped_with_a_note(self) -> None:
        box = self.box()
        box.put_result(part("viejo", 1))
        self.clock.now += timedelta(hours=25)
        box.put_result(part("nuevo", 1))
        self.assertEqual([b["run"]["id"] for b in self.drain_all(box)], ["nuevo"])
        notes = box.take_notes()
        self.assertEqual([(n.code, n.params["reason"], n.params["count"]) for n in notes], [("outbox_dropped", "age", 1)])

    def test_age_is_also_enforced_when_draining(self) -> None:
        box = self.box()
        box.put_result(part("viejo", 1))
        self.clock.now += timedelta(hours=25)
        self.assertEqual(self.drain_all(box), [])

    def test_over_the_size_cap_the_oldest_go_first(self) -> None:
        box = self.box(max_bytes=3000)
        for number in range(1, 6):
            self.clock.now += timedelta(seconds=1)
            box.put_result(part("r", number, filler=900))
        kept = [b["part"] for b in self.drain_all(box)]
        self.assertLess(len(kept), 5)
        self.assertEqual(kept, list(range(6 - len(kept), 6)))
        self.assertTrue(any(n.params["reason"] == "size" for n in box.take_notes()))

    def test_a_piece_bigger_than_the_whole_cap_is_not_kept(self) -> None:
        box = self.box(max_bytes=500)
        box.put_result(part("small", 1))
        self.assertFalse(box.put_result(part("huge", 1, filler=2000)))
        self.assertEqual([b["run"]["id"] for b in self.drain_all(box)], ["small"])
        self.assertEqual(box.take_notes()[0].params["reason"], "size")

    def test_the_default_caps_are_the_spec(self) -> None:
        self.assertEqual(ob.MAX_BYTES, 50 * 1024 * 1024)
        self.assertEqual(ob.MAX_AGE, timedelta(hours=24))


class CrashSafetyTests(OutboxTestCase):
    def test_a_half_written_file_is_ignored_and_removed(self) -> None:
        box = self.box()
        box.put_result(part("bueno", 1))
        (self.folder / "roto-1.json").write_text('{"kind": "result", "body": {"ru', encoding="utf-8")
        (self.folder / ".out-abc.tmp").write_text("{", encoding="utf-8")
        again = self.box()  # el arranque siguiente al corte de luz
        self.assertEqual([b["run"]["id"] for b in self.drain_all(again)], ["bueno"])
        self.assertEqual(list(self.folder.iterdir()), [])
        self.assertEqual(again.take_notes()[0].params["reason"], "corrupt")

    def test_a_failed_write_leaves_nothing_behind_and_never_raises(self) -> None:
        box = self.box()
        with mock.patch.object(ob.os, "replace", side_effect=OSError("disco lleno")):
            self.assertFalse(box.put_result(part("r", 1)))
        self.assertEqual(list(self.folder.iterdir()), [])
        self.assertEqual(box.take_notes()[0].params["reason"], "write")

    def test_a_missing_folder_is_an_empty_queue(self) -> None:
        box = Outbox(Path(tempfile.mkdtemp()) / "no" / "existe")
        self.assertEqual(box.count(), 0)
        self.assertEqual(box.drain(lambda entry: None), 0)

    def test_nothing_but_the_body_is_on_disk(self) -> None:
        box = self.box()
        box.put_result(part("r", 1))
        data = json.loads((self.folder / "r-1.json").read_text(encoding="utf-8"))
        self.assertEqual(set(data), {"kind", "order_id", "queued_at", "seq", "body"})


if __name__ == "__main__":
    unittest.main()
