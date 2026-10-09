"""A step that has a host stuck must finish anyway, with what it already had."""

from __future__ import annotations

import threading
import time
import unittest

from agent.collectors import ssh as ssh_collector


class DeadlineTests(unittest.TestCase):
    def test_stuck_host_is_abandoned_and_noted(self) -> None:
        release = threading.Event()

        def visit(item: int) -> int:
            if item == 2:
                release.wait(30)
            return item * 10

        errors: list = []
        started = time.monotonic()
        try:
            out = ssh_collector.map_with_deadline(3, visit, [1, 2, 3], -1, errors, seconds=0.5)
        finally:
            release.set()
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(out, [10, -1, 30])
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].code, "step_timeout")

    def test_all_fine_has_no_note(self) -> None:
        errors: list = []
        self.assertEqual(ssh_collector.map_with_deadline(2, lambda x: x + 1, [1, 2], 0, errors), [2, 3])
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
