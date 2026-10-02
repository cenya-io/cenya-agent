"""The task queue of protocol 2, without a clock: every rule in a millisecond."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from agent import scheduler as sch
from agent.scheduler import Job, Scheduler

T0 = datetime(2026, 10, 2, 9, 0, tzinfo=timezone.utc)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


def config(**every: int) -> dict:
    return {task: {"every_seconds": seconds} for task, seconds in every.items()}


def run(s: Scheduler, now: datetime, *, paused: bool = False, status: str = "ok") -> Job | None:
    """Saca la siguiente tarea y la da por terminada en ese mismo instante."""
    job = s.next_job(now, paused=paused)
    if job is not None:
        s.finished(job, now, status)
    return job


class CadenceTests(unittest.TestCase):
    def test_the_defaults_are_the_ones_of_the_spec(self) -> None:
        self.assertEqual({t: sch.every_seconds({}, t) for t in sch.TASKS}, sch.DEFAULT_EVERY)
        self.assertEqual(sch.every_seconds(None, "presence"), 300)

    def test_presence_and_ups_may_go_every_minute_and_no_faster(self) -> None:
        self.assertEqual(sch.every_seconds(config(presence=1), "presence"), 60)
        self.assertEqual(sch.every_seconds(config(ups=59), "ups"), 60)
        self.assertEqual(sch.every_seconds(config(ups=90), "ups"), 90)

    def test_the_heavy_tasks_go_every_five_minutes_at_most(self) -> None:
        for task in ("inventory", "configs", "hypervisors"):
            self.assertEqual(sch.every_seconds({task: {"every_seconds": 60}}, task), 300)

    def test_nothing_goes_less_often_than_once_a_week(self) -> None:
        self.assertEqual(sch.every_seconds(config(inventory=10**9), "inventory"), 604800)

    def test_zero_switches_a_task_off(self) -> None:
        self.assertEqual(sch.every_seconds(config(configs=0), "configs"), 0)

    def test_rubbish_from_the_server_is_the_default_not_a_crash(self) -> None:
        for raw in ("rápido", None, -5, True, [1], {"x": 1}):
            self.assertEqual(sch.every_seconds({"presence": {"every_seconds": raw}}, "presence"), 300, raw)
        self.assertEqual(sch.every_seconds({"presence": "cada rato"}, "presence"), 300)

    def test_tasks_follow_their_own_cadence(self) -> None:
        s = Scheduler(config(presence=300, inventory=0, configs=0, ups=0, hypervisors=3600))
        self.assertEqual(run(s, at(0)).task, "presence")
        self.assertEqual(run(s, at(0)).task, "hypervisors")
        self.assertIsNone(s.next_job(at(299)))
        self.assertEqual(s.seconds_until_next(at(200)), 100)
        self.assertEqual(run(s, at(300)).task, "presence")
        self.assertIsNone(s.next_job(at(301)))
        # A la hora tocan los dos; la presencia lleva más retraso y va primero.
        self.assertEqual(run(s, at(3600)).task, "presence")
        self.assertEqual(run(s, at(3600)).task, "hypervisors")

    def test_a_disabled_task_never_runs_and_has_no_next_time(self) -> None:
        s = Scheduler(config(presence=300, inventory=0, configs=0, ups=0, hypervisors=0))
        ran = {run(s, at(n * 300)).task for n in range(10)}
        self.assertEqual(ran, {"presence"})
        view = {row["task"]: row for row in s.view(at(0))}
        self.assertIsNone(view["inventory"]["next_at"])
        self.assertEqual(view["inventory"]["every_seconds"], 0)

    def test_everything_off_means_nothing_to_wait_for(self) -> None:
        s = Scheduler(config(presence=0, inventory=0, configs=0, ups=0, hypervisors=0))
        self.assertIsNone(s.next_job(at(0)))
        self.assertIsNone(s.seconds_until_next(at(0)))

    def test_a_new_configuration_changes_the_cadence(self) -> None:
        s = Scheduler(config(presence=300))
        s.configure(config(presence=600))
        self.assertEqual(s.every("presence"), 600)

    def test_the_view_says_what_ran_and_when_it_runs_again(self) -> None:
        s = Scheduler(config(presence=300, inventory=0, configs=0, ups=0, hypervisors=0))
        run(s, at(0), status="partial")
        presence = s.view(at(10))[0]
        self.assertEqual(presence["task"], "presence")
        self.assertEqual(presence["last_status"], "partial")
        self.assertEqual(presence["last_finished_at"], at(0).isoformat())
        self.assertEqual(presence["next_at"], at(300).isoformat())


class PresenceFirstTests(unittest.TestCase):
    def test_stale_presence_forces_a_presence_first(self) -> None:
        s = Scheduler(config(presence=0, inventory=21600, configs=0, ups=0, hypervisors=0))
        first = run(s, at(0))
        self.assertEqual(first, Job("presence"))
        self.assertEqual(run(s, at(1)).task, "inventory")

    def test_fresh_presence_is_two_presence_periods(self) -> None:
        s = Scheduler(config(presence=300, inventory=21600, configs=0, ups=0, hypervisors=0))
        run(s, at(0))  # presencia
        run(s, at(0))  # inventario, con la presencia de ahora mismo
        # La presencia se apaga a mano... no: se queda vieja porque falla el
        # calendario. Se simula dejando de llamar hasta después del inventario.
        s.configure(config(presence=0, inventory=21600, configs=0, ups=0, hypervisors=0))
        self.assertTrue(s.presence_fresh(at(599)))
        self.assertFalse(s.presence_fresh(at(600)))
        self.assertEqual(s.next_job(at(21600)), Job("presence"))

    def test_configs_and_ups_also_need_live_hosts_but_hypervisors_do_not(self) -> None:
        for task in ("configs", "ups"):
            s = Scheduler({**config(presence=0, inventory=0, configs=0, ups=0, hypervisors=0), task: {"every_seconds": 600}})
            self.assertEqual(s.next_job(at(0)).task, "presence", task)
        s = Scheduler(config(presence=0, inventory=0, configs=0, ups=0, hypervisors=3600))
        self.assertEqual(s.next_job(at(0)).task, "hypervisors")

    def test_a_failed_presence_does_not_loop_in_front_of_the_inventory(self) -> None:
        s = Scheduler(config(presence=0, inventory=21600, configs=0, ups=0, hypervisors=0))
        run(s, at(0), status="error")
        self.assertEqual(s.next_job(at(1)).task, "inventory")


class OrderTests(unittest.TestCase):
    def test_an_order_jumps_the_queue(self) -> None:
        s = Scheduler(config(presence=300, inventory=0, configs=0, ups=0, hypervisors=3600))
        s.add_order(Job("hypervisors", sch.TRIGGER_ORDER, order_id="o-1"))
        job = s.next_job(at(0))
        self.assertEqual(job, Job("hypervisors", "order", order_id="o-1"))
        self.assertEqual(s.queued, ())

    def test_orders_keep_their_arrival_order_ahead_of_new_hosts(self) -> None:
        s = Scheduler()
        run(s, at(0))  # presencia fresca
        s.finished(Job("inventory"), at(0), "ok")
        s.add_new_hosts(["10.0.0.9"], at(1))
        s.add_order(Job("hypervisors", "order", order_id="a"))
        s.add_order(Job("presence", "order", order_id="b"))
        self.assertEqual([j.order_id for j in s.queued], ["a", "b", None])

    def test_pause_blocks_scheduled_tasks_but_not_orders(self) -> None:
        s = Scheduler()
        self.assertIsNone(s.next_job(at(0), paused=True))
        self.assertIsNone(s.seconds_until_next(at(0), paused=True))
        s.add_order(Job("presence", "order", order_id="o"))
        self.assertEqual(s.seconds_until_next(at(0), paused=True), 0)
        self.assertEqual(s.next_job(at(0), paused=True).order_id, "o")
        self.assertIsNone(s.next_job(at(0), paused=True))

    def test_an_order_that_needs_presence_brings_it_even_in_pause(self) -> None:
        s = Scheduler()
        s.add_order(Job("inventory", "order", order_id="o"))
        first = s.next_job(at(0), paused=True)
        self.assertEqual(first, Job("presence", "order", order_id="o"))
        s.finished(first, at(0), "ok")
        self.assertEqual(s.next_job(at(1), paused=True), Job("inventory", "order", order_id="o"))

    def test_an_order_moves_the_cadence_like_a_scheduled_run(self) -> None:
        s = Scheduler(config(presence=0, inventory=0, configs=0, ups=0, hypervisors=3600))
        s.add_order(Job("hypervisors", "order", order_id="o"))
        run(s, at(0))
        self.assertIsNone(s.next_job(at(10)))

    def test_pause_lets_nothing_automatic_through(self) -> None:
        s = Scheduler()
        run(s, at(0))
        s.finished(Job("inventory"), at(0), "ok")
        s.add_new_hosts(["10.0.0.9"], at(1))
        self.assertIsNone(s.next_job(at(2), paused=True))


class NewHostTests(unittest.TestCase):
    def fresh(self) -> Scheduler:
        s = Scheduler()
        for task in sch.TASKS:
            s.finished(Job(task), at(0), "ok")
        return s

    def test_a_new_host_triggers_a_targeted_inventory(self) -> None:
        s = self.fresh()
        job = s.add_new_hosts(["10.0.0.9", "10.0.0.9", "10.0.0.7"], at(10))
        self.assertEqual(job, Job("inventory", "new_host", targets=("10.0.0.9", "10.0.0.7")))
        self.assertEqual(s.next_job(at(11)), job)

    def test_a_targeted_inventory_does_not_need_another_presence(self) -> None:
        s = self.fresh()
        s.add_new_hosts(["10.0.0.9"], at(10))
        # Mucho después, con la presencia vieja: los nuevos se inventarían igual.
        self.assertEqual(s.next_job(at(5000)).trigger, "new_host")

    def test_a_targeted_inventory_does_not_move_the_full_one(self) -> None:
        s = self.fresh()
        s.add_new_hosts(["10.0.0.9"], at(10))
        job = s.next_job(at(11))
        s.finished(job, at(12), "ok")
        self.assertEqual(s.next_at("inventory", at(13)), at(21600))

    def test_more_new_hosts_join_the_pending_job(self) -> None:
        s = self.fresh()
        s.add_new_hosts(["10.0.0.9"], at(10))
        merged = s.add_new_hosts(["10.0.0.8", "10.0.0.9"], at(20))
        self.assertEqual(merged.targets, ("10.0.0.9", "10.0.0.8"))
        self.assertEqual(len(s.queued), 1)

    def test_no_targeted_inventory_when_a_full_one_is_coming_anyway(self) -> None:
        s = Scheduler()
        s.finished(Job("presence"), at(0), "ok")
        self.assertIsNone(s.add_new_hosts(["10.0.0.9"], at(1)))  # nunca hubo inventario: toca ya
        s = self.fresh()
        s.add_order(Job("inventory", "order", order_id="o"))
        self.assertIsNone(s.add_new_hosts(["10.0.0.9"], at(1)))

    def test_no_targeted_inventory_when_inventory_is_off(self) -> None:
        s = Scheduler(config(inventory=0))
        s.finished(Job("presence"), at(0), "ok")
        self.assertIsNone(s.add_new_hosts(["10.0.0.9"], at(1)))
        self.assertIsNone(s.add_new_hosts([], at(1)))


class PauseHelpersTests(unittest.TestCase):
    def test_the_later_of_the_two_pauses_wins(self) -> None:
        self.assertEqual(sch.effective_pause(at(10), at(20)), at(20))
        self.assertEqual(sch.effective_pause(None, at(20)), at(20))
        self.assertIsNone(sch.effective_pause(None, None))

    def test_a_pause_in_the_past_is_no_pause(self) -> None:
        self.assertTrue(sch.is_paused(at(0), at(1)))
        self.assertFalse(sch.is_paused(at(1), at(1)))
        self.assertFalse(sch.is_paused(at(0), None))


if __name__ == "__main__":
    unittest.main()
