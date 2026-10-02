"""Tests for the status file and for what the tray icon makes of it.

Everything here is plain Python: the icon's decisions live in
`agent/status.py` precisely so they can be checked without Windows. The Win32
part (`agent/tray.py`) was checked by hand on a desktop.
"""

from __future__ import annotations

import agent.tests  # noqa: F401 - aísla el fichero de estado también bajo `unittest discover`

import json
import os
import struct
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from agent import icons, status
from agent.config import Config

NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)


def iso(delta: timedelta = timedelta()) -> str:
    return (NOW + delta).isoformat()


class StatusFileTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.file = self.dir / "sub" / "status.json"
        patcher = mock.patch.dict(os.environ, {status.ENV_VAR: str(self.file)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def stored(self) -> dict:
        return json.loads(self.file.read_text(encoding="utf-8"))


class WriteReadTests(StatusFileTestCase):
    def test_writes_merge_instead_of_replacing(self) -> None:
        """Cada punto del bucle escribe solo lo suyo: sin fundir, se borrarían."""
        status.write(state="barriendo", step="sweep")
        status.write(step="snmp")

        data = self.stored()
        self.assertEqual(data["state"], "barriendo")
        self.assertEqual(data["step"], "snmp")
        self.assertIn("updated_at", data)

    def test_read_gives_back_what_was_written(self) -> None:
        status.write(state="durmiendo")

        self.assertEqual(status.read()["state"], "durmiendo")

    def test_no_file_or_garbage_reads_as_nothing(self) -> None:
        self.assertIsNone(status.read())
        self.file.parent.mkdir(parents=True)
        self.file.write_text("{esto no es json", encoding="utf-8")
        self.assertIsNone(status.read())

    def test_a_write_leaves_no_temporary_files_behind(self) -> None:
        status.write(state="iniciando")
        status.write(state="durmiendo")

        self.assertEqual(sorted(p.name for p in self.file.parent.iterdir()), ["status.json"])

    def test_a_write_that_cannot_happen_never_raises(self) -> None:
        """Una carpeta que es un fichero, sin permisos, lo que sea: el agente sigue."""
        blocker = self.dir / "no-es-carpeta"
        blocker.write_text("x", encoding="utf-8")
        with mock.patch.dict(os.environ, {status.ENV_VAR: str(blocker / "status.json")}):
            status.write(state="barriendo")  # no lanza

    def test_a_replace_blocked_by_a_reader_is_retried(self) -> None:
        """En Windows, reemplazar el fichero mientras el icono lo lee falla un instante."""
        real_replace = os.replace
        attempts = []

        def flaky(src, dst):
            attempts.append(1)
            if len(attempts) == 1:
                raise PermissionError("en uso")
            return real_replace(src, dst)

        with mock.patch.object(status.os, "replace", side_effect=flaky), mock.patch.object(status, "_sleep"):
            status.write(state="durmiendo")

        self.assertEqual(len(attempts), 2)
        self.assertEqual(self.stored()["state"], "durmiendo")

    def test_the_url_is_stored_without_credentials_in_it(self) -> None:
        status.started(version="0.9.1", url="https://admin:secreto@inventario.local:8443/", interval_seconds=900)

        self.assertEqual(self.stored()["url"], "https://inventario.local:8443/")
        self.assertNotIn("secreto", self.file.read_text(encoding="utf-8"))


class PathTests(unittest.TestCase):
    def test_the_environment_wins(self) -> None:
        with mock.patch.dict(os.environ, {status.ENV_VAR: "/tmp/x/status.json"}):
            self.assertEqual(status.path(), Path("/tmp/x/status.json"))

    def test_on_windows_it_lives_in_programdata(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != status.ENV_VAR}
        env["ProgramData"] = r"D:\ProgramData"
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(status.sys, "platform", "win32"):
            self.assertEqual(status.path(), Path(r"D:\ProgramData") / "Cenya" / "status.json")

    def test_elsewhere_nothing_is_written_unless_asked(self) -> None:
        """En Linux no hay icono que lo lea: no se ensucia ningún disco."""
        env = {k: v for k, v in os.environ.items() if k != status.ENV_VAR}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(status.sys, "platform", "linux"):
            self.assertIsNone(status.path())
            status.write(state="barriendo")  # no-op, no lanza


class LoopReportsTests(StatusFileTestCase):
    """El bucle del agente cuenta lo que hace, sin cambiar lo que hace."""

    def _client(self, heartbeat=None, push=None) -> mock.Mock:
        client = mock.Mock()
        client.heartbeat.return_value = heartbeat or {"interval_seconds": 600, "config": {}}
        client.push_findings.return_value = push or {"created": 2, "refreshed": 5}
        return client

    def test_a_sweep_reports_its_steps_and_its_result(self) -> None:
        from agent import __main__ as loop

        collector = mock.Mock()
        collector.name = "sweep"
        collector.collect.side_effect = lambda ctx: ctx.setdefault("errors", []).append("ssh: sin credenciales") or []
        steps = []
        real_step = status.sweep_step
        with mock.patch.object(loop, "all_collectors", return_value=[collector]), mock.patch.object(
            loop.status, "sweep_step", side_effect=lambda name: (steps.append(name), real_step(name))
        ), mock.patch("builtins.print"):
            loop.sweep(self._client(), Config(url="http://localhost:8000", token="t"))

        data = self.stored()
        self.assertEqual(steps, ["sweep"])
        self.assertEqual(data["state"], "durmiendo")
        self.assertEqual((data["last_sweep_created"], data["last_sweep_refreshed"]), (2, 5))
        self.assertEqual(data["last_sweep_notes"], ["ssh: sin credenciales"])
        self.assertEqual(data["last_error"], "")

    def test_once_does_not_touch_the_status_file(self) -> None:
        """`--once` es alguien probando a mano: no pisa el estado del servicio."""
        from agent import __main__ as loop

        with mock.patch.object(loop, "from_env", return_value=Config(url="http://localhost:8000", token="t")), mock.patch.object(
            loop, "AgentClient", return_value=self._client()
        ), mock.patch.object(loop, "all_collectors", return_value=[]), mock.patch("builtins.print"):
            loop.main(["--once"])

        self.assertFalse(self.file.exists())

    def test_a_failed_push_is_reported_and_the_loop_says_when_it_stops(self) -> None:
        import threading

        from agent import __main__ as loop
        from agent.client import PushError

        event = threading.Event()

        def fail(client, config):
            event.set()
            raise PushError("El servidor respondió 401: Token de agente no válido.")

        with mock.patch.object(loop, "from_env", return_value=Config(url="http://localhost:8000", token="t")), mock.patch.object(
            loop, "AgentClient"
        ), mock.patch.object(loop, "sweep", side_effect=fail), mock.patch("builtins.print"):
            loop.main([], stop_event=event)

        data = self.stored()
        self.assertEqual(data["last_error"], "El servidor respondió 401: Token de agente no válido.")
        self.assertEqual(data["state"], "detenido")
        self.assertEqual(data["stop_reason"], "")

    def test_a_status_retry_does_not_count_as_a_sip_of_the_nap(self) -> None:
        """Visto intermitente en la batería: Windows bloqueó un instante el
        fichero de estado, el reintento durmió, y un test que cuenta las
        esperas de la siesta vio una de más."""
        from agent.__main__ import _nap

        real_replace = os.replace
        calls = []

        def locked_once(src, dst):
            calls.append(1)
            if len(calls) == 1:
                raise PermissionError("bloqueado un instante")
            return real_replace(src, dst)

        client = mock.Mock()
        client.heartbeat.side_effect = [ConnectionError("caído")] * 14
        with mock.patch.object(status.os, "replace", side_effect=locked_once), mock.patch(
            "agent.__main__.time.sleep"
        ) as slept, mock.patch.object(status, "_sleep"):
            _nap(client, interval=900)

        self.assertEqual(slept.call_count, 15)

    def test_every_sip_of_the_nap_proves_it_is_alive(self) -> None:
        from agent.__main__ import _nap

        client = mock.Mock()
        client.heartbeat.side_effect = [ConnectionError("caído"), {"interval_seconds": 180}]
        with mock.patch("agent.__main__.time.sleep"), mock.patch.object(status, "nap_tick") as tick:
            _nap(client, interval=180)

        self.assertEqual(tick.call_count, 2)
        self.assertIn("caído", tick.call_args_list[0].kwargs["error"])
        self.assertNotIn("error", tick.call_args_list[1].kwargs)


# --- Lo que dice el icono --------------------------------------------------------


def fresh(**fields) -> dict:
    base = {
        "state": "durmiendo",
        "version": "0.9.1",
        "url": "https://inventario.local",
        "updated_at": iso(-timedelta(seconds=30)),
        "last_sweep_finished_at": iso(-timedelta(minutes=5)),
        "last_sweep_created": 3,
        "last_sweep_refreshed": 10,
        "last_contact_ok_at": iso(-timedelta(seconds=30)),
        "last_error": "",
        "next_sweep_at": iso(timedelta(minutes=10)),
    }
    base.update(fields)
    return base


class DescribeTests(unittest.TestCase):
    def test_a_fresh_idle_agent_is_green(self) -> None:
        health = status.describe(fresh(), NOW, status.SERVICE_RUNNING)

        self.assertEqual(health.tone, status.OK)
        self.assertEqual(health.headline, "En marcha")
        self.assertTrue(any("10 ya conocidos" in line for line in health.details))

    def test_a_partial_sweep_stays_green_but_is_told(self) -> None:
        """Sin credenciales, parcial es lo normal: naranja para siempre ya no avisaría."""
        health = status.describe(fresh(last_sweep_notes=["ssh: sin credenciales", "winrm: sin credenciales"]), NOW)

        self.assertEqual(health.tone, status.OK)
        self.assertTrue(any("2 avisos" in line for line in health.details))

    def test_sweeping_says_which_step(self) -> None:
        health = status.describe(fresh(state="barriendo", step="snmp"), NOW)

        self.assertEqual(health.tone, status.OK)
        self.assertIn("snmp", " ".join(health.details))

    def test_a_server_that_stopped_answering_is_orange(self) -> None:
        data = fresh(
            last_error="No se pudo hablar con el servidor: timed out",
            last_error_at=iso(-timedelta(seconds=10)),
            last_contact_ok_at=iso(-timedelta(minutes=20)),
        )

        health = status.describe(data, NOW, status.SERVICE_RUNNING)

        self.assertEqual(health.tone, status.WARNING)
        self.assertIn("timed out", health.details[0])

    def test_an_old_error_already_followed_by_a_good_contact_is_green(self) -> None:
        data = fresh(last_error="caído", last_error_at=iso(-timedelta(minutes=3)))

        self.assertEqual(status.describe(data, NOW).tone, status.OK)

    def test_silence_while_idle_is_grey_not_red_nor_green(self) -> None:
        health = status.describe(fresh(updated_at=iso(-timedelta(minutes=10))), NOW, status.SERVICE_RUNNING)

        self.assertEqual(health.tone, status.UNKNOWN)
        self.assertIn("hace 10 minutos", health.details[0])

    def test_a_long_sweep_is_given_time_before_saying_i_dont_know(self) -> None:
        sweeping = fresh(state="barriendo", step="sweep", updated_at=iso(-timedelta(minutes=20)))

        self.assertEqual(status.describe(sweeping, NOW).tone, status.OK)
        sweeping["updated_at"] = iso(-timedelta(minutes=90))
        self.assertEqual(status.describe(sweeping, NOW).tone, status.UNKNOWN)

    def test_a_stopped_service_wins_over_a_file_that_still_looks_fresh(self) -> None:
        health = status.describe(fresh(), NOW, status.SERVICE_STOPPED)

        self.assertEqual(health.tone, status.UNKNOWN)
        self.assertEqual(health.headline, "Agente detenido")

    def test_stopped_by_an_error_is_orange_and_says_why(self) -> None:
        data = fresh(state="detenido", stop_reason="Falta NETINVENTORY_AGENT_TOKEN.")

        health = status.describe(data, NOW, status.SERVICE_STOPPED)

        self.assertEqual(health.tone, status.WARNING)
        self.assertEqual(health.details[0], "Falta NETINVENTORY_AGENT_TOKEN.")

    def test_a_console_agent_without_the_service_is_judged_by_its_file(self) -> None:
        """«No instalado» no es «detenido»: el agente puede correr en una consola."""
        self.assertEqual(status.describe(fresh(), NOW, status.SERVICE_NOT_INSTALLED).tone, status.OK)

    def test_no_file_is_grey_and_explains_which_case(self) -> None:
        for service, headline in (
            (status.SERVICE_STOPPED, "Agente detenido"),
            (status.SERVICE_NOT_INSTALLED, "Servicio no instalado"),
            (None, "Sin datos del agente"),
        ):
            with self.subTest(service=service):
                health = status.describe(None, NOW, service)
                self.assertEqual((health.tone, health.headline), (status.UNKNOWN, headline))

    def test_a_single_minute_and_many_are_worded_by_the_plural_rule(self) -> None:
        one = status.describe(fresh(updated_at=iso(-timedelta(minutes=61))), NOW)
        self.assertIn("hace 1 hora", one.details[0])
        several = status.describe(fresh(updated_at=iso(-timedelta(hours=3))), NOW)
        self.assertIn("hace 3 horas", several.details[0])


class TrayDecisionTests(unittest.TestCase):
    def test_the_tooltip_fits_windows_limit(self) -> None:
        health = status.Health(status.WARNING, "x" * 300)

        self.assertLessEqual(len(status.tooltip(health)), status.TOOLTIP_MAX)

    def test_notify_only_when_turning_to_warning(self) -> None:
        self.assertTrue(status.should_notify(None, status.WARNING))
        self.assertTrue(status.should_notify(status.OK, status.WARNING))
        self.assertFalse(status.should_notify(status.WARNING, status.WARNING))
        self.assertFalse(status.should_notify(status.OK, status.UNKNOWN))
        self.assertFalse(status.should_notify(None, status.OK))

    def test_only_http_urls_are_opened(self) -> None:
        cases = {
            "https://inventario.local": "https://inventario.local/settings/agents/",
            "http://10.0.0.5:8000/": "http://10.0.0.5:8000/settings/agents/",
            "https://inventario.local/netinventory/": "https://inventario.local/netinventory/settings/agents/",
            "https://admin:secreto@inventario.local": "https://inventario.local/settings/agents/",
            "https://[fe80::1]:8443": "https://[fe80::1]:8443/settings/agents/",
            "file:///C:/Windows/System32/calc.exe": None,
            "javascript:alert(1)": None,
            "https://": None,
            "": None,
        }
        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(status.settings_url({"url": url}), expected)
        self.assertIsNone(status.settings_url(None))


class IconTests(unittest.TestCase):
    def test_the_resource_is_a_32_bit_dib_of_the_asked_size(self) -> None:
        for size in (16, 24, 32):
            with self.subTest(size=size):
                data = icons.icon_resource(size, status.OK)
                header = struct.unpack("<IiiHHIIiiII", data[:40])
                self.assertEqual(header[:5], (40, size, size * 2, 1, 32))
                mask = ((size + 31) // 32) * 4 * size
                self.assertEqual(len(data), 40 + size * size * 4 + mask)

    def test_each_tone_draws_its_own_dot(self) -> None:
        size = 32
        centre = int(size * 0.78) * size + int(size * 0.78)
        for tone, colour in icons.TONE_COLORS.items():
            with self.subTest(tone=tone):
                r, g, b, a = icons.render_rgba(size, tone)[centre]
                self.assertEqual((r, g, b, a), (*colour, 255))

    def test_the_corners_are_transparent(self) -> None:
        """Esquinas redondeadas: sin alfa, se vería un cuadrado negro en la bandeja."""
        pixels = icons.render_rgba(16, status.OK)
        self.assertEqual(pixels[0][3], 0)
        self.assertEqual(pixels[15][3], 0)

    def test_the_mark_is_the_app_icon_navy_with_sky_layers(self) -> None:
        size = 32
        pixels = icons.render_rgba(size, status.OK)
        # El centro de la capa de arriba: (50, 27) en el símbolo.
        dx, dy = icons.LAYER_OFFSET
        row = int((dy + icons.LAYER_SCALE * 27) * size / 100)
        top_layer = pixels[row * size + size // 2]
        near_edge = pixels[3 * size + 3]
        self.assertEqual(top_layer[:3], icons.LAYERS[0])
        self.assertEqual(near_edge[:3], icons.BACKGROUND)


class TrayModuleTests(unittest.TestCase):
    def test_the_tray_and_the_service_agree_on_the_service_name(self) -> None:
        if sys.platform != "win32":
            self.skipTest("agent.tray solo existe en Windows")
        try:
            import win32gui  # noqa: F401
        except ImportError:
            self.skipTest("sin pywin32")
        from agent import tray, winservice

        self.assertEqual(tray.SERVICE_NAME, winservice.SERVICE_NAME)


if __name__ == "__main__":
    unittest.main()
