"""El colector SSH y el transporte que hay debajo, sin red y sin subprocesos.

Las fixturas son salida de verdad: un Ubuntu con `ip -o link`, un Cisco IOS
contestando a `show version` y un MikroTik contestando a `/system ... print`.
Lo que se prueba aquí es sobre todo el parseo --donde se esconden los fallos
silenciosos-- y el contrato de degradación: un colector que no puede correr
anota una línea y devuelve `[]`, nunca lanza.
"""

from __future__ import annotations

import subprocess
import unittest
from typing import Any
from unittest import mock

from agent import notes, ssh
from agent.tests import test_stacks
from agent.credentials import Credential
from agent.collectors import ssh as ssh_collector
from agent.collectors.ssh import (
    LINUX_COMMAND,
    MARK,
    SshCollector,
    interrogate,
    parse_cisco,
    parse_linux,
    parse_mikrotik,
)

# --- Fixturas -------------------------------------------------------------------

#: Un Ubuntu 22.04 virtualizado, con la salida troceada por las marcas que pone
#: el propio comando. `ens19` está levantada pero sin cable (`NO-CARRIER`), que
#: es el caso que distingue «flag administrativa» de «estado del enlace».
LINUX_UBUNTU = r"""@@netinv:uname
Linux 5.15.0-91-generic
@@netinv:os
NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 22.04.3 LTS"
VERSION_ID="22.04"
HOME_URL="https://www.ubuntu.com/"
@@netinv:host
srv-ficheros
@@netinv:link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: ens18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:1a:2b:3c brd ff:ff:ff:ff:ff:ff
3: ens19: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN mode DEFAULT group default qlen 1000\    link/ether 52:54:00:1a:2b:3d brd ff:ff:ff:ff:ff:ff
4: ens18.100@ens18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default qlen 1000\    link/ether 52:54:00:1a:2b:3c brd ff:ff:ff:ff:ff:ff
@@netinv:addr
1: lo    inet 127.0.0.1/8 scope host lo\       valid_lft forever preferred_lft forever
2: ens18    inet 192.168.1.50/24 brd 192.168.1.255 scope global ens18\       valid_lft forever preferred_lft forever
4: ens18.100    inet 10.20.100.50/24 brd 10.20.100.255 scope global ens18.100\       valid_lft forever preferred_lft forever
@@netinv:vendor
QEMU
@@netinv:model
Standard PC (i440FX + PIIX, 1996)
@@netinv:serial
"""

#: Un servidor físico donde el agente **no** corre como root: `product_serial`
#: solo lo lee root, así que la sección llega vacía. El resto sí se lee.
LINUX_SIN_PERMISO_DE_SERIE = r"""@@netinv:uname
Linux 4.18.0-513.5.1.el8_9.x86_64
@@netinv:os
NAME="Rocky Linux"
VERSION="8.9 (Green Obsidian)"
PRETTY_NAME="Rocky Linux 8.9 (Green Obsidian)"
@@netinv:host
srv-copias.acme.local
@@netinv:link
2: eno1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\    link/ether b0:83:fe:11:22:33 brd ff:ff:ff:ff:ff:ff
@@netinv:addr
2: eno1    inet 192.168.1.60/24 brd 192.168.1.255 scope global noprefixroute eno1\       valid_lft forever preferred_lft forever
@@netinv:vendor
Dell Inc.
@@netinv:model
PowerEdge R340
@@netinv:serial
"""

#: Un clónico de tienda: el DMI trae los rellenos de fábrica en vez de datos.
LINUX_CON_RELLENOS_DE_FABRICA = r"""@@netinv:uname
Linux 6.1.0-18-amd64
@@netinv:os
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
@@netinv:host
pc-recepcion
@@netinv:link
2: enp3s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\    link/ether 3c:7c:3f:aa:bb:cc brd ff:ff:ff:ff:ff:ff
@@netinv:addr
2: enp3s0    inet 192.168.1.70/24 brd 192.168.1.255 scope global enp3s0\       valid_lft forever preferred_lft forever
@@netinv:vendor
To Be Filled By O.E.M.
@@netinv:model
Default string
@@netinv:serial
System Serial Number
"""

#: Lo que devuelve un IOS cuando se le manda el comando de Linux: no lo entiende
#: y contesta con su propio error. Ni una marca, así que no es de esta familia.
IOS_RECHAZA_EL_COMANDO_DE_LINUX = (
    'Line has invalid autocommand "echo @@netinv:uname; uname -sr; '
    'echo @@netinv:os; cat /etc/os-release"\n'
)

#: `show version` de un Catalyst 2960X, recortado por donde no aporta.
CISCO_SHOW_VERSION = """Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(4)E7, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2018 by Cisco Systems, Inc.
Compiled Tue 18-Sep-18 13:07 by prod_rel_team

ROM: Bootstrap program is C2960X boot loader
BOOTLDR: C2960X Boot Loader (C2960X-HBOOT-M) Version 15.2(4r)E1, RELEASE SOFTWARE (fc1)

sw-planta-1 uptime is 1 year, 12 weeks, 3 days, 4 hours, 55 minutes
System returned to ROM by power-on
System image file is "flash:/c2960x-universalk9-mz.152-4.E7.bin"

cisco WS-C2960X-24TS-L (APM86XXX) processor (revision D0) with 131072K bytes of memory.
Processor board ID FOC1925X0AB
Last reset from power-on

Base ethernet MAC Address       : 00:1B:2A:3C:4D:5E
Motherboard assembly number     : 73-15884-07
Power supply part number        : 341-0097-03
Motherboard serial number       : FOC19259AAA
Power supply serial number      : LIT19180BBB
Model revision number           : D0
Motherboard revision number     : A0
Model number                    : WS-C2960X-24TS-L
System serial number            : FOC1925X0AB
Top Assembly Part Number        : 800-41791-02

Configuration register is 0xF
"""

#: Lo que contesta RouterOS a un comando que no conoce.
MIKROTIK_RECHAZA = "bad command name echo (line 1 column 1)\n"

#: `/system resource print; /system identity print; /system routerboard print`
#: seguidos, tal cual salen por la consola de RouterOS.
MIKROTIK_PRINT = """                   uptime: 3w4d13h4m9s
                  version: 6.48.6 (stable)
               build-time: Aug/03/2021 14:24:52
              free-memory: 108.4MiB
             total-memory: 128.0MiB
                      cpu: MIPS 74Kc V4.12
                cpu-count: 1
            cpu-frequency: 650MHz
                 cpu-load: 1%
           free-hdd-space: 3.9MiB
          total-hdd-space: 16.0MiB
        architecture-name: mipsbe
               board-name: RB951G-2HnD
                 platform: MikroTik

  name: rt-oficina

       routerboard: yes
             model: RouterBOARD 951G-2HnD
     serial-number: 5D48047C4E1F
     firmware-type: ar9344L
  factory-firmware: 3.19
  current-firmware: 6.48.6
"""


# --- Parseo de Linux --------------------------------------------------------------


class LinuxParsingTests(unittest.TestCase):
    def test_a_real_ubuntu_becomes_a_full_record(self) -> None:
        data = parse_linux(LINUX_UBUNTU)

        self.assertEqual(data["hostname"], "srv-ficheros")
        # El nombre bonito de `/etc/os-release` gana al `uname`, que es más pobre.
        self.assertEqual(data["description"], "Ubuntu 22.04.3 LTS")
        self.assertEqual(data["manufacturer"], "QEMU")
        self.assertEqual(data["model"], "Standard PC (i440FX + PIIX, 1996)")

    def test_the_loopback_never_becomes_an_inventory_interface(self) -> None:
        """`lo` está en todas las máquinas, con la misma dirección, y no lleva a
        ningún sitio: colarla son tantas interfaces falsas como equipos."""
        names = [iface["name"] for iface in parse_linux(LINUX_UBUNTU)["interfaces"]]

        self.assertNotIn("lo", names)
        self.assertEqual(names, ["ens18", "ens19", "ens18.100"])

    def test_each_interface_carries_its_mac_and_its_address(self) -> None:
        by_name = {iface["name"]: iface for iface in parse_linux(LINUX_UBUNTU)["interfaces"]}

        self.assertEqual(by_name["ens18"]["mac"], "52:54:00:1a:2b:3c")
        self.assertEqual(by_name["ens18"]["ip"], "192.168.1.50")
        # Una interfaz sin dirección no inventa una: vacío es vacío.
        self.assertEqual(by_name["ens19"]["ip"], "")

    def test_a_vlan_interface_keeps_its_name_and_not_its_parents(self) -> None:
        """`ip -o link` escribe las VLAN como `ens18.100@ens18`. Quedarse con la
        parte de después de la arroba las fusionaría todas con la interfaz
        padre y la dirección de la VLAN acabaría colgada de la física."""
        by_name = {iface["name"]: iface for iface in parse_linux(LINUX_UBUNTU)["interfaces"]}

        self.assertIn("ens18.100", by_name)
        self.assertEqual(by_name["ens18.100"]["ip"], "10.20.100.50")

    def test_an_interface_that_is_up_but_unplugged_reads_as_up(self) -> None:
        """Criterio actual: la bandera administrativa (`UP` entre los flags), no
        el estado del enlace. `ens19` tiene `NO-CARRIER ... state DOWN` y sale
        como «up» porque el administrador la dejó levantada.

        Se fija aquí a propósito para que un cambio de criterio sea deliberado:
        el colector SNMP usa `ifOperStatus`, que diría «down» para esta misma.
        """
        by_name = {iface["name"]: iface for iface in parse_linux(LINUX_UBUNTU)["interfaces"]}

        self.assertEqual(by_name["ens18"]["status"], "up")
        self.assertEqual(by_name["ens19"]["status"], "up")

    def test_a_serial_that_needs_root_comes_out_empty_and_not_broken(self) -> None:
        """El agente no corre como root en casi ningún sitio: `product_serial`
        llega vacío y el resto de la ficha tiene que salir igualmente."""
        data = parse_linux(LINUX_SIN_PERMISO_DE_SERIE)

        self.assertEqual(data["serial"], "")
        self.assertEqual(data["manufacturer"], "Dell Inc.")
        self.assertEqual(data["model"], "PowerEdge R340")

    def test_the_factory_placeholders_are_dropped_instead_of_stored(self) -> None:
        """«Default string» y «System Serial Number» parecen un dato y no lo son:
        guardarlos llena el inventario de series duplicadas que no existen."""
        data = parse_linux(LINUX_CON_RELLENOS_DE_FABRICA)

        self.assertEqual(data["manufacturer"], "")
        self.assertEqual(data["model"], "")
        self.assertEqual(data["serial"], "")
        self.assertEqual(data["hostname"], "pc-recepcion")

    def test_a_device_that_does_not_understand_uname_is_not_a_linux(self) -> None:
        """Sin esto, un switch se daría por Linux con todos los campos vacíos y
        la familia Cisco no llegaría a probarse nunca."""
        self.assertEqual(parse_linux(IOS_RECHAZA_EL_COMANDO_DE_LINUX), {})
        self.assertEqual(parse_linux(MIKROTIK_RECHAZA), {})
        self.assertEqual(parse_linux(CISCO_SHOW_VERSION), {})
        self.assertEqual(parse_linux(""), {})

    def test_the_marker_is_not_a_shell_comment(self) -> None:
        """Con `#` delante, el `echo` no imprime nada y la salida llega entera y
        sin trocear: el parseo devolvía vacío contra un Linux perfectamente sano.
        """
        self.assertFalse(MARK.startswith("#"))
        self.assertIn(f"echo {MARK}uname", LINUX_COMMAND)
        self.assertNotIn("#", LINUX_COMMAND)


# --- Parseo de equipos de red -----------------------------------------------------


class CiscoParsingTests(unittest.TestCase):
    def test_a_catalyst_gives_name_version_model_and_serial(self) -> None:
        data = parse_cisco(CISCO_SHOW_VERSION)

        self.assertEqual(data["hostname"], "sw-planta-1")
        self.assertEqual(data["manufacturer"], "Cisco")
        self.assertEqual(data["model"], "WS-C2960X-24TS-L")
        self.assertEqual(data["serial"], "FOC1925X0AB")
        self.assertIn("Version 15.2(4)E7", data["description"])

    def test_the_model_is_not_confused_with_the_revision_number(self) -> None:
        """«Model revision number» va antes que «Model number» en la salida real
        y las dos líneas se parecen: coger la primera guardaría «D0» de modelo.
        """
        self.assertEqual(parse_cisco(CISCO_SHOW_VERSION)["model"], "WS-C2960X-24TS-L")

    def test_a_cisco_does_not_claim_interfaces_it_did_not_report(self) -> None:
        """`show version` no las da: inventarlas vacías crearía puertos falsos.
        En un equipo de red las interfaces las trae SNMP, que además no entra."""
        self.assertEqual(parse_cisco(CISCO_SHOW_VERSION)["interfaces"], [])

    def test_anything_that_is_not_a_cisco_is_left_for_the_next_family(self) -> None:
        self.assertEqual(parse_cisco(MIKROTIK_PRINT), {})
        self.assertEqual(parse_cisco("bash: show: command not found"), {})
        self.assertEqual(parse_cisco(""), {})


class MikrotikParsingTests(unittest.TestCase):
    def test_routeros_gives_name_version_board_and_serial(self) -> None:
        data = parse_mikrotik(MIKROTIK_PRINT)

        self.assertEqual(data["hostname"], "rt-oficina")
        self.assertEqual(data["manufacturer"], "MikroTik")
        self.assertEqual(data["model"], "RouterBOARD 951G-2HnD")
        self.assertEqual(data["serial"], "5D48047C4E1F")
        self.assertEqual(data["description"], "MikroTik RouterOS 6.48.6 (stable)")

    def test_the_error_of_a_command_it_does_not_know_is_not_a_record(self) -> None:
        self.assertEqual(parse_mikrotik(MIKROTIK_RECHAZA), {})
        self.assertEqual(parse_mikrotik(""), {})

    def test_a_cisco_output_is_not_mistaken_for_routeros(self) -> None:
        """Las dos salidas son pares `clave: valor`; sin exigir `version` o
        `board-name`, un Catalyst saldría del inventario como un MikroTik."""
        self.assertEqual(parse_mikrotik(CISCO_SHOW_VERSION), {})


# --- Elegir familia y credencial --------------------------------------------------


class _FakeSsh:
    """Un `ssh.run` de mentira: contesta según el comando que se le manda."""

    def __init__(self, answers: dict[str, ssh.Answer], default: ssh.Answer | None = None) -> None:
        self.answers = answers
        self.default = default or ssh.Answer(connected=True, output="")
        self.calls: list[tuple[str, str]] = []

    def __call__(self, **kwargs: Any) -> ssh.Answer:
        command = str(kwargs.get("command", ""))
        self.calls.append((str(kwargs.get("username", "")), command))
        for marker, answer in self.answers.items():
            if marker in command:
                return answer
        return self.default


class FamilyChoiceTests(unittest.TestCase):
    ROOT = Credential(kind="ssh", username="root", key_file="/home/agente/.ssh/id_ed25519")

    def _interrogate(self, fake: _FakeSsh, credentials: list[Credential] | None = None) -> dict:
        with mock.patch("agent.collectors.ssh.ssh.run", fake):
            data, _credential = interrogate("192.168.1.50", credentials or [self.ROOT])
        return data

    def test_a_linux_answers_the_first_try_and_the_rest_is_not_asked(self) -> None:
        fake = _FakeSsh({"uname": ssh.Answer(connected=True, output=LINUX_UBUNTU)})

        data = self._interrogate(fake)

        self.assertEqual(data["family"], "linux")
        self.assertEqual(data["hostname"], "srv-ficheros")
        self.assertEqual(len(fake.calls), 1)

    def test_a_switch_falls_through_to_the_family_that_does_understand_it(self) -> None:
        """El banner miente y cada versión lo cambia, así que la familia se
        decide por quién sabe leer la respuesta, no por quién dice ser."""
        fake = _FakeSsh(
            {
                "uname": ssh.Answer(connected=True, output=IOS_RECHAZA_EL_COMANDO_DE_LINUX),
                "show version": ssh.Answer(connected=True, output=CISCO_SHOW_VERSION),
            }
        )

        data = self._interrogate(fake)

        self.assertEqual(data["family"], "cisco")
        self.assertEqual(data["serial"], "FOC1925X0AB")

    def test_a_mikrotik_is_reached_after_the_three_before_it(self) -> None:
        fake = _FakeSsh(
            {
                "uname": ssh.Answer(connected=True, output=MIKROTIK_RECHAZA),
                "show version": ssh.Answer(connected=True, output="bad command name show (line 1 column 1)"),
                "display version": ssh.Answer(connected=True, output="bad command name display (line 1 column 1)"),
                "/system resource print": ssh.Answer(connected=True, output=MIKROTIK_PRINT),
            }
        )

        data = self._interrogate(fake)

        self.assertEqual(data["family"], "mikrotik")
        self.assertEqual(data["hostname"], "rt-oficina")
        # Linux, «show version», «display version» y por fin RouterOS: el
        # orden de FAMILIES es también la cuenta de conexiones.
        self.assertEqual(len(fake.calls), 4)

    def test_the_first_credential_that_gets_in_stops_the_probing(self) -> None:
        """En un Directorio Activo cada intento fallido cuenta para la política
        de bloqueo: seguir probando después de haber entrado bloquea cuentas.
        """
        good = ssh.Answer(connected=True, output=LINUX_UBUNTU)

        def fake(**kwargs: Any) -> ssh.Answer:
            fake.calls.append(kwargs["username"])  # type: ignore[attr-defined]
            if kwargs["username"] == "malo":
                return ssh.Answer(connected=False, error="Permission denied (publickey,password).")
            return good

        fake.calls = []  # type: ignore[attr-defined]
        credentials = [
            Credential(kind="ssh", username="malo"),
            Credential(kind="ssh", username="root"),
            Credential(kind="ssh", username="nunca"),
        ]

        with mock.patch("agent.collectors.ssh.ssh.run", fake):
            data, credential = interrogate("192.168.1.50", credentials)

        self.assertEqual(data["hostname"], "srv-ficheros")
        self.assertNotIn("nunca", fake.calls)  # type: ignore[attr-defined]
        # La credencial que entró vuelve con los datos: es la que reutiliza la
        # captura de configuración, sin volver a probar las demás.
        self.assertEqual(credential.username, "root")

    def test_getting_in_and_understanding_nothing_does_not_burn_more_credentials(self) -> None:
        """Si la credencial entró, la credencial vale: lo que no encaja es la
        familia. Probar la siguiente serían intentos fallidos de más."""
        fake = _FakeSsh({}, default=ssh.Answer(connected=True, output="un cacharro raro"))
        credentials = [Credential(kind="ssh", username="root"), Credential(kind="ssh", username="nunca")]

        data = self._interrogate(fake, credentials)

        self.assertEqual(data, {})
        self.assertEqual({username for username, _ in fake.calls}, {"root"})

    def test_a_host_nobody_can_enter_is_nothing_and_not_a_crash(self) -> None:
        fake = _FakeSsh({}, default=ssh.Answer(connected=False, error="Connection refused"))

        self.assertEqual(self._interrogate(fake), {})


# --- El transporte ----------------------------------------------------------------


class ArgvTests(unittest.TestCase):
    def test_unattended_means_batch_mode(self) -> None:
        """Sin `BatchMode=yes`, un host que pide contraseña deja el proceso
        esperando hasta el tope duro, uno detrás de otro."""
        argv = ssh.argv_for(host="10.0.0.5", username="root", command="uname -a")

        self.assertIn("BatchMode=yes", argv)
        self.assertIn("StrictHostKeyChecking=accept-new", argv)
        self.assertEqual(argv[-1], "uname -a")

    def test_a_key_is_offered_alone_so_the_agent_keys_do_not_burn_the_attempts(self) -> None:
        argv = ssh.argv_for(host="10.0.0.5", username="root", key_file="/k/id_ed25519", command="x")

        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertIn("/k/id_ed25519", argv)

    def test_the_default_port_is_not_written_out(self) -> None:
        self.assertNotIn("-p", ssh.argv_for(host="10.0.0.5", username="root", port=22, command="x"))
        self.assertIn("-p", ssh.argv_for(host="10.0.0.5", username="root", port=2222, command="x"))

    def test_with_a_password_the_batch_mode_has_to_come_off(self) -> None:
        """Con `BatchMode=yes` puesto, `ssh` ni intenta la autenticación por
        contraseña y `sshpass` no tendría a quién dársela."""
        argv = ssh.argv_for(host="10.0.0.5", username="root", with_password=True, command="x")

        self.assertEqual(argv[:2], ["sshpass", "-e"])
        self.assertIn("BatchMode=no", argv)
        self.assertIn("NumberOfPasswordPrompts=1", argv)


class RunTests(unittest.TestCase):
    def _run(self, completed: Any, *, sshpass: bool = False, secret: str = "") -> tuple[ssh.Answer, dict]:
        captured: dict[str, Any] = {}

        def fake_run(argv: list[str], **kwargs: Any) -> Any:
            captured["argv"] = argv
            captured.update(kwargs)
            if isinstance(completed, BaseException):
                raise completed
            return completed

        with mock.patch("agent.ssh.SSHPASS_AVAILABLE", sshpass), \
             mock.patch("agent.ssh.ASKPASS_AVAILABLE", False), \
             mock.patch("agent.ssh.subprocess.run", fake_run):
            answer = ssh.run(host="10.0.0.5", username="root", secret=secret, command="uname -sr")
        return answer, captured

    def test_the_password_travels_in_the_environment_and_never_in_the_command_line(self) -> None:
        """En la línea de órdenes la ve cualquiera con un `ps` en la máquina
        donde corre el agente, que es la del cliente."""
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

        answer, captured = self._run(completed, sshpass=True, secret="ultrasecreta")

        self.assertTrue(answer.connected)
        self.assertNotIn("ultrasecreta", " ".join(captured["argv"]))
        self.assertEqual(captured["env"]["SSHPASS"], "ultrasecreta")

    def test_without_sshpass_the_secret_is_not_even_put_in_the_environment(self) -> None:
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

        _, captured = self._run(completed, sshpass=False, secret="ultrasecreta")

        self.assertNotIn("SSHPASS", captured["env"])
        self.assertNotIn("sshpass", captured["argv"])

    def test_output_the_console_cannot_decode_does_not_kill_the_sweep(self) -> None:
        """Un equipo con la salida en otra página de códigos lanzaría
        `UnicodeDecodeError`, que no es de los que se capturan aquí abajo."""
        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="ok", stderr="")

        _, captured = self._run(completed)

        self.assertEqual(captured["errors"], "replace")
        self.assertTrue(captured["text"])

    def test_a_timeout_is_an_answer_and_not_an_exception(self) -> None:
        """Un equipo que acepta el TCP y luego calla cuelga la conexión, no la
        corta: sin el tope duro el barrido se queda ahí."""
        answer, _ = self._run(subprocess.TimeoutExpired(cmd="ssh", timeout=20))

        self.assertFalse(answer.connected)
        self.assertIn("tiempo de espera", answer.error)

    def test_a_missing_binary_is_an_answer_and_not_an_exception(self) -> None:
        answer, _ = self._run(FileNotFoundError(2, "No such file or directory", "ssh"))

        self.assertFalse(answer.connected)
        self.assertTrue(answer.error)

    def test_sshs_own_failure_code_means_it_did_not_get_in(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=ssh.SSH_FAILURE_CODE,
            stdout="",
            stderr="root@10.0.0.5: Permission denied (publickey).\nbanner exchange\n",
        )

        answer, _ = self._run(completed)

        self.assertFalse(answer.connected)
        # Solo la primera línea: el resto son avisos que no explican nada.
        self.assertEqual(answer.error, "root@10.0.0.5: Permission denied (publickey).")

    def test_a_password_run_uses_exactly_one_authentication_method(self) -> None:
        """Con `keyboard-interactive` y `password` ofrecidos, `ssh` probaba los
        dos: dos inicios fallidos por contraseña equivocada."""
        argv = ssh.argv_for(host="h", username="u", with_password=True, askpass=True)
        options = [argv[i + 1] for i, part in enumerate(argv) if part == "-o"]

        self.assertIn("PreferredAuthentications=password", options)
        for off in (
            "PubkeyAuthentication=no",
            "KbdInteractiveAuthentication=no",
            "GSSAPIAuthentication=no",
            "HostbasedAuthentication=no",
        ):
            self.assertIn(off, options)
        self.assertIn("PasswordAuthentication=yes", options)
        self.assertIn("NumberOfPasswordPrompts=1", options)

    def test_the_keyboard_interactive_run_turns_password_off(self) -> None:
        argv = ssh.argv_for(host="h", username="u", with_password=True, askpass=True, method="keyboard-interactive")
        options = [argv[i + 1] for i, part in enumerate(argv) if part == "-o"]

        self.assertIn("PreferredAuthentications=keyboard-interactive", options)
        self.assertIn("KbdInteractiveAuthentication=yes", options)
        self.assertIn("PasswordAuthentication=no", options)

    def _runs(self, stderrs: list[str]) -> list[list[str]]:
        calls: list[list[str]] = []

        def fake_run(argv: list[str], **kwargs: Any) -> Any:
            calls.append(argv)
            return subprocess.CompletedProcess(args=argv, returncode=255, stdout="", stderr=stderrs[len(calls) - 1])

        with mock.patch("agent.ssh.ASKPASS_AVAILABLE", True), mock.patch("agent.ssh.ASKPASS", "askpass"), \
             mock.patch("agent.ssh.subprocess.run", fake_run):
            answer = ssh.run(host="10.0.0.5", username="admin", secret="mala", command="show version")
        self.assertFalse(answer.connected)
        return calls

    def test_a_refused_password_is_not_retried(self) -> None:
        calls = self._runs(["admin@10.0.0.5: Permission denied (publickey,keyboard-interactive,password).\n"])

        self.assertEqual(len(calls), 1)

    def test_without_password_on_offer_it_retries_once_by_keyboard_interactive(self) -> None:
        calls = self._runs([
            "** WARNING: connection is not using a post-quantum key exchange algorithm.\n"
            "admin@10.0.0.5: Permission denied (publickey,keyboard-interactive).\n",
            "admin@10.0.0.5: Permission denied (publickey,keyboard-interactive).\n",
        ])

        self.assertEqual(len(calls), 2)
        self.assertIn("PreferredAuthentications=keyboard-interactive", calls[1])

    def test_a_connection_failure_is_not_retried(self) -> None:
        calls = self._runs(["ssh: connect to host 10.0.0.5 port 22: Connection refused\n"])

        self.assertEqual(len(calls), 1)

    def test_the_reason_skips_the_post_quantum_warning(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=ssh.SSH_FAILURE_CODE,
            stdout="",
            stderr="** WARNING: connection is not using a post-quantum key exchange algorithm.\n"
            "root@10.0.0.5: Permission denied (password).\n",
        )

        answer, _ = self._run(completed)

        self.assertEqual(answer.error, "root@10.0.0.5: Permission denied (password).")

    def test_a_remote_command_that_failed_still_counts_as_getting_in(self) -> None:
        """«No me dejó entrar» y «entré y ese comando no existe ahí» son cosas
        distintas: confundirlas hace probar credenciales de más contra un
        equipo donde ya se había entrado."""
        completed = subprocess.CompletedProcess(
            args=[], returncode=127, stdout="", stderr="bash: uname: command not found"
        )

        answer, _ = self._run(completed)

        self.assertTrue(answer.connected)


# --- El colector ------------------------------------------------------------------


class SshCollectorTests(unittest.TestCase):
    HOSTS = [
        {"ip": "192.168.1.50", "mac": "52:54:00:1a:2b:3c"},
        {"ip": "192.168.1.60", "mac": "b0:83:fe:11:22:33"},
    ]

    def _ctx(self, **extra: Any) -> dict:
        ctx: dict[str, Any] = {
            "config": {"credentials": [{"kind": "ssh", "username": "root", "key_file": "/k"}]},
            "env": None,
            "hosts": list(self.HOSTS),
        }
        ctx.update(extra)
        return ctx

    def _collect(self, ctx: dict, *, listening: list[str] | None = None, answers: dict | None = None):
        replies = answers if answers is not None else {"192.168.1.50": LINUX_UBUNTU}
        reachable = listening if listening is not None else list(replies)

        def fake_run(**kwargs: Any) -> ssh.Answer:
            output = replies.get(kwargs["host"], "")
            return ssh.Answer(connected=bool(output), output=output)

        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", return_value=reachable), \
             mock.patch("agent.collectors.ssh.ssh.run", fake_run):
            return SshCollector().collect(ctx)

    def test_without_the_ssh_binary_it_reports_and_returns_nothing(self) -> None:
        ctx = self._ctx()
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", False):
            self.assertEqual(SshCollector().collect(ctx), [])

        self.assertTrue(any("ssh" in line for line in ctx["errors"]))

    def test_running_before_the_sweep_complains_instead_of_going_quiet(self) -> None:
        """El mismo fallo que dejó SNMP mudo en producción: sin `ctx["hosts"]`
        no hay a quién llamar y callarse marca la ejecución como correcta."""
        ctx = self._ctx()
        ctx.pop("hosts")

        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True):
            self.assertEqual(SshCollector().collect(ctx), [])

        self.assertTrue(any("barrido no ha corrido" in line for line in ctx["errors"]))

    def test_without_credentials_it_says_where_to_put_them(self) -> None:
        ctx = self._ctx(config={})
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True):
            self.assertEqual(SshCollector().collect(ctx), [])

        self.assertTrue(any("Ajustes" in line for line in ctx["errors"]))

    def test_a_password_without_sshpass_is_said_out_loud(self) -> None:
        """Sin el aviso el usuario ve «no ha entrado en ningún Linux» y no tiene
        forma de saber que le falta un programa del sistema."""
        ctx = self._ctx(config={"credentials": [{"kind": "ssh", "username": "root", "secret": "x"}]})
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", False), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", return_value=[]):
            SshCollector().collect(ctx)

        self.assertTrue(any("sshpass" in line for line in ctx["errors"]))

    def test_the_secret_never_reaches_the_error_lines(self) -> None:
        ctx = self._ctx(config={"credentials": [{"kind": "ssh", "username": "root", "secret": "ultrasecreta"}]})
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", False), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", return_value=[]):
            SshCollector().collect(ctx)

        self.assertNotIn("ultrasecreta", " ".join(ctx.get("errors", [])))

    def test_a_sweep_that_found_nobody_is_not_an_error(self) -> None:
        ctx = self._ctx(hosts=[])
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", True):
            self.assertEqual(SshCollector().collect(ctx), [])

        self.assertEqual(ctx.get("errors", []), [])

    def test_nobody_with_the_22_open_is_not_an_error_either(self) -> None:
        """En una red de Windows nadie tiene el 22: eso es normal, no un fallo."""
        ctx = self._ctx()

        self.assertEqual(self._collect(ctx, listening=[], answers={}), [])
        self.assertEqual(ctx.get("errors", []), [])

    def test_an_answering_host_is_enriched_not_duplicated(self) -> None:
        """La huella se calcula de la identidad. Si SSH eligiera otra MAC del
        mismo equipo, la bandeja abriría una segunda fila para algo que ya
        estaba ahí desde el barrido y desde SNMP."""
        ctx = self._ctx()

        findings = self._collect(ctx)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.kind, "host")
        self.assertEqual(finding.identity, {"mac": "52:54:00:1a:2b:3c"})
        self.assertEqual(finding.payload["hostname"], "srv-ficheros")
        self.assertEqual(finding.payload["os"], "Ubuntu 22.04.3 LTS")
        self.assertEqual(finding.payload["seen_by"], "ssh")
        self.assertEqual(finding.payload["family"], "linux")
        self.assertEqual(len(finding.payload["interfaces"]), 3)

    def test_the_sweep_mac_wins_over_the_one_the_device_reports_first(self) -> None:
        """Un servidor con varias tarjetas contesta primero por la que le
        apetezca. Con esa dentro de la huella, cada barrido podría estrenar
        fila para el mismo equipo."""
        ctx = self._ctx(hosts=[{"ip": "192.168.1.50", "mac": "aa:bb:cc:dd:ee:ff"}])

        findings = self._collect(ctx, listening=["192.168.1.50"])

        self.assertEqual(findings[0].identity, {"mac": "aa:bb:cc:dd:ee:ff"})
        self.assertEqual(findings[0].payload["mac"], "aa:bb:cc:dd:ee:ff")

    def test_a_host_the_sweep_saw_without_a_mac_falls_back_to_its_address(self) -> None:
        ctx = self._ctx(hosts=[{"ip": "192.168.1.60", "mac": ""}])

        findings = self._collect(
            ctx, listening=["192.168.1.60"], answers={"192.168.1.60": LINUX_SIN_PERMISO_DE_SERIE}
        )

        # Sin MAC del barrido se usa la del propio equipo, que sigue siendo suya.
        self.assertEqual(findings[0].identity, {"mac": "b0:83:fe:11:22:33"})

    def test_a_host_that_says_nothing_useful_leaves_no_row(self) -> None:
        """Un equipo con el 22 abierto que no deja entrar --o que no habla de
        ninguna familia conocida-- no puede acabar como una ficha vacía."""
        ctx = self._ctx()

        findings = self._collect(ctx, listening=["192.168.1.50"], answers={})

        self.assertEqual(findings, [])

    def test_a_credential_with_a_non_standard_port_is_never_even_probed(self) -> None:
        """FALLO REAL DEL COLECTOR -- este test está en rojo a propósito.

        La credencial dice puerto 2222 y `ssh.run` lo respeta (`argv_for` añade
        `-p`), pero el filtro previo pregunta siempre por `SSH_PORT` (22): el
        equipo se cae de `reachable` antes de que nadie llegue a probar la
        credencial. Resultado: cero hallazgos y ni una línea en `ctx["errors"]`,
        que es exactamente el producto mudo que este proyecto no quiere.
        """
        asked: list[int] = []

        def fake_listening(ips: list[str], port: int) -> list[str]:
            asked.append(port)
            return list(ips) if port == 2222 else []

        def fake_run(**kwargs: Any) -> ssh.Answer:
            return ssh.Answer(connected=True, output=LINUX_UBUNTU)

        ctx = self._ctx(
            config={"credentials": [{"kind": "ssh", "username": "root", "key_file": "/k", "port": 2222}]},
            hosts=[{"ip": "192.168.1.50", "mac": "52:54:00:1a:2b:3c"}],
        )
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", fake_listening), \
             mock.patch("agent.collectors.ssh.ssh.run", fake_run):
            findings = SshCollector().collect(ctx)

        self.assertEqual(
            len(findings),
            1,
            f"el puerto de la credencial se ignora en el sondeo previo; se preguntó por {asked}",
        )


class RegistrationTests(unittest.TestCase):
    def test_the_collector_is_registered_under_its_name(self) -> None:
        self.assertEqual(ssh_collector.SshCollector.name, "ssh")


if __name__ == "__main__":
    unittest.main()


class ConfigCaptureTests(unittest.TestCase):
    """La captura de configuración: la mitad nueva del valor del agente."""

    HOSTS = [{"ip": "192.168.1.2", "mac": "aa:bb:cc:dd:ee:01"}]
    RUNNING_CONFIG = "hostname sw-core-01\ninterface Gi1/0/1\n switchport access vlan 10"
    #: La guardada difiere en una línea: alguien cambió la VLAN y no hizo `write`.
    SAVED_CONFIG = "hostname sw-core-01\ninterface Gi1/0/1\n switchport access vlan 20"
    #: Un IOS que nunca guardó: es un estado real, no un rechazo de la orden.
    NEVER_SAVED = "startup-config is not present\n"
    #: Un IOS que no admite la orden (o un usuario sin privilegio para ella).
    REJECTED = "% Invalid input detected at '^' marker.\n"

    def _ctx(self, **extra: Any) -> dict:
        ctx: dict[str, Any] = {
            "config": {"credentials": [{"kind": "ssh", "username": "admin", "key_file": "/k"}]},
            "env": None,
            "hosts": list(self.HOSTS),
        }
        ctx.update(extra)
        return ctx

    def _collect(
        self,
        ctx: dict,
        running_config: str | None = None,
        saved: ssh.Answer | None = None,
        calls: list[str] | None = None,
    ):
        """Un IOS: `show version` entra, y las dos copias contestan lo que se les
        diga (`saved=None`: la guardada de siempre)."""
        config_text = self.RUNNING_CONFIG if running_config is None else running_config
        saved_answer = saved if saved is not None else ssh.Answer(connected=True, output=self.SAVED_CONFIG)

        def fake_run(**kwargs: Any) -> ssh.Answer:
            command = kwargs["command"]
            if calls is not None:
                calls.append(command)
            if command == "show version":
                return ssh.Answer(connected=True, output=CISCO_SHOW_VERSION)
            if command == "show running-config":
                return ssh.Answer(connected=True, output=config_text)
            if command == "show startup-config":
                return saved_answer
            # El comando de Linux: un IOS lo rechaza pero deja entrar.
            return ssh.Answer(connected=True, output=IOS_RECHAZA_EL_COMANDO_DE_LINUX)

        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", return_value=["192.168.1.2"]), \
             mock.patch("agent.collectors.ssh.ssh.run", fake_run):
            return SshCollector().collect(ctx)

    def test_a_network_device_yields_its_config_next_to_its_host_finding(self) -> None:
        findings = self._collect(self._ctx())

        kinds = [finding.kind for finding in findings]
        self.assertEqual(kinds, ["host", "config"])
        config = findings[1]
        # Misma identidad que el hallazgo de host: es lo que permite al
        # servidor colgar la copia del equipo correcto.
        self.assertEqual(config.identity, findings[0].identity)
        self.assertEqual(config.payload["config"], self.RUNNING_CONFIG)
        self.assertEqual(config.payload["family"], "cisco")

    # --- La configuración guardada (`saved_config`) ---------------------------------

    def test_a_cisco_sends_the_saved_config_next_to_the_running_one(self) -> None:
        """Con las dos, el servidor avisa de lo que un reinicio perdería."""
        calls: list[str] = []

        findings = self._collect(self._ctx(), calls=calls)

        config = findings[1]
        self.assertEqual(config.payload["config"], self.RUNNING_CONFIG)
        self.assertEqual(config.payload["saved_config"], self.SAVED_CONFIG)
        # Las dos con la misma credencial que entró, en este orden: la que
        # está en marcha primero, que es la que decide si hay copia.
        self.assertEqual(calls[-2:], ["show running-config", "show startup-config"])

    def test_a_mikrotik_saves_on_apply_and_sends_only_the_running_one(self) -> None:
        """RouterOS no distingue las dos: se pide `/export` y nada más. Sin la
        clave, no con una vacía: para el servidor «sin clave» es «no aplica»."""
        from agent.collectors.ssh import MIKROTIK_COMMAND

        export = "/interface bridge add name=bridge1\n/ip address add address=192.168.1.2/24 interface=bridge1"
        calls: list[str] = []

        def fake_run(**kwargs: Any) -> ssh.Answer:
            command = kwargs["command"]
            calls.append(command)
            if command == MIKROTIK_COMMAND:
                return ssh.Answer(connected=True, output="version: 7.12\nboard-name: hEX\nname: gw-oficina\n")
            if command == "/export":
                return ssh.Answer(connected=True, output=export)
            return ssh.Answer(connected=True, output="bad command name show (line 1 column 1)")

        ctx = self._ctx()
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", return_value=["192.168.1.2"]), \
             mock.patch("agent.collectors.ssh.ssh.run", fake_run):
            findings = SshCollector().collect(ctx)

        self.assertEqual([finding.kind for finding in findings], ["host", "config"])
        self.assertEqual(findings[1].payload["config"], export)
        self.assertNotIn("saved_config", findings[1].payload)
        self.assertEqual(calls[-1], "/export")
        self.assertEqual(ctx.get("errors", []), [])

    def test_a_saved_config_that_fails_leaves_the_copy_without_the_key_and_says_so(self) -> None:
        """La guardada es un extra: si no sale, la copia sigue saliendo."""
        ctx = self._ctx()

        findings = self._collect(ctx, saved=ssh.Answer(connected=False, error="Connection timed out"))

        self.assertEqual([finding.kind for finding in findings], ["host", "config"])
        self.assertEqual(findings[1].payload["config"], self.RUNNING_CONFIG)
        self.assertNotIn("saved_config", findings[1].payload)
        notes = [note for note in ctx["errors"] if getattr(note, "code", "") == "saved_config_unavailable"]
        self.assertEqual(len(notes), 1)
        self.assertEqual((notes[0].collector, notes[0].params["ip"], notes[0].params["family"]), ("ssh", "192.168.1.2", "cisco"))

    def test_an_empty_saved_config_is_no_saved_config(self) -> None:
        findings = self._collect(self._ctx(), saved=ssh.Answer(connected=True, output="   \n"))

        self.assertEqual([finding.kind for finding in findings], ["host", "config"])
        self.assertNotIn("saved_config", findings[1].payload)

    def test_a_cli_that_rejects_the_order_is_not_a_saved_config(self) -> None:
        """«% Invalid input» es `ssh` entrando y el equipo diciendo que no: no
        se manda como configuración, que el servidor la compararía con la de
        verdad y avisaría de cambios sin guardar que no existen."""
        ctx = self._ctx()

        findings = self._collect(ctx, saved=ssh.Answer(connected=True, output=self.REJECTED))

        self.assertNotIn("saved_config", findings[1].payload)
        self.assertTrue(any(getattr(note, "code", "") == "saved_config_unavailable" for note in ctx["errors"]))

    def test_a_device_that_never_saved_is_a_real_state_not_a_rejection(self) -> None:
        """`startup-config is not present` es información: un reinicio lo
        pierde todo. Va tal cual, y el servidor decide qué decir."""
        findings = self._collect(self._ctx(), saved=ssh.Answer(connected=True, output=self.NEVER_SAVED))

        self.assertEqual(findings[1].payload["saved_config"], self.NEVER_SAVED)

    def test_a_real_config_that_mentions_an_error_in_a_banner_is_not_a_rejection(self) -> None:
        from agent.collectors.ssh import rejected_by_cli

        banner = "hostname sw-core-01\nbanner motd ^C\nError: unauthorized access is prohibited\n^C\n"
        config = banner + "\n".join(f"interface Gi1/0/{n}" for n in range(1, 10))

        self.assertFalse(rejected_by_cli(config))
        self.assertTrue(rejected_by_cli(self.REJECTED))
        self.assertTrue(rejected_by_cli("Error: Unrecognized command found at '^' position.\n"))  # Huawei
        self.assertFalse(rejected_by_cli(""))

    def test_the_size_cap_applies_to_the_saved_config_on_its_own(self) -> None:
        """Una guardada que pasa del tope se descarta sin tocar la que está en
        marcha, y al revés: cada una con su techo."""
        from agent.collectors.ssh import MAX_CONFIG_BYTES

        ctx = self._ctx()
        findings = self._collect(ctx, saved=ssh.Answer(connected=True, output="x" * (MAX_CONFIG_BYTES + 1)))

        self.assertEqual([finding.kind for finding in findings], ["host", "config"])
        self.assertEqual(findings[1].payload["config"], self.RUNNING_CONFIG)
        self.assertNotIn("saved_config", findings[1].payload)
        self.assertTrue(any(getattr(note, "code", "") == "saved_config_unavailable" for note in ctx["errors"]))

    def test_without_a_running_config_there_is_no_copy_even_with_a_saved_one(self) -> None:
        calls: list[str] = []

        findings = self._collect(self._ctx(), running_config="", calls=calls)

        self.assertEqual([finding.kind for finding in findings], ["host"])
        self.assertNotIn("show startup-config", calls)

    def test_the_capture_switch_turns_off_the_saved_config_too(self) -> None:
        """Un solo interruptor para las dos: no hay otro que configurar."""
        ctx = self._ctx()
        ctx["config"]["capture_configs"] = False
        calls: list[str] = []

        findings = self._collect(ctx, calls=calls)

        self.assertEqual([finding.kind for finding in findings], ["host"])
        self.assertNotIn("show running-config", calls)
        self.assertNotIn("show startup-config", calls)

    def test_the_saved_config_never_turns_into_an_exception(self) -> None:
        """Regla del colector: anota y sigue, nunca lanza."""
        from agent.collectors import ssh as module

        real = module.fetch_config

        def exploding(host: str, credential: Any, command: str, logins: Any = None, enable: bool = False) -> str:
            if command == "show startup-config":
                raise RuntimeError("se cayó el transporte")
            return real(host, credential, command, logins, enable=enable)

        ctx = self._ctx()
        with mock.patch("agent.collectors.ssh.fetch_config", exploding):
            findings = self._collect(ctx)

        self.assertEqual([finding.kind for finding in findings], ["host", "config"])
        self.assertNotIn("saved_config", findings[1].payload)

    def test_only_the_families_that_tell_the_two_apart_have_a_saved_command(self) -> None:
        """La lista es la promesa: MikroTik, Fortinet y Gaia guardan al aplicar
        y la candidata de Junos es un borrador. Y toda familia con orden de
        guardada captura también la que está en marcha."""
        from agent.collectors.ssh import CAPTURE_COMMANDS, SAVED_CONFIG_COMMANDS

        self.assertEqual(set(SAVED_CONFIG_COMMANDS), {"cisco", "aruba", "dell", "huawei", "comware"})
        self.assertTrue(set(SAVED_CONFIG_COMMANDS) <= set(CAPTURE_COMMANDS))
        for family, command in SAVED_CONFIG_COMMANDS.items():
            self.assertTrue(command.strip())
            self.assertNotEqual(command, CAPTURE_COMMANDS[family])

    def test_the_server_switch_turns_it_off(self) -> None:
        ctx = self._ctx()
        ctx["config"]["capture_configs"] = False

        findings = self._collect(ctx)

        self.assertEqual([finding.kind for finding in findings], ["host"])

    def test_without_a_server_the_environment_decides(self) -> None:
        from agent.config import Config

        ctx = self._ctx(config={}, env=Config(url="http://localhost", token="t", capture_configs=False))
        ctx["config"] = {"credentials": [{"kind": "ssh", "username": "admin", "key_file": "/k"}]}
        ctx["config"]["capture_configs"] = None  # el servidor no dice nada
        del ctx["config"]["capture_configs"]

        findings = self._collect(ctx)

        self.assertEqual([finding.kind for finding in findings], ["host"])

    def test_an_oversize_dump_is_dropped_never_truncated_in_silence(self) -> None:
        from agent.collectors.ssh import MAX_CONFIG_BYTES

        findings = self._collect(self._ctx(), running_config="x" * (MAX_CONFIG_BYTES + 1))

        self.assertEqual([finding.kind for finding in findings], ["host"])

    def test_a_linux_host_never_yields_a_config(self) -> None:
        """La configuración de un servidor no es un archivo, y no se finge."""
        def fake_run(**kwargs: Any) -> ssh.Answer:
            return ssh.Answer(connected=True, output=LINUX_UBUNTU)

        ctx = self._ctx()
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", return_value=["192.168.1.2"]), \
             mock.patch("agent.collectors.ssh.ssh.run", fake_run):
            findings = SshCollector().collect(ctx)

        self.assertEqual([finding.kind for finding in findings], ["host"])


# --- Las familias de la ampliación (Aruba, JunOS, Dell, Huawei/Comware, ---------
# --- Fortinet, Gaia, ESXi), con banners reales de cada CLI ----------------------

JUNOS_SHOW_VERSION = """Hostname: fw-madrid
Model: srx300
Junos: 21.4R3-S4.9
JUNOS Software Release [21.4R3-S4.9]
"""

ARUBA_SHOW_VERSION = """ArubaOS-CX
(c) Copyright 2017-2023 Hewlett Packard Enterprise Development LP
Version      : FL.10.10.1040
Build Date   : 2023-01-20
Serial Number: SG12345678
"""

DELL_SHOW_VERSION = """Dell EMC Networking OS10 Enterprise
Copyright (c) 1999-2022 by Dell Inc.
OS Version: 10.5.4.0
System Type: S4128F-ON
"""

HUAWEI_DISPLAY_VERSION = """Huawei Versatile Routing Platform Software
VRP (R) software, Version 8.180 (S5735 V200R019C00SPC500)
Copyright (C) 2000-2020 HUAWEI TECH Co., Ltd.
HUAWEI S5735-L24T4X-A uptime is 0 week, 6 days, 2 hours
"""

COMWARE_DISPLAY_VERSION = """HPE Comware Software, Version 7.1.070, Release 6126
Copyright (c) 2010-2019 Hewlett Packard Enterprise Development LP
HPE 5130 EI Switch uptime is 12 weeks, 3 days
"""

FORTI_STATUS = """Version: FortiGate-60F v7.2.5,build1517,230609 (GA.F)
Serial-Number: FGT60FTK20012345
Hostname: fw-oficina
Operation Mode: NAT
"""

GAIA_SHOW_VERSION = """Product version Check Point Gaia R81.20
OS build 631
OS kernel version 3.10.0-957.21.3cpx86_64
"""

ESXI_VMWARE_V = "VMware ESXi 7.0.3 build-20036589\n"


class NewFamilyParserTests(unittest.TestCase):
    """Cada analizador con su banner de verdad, y mudo ante los ajenos."""

    def test_junos(self) -> None:
        from agent.collectors.ssh import parse_junos

        data = parse_junos(JUNOS_SHOW_VERSION)
        self.assertEqual(data["family"], "junos")
        self.assertEqual(data["hostname"], "fw-madrid")
        self.assertEqual(data["model"], "srx300")
        self.assertEqual(data["manufacturer"], "Juniper")
        self.assertEqual(parse_junos(CISCO_SHOW_VERSION), {})

    def test_aruba(self) -> None:
        from agent.collectors.ssh import parse_aruba

        data = parse_aruba(ARUBA_SHOW_VERSION)
        self.assertEqual(data["family"], "aruba")
        self.assertEqual(data["manufacturer"], "Aruba")
        self.assertEqual(data["serial"], "SG12345678")
        self.assertEqual(parse_aruba(JUNOS_SHOW_VERSION), {})

    def test_dell(self) -> None:
        from agent.collectors.ssh import parse_dell

        data = parse_dell(DELL_SHOW_VERSION)
        self.assertEqual(data["family"], "dell")
        self.assertIn("OS10", data["description"])
        self.assertEqual(parse_dell(ARUBA_SHOW_VERSION), {})

    def test_huawei_and_comware_share_the_command_not_the_name(self) -> None:
        from agent.collectors.ssh import parse_display_version

        huawei = parse_display_version(HUAWEI_DISPLAY_VERSION)
        self.assertEqual(huawei["family"], "huawei")
        self.assertEqual(huawei["manufacturer"], "Huawei")

        comware = parse_display_version(COMWARE_DISPLAY_VERSION)
        self.assertEqual(comware["family"], "comware")
        self.assertEqual(comware["manufacturer"], "HPE / H3C")

        self.assertEqual(parse_display_version(CISCO_SHOW_VERSION), {})

    def test_fortinet(self) -> None:
        from agent.collectors.ssh import parse_fortinet

        data = parse_fortinet(FORTI_STATUS)
        self.assertEqual(data["family"], "fortinet")
        self.assertEqual(data["hostname"], "fw-oficina")
        self.assertEqual(data["serial"], "FGT60FTK20012345")
        self.assertIn("FortiGate-60F", data["description"])
        self.assertEqual(parse_fortinet(GAIA_SHOW_VERSION), {})

    def test_gaia(self) -> None:
        from agent.collectors.ssh import parse_gaia

        data = parse_gaia(GAIA_SHOW_VERSION)
        self.assertEqual(data["family"], "gaia")
        self.assertEqual(data["description"], "Check Point Gaia R81.20")
        self.assertEqual(parse_gaia(FORTI_STATUS), {})

    def test_esxi(self) -> None:
        from agent.collectors.ssh import parse_esxi

        data = parse_esxi(ESXI_VMWARE_V)
        self.assertEqual(data["family"], "esxi")
        self.assertEqual(data["manufacturer"], "VMware")
        self.assertEqual(parse_esxi(LINUX_UBUNTU), {})

    def test_the_show_version_group_dispatches_by_signature(self) -> None:
        from agent.collectors.ssh import parse_show_version

        self.assertEqual(parse_show_version(CISCO_SHOW_VERSION)["family"], "cisco")
        self.assertEqual(parse_show_version(JUNOS_SHOW_VERSION)["family"], "junos")
        self.assertEqual(parse_show_version(ARUBA_SHOW_VERSION)["family"], "aruba")
        self.assertEqual(parse_show_version(DELL_SHOW_VERSION)["family"], "dell")
        self.assertEqual(parse_show_version("uname: not found"), {})


class NewFamilyCaptureTests(unittest.TestCase):
    """El grupo «show version» afina la familia y la captura sale del mapa."""

    ROOT = Credential(kind="ssh", username="root", key_file="/x/id_ed25519")

    def test_a_junos_is_found_in_two_connections_with_its_capture_command(self) -> None:
        fake = _FakeSsh(
            {
                "uname": ssh.Answer(connected=True, output="command not found"),
                "show version": ssh.Answer(connected=True, output=JUNOS_SHOW_VERSION),
            }
        )
        with mock.patch("agent.collectors.ssh.ssh.run", fake):
            data, credential = interrogate("192.168.1.60", [self.ROOT])

        self.assertEqual(data["family"], "junos")
        self.assertEqual(len(fake.calls), 2)
        from agent.collectors.ssh import CAPTURE_COMMANDS

        self.assertEqual(CAPTURE_COMMANDS[data["family"]], "show configuration | display set")

    def test_every_capture_family_has_a_command_and_the_excluded_do_not(self) -> None:
        """La lista es la promesa del producto: quién respalda y quién no.

        Linux y ESXi fuera a propósito: fingir que su configuración es un
        volcado de texto sería prometer una copia que no restaura nada.
        """
        from agent.collectors.ssh import CAPTURE_COMMANDS

        self.assertEqual(
            set(CAPTURE_COMMANDS),
            {"cisco", "mikrotik", "aruba", "junos", "dell", "huawei", "comware", "fortinet", "gaia",
             "exos", "icx", "awplus", "edgeos"},
        )
        for command in CAPTURE_COMMANDS.values():
            self.assertTrue(command.strip())


# --- Stacks: the units behind one management address ------------------------------


class StackMembersTests(unittest.TestCase):
    """`members` in the host finding: one entry per physical unit, only for two
    or more, with the master's serial as the main one. The vendor captures
    live in `test_stacks`; here, which orders go out and what reaches the payload."""

    ROOT = Credential(kind="ssh", username="admin", key_file="/x/id_ed25519")

    def _members(self, data: dict, answers: dict[str, ssh.Answer]) -> tuple[dict, list[str]]:
        from agent.collectors.ssh import stack_members

        fake = _FakeSsh(answers)
        with mock.patch("agent.collectors.ssh.ssh.run", fake):
            result = stack_members("192.168.1.2", self.ROOT, data)
        return result, [command for _, command in fake.calls]

    def test_a_dell_whose_version_shows_one_unit_asks_show_switch(self) -> None:
        from agent.collectors.ssh import parse_dell

        data = parse_dell("Dell Networking N2048P\n" + test_stacks.DELL_VERSION_MANAGEMENT_ONLY)
        self.assertNotIn("members", data)

        result, calls = self._members(data, {"show switch": ssh.Answer(connected=True, output=test_stacks.DELL_SHOW_SWITCH)})

        self.assertEqual(calls, ["show switch"])
        self.assertEqual([m["unit"] for m in result["members"]], [1, 2])
        self.assertEqual(result["serial"], "CN0D4T5D2829832K0042A00")

    def test_a_dell_whose_version_lists_the_units_asks_nothing_more(self) -> None:
        from agent.collectors.ssh import parse_dell

        data = parse_dell("Dell Networking N3048P\n" + test_stacks.DELL_VERSION_STACK_OF_TWO)

        result, calls = self._members(data, {})

        self.assertEqual(calls, [])
        self.assertEqual(len(result["members"]), 2)
        self.assertEqual(result["serial"], "CN0K9F1P2829831A0012A00")

    def test_an_aruba_stack_of_four(self) -> None:
        result, calls = self._members(
            {"family": "aruba", "serial": "", "model": ""},
            {"show stacking": ssh.Answer(connected=True, output=test_stacks.ARUBA_STACK_OF_FOUR)},
        )

        self.assertEqual(calls, ["show stacking"])
        self.assertEqual(len(result["members"]), 4)
        self.assertEqual(result["model"], "HP JL075A 3810M-16SFP+-2-slot Switch")

    def test_a_juniper_virtual_chassis_of_two_gives_the_master_serial(self) -> None:
        result, calls = self._members(
            {"family": "junos", "serial": "", "model": "ex4300-48p"},
            {"show virtual-chassis": ssh.Answer(connected=True, output=test_stacks.JUNOS_VC_OF_TWO)},
        )

        self.assertEqual(calls, ["show virtual-chassis"])
        self.assertEqual([m["unit"] for m in result["members"]], [0, 1])
        self.assertEqual(result["serial"], "PE3714100218")

    def test_a_standalone_juniper_keeps_its_serial_and_has_no_members(self) -> None:
        result, _ = self._members(
            {"family": "junos", "serial": "", "model": "ex2300-24p"},
            {"show virtual-chassis": ssh.Answer(connected=True, output=test_stacks.JUNOS_VC_ALONE)},
        )

        self.assertNotIn("members", result)
        self.assertEqual(result["serial"], "NV0217290101")

    def test_a_comware_irf_asks_manuinfo_only_when_there_is_a_fabric(self) -> None:
        manuinfo = ssh.Answer(connected=True, output=test_stacks.MANUINFO_OF_THREE)
        result, calls = self._members(
            {"family": "comware", "serial": "", "model": ""},
            {"display irf": ssh.Answer(connected=True, output=test_stacks.IRF_OF_THREE), "manuinfo": manuinfo},
        )

        self.assertEqual(calls, ["display irf", "display device manuinfo"])
        self.assertEqual([m["serial"] for m in result["members"]], ["CN64GPV0AA", "CN64GPV0BB", "CN64GPV0CC"])
        self.assertEqual(result["serial"], "CN64GPV0AA")

        alone, calls = self._members(
            {"family": "comware", "serial": "", "model": ""},
            {"display irf": ssh.Answer(connected=True, output=test_stacks.IRF_ALONE), "manuinfo": manuinfo},
        )
        self.assertEqual(calls, ["display irf"])
        self.assertNotIn("members", alone)

    def test_families_without_a_stack_order_ask_nothing(self) -> None:
        for family in ("cisco", "huawei", "mikrotik", "fortinet", "linux"):
            result, calls = self._members({"family": family, "serial": "S"}, {})
            self.assertEqual(calls, [], family)
            self.assertNotIn("members", result)

    def test_a_rejected_or_broken_order_leaves_the_host_as_it_was(self) -> None:
        data = {"family": "aruba", "serial": "SG1", "model": ""}
        rejected, _ = self._members(data, {"show stacking": ssh.Answer(connected=True, output="Invalid input: stacking\n")})
        self.assertEqual(rejected["serial"], "SG1")
        self.assertNotIn("members", rejected)

        from agent.collectors.ssh import stack_members

        with mock.patch("agent.collectors.ssh.ssh.run", side_effect=RuntimeError("boom")):
            self.assertEqual(stack_members("192.168.1.2", self.ROOT, data), data)


class StackPayloadTests(unittest.TestCase):
    """The whole collector: `members` reaches the host finding only for a stack."""

    def _host_payload(self, show_version: str) -> dict:
        ctx: dict[str, Any] = {
            "config": {"credentials": [{"kind": "ssh", "username": "admin", "key_file": "/k"}]},
            "env": None,
            "hosts": [{"ip": "192.168.1.2", "mac": "70:d3:79:aa:10:00"}],
            "task": "inventory",
        }
        fake = _FakeSsh(
            {"show version": ssh.Answer(connected=True, output=show_version)},
            default=ssh.Answer(connected=True, output=IOS_RECHAZA_EL_COMANDO_DE_LINUX),
        )
        with mock.patch("agent.collectors.ssh.ssh.AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.ssh.PASSWORD_AUTH_AVAILABLE", True), \
             mock.patch("agent.collectors.ssh.net.hosts_listening", return_value=["192.168.1.2"]), \
             mock.patch("agent.collectors.ssh.ssh.run", fake):
            findings = SshCollector().collect(ctx)
        return next(f for f in findings if f.kind == "host").payload

    def test_a_cisco_stack_of_three_sends_its_members(self) -> None:
        payload = self._host_payload(test_stacks.CISCO_STACK_OF_THREE)

        self.assertEqual([m["unit"] for m in payload["members"]], [1, 2, 3])
        self.assertEqual(payload["members"][0]["role"], "master")
        self.assertEqual(payload["serial"], "JAE24350ABC")

    def test_a_single_cisco_sends_no_members_key(self) -> None:
        payload = self._host_payload(test_stacks.CISCO_SINGLE)

        self.assertNotIn("members", payload)
        self.assertEqual(payload["serial"], "FOC2001X0AB")


class DellAndPrivilegeTests(unittest.TestCase):
    """07-10-2026: a Dell N2048P (OS6) gave no copy, and a refusal travelled as one."""

    def test_dell_asks_the_order_os6_knows(self) -> None:
        self.assertEqual(ssh_collector.CAPTURE_COMMANDS["dell"], "show running-config")
        self.assertEqual(ssh_collector.SAVED_CONFIG_COMMANDS["dell"], "show startup-config")

    def test_a_refusal_is_no_copy_and_says_why(self) -> None:
        errors: list = []
        refusal = "              ^\n% Invalid input detected at '^' marker.\n"
        # Asked again who it is, it is still a Dell: a real lack of privilege.
        with mock.patch.object(ssh_collector, "fetch_config", return_value=refusal), mock.patch.object(
            ssh_collector, "interrogate", return_value=({"family": "dell"}, None)
        ):
            copies = ssh_collector.fetch_configs("10.0.0.2", mock.Mock(), "dell", errors=errors)

        self.assertEqual(copies, {})
        self.assertEqual(len(errors), 1)
        note = notes.to_json(errors[0])
        self.assertEqual(note["code"], "config_needs_privilege")
        self.assertEqual(note["params"]["ip"], "10.0.0.2")

    def test_an_authorization_refusal_is_recognised(self) -> None:
        self.assertTrue(ssh_collector.rejected_by_cli("Command authorization failed.\n"))
        self.assertTrue(ssh_collector.rejected_by_cli("% Authorization failed.\n"))

    def test_a_real_configuration_is_kept(self) -> None:
        config = "!Current Configuration:\nhostname planta-baja-SW\n" + "\n".join(f"vlan {n}" for n in range(1, 20))
        with mock.patch.object(ssh_collector, "fetch_config", return_value=config):
            copies = ssh_collector.fetch_configs("10.0.0.2", mock.Mock(), "dell", errors=[])

        self.assertEqual(copies["config"], config)



class LegacyAlgorithmTests(unittest.TestCase):
    """A switch from ten years ago (08-10-2026: OpenSSH 5.9 with only SHA-1 key
    exchange) is retried with the old algorithms added, and only it."""

    NEGOTIATION = (
        "Unable to negotiate with 172.20.5.21 port 22: no matching key exchange method found. "
        "Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1"
    )
    LEGACY = ("-o", "KexAlgorithms=+diffie-hellman-group1-sha1")

    def test_argv_adds_the_old_algorithms_only_when_asked(self) -> None:
        with mock.patch.object(ssh, "legacy_options", return_value=self.LEGACY):
            modern = ssh.argv_for(host="10.0.0.5", username="root", command="x")
            legacy = ssh.argv_for(host="10.0.0.5", username="root", command="x", legacy=True)

        self.assertNotIn("KexAlgorithms=+diffie-hellman-group1-sha1", modern)
        self.assertIn("KexAlgorithms=+diffie-hellman-group1-sha1", legacy)

    def test_a_negotiation_failure_is_retried_with_the_old_algorithms(self) -> None:
        calls: list[bool] = []

        def attempt(*args, legacy: bool = False, **kwargs):  # noqa: ANN002, ANN003, ANN202
            calls.append(legacy)
            if not legacy:
                return ssh.Answer(connected=False, error=self.NEGOTIATION, unreachable=True), self.NEGOTIATION
            return ssh.Answer(connected=True, output="ok"), ""

        with mock.patch.object(ssh, "legacy_options", return_value=self.LEGACY), mock.patch.object(
            ssh, "_attempt", side_effect=attempt
        ), mock.patch.object(ssh, "password_mode", return_value="askpass"):
            answer = ssh.run(host="172.20.5.21", username="sistemas", secret="x$y", command="true")

        self.assertTrue(answer.connected)
        self.assertEqual(calls, [False, True])

    def test_a_wrong_password_is_not_retried(self) -> None:
        calls: list[bool] = []
        denied = "sistemas@10.0.0.5: Permission denied (password)."

        def attempt(*args, legacy: bool = False, **kwargs):  # noqa: ANN002, ANN003, ANN202
            calls.append(legacy)
            return ssh.Answer(connected=False, error=denied), denied

        with mock.patch.object(ssh, "legacy_options", return_value=self.LEGACY), mock.patch.object(
            ssh, "_attempt", side_effect=attempt
        ), mock.patch.object(ssh, "password_mode", return_value="askpass"):
            ssh.run(host="10.0.0.5", username="sistemas", secret="mal", command="true")

        self.assertEqual(calls, [False], "una contraseña mala no se prueba dos veces")

    def test_the_probe_says_the_password_never_left(self) -> None:
        from agent import probe

        stuck = ssh.Answer(connected=False, error=self.NEGOTIATION, unreachable=True)
        denied = ssh.Answer(connected=False, error="Permission denied (password).")

        self.assertEqual(probe._ssh_failed_line([stuck]).code, "no_common_algorithms")
        self.assertEqual(probe._ssh_failed_line([stuck, denied]).code, "none_worked")
        self.assertEqual(probe._ssh_failed_line([]).code, "none_worked")
