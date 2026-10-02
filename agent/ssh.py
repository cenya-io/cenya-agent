"""SSH through the system's own ``ssh`` binary, isolated behind two functions.

Same shape as ``agent.net``: no library, the command that every Windows 10+ and
every Linux already ships. **`paramiko` está descartado a propósito** -- es
LGPL-2.1 y la regla del proyecto es no meter copyleft nuevo en la cadena de
dependencias, así que aquí se hace lo mismo que con el `ping` del barrido:
llamar al binario del sistema y leer su salida.

Tres cosas que no son un detalle:

* ``BatchMode=yes`` -- el agente corre desatendido y no tiene a nadie que
  conteste a un «¿contraseña?». Sin esto, un host que pide contraseña deja el
  proceso esperando hasta el tiempo de espera duro, uno por uno.
* ``StrictHostKeyChecking=accept-new`` -- la primera vez que se ve un equipo se
  acepta su clave y se apunta; si **cambia** después, la conexión falla, que es
  justo la mitad de la protección que importa. Con ``no`` no fallaría nunca.
* Un tiempo de espera duro en el subproceso, además del de conexión: un equipo
  que acepta el TCP y luego no dice nada más cuelga la conexión, no la corta.

**La contraseña** se le da a `ssh` por el mecanismo del propio OpenSSH: con
``SSH_ASKPASS_REQUIRE=force`` (OpenSSH >= 8.4) `ssh` ejecuta el programa de
``SSH_ASKPASS`` -- aquí `agent/askpass.py` -- y lee la contraseña de su salida.
Ella viaja en una variable de entorno del subproceso `ssh`, nunca en la línea
de órdenes ni en un fichero: la misma confianza que `sshpass -e`, que no existe
en Windows. `sshpass` queda como respaldo para un OpenSSH anterior.

Y el binario: el instalador de Windows lleva el suyo en la carpeta ``openssh``
junto al ejecutable (los Windows Server 2019/2022 traen un OpenSSH viejo, o
ninguno), y se prefiere ese al del sistema.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import sysconfig
from dataclasses import dataclass
from pathlib import Path

from agent.askpass import SECRET_ENV

#: Desde esta versión `ssh` entiende ``SSH_ASKPASS_REQUIRE=force``: usa el
#: programa de ``SSH_ASKPASS`` aunque haya terminal o falte ``DISPLAY``. Antes
#: solo lo usaba con ``DISPLAY`` puesto y sin terminal, que un servicio no cumple.
MIN_ASKPASS_VERSION = (8, 4)

_VERSION_RE = re.compile(r"OpenSSH_(?:for_Windows_)?(\d+)\.(\d+)")


def parse_version(text: str) -> tuple[int, int] | None:
    """``(9, 5)`` de ``OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2`` o de
    ``OpenSSH_10.5p1, OpenSSL ...``; ``None`` si lo que salió no es de OpenSSH."""
    match = _VERSION_RE.search(text or "")
    return (int(match.group(1)), int(match.group(2))) if match else None


def detect_version(binary: str) -> tuple[int, int] | None:
    """Lo que dice ``ssh -V`` (escribe en el error estándar). Nunca lanza."""
    try:
        result = subprocess.run(
            [binary, "-V"], capture_output=True, text=True, errors="replace", timeout=5, stdin=subprocess.DEVNULL
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return parse_version((result.stderr or "") + (result.stdout or ""))


def binary_candidates() -> list[str]:
    """Los ``ssh`` que se pueden usar, por orden de preferencia.

    1. El que lleva el instalador, en la carpeta ``openssh`` junto al ejecutable
       congelado: es el único cuya versión controlamos.
    2. El del sistema, el que encuentre el PATH.
    """
    found: list[str] = []
    if getattr(sys, "frozen", False):
        bundled = Path(sys.executable).resolve().parent / "openssh" / ("ssh.exe" if os.name == "nt" else "ssh")
        if bundled.is_file():
            found.append(str(bundled))
    system = shutil.which("ssh")
    if system and system not in found:
        found.append(system)
    return found


def pick_binary() -> tuple[str, tuple[int, int] | None]:
    """El primer candidato que de verdad ejecuta y dice su versión. Si ninguno
    la dice pero hay alguno, se usa el primero con versión desconocida: puede
    seguir sirviendo para claves, pero no se fía de él para la contraseña."""
    candidates = binary_candidates()
    for candidate in candidates:
        version = detect_version(candidate)
        if version:
            return candidate, version
    return (candidates[0], None) if candidates else ("", None)


def askpass_path() -> str:
    """El ejecutable de `agent/askpass.py`: junto al congelado, o el script que
    deja ``pip install`` (junto al intérprete del entorno, o en el PATH). Vacío
    si no está --ejecutando desde las fuentes--, y entonces no hay askpass."""
    name = "cenya-agent-askpass" + (".exe" if os.name == "nt" else "")
    directories = [Path(sys.executable).resolve().parent]
    try:
        scripts = sysconfig.get_path("scripts")
    except (KeyError, OSError):  # un intérprete congelado o raro: no es motivo para no importar el módulo
        scripts = ""
    if scripts:
        directories.append(Path(scripts))
    for directory in directories:
        candidate = directory / name
        if candidate.is_file():
            return str(candidate)
    return shutil.which("cenya-agent-askpass") or ""


#: El binario elegido y su versión. Se resuelve al importar, igual que
#: `snmp.AVAILABLE`, para que el colector pueda decirlo en una línea. Sin el
#: binario no hay colector.
BINARY, VERSION = pick_binary()
AVAILABLE = bool(BINARY)

#: Con contraseña, el mecanismo de OpenSSH: hace falta un `ssh` que lo entienda
#: y el ejecutable que contesta (`agent/askpass.py`).
ASKPASS = askpass_path()
ASKPASS_AVAILABLE = bool(ASKPASS) and VERSION is not None and VERSION >= MIN_ASKPASS_VERSION

#: El respaldo, para un OpenSSH anterior a 8.4 (un Linux viejo): `sshpass`. No es
#: una dependencia del proyecto --no se instala, no se empaqueta, no se
#: enlaza-- sino un programa del sistema que se usa si está, igual que `ping`.
SSHPASS_AVAILABLE = shutil.which("sshpass") is not None

#: Si las credenciales con contraseña se pueden usar de alguna de las dos
#: maneras. Sin ninguna, el colector lo dice en vez de fallar host por host sin
#: explicar por qué.
PASSWORD_AUTH_AVAILABLE = ASKPASS_AVAILABLE or SSHPASS_AVAILABLE

DEFAULT_PORT = 22
CONNECT_TIMEOUT_SECONDS = 5
#: El tope duro del subproceso. Más que el de conexión porque aquí dentro cabe
#: además la autenticación y el comando remoto.
COMMAND_TIMEOUT_SECONDS = 20

#: El código con el que `ssh` dice «no he podido conectarme» (frente a los que
#: devuelve el comando remoto, que son del equipo de enfrente y no nuestros).
SSH_FAILURE_CODE = 255


@dataclass(frozen=True)
class Answer:
    """Lo que dio un intento: si se entró, y lo que se leyó.

    ``connected`` separa «no me dejó entrar» de «entré y el comando no existe
    ahí». Lo primero significa probar la siguiente credencial; lo segundo, que
    la credencial vale y lo que no encaja es la familia de equipo.
    """

    connected: bool
    output: str = ""
    error: str = ""


def argv_for(
    *,
    host: str,
    username: str,
    port: int = 0,
    key_file: str = "",
    with_password: bool = False,
    askpass: bool = False,
    command: str = "",
) -> list[str]:
    """La orden completa, montada aparte para poder mirarla en un test.

    Con contraseña hay que apagar ``BatchMode``: con él puesto, `ssh` ni
    siquiera intenta la autenticación por contraseña, así que ni `sshpass` ni
    el askpass tendrían a quién dársela. El tope duro del subproceso sigue
    estando, que es lo que impide que un prompt inesperado cuelgue el barrido.
    ``askpass`` dice cómo se entrega: por el mecanismo de OpenSSH (el entorno lo
    pone `run`), o, sin él, anteponiendo `sshpass`.
    """
    options = [
        "-o",
        f"ConnectTimeout={CONNECT_TIMEOUT_SECONDS}",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    if with_password:
        options += [
            "-o",
            "BatchMode=no",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "PubkeyAuthentication=no",
        ]
    else:
        options += ["-o", "BatchMode=yes"]
    if key_file:
        # `IdentitiesOnly`: sin esto `ssh` ofrece antes las claves del agente de
        # claves del usuario, y contra un equipo con pocos intentos permitidos
        # eso agota los intentos sin llegar a probar la que se le ha dado.
        options += ["-i", key_file, "-o", "IdentitiesOnly=yes"]
    if port and port != DEFAULT_PORT:
        options += ["-p", str(port)]
    argv = [BINARY or "ssh", *options, f"{username}@{host}"]
    if with_password and not askpass:
        argv = ["sshpass", "-e", *argv]
    if command:
        argv.append(command)
    return argv


def password_mode() -> str:
    """Cómo se entregaría una contraseña ahora: ``askpass``, ``sshpass`` o vacío."""
    if ASKPASS_AVAILABLE:
        return "askpass"
    return "sshpass" if SSHPASS_AVAILABLE else ""


def environment_for(secret: str, mode: str) -> dict[str, str]:
    """El entorno del subproceso `ssh`: el del agente, más lo que lleva la contraseña.

    La contraseña solo está aquí y solo cuando hay modo: sin él ni siquiera se
    pone, y en una ejecución con clave se quitan las variables propias por si
    el agente hereda alguna de fuera.
    """
    environment = dict(os.environ)
    for name in (SECRET_ENV, "SSHPASS"):
        environment.pop(name, None)
    if mode == "askpass":
        environment["SSH_ASKPASS"] = ASKPASS
        environment["SSH_ASKPASS_REQUIRE"] = "force"
        environment[SECRET_ENV] = secret
    elif mode == "sshpass":
        environment["SSHPASS"] = secret
    return environment


def run(
    *,
    host: str,
    username: str,
    secret: str = "",
    port: int = 0,
    key_file: str = "",
    command: str,
) -> Answer:
    """Un comando en ese equipo. Nunca lanza: devuelve lo que pasó.

    La contraseña viaja por una variable de entorno del subproceso y no por la
    línea de órdenes: en la línea la ve cualquiera con un `ps` en la máquina
    donde corre el agente. Tampoco aparece en ningún texto de error: lo que se
    devuelve sale de lo que dice `ssh`, que nunca la repite.
    """
    mode = password_mode() if secret else ""
    if mode == "askpass" and ("\n" in secret or "\r" in secret):
        # `ssh` lee la respuesta del askpass hasta el fin de línea: una
        # contraseña con uno llegaría cortada y fallaría sin explicación.
        return Answer(connected=False, error="la contraseña contiene un salto de línea y no se puede entregar")
    argv = argv_for(
        host=host,
        username=username,
        port=port,
        key_file=key_file,
        with_password=bool(mode),
        askpass=mode == "askpass",
        command=command,
    )
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=COMMAND_TIMEOUT_SECONDS,
            env=environment_for(secret, mode),
        )
    except subprocess.TimeoutExpired:
        return Answer(connected=False, error="tiempo de espera agotado")
    except OSError as exc:
        return Answer(connected=False, error=str(exc))
    if result.returncode == SSH_FAILURE_CODE:
        # La primera línea basta: `ssh` explica el motivo ahí y el resto son
        # avisos de la clave del host que no aportan nada al informe.
        first = (result.stderr or "").strip().splitlines()
        return Answer(connected=False, error=first[0] if first else "conexión rechazada")
    return Answer(connected=True, output=result.stdout or "", error=(result.stderr or "").strip())
