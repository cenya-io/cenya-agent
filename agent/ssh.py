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
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass

#: Sin el binario no hay colector. Se resuelve al importar, igual que
#: `snmp.AVAILABLE`, para que el colector pueda decirlo en una línea.
AVAILABLE = shutil.which("ssh") is not None

#: Con contraseña hace falta un ayudante: el `ssh` del sistema no la lee de una
#: variable ni de la entrada estándar, y `sshpass` es el que sabe dárselas. No
#: es una dependencia del proyecto --no se instala, no se empaqueta, no se
#: enlaza-- sino un programa del sistema que se usa si está, igual que `ping`.
#: Sin él, las credenciales con contraseña no se pueden usar y el colector lo
#: dice en vez de fallar host por host sin explicar por qué.
SSHPASS_AVAILABLE = shutil.which("sshpass") is not None

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
    command: str = "",
) -> list[str]:
    """La orden completa, montada aparte para poder mirarla en un test.

    Con contraseña hay que apagar ``BatchMode``: con él puesto, `ssh` ni
    siquiera intenta la autenticación por contraseña, así que `sshpass` no
    tendría a quién dársela. El tope duro del subproceso sigue estando, que es
    lo que impide que un prompt inesperado cuelgue el barrido.
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
    argv = ["ssh", *options, f"{username}@{host}"]
    if with_password:
        argv = ["sshpass", "-e", *argv]
    if command:
        argv.append(command)
    return argv


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
    donde corre el agente.
    """
    with_password = bool(secret) and SSHPASS_AVAILABLE
    argv = argv_for(
        host=host,
        username=username,
        port=port,
        key_file=key_file,
        with_password=with_password,
        command=command,
    )
    environment = dict(os.environ)
    if with_password:
        environment["SSHPASS"] = secret
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=COMMAND_TIMEOUT_SECONDS,
            env=environment,
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
