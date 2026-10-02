"""Tests for the agent package. Run with ``python -m unittest discover agent/tests``.

Dos cosas del entorno que los tests no pueden heredar de la máquina en que
corren, y que todo el paquete fija aquí salvo que alguien diga otra cosa:

* **El fichero de estado** (`agent/status.py`). En Windows su sitio por defecto
  es `%ProgramData%\\NetInventory`: sin esto, los tests que ejercitan el bucle
  escribirían en el de la máquina -- y pisarían el de un servicio de verdad
  instalado en ella. Va a una carpeta temporal.
* **El idioma** (`agent/i18n.py`). Los textos del icono salen en el idioma de la
  sesión: en un CI con Linux en inglés, los tests que esperan el castellano
  fuente fallarían solo allí. Se fija el castellano; los tests de traducción
  eligen su idioma explícitamente.

Los módulos que dependen de esto importan `agent.tests` de forma explícita:
con `unittest discover agent/tests` este fichero no se ejecuta por sí solo.
"""

import os
import tempfile

os.environ.setdefault(
    "CENYA_STATUS_FILE",
    os.path.join(tempfile.mkdtemp(prefix="cenya-agent-tests-"), "status.json"),
)
# Asignado y no `setdefault`: una máquina con la variable puesta a otro idioma
# rompería tests que nada tienen que ver con traducir.
os.environ["CENYA_LANGUAGE"] = "es"
# El canal local (agent/app/channel.py): ningún test puede llegar al *named
# pipe* del servicio de verdad instalado en la máquina. Los que hablan por el
# canal levantan el servidor falso en un nombre al azar y lo pasan explícito.
os.environ["CENYA_PIPE_NAME"] = r"\\.\pipe\CenyaAgentTests-nobody"
os.environ["CENYA_SOCKET_PATH"] = os.path.join(tempfile.mkdtemp(prefix="cenya-agent-pipe-"), "nobody.sock")
# El almacén del token (`agent/store.py`) también: sin esto, un test que carga
# la configuración leería el enrolamiento de un agente real de esta máquina.
os.environ["CENYA_STATE_DIR"] = tempfile.mkdtemp(prefix="cenya-agent-state-")
