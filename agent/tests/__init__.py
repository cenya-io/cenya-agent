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
import uuid

os.environ.setdefault(
    "CENYA_STATUS_FILE",
    os.path.join(tempfile.mkdtemp(prefix="cenya-agent-tests-"), "status.json"),
)
# Asignado y no `setdefault`: una máquina con la variable puesta a otro idioma
# rompería tests que nada tienen que ver con traducir.
os.environ["CENYA_LANGUAGE"] = "es"
# El almacén del token (`agent/store.py`) también: sin esto, un test que carga
# la configuración leería el enrolamiento de un agente real de esta máquina.
os.environ["CENYA_STATE_DIR"] = tempfile.mkdtemp(prefix="cenya-agent-state-")
# Y el canal local (`agent/localpipe.py`): los tests que arrancan `main` lo
# sirven, y nunca con el nombre del servicio de verdad que puede estar
# corriendo en esta máquina. El socket de Linux ya cae en la carpeta de arriba.
os.environ["CENYA_PIPE_NAME"] = f"CenyaAgentTest-{uuid.uuid4().hex}"
