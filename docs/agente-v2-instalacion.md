# Agente v2 · instalación y actualización (fases 4 y 6)

Complementa `agente-v2-nucleo.md`. Es contrato entre el agente, su instalador,
el flujo de publicación de este repositorio y el servidor.

## 1. Lo que publica una Release

Etiqueta `agent-vX.Y.Z`. Ficheros:

| Fichero | Qué es |
|---|---|
| `Cenya-Agent-Setup-X.Y.Z.exe` | Instalador de Windows |
| `install.sh` | Instalación y actualización en Linux |
| `cenya-agent-X.Y.Z.tar.gz` | El código del agente para Linux (`git archive` de `agent/`) |
| `latest.json` | El manifiesto |
| `latest.json.sig` | Firma Ed25519 del manifiesto |

`latest.json`:

```json
{
  "version": "0.11.0",
  "released": "2026-10-02T18:00:00Z",
  "url": "https://github.com/cenya-io/cenya-agent/releases/download/agent-v0.11.0/Cenya-Agent-Setup-0.11.0.exe",
  "sha256": "<hex del .exe>",
  "files": {
    "windows": {"url": "…/Cenya-Agent-Setup-0.11.0.exe", "sha256": "<hex>", "size": 15000000},
    "linux":   {"url": "…/cenya-agent-0.11.0.tar.gz", "sha256": "<hex>", "size": 900000},
    "install.sh": {"url": "…/install.sh", "sha256": "<hex>", "size": 4000}
  }
}
```

`url` y `sha256` de primer nivel se conservan (los lee quien ya los leía).

El fichero de Linux es un archivo propio y no el zip que GitHub genera de la
etiqueta: aquel se genera al vuelo y GitHub no garantiza que sus bytes no
cambien, así que su huella no se puede firmar.

`latest.json.sig`: la firma Ed25519, en base64 estándar, de **los bytes
exactos** de `latest.json`. La clave privada es un secreto del repositorio
(`CENYA_RELEASE_SIGNING_KEY`, PEM PKCS8); la pública va dentro del agente
(`agent/release_keys.py`, una lista: así se puede rotar) y en la configuración
del servidor. **Sin ninguna clave pública configurada no hay actualización
automática ni se sirve el instalador desde el servidor**: se dice, no se
actualiza a ciegas. El flujo, sin el secreto, publica sin firma y avisa.

Verificar es siempre: firma del manifiesto con una clave conocida → el
manifiesto dice la huella → la huella del fichero descargado coincide. La
huella sola no vale: quien cambia el fichero cambia la huella.

## 2. El instalador de Windows lleva la conexión en su nombre

El servidor entrega el instalador con este nombre:

```
Cenya-Agent-Setup-X.Y.Z_<base32>.exe
```

`<base32>` es la cadena de conexión (`cenya://portal/CÓDIGO`) en base32
(RFC 4648, minúsculas, sin relleno): solo letras y cifras, sin `_`. El
instalador la busca en su propio nombre con
`_([a-z2-7]{16,})( \(\d+\))?\.exe$` (el navegador añade ` (1)` a una descarga
repetida), la decodifica y enrola con ella. Si no la encuentra o no vale, no
pregunta nada: instala y abre la aplicación en «Conectar».

El servicio se arranca siempre, también sin enrolar: sin identidad sirve el
canal local y espera (núcleo, 4.2), y la aplicación conecta el equipo por él.
En silencio, una cadena que no se pudo canjear sale con 21 antes de instalar
el servicio. La aplicación (`cenya-agent-app.exe`, acceso directo «Cenya
Agent» en el menú Inicio con el AppUserModelID `Cenya.Agent.App`) necesita el
runtime WebView2 de Microsoft: si falta, la última página y el registro lo
avisan y la instalación sigue (el servicio no lo necesita). Desinstalar y
`/UPDATE` cierran la ventana antes de tocar ficheros, igual que el icono.

`/CONNECTION=` manda sobre el nombre. Un equipo ya enrolado ignora las dos.
Además: `/CA=<fichero>` (certificado propio del portal), y la página del
asistente gana ese mismo campo.

Al desinstalar: `cenya-agent goodbye` antes de quitar el servicio.

## 3. El servidor y el instalador

- El servidor lee `latest.json` y su firma del repositorio (caché de horas),
  los verifica, descarga el instalador una vez, comprueba su huella y lo
  guarda. Lo entrega a un usuario con sesión en
  `GET /discovery/agents/installer/<uuid del código>/` con el nombre de 2.
- A un agente, en `GET /api/agent/v2/installer/` (Bearer): el `.exe` vigente,
  con cabeceras `X-Cenya-Version`, `X-Cenya-Sha256` y `X-Cenya-Manifest`
  (el manifiesto en base64) y `X-Cenya-Manifest-Signature`.
- Sin Internet en el servidor: un administrador sube el instalador, el
  manifiesto y la firma; se aceptan solo si verifican.

## 4. Actualización del agente

- El servidor dice a qué versión ir en el checkin:
  `"update": {"version": "0.11.1"}` (cuando la política del agente es
  automática, o alguien pulsó «Actualizar»). `null` = quédate. Con
  `"explicit": true` (lo pidió una persona) el agente no mira su ajuste local
  `auto_update` ni la espera entre reintentos; el servidor deja de mandarlo
  cuando ve esa versión en `installing` o `failed`.
- El agente, con `auto_update` local encendido (o con la orden explícita):
  1. Trae el manifiesto y su firma (de este repositorio; si no llega, de su
     servidor) y los verifica con `agent/release_keys.py`.
  2. Comprueba que `version` es **mayor** que la suya (nunca baja de versión)
     e igual a la pedida.
  3. Descarga el fichero de su plataforma a la carpeta de estado
     (`updates/`), comprueba tamaño y huella.
  4. No interrumpe una tarea: espera a que no haya ninguna en curso.
  5. Windows: lanza el instalador `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART
     /UPDATE` desacoplado del servicio (el instalador lo para y lo arranca).
     Linux: `install.sh --update` (venv nuevo al lado, cambio de enlace,
     `systemctl restart`).
- **Vuelta atrás.** Antes de sustituir nada, el instalador guarda la versión
  anterior (`previous/`). Tras actualizar, si el servicio nuevo no consigue
  un checkin correcto en 10 minutos, el vigilante (una tarea programada de
  Windows creada por el instalador para esa ocasión; en Linux, una unidad
  `systemd` temporal) restaura la anterior, arranca el servicio y deja
  constancia: el agente restaurado informa `update_failed` con la versión que
  falló y no la vuelve a intentar.
- Estado en el checkin, en cada uno: el agente añade
  `"update_state": {"state": "idle|downloading|ready|installing|failed", "version": "…", "error": "<código>", "note": {nota con código, colector `update`}}`.
  Códigos: `bad_signature`, `bad_hash`, `bad_manifest`, `no_keys`,
  `no_crypto`, `not_newer`, `wrong_version`, `download_failed`,
  `install_failed`, `update_failed`, `unsupported`. **Definitivos** (esa
  versión no se reintenta, ni con orden explícita): `update_failed` e
  `install_failed`. Los demás se reintentan solos a los 30 minutos.
- Un fichero que no verifica se borra y se anota (`update` / `bad_signature`
  o `bad_hash`). Nunca se ejecuta nada sin verificar.

## 5. Linux

```
curl -fsSL https://github.com/cenya-io/cenya-agent/releases/latest/download/install.sh | sudo sh -s -- cenya://portal/CÓDIGO
```

`install.sh`: comprueba Python ≥ 3.10, crea `/opt/cenya-agent/<versión>` (venv)
e instala desde el archivo de la etiqueta, enlaza `/opt/cenya-agent/current`,
deja `/usr/local/bin/cenya-agent`, instala la unidad systemd
(`StateDirectory=cenya-agent`, usuario propio sin privilegios, las
capacidades justas para el ping), enrola si se le dio la cadena y arranca.
El agente corre sin privilegios, así que no se actualiza él: deja una
petición en `updates/request.json` y una unidad `cenya-agent-update.path` la
recoge como root, que **vuelve a verificar** firma, versión y huellas con el
código y las claves ya instalados antes de ejecutar nada.
Volver a ejecutarlo actualiza. `--uninstall` se despide y quita todo.
