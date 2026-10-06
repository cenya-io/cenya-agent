# El agente de Cenya

Un proceso pequeño y sin estado que recorre la red y empuja lo que encuentra a
la aplicación por HTTPS saliente. No abre puertos, no necesita base de datos y
en disco solo guarda su propio token, protegido: todo lo que hay que recordar
(qué se vio, qué decidió la gente) lo recuerda el servidor. Si la máquina se
pierde, se enrola otro agente y no se ha perdido nada.

## Enrolarlo

1. En la aplicación: **Ajustes → Agentes → Añadir un agente**. Aparece una
   *cadena de conexión* con la forma `cenya://inventario.midominio.local/K7QF-9M2X-4TQN`:
   dónde está el portal y un código de un solo uso que caduca en una hora.
2. En la máquina de la red que va a barrer, canjearla y arrancar:

```bash
cenya-agent enroll cenya://inventario.midominio.local/K7QF-9M2X-4TQN
cenya-agent
```

(Sin instalar el paquete, `python -m agent enroll …` y `python -m agent` hacen
lo mismo, con Python 3.12+.)

**Nadie ve ni copia ningún token.** El agente trae su token permanente a cambio
del código y lo guarda él mismo: con `0600` en Linux
(`/var/lib/cenya-agent/enrollment.json`, o `~/.config/cenya-agent` si no es root)
y, en Windows, en `%ProgramData%\Cenya\enrollment.json` con la herencia quitada
y solo SYSTEM, los administradores y quien lo enroló con acceso. Si no puede
protegerlo, no lo escribe. La pantalla de Ajustes pasa sola de «Esperando al
agente…» a «conectado». `--force` enrola de nuevo una máquina ya enrolada.
`cenya://` va por HTTPS; `cenya+http://` es solo para un portal local de
pruebas, y el agente se niega a mandar nada por `http://` a otra máquina.

Con Docker (solo en Linux; ver el aviso más abajo), con la cadena en el entorno.
Se canjea la primera vez y el token queda en el volumen `agent_state`:

```bash
CENYA_CONNECTION=cenya://inventario.midominio.local/K7QF-9M2X-4TQN \
docker compose up -d
```

Lo mismo sirve para un script de despliegue en cualquier servidor: si en el
entorno hay `CENYA_CONNECTION` y la máquina aún no está enrolada, el agente la
canjea al arrancar.

**El modo antiguo con token sigue valiendo** (`CENYA_AGENT_TOKEN`, o
`NETINVENTORY_AGENT_TOKEN`, como se llamaba antes de ser Cenya) para quien ya lo tiene
desplegado así. Cada variable `CENYA_*` tiene su antigua `NETINVENTORY_*`, que se
sigue leyendo donde no haya una `CENYA_*`. El ejecutable se llama ahora
`cenya-agent` (antes `netinventory-agent`).

Para un solo barrido y salir (pruebas, demos):

```bash
python -m agent --once
```

## Dónde se descarga

Cada versión etiquetada (`agent-vX.Y.Z`) que pasa la prueba de verdad del
instalador (`.github/workflows/agent-installer.yml`) se publica, y ya no se
toca, como *Release* de este repositorio
(`docs/agente-v2-instalacion.md`, sección 1):

| Fichero | Qué es |
|---|---|
| `Cenya-Agent-Setup-<versión>.exe` | El instalador de Windows |
| `cenya-agent-<versión>.tar.gz` | El agente para Linux (la carpeta `agent/` de la etiqueta, hecho una vez y firmado) |
| `install.sh` | Instalación y actualización en Linux, con las claves públicas dentro |
| `latest.json` | El manifiesto: versión, y URL, SHA-256 y tamaño de cada fichero |
| `latest.json.sig` | La firma Ed25519 del manifiesto |

El archivo de Linux es propio y no el `.zip` que GitHub genera para la
etiqueta: ese se genera al vuelo y GitHub no garantiza que sus bytes (y su
huella) sean siempre los mismos, así que no se puede firmar su SHA-256.

**Firmas.** Verificar es siempre lo mismo y nunca se salta un paso: la firma
del manifiesto con una clave conocida (`agent/release_keys.py`), luego la
huella y el tamaño del fichero que dice el manifiesto (`agent/release.py`).
La huella sola no vale: quien cambia el fichero cambia la huella. Sin ninguna
clave pública en `agent/release_keys.py` el agente **no se actualiza solo** y
lo dice. El par de claves lo genera el dueño del repositorio con
`python agent/packaging/release_key.py generate`: la privada va al secreto
`CENYA_RELEASE_SIGNING_KEY` del repositorio y la pública a
`agent/release_keys.py` y al servidor. Sin el secreto, el flujo publica sin
firma y lo avisa.

## El instalador de Windows

Para quien no quiere ni oír hablar de Python: **`Cenya-Agent-Setup-<versión>.exe`**.
Lleva dentro su Python y todas las librerías (SNMP, WinRM…), y deja el agente
funcionando como servicio de Windows con su icono de bandeja. Habla los cinco
idiomas del producto.

**La conexión va en el nombre.** El instalador que se descarga desde Ajustes →
Agentes se llama `Cenya-Agent-Setup-<versión>_<base32>.exe`: detrás del último
`_` va la cadena de conexión en base32 (RFC 4648, minúsculas, sin relleno). El
instalador la lee de su propio nombre (también con el « (1)» que añade el
navegador a una descarga repetida) y enrola sin preguntar nada. Sin conexión
en el nombre ni en la línea de comandos, la página de conexión es opcional: se
puede dejar en blanco y enrolar después (`cenya-agent enroll <cadena>`); el
servicio queda instalado pero parado hasta entonces.

Para desplegarlo en masa (un MSP con muchas máquinas, un script, Intune), en
silencio:

```powershell
.\Cenya-Agent-Setup-0.11.0.exe /VERYSILENT /CONNECTION=cenya://portal.midominio.com/K7QF-9M2X-4TQN
```

| Parámetro | Para qué |
|---|---|
| `/CONNECTION=…` | La cadena de conexión. Manda sobre la del nombre. En un equipo ya enrolado se ignoran las dos |
| `/CA=<fichero>` | El certificado (PEM o DER) de la CA propia del portal. Se valida, se copia a la carpeta de estado (`ca.pem`) y queda en `settings.json` **antes** de enrolar. La página del asistente tiene el mismo campo |
| `/TASKS="!tray"` | Sin icono de bandeja: para un servidor en el que nadie inicia sesión |
| `/DIR="D:\Cenya"` | Otra carpeta de instalación (por defecto, `Archivos de programa\Cenya Agent`) |
| `/UPDATE` | Lo usa el propio agente al actualizarse (ver «Actualización») |

**Códigos de salida** además de los de Inno Setup (0 a 8): **21** si el agente se
instaló pero no pudo enrolarse (cadena caducada o ya usada, portal inalcanzable),
**22** si no se pudo instalar el servicio y **23** si el certificado de `/CA=`
no se pudo aplicar. Quien despliega en masa tiene que mirar el código: un
equipo sin enrolar es un equipo sin agente.

La carpeta del agente queda en el PATH del sistema: en cualquier consola nueva,
`cenya-agent …` funciona sin `cd`. `cenya-agent settings set ca_bundle <fichero>`
y `cenya-agent settings set auto_update on|off` cambian esos dos ajustes a mano.

Volver a ejecutar el instalador **actualiza**: no pide nada y conserva el
enrolamiento, aunque se repita el mismo comando con su `/CONNECTION` (un código
de un solo uso ya está gastado). Para pasar un equipo a otro portal:
`cenya-agent enroll <cadena> --force`. Desinstalar **se despide del servidor**
(`cenya-agent goodbye`; sin red borra igual), quita el servicio, saca la
carpeta del PATH y borra el token y el estado: un secreto no se queda en una
máquina en la que ya no hay agente.

**Construirlo** (en Windows, desde la raíz del repositorio; hace falta Inno Setup 6
y `pip install ./agent[completo] pyinstaller`):

```powershell
.\agent\packaging\build.ps1
```

PyInstaller congela el agente en una carpeta con tres ejecutables
(`cenya-agent.exe`, `cenya-agent-service.exe`, `cenya-agent-tray.exe`),
`cenya-agent selftest` comprueba que la compilación está completa (todos los
colectores, los cinco idiomas, las librerías de Windows) y Inno Setup lo
empaqueta. PyInstaller es GPL con una excepción expresa que permite distribuir lo
que construye bajo cualquier licencia: es una herramienta de construcción, no
entra en el agente, que sigue siendo Apache 2.0.

En GitHub Actions, `.github/workflows/agent-installer.yml` lo construye y,
sobre un Windows limpio con administrador, **lo instala de verdad contra un
servidor de mentira**: el servicio, el checkin, los permisos del token, la
reinstalación, la desinstalación con su despedida y el código 21 con una cadena
mala. Con una clave de PRUEBA que nace y muere en la ejecución compila además
las versiones N, N+1 y N+2 y prueba la conexión en el nombre, `/CA=`, la
actualización sola de N a N+1, que un instalador manipulado no se ejecuta y que
una N+2 que nunca conecta vuelve atrás sola (`agent/packaging/smoke-test.ps1`).

Aún sin firmar: Windows enseñará «Windows protegió su PC» al ejecutarlo. La firma
de código es el siguiente paso, antes del primer cliente.

## Actualización

El servidor dice en el checkin a qué versión ir (`"update": {"version": …}`,
con `"explicit": true` si alguien pulsó «Actualizar»). Con `auto_update`
encendido en `settings.json` (lo está por defecto), o con la orden explícita,
el agente (`agent/update.py`):

1. Trae `latest.json` y su firma de la Release de esa versión y, si no llega,
   de su propio servidor (`GET /api/agent/v2/installer/`, con el manifiesto y
   la firma en las cabeceras). Sin claves configuradas no baja nada.
2. Acepta solo exactamente la versión pedida y **estrictamente más nueva** que
   la suya: nunca baja de versión.
3. Descarga a `updates/` de su carpeta protegida, con el tope del tamaño del
   manifiesto, y comprueba la huella. Lo que no verifica se borra y se informa
   (`update_state` del checkin, nota `update` / `bad_signature`, `bad_hash`…).
   Un fallo así se reintenta a la media hora; una orden explícita, ya.
4. Espera a que no haya ninguna tarea en curso (y no empieza otra), vuelve a
   comprobar la huella y lanza el instalador.

**Windows.** El instalador en modo `/UPDATE`, desacoplado del servicio. Antes de
sustituir nada copia la versión instalada a `%ProgramData%\Cenya\previous\app`
y deja un vigilante: una tarea programada de un solo uso, como SYSTEM, que se
lanza al registrarse y en cada arranque del equipo
(`agent/packaging/update-watchdog.cmd`). Si en 10 minutos la versión nueva no
ha hecho un checkin correcto (su marca `updates\healthy-<versión>`), restaura
la anterior, la arranca y deja `updates\failed-<versión>`: el agente
restaurado informa `update_failed` y no vuelve a intentar esa versión. Si no se
pudo hacer la copia o crear el vigilante, no se sustituye nada.

**Linux.** El agente corre sin privilegios y no puede tocar `/opt` ni reiniciar
su servicio: deja `updates/request.json`, y `cenya-agent-update.path` lanza como
root `cenya-agent update apply-request`, que **vuelve a verificarlo todo** con
el código y las claves de la versión instalada antes de ejecutar el
`install.sh --update` verificado. El vigilante es una unidad
`cenya-agent-watchdog.timer` que hace lo mismo que el de Windows y sobrevive a
un reinicio.

## Instalarlo como servicio con pip

El agente se instala con pip, sin copiar carpetas, desde la raíz del
repositorio (o desde una wheel construida con `python -m build agent`):

```bash
pip install ./agent              # barrido ping + ARP + DNS, y SSH con el ssh del sistema
pip install ./agent[snmp]        # además SNMP: identidad, LLDP/CDP y autonomía del SAI
pip install ./agent[winrm]       # además WinRM
pip install ./agent[windows]     # además, correr como servicio de Windows (solo Windows)
pip install ./agent[completo]    # todo
```

Eso deja el ejecutable `cenya-agent` en el PATH del entorno. Las
dependencias son opcionales a propósito: sin ellas el agente arranca igual y
el colector que las necesita se reporta no disponible — barrido parcial,
nunca roto.

**Linux.** No hace falta pip a mano:

```bash
curl -fsSL https://github.com/cenya-io/cenya-agent/releases/latest/download/install.sh | sudo sh -s -- cenya://portal/CODIGO
```

`install.sh` (POSIX `sh`; Debian, Ubuntu y la familia RHEL, con systemd y Python
3.10 o posterior) verifica la firma del manifiesto y la huella del archivo
antes de instalar nada, crea `/opt/cenya-agent/<versión>` (un entorno virtual
por versión) y el enlace `/opt/cenya-agent/current`, deja la orden
`/usr/local/bin/cenya-agent` (con `sudo` corre como el usuario del agente),
crea el usuario sin privilegios `cenya-agent`, instala
[`deploy/cenya-agent.service`](deploy/cenya-agent.service) (estado en
`/var/lib/cenya-agent` con `StateDirectory`, solo la capacidad `CAP_NET_RAW`
que necesita el ping, `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp`) y las unidades de la actualización, enrola si se
le dio la cadena y arranca. `--ca FICHERO` aplica una CA propia antes de
enrolar. Volver a ejecutarlo actualiza; `sudo sh /opt/cenya-agent/install.sh
--uninstall` se despide del servidor y quita todo. Los registros:
`journalctl -u cenya-agent`.

**Windows (servicio).** Un servicio de verdad: aparece en `services.msc`,
arranca sin que nadie inicie sesión y se para limpiamente. Con Python 3.12
**instalada para todos los usuarios** (no la de `AppData` de una persona: si esa
cuenta se borra, el servicio se queda sin Python), desde un PowerShell de
administrador:

```powershell
py -3.12 -m venv C:\cenya\venv
C:\cenya\venv\Scripts\pip install "C:\ruta\al\repo\agent[completo]"
.\agent\deploy\install-service.ps1 -Connection cenya://inventario.midominio.local/K7QF-9M2X-4TQN
```

El script canjea la cadena (o la pide, si el equipo no está enrolado), instala el servicio «Cenya Agent»
con arranque automático retrasado (espera a la red), lo configura para
reiniciarse si se cae y lo arranca. Volver a ejecutarlo lo actualiza. Por
debajo es `cenya-agent-service install | update | start | stop | remove`,
el comando que deja el extra `[windows]`.

Tres cosas que hace ese comando y que no se ven, porque sin ellas el servicio
se instala bien y luego no arranca o expone el token:

- **Coloca el ejecutable del servicio en `Scripts` del entorno**, con las DLL de
  Python al lado. Donde lo pone `pywin32` por defecto (la raíz del entorno),
  Windows no encuentra `python312.dll` y, aun encontrándola, Python no ve los
  paquetes del entorno.
- **Lee el token de su almacén protegido** (`%ProgramData%\Cenya\enrollment.json`),
  que el servicio, como SYSTEM, puede leer y los demás usuarios no. Lo que
  haya de configuración en variables de la consola que lo instala (`CENYA_*` y
  las antiguas `CENYA_*`) se copia al propio servicio, no a variables de
  la máquina: un servicio no ve una variable de máquina nueva hasta que se
  reinicia el equipo.
- **Cierra esa clave del registro**: por defecto cualquier usuario del equipo
  puede leer la configuración de un servicio, y ahí podría estar un token si se
  instaló con el modo antiguo. Queda legible solo por SYSTEM y los
  administradores.

**Dónde mirar si algo no va:** el Visor de eventos, *Registros de Windows →
Aplicación*, origen `CenyaAgent`. Ahí van los mensajes del agente
(«barrido enviado», «el servidor no contesta») y, si el servicio se detiene
solo, el motivo (por ejemplo, que falta el token).

Al pararlo, el agente termina el barrido que tuviera en curso y no empieza
otro; si estaba esperando entre barridos, para en el acto. Mientras termina,
Windows lo ve «deteniéndose», no colgado.

**El icono de bandeja.** El mismo script deja el icono arrancando al iniciar
sesión cualquier usuario del equipo (`-NoTray` para no hacerlo, en un servidor
en el que nadie entra). Es la marca de Cenya con un punto de estado:

- **Verde**: el agente funciona. El último barrido pudo salir parcial --lo
  normal mientras falten credenciales--, y la ventana de estado lo cuenta,
  pero no pone el icono en naranja: un aviso permanente deja de avisar.
- **Naranja**: sabe que algo va mal. El servidor no contesta o rechaza el
  token, o el servicio se detuvo por un error (por ejemplo, falta el token).
  Al pasar a naranja, el icono pide además una notificación a Windows, que
  la enseña o no según su configuración (el modo «No molestar» la calla).
- **Gris**: no lo sabe. El servicio está detenido, no está instalado, o lleva
  varios minutos sin dar noticias. Gris nunca quiere decir «todo bien».

Un clic enseña el estado (último barrido, cuántos hallazgos, próximo barrido);
con el botón derecho, además, abre Ajustes → Agentes en el navegador. «Cerrar
este icono» cierra el icono, no el agente: el servicio sigue barriendo aunque
nadie mire.

Windows 11 guarda cualquier icono nuevo en el desplegable `^` de la barra de
tareas: hay que arrastrarlo fuera una vez para tenerlo siempre a la vista.

Por dentro: el agente escribe lo que hace en
`%ProgramData%\Cenya\status.json` y el icono lo lee cada cinco segundos,
junto con lo que dice Windows del servicio. No hay ningún puerto entre los dos,
y en ese fichero no hay ningún secreto (ni el token, ni usuario y contraseña
dentro de la URL). La instalación deja esa carpeta escribible solo por SYSTEM y
los administradores: por defecto cualquier usuario puede crear ahí ficheros, y
podría dejar un estado falso con una URL que el icono abriría en el navegador.
Para quitar el arranque automático del icono:
`Remove-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run -Name "Cenya Agent"`.

El icono habla el idioma de la sesión de Windows: castellano, inglés, alemán,
francés y portugués de Brasil, con los mismos términos que la web
(`locale/GLOSARIO.md`). Una variante regional busca su lengua (`de_AT` lee el
alemán, `pt_PT` el portugués de Brasil), y un idioma sin catálogo sale en
castellano. `CENYA_LANGUAGE` lo fija a mano. Los catálogos son
`agent/translations/<idioma>/LC_MESSAGES/cenya-agent.po` y el agente los lee
tal cual, sin `.mo` que compilar; cómo actualizarlos tras cambiar un texto está
en `agent/i18n.py`.

La instalación también: los avisos de `install-service.ps1` y lo que imprime
`cenya-agent-service install` salen del mismo catálogo. El script de
PowerShell no tiene gettext, así que pide sus textos ya traducidos al agente que
instala (`python -m agent.installer_text`); solo el aviso de que no encuentra
ese agente va en castellano e inglés a la vez, porque sin agente no hay quien
traduzca.

Y lo que el agente cuenta mientras funciona: sus líneas en la consola o en
`docker logs` («[agente] Barrido enviado…») y, con el servicio, lo que deja en
el Visor de eventos, incluido el motivo cuando se detiene. El servicio corre
como SYSTEM, así que usa el idioma del sistema; si se instaló con
`CENYA_LANGUAGE` puesta, esa variable viaja al servicio con las demás y
manda.

Los motivos de los colectores («ssh: no hay credenciales configuradas») y los
informes de «Analizar» son otra cosa: no se leen en la máquina del agente sino
en la web, así que **no los traduce el agente**. Los manda como códigos con sus
datos (`agent/notes.py`), además del texto en castellano de siempre, y el
servidor los escribe en el idioma de cada persona que mira
(`core/agent_notes.py`). Un agente anterior a los códigos, o un código que el
servidor aún no conoce, se ve con su texto tal cual llegó. Lo que viene de
fuera va sin traducir: el error que devuelve un hipervisor o el sistema.

El agente le dice al servidor su idioma (`Accept-Language`) en cada petición,
así que cuando el servidor rechaza algo («Token de agente no válido.») el motivo
también llega en el idioma del agente, y sin el sobre JSON en que viaja.

Lo que **no** se traduce: los avisos propios de Windows y de `pywin32` en el
Visor de eventos («The service has started») y sus líneas al instalar
(«Installing service»), que salen siempre en inglés; y lo que devuelve algo que
no es el servidor (un proxy, un portal cautivo), que se enseña tal cual.

**Windows sin el extra `[windows]` (Programador de tareas).** La alternativa
sin `pywin32`: una tarea al arranque, apuntando al `cenya-agent.exe` del
entorno.

```powershell
schtasks /Create /TN "Cenya Agent" /SC ONSTART /RU SYSTEM `
  /TR "C:\cenya\venv\Scripts\cenya-agent.exe"
```

Aquí las variables (`CENYA_URL`, `CENYA_AGENT_TOKEN`) van a nivel
de máquina (`[Environment]::SetEnvironmentVariable(..., "Machine")`), o en un
`.cmd` envoltorio que las exporte antes de arrancar. Ten en cuenta que una
variable de máquina la puede leer cualquier usuario del equipo. El agente
reintenta solo si el servidor no está: no hace falta retrasar la tarea al
arranque.

**SSH con usuario y contraseña, en Windows y en Linux.** El colector SSH usa el
binario `ssh` de OpenSSH, no una librería (`paramiko` es LGPL y está descartado).
Para la contraseña usa el mecanismo del propio OpenSSH: con
`SSH_ASKPASS_REQUIRE=force` (OpenSSH 8.4 o posterior), `ssh` ejecuta el programa
`cenya-agent-askpass` y lee de su salida la contraseña. La contraseña viaja en
una variable de entorno del proceso `ssh` y nada más: no va en la línea de
órdenes (donde la vería un `ps`), ni en un fichero, ni pasa por un intérprete de
órdenes, así que comillas, `%`, `!`, `^`, `&`, acentos o una barra final llegan
tal cual. Es la misma confianza que tenía `sshpass -e`. El ayudante contesta
**solo** a una petición de contraseña: ante «¿seguro que quieres continuar
conectando?» o la frase de paso de una clave no imprime nada.

- **El instalador de Windows** lleva su propio OpenSSH (Win32-OpenSSH, licencia
  BSD) en la carpeta `openssh` junto al programa, y lo usa en lugar del que
  tenga el sistema: Windows Server 2019 y 2022 traen uno antiguo o ninguno. No
  hay que instalar nada más.
- **Con `pip install`** hace falta un OpenSSH 8.4 o posterior en el PATH
  (Windows 10/11 recientes y cualquier Linux actual lo traen; `ssh -V` lo dice) y
  el comando `cenya-agent-askpass`, que deja `pip` junto a `cenya-agent`.
- **Con un OpenSSH anterior a 8.4** (un Linux viejo) se usa `sshpass` si está
  instalado, como antes (`apt install sshpass`; la imagen Docker oficial ya lo
  trae). Si no, las credenciales con contraseña no se usan y el barrido lo dice
  con la versión que ha encontrado; las de clave (`key_file`) funcionan siempre.

`cenya-agent selftest` enseña qué `ssh` va a usar, su versión y si la contraseña
está disponible (sección `ssh`).

Variables:

| Variable | Por defecto | Para qué |
|---|---|---|
| `CENYA_URL` | `http://localhost:8000` | Dónde empujar |
| `CENYA_AGENT_TOKEN` | — | La credencial del agente (obligatoria) |
| `CENYA_INTERVAL` | `900` | Segundos entre barridos, si el servidor no dice otro |
| — | `60` | Mientras duerme, el agente pregunta al servidor cada minuto («¿algo urgente?»): es lo que hace que «Barrer ahora» y «Analizar» tarden menos de un minuto en recogerse, sin abrir ningún puerto |
| `CENYA_CA_BUNDLE` | — | Ruta a un certificado de CA propio, si `CENYA_URL` es HTTPS con uno autofirmado |
| `CENYA_CAPTURE_CONFIGS` | `1` | A `0` para no guardar copias de configuración de los equipos de red |
| `CENYA_CREDENTIALS` | — | Credenciales en JSON, solo para pruebas standalone. Lo normal es ponerlas en Ajustes (ver [Configuración](#configuración)) |
| `CENYA_LANGUAGE` | el de la sesión de Windows | Idioma del icono de bandeja (`en`, `de`, `fr`, `pt_BR`, `es`), si se prefiere otro |
| `CENYA_STATUS_FILE` | `%ProgramData%\Cenya\status.json` en Windows; ninguno en Linux | Dónde escribe el agente su estado para el icono de bandeja. En Linux no se escribe salvo que se dé una ruta. `--once` no lo escribe nunca |

### Aviso sobre el despliegue con Docker

El servicio `agent` del `docker-compose.yml` de este repositorio usa `network_mode: host`: sin eso,
el barrido recorre la red interna del propio Docker (172.x) y no la de la
empresa, y **la primera vez que alguien lo prueba no encuentra nada**, aunque
diga que barre su propia /24 -- esa /24 no es la suya.

Eso solo funciona en Linux. En Docker Desktop (Windows o Mac) el modo de red
del host no da acceso a la LAN real de todos modos: en esas máquinas, la vía
que funciona es arrancar el agente directamente con `python -m agent`, como
más arriba, desde un equipo que sí esté en esa red.

### Un certificado propio

Si `CENYA_URL` es HTTPS y el certificado lo firma la propia empresa --lo
normal en una pyme--, la conexión falla por defecto: **la salida correcta no es
desactivar la verificación de TLS**, es dar la CA que lo firma con
`CENYA_CA_BUNDLE=/ruta/al/ca.pem`. Con Docker, el fichero hay que
montarlo dentro del contenedor con un volumen; hay un ejemplo comentado en
`docker-compose.yml`.

### Un certificado público que Windows «rechaza»

Desde la 0.10.2, si la verificación del certificado falla y no hay
`CENYA_CA_BUNDLE`, el agente lo intenta **una vez más con la lista de CA
públicas de Mozilla** (`certifi`, que lleva el instalador) y se queda con la
que funcione. Existe por un caso real: Python en Windows lee el almacén de
certificados del sistema, que conserva certificados antiguos y caducados, y
OpenSSL puede elegir uno y rechazar con «certificate has expired» un
certificado de Let's Encrypt que el navegador acepta sin problema. La
verificación nunca se desactiva; con una CA propia puesta en `CENYA_CA_BUNDLE`
no se prueba nada más, porque esa es la decisión de quien opera el equipo; y
si el segundo intento también falla, el error que se enseña es el del primero.
Sin `certifi` (un `python -m agent` pelado) no hay segundo intento.

## Qué hace

Los colectores corren en este orden, y **cada uno se apoya en el anterior**: el
barrido deja los hosts vivos y los demás solo llaman a esas puertas.

- **local**: reporta el propio host donde corre.
- **sweep** (L1): barre las subredes configuradas con el `ping` del sistema,
  lee la caché ARP para las MAC y resuelve nombres por DNS inverso.
- **snmp** (L2): a cada host vivo le pregunta quién es (sysDescr/sysName), sus
  interfaces reales con MAC y estado, y sus direcciones IP. También sus vecinos
  LLDP/CDP, que son **cables que se dibujan solos**. Habla v2c y v3: los
  usuarios SNMPv3 (credencial `snmpv3` en Ajustes, con sus protocolos de
  autenticación y cifrado) se prueban antes que las comunidades, porque un
  equipo configurado con v3 suele tener v2c apagado.
- **ssh** (L3): entra en los que tengan el puerto abierto y saca sistema
  operativo, hostname real, interfaces y --si el permiso da-- fabricante,
  modelo y número de serie. Prueba una familia de comandos tras otra: primero
  Linux, y si el equipo no entiende `uname`, las CLI de red -- Cisco, Aruba,
  Dell y Juniper comparten `show version` (una conexión y la firma del texto
  decide), Huawei y HPE/Comware comparten `display version`, y MikroTik,
  Fortinet, CheckPoint Gaia y ESXi tienen el suyo. Con la primera credencial
  que entra deja de probar. Si la familia que responde es un
  equipo de red, además **guarda su configuración** (nueve familias: Cisco,
  MikroTik, Aruba, Juniper, Dell, Huawei, HPE/Comware, Fortinet y CheckPoint
  Gaia; ESXi se identifica pero no se captura) y la empuja aparte: el servidor la
  convierte en copia de configuración del equipo, solo si ya existe en el
  inventario y solo si cambió respecto a la última. En las familias que
  distinguen la configuración **en marcha** de la **guardada** (la que carga
  al reiniciar: Cisco, Aruba, Dell, Huawei y HPE/Comware) pide también la
  guardada y la manda al lado (`saved_config`), para que el servidor avise de
  los cambios que un reinicio perdería; si esa segunda orden falla, la copia
  sale igual, sin ella. Se apaga desde Ajustes → Agentes o con
  `CENYA_CAPTURE_CONFIGS=0`: un solo interruptor para las dos.
- **winrm** (L4): lo mismo para Windows, por PowerShell remoto: nombre,
  dominio, fabricante, modelo, serie e interfaces.
- **hypervisors** (L5): pregunta a los hipervisores que estén configurados:
  vCenter y Proxmox por REST, **Hyper-V** por PowerShell remoto sobre WinRM
  (necesita `pywinrm`, como el colector de Windows) y **XCP-ng / XenServer**
  por XAPI (JSON-RPC, biblioteca estándar). De cada uno salen sus
  **servidores** y sus **máquinas virtuales** con vCPU, RAM, disco y estado.
  No depende del barrido: un hipervisor tiene una dirección conocida y se le
  pregunta directamente.

Todos los hallazgos de un mismo equipo se **fusionan por huella**: un servidor
que aparece por ping, por SNMP y por SSH es **una fila** que se va
enriqueciendo, no tres.

Un colector que no puede correr --le falta su librería, le falta el binario, no
hay credenciales-- lo dice en el resultado del barrido y devuelve cero
hallazgos. **El barrido sale parcial, nunca roto.**

### Qué órdenes ejecuta en los equipos por SSH

Todas son de **solo lectura**: el agente nunca cambia nada en un equipo. La
identificación se prueba en este orden hasta que una contesta; las dos
columnas de configuración solo se piden a la familia que respondió, con la
misma credencial, y cada orden es una conexión `ssh` (el transporte es un
proceso por orden; no hay sesión que reutilizar). Donde la celda está vacía,
esa familia no tiene esa configuración y no se le pide nada.

La columna «Unidades del stack» es la orden que lista las cajas de un stack
(cada una con su número, modelo y serie, y quién manda), en las familias que
no lo cuentan ya al identificarse. Se pide con la misma credencial, en el
inventario, y solo si la identificación no las trajo.

| Familia | Identificación | Unidades del stack | Configuración en marcha | Configuración guardada |
|---|---|---|---|---|
| Linux | `uname -sr`, `cat /etc/os-release`, `hostname`, `ip -o link`, `ip -o -4 addr`, `cat /sys/class/dmi/id/{sys_vendor,product_name,product_serial}` | | | |
| Cisco IOS | `show version` | *(las trae `show version`)* | `show running-config` | `show startup-config` |
| Aruba (AOS-S, AOS-CX, ProCurve) | `show version` | `show stacking` | `show running-config` | `show startup-config` |
| Dell Networking | `show version` | `show switch` *(solo si `show version` describe una sola unidad)* | `show running-configuration` | `show startup-configuration` |
| Juniper JunOS | `show version` | `show virtual-chassis` | `show configuration \| display set` | *(la candidata es un borrador, no se pide)* |
| Huawei VRP | `display version` | | `display current-configuration` | `display saved-configuration` |
| HPE / H3C Comware | `display version` | `display irf`, y `display device manuinfo` si hay dos o más miembros | `display current-configuration` | `display saved-configuration` |
| MikroTik RouterOS | `/system resource print`, `/system identity print`, `/system routerboard print` | | `/export` | *(guarda al aplicar)* |
| Fortinet FortiOS | `get system status` | | `show full-configuration` | *(guarda al aplicar)* |
| Check Point Gaia | `show version all` | | `show configuration` | *(guarda al aplicar)* |
| VMware ESXi | `vmware -v` | | *(no se captura: no es un volcado de texto)* | |

La lista vive en `agent/collectors/ssh.py` (`FAMILIES`, `STACK_COMMANDS`,
`CAPTURE_COMMANDS` y `SAVED_CONFIG_COMMANDS`); los tests fijan qué familias capturan y cuáles
tienen configuración guardada, así que un cambio allí obliga a tocar esta
tabla a la vez.

## A demanda

El servidor nunca llama al agente: le deja **encargos** que el agente recoge
en su siguiente latido (pregunta cada ~60 s mientras duerme entre barridos).

- **Barrer ahora** (Ajustes → Agentes): adelanta el siguiente barrido. Para el
  «acabo de enchufar el aparato, quiero verlo ya».
- **Analizar** (un hallazgo de la bandeja): sondeo dirigido de esa IP — qué
  protocolo contesta y qué credencial entra, intento por intento. El informe
  vuelve a la fila de la bandeja («SSH: puerto abierto, ninguna credencial
  entró») y **nunca cita un secreto**: una comunidad SNMP se nombra por su
  número, un usuario por su nombre.

## Configuración

Se edita en la aplicación, **Ajustes → Agentes → Barrido**:

- **Subredes**, una por línea. Vacío: el agente barre su propia /24.
- **Comunidades SNMP**. Vacío: prueba con `public`.
- **Credenciales**, una por protocolo: SSH, WinRM, SNMPv3, y los hipervisores — vCenter, Proxmox, Hyper-V y XCP-ng (estos cuatro con su dirección: no se descubren solos).

Todo lo que es un secreto se guarda **cifrado en la base de datos** y se le
entrega al agente en su latido, por su canal ya autenticado. No vuelve nunca al
navegador: la pantalla enseña cuántas credenciales hay, no cuáles.

Las credenciales van **separadas por protocolo a propósito**. La contraseña del
vCenter no es la del Linux, y probar una donde no toca son intentos fallidos de
autenticación: contra un Directorio Activo, eso bloquea la cuenta.

Para pruebas standalone, el entorno manda sobre el servidor:

```bash
CENYA_SUBNETS=192.168.1.0/24,10.0.0.0/24
CENYA_SNMP_COMMUNITIES=public,privada
CENYA_CREDENTIALS='[
  {"kind": "ssh",     "username": "root",  "secret": "..."},
  {"kind": "ssh",     "username": "admin", "key_file": "/home/user/.ssh/id_ed25519", "port": 2222},
  {"kind": "winrm",   "username": "MIEMPRESA\\administrador", "secret": "..."},
  {"kind": "vmware",  "username": "administrator@vsphere.local", "secret": "...", "host": "vcenter.midominio.local"},
  {"kind": "proxmox", "username": "root@pam", "secret": "...", "host": "proxmox.midominio.local"}
]'
```

Campos admitidos: `kind` y `username` son obligatorios; `secret`, `host`,
`port`, `key_file`, `ca_file` y `label` son opcionales. Un JSON mal escrito
**no tumba el arranque**: el agente se queda sin esas credenciales y lo dice,
igual que si no hubiera ninguna. Morir ahí dejaría sin barrido también al ping
y al SNMP, que no tienen la culpa.

## Dependencias

Todas **opcionales** y todas permisivas. Sin ellas instaladas el agente arranca
igual y el colector que las necesita se reporta no disponible.

| Para | Qué usa | Licencia |
|---|---|---|
| SNMP | `pysnmp` | BSD-2-Clause |
| WinRM | `pywinrm` + `requests_ntlm` | MIT · ISC |
| Servicio de Windows | `pywin32` (solo Windows) | BSD-3-Clause en lo que se usa; su único componente LGPL, `adodbapi`, no se importa |
| SSH | el binario `ssh` del sistema | — |
| Hipervisores | REST con la biblioteca estándar | — |

Se instalan solas en la imagen Docker del agente.

**Dos ausencias deliberadas**, por si alguien las echa en falta:

- **`paramiko`** es LGPL-2.1, y este proyecto no mete copyleft nuevo. El
  binario `ssh` ya está en cualquier Linux y en el Windows moderno, y el
  barrido ya usaba el `ping` del sistema con el mismo criterio. Para
  credenciales con contraseña hace falta además `sshpass`; sin él solo se usan
  las de clave, y el agente lo avisa en vez de callarse.
- **`pyVmomi`** tiene licencia limpia (Apache-2.0), pero tanto vCenter como
  Proxmox se hablan por REST y el agente ya tiene su cliente HTTP. Un SDK
  entero para hacer peticiones JSON no se pagaba. De regalo, Proxmox salió al
  mismo precio que vCenter.

## Cómo se añade un colector

Un módulo en `agent/collectors/` con una clase que cumple el protocolo
`Collector` (`collect(ctx) -> list[Finding]`) y el decorador `@register`. El
bucle principal no cambia: el registro lo descubre solo. `ctx` trae la config
del servidor (`ctx["config"]`), los overrides del entorno (`ctx["env"]`) y lo
que un colector deja para el siguiente (`ctx["hosts"]`).

Dos cosas que no se pueden saltar:

- **Añádelo a `RUN_ORDER`**, en `agent/collectors/__init__.py`. Un colector que
  no está en esa lista corre igual, pero al final. Y el orden importa: el que
  necesita `ctx["hosts"]` y corre antes que el barrido no encuentra nada, no
  falla, y **no dice nada**. Ese fallo dejó a SNMP inerte en producción sin que
  nadie se enterara; está contado en ese mismo fichero.
- **Nunca lances una excepción hacia arriba.** Si no puedes correr --falta la
  librería, falta el binario, no hay credenciales-- añade una línea a
  `ctx["errors"]` y devuelve `[]`. Un colector que revienta se lleva por
  delante el barrido entero, incluido el ping, que no tenía la culpa.

Las credenciales se piden con `agent/credentials.py`: `creds.for_kind(ctx,
creds.SSH)` devuelve solo las de ese protocolo. No las leas de `ctx["config"]`
a mano.

## Tests

Sin Django, sin red y sin las librerías opcionales instaladas: los subprocesos
y los sockets se fingen con fixtures y fakes.

```bash
python -m unittest discover agent/tests -v
```

Los tests de la parte servidora (bandeja, fusión por huella, API de ingesta y
la pantalla de Ajustes) son de Django y viven en `core/tests/`:

```bash
docker compose exec web python manage.py test core.tests.test_agent_api core.tests.test_discovery core.tests.test_agent_ui
```

## Licencia

El agente se publica bajo [Apache 2.0](LICENSE). Es la parte de Cenya
que corre dentro de la red del cliente, entra en sus equipos y maneja sus
credenciales, y por eso es la parte que tiene que poder leerse, auditarse y
redistribuirse sin pedir permiso. El servidor, en cambio, es propietario
(`LICENSE` de la raíz del repositorio). El agente no importa nada del
servidor, y tiene que seguir así.
