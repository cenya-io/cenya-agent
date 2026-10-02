# Agente v2 · núcleo: protocolo y diseño interno

Especificación de la fase 1 del hito «Agente v2». La leen por igual quien toca
el agente (este repositorio) y quien toca el servidor (repositorio privado de
Cenya). **Lo que dice la sección 1 es un contrato entre los dos**: no se cambia
en un lado sin cambiarlo en el otro, y en este orden: primero el servidor
acepta lo nuevo y lo viejo, después sale el agente.

Versión del agente que lo estrena: **0.11.0**. Número de protocolo: **2**.

Lo que no cambia: el agente solo habla por HTTPS saliente y no abre puertos;
propone y la persona decide; un colector que no puede correr anota en
`ctx["errors"]` y devuelve `[]`, nunca lanza; las notas viajan como códigos
(`agent/notes.py`); ningún secreto en un registro, un informe o un fichero que
no sea el almacén protegido; nada del servidor se importa aquí.

---

## 1. Protocolo (contrato agente ↔ servidor)

Todo es `POST` con cuerpo JSON y `Authorization: Bearer <token>`, salvo
`enroll`. Los errores son `{"error": "<frase para una persona>"}` con el
código HTTP que toque (400 cuerpo mal formado, 401 token no válido o revocado,
402 instalación en solo lectura, 404 no existe, 429 demasiados intentos). Las
fechas son ISO 8601 con zona. Un campo que el receptor no conoce **se ignora**;
un campo que falta toma su valor por defecto. Así se añade sin romper.

Las puertas del protocolo 1 (`/api/agent/heartbeat/`, `/api/agent/findings/`)
siguen existiendo para los agentes 0.10.x.

### 1.1 `POST /api/agent/enroll/` (ampliada)

Petición (lo nuevo es opcional; un agente 0.10.x manda solo los tres primeros):

```json
{
  "code": "K7QF-9M2X-4TQN",
  "hostname": "SRV-OFICINA",
  "version": "0.11.0",
  "protocol": 2,
  "public_key": "-----BEGIN PUBLIC KEY-----\n…",
  "about": { … véase 1.5 … }
}
```

Respuesta: la de hoy (`ok`, `token`, `name`, `uuid`) más `"protocol": 2` (el
máximo que habla el servidor). Un servidor antiguo no lo manda: el agente lo
toma como 1.

`public_key`: PEM SubjectPublicKeyInfo, RSA de 3072 bits. Tope de 2.000
caracteres; algo que no sea una clave RSA pública válida se descarta sin
fallar el enrolado.

### 1.2 `POST /api/agent/v2/checkin/` — el canal de control

Cada `checkin_seconds` (30 por defecto), **también en mitad de una tarea**.

Petición:

```json
{
  "protocol": 2,
  "agent_version": "0.11.0",
  "state": "idle",
  "activity": {
    "task": "inventory", "run_id": "<uuid>", "step": "ssh",
    "done": 14, "total": 37, "started_at": "…"
  },
  "schedule": [
    {"task": "presence", "last_finished_at": "…", "last_status": "ok", "next_at": "…"}
  ],
  "paused_until": null,
  "config_etag": "<el que tiene el agente, o \"\">",
  "about_hash": "<sha256 hex del about canónico>",
  "about": { … solo si cambió o el servidor lo pidió … },
  "outbox": 0
}
```

- `state`: `idle` | `running` | `paused`. `activity` es `null` si no hay tarea.
- `paused_until`: la pausa **local** (puesta en la máquina del agente), o `null`.
- `outbox`: cuántos envíos tiene pendientes en su cola local.

Respuesta:

```json
{
  "ok": true,
  "protocol": 2,
  "server_time": "…",
  "checkin_seconds": 30,
  "config_etag": "<sha256 hex>",
  "config": { … véase 1.4; solo si el etag difiere del que mandó el agente … },
  "need_about": false,
  "orders": [
    {"id": "<uuid>", "kind": "run_task", "params": {"task": "presence"}}
  ],
  "paused_until": null,
  "update": null
}
```

- `config_etag` es el SHA-256 del JSON canónico de `config` (claves ordenadas,
  sin espacios, UTF-8). Lo calcula el servidor; el agente solo lo guarda y lo
  devuelve. Con el mismo etag, `config` no viaja.
- `need_about`: el servidor no tiene el `about` de ese hash; el agente lo manda
  entero en el siguiente checkin.
- `paused_until`: pausa puesta **desde la web**. El agente está en pausa hasta
  la más tardía de las dos (local y de servidor).
- `update`: `null` o `{"version": "0.11.1"}`. En la fase 1 el agente solo lo
  registra; actualizarse es de la fase 6.
- `checkin_seconds`: el agente lo acota a [10, 300].

### 1.3 Encargos (`orders`)

Un encargo se repite en cada respuesta de checkin **hasta que el agente
contesta** en `POST /api/agent/v2/orders/<id>/result/`. El agente no ejecuta
dos veces el mismo `id` (recuerda los que ya atendió) y, si el envío de la
respuesta falla, la deja en su cola y la reintenta.

| `kind` | `params` | Qué hace el agente | `result` |
|---|---|---|---|
| `run_task` | `{"task": "presence"}` (cualquier tarea de 1.4) | La ejecuta ya, fuera de turno | `{}`; lo descubierto llega por `results` con `order_id` |
| `probe` | `{"ip": "10.0.0.5"}` | Sondeo dirigido de **solo esa IP** | `{"probe_report": {…}}`, el mismo informe de `agent/probe.py` |

Cuerpo de la respuesta del agente:

```json
{"status": "done", "result": {…}, "notes": [ … notas con código … ]}
```

`status`: `done` | `failed` | `unsupported`. Un `kind` que el agente no conoce
se contesta `unsupported` (un servidor más nuevo que el agente no lo cuelga).
`run_task` se contesta `done` **al aceptarlo**, no al terminar la tarea.

Servidor: un encargo sin respuesta en 24 h caduca. El `id` solo vale para el
agente al que se le dio (otro agente recibe 404).

### 1.4 `config`

```json
{
  "subnets": ["192.168.1.0/24"],
  "communities": ["public"],
  "credentials": [
    {"id": "c1f0…", "kind": "ssh", "username": "admin", "secret": "…",
     "host": "", "port": 0, "key_file": "", "label": "Switches",
     "scope": {"subnets": ["10.0.0.0/24"], "hosts": []}}
  ],
  "capture_configs": true,
  "tasks": {
    "presence":    {"every_seconds": 300},
    "inventory":   {"every_seconds": 21600},
    "configs":     {"every_seconds": 86400},
    "ups":         {"every_seconds": 300},
    "hypervisors": {"every_seconds": 3600}
  },
  "gentleness": "normal"
}
```

- `every_seconds`: `0` desactiva la tarea. El agente acota a [60, 604800]
  (presencia y SAI) y [300, 604800] (las demás).
- `gentleness`: `gentle` | `normal` | `fast`.
- `credentials[].id`: opaco, estable mientras la credencial no cambie. Lo pone
  el servidor. `scope` vacío o ausente = todo el perfil.
- Hasta la fase 3 (credenciales selladas) los secretos siguen viajando aquí en
  claro por el canal autenticado, como en el protocolo 1; la diferencia es que
  ya solo viajan **cuando cambian**.
- Sin perfil configurado, `config` trae los valores por defecto (subredes
  vacías: cada agente barre su propia /24).

### 1.5 `about` — el agente se presenta

```json
{
  "hostname": "SRV-OFICINA",
  "os": {"system": "Windows", "release": "2022Server", "version": "10.0.20348"},
  "python": "3.12.10",
  "agent_version": "0.11.0",
  "frozen": true,
  "networks": [
    {"interface": "Ethernet", "address": "192.168.1.10",
     "cidr": "192.168.1.0/24", "mac": "aa:bb:cc:dd:ee:ff"}
  ],
  "capabilities": {
    "snmp": true, "ssh": true, "ssh_password": true, "winrm": true,
    "hypervisors": true, "sealed_credentials": true
  },
  "excluded": {"subnets": [], "addresses": []},
  "auto_update": true
}
```

`about_hash` = SHA-256 del JSON canónico. Servidor: tope de 32 KB y de 64
redes; todo texto se recorta a la longitud de su columna antes de guardar (un
valor largo del agente no puede dar un 500).

### 1.6 `POST /api/agent/v2/results/` — el resultado de una tarea

```json
{
  "run": {
    "id": "<uuid generado por el agente>",
    "task": "presence",
    "trigger": "schedule",
    "order_id": null,
    "started_at": "…", "finished_at": "…",
    "status": "ok",
    "notes": [ … ], "error": "texto en castellano",
    "stats": {"hosts_alive": 41, "new_hosts": 1},
    "agent_version": "0.11.0"
  },
  "items": [ … hallazgos, en el formato de siempre … ],
  "part": 1,
  "final": true
}
```

- `trigger`: `schedule` | `order` | `new_host`.
- `status`: `ok` | `partial` | `error`.
- **Idempotente por `run.id`**: reenviar el mismo trozo no duplica la
  ejecución ni los hallazgos (estos ya lo son por huella). Los trozos de una
  misma ejecución comparten `run.id`; `part` empieza en 1 y `final` cierra.
- Mismos topes que el protocolo 1: 500 elementos y 1,5 MB por trozo.

Respuesta: `{"ok": true, "created": 3, "refreshed": 38}`.

Un resultado de `presence` trae hallazgos «finos» (IP, MAC, nombre). **No
puede borrar lo que un inventario anterior ya sabía** de ese equipo: el
servidor funde, no sustituye.

### 1.7 `POST /api/agent/v2/goodbye/`

`{"reason": "uninstall"}`. El servidor marca el agente como desinstalado y su
token deja de valer. Respuesta `{"ok": true}`.

### 1.8 Compatibilidad

- **Agente 2 contra servidor 1**: `v2/checkin` contesta 404. El agente pasa al
  bucle del protocolo 1 (el de la 0.10.x, que se conserva) y vuelve a probar
  `v2/checkin` cada hora.
- **Agente 1 contra servidor 2**: funciona como hoy.

---

## 2. Diseño interno del agente

### 2.1 Tareas

| Tarea | Colectores | Sobre qué equipos |
|---|---|---|
| `presence` | `local`, `sweep` | Las subredes del perfil |
| `inventory` | `snmp`, `ssh`, `winrm` | Los vivos de la última presencia; o solo los nuevos |
| `configs` | `ssh` (solo la copia) | Los equipos de red en los que SSH ya entró |
| `ups` | `snmp` (solo la UPS-MIB) | Los que ya contestaron a la UPS-MIB |
| `hypervisors` | `hypervisors` | Los servidores de sus credenciales |

- Las tareas programadas van **de una en una** (una cola). Un encargo `probe`
  corre en su propio hilo, sin esperar a la cola. Un `run_task` entra el
  primero en la cola.
- `inventory`, `configs` y `ups` necesitan los vivos: usan los de la última
  presencia si tiene menos de dos periodos de presencia; si no, se lanza antes
  una presencia (que empuja su propio resultado).
- Tras cada presencia, los equipos que la memoria no conocía disparan un
  `inventory` solo para ellos (`trigger: "new_host"`).
- En pausa no arranca ninguna tarea programada; la que está en curso termina.
  Los encargos sí se atienden (los pide una persona).
- Cada tarea empuja su resultado al terminar. Si el envío falla va a la cola
  local y la siguiente tarea no espera.

### 2.2 El contexto de un colector (`ctx`)

La interfaz del colector no cambia: `collect(ctx) -> list[Finding]`. Claves:

| Clave | Tipo | Quién la pone | Para qué |
|---|---|---|---|
| `config` | dict | el bucle | la de 1.4 |
| `env` | `Config` | el bucle | variables y ajustes locales |
| `task` | str | el bucle | la tarea en curso. **Ausente = comportamiento de la 0.10.x** (todo de una vez): así el bucle del protocolo 1 y los tests de siempre no cambian |
| `hosts` | list[{"ip","mac"}] | `sweep` en presencia; el bucle en las demás | los vivos |
| `targets` | list[str] \| None | el bucle | si no es `None`, solo esas IP |
| `memory` | `Memory` \| None | el bucle | 2.3. `None` = sin memoria (protocolo 1) |
| `workers` | {"ping","login","snmp"} | el bucle | cuántas conexiones a la vez (2.5). Ausente = las constantes de hoy |
| `excluded` | `Excluded` \| None | el bucle | 2.4 |
| `progress` | callable(step, done, total) \| None | el bucle | el colector avisa de su avance; llamarlo nunca lanza |
| `errors` | list[Note] | los colectores | como hoy |

Con `task`:

- `inventory`: `ssh` interroga pero **no** copia configuraciones; `snmp` pide
  identidad, interfaces y vecinos, y si el equipo contesta a la UPS-MIB lo
  apunta en la memoria.
- `configs`: `ssh` trabaja solo sobre `memory.config_hosts()`, y solo pide la
  copia (con la credencial recordada).
- `ups`: `snmp` trabaja solo sobre `memory.ups_hosts()` y pide solo la UPS-MIB;
  el hallazgo lleva la misma identidad que el del inventario (la MAC guardada
  en la memoria) para refrescar la misma fila, no abrir otra.

### 2.3 Memoria (`agent/memory.py`)

Prescindible: si el fichero falta o está roto, se empieza de cero y **nunca**
se lanza. Sin secretos: de una credencial solo se guarda su `id`.

```python
class Memory:
    @classmethod
    def load(cls, path: Path | None) -> "Memory": ...   # None: solo en memoria
    def save(self) -> None: ...                         # atómico; nunca lanza

    # equipos
    def note_host(self, ip: str, mac: str, now: datetime) -> bool: ...  # True si es nuevo
    def flag(self, host_key: str, *, ups: bool | None = None,
             config_family: str | None = None, identity_mac: str | None = None) -> None: ...
    def ups_hosts(self) -> list[dict]: ...      # [{"ip","mac","identity_mac"}]
    def config_hosts(self) -> list[dict]: ...   # [{"ip","mac","family"}]

    # credenciales
    def order_for(self, host_key: str, protocol: str,
                  credentials: list[Credential], now: datetime) -> list[Credential]: ...
    def record_success(self, host_key: str, protocol: str,
                       credential: Credential, now: datetime) -> None: ...
    def record_round_failed(self, host_key: str, protocol: str, now: datetime) -> None: ...
    def credentials_changed(self, etag: str) -> None: ...
```

- `host_key`: la MAC si se conoce; si no, la IP.
- `order_for` devuelve qué credenciales probar y en qué orden: primero la que
  entró la última vez; las demás **solo** si no ha habido ya una ronda
  completa fallida contra ese equipo y protocolo en las últimas 24 h. Antes de
  nada filtra por `scope` (una credencial con alcance no se prueba fuera de
  él). Con la lista vacía el colector no intenta nada y no lo anota como error.
- `credentials_changed(etag)`: al cambiar el etag de la configuración se
  olvidan las rondas fallidas (alguien ha tocado las credenciales: merece otra
  ronda), no los aciertos.
- Un equipo que no se ve en 30 días se olvida.

`Credential` gana `ident` (el `id` del servidor; si no viene, un derivado
estable de tipo, usuario, servidor, puerto, etiqueta y posición — nunca del
secreto) y `scope`.

### 2.4 Exclusiones

`Excluded` (en `agent/memory.py` o módulo propio del mismo dueño):
`Excluded(subnets, addresses)` con `__contains__(ip) -> bool`. El barrido no
hace ping a una dirección excluida y ningún colector la toca, tampoco un
`probe`. Salen de los ajustes locales (2.6).

### 2.5 Suavidad

| | `ping` | `login` (SSH/WinRM) | `snmp` |
|---|---|---|---|
| `gentle` | 8 | 2 | 5 |
| `normal` | 50 | 10 | 20 |
| `fast` | 100 | 20 | 40 |

El ajuste local `gentleness_cap` puede bajarla, nunca subirla.

### 2.6 Ficheros (carpeta de estado, la de `agent/store.py`)

| Fichero | Contenido |
|---|---|
| `enrollment.json` | portal y token (ya existe) |
| `identity.key` | clave privada RSA (PEM), con la misma protección que el token |
| `settings.json` | ajustes locales |
| `memory.json` | 2.3 |
| `outbox/` | envíos pendientes: `<run_id>-<part>.json` y `order-<id>.json` |
| `logs/agent.log` | actividad, rotada (5 × 2 MB) |

`settings.json` (todo opcional):

```json
{
  "language": "", "ca_bundle": "",
  "proxy": {"mode": "system", "url": ""},
  "excluded": {"subnets": [], "addresses": []},
  "gentleness_cap": "", "auto_update": true, "notifications": true,
  "paused_until": null
}
```

Las variables `CENYA_*` mandan sobre `settings.json`.

**La carpeta se protege en cada arranque** (servicio, consola, `enroll`,
`--once`), antes de leer nada de ella, y solo lo sabe hacer `agent/store.py`
(`secure_state_dir`):

- Windows: la carpeta con una DACL protegida (nada heredado de
  `%ProgramData%`): SYSTEM y Administradores control total, la cuenta que corre
  el agente también cuando no es ninguna de las dos, y Usuarios y OWNER RIGHTS
  solo lectura **de la carpeta, sin herencia** (el icono de bandeja lee
  `status.json`, que lleva esa lectura explícita y nada más la lleva).
  `enrollment.json`, `identity.key`, `settings.json`, `memory.json`, `outbox/` y
  `logs/`: SYSTEM, Administradores (y la cuenta que corre el agente si no es
  ninguna de las dos), sin Usuarios y sin herencia. Elevado o como SYSTEM, el
  dueño pasa a ser Administradores. Todo por SID.
- POSIX: carpeta `0700`, ficheros `0600`.
- **Lo que ya había solo se cree si la carpeta ya estaba protegida.** Si no lo
  estaba (DACL no protegida, o un grupo amplio --Usuarios, Usuarios
  autentificados, Todos, INTERACTIVE-- podía crear o cambiar algo dentro, o un
  dueño ajeno sin OWNER RIGHTS; en POSIX, escritura de grupo u otros o dueño
  ajeno), `settings.json`, `identity.key`, `memory.json`, `enrollment.json`,
  `outbox/` y `logs/` se renombran con el sufijo `.untrusted-<fecha>` dentro de
  la carpeta (nunca se borran) y se dice en una línea. El enrolamiento apartado
  no se usa: el agente dice que hay que repetirlo
  (`cenya-agent enroll <cadena> --force`) y sale como cuando no está enrolado.
  La disposición que dejaba el instalador 0.10.x (SYSTEM y Administradores
  total; Usuarios y OWNER RIGHTS lectura heredada) cuenta como protegida.
- Si una carpeta sin proteger no se puede proteger (sin derechos), el agente no
  arranca ni guarda en ella ningún secreto, y dice por qué.

Cola (`outbox/`): tope de 50 MB y de 24 h; lo que no cabe o caduca se tira
empezando por lo más viejo, y se anota (`outbox_dropped`). Se vacía en orden
en cada checkin que sale bien. Nunca contiene credenciales: solo resultados.

### 2.7 Estado para el icono de bandeja

`status.json` se sigue escribiendo como hoy (el icono actual tiene que seguir
funcionando hasta la fase 5), con el paso y la tarea en curso.

---

## 3. Credenciales selladas (fase 3)

El servidor guarda cada secreto **cerrado para un agente concreto** y no puede
abrirlo. Protege de una fuga de la base de datos o de una copia de seguridad,
y de que quien opera el servidor lea las contraseñas. **No** protege de un
servidor manipulado a propósito (sirve la página donde se teclean y entrega
las claves públicas); eso se dice tal cual en el contrato de encargo.

### 3.1 El sobre

Cifrado híbrido con lo que traen todos los navegadores (WebCrypto) y
`cryptography` en el agente:

1. Clave AES-256 aleatoria `K` y `iv` de 12 bytes aleatorios.
2. `ct` = AES-256-GCM(`K`, `iv`, texto, AAD), con la etiqueta de 16 bytes al
   final (como la devuelven WebCrypto y `AESGCM`).
3. `ek` = RSA-OAEP(SHA-256, MGF1-SHA-256, sin etiqueta) de `K` con la clave
   pública del agente (la de 1.1).

```json
{"v": 1, "alg": "RSA-OAEP-256+A256GCM", "ek": "<base64>", "iv": "<base64>", "ct": "<base64>"}
```

Base64 estándar con relleno. El **texto** es JSON UTF-8 con solo los campos
secretos: `{"secret": "…", "priv_secret": "…"}` (una comunidad SNMP v2c va en
`secret`). La **AAD** ata el sobre a su dueño y a su credencial, para que no se
pueda cambiar de sitio:

```
cenya-seal-v1|<uuid del agente>|<id de la credencial>
```

Para lo que no es una credencial guardada (el token de NetBox de 3.4) el
tercer campo es el `id` del encargo.

Un sobre que no abre (clave distinta, AAD distinta, dato tocado) **no es un
error del barrido**: esa credencial no se usa y se anota
(`credentials` / `sealed_unreadable`, con `count`).

### 3.2 `config` con credenciales selladas

Sustituye a `communities` y a los secretos en claro de 1.4:

```json
"credentials": [
  {"id": "<uuid>", "kind": "ssh", "name": "Switches Aruba", "username": "admin",
   "host": "", "port": 0, "key_file": "",
   "auth_protocol": "", "priv_protocol": "",
   "scope": {"subnets": ["10.0.0.0/24"], "hosts": []},
   "sealed": { … sobre de 3.1 para ESTE agente … }}
]
```

- `kind` nuevo: `snmp` (una comunidad v2c; `username` vacío).
- Una credencial sin sobre para este agente viaja sin `sealed`: el agente la
  ignora y la cuenta en `sealed_unreadable`.
- Mientras un perfil tenga secretos sin sellar (servidor sin migrar), `secret`
  y `communities` siguen llegando como en 1.4 y el agente los usa. Un agente
  0.11 entiende las dos formas.
- El agente informa de lo que funcionó en `stats` de `results`:
  `"credentials_ok": {"<id>": <nº de equipos>}`.

### 3.3 Encargos nuevos

| `kind` | `params` | Qué hace el agente | `result` |
|---|---|---|---|
| `test_credential` | `{"credential_id": "<uuid>", "ip": "10.0.0.5"}` | Prueba **esa** credencial contra esa IP (para un hipervisor, contra su servidor; `ip` puede faltar) | `{"ok": true, "line": {código y parámetros, como un informe de sondeo}}` |
| `reseal` | `{"agent": "<uuid del agente nuevo>", "public_key": "<PEM>", "credential_ids": ["…"]}` | Abre sus sobres de esas credenciales y los cierra para la otra clave (AAD con el uuid del agente nuevo) | `{"envelopes": {"<id>": {sobre}}, "missing": ["<id>"]}` |
| `netbox_export` | `{"url": "https://netbox…", "verify_tls": true, "sealed_token": {sobre}}` | Lee ese NetBox (`agent/netbox_export.py`) y sube el resultado a 3.4 | `{"import": "<uuid>", "summary": {"devices": 214, …}}` |

- `test_credential` no consulta ni altera el límite de rondas de la memoria
  (lo pide una persona), pero apunta un acierto.
- Ninguna respuesta cita un secreto, tampoco en un error.
- `netbox_export` informa de su avance en `activity` (paso = colección).

### 3.4 `POST /api/agent/v2/netbox-bundle/`

El cuerpo es el JSON del exportador (el mismo fichero de hoy), con
`Content-Type: application/json` y la cabecera `X-Cenya-Order: <id>` cuando
viene de un encargo. Tope de 50 MB. Respuesta
`{"ok": true, "import": "<uuid>"}`. El servidor lo valida con el mismo lector
que la subida a mano y lo deja como lectura pendiente; no importa nada hasta
que una persona lo confirma.

---

## 4. Canal local (fase 5)

Entre el servicio y la aplicación de escritorio, en la misma máquina. **No es
un puerto de red.**

- Windows: *named pipe* `\.\pipe\CenyaAgent`. Linux: socket Unix
  `<carpeta de estado>/agent.sock`.
- Lo sirve el servicio. Un mensaje por línea, JSON UTF-8:
  petición `{"id": 1, "op": "status", "args": {}}` → respuesta
  `{"id": 1, "ok": true, "data": {…}}` o
  `{"id": 1, "ok": false, "error": "<código>", "message": "<frase>"}`.
- **Leer** puede cualquier usuario local; **actuar**, solo un administrador
  (Windows: el servicio suplanta al cliente del pipe y comprueba que su token
  pertenece al grupo Administradores, elevado; Linux: `SO_PEERCRED`, uid 0 o
  el del servicio). Sin permiso: `error: "forbidden"`.

| `op` | Tipo | Qué hace |
|---|---|---|
| `status` | leer | conexión, tarea en curso y progreso, agenda, pausa, versión, cola |
| `log` | leer | últimas líneas del registro (`args.lines`, `args.after`) |
| `about` | leer | la presentación de 1.5 |
| `settings.get` | leer | ajustes locales, sin secretos |
| `run` | actuar | `args.task`: ejecuta ya esa tarea |
| `pause` / `resume` | actuar | `args.until` (ISO) o `args.seconds` |
| `settings.set` | actuar | cambia ajustes locales (2.6) y los aplica sin reiniciar |
| `probe` | actuar | `args.ip`: sondeo dirigido, devuelve el informe |
| `test_connection` | actuar | nombre, puerto, certificado y token, paso a paso |
| `connect` | actuar | `args.connection` (cadena o código + portal): enrola o cambia de portal |
| `disconnect` | actuar | se despide del servidor (1.7) y borra el enrolado |
| `netbox.export` | actuar | `args.url`, `args.token`, `args.verify_tls`, `args.send`: lee un NetBox; con `send` lo sube (3.4), sin él lo guarda en `args.path` |
| `support_bundle` | actuar | escribe el paquete de soporte en `args.path`, sin secretos |
| `check_update` | actuar | pregunta por la versión vigente |

Un secreto que llega por este canal (el token de NetBox) se usa y se olvida:
no se guarda, no se registra, no vuelve en ninguna respuesta. Las operaciones
largas (`netbox.export`, `probe`) contestan al terminar; su avance se lee con
`status`.
