# Perfiles de fabricante por SNMP — contrato de la fase 1

*08-10-2026. Sale del análisis `analisis-netdisco-2026-10-08.md` del repositorio del servidor. Rama `perfiles-snmp` de este repositorio.*

## Qué se construye

Hoy el colector SNMP devuelve `hostname`, `description` (sysDescr) e interfaces, y nada más: por SNMP el agente **no dice qué es el equipo**. Esta fase copia el método de SNMP::Info (Netdisco): mirar `sysObjectID` y `sysDescr`, elegir un **perfil de fabricante** y con él pedir dos o tres OIDs propios que dan modelo, número de serie, sistema y versión. El hallazgo `host` pasa a llevar `manufacturer`, `model`, `serial`, `os` (que el servidor ya acepta: `core/discovery.py:820-823`) y `os_version`.

Protocolo: **sin cambios**. Son campos nuevos dentro del `payload`; el servidor ignora los que no conoce.

## Reparto de archivos (dos agentes en paralelo, sin pisarse)

| Archivo | Dueño | Contenido |
|---|---|---|
| `agent/profiles.py` | motor | Tipos (`Profile`, `Identity`), `resolve(object_id, description) -> Profile`, `identify(profile, system, extra, entity) -> Identity`, `extra_oids(profile)`. Importa la tabla de `profiles_data.py`. |
| `agent/snmp.py`, `agent/collectors/snmp.py` | motor | Integración: tras `SYSTEM_OIDS`, resolver el perfil, pedir sus OIDs con `_get`, respaldo ENTITY-MIB, y volcar los campos en el `payload` del hallazgo `host`. |
| `agent/tests/test_profiles.py` | motor | Tests del motor con dos o tres perfiles mínimos **definidos en el propio test** (no depende de la tabla real). |
| `agent/profiles_data.py` | datos | La tabla `PROFILES: tuple[Profile, ...]`, un perfil por fabricante, con comentarios de dónde sale cada OID. |
| `agent/tests/test_profiles_data.py` | datos | Un test por perfil con `sysDescr` y `sysObjectID` **reales** (capturados de equipos reales, de la documentación del fabricante, de SNMP::Info o de los issues de LibreNMS/Netdisco), que comprueba que `resolve` elige ese perfil y que `identify` saca modelo/versión de la descripción cuando el perfil lo promete. |

El agente de datos puede importar `Profile` de `agent/profiles.py`; hasta que exista, trabaja contra la definición de abajo (es exactamente la que el motor tiene que implementar).

## El formato del perfil

```python
from dataclasses import dataclass, field

@dataclass(frozen=True)
class Profile:
    key: str                                  # "mikrotik", "cisco-ios", "cisco-sb"… estable, en minúsculas
    vendor: str                               # Lo que ve la persona: "MikroTik", "Cisco", "HPE Aruba"
    enterprise: int | None = None             # Número de empresa IANA: sysObjectID = 1.3.6.1.4.1.<enterprise>.…
    object_id_prefix: str = ""                # Prefijo largo cuando una empresa tiene varias familias:
                                              #   Cisco Small Business "1.3.6.1.4.1.9.6.1", Cisco clásico "1.3.6.1.4.1.9.1"
    description_match: str = ""               # Regex (re.search, IGNORECASE) sobre sysDescr. Gana a enterprise.
    os: str = ""                              # Nombre fijo del sistema: "RouterOS", "IOS", "JunOS". Vacío si lo da un OID/regex.
    serial_oid: str = ""                      # OID de hoja (termina en .0) con el número de serie
    model_oid: str = ""                       # OID de hoja con el modelo
    version_oid: str = ""                     # OID de hoja con la versión del sistema
    os_oid: str = ""                          # OID de hoja con el nombre del sistema (raro; Fortinet no lo tiene, Synology sí)
    model_from_description: str = ""          # Regex, un grupo (por alternativa): el modelo, sacado de sysDescr
    version_from_description: str = ""        # Regex, un grupo (por alternativa): la versión, sacada de sysDescr
    os_from_description: str = ""             # Regex, un grupo (por alternativa): el sistema, sacado de sysDescr
    entity_fallback: bool = True              # Si tras todo falta modelo o serie, pedir ENTITY-MIB (chasis)
```

Reglas:

- **Un perfil no pide tablas**, solo OIDs de hoja (`.0`): identificar un equipo cuesta un `get` más, nunca un `walk`. La única tabla permitida es ENTITY-MIB, que es común y que `snmp.py` ya recorre para los stacks.
- Un OID de perfil que no contesta **no es un error**: ese campo queda vacío y se pasa al siguiente respaldo.
- Orden de resolución (`resolve`), copiado de `device_type` de SNMP::Info:
  1. `description_match`, en el orden de la tabla (el primero que casa gana).
  2. `object_id_prefix`, el **más largo** que sea prefijo de `sysObjectID`.
  3. `enterprise` igual al quinto número de `sysObjectID` (`1.3.6.1.4.1.N`).
  4. Si nada casa: `None`, y el equipo se identifica solo con ENTITY-MIB genérica (`entity_fallback`).
- Orden de cada campo (`identify`): OID del perfil → regex sobre sysDescr → ENTITY-MIB (solo modelo, serie, versión y fabricante: `entPhysicalModelName` .13, `entPhysicalSerialNum` .11, `entPhysicalSoftwareRev` .10, `entPhysicalMfgName` .12 de la **primera fila con `entPhysicalClass` = 3 (chassis)**) → vacío. `vendor` es siempre el del perfil; sin perfil, `entPhysicalMfgName` o vacío.
- `os` en el `payload` es **lo que el servidor guarda en `os_firmware`**: `"<os> <os_version>"` cuando hay los dos, uno de ellos si falta el otro, y **vacío** si no hay nada (el servidor ya pone `description` de respaldo: no mandarle sysDescr como `os`).
- `os_version` va además suelto, para el día que el servidor lo guarde aparte.
- La identidad no toca `hostname`, `description`, `interfaces` ni nada de lo que ya hay.

## Identidad devuelta

```python
@dataclass(frozen=True)
class Identity:
    manufacturer: str = ""
    model: str = ""
    serial: str = ""
    os: str = ""          # nombre: "IOS", "RouterOS"
    os_version: str = ""  # "15.2(7)E8", "7.15.3"
    profile: str = ""     # key del perfil, o "" si se resolvió por ENTITY-MIB a secas

    def payload_fields(self) -> dict[str, str]:
        """Solo los campos con valor: manufacturer, model, serial, os (compuesto), os_version."""
```

## Perfiles que entran en esta fase (agente de datos)

Por lo que hay en una pyme española, en este orden de importancia. Para cada uno, los OIDs vienen de SNMP::Info (`lib/SNMP/Info/Layer*/<Clase>.pm` en github.com/netdisco/snmp-info, licencia BSD: copiar con atribución en `NOTICE`), de LibreNMS (`includes/definitions/*.yaml` y `includes/discovery/os/*`) o del MIB del fabricante:

1. Cisco IOS / IOS-XE (`1.3.6.1.4.1.9.1`; versión por regex de sysDescr `Version ([^,\s]+)`; serie por ENTITY-MIB; modelo por ENTITY-MIB)
2. Cisco NX-OS (sysDescr `NX-OS`)
3. Cisco Small Business / CBS (`1.3.6.1.4.1.9.6.1`)
4. Cisco Meraki (`29671`)
5. HP ProCurve / Aruba switches (`1.3.6.1.4.1.11.2.3.7.11`; serie en `1.3.6.1.4.1.11.2.36.1.1.2.9.0`)
6. Aruba CX (`47196`)
7. HPE Comware / H3C (`25506`; sysDescr `Comware`)
8. Dell Networking N-series / OS6 (`674.10895`), Dell OS10 (`674.11000.5000.100`)
9. Netgear (`4526`; sysDescr suele traer el modelo)
10. TP-Link (`11863`)
11. Ubiquiti EdgeSwitch / EdgeRouter / UniFi (`4413`, `41112`, `10002`)
12. MikroTik (`14988`; `mtxrLicVersion` 1.3.6.1.4.1.14988.1.1.4.4.0, serie 1.3.6.1.4.1.14988.1.1.7.3.0, modelo por regex `^RouterOS\s+(.+)$`)
13. Juniper (`2636`; sysDescr `Juniper Networks, Inc. (\S+) .* kernel JUNOS ([\d.A-Z-]+)`; serie `1.3.6.1.4.1.2636.3.1.3.0`)
14. Fortinet (`12356`; `fgSysVersion` 1.3.6.1.4.1.12356.101.4.1.1.0, serie `fnSysSerial` 1.3.6.1.4.1.12356.100.1.1.1.0, modelo del sysObjectID o sysDescr)
15. Palo Alto (`25461`; `panSysSwVersion` 1.3.6.1.4.1.25461.2.1.2.1.1.0, serie 1.3.6.1.4.1.25461.2.1.2.1.3.0, modelo 1.3.6.1.4.1.25461.2.1.2.2.1.0)
16. Check Point (`2620`; `svnVersion` 1.3.6.1.4.1.2620.1.6.4.1.0, serie 1.3.6.1.4.1.2620.1.6.16.3.0, modelo 1.3.6.1.4.1.2620.1.6.16.7.0)
17. Sophos (`2604`)
18. Huawei (`2011`; sysDescr `Huawei Versatile Routing Platform Software.*Version ([\d.]+)`)
19. D-Link (`171`)
20. Allied Telesis (`207`)
21. APC (`318`; `upsBasicIdentModel` 1.3.6.1.4.1.318.1.1.1.1.1.1.0, serie `upsAdvIdentSerialNumber` 1.3.6.1.4.1.318.1.1.1.1.2.3.0, firmware 1.3.6.1.4.1.318.1.1.1.1.2.1.0)
22. Eaton (`534`; xUPS MIB `xupsIdentModel` 1.3.6.1.4.1.534.1.1.2.0, versión 1.3.6.1.4.1.534.1.1.1.0)
23. Synology (`6574`; modelo 1.3.6.1.4.1.6574.1.5.1.0, serie 1.3.6.1.4.1.6574.1.5.2.0, versión 1.3.6.1.4.1.6574.1.5.3.0)
24. QNAP (`24681` y `55062`)
25. VMware ESXi (`6876`; sysDescr `VMware ESXi (\S+) build-(\d+)`)
26. Net-SNMP / Linux (`8072`, `2021`; os por regex de sysDescr `^Linux \S+ (\S+)`: versión del núcleo; sin fabricante)
27. Windows (`311`; sysDescr `Hardware:.*Software: Windows Version ([\d.]+)`)
28. Zyxel (`890`)
29. Brother / HP / Canon / Epson impresoras (`2435`, `11.2.3.9`, `1602`, `1248`; modelo en `hrDeviceDescr` 1.3.6.1.2.1.25.3.2.1.3.1 o `prtGeneralPrinterName`); **Printer-MIB es común a todos**: un perfil genérico `printer` por sysDescr o por `1.3.6.1.2.1.43` no se puede (no es sysObjectID); usar la empresa.
30. Hikvision (`39165`), Dahua (`1004849`), Axis (`368`): cámaras; modelo por sysDescr.

Los que no se puedan documentar con un `sysDescr`/`sysObjectID` real **no se inventan**: mejor 20 perfiles probados que 30 adivinados. Cada perfil lleva en el comentario la fuente del OID.

## Lo que no entra

- Cambios de protocolo ni de servidor (lo poco que falte en la bandeja va en otro PR).
- MIBs con nombres, `walk` de tablas propietarias, PoE, módulos, fuentes.
- Tocar `stacks.py`, el colector SSH o los hipervisores.

## Comprobación

- `python -m unittest agent.tests.test_profiles agent.tests.test_profiles_data agent.tests.test_collectors` en verde.
- Un equipo sin perfil y sin ENTITY-MIB sigue produciendo exactamente el mismo hallazgo que hoy (test de regresión en `test_collectors`).
- Un OID de perfil que no contesta no rompe el inventario del equipo.

---

# Fase 2 · Conectar como Netdisco (rama `conexion-netdisco`, 08-10-2026)

Lo que cambia, todo en el agente y sin tocar el protocolo:

- **Pasada rápida y pasada lenta** (`agent/snmp.py::_query_host_indexed`): primero todas las credenciales con 0,5 s y sin reintento; solo si nadie contesta, otra vez con 2 s y un reintento. Un equipo que **ya contestó alguna vez** (la memoria recuerda una credencial para él, `tasking.answered_before`) solo recibe la pasada rápida: si hoy calla es que está apagado. `query_plan(..., known=[...])` es quien lo dice; `query_hosts` (protocolo 1, sin memoria) sigue siendo paciente con todos.
- **Qué cuenta como sesión** (`_answered`): `sysDescr` o `sysUpTime` con valor. Cuatro binds vacíos no son un equipo y su comunidad no se recuerda como la buena. `sysUpTime` entra en `SYSTEM_OIDS` por eso.
- **Columnas nuevas de IF-MIB** por interfaz: `type` (IANAifType → `ethernet`, `lag`, `vlan`, `virtual`, `loopback`, `tunnel`, `wifi`, `other`), `admin` (`ifAdminStatus`) y `lag` (nombre del agregado al que pertenece el puerto, por `dot3adAggPortAttachedAggID` de IEEE8023-LAG-MIB, oportunista). Solo viajan cuando traen algo: un hallazgo sin ellas es idéntico al de antes. **El servidor aún no las usa**: hoy deduce el tipo por el nombre (`core/discovery.py::_interface_kind`); usarlas es un PR pequeño del servidor.

Lo que el análisis proponía y **no** entra, con el porqué: «recordar el perfil detectado» no ahorra nada aquí, porque `resolve` es puro y no cuesta red (en Netdisco ahorraba cargar clases Perl). Dúplex y MTU no tienen sitio en el modelo del servidor.

---

# Fase 3 · Vecinos con IP (rama `vecinos-con-ip`, 08-10-2026)

Del análisis, la parte del agente. Las otras dos piezas de la fase ya existían en el servidor: **descartar lo que un switch ve por una boca de subida** es `core/port_placement.py` (hito «ve detrás»), y **casar un extremo sin IP por su MAC o por su nombre** lo hace `core/link_check.py` (MAC de interfaz → IP → nombre, corto o largo). Lo que faltaba era que un vecino LLDP o CDP **llegase con IP**: sin ella, un vecino en otra subred (que el barrido nunca pingó) no tenía a quién sondear con «Descubrir».

- LLDP: `lldpRemManAddrIfSubtype` (`1.0.8802.1.1.2.1.4.2.1.3`), cuyo índice lleva la dirección de gestión (`lldp_man_addr_from_suffix`); IPv4 gana a IPv6.
- CDP: `cdpCacheAddressType` + `cdpCacheAddress` (octetos en bruto, `_ip_from_value`).
- El vecino trae `remote_ip`; el enlace lo pone en `payload.remote.device_ip` y **nunca en la huella** (`identity.remote.device_ip` sigue vacía): un enlace ya conocido no se duplica por leer la IP. El servidor lee los extremos de la carga (`link_check`, `discovery`), así que casa por IP y sondea sin cambios.

Lo que queda de la fase 3 para el servidor (otro PR): el **descubrimiento en cadena** — que un vecino con IP fuera de los rangos del perfil se ofrezca a añadir a las redes del perfil o a sondear solo, con límite de saltos y sin entrar en teléfonos ni puntos de acceso.
# Fase 4 · Tablas ARP y MAC por SSH (rama `tablas-por-ssh`, 08-10-2026)

Para las redes donde solo el cortafuegos sabe quién está, y nadie activó SNMP. Todo en el agente, protocolo sin cambios: las tablas viajan **con la forma del hallazgo SNMP** (`arp` como `[{ip, mac}]`, `fdb_ports` por boca) y los enlaces los construye el mismo código (`collectors.snmp._links_for`, con el nombre del puerto como índice).

- `agent/tables.py`: una orden de ARP por familia (`ARP_COMMANDS`: Linux, Cisco, JunOS, ProCurve/Aruba, Dell, Huawei, Comware, MikroTik, Fortinet, Gaia) y una de tabla MAC solo para los switches (`MAC_COMMANDS`: Cisco, JunOS, ProCurve, Dell, Huawei, Comware, MikroTik). ESXi y la familia `cli` no se preguntan.
- **ARP con un solo lector**: una fila es una línea con una IP y una MAC, se escriban como se escriban (`aa:bb:…`, `aabb.ccdd.eeff`, `aabb-ccdd-eeff`, `0050:56aa:bb20` de Fortinet, `001b3f-aabbcc` de ProCurve). Fuera las filas `incomplete`/`failed`, las multicast y las de broadcast.
- **MAC con un lector por familia** (`MAC_PARSERS`), porque ahí sí cambian las columnas; fuera la fila de la CPU, las interfaces enrutadas del propio switch (`Vlan1`, `Loopback`) y, en MikroTik, las MAC locales del puente.
- `collectors/ssh.py::with_tables` las pide **con la credencial que entró** (una o dos órdenes más por equipo de red por inventario; Linux una), después de los stacks; el hallazgo `host` lleva `arp` y `fdb_ports` solo si traen algo, y por cada MAC conocida (barrido, equipos leídos, ARP de todos) sale un enlace `fdb` como en SNMP.

Pendiente de la fase: en el servidor, `coverage.py` marca el origen de las tablas como SNMP (`_SNMP_MARKS`); con tablas por SSH ese cartel habría que revisarlo.

---

# Fase 6 · Fuentes de alimentación (rama `fuentes-por-snmp`, 08-10-2026)

La pregunta que el inventario no sabía contestar: **cuántas fuentes tiene un equipo y si cada una recibe corriente**. Todo en el agente, protocolo compatible: el hallazgo `host` lleva una clave nueva, `power_supplies`, solo cuando el equipo listó alguna; un hallazgo sin ella es idéntico al de antes. El servidor la acepta en su propio PR (hasta entonces la ignora, como cualquier clave que no conoce).

- **Cuántas y cómo se llaman** (`agent/power.py`, `snmp._query_power_supplies`): las filas de `entPhysicalClass` con valor `powerSupply(6)`. La columna de clase ya se recorre para la identidad y los stacks, así que contarlas no cuesta nada; el nombre, la descripción, el modelo y el número de serie de cada una son **un `get` de instancias de hoja por fuente** (`entPhysicalName.<índice>`…), nunca un `walk` de esas columnas. Tope de 16 por equipo.
- **Estado**: una columna por fabricante indexada por el mismo `entPhysicalIndex`, otro `get` por fuente. Cisco `cefcFRUPowerOperStatus`, Huawei `hwEntityOperStatus`, y para los demás el `entStateOper` genérico de ENTITY-STATE-MIB, que casi nadie implementa. Palabras estables: `ok`, `failed`, `no_input` (la fuente está pero no le llega corriente), `off`, `absent`, y vacío cuando no se sabe. Un fabricante sin columna conocida deja el estado vacío: el servidor enseña «desconocido», nunca inventa.
- **Dos avisos que el servidor tiene que asumir**: muchos equipos listan la **bahía vacía** como fuente (un Catalyst con una sola PSU sigue enseñando «Power Supply B»), así que la cuenta es de bahías, no de fuentes montadas, y es el estado el que las distingue; y la gama barata (Cisco SB, TP-Link, Ubiquiti, MikroTik antiguo) **no implementa ENTITY-MIB** y no manda nada, con lo que ahí manda la plantilla del modelo del catálogo (ya en el servidor, 08-10-2026).

Forma de cada fuente: `{"index", "name", "description", "model", "serial", "status"}`; `name` nunca va vacío (nombre, si no descripción, si no `PSU<n>`), porque el servidor bautiza la entrada con él.

Pendiente para el servidor (PR 3): crear las entradas a partir de `power_supplies` cuando el equipo no tiene ninguna ni modelo de catálogo; guardar el estado de cada fuente con fecha de lectura y alimentar el aviso de redundancia falsa. Pendiente del agente: en un stack, atribuir cada fuente a su unidad (`entPhysicalContainedIn`); hoy van todas en el hallazgo del maestro con el nombre que les da el equipo («Switch 2 - Power Supply A»).
