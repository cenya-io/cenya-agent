# Qué cuenta crear en cada equipo para que el agente solo pueda leer

Guía para el informático que instala el agente de Cenya. La idea es sencilla:
**cuanto menos privilegio tenga la cuenta, menos puede salir mal**. El agente
solo lee, pero una cuenta de solo lectura lo garantiza también si alguien se
equivoca o si la contraseña se pierde.

Esta guía pide a cada equipo **solo** lo que el agente ejecuta de verdad (las
órdenes salen de `agent/collectors/ssh.py`, `agent/tables.py`, `agent/snmp.py`,
`agent/winrm.py`, `agent/hyperv.py`, `agent/hypervisor.py` y `agent/xcpng.py`).

## Cómo leer las marcas

- **[Doc]**: lo respalda documentación oficial del fabricante, enlazada.
- **⚠ sin verificar**: no se ha podido contrastar con documentación del
  fabricante ni con un equipo real. No lo des por seguro: pruébalo en un equipo
  de laboratorio (o fuera de horas) antes de ponerlo en producción. Al lado va
  qué comprobar.

**Estado de la verificación (09-10-2026).** Se han abierto las páginas
oficiales de Cisco IOS/IOS-XE, Juniper, MikroTik, Fortinet (parcial), Proxmox,
Broadcom (vCenter), Microsoft (WinRM y WMI), net-snmp y el código del núcleo
de Linux. Quedan **36 marcas «⚠ sin verificar»** (eran 34 en el borrador, pero
ahora cada afirmación sin respaldo lleva la suya) frente a **21 marcas
«[Doc]»** (eran 6). Siguen enteras sin verificar las familias de menor
prioridad: Aruba, Dell, Huawei, HPE/Comware, Check Point Gaia (parcial),
Extreme, Ruckus, Allied Telesis, Ubiquiti, ESXi por SSH, Hyper-V y XCP-ng. El
resto de huecos concretos están marcados en su sitio. Donde la documentación
contradecía el borrador, la guía está corregida y el cambio se resume en el
comentario del PR.

El punto 4 de cada familia («comprobar que no escribe») es cosa tuya: entra a
mano con la cuenta nueva y comprueba que el equipo te lo niega.

## Reglas para todas las cuentas

- **Una clave distinta por equipo**, o mejor una clave SSH, y guárdalas en un
  gestor de contraseñas. En esta guía todas son marcadores:
  `CAMBIAR-ESTA-CLAVE`. No copies esas palabras tal cual.
- Nombre de usuario reconocible (`cenya-lectura`), para ver en los registros
  del equipo qué hace.
- Las credenciales se **sellan en tu navegador para cada agente**: el servidor
  guarda solo el sobre cerrado y no puede leerlas. Eso protege la base de datos
  y las copias de seguridad; no sustituye a darle a la cuenta el mínimo
  privilegio.
- **Cuidado con los bloqueos.** Una contraseña mala varias veces puede bloquear
  la cuenta (sobre todo en un dominio). Limita cada credencial a las subredes o
  equipos donde vale.
- El agente **no usa `enable` ni `sudo`**: el privilegio tiene que llegar con el
  inicio de sesión.

## Resumen

| Familia | ¿Solo lectura real para ver la configuración? |
|---|---|
| MikroTik, Check Point Gaia, Juniper | Sí, con matices (ver cada una) |
| Fortinet | **Con reservas:** Fortinet documenta que la copia completa exige más que lectura |
| Cisco, Dell, Huawei, Aruba, Comware | **Lo habitual es que ver la configuración exija el nivel más alto**, que también puede escribir |
| Linux | Sí, pero sin el número de serie (lo lee root) |
| Windows | Parcial: hay que tocar permisos de WMI y de WinRM |
| SNMP, vCenter, Proxmox | Sí |
| Hyper-V, XCP-ng | No de forma sencilla |

---

## 1. Equipos de red por SSH

El agente identifica la familia con unas órdenes y, si es un equipo de red,
pide su configuración. Son órdenes de lectura (`show`, `display`, `get`,
`/export`). Cada orden es una conexión SSH nueva con la misma cuenta. Además
pide, donde existen, la tabla ARP, la tabla de MAC, el nombre del equipo y la
lista de unidades de un stack.

### 1.1 Cisco IOS / IOS-XE / NX-OS

1. **Qué ejecuta:** `show version`, `show running-config`,
   `show startup-config`, `show ip arp`, `show mac address-table`. En sesión
   interactiva (si el equipo no contesta a la orden suelta) añade
   `terminal length 0`.
2. **Cuenta [Doc]:** la forma de crear un usuario local con un nivel es
   `username NOMBRE privilege N secret CLAVE`
   ([Cisco IOS XE 16.6, «Configuring Security with Passwords, Privileges, and Logins»](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/xe-16-6/sec-usr-cfg-xe-16-6-book/sec-cfg-sec-4cli.html),
   apartado sobre el nombre de usuario con nivel). Por defecto el modo usuario
   es el nivel 1 y el modo privilegiado el 15, y con `privilege exec` se puede
   mover una orden a cualquier nivel intermedio.

   ```
   username cenya-lectura privilege 15 secret CAMBIAR-ESTA-CLAVE
   ```

   Con nivel 15 el usuario **puede escribir**.
3. **Limitación [Doc]:** a un nivel menor que 15, `show running-config` solo
   enseña las líneas que ese nivel podría cambiar, aunque la orden se le haya
   asignado: es un comportamiento deliberado de seguridad, y la salida sale
   **incompleta**. Lo cuentan dos páginas de Cisco: la guía de IOS XE 16.6
   (apartado «Configuring a Device to Allow Users to View the Running
   Configuration»: mover la orden con `privilege exec all level N show
   running-config` y dar permiso de ficheros con `file privilege N`, y aun así
   hay que mover aparte las líneas de configuración que se quieran ver) y el
   documento [Cisco 212149](https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-aggregation-services-routers/212149-Configure-IOS-XE-to-display-full-show-ru.html),
   que presenta la variante `show running-config view full` (asignada con
   `privilege exec level N show running-config view full`) como la que sí
   enseña todo a un nivel intermedio.
   **El agente ejecuta `show running-config` a secas, sin `view full`.** Con un
   usuario de nivel intermedio la copia puede quedar incompleta sin avisar.
   Hasta que el agente sepa pedir `view full`, usa para Cisco un nivel que vea
   la configuración entera (15).
   - **Vistas de CLI (parser view) [Doc]:** la guía
     [«Role-Based CLI Access»](https://www.cisco.com/en/US/docs/ios-xml/ios/sec_usr_cfg/configuration/15-1s/sec-role-base-cli.html)
     exige `aaa new-model`, crear la vista desde la vista raíz
     (`enable view`) y añadir órdenes con `commands exec include ...`. Esa
     página **no habla de `view full`** (es una palabra de `show
     running-config`, no de las vistas) ni de `show startup-config`, y solo
     documenta asignar la vista a un usuario mediante el atributo `cli-view-name`
     de un servidor AAA; la forma `username ... view ...` solo aparece para el
     usuario de interceptación legal. ⚠ sin verificar que una vista deje al
     agente ver la configuración entera: pruébalo en un equipo de laboratorio.
   - **`show startup-config`:** [Cisco (TACACS, 23383)](https://www.cisco.com/c/en/us/support/docs/security-vpn/terminal-access-controller-access-control-system-tacacs-/23383-showrun.html)
     explica que esta orden vuelca el contenido guardado en la NVRAM, sin el
     filtrado por nivel de `show running-config`. ⚠ sin verificar que un nivel
     menor que 15 pueda ejecutarla en tu versión (falta documentación oficial
     de `privilege exec level N show startup-config`).
4. **Comprobar que no escribe:** entra con la cuenta, ejecuta `show privilege`
   y luego `configure terminal`. Si el equipo no te lo niega, la cuenta puede
   escribir.

### 1.2 Aruba (AOS-S / ProCurve y AOS-CX)

1. **Qué ejecuta:** `show version`, `show running-config`,
   `show startup-config`, `show stacking`, `show system`, `show arp`,
   `show mac-address`.
2. **Cuenta:** en AOS-CX hay tres grupos de fábrica (administrators, auditors,
   operators) y se pueden crear grupos propios con las órdenes permitidas. Un
   ejemplo de grupo propio que permite `show running-config` aparece en la guía
   de cuenta mínima de Qualys
   ([AOS-CX](https://docs.qualys.com/en/vmdr/latest/authentication/unix/privilege_level_for_arubaos_cx.htm)),
   que no es documentación de Aruba. ⚠ sin verificar la sintaxis exacta de
   `user-group` y `user`: sácala del manual de órdenes de AOS-CX de tu versión.
   En AOS-S (ProCurve) ⚠ sin verificar qué ve cada tipo de cuenta.
3. **Limitación:** ⚠ sin verificar si el grupo de fábrica *operators* de AOS-CX
   puede ejecutar `show running-config`. Pruébalo.
4. **Comprobar:** `configure terminal` debe ser rechazado.

### 1.3 Dell Networking (N-Series, PowerConnect, OS6)

1. **Qué ejecuta:** `show version`, `show running-config`, `show startup-config`,
   `show switch` (si hay stack), `show system`, `show arp`,
   `show mac address-table`.
2. **Cuenta:** Dell documenta niveles de acceso 0, 1 y 15 (sin acceso, lectura
   y lectura/escritura), y en N-Series la palabra es `privilege`
   ([Dell KB 000108308](https://dell.com/support/kbdoc/en-my/000108308/how-to-set-a-username-and-password-for-web-telnet-access-on-powerconnect-and-n-series-switches)).
3. **Limitación:** el código del agente asume que en Dell OS6 y en Cisco un
   usuario sin nivel 15 recibe una negativa al pedir la configuración, y
   entonces no hay copia (el agente lo anota como «falta privilegio»). Es
   decir: **para copiar la configuración hace falta el nivel de escritura**.
   ⚠ sin verificar con documentación de Dell que el nivel 1 no pueda ejecutar
   `show running-config` en tu firmware: pruébalo; si funciona, usa el nivel 1.
4. **Comprobar:** `configure` debe ser rechazado con el nivel 1.

### 1.4 Huawei VRP

1. **Qué ejecuta:** `display version`, `display current-configuration`,
   `display saved-configuration`, `display arp`, `display mac-address`.
2. **Cuenta:** la guía de Qualys indica que el usuario necesita nivel 3 para
   `display current-configuration`, y que se crea en la vista `aaa` con
   `local-user NOMBRE password cipher CAMBIAR-ESTA-CLAVE privilege level 3` y
   `local-user NOMBRE service-type ssh`
   ([Qualys, Huawei](https://docs.qualys.com/en/vmdr/latest/authentication/unix/huawei.htm);
   no es documentación de Huawei). ⚠ sin verificar con Huawei: según la versión
   hace falta además `ssh user NOMBRE authentication-type password` y
   `ssh user NOMBRE service-type stelnet`, y la línea `user-interface vty`
   con `authentication-mode aaa` y `protocol inbound ssh`.
3. **Limitación:** el nivel 3 es de gestión (puede configurar). ⚠ no se sabe si
   un nivel inferior ve la configuración.
4. **Comprobar:** `system-view` no debe estar disponible si el nivel no lo
   permite.

### 1.5 HPE / H3C Comware

1. **Qué ejecuta:** `display version`, `display current-configuration`,
   `display saved-configuration`, `display irf`,
   `display device manuinfo` (si hay stack), `display arp`,
   `display mac-address`.
2. **Cuenta:** en Comware 7 la estructura es
   `local-user NOMBRE class manage`, `password simple CAMBIAR-ESTA-CLAVE`,
   `service-type ssh` y `authorization-attribute user-role network-operator`
   (aparece en guías de integración de terceros; `network-operator` es un rol
   válido). ⚠ sin verificar con documentación de HPE que `network-operator`
   pueda ejecutar `display current-configuration`. Compruébalo. En Comware 5 la
   sintaxis es distinta.
3. **Limitación:** ⚠ si `network-operator` no ve la configuración, hará falta
   `network-admin`, que escribe.
4. **Comprobar:** `system-view` debe fallar con `network-operator`.

### 1.6 Juniper Junos

1. **Qué ejecuta:** `show version`, `show configuration | display set`,
   `show virtual-chassis`, `show arp no-resolve`,
   `show ethernet-switching table`.
2. **Cuenta [Doc]:** en Junos cada marca de permiso de una clase de inicio de
   sesión tiene una forma simple, que da solo lectura, y otra acabada en
   `-control`, que da lectura y escritura; las marcas no se acumulan, así que
   cada clase lista todas las que necesita
   ([Junos, «Login Class Permission Flags»](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-login-class.html)).
   **Corrección respecto al borrador:** la clase de fábrica `read-only` lleva
   solo la marca `view`, que según la documentación enseña valores del sistema,
   rutas y estadísticas de protocolos sin mencionar la configuración; la marca
   que documenta Juniper para ver la configuración (sin secretos, guiones del
   sistema ni opciones de eventos) es `view-configuration`
   ([Junos, «Login Class Overview»](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-login-class-overview.html)).
   Las clases de fábrica no se pueden modificar. Por eso hace falta una clase
   propia con las dos marcas simples. La instrucción `permissions` con una
   lista entre corchetes y el uso de `class` en un usuario aparecen en la
   documentación de Juniper (apartado «Login Class Permission Flags» y
   «User Accounts»), pero sin la sintaxis completa a la vista, así que:

   ```
   set system login class cenya-lectura permissions [ view view-configuration ]
   set system login user cenya-lectura class cenya-lectura
   set system login user cenya-lectura authentication plain-text-password
   ```

   La última orden pide la clave por consola dos veces y la guarda cifrada
   (la opción se llama `plain-text-password`, con guion, y es una de las que
   documenta Juniper en la referencia de la sentencia `user`,
   [user (Access)](https://juniper.net/documentation/en_US/junos/topics/reference/configuration-statement/user-edit-system-login.html)).
   ⚠ sin verificar con una página de Juniper la sintaxis exacta de las dos
   primeras líneas (la página no la muestra completa) ni que `view` más
   `view-configuration` basten para `show configuration | display set`:
   pruébalo en un equipo de laboratorio.
3. **Limitación [Doc]:** `view-configuration` enseña la configuración sin los
   secretos, los guiones del sistema ni las opciones de eventos (ver el
   apartado «Login Class Overview» enlazado arriba); para ver también los
   secretos haría falta la marca `secret`, que esta guía no pide. Es lo
   deseable para este producto. Ver los guiones de comandos, operaciones o
   eventos exige la marca `maintenance` (también documentado), que tampoco se
   pide.
4. **Comprobar:** `configure` debe ser rechazado.

### 1.7 MikroTik RouterOS

1. **Qué ejecuta:** `/system resource print; /system identity print;
   /system routerboard print`, `/export`, `/ip arp print without-paging`,
   `/interface bridge host print without-paging`.
2. **Cuenta [Doc]:** las políticas se asignan a un grupo y un `!` delante
   quita una política
   ([RouterOS, «User»](http://manual.mikrotik.com/docs/authentication-authorization-accounting/user/)).
   Los grupos de fábrica `read`, `write` y `full` **llevan `sensitive` y
   `reboot`** (`read` incluye además `local`, `telnet`, `ssh`, `winbox`, `web`,
   `api`, `rest-api`, `sniff`, `test`, `password` y `romon`; no lleva `ftp`,
   `write` ni `policy`), y MikroTik recomienda no dárselo a gente de poca
   confianza y crear un grupo propio con solo las políticas necesarias. La
   política `read` es la que permite ver la configuración, `ssh` la de entrar
   por SSH y `sensitive` la de ver y modificar datos sensibles
   ([RouterOS, `/user group`](http://manual.mikrotik.com/docs/cli-reference/user/group/)).
   Esa misma página dice que `add` sin listar una política **revoca todas las
   que no pones**, así que no hace falta una lista larga de `!`:

   ```
   /user group add name=cenya-lectura policy=read,ssh
   /user add name=cenya-lectura group=cenya-lectura password=CAMBIAR-ESTA-CLAVE
   ```

   (Si vas a entrar con clave SSH, `password` en la cuenta no es obligatorio.)
   ⚠ sin verificar que `/export` y las órdenes `print` del agente funcionen
   con solo `read` y `ssh` en tu versión (la documentación no dice qué
   política exige cada orden): pruébalo en un equipo de laboratorio.
3. **Limitación [Doc]:** en el manual vigente
   ([RouterOS, «Configuration Management»](https://manual.mikrotik.com/docs/7.25/getting-started/configuration-management/))
   los valores sensibles de un `/export` salen ocultos por defecto y solo se
   muestran con el parámetro `show-sensitive`; esa página **no describe un
   parámetro `hide-sensitive`** (el borrador lo daba por existente) ni dice qué
   política exige `show-sensitive`. El agente ejecuta `/export` a secas, que es
   lo que queremos: la copia no lleva secretos. La misma página aclara que
   la exportación no incluye ni con `show-sensitive` las contraseñas de los
   usuarios del sistema, las claves SSH de usuario ni los certificados. ⚠ sin
   verificar con documentación oficial qué datos cuenta MikroTik exactamente
   como «sensibles»: la página enlaza una lista de menús con parámetros
   sensibles, pero no la hemos contrastado con lo que sale en un `/export`
   real.
4. **Comprobar:** con la cuenta, añadir una dirección
   (`/ip address add address=192.0.2.1/32 interface=ether1`) debe dar «not
   enough permissions».

### 1.8 Fortinet FortiOS

1. **Qué ejecuta:** `get system status`, `show full-configuration`,
   `get system arp`.
2. **Cuenta [Doc parcial]:** un perfil de administrador propio con lectura en
   los grupos. La referencia de `config system accprofile` (FortiOS 6.0,
   [system accprofile](https://docs.fortinet.com/document/fortigate/6.0.0/cli-reference/609909/system-accprofile))
   define para cada área los valores `none`, `read` y `read-write` (y
   `custom` en `sysgrp`, `netgrp`, `loggrp`, `fwgrp` y `utmgrp`), y dice que
   `read` deja ver la configuración sin cambiarla. Además de los grupos del
   borrador existen `secfabgrp`, `ftviewgrp`, `wanoptgrp` y `wifi`. Los
   nombres de los campos cambian entre versiones (la 6.0 quitó varios
   campos antiguos), así que ⚠ sin verificar el conjunto exacto en tu versión
   (míralos con `set ?`):

   ```
   config system accprofile
     edit "cenya-lectura"
       set sysgrp read
       set netgrp read
       set authgrp read
       set fwgrp read
       set vpngrp read
       set utmgrp read
       set loggrp read
     next
   end
   config system admin
     edit "cenya-lectura"
       set accprofile "cenya-lectura"
       set password CAMBIAR-ESTA-CLAVE
     next
   end
   ```
3. **Limitación [Doc]:** una nota técnica de Fortinet para FortiOS 5.4
   ([Read-only administrators and configuration backup/restore](https://community.fortinet.com/fortigate-3/technical-tip-read-only-administrators-and-configuration-backup-restore-in-firmware-version-5-4-96081))
   dice que los administradores de solo lectura no pueden hacer ni restaurar
   copias de configuración, y que solo el perfil `super_admin` por defecto
   recupera todos los componentes: una exportación omite los administradores y
   perfiles de mayor autoridad que quien exporta. Otra nota de Fortinet
   ([copia por SCP con permisos limitados](https://community.fortinet.com/fortigate-3/technical-tip-backing-up-the-fortigate-configuration-file-via-scp-with-limited-read-write-permissions-193679))
   dice que **desde la 7.4.4 la copia exige lectura y escritura**: un
   administrador de solo lectura ya no puede; propone un perfil propio con
   lectura en casi todo y lectura/escritura solo en «Administrator Users».
   Ninguna de las dos habla de `show full-configuration`, así que ⚠ **sin
   verificar que `show full-configuration` con un perfil de solo lectura
   salga entero**: compruébalo antes de fiarte de la copia. El perfil
   `super_admin_readonly` solo aparece en un mensaje del foro, no en la
   documentación: ⚠ no lo uses sin verificar.
   **Copia por REST con token [Doc]:** la guía de integración de FortiSIEM
   ([FortiGate REST API](https://docs.fortinet.com/document/fortisiem/7.2.4/external-systems-configuration-guide/751381))
   dice que un perfil de solo lectura vale para auditoría y rendimiento, pero
   que **bajar copias de configuración por la API exige además escritura en
   «System > Administrator Users»**, porque FortiOS trata a ese usuario como
   administrador. Es decir: para la copia por REST hace falta algo más que
   lectura. El agente no usa REST contra FortiOS hoy; esto solo es para
   decidir.
4. **Comprobar:** `config system interface` seguido de `edit` y `set` debe dar
   permiso denegado.

### 1.9 Check Point Gaia

1. **Qué ejecuta:** `show version all`, `show configuration`,
   `show arp dynamic all`.
2. **Cuenta [Doc]:** Gaia trae el rol predefinido `monitorRole`, de solo
   lectura en todas las funciones, y permite crear roles propios con
   `add rba role NOMBRE domain-type System readonly-features ...` y asignarlos
   con `add rba user USUARIO roles NOMBRE`
   ([Gaia, roles en clish](https://sc1.checkpoint.com/documents/R82/WebAdminGuides/EN/CP_R82_Gaia_AdminGuide/Content/Topics-GAG/Roles-Gaia-Clish.htm)).
   ⚠ sin verificar: la creación del usuario del sistema
   (`add user ...`), su contraseña y su shell `clish`; sácalo de la misma guía.
3. **Limitación:** `access-mechanisms` debe incluir `CLI`. ⚠ comprueba que
   `show configuration` funciona con `monitorRole`. Un usuario con escritura
   sobre la función «user» puede cambiar contraseñas: no lo uses.
4. **Comprobar:** `set hostname prueba` debe ser rechazado.

### 1.10 Extreme EXOS

1. **Qué ejecuta:** `show version`, `show configuration` (con
   `disable clipaging` en sesión).
2. **Cuenta:** ⚠ sin verificar. EXOS distingue cuentas `admin` y `user`; no se
   ha contrastado que `show configuration` funcione con la de solo lectura.
3. **Limitación:** ⚠ posible que se necesite `admin`. Pruébalo.
4. **Comprobar:** un `configure ...` cualquiera debe ser rechazado.

### 1.11 Ruckus ICX / Brocade FastIron

1. **Qué ejecuta:** `show version`, `show running-config` (con
   `skip-page-display` en sesión).
2. **Cuenta:** ⚠ sin verificar. El código indica que hace falta modo
   privilegiado; no se ha contrastado ningún nivel menor que permita
   `show running-config`.
3. **Limitación:** probablemente la cuenta necesita el nivel más alto.
4. **Comprobar:** `configure terminal` debe ser rechazado.

### 1.12 Allied Telesis AlliedWare Plus

1. **Qué ejecuta:** `show version`, `show running-config`.
2. **Cuenta:** ⚠ sin verificar. No se ha contrastado qué nivel de privilegio
   permite `show running-config`.
3. **Limitación:** ⚠ probablemente el nivel 15.
4. **Comprobar:** `configure terminal` debe ser rechazado.

### 1.13 Ubiquiti EdgeOS

1. **Qué ejecuta:** `show version` o, si responde como Linux, el análisis de
   Linux más `test -x /opt/vyatta/bin/vyatta-op-cmd-wrapper` y
   `cat /etc/version`; la configuración con
   `/opt/vyatta/bin/vyatta-op-cmd-wrapper show configuration`.
2. **Cuenta:** ⚠ sin verificar. EdgeOS distingue los niveles `admin` y
   `operator`; no se ha contrastado que `operator` pueda ejecutar
   `show configuration`.
3. **Limitación:** ⚠ si no, hará falta `admin`.
4. **Comprobar:** `configure` debe ser rechazado para `operator`.

### 1.14 VMware ESXi por SSH

1. **Qué ejecuta:** solo `vmware -v` (se identifica; no se captura nada).
2. **Recomendación:** **no actives SSH en ESXi para esto.** El inventario de
   verdad (host, máquinas, redes) llega mejor por vCenter (apartado 4.1). El
   cliente de VMware del agente habla con la API de sesión de vCenter, no con
   la de un ESXi suelto.
3. **Limitación:** ⚠ sin verificar qué cuenta local de ESXi (distinta de
   `root`) puede iniciar sesión por SSH y ejecutar `vmware -v`.

---

## 2. Linux

1. **Qué ejecuta:** `uname -sr`, `cat /etc/os-release`, `hostname`,
   `ip -o link`, `ip -o -4 addr`,
   `cat /sys/class/dmi/id/{sys_vendor,product_name,product_serial}`,
   `test -x /opt/vyatta/bin/vyatta-op-cmd-wrapper`, `cat /etc/version` e
   `ip neigh show`.
2. **Cuenta:** un usuario normal, sin `sudo`:

   ```
   sudo useradd --create-home --shell /bin/bash cenya-lectura
   sudo passwd cenya-lectura
   ```

   (o instala su clave pública en `~/.ssh/authorized_keys`). **No hace falta
   `sudoers`.** Esta guía no incluye una regla de `sudo` para `dmidecode`
   porque **el agente no llama a `sudo` ni a `dmidecode`**: lee
   `/sys/class/dmi/id/*`. Dar `sudo dmidecode` no cambiaría nada.
3. **Limitación [Doc]:** en el código del núcleo
   ([drivers/firmware/dmi-id.c](https://github.com/torvalds/linux/blob/master/drivers/firmware/dmi-id.c))
   `sys_vendor` y `product_name` son legibles por todos (modo 0444), pero
   `product_serial` (igual que `product_uuid`, `board_serial` y
   `chassis_serial`) es de solo root (0400). Con un usuario normal el número de
   serie queda vacío; el resto sale igual. Una máquina virtual o un
   contenedor casi nunca lo tienen. Una distribución o el administrador pueden
   cambiar esos permisos, pero esta guía no lo propone. ⚠ sin verificar con
   documentación oficial que `uname`, `/etc/os-release`, `hostname`,
   `ip -o link`, `ip -o -4 addr` e `ip neigh show` no pidan privilegios para un
   usuario normal (en la práctica es lo habitual; la página de `ip-neighbour`
   no dice nada de permisos).
4. **Comprobar:** `sudo -n true` debe pedir contraseña y `touch /etc/prueba`
   debe fallar.

---

## 3. Windows (WinRM)

1. **Qué ejecuta:** un único PowerShell que consulta `Win32_ComputerSystem`,
   `Win32_OperatingSystem`, `Win32_BIOS` y `Win32_NetworkAdapterConfiguration`
   (con `Get-CimInstance`, o `Get-WmiObject` en PowerShell antiguo) y mira si
   existe el servicio `vmms`. Va por NTLM (o `basic` si está activado), por el
   puerto 5985 o el 5986.
2. **Cuenta:** una cuenta local o de dominio **que no sea administradora**.
   - **Grupo [Doc]:** Microsoft dice que para crear sesiones remotas de
     PowerShell y ejecutar órdenes hay que ser miembro de **Administradores** o
     de **Usuarios de administración remota** (Remote Management Users) en el
     equipo remoto ([about_Remote_Requirements](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_requirements?view=powershell-7.6),
     apartado «User permissions»).
   - **Permiso en el endpoint [Doc, con una contradicción]:** esa misma página
     dice que las configuraciones de sesión por defecto
     (`Microsoft.PowerShell` y `Microsoft.PowerShell32`) solo dejan pasar a
     Administradores, y que quien administra puede cambiar el descriptor de
     seguridad o crear otra configuración. Sin embargo, la referencia de
     [Enable-PSRemoting](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-7.6)
     muestra los endpoints de PowerShell 7 con «Remote Management Users:
     AccessAllowed». ⚠ sin verificar qué hay en tu equipo: mira el permiso con
     `Get-PSSessionConfiguration` y, si falta, añádelo con
     `Set-PSSessionConfiguration -Name Microsoft.PowerShell
     -ShowSecurityDescriptorUI`
     ([Microsoft](https://learn.microsoft.com/en-us/previous-versions/powershell/module/Microsoft.PowerShell.Core/set-pssessionconfiguration?view=powershell-5.0)).
   - **WMI [Doc]:** Microsoft dice que por defecto solo los administradores
     acceden a un espacio de nombres de WMI de forma remota. Para un usuario
     normal describe dos capas: la de DCOM (permisos remotos de inicio,
     activación y acceso con `dcomcnfg`, o pertenecer al grupo local
     **Distributed COM Users**, que por defecto tiene todos los permisos de
     COM/DCOM) y la del espacio de nombres: con `wmimgmt.msc`, Propiedades de
     «WMI Control», pestaña Seguridad, `Root\CIMV2` (el espacio por defecto),
     marcar **Remote Enable** y **Read Security** para la cuenta, y «This
     namespace and subnamespaces» en Avanzado para que valga en los
     subespacios ([Microsoft, «Scenario guide: Troubleshoot WMI connectivity
     and access issues»](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/scenario-guide-troubleshoot-wmi-connectivity-access-issues);
     [Securing a Remote WMI Connection](https://learn.microsoft.com/en-us/windows/win32/wmisdk/securing-a-remote-wmi-connection)).
     **Corrección respecto al borrador:** el permiso se llama **Remote Enable**
     (y Read Security), no «Habilitar cuenta»; y **el grupo Performance
     Monitor Users no aparece en la documentación de Microsoft como mecanismo de
     WMI**, así que se quita. Un permiso de escritura en el espacio de nombres
     no hace falta y no se debe dar.
   - Microsoft ofrece `Enable-ServerManagerStandardUserRemoting`, que aplica
     parte de esto, pero avisa de que da a usuarios normales acceso a datos
     reservados a administradores
     ([Microsoft](https://technet.microsoft.com/en-us/library/dd819440.aspx)).
3. **Limitación honesta:** ⚠ sin verificar que estas cosas bastan para las
   cuatro clases exactas que consulta el agente. Hay un matiz importante: el
   agente consulta WMI **desde dentro** de la sesión de PowerShell por WinRM,
   no por DCOM remoto, así que las capas de DCOM y de «Remote Enable» pueden no
   hacer falta; lo que sí hace falta es poder abrir la sesión (grupo y endpoint)
   y que la cuenta lea las clases `Win32_ComputerSystem`, `Win32_OperatingSystem`,
   `Win32_BIOS` y `Win32_NetworkAdapterConfiguration` en el equipo. Microsoft no
   documenta qué permisos concretos necesita un usuario normal para esas clases.
   Si falta algún dato (serie, modelo), la alternativa es una cuenta
   administradora local **solo en esos equipos**.
4. **Comprobar:** desde una sesión remota con la cuenta, `Restart-Service
   Spooler` o `New-Item C:\prueba.txt` deben dar «acceso denegado».

---

## 4. Hipervisores

### 4.1 VMware vCenter (REST)

1. **Qué ejecuta:** `POST /api/session` (o `/rest/com/vmware/cis/session`) y
   `GET /vcenter/host`, `/vcenter/cluster`, `/vcenter/vm`, `/vcenter/vm/{id}` y
   `/vcenter/vm/{id}/guest/networking/interfaces`. Solo lectura.
2. **Cuenta:** un usuario local de vCenter (SSO) o de dominio con el rol del
   sistema **«Solo lectura»** (Read-only). **[Doc]** Broadcom documenta que los
   roles del sistema son Administrator, Read-only y No access, que no se pueden
   editar ni borrar, y que Read-only deja ver el estado y los detalles de un
   objeto pero bloquea todas las acciones de menús y barras
   ([vSphere 8.0, «Using Roles to Assign Privileges»](https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/8-0/vsphere-security/vsphere-permissions-and-user-management-tasks/using-roles-to-assign-privileges.html)).
   ⚠ sin verificar con una página oficial el detalle de asignarlo en la raíz
   con «Propagar a los hijos» (la página de permisos globales de Broadcom no
   se pudo abrir con ese detalle): asígnalo en la raíz del inventario con
   esa casilla marcada y comprueba que la cuenta ve los hosts y las VM.
3. **Limitación:** ⚠ sin verificar que «Solo lectura» baste para
   `guest/networking/interfaces` (IP de los invitados; requiere VMware Tools):
   pruébalo. Un hilo de la comunidad de Broadcom cuenta un caso en que asignar
   el rol como permiso global no tuvo efecto y funcionó a nivel del centro de
   datos.
4. **Comprobar:** con la cuenta, apagar una VM de prueba debe estar
   deshabilitado.

### 4.2 Proxmox VE

1. **Qué ejecuta:** `POST /api2/json/access/ticket` (o la cabecera
   `PVEAPIToken` si el usuario lleva `!`) y `GET` de `nodes`, `storage`,
   `cluster/resources`, `cluster/status` y
   `nodes/{nodo}/{qemu|lxc}/{id}/config`; si la VM corre con el agente QEMU,
   `.../agent/network-get-interfaces`. No envía el token anti-CSRF, así que
   con ticket no puede escribir.
2. **Cuenta [Doc]:** rol **PVEAuditor**, descrito en la guía de Proxmox
   ([User Management](https://pve.proxmox.com/wiki/User_Management)) como
   acceso de solo lectura; esa página enseña como ejemplo dar el rol en `/`
   para ver todo, o en `/vms` para ver solo las máquinas. Los tokens nuevos
   tienen **privilegios separados** por defecto: los permisos efectivos del
   token son la **intersección** de los del usuario y los del token, y un token
   nunca puede tener un permiso que su usuario no tenga. Por eso el rol hay que
   darlo **al usuario y al token** (el borrador solo lo daba al token y habría
   quedado sin permisos). Las órdenes y opciones salen de la referencia
   [pveum](https://pve.proxmox.com/pve-docs/pveum.1.html) (`pveum acl modify`,
   con el alias `aclmod`; la opción es `--tokens`, en plural y con dos
   guiones, y no existe `-token`; `--privsep` vale 1 por defecto):

   ```
   pveum user add cenya-lectura@pve
   pveum user token add cenya-lectura@pve cenya --privsep 1
   pveum acl modify / --users cenya-lectura@pve --roles PVEAuditor
   pveum acl modify / --tokens 'cenya-lectura@pve!cenya' --roles PVEAuditor
   ```

   El secreto del token se muestra una sola vez al crearlo. En el usuario de
   Cenya va `cenya-lectura@pve!cenya` y en el secreto el valor del token.
   `pveum help` te da el detalle de las opciones de tu versión.
3. **Limitación:** ⚠ sin verificar si PVEAuditor permite consultar las IP del
   agente QEMU del invitado; si no salen, es esto.
4. **Comprobar [Doc]:** `pveum user token permissions cenya-lectura@pve cenya`
   (existe en la referencia de `pveum`) debe mostrar solo privilegios de
   auditoría.

### 4.3 Hyper-V

1. **Qué ejecuta:** el mismo mecanismo de WinRM que Windows (apartado 3), con
   `Get-Service vmms`, `Get-VM`, `Get-VHD`, `Get-VMNetworkAdapter`,
   `Get-VMNetworkAdapterVlan`, `Get-IscsiSession`, `Get-Disk`, `Get-Partition`,
   `Get-ClusterSharedVolume`, `Get-Cluster` y `Get-CimInstance`.
2. **Cuenta:** la única pertenencia nativa que se ha podido confirmar es el
   grupo **Hyper-V Administrators**, que da control total, no lectura. No se ha
   encontrado un grupo nativo de solo lectura.
3. **Limitación honesta:** ⚠ sin verificar. Las alternativas (rol propio con
   Authorization Manager, o un punto final JEA) no se han contrastado con
   Microsoft, y un JEA no admite un script libre como el del agente. Hasta
   entonces esta cuenta puede escribir: protégela más (red de gestión, clave
   única).
4. **Comprobar:** `Stop-VM` sobre una VM de prueba con la cuenta debe fallar
   solo si has conseguido una cuenta realmente de lectura.

### 4.4 XCP-ng / XenServer

1. **Qué ejecuta:** XAPI por JSON-RPC: `session.login_with_password` y las
   lecturas `*.get_all_records` de host, pool, VM, VBD, VDI, SR, PBD, VIF y
   VM_guest_metrics.
2. **Cuenta:** el rol RBAC **read-only** de XenServer, asignado con
   `xe subject-role-add uuid=<sujeto> role-name=read-only`
   ([XenServer, RBAC en la CLI](https://docs.xenserver.com/en-us/xenserver/9/users/rbac-cli)).
3. **Limitación:** los sujetos son usuarios o grupos de **Active Directory**
   (`xe pool-enable-external-auth`); sin AD solo queda `root`, que escribe.
   ⚠ sin verificar que XCP-ng (y no solo XenServer) lo permita igual.
4. **Comprobar:** con el sujeto, `xe vm-shutdown` debe dar «permiso denegado».

---

## 5. SNMP

El agente solo hace consultas `GET` y recorridos (`walk`); **no envía `SET`**.
Prueba primero los usuarios SNMPv3 y después las comunidades v2c.

Lo que lee: sistema (`1.3.6.1.2.1.1`), interfaces (`...2.2`, `...31`), IP
(`...4`), puente/MAC (`...17`), recursos del host (`...25`), impresoras
(`...43`), SAI (`...33`), entidades (`...47`), LLDP (`1.0.8802`), CDP y VTP de
Cisco (`1.3.6.1.4.1.9.9.23`, `...9.9.46`), datos de PDU de Raritan (`13742`) y
APC (`318`) y los OID de identificación por fabricante de
`agent/profiles_data.py`. Una vista restringida debe incluir esas ramas; si no
quieres mantenerla, una vista de solo lectura sobre `1.3.6.1` basta.

### 5.1 SNMP v2c

Una comunidad **de solo lectura** (nunca una de lectura/escritura):

- Cisco, ⚠ sin verificar (la guía de SNMP de IOS XE 17 tiene un apartado
  «Configuring SNMP Versions 1 and 2», pero no se pudo leer la sintaxis de la
  comunidad): `snmp-server community CAMBIAR-ESTA-COMUNIDAD RO`
- Linux (net-snmp), [snmpd.conf](https://www.root.cz/man/5/snmpd-conf/):
  `rocommunity CAMBIAR-ESTA-COMUNIDAD 192.0.2.0/24` (limita el origen a la red
  del agente)

La v2c viaja sin cifrar. Si el equipo admite v3, usa v3.

### 5.2 SNMP v3 (authPriv, solo lectura)

Cenya decide el nivel por las contraseñas que pongas: dos contraseñas es
`authPriv`. Usa SHA y AES-128.

**Linux (net-snmp) [Doc].** Según la página de manual de
[snmpd.conf](http://www.net-snmp.org/docs/man/snmpd.conf.html): un usuario
v3 se crea con `createUser [-e ENGINEID] usuario (MD5|SHA) clave-auth
[DES|AES] [clave-cifrado]`; las claves tienen al menos 8 caracteres; SHA y
AES exigen que net-snmp esté compilado con OpenSSL; un usuario no puede hacer
nada hasta que se le da acceso en las tablas VACM; y `rouser usuario
[noauth|auth|priv [OID | -V VISTA]]` le da solo lectura (GET y GETNEXT) con el
nivel de seguridad pedido y, si quieres, limitado a un subárbol o a una vista.
La página dice que la línea `createUser` va en el archivo **persistente**
(`/var/net-snmp/snmpd.conf` en esa página; la ruta depende de la compilación y
de la distribución), no en el principal, y que el propio `snmpd` la quita y la
sustituye por una clave localizada tras leerla. También recomienda
`net-snmp-config --create-snmpv3-user`, que escribe la línea donde toca. Con el
servicio parado:

```
createUser cenya-lectura SHA "CAMBIAR-ESTA-CLAVE-1" AES "CAMBIAR-ESTA-CLAVE-2"
```

y en el archivo principal (`snmpd.conf`):

```
rouser cenya-lectura priv
```

Para limitarlo a una vista, la misma página define `view NOMBRE (included|excluded)
OID` y `rouser usuario priv -V NOMBRE`.

**Cisco [Doc, sintaxis].** La guía de configuración de SNMP de IOS XE 17
([Configuring SNMP Support](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/snmp/configuration/xe-17-x/snmp-xe-17-book/nm-snmp-cfg-snmp-support.html))
da la sintaxis de las tres órdenes: `snmp-server view NOMBRE OID
(included|excluded)`, `snmp-server group GRUPO v3 (auth|noauth|priv) [read VISTA]
[write VISTA]...` y `snmp-server user USUARIO GRUPO v3 [auth (md5|sha|sha-2 ...)
CLAVE] [privacy (des|3des|aes 128|192|256) CLAVE]`. Esa página no trae un
ejemplo que junte `v3 priv read`, así que el siguiente es **composición
nuestra** a partir de esa sintaxis, y la sintaxis exacta de `snmp-server user`
cambia entre plataformas y versiones (la que usa el ejemplo, con la palabra
`privacy` para el cifrado, es la de la guía de IOS XE 17). Contrástalo con la
guía de tu plataforma:

```
snmp-server view CENYA-VISTA iso included
snmp-server group CENYA-GRUPO v3 priv read CENYA-VISTA
snmp-server user cenya-lectura CENYA-GRUPO v3 auth sha CAMBIAR-ESTA-CLAVE-1 privacy aes 128 CAMBIAR-ESTA-CLAVE-2
```

La página describe la vista de lectura del grupo como lo que limita qué
objetos puede ver el gestor, y no dice que un grupo sin vista de escritura sea
de solo lectura: ⚠ sin verificar con Cisco que sin `write` el grupo no pueda
escribir; compruébalo con `snmpset`.

**Comprobar que no escribe:** desde otra máquina, un `snmpset` con ese usuario
sobre `sysContact.0` debe responder `noAccess` o `notWritable`.

---

## Qué hace y qué no hace el agente con estas cuentas

Solo lo que el código demuestra:

- **Solo lee.** Todas las órdenes por SSH son de consulta (`show`, `display`,
  `get`, `/export`, `uname`, `cat`, `ip`). Por SNMP solo hace `get` y `walk`.
  Contra Proxmox con ticket no manda el token anti-CSRF. Contra WinRM ejecuta
  un PowerShell fijo de consultas; contra Hyper-V, uno de `Get-*`.
- **No cambia la configuración** de ningún equipo. En una sesión interactiva
  (equipos que no contestan a la orden suelta) lo único que cambia es la
  paginación **de esa sesión** (`terminal length 0`, `screen-length 0
  temporary`, etc.).
- **No usa `enable` ni `sudo`**: no escala privilegios.
- **Guarda copias de configuración** de los equipos de red y las manda al
  servidor, y solo si cambiaron. Una configuración puede contener contraseñas
  o claves: por eso conviene que la cuenta no vea los secretos (MikroTik sin
  `sensitive`, Junos de solo lectura).
- **Nunca guarda la contraseña en claro** en disco: las credenciales llegan
  selladas para ese agente y se abren en memoria. La contraseña de SSH se pasa
  al proceso `ssh` por una variable de entorno de ese proceso, nunca por línea
  de órdenes; en una sesión interactiva se teclea dentro del canal cifrado.
  Los informes de «Analizar» y «Probar» nunca citan un secreto.
- **No desactiva la verificación TLS** en vCenter, Proxmox, XCP-ng ni WinRM.
  Para una CA propia se da el certificado o la huella.

Lo que **no** promete esta guía: que una cuenta con el mínimo privilegio vea
siempre todo. Cuando el equipo exige el nivel más alto para ver su
configuración (Cisco, Dell, Huawei, quizá otros), el agente no puede hacer
nada con menos: la protección se pone entonces en el propio equipo
(autorización de comandos) y en la red (que solo el agente llegue al puerto de
gestión).
