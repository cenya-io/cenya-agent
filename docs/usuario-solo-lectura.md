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
| MikroTik, Check Point Gaia, Juniper, Fortinet | Sí, con matices (ver cada una) |
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
2. **Cuenta:** ⚠ sin verificar (sintaxis de IOS escrita de memoria; contrástala
   con la guía de tu versión):

   ```
   username cenya-lectura privilege 15 secret CAMBIAR-ESTA-CLAVE
   ```

   Con nivel 15 el usuario **puede escribir**. Para limitarlo la vía real es la
   autorización de comandos por TACACS+/RADIUS o una vista de CLI, que esta
   guía no detalla.
3. **Limitación [Doc]:** Cisco explica que `show running-config` se trata
   distinto de otros `show`: un usuario de nivel bajo solo ve las partes de la
   configuración que su nivel podría cambiar, así que la salida sale
   **incompleta**. La solución documentada es
   `privilege exec level N show running-config view full` y que el usuario
   ejecute `show running-config view full`
   ([Cisco 212149](https://www.cisco.com/c/en/us/support/docs/routers/asr-1000-series-aggregation-services-routers/212149-Configure-IOS-XE-to-display-full-show-ru.html)).
   **El agente ejecuta `show running-config` a secas, sin `view full`.** Con un
   usuario de nivel intermedio la copia puede quedar incompleta sin avisar.
   Hasta que el agente sepa pedir `view full`, usa para Cisco un nivel que vea
   la configuración entera.
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
2. **Cuenta [Doc]:** los permisos de una clase de inicio de sesión no se
   acumulan y la forma sin `-control` es de solo lectura
   ([Junos, login class](https://www.juniper.net/documentation/us/en/software/junos/user-access/topics/topic-map/junos-os-login-class.html)).
   La clase de fábrica `read-only` usa solo el permiso `view`. ⚠ sin verificar
   con Juniper que baste para `show configuration | display set` y el alcance
   exacto de `view-configuration` (permiso que usan las guías de copias de
   configuración de terceros). Empieza por `read-only`:

   ```
   set system login user cenya-lectura class read-only
   set system login user cenya-lectura authentication plaintext-password
   ```

   (`plaintext-password` te pide la clave por consola; ⚠ sin verificar la
   sintaxis exacta en tu versión.)
3. **Limitación:** una clase de solo lectura puede no ver los secretos de la
   configuración (los muestra ocultos). Es lo deseable para este producto.
4. **Comprobar:** `configure` debe ser rechazado.

### 1.7 MikroTik RouterOS

1. **Qué ejecuta:** `/system resource print; /system identity print;
   /system routerboard print`, `/export`, `/ip arp print without-paging`,
   `/interface bridge host print without-paging`.
2. **Cuenta [Doc]:** las políticas se asignan a un grupo y un `!` delante
   quita una política
   ([User, MikroTik](https://help.mikrotik.com/docs/spaces/ROS/pages/8978504/User)).
   El grupo `read` de fábrica **incluye `sensitive` y `reboot`**, y MikroTik
   recomienda no dárselo a gente de poca confianza y crear un grupo propio.
   ⚠ sin verificar la lista exacta de políticas de tu versión (míralas con
   `/user group print`); la forma general es:

   ```
   /user group add name=cenya-lectura policy=read,ssh,!write,!sensitive,!reboot,!policy,!ftp,!local,!telnet,!winbox,!web,!password,!sniff,!api
   /user add name=cenya-lectura group=cenya-lectura password=CAMBIAR-ESTA-CLAVE
   ```
3. **Limitación:** sin `sensitive`, `/export` oculta contraseñas y secretos
   (PPP, IPsec, claves wifi). Para este producto es lo que queremos: la copia
   no lleva secretos.
4. **Comprobar:** con la cuenta, añadir una dirección
   (`/ip address add address=192.0.2.1/32 interface=ether1`) debe dar «not
   enough permissions».

### 1.8 Fortinet FortiOS

1. **Qué ejecuta:** `get system status`, `show full-configuration`,
   `get system arp`.
2. **Cuenta:** un perfil de administrador propio con permiso de lectura en los
   grupos. La referencia de `config system accprofile` lista las áreas con
   valores `none`, `read` y `read-write`
   ([FortiOS, accprofile](https://docs2.fortinet.com/document/fortigate/6.0.0/cli-reference/609909)).
   ⚠ sin verificar el conjunto de campos de tu versión (míralos con `set ?`):

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
3. **Limitación:** Fortinet avisó de que en 5.4 los perfiles que no son
   `super_admin` no podían hacer copia completa de la configuración, y un hilo
   del foro de la comunidad cuenta que un administrador de solo lectura no ve
   toda la configuración por SSH. ⚠ **Comprueba que `show full-configuration`
   con tu perfil sale entero** antes de fiarte de la copia. El perfil
   `super_admin_readonly` solo aparece en un mensaje del foro, no en la
   documentación: ⚠ no lo uses sin verificar.
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
3. **Limitación:** el número de serie (`product_serial`) solo lo lee root. Con
   un usuario normal queda vacío; el resto sale igual. Una máquina virtual o
   un contenedor casi nunca lo tienen.
4. **Comprobar:** `sudo -n true` debe pedir contraseña y `touch /etc/prueba`
   debe fallar.

---

## 3. Windows (WinRM)

1. **Qué ejecuta:** un único PowerShell que consulta `Win32_ComputerSystem`,
   `Win32_OperatingSystem`, `Win32_BIOS` y `Win32_NetworkAdapterConfiguration`
   (con `Get-CimInstance`, o `Get-WmiObject` en PowerShell antiguo) y mira si
   existe el servicio `vmms`. Va por NTLM (o `basic` si está activado), por el
   puerto 5985 o el 5986.
2. **Cuenta:** una cuenta local o de dominio **que no sea administradora**, con
   tres permisos (según documentación de Microsoft y guías de terceros):
   - miembro del grupo **Usuarios de administración remota** (Remote Management
     Users);
   - en WMI (`wmimgmt.msc`, Seguridad, `Root\CIMV2`), permisos **Habilitar
     cuenta** y **Habilitar remoto**
     ([Paessler](https://helpdesk.paessler.com/en/support/solutions/articles/76000088235-how-can-i-use-a-non-administrator-windows-account-for-wmi-monitoring-via-the-wsman-protocol-));
   - permiso de ejecución en el endpoint de PowerShell
     (`Set-PSSessionConfiguration -Name Microsoft.PowerShell
     -ShowSecurityDescriptorUI`;
     [Microsoft](https://learn.microsoft.com/en-us/previous-versions/powershell/module/Microsoft.PowerShell.Core/set-pssessionconfiguration?view=powershell-5.0)).

   Microsoft ofrece `Enable-ServerManagerStandardUserRemoting`, que aplica
   parte de esto, pero avisa de que da a usuarios normales acceso a datos
   reservados a administradores
   ([Microsoft](https://technet.microsoft.com/en-us/library/dd819440.aspx)).
3. **Limitación honesta:** ⚠ sin verificar que estas tres cosas bastan para las
   cuatro clases exactas que consulta el agente. Las guías avisan de que
   algunas clases de WMI piden permisos extra a un usuario normal. Si falta
   algún dato (serie, modelo), la alternativa es una cuenta administradora
   local **solo en esos equipos**.
4. **Comprobar:** desde una sesión remota con la cuenta, `Restart-Service
   Spooler` o `New-Item C:\prueba.txt` deben dar «acceso denegado».

---

## 4. Hipervisores

### 4.1 VMware vCenter (REST)

1. **Qué ejecuta:** `POST /api/session` (o `/rest/com/vmware/cis/session`) y
   `GET /vcenter/host`, `/vcenter/cluster`, `/vcenter/vm`, `/vcenter/vm/{id}` y
   `/vcenter/vm/{id}/guest/networking/interfaces`. Solo lectura.
2. **Cuenta:** un usuario local de vCenter (SSO) o de dominio con el rol del
   sistema **«Solo lectura»** (Read-only), asignado en la raíz con «propagar a
   los hijos»
   ([permisos globales, vSphere 8](https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-security/GUID-74F53189-EF41-4AC1-A78E-D25621855800.html)).
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
2. **Cuenta [Doc parcial]:** rol **PVEAuditor**. Un parche de documentación de
   Proxmox publica el patrón de un token con separación de privilegios y solo
   ese rol
   ([pve-devel](https://lists.proxmox.com/pipermail/pve-devel/2020-January/041484.html));
   la referencia vigente es [pveum](https://pve.proxmox.com/pve-docs/pveum.1.html).

   ```
   pveum user add cenya-lectura@pve
   pveum user token add cenya-lectura@pve cenya -privsep 1
   pveum aclmod / -token 'cenya-lectura@pve!cenya' -role PVEAuditor
   ```

   En el usuario de Cenya va `cenya-lectura@pve!cenya` y en el secreto el valor
   del token. ⚠ sin verificar los argumentos exactos de tu versión
   (`pveum help`).
3. **Limitación:** ⚠ sin verificar si PVEAuditor permite consultar las IP del
   agente QEMU del invitado; si no salen, es esto.
4. **Comprobar:** `pveum user token permissions cenya-lectura@pve cenya` debe
   mostrar solo privilegios de auditoría.

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

- Cisco, ⚠ sin verificar: `snmp-server community CAMBIAR-ESTA-COMUNIDAD RO`
- Linux (net-snmp), [snmpd.conf](https://www.root.cz/man/5/snmpd-conf/):
  `rocommunity CAMBIAR-ESTA-COMUNIDAD 192.0.2.0/24` (limita el origen a la red
  del agente)

La v2c viaja sin cifrar. Si el equipo admite v3, usa v3.

### 5.2 SNMP v3 (authPriv, solo lectura)

Cenya decide el nivel por las contraseñas que pongas: dos contraseñas es
`authPriv`. Usa SHA y AES-128.

**Linux (net-snmp).** Los usuarios se crean con `createUser` y se les da
lectura con `rouser`; sin `rouser`/`rwuser` el usuario es inútil, y
`createUser` va en el archivo persistente (por ejemplo
`/var/lib/snmp/snmpd.conf`), no en el principal
([snmpd.conf](https://www.root.cz/man/5/snmpd-conf/)). Con el servicio parado:

```
createUser cenya-lectura SHA "CAMBIAR-ESTA-CLAVE-1" AES "CAMBIAR-ESTA-CLAVE-2"
```

y en `/etc/snmp/snmpd.conf`:

```
rouser cenya-lectura priv
```

Las claves tienen mínimo 8 caracteres. ⚠ sin verificar la forma de limitarlo a
una vista concreta (`view ... included ...` y una línea `access`): mira
`man snmpd.conf` de tu versión.

**Cisco.** ⚠ sin verificar (de memoria; contrástalo con la guía de tu
plataforma):

```
snmp-server view CENYA-VISTA iso included
snmp-server group CENYA-GRUPO v3 priv read CENYA-VISTA
snmp-server user cenya-lectura CENYA-GRUPO v3 auth sha CAMBIAR-ESTA-CLAVE-1 priv aes 128 CAMBIAR-ESTA-CLAVE-2
```

Sin `write`, el grupo no puede escribir.

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
