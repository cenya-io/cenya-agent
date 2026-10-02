; Instalador de Windows del agente de Cenya (Inno Setup 6).
;
; Una persona lo ejecuta y termina con el servicio instalado, el icono de
; bandeja y, si el instalador traía la conexión, el agente enrolado. Lo normal
; es que la traiga en su propio NOMBRE: el servidor lo entrega como
;
;   Cenya-Agent-Setup-0.11.0_<base32>.exe
;
; con la cadena de conexión (cenya://portal/CÓDIGO) en base32 (RFC 4648,
; minúsculas, sin relleno) detrás del último «_» (docs/agente-v2-instalacion.md,
; sección 2). El navegador puede añadir « (1)» a una descarga repetida: también
; vale. Sin conexión en el nombre ni en la línea de comandos, la página de
; conexión es OPCIONAL: se puede dejar en blanco y conectar después.
;
; Para desplegar en masa (un MSP con muchas máquinas), en silencio:
;
;   Cenya-Agent-Setup-0.11.0.exe /VERYSILENT /CONNECTION=cenya://portal/XXXX-XXXX-XXXX
;
; Orden: /CONNECTION= manda sobre el nombre; un equipo ya enrolado ignora los
; dos (un despliegue en masa repite el mismo comando, y canjear otra vez un
; código ya gastado dejaría el agente parado). Para cambiarlo de portal:
;   cenya-agent enroll <cadena> --force
;
; Otros parámetros:
;   /CA=<fichero>   certificado de la CA propia del portal (PEM o DER). Se copia
;                   a la carpeta de estado y queda en settings.json ANTES de
;                   enrolar, con `cenya-agent settings set ca_bundle`.
;   /TASKS="!tray"  sin icono de bandeja (un servidor en el que nadie entra).
;   /DIR="D:\Cenya" otra carpeta de instalación.
;   /UPDATE         lo usa el propio agente al actualizarse (lo lanza en
;                   silencio y desacoplado del servicio). Conserva enrolamiento,
;                   identidad y ajustes; antes de sustituir nada guarda la
;                   versión instalada en %ProgramData%\Cenya\previous\app y deja
;                   un vigilante (tarea programada de un solo uso, como SYSTEM)
;                   que vuelve a ella si la nueva no consigue un checkin en
;                   /WATCHDOGSECONDS= segundos (600 por defecto). El diseño y
;                   sus fallos posibles están en update-watchdog.cmd.
;
; Se construye con `agent/packaging/build.ps1`, que ejecuta antes PyInstaller:
;   iscc /DAppVersion=0.11.0 /DSourceDir=..\dist\cenya-agent cenya-agent.iss
;
; Códigos de salida en silencio (además de los de Inno, 0 a 8): 21 si el agente
; se instaló pero no pudo enrolarse (cadena caducada o ya usada, portal
; inalcanzable), 22 si no se pudo instalar el servicio y 23 si el certificado
; de /CA= no se pudo aplicar. Con /UPDATE, si no se pudo guardar la versión
; anterior o crear el vigilante, no se sustituye nada, el servicio vuelve a
; arrancar y Inno sale con su 7 («preparación fallida»). Un despliegue en masa
; que no mirase el código daría por bueno un equipo sin agente.
;
; Todo lo que ve una persona está en los cinco idiomas del producto: los
; mensajes propios van en [CustomMessages] y el resto son los oficiales de Inno.
;
; Qué hace cada pieza y por qué:
;  * El servicio se instala con `cenya-agent-service.exe`, el mismo comando del
;    agente que ya endurece la clave del registro y la carpeta de estado.
;  * El enrolamiento corre con `cenya-agent.exe enroll`, **después** de copiar
;    los ficheros: el token lo guarda el propio agente en su almacén protegido
;    (ProgramData\Cenya\enrollment.json) y el instalador nunca lo ve.
;  * Si el enrolamiento falla, o no se dio conexión, el servicio se instala pero
;    no se arranca: sin token solo daría errores en el Visor de eventos.
;  * La carpeta del programa entra en el PATH del sistema (una sola vez, aunque
;    se actualice) para que `cenya-agent` funcione en cualquier consola nueva,
;    que es lo que enseñan las pantallas de Cenya. Al desinstalar se quita esa
;    entrada y nada más del PATH.
;  * Al desinstalar, `cenya-agent goodbye` avisa al servidor (el agente deja de
;    aparecer como activo) antes de quitar el servicio; sin red, borra igual.

; ExecAndCaptureOutput, con el que se enrola sin pasar por cmd.exe.
#if VER < EncodeVer(6,3,0)
  #error Hace falta Inno Setup 6.3 o posterior.
#endif

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\dist\cenya-agent"
#endif

#define ServiceName "CenyaAgent"
; La clave de desinstalación que Inno escribe para el AppId de abajo (con _is1).
#define UninstallKey "Software\Microsoft\Windows\CurrentVersion\Uninstall\{B6D2F3A1-7C54-4E0B-9A18-5E2C8D9F4A63}_is1"
#define WatchdogTask "Cenya Agent update watchdog"

[Setup]
AppId={{B6D2F3A1-7C54-4E0B-9A18-5E2C8D9F4A63}
AppName=Cenya Agent
AppVersion={#AppVersion}
AppPublisher=Cenya
DefaultDirName={autopf}\Cenya Agent
DisableProgramGroupPage=yes
DisableDirPage=auto
#ifdef Unprivileged
; Solo para probar el instalador sin permisos de administrador (copia de
; ficheros, enrolamiento, rutas de error): no puede instalar el servicio.
PrivilegesRequired=lowest
#else
PrivilegesRequired=admin
#endif
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\installer
#ifdef Unprivileged
OutputBaseFilename=Cenya-Agent-Setup-{#AppVersion}-prueba
#else
OutputBaseFilename=Cenya-Agent-Setup-{#AppVersion}
#endif
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=cenya.ico
UninstallDisplayIcon={app}\cenya-agent-tray.exe
UninstallDisplayName=Cenya Agent
VersionInfoVersion={#AppVersion}
VersionInfoDescription=Cenya Agent
CloseApplications=yes
RestartApplications=no
SetupLogging=yes
; Avisa a Windows de que el PATH cambió: las consolas nuevas ya lo ven.
ChangesEnvironment=yes

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "german"; MessagesFile: "compiler:Languages\German.isl"
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[CustomMessages]
spanish.ConnectionTitle=Conectar con Cenya
spanish.ConnectionDescription=Opcional: puedes dejarlo en blanco y conectar después desde la aplicación.
spanish.ConnectionSubCaption=Si tienes una cadena de conexión (en Cenya, Ajustes → Agentes → Añadir un agente), pégala aquí. Vale una hora y un solo uso.
spanish.ConnectionLabel=Cadena de conexión:
spanish.ConnectionInvalid=La cadena de conexión no es válida. Debe empezar por cenya:// y copiarse entera de Ajustes → Agentes.
spanish.CaLabel=Certificado de la CA del portal (solo si usa un certificado propio):
spanish.CaFilter=Certificados (*.pem;*.crt;*.cer)|*.pem;*.crt;*.cer|Todos los archivos (*.*)|*.*
spanish.CaNotFound=No se encuentra el fichero del certificado de la CA:%n%n%1
spanish.CaFailed=No se pudo aplicar el certificado de la CA:%n%n%1
spanish.EnrollFailed=El agente se ha instalado, pero no se ha podido enrolar:%n%n%1%nGenera otra cadena en Ajustes → Agentes y ejecútala con: cenya-agent enroll <cadena>
spanish.ServiceFailed=No se pudo instalar el servicio de Windows (código %1). Mira el registro de la instalación.
spanish.NotEnrolledNote=El servicio está instalado pero no se ha arrancado porque este equipo aún no está enrolado.
spanish.TrayTask=Mostrar el icono de estado en la bandeja del sistema
spanish.UpdateBackupFailed=No se pudo guardar la versión instalada antes de actualizar (código %1). No se ha cambiado nada.
spanish.UpdateWatchdogFailed=No se pudo crear la tarea que vigila la actualización (código %1). No se ha cambiado nada.
spanish.WatchdogDescription=Vigila una actualización del agente de Cenya y vuelve a la versión anterior si la nueva no consigue conectar. Se borra sola.

english.ConnectionTitle=Connect to Cenya
english.ConnectionDescription=Optional: you can leave it blank and connect later from the application.
english.ConnectionSubCaption=If you have a connection string (in Cenya, Settings → Agents → Add an agent), paste it here. It is valid for one hour and a single use.
english.ConnectionLabel=Connection string:
english.ConnectionInvalid=The connection string is not valid. It must start with cenya:// and be copied whole from Settings → Agents.
english.CaLabel=Certificate of the portal's CA (only if it uses its own certificate):
english.CaFilter=Certificates (*.pem;*.crt;*.cer)|*.pem;*.crt;*.cer|All files (*.*)|*.*
english.CaNotFound=The CA certificate file cannot be found:%n%n%1
english.CaFailed=The CA certificate could not be applied:%n%n%1
english.EnrollFailed=The agent was installed, but it could not be enrolled:%n%n%1%nGenerate another string in Settings → Agents and run: cenya-agent enroll <string>
english.ServiceFailed=The Windows service could not be installed (code %1). See the installation log.
english.NotEnrolledNote=The service is installed but was not started because this machine is not enrolled yet.
english.TrayTask=Show the status icon in the system tray
english.UpdateBackupFailed=The installed version could not be saved before updating (code %1). Nothing has been changed.
english.UpdateWatchdogFailed=The task that watches over the update could not be created (code %1). Nothing has been changed.
english.WatchdogDescription=Watches over an update of the Cenya agent and goes back to the previous version if the new one cannot connect. Removes itself.

german.ConnectionTitle=Mit Cenya verbinden
german.ConnectionDescription=Optional: Sie können das Feld leer lassen und sich später über die Anwendung verbinden.
german.ConnectionSubCaption=Wenn Sie eine Verbindungszeichenfolge haben (in Cenya unter Einstellungen → Agenten → Agent hinzufügen), fügen Sie sie hier ein. Sie gilt eine Stunde und nur einmal.
german.ConnectionLabel=Verbindungszeichenfolge:
german.ConnectionInvalid=Die Verbindungszeichenfolge ist ungültig. Sie muss mit cenya:// beginnen und vollständig aus Einstellungen → Agenten kopiert werden.
german.CaLabel=Zertifikat der Zertifizierungsstelle des Portals (nur bei eigenem Zertifikat):
german.CaFilter=Zertifikate (*.pem;*.crt;*.cer)|*.pem;*.crt;*.cer|Alle Dateien (*.*)|*.*
german.CaNotFound=Die Zertifikatsdatei der Zertifizierungsstelle wurde nicht gefunden:%n%n%1
german.CaFailed=Das Zertifikat der Zertifizierungsstelle konnte nicht übernommen werden:%n%n%1
german.EnrollFailed=Der Agent wurde installiert, konnte aber nicht registriert werden:%n%n%1%nErzeugen Sie unter Einstellungen → Agenten eine neue Zeichenfolge und führen Sie aus: cenya-agent enroll <Zeichenfolge>
german.ServiceFailed=Der Windows-Dienst konnte nicht installiert werden (Code %1). Siehe das Installationsprotokoll.
german.NotEnrolledNote=Der Dienst ist installiert, wurde aber nicht gestartet, da dieser Rechner noch nicht registriert ist.
german.TrayTask=Statussymbol im Infobereich der Taskleiste anzeigen
german.UpdateBackupFailed=Die installierte Version konnte vor dem Update nicht gesichert werden (Code %1). Es wurde nichts geändert.
german.UpdateWatchdogFailed=Die Aufgabe, die das Update überwacht, konnte nicht erstellt werden (Code %1). Es wurde nichts geändert.
german.WatchdogDescription=Überwacht ein Update des Cenya-Agenten und kehrt zur vorherigen Version zurück, wenn sich die neue nicht verbinden kann. Entfernt sich selbst.

french.ConnectionTitle=Se connecter à Cenya
french.ConnectionDescription=Facultatif : vous pouvez laisser ce champ vide et vous connecter plus tard depuis l'application.
french.ConnectionSubCaption=Si vous avez une chaîne de connexion (dans Cenya, Paramètres → Agents → Ajouter un agent), collez-la ici. Elle est valable une heure et une seule fois.
french.ConnectionLabel=Chaîne de connexion :
french.ConnectionInvalid=La chaîne de connexion n'est pas valide. Elle doit commencer par cenya:// et être copiée en entier depuis Paramètres → Agents.
french.CaLabel=Certificat de l'autorité du portail (seulement s'il utilise son propre certificat) :
french.CaFilter=Certificats (*.pem;*.crt;*.cer)|*.pem;*.crt;*.cer|Tous les fichiers (*.*)|*.*
french.CaNotFound=Le fichier du certificat de l'autorité est introuvable :%n%n%1
french.CaFailed=Le certificat de l'autorité n'a pas pu être appliqué :%n%n%1
french.EnrollFailed=L'agent a été installé, mais n'a pas pu être enrôlé :%n%n%1%nGénérez une autre chaîne dans Paramètres → Agents et exécutez : cenya-agent enroll <chaîne>
french.ServiceFailed=Le service Windows n'a pas pu être installé (code %1). Consultez le journal d'installation.
french.NotEnrolledNote=Le service est installé mais n'a pas été démarré, car cette machine n'est pas encore enrôlée.
french.TrayTask=Afficher l'icône d'état dans la zone de notification
french.UpdateBackupFailed=La version installée n'a pas pu être sauvegardée avant la mise à jour (code %1). Rien n'a été modifié.
french.UpdateWatchdogFailed=La tâche qui surveille la mise à jour n'a pas pu être créée (code %1). Rien n'a été modifié.
french.WatchdogDescription=Surveille une mise à jour de l'agent Cenya et revient à la version précédente si la nouvelle ne parvient pas à se connecter. Se supprime d'elle-même.

brazilianportuguese.ConnectionTitle=Conectar ao Cenya
brazilianportuguese.ConnectionDescription=Opcional: você pode deixar em branco e conectar depois pelo aplicativo.
brazilianportuguese.ConnectionSubCaption=Se você tem uma cadeia de conexão (no Cenya, Configurações → Agentes → Adicionar um agente), cole-a aqui. Ela vale por uma hora e um único uso.
brazilianportuguese.ConnectionLabel=Cadeia de conexão:
brazilianportuguese.ConnectionInvalid=A cadeia de conexão não é válida. Ela deve começar com cenya:// e ser copiada inteira de Configurações → Agentes.
brazilianportuguese.CaLabel=Certificado da CA do portal (somente se usar um certificado próprio):
brazilianportuguese.CaFilter=Certificados (*.pem;*.crt;*.cer)|*.pem;*.crt;*.cer|Todos os arquivos (*.*)|*.*
brazilianportuguese.CaNotFound=O arquivo do certificado da CA não foi encontrado:%n%n%1
brazilianportuguese.CaFailed=Não foi possível aplicar o certificado da CA:%n%n%1
brazilianportuguese.EnrollFailed=O agente foi instalado, mas não foi possível registrá-lo:%n%n%1%nGere outra cadeia em Configurações → Agentes e execute: cenya-agent enroll <cadeia>
brazilianportuguese.ServiceFailed=Não foi possível instalar o serviço do Windows (código %1). Veja o registro da instalação.
brazilianportuguese.NotEnrolledNote=O serviço está instalado, mas não foi iniciado porque esta máquina ainda não está registrada.
brazilianportuguese.TrayTask=Mostrar o ícone de status na área de notificação
brazilianportuguese.UpdateBackupFailed=Não foi possível guardar a versão instalada antes de atualizar (código %1). Nada foi alterado.
brazilianportuguese.UpdateWatchdogFailed=Não foi possível criar a tarefa que vigia a atualização (código %1). Nada foi alterado.
brazilianportuguese.WatchdogDescription=Vigia uma atualização do agente do Cenya e volta à versão anterior se a nova não conseguir conectar. Remove-se sozinha.

[Tasks]
Name: "tray"; Description: "{cm:TrayTask}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
; El vigilante de /UPDATE: no se instala con el programa (se reemplazaría a sí
; mismo); se extrae y se copia a %ProgramData%\Cenya\previous en PrepareToInstall.
Source: "update-watchdog.cmd"; Flags: dontcopy

[Registry]
; El icono arranca al iniciar sesión cualquier usuario de este equipo, y se
; quita solo al desinstalar.
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Cenya Agent"; ValueData: """{app}\cenya-agent-tray.exe"""; Flags: uninsdeletevalue; Tasks: tray
; `cenya-agent` en cualquier consola, sin `cd` a Archivos de programa. Se quita
; al desinstalar en CurUninstallStepChanged: Inno no sabe quitar un trozo de un
; valor, y borrar el valor entero se llevaría el PATH de todo el equipo.
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsPathEntry

[Run]
; Para ver el icono ya, sin esperar al próximo inicio de sesión.
Filename: "{app}\cenya-agent-tray.exe"; Flags: nowait postinstall skipifsilent runasoriginaluser; Tasks: tray

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/im cenya-agent-tray.exe /f"; Flags: runhidden; RunOnceId: "KillTray"
Filename: "{app}\cenya-agent-service.exe"; Parameters: "--wait 60 stop"; Flags: runhidden; RunOnceId: "StopService"
; Se despide del servidor (spec 1.7) antes de quitar el servicio. Sin red borra
; igual el enrolamiento y sale con 0: no bloquea la desinstalación.
Filename: "{app}\cenya-agent.exe"; Parameters: "goodbye"; Flags: runhidden; RunOnceId: "Goodbye"
Filename: "{app}\cenya-agent-service.exe"; Parameters: "remove"; Flags: runhidden; RunOnceId: "RemoveService"
; Un vigilante de una actualización que aún no terminó no sobrevive al agente.
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""{#WatchdogTask}"" /F"; Flags: runhidden; RunOnceId: "DeleteWatchdog"

[UninstallDelete]
; El token y el estado se van con el programa: un secreto no se queda en un
; equipo en el que ya no hay agente. La copia de la versión anterior (previous)
; vive ahí dentro y se va con él.
Type: filesandordirs; Name: "{commonappdata}\Cenya"

[Code]
procedure ExitProcess(ExitCode: Cardinal);
  external 'ExitProcess@kernel32.dll stdcall';

var
  ConnectionPage: TInputQueryWizardPage;
  CaBrowseButton: TNewButton;
  { La versión instalada antes de esta, leída del registro al empezar. }
  InstalledVersion: String;

{ Inno no deja fijar el código de salida desde [Code] una vez instalado: una
  excepción o un Abort se registran y el proceso termina con 0. En silencio,
  quien despliega solo tiene ese código, así que se sale con uno propio. La
  instalación ya está guardada (el desinstalador existe), no queda a medias. }
procedure FailDeployment(ExitCode: Integer; const Message: String);
begin
  Log(Message);
  if WizardSilent then
    ExitProcess(ExitCode);
end;

function StateDir: String;
begin
  Result := ExpandConstant('{commonappdata}\Cenya');
end;

function EnrollmentFile: String;
begin
  Result := StateDir + '\enrollment.json';
end;

function PreviousDir: String;
begin
  Result := StateDir + '\previous';
end;

{ /UPDATE: un interruptor sin valor, así que no sirve {param:...}. }
function IsUpdateMode: Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/UPDATE') = 0 then
      Result := True;
end;

{ Cuánto espera el vigilante el primer checkin de la versión nueva. }
function WatchdogSeconds: Integer;
begin
  Result := StrToIntDef(ExpandConstant('{param:WATCHDOGSECONDS|600}'), 600);
  if Result < 60 then
    Result := 60;
  if Result > 86400 then
    Result := 86400;
end;

{ Lo que dice la línea de comandos, para el despliegue en silencio. }
function ConnectionParam: String;
begin
  Result := Trim(ExpandConstant('{param:CONNECTION|}'));
end;

{ Esquema conocido y solo los caracteres que puede llevar una cadena buena
  (host, puerto, IPv6 entre corchetes y el código). El análisis de verdad lo
  hace el agente; esto impide que una comilla o un espacio lleguen siquiera a
  su línea de comandos. }
function LooksLikeConnection(const Value: String): Boolean;
var
  Lower: String;
  I: Integer;
begin
  Lower := Lowercase(Value);
  Result := (Pos('cenya://', Lower) = 1) or (Pos('cenya+http://', Lower) = 1);
  for I := 1 to Length(Lower) do
    if Pos(Lower[I], 'abcdefghijklmnopqrstuvwxyz0123456789.-:/[]+') = 0 then
      Result := False;
end;

{ Base32 de RFC 4648, alfabeto en minúsculas y sin relleno: cinco bits por
  carácter, un byte cada vez que se juntan ocho. Lo que sobra al final tiene
  que ser menos de un carácter (menos de 5 bits) y todo ceros: así solo hay una
  forma válida de escribir cada cadena, y un nombre manipulado no se acepta a
  medias. Buffer nunca pasa de 12 bits. }
function Base32Decode(const Value: String; var Decoded: String): Boolean;
var
  Alphabet: String;
  I, Index, Buffer, Bits: Integer;
begin
  Alphabet := 'abcdefghijklmnopqrstuvwxyz234567';
  Decoded := '';
  Buffer := 0;
  Bits := 0;
  Result := Length(Value) > 0;
  for I := 1 to Length(Value) do
  begin
    Index := Pos(Value[I], Alphabet);
    if Index = 0 then
    begin
      Result := False;
      Exit;
    end;
    Buffer := (Buffer shl 5) or (Index - 1);
    Bits := Bits + 5;
    if Bits >= 8 then
    begin
      Bits := Bits - 8;
      Decoded := Decoded + Chr((Buffer shr Bits) and $FF);
      Buffer := Buffer and ((1 shl Bits) - 1);
    end;
  end;
  if (Bits >= 5) or (Buffer <> 0) then
    Result := False;
end;

{ La cadena de conexión del nombre del instalador (contrato, sección 2):
  Cenya-Agent-Setup-X.Y.Z_<base32>.exe, quizá con el « (1)» que añade el
  navegador. Lo mismo que _([a-z2-7]{16,})( \(\d+\))?\.exe$. '' si no hay. }
function InstallerNameConnection: String;
var
  Name, Payload, Decoded: String;
  I, P: Integer;
begin
  Result := '';
  Name := ExtractFileName(ExpandConstant('{srcexe}'));
  if (Length(Name) < 5) or (CompareText(Copy(Name, Length(Name) - 3, 4), '.exe') <> 0) then
    Exit;
  Name := Copy(Name, 1, Length(Name) - 4);
  { « (1)», « (2)»...: espacio, paréntesis y al menos una cifra. }
  if (Length(Name) > 0) and (Name[Length(Name)] = ')') then
  begin
    P := Length(Name) - 1;
    while (P > 0) and (Name[P] >= '0') and (Name[P] <= '9') do
      P := P - 1;
    if (P < Length(Name) - 1) and (P >= 2) and (Name[P] = '(') and (Name[P - 1] = ' ') then
      Name := Copy(Name, 1, P - 2)
    else
      Exit;
  end;
  P := 0;
  for I := Length(Name) downto 1 do
    if (P = 0) and (Name[I] = '_') then
      P := I;
  if P = 0 then
    Exit;
  Payload := Copy(Name, P + 1, Length(Name) - P);
  if Length(Payload) < 16 then
    Exit;
  if not Base32Decode(Payload, Decoded) then
    Exit;
  if LooksLikeConnection(Decoded) then
    Result := Decoded;
end;

{ Una actualización de un equipo ya enrolado no vuelve a pedir nada, ni quien
  trae la conexión en la línea de comandos o en el nombre. }
function NeedsConnection: Boolean;
begin
  Result := (ConnectionParam = '') and (InstallerNameConnection = '') and
    (not FileExists(EnrollmentFile)) and (not IsUpdateMode);
end;

{ Ya enrolado, /CONNECTION y el nombre se ignoran: ver la cabecera.
  /CONNECTION manda sobre el nombre; la página, sobre nada. }
function ChosenConnection: String;
begin
  Result := '';
  if FileExists(EnrollmentFile) then
  begin
    if (ConnectionParam <> '') or (InstallerNameConnection <> '') then
      Log('Equipo ya enrolado: se conserva su token y se ignoran /CONNECTION y el nombre del instalador.');
  end
  else if ConnectionParam <> '' then
    Result := ConnectionParam
  else if InstallerNameConnection <> '' then
    Result := InstallerNameConnection
  else
    Result := Trim(ConnectionPage.Values[0]);
end;

{ /CA=, o el campo de la página. Ruta completa: el agente corre en {app}. }
function ChosenCa: String;
begin
  Result := Trim(ExpandConstant('{param:CA|}'));
  if Result = '' then
    Result := Trim(ConnectionPage.Values[1]);
  if Result <> '' then
    Result := ExpandFileName(Result);
end;

procedure CaBrowseClick(Sender: TObject);
var
  FileName: String;
begin
  FileName := ConnectionPage.Values[1];
  if GetOpenFileName('', FileName, '', CustomMessage('CaFilter'), 'pem') then
    ConnectionPage.Values[1] := FileName;
end;

procedure InitializeWizard;
begin
  ConnectionPage := CreateInputQueryPage(
    wpSelectTasks,
    CustomMessage('ConnectionTitle'),
    CustomMessage('ConnectionDescription'),
    CustomMessage('ConnectionSubCaption'));
  ConnectionPage.Add(CustomMessage('ConnectionLabel'), False);
  ConnectionPage.Add(CustomMessage('CaLabel'), False);
  { «Examinar...» al lado del campo del certificado. }
  CaBrowseButton := TNewButton.Create(ConnectionPage);
  CaBrowseButton.Parent := ConnectionPage.Surface;
  CaBrowseButton.Caption := SetupMessage(msgButtonWizardBrowse);
  CaBrowseButton.Width := ScaleX(80);
  CaBrowseButton.Height := ConnectionPage.Edits[1].Height + ScaleY(2);
  CaBrowseButton.Top := ConnectionPage.Edits[1].Top - ScaleY(1);
  CaBrowseButton.Left := ConnectionPage.SurfaceWidth - CaBrowseButton.Width;
  ConnectionPage.Edits[1].Width := CaBrowseButton.Left - ScaleX(8) - ConnectionPage.Edits[1].Left;
  CaBrowseButton.OnClick := @CaBrowseClick;
end;

function InitializeSetup: Boolean;
begin
  Result := True;
  { HKLM64: la clave que escribe Inno en modo de 64 bits (el único que se instala). }
  if not RegQueryStringValue(HKLM64, '{#UninstallKey}', 'DisplayVersion', InstalledVersion) then
    InstalledVersion := '';
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if PageID = ConnectionPage.ID then
    Result := not NeedsConnection;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Connection, Ca: String;
begin
  Result := True;
  if CurPageID = ConnectionPage.ID then
  begin
    { En blanco vale: se conecta después. Lo que se escriba, que valga. }
    Connection := Trim(ConnectionPage.Values[0]);
    if (Connection <> '') and (not LooksLikeConnection(Connection)) then
    begin
      MsgBox(CustomMessage('ConnectionInvalid'), mbError, MB_OK);
      Result := False;
      Exit;
    end;
    Ca := Trim(ConnectionPage.Values[1]);
    if (Ca <> '') and (not FileExists(ExpandFileName(Ca))) then
    begin
      MsgBox(FmtMessage(CustomMessage('CaNotFound'), [Ca]), mbError, MB_OK);
      Result := False;
    end;
  end;
end;

{ Antes de copiar nada: un servicio o un icono en marcha tienen ficheros bloqueados. }
procedure StopRunningAgent;
var
  ResultCode: Integer;
begin
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/im cenya-agent-tray.exe /f', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\net.exe'), 'stop {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function OutputText(const Output: TExecOutput): String;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to GetArrayLength(Output.StdOut) - 1 do
    Result := Result + Output.StdOut[I] + #13#10;
  for I := 0 to GetArrayLength(Output.StdErr) - 1 do
    Result := Result + Output.StdErr[I] + #13#10;
  Result := Trim(Result);
end;

{ El enrolamiento lo hace el propio agente; su salida se recoge para poder
  enseñar el motivo si falla (y nunca contiene el token). Se lanza el
  ejecutable directamente, sin cmd.exe: la cadena la escribe una persona o un
  script de despliegue y no debe pasar nunca por un intérprete de comandos con
  permisos de administrador. }
function EnrollAgent(const Connection: String; var Reason: String): Boolean;
var
  ResultCode: Integer;
  Output: TExecOutput;
begin
  Result := ExecAndCaptureOutput(
    ExpandConstant('{app}\cenya-agent.exe'), 'enroll "' + Connection + '" --force',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode, Output) and (ResultCode = 0);
  Reason := '';
  if not Result then
    Reason := OutputText(Output);
end;

{ El certificado de la CA lo copia y lo anota el propio agente
  (`cenya-agent settings set ca_bundle`), que también lo valida: el instalador
  no escribe JSON. Una ruta de Windows no puede llevar comillas, así que
  entrecomillarla basta; aun así, una que las traiga no se pasa. }
function ApplyCa(const Path: String; var Reason: String): Boolean;
var
  ResultCode: Integer;
  Output: TExecOutput;
begin
  Reason := Path;
  Result := False;
  if (Pos('"', Path) > 0) or (not FileExists(Path)) then
  begin
    Reason := FmtMessage(CustomMessage('CaNotFound'), [Path]);
    Exit;
  end;
  Result := ExecAndCaptureOutput(
    ExpandConstant('{app}\cenya-agent.exe'), 'settings set ca_bundle "' + Path + '"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode, Output) and (ResultCode = 0);
  if not Result then
    Reason := OutputText(Output);
end;

function RunService(const Parameters: String): Integer;
var
  ResultCode: Integer;
begin
  if not Exec(ExpandConstant('{app}\cenya-agent-service.exe'), Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;
  Result := ResultCode;
end;

function ServiceExists: Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

procedure InstallAgentService;
var
  Code, ResultCode: Integer;
  Verb: String;
begin
  if ServiceExists then Verb := 'update' else Verb := 'install';
  Code := RunService('--startup delayed ' + Verb);
  if Code <> 0 then
  begin
    SuppressibleMsgBox(FmtMessage(CustomMessage('ServiceFailed'), [IntToStr(Code)]), mbError, MB_OK, IDOK);
    FailDeployment(22, FmtMessage(CustomMessage('ServiceFailed'), [IntToStr(Code)]));
  end;
  { Si se cae, que vuelva: al minuto, al minuto y a los cinco. }
  Exec(ExpandConstant('{sys}\sc.exe'), 'failure {#ServiceName} reset= 86400 actions= restart/60000/restart/60000/restart/300000', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

{ --- /UPDATE: la versión anterior y su vigilante ---
  Todo antes de sustituir un solo fichero (PrepareToInstall). Si algo de esto
  falla, el servicio vuelve a arrancar con la versión de siempre y la
  actualización no sigue: mejor sin actualizar que sin vuelta atrás. }

{ Solo cifras y puntos: va como argumento de una tarea y a un .cmd. }
function SafeVersion(const Value: String): String;
var
  I: Integer;
begin
  Result := Value;
  if Result = '' then
    Result := 'unknown';
  for I := 1 to Length(Value) do
    if Pos(Value[I], '0123456789.') = 0 then
      Result := 'unknown';
end;

function XmlEscape(const Value: String): String;
begin
  Result := Value;
  StringChangeEx(Result, '&', '&amp;', True);
  StringChangeEx(Result, '<', '&lt;', True);
  StringChangeEx(Result, '>', '&gt;', True);
  StringChangeEx(Result, '"', '&quot;', True);
end;

{ Copia la carpeta del programa a previous\app: primero a app.partial y solo
  entera se renombra. Un instalador matado a mitad nunca deja una copia a
  medias que el vigilante pudiera restaurar. 0 si fue bien. }
function BackupPrevious: Integer;
var
  Partial, Target: String;
  ResultCode: Integer;
begin
  Partial := PreviousDir + '\app.partial';
  Target := PreviousDir + '\app';
  ForceDirectories(PreviousDir);
  DelTree(Partial, True, True, True);
  if not Exec(ExpandConstant('{sys}\robocopy.exe'),
      '"' + ExpandConstant('{app}') + '" "' + Partial + '" /MIR /R:2 /W:2 /NP /NFL /NDL /NJH /NJS',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Result := 1001;
    Exit;
  end;
  { robocopy: 0 a 7 es éxito (con o sin cambios); 8 o más, algo no se copió. }
  if ResultCode >= 8 then
  begin
    Result := ResultCode;
    Exit;
  end;
  DelTree(Target, True, True, True);
  if not RenameFile(Partial, Target) then
  begin
    Result := 1002;
    Exit;
  end;
  Result := 0;
end;

{ La tarea programada: al registrarse (30 s después) y en cada arranque del
  equipo, como SYSTEM, una sola instancia a la vez. El .cmd hace el resto y
  borra la tarea al terminar. }
function CreateWatchdog: Integer;
var
  Script, XmlFile, Arguments, Xml: String;
  Lines: TArrayOfString;
  ResultCode: Integer;
begin
  Script := PreviousDir + '\update-watchdog.cmd';
  ExtractTemporaryFile('update-watchdog.cmd');
  if not FileCopy(ExpandConstant('{tmp}\update-watchdog.cmd'), Script, False) then
  begin
    Result := 1003;
    Exit;
  end;
  { Una marca de «sana» de un intento anterior de esta misma versión no vale. }
  ForceDirectories(StateDir + '\updates');
  DeleteFile(StateDir + '\updates\healthy-{#AppVersion}');
  { El vigilante espera a que esta marca desaparezca (DeinitializeSetup). }
  SaveStringToFile(PreviousDir + '\installing', '{#AppVersion}', False);
  Arguments := '"' + ExpandConstant('{app}') + '" ' + SafeVersion(InstalledVersion) + ' {#AppVersion} ' + IntToStr(WatchdogSeconds);
  Xml :=
    '<?xml version="1.0" encoding="UTF-8"?>' + #13#10 +
    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">' + #13#10 +
    '  <RegistrationInfo><Description>' + XmlEscape(CustomMessage('WatchdogDescription')) + '</Description></RegistrationInfo>' + #13#10 +
    '  <Triggers>' + #13#10 +
    '    <RegistrationTrigger><Enabled>true</Enabled><Delay>PT30S</Delay></RegistrationTrigger>' + #13#10 +
    '    <BootTrigger><Enabled>true</Enabled><Delay>PT1M</Delay></BootTrigger>' + #13#10 +
    '  </Triggers>' + #13#10 +
    '  <Principals><Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>' + #13#10 +
    '  <Settings>' + #13#10 +
    '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>' + #13#10 +
    '    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>' + #13#10 +
    '    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>' + #13#10 +
    '    <StartWhenAvailable>true</StartWhenAvailable>' + #13#10 +
    '    <ExecutionTimeLimit>PT3H</ExecutionTimeLimit>' + #13#10 +
    '    <Enabled>true</Enabled>' + #13#10 +
    '  </Settings>' + #13#10 +
    '  <Actions Context="Author"><Exec><Command>' + XmlEscape(Script) + '</Command><Arguments>' + XmlEscape(Arguments) + '</Arguments></Exec></Actions>' + #13#10 +
    '</Task>' + #13#10;
  XmlFile := ExpandConstant('{tmp}\cenya-watchdog.xml');
  SetArrayLength(Lines, 1);
  Lines[0] := Xml;
  if not SaveStringsToUTF8File(XmlFile, Lines, False) then
  begin
    Result := 1004;
    Exit;
  end;
  if not Exec(ExpandConstant('{sys}\schtasks.exe'), '/Create /F /TN "{#WatchdogTask}" /XML "' + XmlFile + '"',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := 1005;
  Result := ResultCode;
  if Result <> 0 then
    DeleteFile(PreviousDir + '\installing');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  Result := '';
  { Solo una actualización de verdad: modo /UPDATE, con administrador, sobre
    una instalación existente y enrolada (su carpeta de estado ya protegida). }
  if not (IsUpdateMode and IsAdminInstallMode) then
    Exit;
  if not (FileExists(ExpandConstant('{app}\cenya-agent.exe')) and FileExists(EnrollmentFile)) then
  begin
    Log('/UPDATE sin una instalación enrolada: se instala sin vigilante.');
    Exit;
  end;
  StopRunningAgent;
  Code := BackupPrevious;
  if Code <> 0 then
  begin
    RunService('--wait 60 start');
    Result := FmtMessage(CustomMessage('UpdateBackupFailed'), [IntToStr(Code)]);
    Log(Result);
    Exit;
  end;
  Code := CreateWatchdog;
  if Code <> 0 then
  begin
    RunService('--wait 60 start');
    Result := FmtMessage(CustomMessage('UpdateWatchdogFailed'), [IntToStr(Code)]);
    Log(Result);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Connection, Reason, Ca: String;
  Enrolled: Boolean;
begin
  if CurStep = ssInstall then
    StopRunningAgent;

  if CurStep = ssPostInstall then
  begin
    { El certificado, antes que nada: sin él no se podría enrolar contra un
      portal con certificado propio. Vale también para un equipo ya enrolado. }
    Ca := ChosenCa;
    if Ca <> '' then
    begin
      if not ApplyCa(Ca, Reason) then
      begin
        SuppressibleMsgBox(FmtMessage(CustomMessage('CaFailed'), [Reason]), mbError, MB_OK, IDOK);
        FailDeployment(23, FmtMessage(CustomMessage('CaFailed'), [Reason]));
      end;
    end;

    Enrolled := FileExists(EnrollmentFile);
    Connection := ChosenConnection;
    if Connection <> '' then
    begin
      if LooksLikeConnection(Connection) then
        Enrolled := EnrollAgent(Connection, Reason)
      else
      begin
        { En silencio nadie pasó por la página que lo comprueba. }
        Enrolled := False;
        Reason := CustomMessage('ConnectionInvalid');
      end;
      if not Enrolled then
      begin
        { Interactivo: se enseña el motivo. En silencio no hay quien lo lea, y
          lo que importa es que el despliegue vea un código de error. }
        SuppressibleMsgBox(FmtMessage(CustomMessage('EnrollFailed'), [Reason]), mbError, MB_OK, IDOK);
        { En silencio, ya: la causa es la cadena, no el servicio. }
        FailDeployment(21, FmtMessage(CustomMessage('EnrollFailed'), [Reason]));
      end;
    end;

    InstallAgentService;

    if Enrolled then
      RunService('--wait 60 start')
    else
    begin
      Log(CustomMessage('NotEnrolledNote'));
    end;
  end;
end;

{ Siempre, haya ido bien o mal: el vigilante deja de esperar al instalador. }
procedure DeinitializeSetup;
begin
  if IsUpdateMode then
    DeleteFile(PreviousDir + '\installing');
end;

{ --- La carpeta del programa en el PATH del sistema --- }

const
  EnvironmentKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

{ "C:\Program Files\Cenya Agent\" y "c:\program files\cenya agent" son la misma. }
function SamePathEntry(const Entry, Dir: String): Boolean;
begin
  Result := CompareText(RemoveBackslashUnlessRoot(Trim(Entry)), RemoveBackslashUnlessRoot(Trim(Dir))) = 0;
end;

{ Quita Dir de una lista separada por ';' y deja el resto tal cual. }
function WithoutPathEntry(const Path, Dir: String; var Found: Boolean): String;
var
  Rest, Entry: String;
  P: Integer;
begin
  Result := '';
  Found := False;
  Rest := Path;
  while Rest <> '' do
  begin
    P := Pos(';', Rest);
    if P = 0 then
    begin
      Entry := Rest;
      Rest := '';
    end
    else
    begin
      Entry := Copy(Rest, 1, P - 1);
      Delete(Rest, 1, P);
    end;
    if SamePathEntry(Entry, Dir) then
      Found := True
    else if Trim(Entry) <> '' then
    begin
      if Result <> '' then
        Result := Result + ';';
      Result := Result + Entry;
    end;
  end;
end;

{ Check de [Registry]: solo si no está ya (una actualización no la duplica) y
  solo en la instalación de verdad: la de prueba sin administrador no puede
  escribir en HKLM. }
function NeedsPathEntry: Boolean;
var
  Path: String;
  Found: Boolean;
begin
  Result := IsAdminInstallMode;
  if Result and RegQueryStringValue(HKLM, EnvironmentKey, 'Path', Path) then
  begin
    WithoutPathEntry(Path, ExpandConstant('{app}'), Found);
    Result := not Found;
  end;
end;

procedure RemovePathEntry;
var
  Path, Cleaned: String;
  Found: Boolean;
begin
  if not IsAdminInstallMode then
    Exit;
  if not RegQueryStringValue(HKLM, EnvironmentKey, 'Path', Path) then
    Exit;
  Cleaned := WithoutPathEntry(Path, ExpandConstant('{app}'), Found);
  if Found then
    RegWriteExpandStringValue(HKLM, EnvironmentKey, 'Path', Cleaned);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemovePathEntry;
end;
