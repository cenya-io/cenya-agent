; Instalador de Windows del agente de Cenya (Inno Setup 6).
;
; Una persona lo ejecuta, pega la cadena de conexión de Ajustes -> Agentes y
; termina con el servicio instalado, el icono de bandeja y el agente enrolado.
; Para desplegar en masa (un MSP con muchas máquinas), en silencio:
;
;   Cenya-Agent-Setup-0.10.2.exe /VERYSILENT /CONNECTION=cenya://portal/XXXX-XXXX-XXXX
;
; Otros parámetros: /TASKS="!tray" (sin icono de bandeja, para un servidor en el
; que nadie inicia sesión) y /DIR="D:\Cenya". Un equipo ya enrolado (una
; actualización) no pide nada y conserva su token, aunque se le vuelva a pasar
; /CONNECTION: un despliegue en masa repite el mismo comando, y canjear otra vez
; un código ya gastado dejaría el agente parado. Para cambiarlo de portal:
;   cenya-agent enroll <cadena> --force
;
; Se construye con `agent/packaging/build.ps1`, que ejecuta antes PyInstaller:
;   iscc /DAppVersion=0.10.2 /DSourceDir=..\dist\cenya-agent cenya-agent.iss
;
; Códigos de salida en silencio (además de los de Inno, 0 a 8): 21 si el agente
; se instaló pero no pudo enrolarse (cadena caducada o ya usada, portal
; inalcanzable) y 22 si no se pudo instalar el servicio. Un despliegue en masa
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
;  * Si el enrolamiento falla el servicio se instala pero no se arranca: sin
;    token solo daría errores en el Visor de eventos.
;  * La carpeta del programa entra en el PATH del sistema (una sola vez, aunque
;    se actualice) para que `cenya-agent` funcione en cualquier consola nueva,
;    que es lo que enseñan las pantallas de Cenya. Al desinstalar se quita esa
;    entrada y nada más del PATH.

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
spanish.ConnectionDescription=El agente necesita saber a qué portal pertenece.
spanish.ConnectionSubCaption=En Cenya, abre Ajustes → Agentes → Añadir un agente y pega aquí la cadena de conexión. Vale una hora y un solo uso.
spanish.ConnectionLabel=Cadena de conexión:
spanish.ConnectionInvalid=La cadena de conexión no es válida. Debe empezar por cenya:// y copiarse entera de Ajustes → Agentes.
spanish.EnrollFailed=El agente se ha instalado, pero no se ha podido enrolar:%n%n%1%nGenera otra cadena en Ajustes → Agentes y ejecútala con: cenya-agent enroll <cadena>
spanish.ServiceFailed=No se pudo instalar el servicio de Windows (código %1). Mira el registro de la instalación.
spanish.NotEnrolledNote=El servicio está instalado pero no se ha arrancado porque este equipo aún no está enrolado.
spanish.TrayTask=Mostrar el icono de estado en la bandeja del sistema

english.ConnectionTitle=Connect to Cenya
english.ConnectionDescription=The agent needs to know which portal it belongs to.
english.ConnectionSubCaption=In Cenya, open Settings → Agents → Add an agent and paste the connection string here. It is valid for one hour and a single use.
english.ConnectionLabel=Connection string:
english.ConnectionInvalid=The connection string is not valid. It must start with cenya:// and be copied whole from Settings → Agents.
english.EnrollFailed=The agent was installed, but it could not be enrolled:%n%n%1%nGenerate another string in Settings → Agents and run: cenya-agent enroll <string>
english.ServiceFailed=The Windows service could not be installed (code %1). See the installation log.
english.NotEnrolledNote=The service is installed but was not started because this machine is not enrolled yet.
english.TrayTask=Show the status icon in the system tray

german.ConnectionTitle=Mit Cenya verbinden
german.ConnectionDescription=Der Agent muss wissen, zu welchem Portal er gehört.
german.ConnectionSubCaption=Öffnen Sie in Cenya Einstellungen → Agenten → Agent hinzufügen und fügen Sie die Verbindungszeichenfolge hier ein. Sie gilt eine Stunde und nur einmal.
german.ConnectionLabel=Verbindungszeichenfolge:
german.ConnectionInvalid=Die Verbindungszeichenfolge ist ungültig. Sie muss mit cenya:// beginnen und vollständig aus Einstellungen → Agenten kopiert werden.
german.EnrollFailed=Der Agent wurde installiert, konnte aber nicht registriert werden:%n%n%1%nErzeugen Sie unter Einstellungen → Agenten eine neue Zeichenfolge und führen Sie aus: cenya-agent enroll <Zeichenfolge>
german.ServiceFailed=Der Windows-Dienst konnte nicht installiert werden (Code %1). Siehe das Installationsprotokoll.
german.NotEnrolledNote=Der Dienst ist installiert, wurde aber nicht gestartet, da dieser Rechner noch nicht registriert ist.
german.TrayTask=Statussymbol im Infobereich der Taskleiste anzeigen

french.ConnectionTitle=Se connecter à Cenya
french.ConnectionDescription=L'agent doit savoir à quel portail il appartient.
french.ConnectionSubCaption=Dans Cenya, ouvrez Paramètres → Agents → Ajouter un agent et collez ici la chaîne de connexion. Elle est valable une heure et une seule fois.
french.ConnectionLabel=Chaîne de connexion :
french.ConnectionInvalid=La chaîne de connexion n'est pas valide. Elle doit commencer par cenya:// et être copiée en entier depuis Paramètres → Agents.
french.EnrollFailed=L'agent a été installé, mais n'a pas pu être enrôlé :%n%n%1%nGénérez une autre chaîne dans Paramètres → Agents et exécutez : cenya-agent enroll <chaîne>
french.ServiceFailed=Le service Windows n'a pas pu être installé (code %1). Consultez le journal d'installation.
french.NotEnrolledNote=Le service est installé mais n'a pas été démarré, car cette machine n'est pas encore enrôlée.
french.TrayTask=Afficher l'icône d'état dans la zone de notification

brazilianportuguese.ConnectionTitle=Conectar ao Cenya
brazilianportuguese.ConnectionDescription=O agente precisa saber a qual portal pertence.
brazilianportuguese.ConnectionSubCaption=No Cenya, abra Configurações → Agentes → Adicionar um agente e cole aqui a cadeia de conexão. Ela vale por uma hora e um único uso.
brazilianportuguese.ConnectionLabel=Cadeia de conexão:
brazilianportuguese.ConnectionInvalid=A cadeia de conexão não é válida. Ela deve começar com cenya:// e ser copiada inteira de Configurações → Agentes.
brazilianportuguese.EnrollFailed=O agente foi instalado, mas não foi possível registrá-lo:%n%n%1%nGere outra cadeia em Configurações → Agentes e execute: cenya-agent enroll <cadeia>
brazilianportuguese.ServiceFailed=Não foi possível instalar o serviço do Windows (código %1). Veja o registro da instalação.
brazilianportuguese.NotEnrolledNote=O serviço está instalado, mas não foi iniciado porque esta máquina ainda não está registrada.
brazilianportuguese.TrayTask=Mostrar o ícone de status na área de notificação

[Tasks]
Name: "tray"; Description: "{cm:TrayTask}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

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
Filename: "{app}\cenya-agent-service.exe"; Parameters: "remove"; Flags: runhidden; RunOnceId: "RemoveService"

[UninstallDelete]
; El token y el estado se van con el programa: un secreto no se queda en un
; equipo en el que ya no hay agente.
Type: filesandordirs; Name: "{commonappdata}\Cenya"

[Code]
procedure ExitProcess(ExitCode: Cardinal);
  external 'ExitProcess@kernel32.dll stdcall';

var
  ConnectionPage: TInputQueryWizardPage;

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

function EnrollmentFile: String;
begin
  Result := ExpandConstant('{commonappdata}\Cenya\enrollment.json');
end;

{ Lo que dice la línea de comandos, para el despliegue en silencio. }
function ConnectionParam: String;
begin
  Result := Trim(ExpandConstant('{param:CONNECTION|}'));
end;

{ Una actualización de un equipo ya enrolado no vuelve a pedir nada. }
function NeedsConnection: Boolean;
begin
  Result := (ConnectionParam = '') and (not FileExists(EnrollmentFile));
end;

{ Ya enrolado, /CONNECTION se ignora: ver la cabecera. }
function ChosenConnection: String;
begin
  Result := '';
  if FileExists(EnrollmentFile) then
  begin
    if ConnectionParam <> '' then
      Log('Equipo ya enrolado: se conserva su token y se ignora /CONNECTION.');
  end
  else if ConnectionParam <> '' then
    Result := ConnectionParam
  else
    Result := Trim(ConnectionPage.Values[0]);
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

procedure InitializeWizard;
begin
  ConnectionPage := CreateInputQueryPage(
    wpSelectTasks,
    CustomMessage('ConnectionTitle'),
    CustomMessage('ConnectionDescription'),
    CustomMessage('ConnectionSubCaption'));
  ConnectionPage.Add(CustomMessage('ConnectionLabel'), False);
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if PageID = ConnectionPage.ID then
    Result := not NeedsConnection;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = ConnectionPage.ID then
  begin
    if not LooksLikeConnection(Trim(ConnectionPage.Values[0])) then
    begin
      MsgBox(CustomMessage('ConnectionInvalid'), mbError, MB_OK);
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

{ El enrolamiento lo hace el propio agente; su salida se recoge para poder
  enseñar el motivo si falla (y nunca contiene el token). Se lanza el
  ejecutable directamente, sin cmd.exe: la cadena la escribe una persona o un
  script de despliegue y no debe pasar nunca por un intérprete de comandos con
  permisos de administrador. }
function EnrollAgent(const Connection: String; var Reason: String): Boolean;
var
  ResultCode, I: Integer;
  Output: TExecOutput;
begin
  Result := ExecAndCaptureOutput(
    ExpandConstant('{app}\cenya-agent.exe'), 'enroll "' + Connection + '" --force',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode, Output) and (ResultCode = 0);
  Reason := '';
  if not Result then
  begin
    for I := 0 to GetArrayLength(Output.StdOut) - 1 do
      Reason := Reason + Output.StdOut[I] + #13#10;
    for I := 0 to GetArrayLength(Output.StdErr) - 1 do
      Reason := Reason + Output.StdErr[I] + #13#10;
    Reason := Trim(Reason);
  end;
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

procedure CurStepChanged(CurStep: TSetupStep);
var
  Connection, Reason: String;
  Enrolled: Boolean;
begin
  if CurStep = ssInstall then
    StopRunningAgent;

  if CurStep = ssPostInstall then
  begin
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
