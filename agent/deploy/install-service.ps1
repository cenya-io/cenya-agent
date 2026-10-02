<#
.SYNOPSIS
    Instala (o actualiza) el agente de NetInventory como servicio de Windows.

.DESCRIPTION
    El equivalente en Windows de cenya-agent.service (systemd). Da por
    hecho que el agente ya está instalado con el extra [windows] en un entorno
    virtual:

        py -3.12 -m venv C:\cenya\venv
        C:\cenya\venv\Scripts\pip install "C:\ruta\al\repo\agent[completo]"

    El agente se enrola con la cadena de conexión que da Ajustes → Agentes
    (-Connection, o se pide al ejecutarlo): la canjea por su token y lo guarda
    en un almacén que solo leen SYSTEM y los administradores. Nadie ve ni copia
    ningún token. Si el equipo ya estaba enrolado, no hace falta nada de esto.

    Y deja:
      * El servicio «Cenya Agent», con arranque automático retrasado:
        espera a que la red esté lista, que es lo primero que necesita.
      * Reinicio automático si se cae: al minuto, otra vez al minuto, y luego
        cada cinco. Un token revocado o un servidor que no contesta ya no lo
        tumban (el agente reintenta solo); esto es para lo que sí.
      * El icono de bandeja, que arranca solo al iniciar sesión cualquier
        usuario de este equipo y dice de un vistazo si el agente funciona.
        Con -NoTray no se instala.

    Ejecutar desde un PowerShell de administrador. Funciona con Windows
    PowerShell 5.1, el que trae Windows.

.EXAMPLE
    .\install-service.ps1 -Connection cenya://inventario.midominio.local/K7QF-9M2X-4TQN
    (sin -Connection, y si el equipo no está enrolado, la pide)
#>
[CmdletBinding()]
param(
    # La cadena de conexión de Ajustes → Agentes. Vale una hora y una sola vez,
    # así que dejarla en el historial de PowerShell no regala nada.
    [string] $Connection,

    # Solo para un portal que cambió de dirección, o para el modo antiguo con
    # token (-Token): sin él, la URL sale de la cadena de conexión.
    [string] $Url,

    # El modo antiguo: un token ya generado. Pasarlo aquí lo deja en el
    # historial de PowerShell de esta cuenta; mejor -Connection.
    [string] $Token,

    [string] $AgentDir = "C:\cenya\venv",

    # Opcional: la CA de la empresa, si $Url es HTTPS con un certificado propio.
    [string] $CaBundle,

    # Sin icono de bandeja: para un servidor en el que nadie inicia sesión.
    [switch] $NoTray
)

$ErrorActionPreference = "Stop"
$ServiceName = "CenyaAgent"

# Los textos, traducidos al idioma de esta sesión por el propio agente que se
# instala (agent/installer_text.py): el mismo catálogo que el icono de bandeja.
# Llegan como JSON en ASCII puro, que sobrevive a la página de códigos de la
# consola. Solo este primer aviso no puede traducirse: sin agente no hay textos.
$python = Join-Path $AgentDir "Scripts\python.exe"
$messagesJson = $null
if (Test-Path $python) {
    # try: con ErrorActionPreference = Stop, Windows PowerShell 5.1 convierte lo
    # que un programa escribe en stderr (un agente antiguo sin este módulo) en
    # un error que cortaría el script antes del aviso de abajo.
    try { $messagesJson = & $python -m agent.installer_text 2>$null } catch { $messagesJson = $null }
}
if (-not $messagesJson -or $LASTEXITCODE -ne 0) {
    throw "No se encuentra el agente de NetInventory en $AgentDir (o es anterior a este script). / NetInventory agent not found in $AgentDir (or older than this script)."
}
$Messages = ($messagesJson -join "") | ConvertFrom-Json

function Msg([string] $Key, [hashtable] $Values = @{}) {
    $text = $Messages.$Key
    if ($null -eq $text) { throw "install-service.ps1: falta el texto '$Key' en agent/installer_text.py" }
    foreach ($name in $Values.Keys) { $text = $text.Replace("%($name)s", [string] $Values[$name]) }
    return $text
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw (Msg "need_admin")
}

$exe = Join-Path $AgentDir "Scripts\cenya-agent-service.exe"
if (-not (Test-Path $exe)) {
    throw (Msg "no_service_exe" @{ exe = $exe; dir = $AgentDir })
}

$enrollmentFile = Join-Path $env:ProgramData "Cenya\enrollment.json"
if ($Token) {
    if (-not $Url) { throw (Msg "no_url") }
    # Solo en este proceso: `install` los copia al servicio y no quedan como
    # variables de la máquina ni del usuario.
    $env:CENYA_URL = $Url
    $env:CENYA_AGENT_TOKEN = $Token
} else {
    if (-not $Connection -and -not (Test-Path $enrollmentFile)) {
        $Connection = Read-Host -Prompt (Msg "connection_prompt")
    }
    if ($Connection) {
        # El agente canjea el código y guarda su token donde solo lo lee el
        # servicio. Lo que escribe en stderr no debe cortar este script (en
        # Windows PowerShell 5.1 lo haría): se deja salir y se mira el código.
        $previous = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        & $python -m agent enroll $Connection --force
        $enrolled = $LASTEXITCODE
        $ErrorActionPreference = $previous
        if ($enrolled -ne 0) { throw (Msg "enroll_failed") }
    } elseif (-not (Test-Path $enrollmentFile)) {
        throw (Msg "no_enrollment")
    }
    if ($Url) { $env:CENYA_URL = $Url }
}
if ($CaBundle) { $env:CENYA_CA_BUNDLE = $CaBundle }

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne "Stopped") {
        Write-Host (Msg "stopping_to_update")
        & $exe --wait 120 stop
    }
    & $exe --startup delayed update
} else {
    & $exe --startup delayed install
}
if ($LASTEXITCODE -ne 0) { throw (Msg "install_failed" @{ code = $LASTEXITCODE }) }

Remove-Item Env:\CENYA_AGENT_TOKEN -ErrorAction SilentlyContinue

& sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Warning (Msg "restart_policy_failed") }

# El icono, para todos los usuarios que inicien sesión aquí. Es un proceso
# aparte que solo lee el estado: cerrarlo no para el agente.
$tray = Join-Path $AgentDir "Scripts\cenya-agent-tray.exe"
$runKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
if ($NoTray) {
    Remove-ItemProperty -Path $runKey -Name "Cenya Agent" -ErrorAction SilentlyContinue
} elseif (Test-Path $tray) {
    Set-ItemProperty -Path $runKey -Name "Cenya Agent" -Value "`"$tray`""
} else {
    Write-Warning (Msg "no_tray_exe" @{ tray = $tray })
}

& $exe --wait 60 start
if ($LASTEXITCODE -ne 0) {
    throw (Msg "start_failed" @{ source = $ServiceName })
}

Write-Host ""
Write-Host (Msg "installed")
Write-Host (Msg "event_log_hint" @{ source = $ServiceName })
Write-Host (Msg "manage_hint" @{ exe = $exe })
if (-not $NoTray -and (Test-Path $tray)) {
    Write-Host ""
    Write-Host (Msg "tray_hint" @{ tray = $tray })
    Write-Host (Msg "tray_overflow_hint")
}
