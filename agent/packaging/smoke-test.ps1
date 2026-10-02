<#
.SYNOPSIS
    Prueba de humo del instalador: lo instala de verdad, comprueba que funciona
    y lo desinstala.

.DESCRIPTION
    DESTRUCTIVO: instala un servicio de Windows y escribe en %ProgramData% y en
    Archivos de programa. Está pensado para el runner de GitHub Actions (un
    Windows limpio y desechable, con administrador); en un equipo de verdad,
    solo si se sabe lo que se hace.

    Lo que comprueba, que es lo que ninguna prueba unitaria puede ver:
      1. El instalador en silencio termina con 0 y enrola con una cadena buena.
      2. El servicio «CenyaAgent» existe, es automático retrasado y está en marcha.
      3. El agente manda un latido autenticado con el token que recibió.
      4. El token queda protegido: ni Usuarios ni Todos pueden leerlo.
      5. La carpeta del programa está en el PATH del sistema y `cenya-agent`
         funciona en una consola nueva, sin `cd`.
      5b. El OpenSSH que lleva el instalador (`openssh\ssh.exe` y sus DLL) arranca,
         es >= 8.4, `cenya-agent selftest` lo da por bueno y, contra un servidor
         SSH de mentira en 127.0.0.1, entra con contraseñas con comillas, `%`,
         acentos y una barra final a través de `cenya-agent-askpass.exe`.
      6. Volver a ejecutar el instalador (actualización) conserva el enrolamiento,
         el servicio sigue en marcha y el PATH no se duplica. Repetirlo con una
         cadena ya gastada no lo toca: un equipo enrolado ignora /CONNECTION.
      7. La desinstalación quita el servicio, borra el token y el estado y saca
         la carpeta del PATH.
      8. Una cadena mala termina con el código 21 y sin dejar el servicio en marcha.

    Usa un servidor de mentira (ci_stub_server.py) en lugar de Cenya.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Installer,
    [int] $Port = 8765
)

$ErrorActionPreference = "Stop"
$work = Join-Path ($env:RUNNER_TEMP ?? $env:TEMP) "cenya-smoke"
New-Item -ItemType Directory -Force $work | Out-Null
$requests = Join-Path $work "stub.jsonl"
$state = Join-Path $env:ProgramData "Cenya"
$appDir = Join-Path $env:ProgramFiles "Cenya Agent"
$connection = "cenya+http://localhost:$Port/TEST-TEST-TEST"
$failures = New-Object System.Collections.Generic.List[string]

function Check($Name, [bool] $Ok, $Detail = "") {
    if ($Ok) { Write-Host "  ok   $Name" } else { Write-Host "  FAIL $Name $Detail"; $script:failures.Add($Name) }
}

# Cuántas veces está la carpeta del programa en el PATH del sistema, leído del
# registro como lo leerá una consola nueva (el de este proceso es de antes).
function PathEntries {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    return @($machine -split ";" | Where-Object { $_.Trim().TrimEnd("\") -eq $appDir }).Count
}

function Install($Arguments, $LogName) {
    $log = Join-Path $work $LogName
    $p = Start-Process -FilePath $Installer -Wait -PassThru -ArgumentList (@(
            "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", '/TASKS="!tray"', "/LOG=`"$log`"") + $Arguments)
    return $p.ExitCode
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$stub = Start-Process -FilePath "python" -PassThru -WindowStyle Hidden -ArgumentList @(
    (Join-Path $here "ci_stub_server.py"), "--port", $Port, "--log", $requests)
Start-Sleep -Seconds 2

try {
    Write-Host "1. Instalación en silencio con una cadena buena"
    $exit = Install @("/CONNECTION=$connection") "setup-1.log"
    Check "el instalador termina con 0" ($exit -eq 0) "(código $exit)"

    Write-Host "2. El servicio"
    $service = Get-Service -Name "CenyaAgent" -ErrorAction SilentlyContinue
    Check "existe el servicio CenyaAgent" ($null -ne $service)
    Check "está en marcha" ($service -and $service.Status -eq "Running") "($($service.Status))"
    $config = (& sc.exe qc CenyaAgent | Out-String)
    Check "arranque automático retrasado" ($config -match "DELAYED")
    Check "su programa es el ejecutable instalado" ($config -match [regex]::Escape("cenya-agent-service.exe"))

    Write-Host "3. El agente late con su token"
    $beat = $null
    for ($i = 0; $i -lt 45 -and -not $beat; $i++) {
        Start-Sleep -Seconds 2
        $beat = Get-Content $requests -ErrorAction SilentlyContinue |
            ForEach-Object { $_ | ConvertFrom-Json } |
            Where-Object { $_.path -eq "/api/agent/heartbeat/" -and $_.ok } | Select-Object -First 1
    }
    Check "llegó un latido autenticado" ($null -ne $beat)

    Write-Host "4. El token está protegido"
    $tokenFile = Join-Path $state "enrollment.json"
    Check "existe el almacén del token" (Test-Path $tokenFile)
    $acl = (& icacls.exe $tokenFile | Out-String)
    Check "no lo lee Usuarios ni Todos" (($acl -notmatch "Users|Usuarios|Everyone|Todos|Authenticated") ) $acl
    Check "el estado del agente existe" (Test-Path (Join-Path $state "status.json"))

    Write-Host "5. cenya-agent en una consola nueva"
    Check "la carpeta está en el PATH del sistema una vez" ((PathEntries) -eq 1) "($(PathEntries) veces)"
    $found = & cmd.exe /d /c "set `"PATH=$([Environment]::GetEnvironmentVariable('Path', 'Machine'))`" && where cenya-agent" 2>$null
    Check "una consola nueva encuentra cenya-agent" (($found | Out-String) -match [regex]::Escape((Join-Path $appDir "cenya-agent.exe"))) ($found | Out-String)

    Write-Host "5b. El OpenSSH propio y la contraseña SSH"
    $sshExe = Join-Path $appDir "openssh\ssh.exe"
    $askpassExe = Join-Path $appDir "cenya-agent-askpass.exe"
    Check "el instalador lleva openssh\ssh.exe" (Test-Path $sshExe)
    Check "y el ayudante cenya-agent-askpass.exe" (Test-Path $askpassExe)
    $banner = (& cmd.exe /d /c ('"' + $sshExe + '" -V 2>&1') | Out-String).Trim()
    Check "ssh.exe arranca y dice su versión" ($banner -match "OpenSSH_") $banner
    $selftest = (& (Join-Path $appDir "cenya-agent.exe") selftest | Out-String) | ConvertFrom-Json
    Check "selftest ve el OpenSSH empaquetado" ($selftest.ssh.bundled -eq $true) ($selftest.ssh | ConvertTo-Json -Compress)
    Check "selftest da la contraseña SSH por disponible" ($selftest.ssh.password_auth -eq $true)
    # Un inicio de sesión de verdad con los ficheros instalados. `cryptography` solo
    # lo usa el servidor de mentira de las pruebas; el agente no depende de ella.
    & python -c "import cryptography" 2>$null
    if ($LASTEXITCODE -ne 0) { & python -m pip install --quiet cryptography | Out-Null }
    $repoRoot = (Resolve-Path (Join-Path $here "..\..")).Path
    Push-Location $repoRoot
    try { & python (Join-Path $here "ci_ssh_check.py") --ssh $sshExe --askpass $askpassExe; $loginExit = $LASTEXITCODE } finally { Pop-Location }
    Check "entra con contraseña a través del ssh.exe y el askpass instalados" ($loginExit -eq 0) "(código $loginExit)"

    Write-Host "6. Actualización: no pide nada y conserva el enrolamiento"
    $exit = Install @() "setup-2.log"
    Check "la actualización termina con 0" ($exit -eq 0) "(código $exit)"
    $service = Get-Service -Name "CenyaAgent" -ErrorAction SilentlyContinue
    Check "el servicio sigue en marcha" ($service -and $service.Status -eq "Running")
    Check "el token sigue ahí" (Test-Path $tokenFile)
    Check "el PATH no se duplica" ((PathEntries) -eq 1) "($(PathEntries) veces)"

    # Un despliegue en masa repite su comando con una cadena ya gastada: un
    # equipo enrolado la ignora y su agente sigue funcionando.
    $exit = Install @("/CONNECTION=cenya+http://localhost:$Port/MALA-MALA-MALA") "setup-2b.log"
    Check "repetir el despliegue con /CONNECTION termina con 0" ($exit -eq 0) "(código $exit)"
    $service = Get-Service -Name "CenyaAgent" -ErrorAction SilentlyContinue
    Check "y el servicio sigue en marcha" ($service -and $service.Status -eq "Running")

    Write-Host "7. Desinstalación"
    $uninstaller = Join-Path $appDir "unins000.exe"
    Check "existe el desinstalador" (Test-Path $uninstaller)
    Start-Process -FilePath $uninstaller -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" -Wait
    Start-Sleep -Seconds 3
    Check "el servicio ya no existe" ($null -eq (Get-Service -Name "CenyaAgent" -ErrorAction SilentlyContinue))
    Check "el token y el estado se borraron" (-not (Test-Path $state))
    Check "la carpeta salió del PATH" ((PathEntries) -eq 0) "($(PathEntries) veces)"

    Write-Host "8. Una cadena mala"
    $exit = Install @("/CONNECTION=cenya+http://localhost:$Port/MALA-MALA-MALA") "setup-3.log"
    Check "termina con el código 21" ($exit -eq 21) "(código $exit)"
    $service = Get-Service -Name "CenyaAgent" -ErrorAction SilentlyContinue
    Check "el servicio no está en marcha sin enrolar" (-not $service -or $service.Status -ne "Running")
}
finally {
    if ($stub -and -not $stub.HasExited) { Stop-Process -Id $stub.Id -Force }
    # Dejar el runner como estaba, pase lo que pase.
    $leftover = Join-Path $appDir "unins000.exe"
    if (Test-Path $leftover) { Start-Process $leftover -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES" -Wait }
    if ($failures.Count -gt 0) {
        Get-ChildItem $work -Filter "setup-*.log" | ForEach-Object {
            Write-Host "----- $($_.Name) (últimas líneas)"
            Get-Content $_.FullName -Tail 25
        }
    }
}

if ($failures.Count -gt 0) {
    Write-Host ""
    Write-Host ("FALLÓ: " + ($failures -join "; "))
    exit 1
}
Write-Host ""
Write-Host "Todo en orden."
