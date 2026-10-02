<#
.SYNOPSIS
    Prueba de humo del instalador: lo instala de verdad, comprueba que funciona,
    lo actualiza, lo hace volver atrás y lo desinstala.

.DESCRIPTION
    DESTRUCTIVO: instala un servicio de Windows, crea y borra tareas programadas
    y escribe en %ProgramData% y en Archivos de programa. Está pensado para el
    runner de GitHub Actions (un Windows limpio y desechable, con
    administrador); en un equipo de verdad, solo si se sabe lo que se hace.

    Lo que comprueba, que es lo que ninguna prueba unitaria puede ver. Con el
    instalador que se publica (-Installer):
      1. El instalador en silencio termina con 0 y enrola con una cadena buena.
      2. El servicio «CenyaAgent» existe, es automático retrasado y está en marcha.
      3. El agente hace checkin (protocolo 2) con el token que recibió.
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
      7. La desinstalación se despide del servidor, quita el servicio, borra el
         token y el estado y saca la carpeta del PATH.
      8. Una cadena mala termina con el código 21 y sin dejar el servicio en marcha.

    Con los tres instaladores de prueba (-UpdateBase, -UpdateNext,
    -UpdateBroken: versiones N, N+1 y N+2 compiladas con la clave pública de
    PRUEBA cuya privada es -TestKey; build.ps1 -ExtraReleaseKey):
      9. Enrola con la conexión en el NOMBRE del instalador (base32), sin
         /CONNECTION, y con /CA= deja la CA copiada y anotada antes de enrolar.
     10. El servidor ofrece N+1 (manifiesto firmado con la clave de prueba): el
         agente la descarga, la verifica, lanza el instalador /UPDATE y vuelve
         como N+1 con su mismo enrolamiento; el vigilante ve la marca de sana,
         borra la copia anterior y su tarea.
     11. Un instalador manipulado (un byte cambiado) se rechaza: bad_hash en el
         checkin, nada ejecutado, nada descargado que quede, sigue en N+1.
     12. Una N+2 que nunca consigue un checkin bueno: el vigilante restaura N+1,
         la arranca, y N+1 informa update_failed y no vuelve a intentarla.
     13. Desinstalar avisa al servidor (goodbye) y no deja la tarea del vigilante.

    Usa un servidor de mentira (ci_stub_server.py) en lugar de Cenya y de GitHub.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)] [string] $Installer,
    [int] $Port = 8765,
    [string] $UpdateBase = "",
    [string] $UpdateNext = "",
    [string] $UpdateBroken = "",
    # La clave PRIVADA de prueba (PEM), la que firma los manifiestos de 10 a 12.
    [string] $TestKey = "",
    # Lo que espera el vigilante el primer checkin de la versión nueva.
    [int] $WatchdogSeconds = 90
)

$ErrorActionPreference = "Stop"
$work = Join-Path ($env:RUNNER_TEMP ?? $env:TEMP) "cenya-smoke"
New-Item -ItemType Directory -Force $work | Out-Null
$requests = Join-Path $work "stub.jsonl"
$releases = Join-Path $work "releases"
New-Item -ItemType Directory -Force $releases | Out-Null
$state = Join-Path $env:ProgramData "Cenya"
$appDir = Join-Path $env:ProgramFiles "Cenya Agent"
$connection = "cenya+http://localhost:$Port/TEST-TEST-TEST"
$watchdogTask = "Cenya Agent update watchdog"
$uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B6D2F3A1-7C54-4E0B-9A18-5E2C8D9F4A63}_is1"
$failures = New-Object System.Collections.Generic.List[string]
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = (Resolve-Path (Join-Path $here "..\..")).Path

function Check($Name, [bool] $Ok, $Detail = "") {
    if ($Ok) { Write-Host "  ok   $Name" } else { Write-Host "  FAIL $Name $Detail"; $script:failures.Add($Name) }
}

# Cuántas veces está la carpeta del programa en el PATH del sistema, leído del
# registro como lo leerá una consola nueva (el de este proceso es de antes).
function PathEntries {
    $machine = [Environment]::GetEnvironmentVariable("Path", "Machine")
    return @($machine -split ";" | Where-Object { $_.Trim().TrimEnd("\") -eq $appDir }).Count
}

function Install($Arguments, $LogName, $Exe = $Installer) {
    $log = Join-Path $work $LogName
    $p = Start-Process -FilePath $Exe -Wait -PassThru -ArgumentList (@(
            "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", '/TASKS="!tray"', "/LOG=`"$log`"") + $Arguments)
    return $p.ExitCode
}

function Uninstall {
    $uninstaller = Join-Path $appDir "unins000.exe"
    if (Test-Path $uninstaller) {
        Start-Process -FilePath $uninstaller -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART" -Wait
        Start-Sleep -Seconds 3
    }
}

# Lo que el servidor de mentira ha anotado, desde la línea `$From` (0 = todo).
function Requests([int] $From = 0) {
    return @(Get-Content $requests -ErrorAction SilentlyContinue | Select-Object -Skip $From |
        ForEach-Object { $_ | ConvertFrom-Json })
}

function Mark { return @(Get-Content $requests -ErrorAction SilentlyContinue).Count }

# Espera hasta `$Seconds` a que `$Condition` devuelva algo; devuelve lo último que devolvió.
function WaitFor([scriptblock] $Condition, [int] $Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        $found = & $Condition
        if ($found) { return $found }
        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $deadline)
    return $null
}

function Checkins([int] $From, [string] $Version = "") {
    return @(Requests $From | Where-Object { $_.path -eq "/api/agent/v2/checkin/" -and (-not $Version -or $_.version -eq $Version) })
}

function StubState($Body) {
    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:$Port/ci/state" -ContentType "application/json" `
        -Body ($Body | ConvertTo-Json -Compress -Depth 5) | Out-Null
}

function TaskExists {
    & schtasks.exe /Query /TN $watchdogTask 2>$null | Out-Null
    return $LASTEXITCODE -eq 0
}

function InstalledVersion {
    return (Get-ItemProperty -Path $uninstallKey -ErrorAction SilentlyContinue).DisplayVersion
}

# «Cenya-Agent-Setup-0.11.0.1.exe» -> «0.11.0.1»
function VersionOf($Exe) {
    if ((Split-Path -Leaf $Exe) -notmatch '^Cenya-Agent-Setup-(\d+(?:\.\d+){1,3})\.exe$') { throw "No sé qué versión es $Exe" }
    return $Matches[1]
}

$stub = Start-Process -FilePath "python" -PassThru -WindowStyle Hidden -ArgumentList @(
    (Join-Path $here "ci_stub_server.py"), "--port", $Port, "--log", $requests, "--releases", $releases)
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

    Write-Host "3. El agente hace checkin con su token"
    $beat = WaitFor { Requests | Where-Object { $_.path -in "/api/agent/v2/checkin/", "/api/agent/heartbeat/" -and $_.ok } | Select-Object -First 1 } 90
    Check "llegó un checkin autenticado" ($null -ne $beat)

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
    $mark = Mark
    Uninstall
    Check "se despide del servidor (goodbye con su token)" (@(Requests $mark | Where-Object { $_.path -eq "/api/agent/v2/goodbye/" -and $_.ok }).Count -eq 1)
    Check "el servicio ya no existe" ($null -eq (Get-Service -Name "CenyaAgent" -ErrorAction SilentlyContinue))
    Check "el token y el estado se borraron" (-not (Test-Path $state))
    Check "la carpeta salió del PATH" ((PathEntries) -eq 0) "($(PathEntries) veces)"

    Write-Host "8. Una cadena mala"
    $exit = Install @("/CONNECTION=cenya+http://localhost:$Port/MALA-MALA-MALA") "setup-3.log"
    Check "termina con el código 21" ($exit -eq 21) "(código $exit)"
    $service = Get-Service -Name "CenyaAgent" -ErrorAction SilentlyContinue
    Check "el servicio no está en marcha sin enrolar" (-not $service -or $service.Status -ne "Running")
    Uninstall

    if ($UpdateBase -and $UpdateNext -and $UpdateBroken -and $TestKey) {
        $base = VersionOf $UpdateBase
        $next = VersionOf $UpdateNext
        $broken = VersionOf $UpdateBroken
        # Lo que el servicio necesita para esta prueba, en su propio registro
        # (`cenya-agent-service install` copia las CENYA_* de quien lo instala):
        # de dónde bajar las versiones y cuánto espera el vigilante.
        $env:CENYA_RELEASES_URL = "http://127.0.0.1:$Port/releases"
        $env:CENYA_UPDATE_WATCHDOG_SECONDS = "$WatchdogSeconds"

        # Las «publicaciones» N+1 y N+2, firmadas con la clave de prueba.
        $env:CENYA_RELEASE_SIGNING_KEY = Get-Content -Raw $TestKey
        try {
            foreach ($pair in @(@($UpdateNext, $next), @($UpdateBroken, $broken))) {
                $folder = Join-Path $releases $pair[1]
                New-Item -ItemType Directory -Force $folder | Out-Null
                $copy = Join-Path $folder (Split-Path -Leaf $pair[0])
                Copy-Item $pair[0] $copy -Force
                $manifest = Join-Path $folder "latest.json"
                & python (Join-Path $here "release_key.py") manifest --version $pair[1] `
                    --base-url "http://127.0.0.1:$Port/releases/agent-v$($pair[1])" --windows $copy --out $manifest
                if ($LASTEXITCODE -ne 0) { throw "No se pudo escribir el manifiesto de $($pair[1])." }
                & python (Join-Path $here "release_key.py") sign $manifest
                if ($LASTEXITCODE -ne 0) { throw "No se pudo firmar el manifiesto de $($pair[1])." }
            }
        }
        finally { Remove-Item Env:CENYA_RELEASE_SIGNING_KEY -ErrorAction SilentlyContinue }

        Write-Host "9. La conexión en el nombre del instalador, y /CA"
        $payload = (& python -c "import base64,sys; print(base64.b32encode(sys.argv[1].encode()).decode().rstrip('=').lower())" $connection).Trim()
        $named = Join-Path $work ("Cenya-Agent-Setup-{0}_{1}.exe" -f $base, $payload)
        Copy-Item $UpdateBase $named -Force
        $ca = Join-Path $work "ci-ca.pem"
        & python (Join-Path $here "ci_stub_server.py") make-ca $ca
        $mark = Mark
        $exit = Install @("/CA=$ca") "setup-9.log" $named
        Check "el instalador con la conexión en el nombre termina con 0" ($exit -eq 0) "(código $exit)"
        Check "enroló con la cadena del nombre" (@(Requests $mark | Where-Object { $_.path -eq "/api/agent/enroll/" -and $_.ok }).Count -eq 1)
        Check "queda enrolado" (Test-Path (Join-Path $state "enrollment.json"))
        $settings = Get-Content -Raw (Join-Path $state "settings.json") -ErrorAction SilentlyContinue | ConvertFrom-Json
        Check "settings.json apunta a la CA copiada en la carpeta de estado" ($settings.ca_bundle -eq (Join-Path $state "ca.pem")) "($($settings.ca_bundle))"
        Check "la copia de la CA existe" (Test-Path (Join-Path $state "ca.pem"))
        $first = WaitFor { Checkins $mark $base | Where-Object { $_.ok } | Select-Object -First 1 } 120
        Check "la versión $base hace checkin" ($null -ne $first)

        Write-Host "10. Actualización de $base a $next, sola"
        $mark = Mark
        StubState @{ offer = @{ version = $next }; tamper = $false; refuse = @() }
        $updated = WaitFor { Checkins $mark $next | Where-Object { $_.ok } | Select-Object -First 1 } 420
        Check "vuelve como $next" ($null -ne $updated)
        # El primer checkin de la versión nueva aún dice «installing»: la marca
        # de sana se deja al recibir su respuesta.
        Check "informa update_state installing de $next" (@(Checkins $mark | Where-Object { $_.update_state.state -eq "installing" -and $_.update_state.version -eq $next }).Count -ge 1)
        Check "con el mismo enrolamiento (sus checkins siguen autenticados)" ($updated -and $updated.ok)
        Check "deja la marca de sana" (Test-Path (Join-Path $state "updates\healthy-$next"))
        $gone = WaitFor { if (-not (TaskExists)) { $true } } ($WatchdogSeconds + 120)
        Check "el vigilante se borra solo" ($gone -eq $true)
        Check "y borra la copia de la versión anterior" (-not (Test-Path (Join-Path $state "previous\app")))
        Check "Programas y características dice $next" ((InstalledVersion) -eq $next) "($(InstalledVersion))"
        $service = Get-Service -Name "CenyaAgent" -ErrorAction SilentlyContinue
        Check "el servicio está en marcha" ($service -and $service.Status -eq "Running")

        Write-Host "11. Un instalador manipulado no se ejecuta"
        $mark = Mark
        StubState @{ offer = @{ version = $broken }; tamper = $true; refuse = @() }
        $refused = WaitFor { Checkins $mark $next | Where-Object { $_.update_state.state -eq "failed" -and $_.update_state.error -eq "bad_hash" } | Select-Object -First 1 } 240
        Check "lo rechaza con bad_hash" ($null -ne $refused) ((Checkins $mark | Select-Object -Last 1) | ConvertTo-Json -Compress -Depth 5)
        Check "y no queda nada descargado" (-not (Test-Path (Join-Path $state "updates\cenya-agent-$broken.exe")))
        Check "nada se instaló: sigue siendo $next" (@(Checkins $mark $broken).Count -eq 0 -and (InstalledVersion) -eq $next)

        Write-Host "12. Una versión rota vuelve atrás sola"
        $mark = Mark
        StubState @{ offer = @{ version = $broken; explicit = $true }; tamper = $false; refuse = @($broken) }
        $tried = WaitFor { Checkins $mark $broken | Select-Object -First 1 } 420
        Check "la $broken se instala y no consigue checkin" ($tried -and -not $tried.ok)
        $back = WaitFor { Checkins $mark $next | Where-Object { $_.ok -and $_.update_state.error -eq "update_failed" -and $_.update_state.version -eq $broken } | Select-Object -First 1 } ($WatchdogSeconds + 300)
        Check "el vigilante vuelve a $next, que informa update_failed" ($null -ne $back)
        Check "queda la marca de la versión que falló" (Test-Path (Join-Path $state "updates\failed-$broken"))
        Check "Programas y características vuelve a decir $next" ((InstalledVersion) -eq $next) "($(InstalledVersion))"
        $gone = WaitFor { if (-not (TaskExists)) { $true } } 60
        Check "el vigilante se borra" ($gone -eq $true)
        if ($back) {
            $after = Mark
            Start-Sleep -Seconds 60
            Check "y no lo vuelve a intentar" (@(Checkins $after $broken).Count -eq 0 -and @(Checkins $after $next | Where-Object { $_.update_state.state -in "downloading", "ready", "installing" }).Count -eq 0)
        }

        Write-Host "13. Desinstalar se despide"
        $mark = Mark
        Uninstall
        Check "goodbye llega al servidor" (@(Requests $mark | Where-Object { $_.path -eq "/api/agent/v2/goodbye/" -and $_.ok }).Count -eq 1)
        Check "el servicio ya no existe" ($null -eq (Get-Service -Name "CenyaAgent" -ErrorAction SilentlyContinue))
        Check "ni la tarea del vigilante" (-not (TaskExists))
        Check "ni la carpeta de estado" (-not (Test-Path $state))
    }
    else {
        Write-Host "(sin instaladores de prueba: no se prueban la actualización ni la vuelta atrás)"
    }
}
finally {
    if ($stub -and -not $stub.HasExited) { Stop-Process -Id $stub.Id -Force }
    Remove-Item Env:CENYA_RELEASES_URL, Env:CENYA_UPDATE_WATCHDOG_SECONDS -ErrorAction SilentlyContinue
    # Dejar el runner como estaba, pase lo que pase.
    $leftover = Join-Path $appDir "unins000.exe"
    if (Test-Path $leftover) { Start-Process $leftover -ArgumentList "/VERYSILENT", "/SUPPRESSMSGBOXES" -Wait }
    & schtasks.exe /Delete /TN $watchdogTask /F 2>$null | Out-Null
    if ($failures.Count -gt 0) {
        Get-ChildItem $work -Filter "setup-*.log" | ForEach-Object {
            Write-Host "----- $($_.Name) (últimas líneas)"
            Get-Content $_.FullName -Tail 25
        }
        foreach ($extra in (Join-Path $state "previous\watchdog.log"), $requests) {
            if (Test-Path $extra) { Write-Host "----- $extra"; Get-Content $extra -Tail 40 }
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
