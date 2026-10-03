<#
.SYNOPSIS
    La prueba de humo del instalador (smoke-test.ps1), en este equipo y sin
    tocarlo: dentro de Windows Sandbox.

.DESCRIPTION
    smoke-test.ps1 es destructivo (instala un servicio, tareas programadas,
    escribe en %ProgramData%) y por eso solo corría en el runner de GitHub: una
    vuelta de más de diez minutos por cada fallo del instalador. Esto hace lo
    mismo en un Windows limpio y desechable que arranca en segundos:

      1. Construye aquí el instalador (y, con -Update, los tres de prueba N,
         N+1 y N+2 con una clave de PRUEBA que nace y muere en esta ejecución).
      2. Abre Windows Sandbox con el repositorio, Python y PowerShell 7 de este
         equipo montados en SOLO LECTURA, y una carpeta de salida.
      3. Dentro corre smoke-test.ps1; al terminar, el Sandbox se cierra.
      4. Enseña el registro y termina con el código de la prueba.

    Nada de fuera del Sandbox se instala ni se modifica: ni el servicio, ni
    %ProgramData%\Cenya, ni el Programador de tareas de este equipo.

    Hace falta: Windows Sandbox activado («Espacio aislado de Windows» en
    Características de Windows), PowerShell 7, y lo mismo que build.ps1.
    Solo puede haber un Sandbox abierto a la vez.

.EXAMPLE
    .\agent\packaging\sandbox-test.ps1 -Python ..\cenya-agent-gui\.venv-gui\Scripts\python.exe
    .\agent\packaging\sandbox-test.ps1 -SkipBuild            # repite la prueba con lo ya construido
    .\agent\packaging\sandbox-test.ps1 -Update               # también actualización y vuelta atrás
#>
[CmdletBinding()]
param(
    # El Python con que se construye (pywebview y PyInstaller instalados).
    [string] $Python = "python",
    # No reconstruir: probar los instaladores de la vez anterior.
    [switch] $SkipBuild,
    # También los pasos 9 a 13 (tres compilaciones más).
    [switch] $Update,
    [int] $TimeoutMinutes = 30,
    # Dejar el Sandbox abierto al terminar, para mirar dentro.
    [switch] $KeepOpen
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$work = Join-Path $repo ".sandbox"
$installers = Join-Path $work "installers"
$out = Join-Path $work "out"
$pylibs = Join-Path $work "pylibs"
$keys = Join-Path $work "keys"

$sandboxExe = Join-Path $env:SystemRoot "System32\WindowsSandbox.exe"
if (-not (Test-Path $sandboxExe)) { throw "Windows Sandbox no está activado en este equipo." }
if (-not (Get-Command wsb -ErrorAction SilentlyContinue)) { throw "Falta la CLI de Windows Sandbox (wsb.exe, Windows 11 24H2)." }
if ((& wsb list | Out-String).Trim()) {
    throw "Ya hay un Windows Sandbox abierto: ciérralo antes."
}
$pwshDir = Split-Path -Parent (Get-Command pwsh).Source
# El Python de base (no el del entorno virtual): es el que se monta dentro.
$pythonHome = (& $Python -c "import sys; print(sys.base_prefix)").Trim()
if (-not (Test-Path (Join-Path $pythonHome "python.exe"))) { throw "No encuentro python.exe en $pythonHome" }

New-Item -ItemType Directory -Force $installers, $out, $pylibs, $keys | Out-Null
$version = (Select-String -Path (Join-Path $repo "agent\__init__.py") -Pattern '__version__ = "(.+)"').Matches[0].Groups[1].Value

if (-not $SkipBuild) {
    Get-ChildItem $installers -Filter "*.exe" | Remove-Item -Force
    $build = Join-Path $PSScriptRoot "build.ps1"
    # Con -OutputDir: agent\installer es solo para el que se publica.
    if ($Update) {
        & $Python (Join-Path $PSScriptRoot "release_key.py") generate --private-out "$keys\private.pem" --public-out "$keys\public.txt"
        if ($LASTEXITCODE -ne 0) { throw "No se pudo generar la clave de prueba." }
        $public = (Get-Content "$keys\public.txt").Trim()
        foreach ($v in @($version, "$version.1", "$version.2")) {
            & $build -Python $Python -ExtraReleaseKey $public -OutputDir $installers -Version $v
        }
    }
    else {
        & $build -Python $Python -OutputDir $installers -Version $version
    }
}
if (-not (Test-Path (Join-Path $installers "Cenya-Agent-Setup-$version.exe"))) {
    throw "No hay instalador de $version en $installers (¿-SkipBuild sin haber construido?)."
}
$hasTrio = (Test-Path "$installers\Cenya-Agent-Setup-$version.1.exe") -and (Test-Path "$installers\Cenya-Agent-Setup-$version.2.exe") -and (Test-Path "$keys\private.pem")
if ($Update -and -not $hasTrio) { throw "Faltan los instaladores de prueba de la actualización." }

# Lo que los guiones de la prueba importan y el Python de base no trae.
if (-not (Test-Path (Join-Path $pylibs "cryptography"))) {
    & (Join-Path $pythonHome "python.exe") -m pip install --quiet --target $pylibs "cryptography>=42"
    if ($LASTEXITCODE -ne 0) { throw "No se pudo preparar cryptography para el Sandbox." }
}

Get-ChildItem $out -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
$updateArgs = ""
if ($Update) {
    Copy-Item "$keys\private.pem" (Join-Path $out "test-key.pem")
    $updateArgs = " -UpdateBase 'C:\cenya\installers\Cenya-Agent-Setup-$version.exe' -UpdateNext 'C:\cenya\installers\Cenya-Agent-Setup-$version.1.exe' -UpdateBroken 'C:\cenya\installers\Cenya-Agent-Setup-$version.2.exe' -TestKey 'C:\cenya\out\test-key.pem'"
}
# El Sandbox no trae WebView2: es justo el equipo en el que el instalador
# tiene que ponerlo él (con la red del Sandbox), y la prueba lo comprueba.
@"
`$env:PATH = "C:\cenya\python;C:\cenya\pwsh;`$env:PATH"
`$env:PYTHONPATH = "C:\cenya\pylibs"
`$env:PYTHONDONTWRITEBYTECODE = "1"
`$code = 99
try {
    & C:\cenya\repo\agent\packaging\smoke-test.ps1 -Installer 'C:\cenya\installers\Cenya-Agent-Setup-$version.exe'$updateArgs *>&1 |
        Tee-Object -FilePath C:\cenya\out\smoke.log
    `$code = `$LASTEXITCODE
}
catch { "ERROR: `$_" | Add-Content C:\cenya\out\smoke.log }
finally {
    Set-Content C:\cenya\out\exit.txt `$code
}
"@ | Set-Content (Join-Path $out "run.ps1") -Encoding utf8

# Con la CLI (`wsb`), no con un fichero .wsb: en Windows 11 24H2 el Sandbox
# abierto con un .wsb arrancaba sin las carpetas montadas y sin decir nada.
Write-Host "Abriendo Windows Sandbox (Cenya Agent $version$(if ($Update) { ', con actualización' }))..."
$started = Get-Date
$id = ((& wsb start --raw | Out-String | ConvertFrom-Json).Id)
if (-not $id) { throw "wsb start no devolvió un identificador." }
function Share($HostFolder, $Name, [switch] $Write) {
    $arguments = @("share", "--id", $id, "-f", $HostFolder, "-s", "C:\cenya\$Name")
    if ($Write) { $arguments += "--allow-write" }
    & wsb @arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "No se pudo montar $HostFolder en el Sandbox." }
}
Share $repo "repo"
Share $installers "installers"
Share $pylibs "pylibs"
Share $pythonHome "python"
Share $pwshDir "pwsh"
Share $out "out" -Write
# La sesión de usuario (la ventana): la prueba abre la aplicación de verdad.
# `wsb connect` no vuelve hasta que se cierra la ventana, así que va aparte.
Start-Process wsb -ArgumentList "connect", "--id", $id
$session = $false
foreach ($attempt in 1..60) {
    & wsb exec --id $id -r ExistingLogin -c "cmd /c exit 0" | Out-Null
    if ($LASTEXITCODE -eq 0) { $session = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $session) { & wsb stop --id $id | Out-Null; throw "La sesión del Sandbox no llegó a abrirse." }
# `wsb exec` tampoco vuelve hasta que acaba la prueba: aparte, y aquí se espera exit.txt.
Start-Process wsb -WindowStyle Hidden -ArgumentList "exec", "--id", $id, "-r", "ExistingLogin", "-c",
    "`"C:\cenya\pwsh\pwsh.exe -NoProfile -ExecutionPolicy Bypass -File C:\cenya\out\run.ps1`""
$exitFile = Join-Path $out "exit.txt"
$deadline = $started.AddMinutes($TimeoutMinutes)
while (-not (Test-Path $exitFile) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 5 }

$log = Join-Path $out "smoke.log"
if (Test-Path $log) { Get-Content $log }
if (-not (Test-Path $exitFile)) {
    Write-Host "La prueba no terminó en $TimeoutMinutes minutos. El Sandbox sigue abierto para mirar dentro."
    exit 98
}
$code = [int](Get-Content $exitFile | Select-Object -First 1)
if (-not $KeepOpen) { & wsb stop --id $id | Out-Null }
Write-Host ("Prueba terminada en {0:n1} min con código {1}. Registro: {2}" -f ((Get-Date) - $started).TotalMinutes, $code, $log)
exit $code
