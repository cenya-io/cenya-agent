<#
.SYNOPSIS
    Construye el instalador de Windows del agente de Cenya.

.DESCRIPTION
    1. PyInstaller congela el agente en agent\dist\cenya-agent (tres
       ejecutables que comparten Python y librerías).
    2. `cenya-agent selftest` comprueba que la compilación está completa: todos
       los colectores, los cinco idiomas y las librerías de Windows. Una
       compilación a la que le falta un módulo no llega al instalador.
    3. Inno Setup lo empaqueta en agent\installer\Cenya-Agent-Setup-<versión>.exe.

    Hace falta, en el Python que se use: el agente con todos sus extras y
    PyInstaller (`pip install .\agent[completo] pyinstaller`), y Inno Setup 6.
    La versión sale de agent\__init__.py: es la misma que ve el servidor.

    -Unprivileged compila una variante que se instala sin ser administrador y no
    puede instalar el servicio: solo para probar la copia de ficheros, el
    enrolamiento y los códigos de salida en una máquina de desarrollo.

.EXAMPLE
    .\agent\packaging\build.ps1
#>
[CmdletBinding()]
param(
    [string] $Python = "python",
    [switch] $Unprivileged
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

$version = (Select-String -Path (Join-Path $repo "agent\__init__.py") -Pattern '__version__ = "([^"]+)"').Matches[0].Groups[1].Value
Write-Host "Cenya Agent $version"

& $Python -m PyInstaller --noconfirm --clean `
    --distpath (Join-Path $repo "agent\dist") `
    --workpath (Join-Path $repo "agent\build-pyi") `
    (Join-Path $repo "agent\packaging\cenya-agent.spec")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller falló ($LASTEXITCODE)." }

$cli = Join-Path $repo "agent\dist\cenya-agent\cenya-agent.exe"
& $cli selftest
if ($LASTEXITCODE -ne 0) { throw "La compilación congelada no está completa (cenya-agent selftest)." }

$candidates = @(
    (Get-Command iscc -ErrorAction SilentlyContinue).Source,
    (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"),
    (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
    (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe")
) | Where-Object { $_ -and (Test-Path $_) }
if (-not $candidates) { throw "No se encuentra Inno Setup 6 (ISCC.exe)." }
$iscc = @($candidates)[0]

$arguments = @("/Qp", "/DAppVersion=$version", "/DSourceDir=..\dist\cenya-agent")
if ($Unprivileged) { $arguments += "/DUnprivileged=1" }
$arguments += (Join-Path $repo "agent\packaging\cenya-agent.iss")
& $iscc @arguments
if ($LASTEXITCODE -ne 0) { throw "Inno Setup falló ($LASTEXITCODE)." }

Get-ChildItem (Join-Path $repo "agent\installer") -Filter "Cenya-Agent-Setup-*.exe" |
    ForEach-Object { Write-Host ("{0}  {1:N1} MB" -f $_.FullName, ($_.Length / 1MB)) }
