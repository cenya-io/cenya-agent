<#
.SYNOPSIS
    Construye el instalador de Windows del agente de Cenya.

.DESCRIPTION
    1. PyInstaller congela el agente en agent\dist\cenya-agent (cinco
       ejecutables que comparten Python y librerías; el quinto es la ventana,
       cenya-agent-app.exe, con pywebview).
    2. Baja el OpenSSH de Windows (Win32-OpenSSH, el port del equipo de
       PowerShell), comprueba su SHA-256 contra el fijado aquí abajo y deja
       `ssh.exe` con sus DLL y sus licencias en dist\cenya-agent\openssh. El
       colector SSH usa ese y no el del sistema: Windows Server 2019/2022 traen
       uno viejo o ninguno, y sin OpenSSH >= 8.4 no hay contraseña SSH.
    3. `cenya-agent selftest` comprueba que la compilación está completa: todos
       los colectores, los cinco idiomas, las librerías de Windows y el OpenSSH
       propio. Una compilación a la que le falta algo no llega al instalador.
    4. Inno Setup lo empaqueta en agent\installer\Cenya-Agent-Setup-<versión>.exe.

    Hace falta, en el Python que se use: el agente con todos sus extras y
    PyInstaller (`pip install .\agent[completo,gui] pyinstaller`), y Inno Setup 6.
    La versión sale de agent\__init__.py: es la misma que ve el servidor.

    -Unprivileged compila una variante que se instala sin ser administrador y no
    puede instalar el servicio: solo para probar la copia de ficheros, el
    enrolamiento y los códigos de salida en una máquina de desarrollo.

    -Version y -ExtraReleaseKey son SOLO para la prueba de la actualización en
    CI (smoke-test.ps1): compilan «la versión N+1» con una clave pública de
    PRUEBA, generada y tirada en la misma ejecución, que esa compilación acepta
    además de las de agent/release_keys.py. Tocan agent/__init__.py y
    agent/release_keys.py mientras dura la compilación y los dejan como
    estaban al terminar, pase lo que pase. Exigen -OutputDir: un instalador de
    prueba nunca cae en agent\installer, que es lo que se publica.

.EXAMPLE
    .\agent\packaging\build.ps1
#>
[CmdletBinding()]
param(
    [string] $Python = "python",
    [switch] $Unprivileged,
    # Un OpenSSH-Win64.zip ya descargado (compilar sin red). Se verifica igual.
    [string] $OpenSshZip = "",
    # Solo pruebas de CI: otra versión que la del código (p. ej. 0.11.0.1).
    [string] $Version = "",
    # Solo pruebas de CI: una clave pública Ed25519 de PRUEBA (base64 en una línea).
    [string] $ExtraReleaseKey = "",
    # Dónde deja Inno el instalador (por defecto agent\installer).
    [string] $OutputDir = ""
)

$ErrorActionPreference = "Stop"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

$initFile = Join-Path $repo "agent\__init__.py"
$keysFile = Join-Path $repo "agent\release_keys.py"
if (($Version -or $ExtraReleaseKey) -and -not $OutputDir) {
    throw "-Version y -ExtraReleaseKey son para pruebas: hace falta -OutputDir (nunca agent\installer)."
}
if ($Version -and $Version -notmatch '^\d{1,6}(\.\d{1,6}){1,3}$') { throw "-Version no es una versión: $Version" }
if ($ExtraReleaseKey -and $ExtraReleaseKey -notmatch '^[A-Za-z0-9+/]{43}=$') { throw "-ExtraReleaseKey no es una clave Ed25519 en base64." }
$originalInit = [IO.File]::ReadAllBytes($initFile)
$originalKeys = [IO.File]::ReadAllBytes($keysFile)
$utf8 = New-Object System.Text.UTF8Encoding($false)
if ($Version) {
    $text = [IO.File]::ReadAllText($initFile, $utf8) -replace '__version__ = "[^"]+"', ('__version__ = "' + $Version + '"')
    [IO.File]::WriteAllText($initFile, $text, $utf8)
}
if ($ExtraReleaseKey) {
    $text = [IO.File]::ReadAllText($keysFile, $utf8).Replace(
        "PUBLIC_KEYS: list[str] = [", "PUBLIC_KEYS: list[str] = [`n    `"$ExtraReleaseKey`",  # PRUEBA de CI: build.ps1 -ExtraReleaseKey")
    [IO.File]::WriteAllText($keysFile, $text, $utf8)
}
try {

$version = (Select-String -Path $initFile -Pattern '__version__ = "([^"]+)"').Matches[0].Groups[1].Value
Write-Host "Cenya Agent $version"

# La ventana sin pywebview no es una ventana: mejor no construir que publicar un
# cenya-agent-app.exe que no abre. `selftest` lo vuelve a mirar en lo construido.
& $Python -c "import webview, clr_loader, pythonnet" 2>$null
if ($LASTEXITCODE -ne 0) { throw "Falta pywebview en este Python: pip install .\agent[completo,gui] pyinstaller" }

& $Python -m PyInstaller --noconfirm --clean `
    --distpath (Join-Path $repo "agent\dist") `
    --workpath (Join-Path $repo "agent\build-pyi") `
    (Join-Path $repo "agent\packaging\cenya-agent.spec")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller falló ($LASTEXITCODE)." }

# --- El OpenSSH que viaja en el instalador --------------------------------------
# Win32-OpenSSH: el port de OpenSSH para Windows del equipo de PowerShell.
# Licencias de lo que se empaqueta, aparte de las del propio agente (Apache-2.0):
#   - OpenSSH: el conjunto de licencias de OpenSSH (BSD-2/3-Clause, ISC, dominio
#     público). Permisiva, compatible con Apache-2.0.
#   - LibreSSL libcrypto (la `libcrypto.dll` del zip): ISC / estilo OpenSSL.
#     Permisiva. Sin copyleft en la cadena (regla 7 de CLAUDE.md).
# Su LICENSE.txt y NOTICE.txt se copian junto al ejecutable.
#
# Para subir de versión: cambiar la etiqueta y el SHA-256 JUNTOS, con la
# etiqueta de https://github.com/PowerShell/Win32-OpenSSH/releases y el hash
# calculado sobre el zip descargado (el campo "digest" de la API de releases de
# GitHub lo da sin descargarlo: `gh api repos/PowerShell/Win32-OpenSSH/releases`).
$openSshTag = "10.0.0.0p2-Preview"
$openSshSha256 = "23f50f3458c4c5d0b12217c6a5ddfde0137210a30fa870e98b29827f7b43aba5"
$openSshUrl = "https://github.com/PowerShell/Win32-OpenSSH/releases/download/$openSshTag/OpenSSH-Win64.zip"
$openSshMinimum = [version]"8.4"   # SSH_ASKPASS_REQUIRE=force; ver agent/ssh.py::MIN_ASKPASS_VERSION

$cache = Join-Path $repo "agent\build-openssh"
New-Item -ItemType Directory -Force $cache | Out-Null
$zip = if ($OpenSshZip) { (Resolve-Path $OpenSshZip).Path } else { Join-Path $cache "OpenSSH-Win64-$openSshTag.zip" }
if (-not (Test-Path $zip)) {
    Write-Host "Descargando OpenSSH $openSshTag"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $previous = $ProgressPreference; $ProgressPreference = "SilentlyContinue"
    try { Invoke-WebRequest -Uri $openSshUrl -OutFile $zip -UseBasicParsing } finally { $ProgressPreference = $previous }
}
$actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash.ToLowerInvariant()
if ($actual -ne $openSshSha256) {
    # Un zip que no es el que se fijó no se desempaqueta nunca, y no se deja en la caché.
    if (-not $OpenSshZip) { Remove-Item -Force $zip }
    throw "El SHA-256 de OpenSSH no coincide (esperado $openSshSha256, recibido $actual)."
}
$extracted = Join-Path $cache "extracted"
if (Test-Path $extracted) { Remove-Item -Recurse -Force $extracted }
Expand-Archive -Path $zip -DestinationPath $extracted -Force
$sshExe = Get-ChildItem -Path $extracted -Recurse -Filter "ssh.exe" | Select-Object -First 1
if (-not $sshExe) { throw "El zip de OpenSSH no contiene ssh.exe." }
$bundle = Join-Path $repo "agent\dist\cenya-agent\openssh"
if (Test-Path $bundle) { Remove-Item -Recurse -Force $bundle }
New-Item -ItemType Directory -Force $bundle | Out-Null
# Solo el cliente: ssh.exe, las DLL que lleve a su lado y las licencias. Nada de
# sshd, scp ni los guiones de instalación del servidor.
Copy-Item $sshExe.FullName $bundle
Get-ChildItem -Path $sshExe.Directory.FullName -Filter "*.dll" | Copy-Item -Destination $bundle
foreach ($license in "LICENSE.txt", "NOTICE.txt") {
    $found = Join-Path $sshExe.Directory.FullName $license
    if (Test-Path $found) { Copy-Item $found $bundle }
}
# Que el ssh.exe del zip arranca de verdad y es lo bastante nuevo. `cmd /c` para
# que el error estándar (donde `ssh -V` escribe) no sea una excepción de PowerShell.
$banner = (& cmd.exe /d /c ('"' + (Join-Path $bundle "ssh.exe") + '" -V 2>&1') | Out-String).Trim()
if ($banner -notmatch 'OpenSSH_(?:for_Windows_)?(\d+)\.(\d+)') { throw "ssh.exe no dice su versión: $banner" }
$openSshVersion = [version]("{0}.{1}" -f $Matches[1], $Matches[2])
if ($openSshVersion -lt $openSshMinimum) { throw "OpenSSH $openSshVersion es anterior a $openSshMinimum (SSH_ASKPASS_REQUIRE)." }
Write-Host "OpenSSH empaquetado: $banner"

$cli = Join-Path $repo "agent\dist\cenya-agent\cenya-agent.exe"
$selftest = (& $cli selftest | Out-String)
$selftestExit = $LASTEXITCODE
Write-Host $selftest
if ($selftestExit -ne 0) { throw "La compilación congelada no está completa (cenya-agent selftest)." }
# Las claves de publicación que acepta esta compilación: la de prueba solo si
# se pidió. Un agente sin ninguna funciona, pero no se actualiza solo.
$keys = ($selftest | ConvertFrom-Json).release_keys
Write-Host ("Claves de publicación en esta compilación: {0} {1}" -f $keys.count, ($keys.fingerprints -join ", "))
if ($ExtraReleaseKey -and $keys.count -lt 1) { throw "La clave de prueba no llegó a la compilación." }

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
$output = if ($OutputDir) { [IO.Path]::GetFullPath($OutputDir) } else { Join-Path $repo "agent\installer" }
if ($OutputDir) { $arguments += "/O$output" }
$arguments += (Join-Path $repo "agent\packaging\cenya-agent.iss")
& $iscc @arguments
if ($LASTEXITCODE -ne 0) { throw "Inno Setup falló ($LASTEXITCODE)." }

Get-ChildItem $output -Filter "Cenya-Agent-Setup-$version*.exe" |
    ForEach-Object { Write-Host ("{0}  {1:N1} MB" -f $_.FullName, ($_.Length / 1MB)) }

}
finally {
    # El código vuelve a ser el de siempre, aunque la compilación haya fallado.
    [IO.File]::WriteAllBytes($initFile, $originalInit)
    [IO.File]::WriteAllBytes($keysFile, $originalKeys)
}
