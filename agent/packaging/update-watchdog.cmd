@echo off
rem Vigilante de una actualizacion del agente de Cenya (docs/agente-v2-instalacion.md, 4).
rem
rem Lo deja el instalador en modo /UPDATE, ANTES de sustituir nada, en
rem %ProgramData%\Cenya\previous\, junto a la copia de la version anterior
rem (previous\app). Lo lanza una tarea programada de un solo uso, como SYSTEM,
rem al registrarse y en cada arranque del equipo (por si se reinicia en mitad):
rem
rem   update-watchdog.cmd "<carpeta del programa>" <version anterior> <version nueva> <segundos>
rem
rem 1. Espera a que el instalador termine (la marca previous\installing; como
rem    mucho 15 minutos: un instalador matado la deja puesta).
rem 2. Espera hasta <segundos> a la marca updates\healthy-<version nueva>, que el
rem    agente nuevo escribe tras su primer checkin correcto.
rem 3. Si llega: borra la copia anterior y la tarea. Si no: para el servicio,
rem    restaura la copia anterior encima de la carpeta del programa, deja
rem    updates\failed-<version nueva> (el agente restaurado lo informa y no
rem    vuelve a intentar esa version), arranca el servicio y borra la tarea.
rem
rem Todo es repetible: si el equipo se apaga a mitad, la tarea sigue ahi y al
rem arrancar se hace otra vez lo mismo. La tarea solo se borra al final.
rem Es un .cmd y no PowerShell a proposito: la politica de ejecucion de una
rem empresa (AllSigned) no lo bloquea. Sin acentos: cmd lee en la pagina OEM.

setlocal EnableExtensions DisableDelayedExpansion
set "PREV=%~dp0"
set "PREV=%PREV:~0,-1%"
for %%I in ("%PREV%\..") do set "STATE=%%~fI"
set "APPDIR=%~1"
set "FROM=%~2"
set "TO=%~3"
set "LIMIT=%~4"
set "TASK=Cenya Agent update watchdog"
set "LOG=%PREV%\watchdog.log"
set "MARKERS=%STATE%\updates"
set "UNINSTALL_KEY=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{B6D2F3A1-7C54-4E0B-9A18-5E2C8D9F4A63}_is1"

if "%APPDIR%"=="" goto :eof
if "%TO%"=="" goto :eof
rem Lo que no es un numero vale 0, y 0 son los diez minutos de siempre.
set /a LIMIT=LIMIT+0 >nul 2>&1
if %LIMIT% LSS 60 set "LIMIT=600"
>>"%LOG%" echo %DATE% %TIME% vigilante: %FROM% a %TO%, %LIMIT% s, %APPDIR%

set /a WAITED=0
:installer
if not exist "%PREV%\installing" goto poll_start
if %WAITED% GEQ 900 goto poll_start
call :sleep
set /a WAITED+=10
goto installer

:poll_start
set /a WAITED=0
:poll
if exist "%MARKERS%\healthy-%TO%" goto healthy
if %WAITED% GEQ %LIMIT% goto rollback
call :sleep
set /a WAITED+=10
goto poll

:healthy
>>"%LOG%" echo %DATE% %TIME% %TO% ha conectado: se queda.
if exist "%PREV%\app" rmdir /s /q "%PREV%\app"
schtasks /Delete /TN "%TASK%" /F >nul 2>&1
goto :eof

:rollback
if not exist "%PREV%\app\cenya-agent.exe" goto no_backup
>>"%LOG%" echo %DATE% %TIME% %TO% no ha conectado: se restaura %FROM%.
taskkill /f /im cenya-agent-tray.exe >nul 2>&1
net stop CenyaAgent >nul 2>&1
taskkill /f /im cenya-agent-service.exe >nul 2>&1
taskkill /f /im cenya-agent.exe >nul 2>&1
robocopy "%PREV%\app" "%APPDIR%" /MIR /R:5 /W:5 /NP /NFL /NDL /NJH /NJS >>"%LOG%" 2>&1
if errorlevel 8 goto restore_failed
if not exist "%MARKERS%" mkdir "%MARKERS%"
type nul >"%MARKERS%\failed-%TO%"
echo %FROM%| findstr /r /x "[0-9][0-9.]*" >nul && reg add "%UNINSTALL_KEY%" /v DisplayVersion /t REG_SZ /d "%FROM%" /f /reg:64 >nul 2>&1
net start CenyaAgent >nul 2>&1
>>"%LOG%" echo %DATE% %TIME% %FROM% restaurada y arrancada.
rmdir /s /q "%PREV%\app"
schtasks /Delete /TN "%TASK%" /F >nul 2>&1
goto :eof

:restore_failed
rem Ficheros bloqueados o disco lleno: se arranca lo que haya y la tarea se
rem queda, para volver a intentarlo en el proximo arranque del equipo.
>>"%LOG%" echo %DATE% %TIME% la restauracion ha fallado; se reintentara al arrancar.
if not exist "%MARKERS%" mkdir "%MARKERS%"
type nul >"%MARKERS%\failed-%TO%"
net start CenyaAgent >nul 2>&1
goto :eof

:no_backup
rem Sin copia anterior no hay nada que restaurar: que al menos corra el agente.
>>"%LOG%" echo %DATE% %TIME% no hay copia anterior; se arranca el servicio.
net start CenyaAgent >nul 2>&1
schtasks /Delete /TN "%TASK%" /F >nul 2>&1
goto :eof

:sleep
rem `timeout` no funciona sin consola (una tarea programada): ping espera 10 s.
ping -n 11 127.0.0.1 >nul 2>&1
goto :eof
