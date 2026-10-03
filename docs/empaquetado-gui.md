# Empaquetado de la aplicación de escritorio (Cenya Agent)

> **Hecho (02-10-2026, integración en `agent-v2-next`).** Lo que sigue era la
> lista de lo que faltaba; está en `agent/packaging/` (spec, `entry_app.py`,
> `.iss`, `build.ps1`, `smoke-test.ps1` sección 5c) y lo guardan
> `agent/tests/test_installer_packaging.py`. Las traducciones de la ventana ya
> están en los catálogos del agente. Dos cambios sobre esta nota: el cliente del
> canal es uno solo, `agent/localclient.py` (`agent/app/channel.py` ya no
> existe), y un equipo sin enrolar ya no tiene el servicio parado.

Lo que el spec de PyInstaller (`agent/packaging/cenya-agent.spec`) y el
instalador (`agent/packaging/cenya-agent.iss`) tienen que añadir para la
ventana `agent/app`. No se ha tocado `agent/packaging/` desde esta rama: lo
lleva otra persona en paralelo. Mientras no se haga, falla a propósito
`test_installer_packaging.PackagingAgreesWithTheCodeTests.test_the_spec_builds_exactly_the_executables_the_package_declares`
(el paquete declara `cenya-agent-app` y el spec no lo construye).

## 1. Dependencias del entorno de construcción

`pip install ./agent[completo] pyinstaller` ya trae `pywebview` (el extra
`completo` lo incluye, solo en Windows). Licencias revisadas, todas
permisivas: ver el comentario del extra `gui` en `agent/pyproject.toml`.

## 2. Spec de PyInstaller

1. **Punto de entrada nuevo**, `agent/packaging/entry_app.py`, igual que los demás:

   ```python
   from agent.app.main import main

   if __name__ == "__main__":
       main()
   ```

   y añadirlo a `test_every_entry_point_script_exists_and_calls_the_real_main`
   (`"entry_app.py": "agent.app.main"`).

2. **Un `Analysis` más** y su entrada en `MERGE`:

   ```python
   a_app = Analysis([str(PACKAGING / "entry_app.py")], **common)
   MERGE(..., (a_app, "cenya-agent-app", "cenya-agent-app"))
   ```

3. **Un `EXE` sin consola** (`console=False`), con el mismo `ICON`,
   `name="cenya-agent-app"`, y sus `binaries`/`datas` en `COLLECT`.

4. **Datos** (en `common["datas"]`):

   - la página: `(str(AGENT / "app" / "ui"), "agent/app/ui")` -- la lee
     `agent/app/main.py::build_page` de al lado del módulo; sin ella la ventana
     no arranca. Lleva `LUCIDE-LICENSE.txt` (licencia ISC de los iconos), que
     tiene que viajar con ellos.
   - lo de pywebview: `collect_data_files("webview")` -- su JavaScript propio
     (`webview/js/*.js`) y, sobre todo, `webview/lib/*`:
     `Microsoft.Web.WebView2.Core.dll`, `Microsoft.Web.WebView2.WinForms.dll`,
     `WebBrowserInterop.x64.dll` / `.x86.dll` y
     `runtimes/win-x64/native/WebView2Loader.dll` (y `win-arm64`, `win-x86`
     si se construye para esas). Puede excluirse `pywebview-android.jar`.
   - pythonnet: `collect_data_files("pythonnet")` (trae `runtime/Python.Runtime.dll`)
     y `collect_data_files("clr_loader")` (sus `ffi/dlls/*/ClrLoader.dll`).

   Lo más seguro es `collect_all("webview")`, `collect_all("pythonnet")` y
   `collect_all("clr_loader")` y sumar sus datas, binaries y hiddenimports.

5. **Hidden imports** (además de los de hoy):

   ```
   "agent.app", "agent.app.main", "agent.app.bridge", "agent.app.channel",
   "agent.app.view", "agent.app.strings", "agent.app.winsys",
   "webview", "webview.platforms.winforms", "webview.platforms.edgechromium",
   "clr", "clr_loader", "pythonnet", "proxy_tools", "bottle",
   "win32file", "win32pipe", "win32event", "win32security", "win32clipboard",
   "win32process", "winerror", "pywintypes"
   ```

   `bottle` se importa al cargar pywebview aunque la ventana nunca arranque su
   servidor (ver más abajo); si falta, `import webview` falla.

6. **El icono también usa `agent.app`**: `agent/tray.py` importa
   `agent.app.channel`, `agent.app.view` y `agent.app.winsys` (puro Python,
   sin pywebview). Ya los recoge el análisis de `entry_tray.py`; no hace falta
   pywebview en el ejecutable del icono, pero comparte librerías por `MERGE`.

7. **`excludes`**: `unittest.mock` sigue fuera; la aplicación no lo usa.

## 3. Instalador (Inno Setup)

1. **Copiar `cenya-agent-app.exe`** (va en la carpeta de PyInstaller; con
   `Source: {#SourceDir}\*` ya entra) y añadirlo a
   `test_the_installer_ships_every_executable_and_the_tray_starts_at_logon`.

2. **Acceso directo en el menú Inicio**: «Cenya Agent» →
   `{app}\cenya-agent-app.exe`, con el AppUserModelID
   `Cenya.Agent.App` (`AppUserModelID: "Cenya.Agent.App"` en `[Icons]`), el
   mismo que pone la ventana al arrancar, para que el acceso directo y la
   ventana se agrupen en la barra de tareas.

3. **Comprobar WebView2.** Windows 11 y Windows 10 actualizado lo traen; un
   Windows Server 2016/2019 o un Windows 10 LTSC puede no tenerlo. Detección,
   la misma que `agent/app/winsys.py::webview2_version`: valor `pv` (no vacío
   ni `0.0.0.0`) en cualquiera de

   ```
   HKLM\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}
   HKLM\SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}
   HKCU\Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}
   ```

   Si falta, **no se para la instalación** (el servicio no lo necesita):
   avisar en la página final de que la ventana necesita «Microsoft Edge
   WebView2 Runtime» y cómo conseguirlo, u ofrecer instalar el
   *Evergreen Bootstrapper* de Microsoft (`MicrosoftEdgeWebview2Setup.exe
   /silent /install`) si se decide llevarlo dentro (es redistribuible bajo
   la licencia de Microsoft; revisar antes de incluirlo). La ventana, si se
   abre sin WebView2, lo dice con un mensaje nativo y sale (código 3).

4. **Icono de bandeja**: sigue igual (`HKLM\...\Run`, valor «Cenya Agent»).
   La ventana enciende y apaga esa entrada desde Ajustes como el
   Administrador de tareas, en
   `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run`
   (valor «Cenya Agent», `02…` activa, `03…` desactivada). Al desinstalar
   conviene borrar también ese valor si existe.

5. **Desinstalar**: además de `taskkill /im cenya-agent-tray.exe`, cerrar
   `cenya-agent-app.exe` (`taskkill /im cenya-agent-app.exe /f`) antes de
   borrar la carpeta.

6. **Prueba de humo** (`smoke-test.ps1`): basta con comprobar que
   `cenya-agent-app.exe` existe y que `cenya-agent.exe selftest` sigue
   saliendo completo. Arrancar la ventana necesita un escritorio; en CI se
   puede arrancar con `CENYA_PIPE_NAME` apuntando a un nombre que no existe y
   comprobar que sigue viva unos segundos (enseña «el servicio no está en
   marcha»).

## 4. Lo que no puede cambiar al empaquetar

- **Ningún puerto.** La página se entrega a WebView2 como cadena (`html=`) con
  el CSS y el JS dentro; nada se sirve por HTTP. pywebview solo arrancaría su
  servidor `bottle` con `url=` a un fichero local o `http_server=True`, y la
  ventana no usa ninguno de los dos (`agent/app/main.py::assert_no_server` lo
  vigila al abrirse, y `agent/tests/test_app_gui.py` en la batería).
  Comprobado a mano: con la ventana abierta, el proceso no tiene ningún socket
  TCP ni UDP (`Get-NetTCPConnection` / `Get-NetUDPEndpoint -OwningProcess`).
- **Sin CDN.** La página lleva una política de contenido que no deja cargar
  nada de fuera (`default-src 'none'`, `connect-src 'none'`).
- **El canal**: la ventana y el icono hablan con el servicio por
  `\\.\pipe\CenyaAgent`; `CENYA_PIPE_NAME` lo cambia (desarrollo). Ninguna
  variable de ese tipo debe quedar puesta en una instalación real.
