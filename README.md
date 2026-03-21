# Zenoterm Remote Tabs

Zenoterm Remote Tabs es una terminal web para Windows con pestañas múltiples, targets locales y remotos, autenticación simple de acceso al panel y soporte para shells locales y sesiones SSH interactivas.

Esta versión añade estas capacidades principales:

- targets locales por defecto para PowerShell moderna, PowerShell 5.1, CMD, Git Bash y WSL2;
- detección automática de todas las distribuciones WSL2 instaladas;
- targets remotos por SSH **por contraseña** y **por clave pública/privada** para cada familia de shell local detectada;
- pestañas con nombre libre;
- credenciales SSH introducidas en la propia web por pestaña;
- columna izquierda desplazable para que siempre se vean las secciones inferiores;
- estado detallado de la pestaña activa.

## Qué hace

La aplicación levanta un servidor web local en Windows y expone una interfaz con una o varias terminales dentro del navegador. Cada pestaña puede conectarse a:

- una shell local del propio equipo donde corre Zenoterm;
- un host remoto por SSH usando usuario/contraseña;
- un host remoto por SSH usando clave privada.

La sesión interactiva viaja en tiempo real por WebSocket. Las pestañas mantienen su propio buffer, su propio scrollback y su propio contexto de conexión.

## Arquitectura resumida

### Backend (`app.py`)

El backend hace estas funciones:

- carga la configuración desde `zenoterm.config.json`;
- detecta shells Windows disponibles;
- detecta distribuciones WSL2 con `wsl.exe -l -q`;
- genera la lista de targets por defecto;
- autentica el acceso a la web con cookie de sesión;
- abre sesiones locales con `pywinpty`;
- abre sesiones SSH interactivas con `paramiko`;
- multiplexa la entrada y salida de cada pestaña mediante WebSockets.

### Frontend (`web/`)

La web se divide en:

- `index.html`: estructura principal de la interfaz;
- `style.css`: tema visual corinto / rojo oscuro y layout;
- `app.js`: lógica de pestañas, formularios de credenciales, conexión por WebSocket y acciones de UI.

## Targets por defecto

### Targets locales

Zenoterm crea automáticamente estos targets si existen en el sistema:

- Local: PowerShell 7
- Local: PowerShell 5.1
- Local: CMD
- Local: Git Bash
- Local: WSL2 Ubuntu
- Local: WSL2 Debian
- y cualquier otra distribución WSL2 detectada

### Targets remotos

Para **cada shell local detectada**, Zenoterm crea automáticamente dos targets remotos:

- `Remote SSH User/Pass: <shell>`
- `Remote SSH Public/Private key: <shell>`

Esos targets no llevan host ni usuario cerrados. Se rellenan en la propia web, en la pestaña activa.

## Cómo está montado el modo remoto

Los targets remotos funcionan como plantillas de conexión:

- eliges el target que representa la shell remota que quieres abrir;
- introduces host, puerto y usuario en la web;
- introduces contraseña o ruta de clave privada y passphrase, según el modo;
- el backend abre la conexión SSH y, una vez dentro, lanza el comando de shell asociado al target.

Ejemplos de comandos remotos asociados:

- `pwsh`
- `powershell.exe`
- `cmd.exe`
- `bash`
- `wsl.exe -d <distro>`

Eso significa que el target remoto tiene sentido si el host SSH realmente dispone de esa shell.

## Estructura del proyecto

```text
zenoterm-win/
├─ app.py
├─ README.md
├─ GUIA_CONFIGURACION.md
├─ GUIA_USO.md
├─ requirements.txt
├─ zenoterm.config.json
├─ known_hosts
└─ web/
   ├─ index.html
   ├─ app.js
   └─ style.css
```

## Ficheros de configuración

### `zenoterm.config.json`

Controla:

- título de la aplicación;
- host y puerto del servidor web;
- apertura automática del navegador;
- autenticación de acceso al panel;
- valores por defecto para conexiones remotas.

### `known_hosts`

Se usa cuando `strict_host_key` está activado para conexiones SSH. Debe contener las claves públicas de los hosts remotos conocidos.

### `requirements.txt`

Contiene las dependencias Python del proyecto.

## Uso rápido

1. Instala dependencias.
2. Ejecuta `python app.py`.
3. Haz login.
4. Crea una pestaña con nombre propio.
5. Elige el target.
6. Si es remoto, rellena host, puerto, usuario y credenciales.
7. Pulsa **Conectar**.

## Ejemplos reales

### Abrir PowerShell 7 local

- crea una pestaña llamada `Local PS7`;
- selecciona `Local: PowerShell 7`;
- pulsa `Conectar`.

### Abrir Ubuntu WSL local

- crea una pestaña llamada `Ubuntu WSL`;
- selecciona `Local: WSL2 Ubuntu`;
- pulsa `Conectar`.

### Abrir servidor Windows remoto con PowerShell 5.1 por contraseña

- crea una pestaña llamada `WinSrv PS5`;
- selecciona `Remote SSH User/Pass: PowerShell 5.1`;
- escribe host, puerto y usuario;
- escribe la contraseña efímera;
- pulsa `Conectar`.

### Abrir servidor remoto por clave privada con CMD

- crea una pestaña llamada `Jumpbox CMD`;
- selecciona `Remote SSH Public/Private key: CMD`;
- rellena host, puerto y usuario;
- escribe la ruta local de la clave privada;
- añade passphrase si aplica;
- pulsa `Conectar`.

## Acciones sobre la pestaña activa

La barra izquierda permite:

- reconectar la sesión;
- limpiar el contenido visible;
- copiar todo el buffer al portapapeles;
- guardar la salida a un fichero local;
- ver estado y parámetros de la conexión activa.

## Notas importantes

- Las contraseñas y passphrases no se guardan en disco.
- La ruta de la clave privada puede venir del target o escribirse manualmente en cada pestaña.
- Si un target remoto lanza una shell que no existe en el host SSH, la conexión SSH abrirá pero el cambio a esa shell fallará dentro de la sesión.
- Los targets WSL aparecen solo si Zenoterm detecta distribuciones instaladas en ese sistema Windows.

## Arranque

```powershell
python -m pip install -r requirements.txt
python app.py
```
