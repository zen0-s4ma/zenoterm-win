# Zenoterm Remote Tabs

Zenoterm Remote Tabs es una terminal web pensada para el host actual: al arrancar detecta automáticamente el sistema operativo donde corre y construye el inventario real de terminales locales disponibles, manteniendo además targets remotos por SSH.

Esta versión añade estas capacidades principales:

- detección automática de terminales locales reales del host actual (por ejemplo PowerShell/CMD/Git Bash/WSL en Windows, o shells POSIX en Linux/macOS);
- detección automática de todas las distribuciones WSL2 instaladas;
- dos presets remotos base por SSH: uno **por contraseña** y otro **por clave pública/privada**, ambos editables;
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

Los targets locales ya no se guardan como presets estáticos en el JSON. Se detectan en cada arranque según el host actual y solo se persisten sus overrides de Zenoterm (nombre visible, comando de arranque y comandos iniciales).

Zenoterm crea automáticamente estos targets si existen en el sistema:

- Local: PowerShell 7
- Local: PowerShell 5.1
- Local: CMD
- Local: Git Bash
- Local: WSL2 Ubuntu
- Local: WSL2 Debian
- y cualquier otra distribución WSL2 detectada

### Targets remotos

Zenoterm trae de base solo dos presets remotos editables:

- `Remote: SSH Remote · User/Pass`
- `Remote: SSH Remote · Public/Private Key`

Ambos son plantillas iniciales. Desde configuración puedes cambiarles el sistema operativo target, la shell base, el comando de arranque y duplicarlos o crear más presets remotos si lo necesitas.

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

### Abrir servidor remoto por contraseña

- crea una pestaña llamada `Servidor SSH`;
- selecciona `Remote: SSH Remote · User/Pass`;
- escribe host, puerto y usuario;
- escribe la contraseña efímera;
- pulsa `Conectar`.

### Abrir servidor remoto por clave privada

- crea una pestaña llamada `Jumpbox SSH`;
- selecciona `Remote: SSH Remote · Public/Private Key`;
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
