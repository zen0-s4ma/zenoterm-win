# Guía de configuración

## 1. `zenoterm.config.json`

Este fichero es el único fichero de configuración obligatorio del proyecto.

### `app.title`
Nombre visible de la aplicación en la UI y en algunos mensajes del backend.

### `server.host`
Host de escucha del servidor web.

- `127.0.0.1`: solo acceso local.
- `0.0.0.0`: acceso desde red local o remoto.

### `server.port`
Puerto preferido.

### `server.open_browser`
Si vale `true`, Zenoterm abre el navegador automáticamente al arrancar.

### `server.auto_port_if_busy`
Si el puerto elegido ya está ocupado, Zenoterm busca otro libre.

### `auth.mode`
Modo de autenticación del panel.

- `password`: requiere contraseña para entrar en la web.
- `none`: sin login.

### `auth.app_password`
Contraseña del panel cuando `auth.mode` es `password`.

### `auth.session_secret`
Secreto usado para firmar la cookie de sesión.

### `auth.session_ttl_seconds`
Duración máxima de la sesión web autenticada.

### `remote_defaults.host`
Host por defecto sugerido en los targets remotos. Puede dejarse vacío.

### `remote_defaults.port`
Puerto SSH por defecto.

### `remote_defaults.username`
Usuario SSH por defecto sugerido en la web. Puede dejarse vacío.

### `remote_defaults.private_key_path`
Ruta por defecto sugerida para targets `ssh_key`. Puede dejarse vacía.

### `remote_defaults.strict_host_key`
Si vale `true`, Zenoterm exige que el host remoto exista en `known_hosts`.

## 2. `known_hosts`

Zenoterm lo usa para validación estricta de host keys SSH.

Si `strict_host_key` está activado y el host no existe en este fichero, la conexión remota fallará.

## 3. `requirements.txt`

Dependencias del proyecto:

- `fastapi`
- `uvicorn[standard]`
- `pywinpty`
- `paramiko`

## 4. Targets generados automáticamente

No se escriben manualmente en el JSON actual. El backend los genera en tiempo de arranque con estas reglas:

### Locales

- PowerShell moderna (`pwsh`) si existe
- PowerShell 5.1 (`powershell.exe`) si existe
- CMD si existe
- Git Bash si existe
- todas las distros WSL2 detectadas

### Remotos

Para cada shell local detectada, se crean:

- un target `Remote SSH User/Pass: ...`
- un target `Remote SSH Public/Private key: ...`

Los datos variables del remoto se introducen en la propia web por pestaña.
