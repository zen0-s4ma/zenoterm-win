# Guía de configuración

Instala dependencias con:

```powershell
python -m pip install fastapi "uvicorn[standard]" pywinpty paramiko
```

`pywinpty` es la capa de terminal local en Windows y `Paramiko` maneja `SSHClient.connect()`, `load_host_keys()` e `invoke_shell()` para sesiones remotas interactivas. FastAPI soporta las sesiones en tiempo real con `WebSocket`. citeturn806613search0turn806613search1turn806613search3

## `zenoterm.config.json`

### `app.title`
Nombre visible de la aplicación.

### `server.host`
`127.0.0.1` para solo local. `0.0.0.0` para red o remoto.

### `server.port`
Puerto preferido.

### `server.open_browser`
Abre el navegador al arrancar.

### `server.auto_port_if_busy`
Si el puerto está ocupado, usa otro libre.

### `auth.mode`
`password` o `none`.

### `auth.app_password`
Contraseña de acceso al panel.

### `auth.session_secret`
Secreto usado para firmar la cookie de sesión.

### `auth.session_ttl_seconds`
Duración de la sesión web.

## `targets`
Modelo 3: targets predefinidos y credenciales efímeras.

### Campos comunes
- `id`: identificador único.
- `label`: nombre visible.
- `mode`: `direct`, `ssh_password` o `ssh_key`.
- `description`: texto descriptivo.

### `direct`
- `shell_id`: `pwsh`, `powershell`, `cmd` o `gitbash`.

### `ssh_password`
- `host`
- `port`
- `username`
- `prompt_password`
- `strict_host_key`

### `ssh_key`
- `host`
- `port`
- `username`
- `private_key_path`
- `prompt_passphrase`
- `strict_host_key`

## `known_hosts`
Si `strict_host_key` es `true`, el host remoto debe existir aquí en formato OpenSSH. Paramiko carga este archivo con `load_host_keys()` y, con política estricta, rechaza hosts desconocidos. citeturn806613search0turn806613search6
