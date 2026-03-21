# Guía de uso

## Arranque

```powershell
python app.py
```

## Flujo básico

1. Abre la web.
2. Haz login con `auth.app_password` si `auth.mode = "password"`.
3. Crea una pestaña con `+ Nueva pestaña`.
4. Selecciona target.
5. Introduce contraseña SSH o passphrase si ese target la pide.
6. Pulsa `Conectar`.

## Tabs
Cada pestaña mantiene su propia terminal, su propio WebSocket y su propio destino.

## Botones
- `Conectar`: inicia la sesión de la pestaña activa.
- `Reiniciar`: reinicia esa sesión.
- `Limpiar`: limpia la terminal activa.
- `Copiar todo`: copia el buffer de la pestaña activa.
- `Salir`: invalida la sesión web.

## Casos de uso
- `direct`: shell local del PC Windows donde corre la app.
- `ssh_password`: SSH con contraseña efímera.
- `ssh_key`: SSH con clave privada y passphrase efímera opcional.

Paramiko usa `invoke_shell()` con PTY para terminal interactiva, y FastAPI soporta múltiples conexiones `WebSocket` simultáneas. citeturn806613search1turn806613search3
