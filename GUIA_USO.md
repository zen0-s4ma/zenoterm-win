# Guía de uso

## 1. Arranque

```powershell
python -m pip install -r requirements.txt
python app.py
```

## 2. Login

Si `auth.mode` es `password`, introduce `auth.app_password` para acceder.

## 3. Columna izquierda

### Config global
Permite elegir:

- target por defecto para pestañas nuevas;
- scrollback por defecto.

### Crear nueva pestaña
Permite:

- elegir nombre de pestaña;
- elegir target inicial.

### Acciones sobre conexión seleccionada
Permite sobre la pestaña activa:

- conectar;
- reconectar;
- limpiar;
- copiar todo;
- guardar salida a fichero.

### Estado de la pestaña activa
Muestra:

- nombre;
- target;
- estado;
- modo de conexión;
- host, usuario y shell cuando aplica;
- scrollback;
- si está conectada o no.

## 4. Uso de targets locales

1. Crea la pestaña.
2. Selecciona un target `Local: ...`.
3. Pulsa `Conectar`.

## 5. Uso de targets remotos por contraseña

1. Crea la pestaña.
2. Selecciona `Remote SSH User/Pass: ...`.
3. Rellena host, puerto y usuario.
4. Introduce la contraseña.
5. Pulsa `Conectar`.

## 6. Uso de targets remotos por clave

1. Crea la pestaña.
2. Selecciona `Remote SSH Public/Private key: ...`.
3. Rellena host, puerto y usuario.
4. Escribe la ruta de la clave privada.
5. Escribe passphrase si aplica.
6. Pulsa `Conectar`.

## 7. Pestañas

Cada pestaña mantiene:

- un nombre propio;
- un target propio;
- credenciales efímeras propias;
- buffer propio;
- WebSocket propio.

## 8. Guardar salida

Pulsa `Guardar salida` para descargar un `.txt` con el contenido completo del buffer de la pestaña activa.
