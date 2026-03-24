# Guía de configuración

## Inventario local y remoto

Desde esta versión, Zenoterm separa claramente dos conceptos:

- **Terminales locales detectadas**: se descubren automáticamente al arrancar según el sistema operativo real del host. No se crean manualmente ni se fuerzan desde el JSON.
- **Terminales remotas configuradas**: sí se guardan en `zenoterm.config.json` y siguen siendo editables desde la vista de configuración.

## Qué se guarda ahora en `zenoterm.config.json`

- `terminal_presets`: solo presets remotos.
- `local_terminal_overrides`: ajustes propios de Zenoterm para cada terminal local detectada (nombre visible, `launch_command`, `startup_command` o fichero `.command`).
- `remote_defaults`, `ui`, `auth`, `server`: igual que antes.

## Comportamiento del formulario

- Al crear una pestaña **local**, el campo **Sistema operativo target** es solo informativo y muestra el host actual.
- El desplegable **Target** enseña únicamente las terminales locales realmente detectadas en ese host.
- Al crear una pestaña **remota**, el sistema operativo target vuelve a ser editable y filtra los presets remotos.

- De base el proyecto trae solo dos presets remotos iniciales: uno por contraseña y otro por clave. Después puedes editarlos, duplicar lógica creando otros nuevos o especializarlos por SO/shell.
