from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import socket
import sys
import threading
import time
import traceback
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

try:
    import paramiko
except Exception:
    paramiko = None

if os.name == "nt":
    try:
        from winpty import PTY
    except Exception:
        PTY = None
else:
    PTY = None

APP_DIR = Path(__file__).resolve().parent
WEB_DIR = APP_DIR / "web"
CONFIG_PATH = APP_DIR / "zenoterm.config.json"
KNOWN_HOSTS_PATH = APP_DIR / "known_hosts"
COOKIE_NAME = "zenoterm_session"
SESSION_STORE: dict[str, dict[str, Any]] = {}
SESSION_LOCK = threading.Lock()


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        raise RuntimeError(f"No existe el fichero de configuración: {CONFIG_PATH}")
    with CONFIG_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


CONFIG = load_config()
APP_TITLE = str(CONFIG.get("app", {}).get("title") or "Zenoterm Web")
AUTH_MODE = str(CONFIG.get("auth", {}).get("mode") or "password")
SESSION_TTL_SECONDS = int(CONFIG.get("auth", {}).get("session_ttl_seconds") or 43200)
SESSION_SECRET = str(CONFIG.get("auth", {}).get("session_secret") or "change-me")


class AppConfigError(RuntimeError):
    pass


class SessionBase:
    def read(self) -> str:
        raise NotImplementedError
    def write(self, text: str) -> None:
        raise NotImplementedError
    def resize(self, cols: int, rows: int) -> None:
        raise NotImplementedError
    def is_alive(self) -> bool:
        raise NotImplementedError
    def close(self) -> None:
        raise NotImplementedError


def is_port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) != 0


def find_free_port(host: str, preferred_port: int) -> int:
    if is_port_free(host, preferred_port):
        return preferred_port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])


def shutil_which_windows(cmd: str) -> str | None:
    path_env = os.environ.get("PATH", "")
    exts = os.environ.get("PATHEXT", ".EXE;.BAT;.CMD;.COM").split(";")
    p = Path(cmd)
    if p.is_absolute() or "\\" in cmd or "/" in cmd:
        if p.exists():
            return str(p)
        for ext in exts:
            for maybe in (ext.lower(), ext.upper()):
                candidate = Path(str(p) + maybe)
                if candidate.exists():
                    return str(candidate)
        return None
    for folder in path_env.split(os.pathsep):
        folder = folder.strip('" ')
        if not folder:
            continue
        base = Path(folder) / cmd
        if base.exists():
            return str(base)
        for ext in exts:
            for maybe in (ext.lower(), ext.upper()):
                candidate = Path(str(base) + maybe)
                if candidate.exists():
                    return str(candidate)
    return None


def detect_git_bash() -> str | None:
    candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\Program Files\Git\git-bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\usr\bin\bash.exe",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return shutil_which_windows("bash.exe") or shutil_which_windows("git-bash.exe")


WINDOWS_SHELLS: dict[str, dict[str, str]] = {}
if os.name == "nt":
    for key, cmd, label in [
        ("pwsh", "pwsh", "PowerShell 7"),
        ("powershell", "powershell.exe", "Windows PowerShell"),
        ("cmd", "cmd.exe", "CMD"),
    ]:
        path = shutil_which_windows(cmd)
        if path:
            WINDOWS_SHELLS[key] = {"id": key, "label": label, "path": path}
    gitbash = detect_git_bash()
    if gitbash:
        WINDOWS_SHELLS["gitbash"] = {"id": "gitbash", "label": "Git Bash", "path": gitbash}
DEFAULT_WINDOWS_SHELL = next(iter(WINDOWS_SHELLS), None)


def get_targets() -> list[dict[str, Any]]:
    targets = CONFIG.get("targets") or []
    if not isinstance(targets, list):
        raise AppConfigError("targets debe ser una lista")
    return targets

TARGETS_BY_ID = {str(item["id"]): item for item in get_targets() if isinstance(item, dict) and item.get("id")}


def public_targets() -> list[dict[str, Any]]:
    items = []
    for target in get_targets():
        mode = str(target.get("mode") or "direct")
        items.append({
            "id": str(target.get("id") or ""),
            "label": str(target.get("label") or target.get("id") or "Destino"),
            "mode": mode,
            "description": str(target.get("description") or ""),
            "host": str(target.get("host") or "") if mode.startswith("ssh") else "",
            "port": int(target.get("port") or 22) if mode.startswith("ssh") else None,
            "username": str(target.get("username") or "") if mode.startswith("ssh") else "",
            "shell_id": str(target.get("shell_id") or DEFAULT_WINDOWS_SHELL or "") if mode == "direct" else "",
            "prompt_password": bool(target.get("prompt_password") or mode == "ssh_password"),
            "prompt_passphrase": bool(target.get("prompt_passphrase") or False),
            "private_key_path": str(target.get("private_key_path") or "") if mode == "ssh_key" else "",
            "strict_host_key": bool(target.get("strict_host_key", True)) if mode.startswith("ssh") else False,
        })
    return items


class LocalPtySession(SessionBase):
    def __init__(self, shell_id: str, cols: int, rows: int) -> None:
        if os.name != "nt":
            raise RuntimeError("La sesión local directa solo está soportada en Windows.")
        if PTY is None:
            raise RuntimeError("Falta pywinpty. Instala: python -m pip install pywinpty")
        shell = WINDOWS_SHELLS.get(shell_id)
        if not shell:
            raise RuntimeError(f"Shell no soportada: {shell_id}")
        self.cols = max(20, int(cols))
        self.rows = max(5, int(rows))
        self.proc = PTY(self.cols, self.rows)
        self.proc.spawn(shell["path"])
        self._closed = False
    def read(self) -> str:
        data = self.proc.read()
        if data is None:
            return ""
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return str(data)
    def write(self, text: str) -> None:
        if not self._closed and text:
            self.proc.write(text)
    def resize(self, cols: int, rows: int) -> None:
        if not self._closed:
            self.cols = max(20, int(cols))
            self.rows = max(5, int(rows))
            self.proc.set_size(self.cols, self.rows)
    def is_alive(self) -> bool:
        return False if self._closed else bool(self.proc.isalive())
    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self.proc.write("exit\r\n")
            except Exception:
                pass


@dataclass
class LoadedPrivateKey:
    key: Any
    key_type: str


def load_private_key_file(path: str, passphrase: str | None) -> LoadedPrivateKey:
    if paramiko is None:
        raise RuntimeError("Falta paramiko. Instala: python -m pip install paramiko")
    classes = [getattr(paramiko, n, None) for n in ("RSAKey", "ECDSAKey", "Ed25519Key", "DSSKey")]
    errors = []
    for cls in classes:
        if cls is None:
            continue
        try:
            key = cls.from_private_key_file(path, password=passphrase)
            return LoadedPrivateKey(key=key, key_type=cls.__name__)
        except Exception as exc:
            errors.append(f"{getattr(cls, '__name__', 'Key')}: {exc}")
    raise RuntimeError("No se pudo cargar la clave privada. Detalle: " + " | ".join(errors))


class ParamikoShellSession(SessionBase):
    def __init__(self, host: str, port: int, username: str, password: str | None, private_key_path: str | None, passphrase: str | None, strict_host_key: bool, cols: int, rows: int) -> None:
        if paramiko is None:
            raise RuntimeError("Falta paramiko. Instala: python -m pip install paramiko")
        self.cols = max(20, int(cols))
        self.rows = max(5, int(rows))
        self.client = paramiko.SSHClient()
        if KNOWN_HOSTS_PATH.exists():
            self.client.load_host_keys(str(KNOWN_HOSTS_PATH))
        else:
            try:
                self.client.load_system_host_keys()
            except Exception:
                pass
        self.client.set_missing_host_key_policy(paramiko.RejectPolicy() if strict_host_key else paramiko.AutoAddPolicy())
        connect_kwargs: dict[str, Any] = {
            "hostname": host,
            "port": int(port),
            "username": username,
            "timeout": 12,
            "banner_timeout": 12,
            "auth_timeout": 12,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if private_key_path:
            loaded = load_private_key_file(private_key_path, passphrase)
            connect_kwargs["pkey"] = loaded.key
        elif password is not None:
            connect_kwargs["password"] = password
        else:
            raise RuntimeError("Faltan credenciales SSH para iniciar la sesión.")
        self.client.connect(**connect_kwargs)
        self.channel = self.client.invoke_shell(term="xterm", width=self.cols, height=self.rows)
        self.channel.settimeout(0.2)
        self._closed = False
    def read(self) -> str:
        if self._closed:
            return ""
        try:
            data = self.channel.recv(65535)
        except Exception:
            return ""
        if not data:
            return ""
        return data.decode("utf-8", errors="replace") if isinstance(data, bytes) else str(data)
    def write(self, text: str) -> None:
        if not self._closed and text:
            self.channel.send(text)
    def resize(self, cols: int, rows: int) -> None:
        if not self._closed:
            self.cols = max(20, int(cols)); self.rows = max(5, int(rows))
            try:
                self.channel.resize_pty(width=self.cols, height=self.rows)
            except Exception:
                pass
    def is_alive(self) -> bool:
        return not self._closed and not self.channel.closed
    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try: self.channel.close()
            except Exception: pass
            try: self.client.close()
            except Exception: pass


def build_runtime_config() -> dict[str, Any]:
    return {
        "title": APP_TITLE,
        "auth": {"mode": AUTH_MODE, "login_required": AUTH_MODE != "none", "session_ttl_seconds": SESSION_TTL_SECONDS},
        "targets": public_targets(),
        "windows_shells": list(WINDOWS_SHELLS.values()),
    }

APP = FastAPI(title=APP_TITLE)
if WEB_DIR.exists():
    APP.mount('/web', StaticFiles(directory=str(WEB_DIR)), name='web')

@APP.get('/')
async def index() -> Any:
    p = WEB_DIR / 'index.html'
    return FileResponse(p) if p.exists() else JSONResponse({'error': 'Falta web/index.html'}, status_code=500)

@APP.get('/api/config')
async def api_config() -> JSONResponse:
    return JSONResponse(build_runtime_config())

@APP.get('/api/auth/status')
async def auth_status(request: Request) -> JSONResponse:
    return JSONResponse({'authenticated': is_request_authenticated(request)})

@APP.post('/api/auth/login')
async def auth_login(request: Request) -> JSONResponse:
    data = await request.json()
    if AUTH_MODE == 'none':
        response = JSONResponse({'ok': True, 'authenticated': True})
        set_auth_cookie(response, create_session('anonymous'))
        return response
    configured = str((CONFIG.get('auth') or {}).get('app_password') or '')
    password = str(data.get('password') or '')
    if not configured:
        return JSONResponse({'ok': False, 'message': 'No hay app_password configurado.'}, status_code=500)
    if not hmac.compare_digest(password, configured):
        return JSONResponse({'ok': False, 'message': 'Contraseña incorrecta.'}, status_code=401)
    response = JSONResponse({'ok': True, 'authenticated': True})
    set_auth_cookie(response, create_session('app-user'))
    return response

@APP.post('/api/auth/logout')
async def auth_logout(request: Request) -> JSONResponse:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        delete_session(token)
    response = JSONResponse({'ok': True, 'authenticated': False})
    response.delete_cookie(COOKIE_NAME, path='/')
    return response

@APP.get('/api/health')
async def health() -> JSONResponse:
    return JSONResponse({'ok': True, 'app': APP_TITLE})


def create_signature(token: str) -> str:
    return hmac.new(SESSION_SECRET.encode('utf-8'), token.encode('utf-8'), hashlib.sha256).hexdigest()

def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    with SESSION_LOCK:
        SESSION_STORE[token] = {'username': username, 'expires_at': time.time() + SESSION_TTL_SECONDS}
    return f'{token}.{create_signature(token)}'

def validate_signed_cookie(signed_cookie: str | None) -> bool:
    if not signed_cookie or '.' not in signed_cookie:
        return False
    token, signature = signed_cookie.rsplit('.', 1)
    if not hmac.compare_digest(signature, create_signature(token)):
        return False
    with SESSION_LOCK:
        record = SESSION_STORE.get(token)
        if not record:
            return False
        if record.get('expires_at', 0) < time.time():
            SESSION_STORE.pop(token, None)
            return False
    return True

def delete_session(signed_cookie: str) -> None:
    if '.' in signed_cookie:
        token = signed_cookie.rsplit('.', 1)[0]
        with SESSION_LOCK:
            SESSION_STORE.pop(token, None)

def set_auth_cookie(response: Response, signed_cookie: str) -> None:
    response.set_cookie(COOKIE_NAME, signed_cookie, httponly=True, samesite='lax', secure=False, path='/', max_age=SESSION_TTL_SECONDS)

def is_request_authenticated(request: Request) -> bool:
    return True if AUTH_MODE == 'none' else validate_signed_cookie(request.cookies.get(COOKIE_NAME))

def is_websocket_authenticated(websocket: WebSocket) -> bool:
    return True if AUTH_MODE == 'none' else validate_signed_cookie(websocket.cookies.get(COOKIE_NAME))

class SessionFactory:
    @staticmethod
    def create(target_id: str, creds: dict[str, Any], cols: int, rows: int) -> SessionBase:
        target = TARGETS_BY_ID.get(target_id)
        if not target:
            raise RuntimeError(f'Target no encontrado: {target_id}')
        mode = str(target.get('mode') or 'direct')
        if mode == 'direct':
            shell_id = str(target.get('shell_id') or DEFAULT_WINDOWS_SHELL or '')
            if not shell_id:
                raise RuntimeError('No hay shell local disponible configurada para este target.')
            return LocalPtySession(shell_id=shell_id, cols=cols, rows=rows)
        if mode == 'ssh_password':
            password = str(creds.get('password') or '')
            if not password:
                raise RuntimeError('Este target requiere contraseña SSH efímera.')
            return ParamikoShellSession(str(target.get('host') or ''), int(target.get('port') or 22), str(target.get('username') or ''), password, None, None, bool(target.get('strict_host_key', True)), cols, rows)
        if mode == 'ssh_key':
            key_path = str(target.get('private_key_path') or '')
            if not key_path:
                raise RuntimeError('El target ssh_key no tiene private_key_path configurado.')
            return ParamikoShellSession(str(target.get('host') or ''), int(target.get('port') or 22), str(target.get('username') or ''), None, key_path, (str(creds.get('passphrase') or '') or None), bool(target.get('strict_host_key', True)), cols, rows)
        raise RuntimeError(f'Modo no soportado: {mode}')

@APP.websocket('/ws')
async def websocket_terminal(websocket: WebSocket) -> None:
    if not is_websocket_authenticated(websocket):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    loop = asyncio.get_running_loop()
    stop_event = threading.Event()
    session: Optional[SessionBase] = None
    async def send_json(payload: dict[str, Any]) -> None:
        await websocket.send_text(json.dumps(payload))
    def schedule_send(payload: dict[str, Any]) -> None:
        if not stop_event.is_set():
            loop.call_soon_threadsafe(asyncio.create_task, send_json(payload))
    def reader_worker() -> None:
        nonlocal session
        try:
            while not stop_event.is_set() and session is not None and session.is_alive():
                chunk = session.read()
                if chunk:
                    schedule_send({'type': 'output', 'data': chunk})
                else:
                    time.sleep(0.02)
        except Exception as exc:
            schedule_send({'type': 'status', 'status': 'error', 'message': f'{type(exc).__name__}: {exc}'})
        finally:
            schedule_send({'type': 'status', 'status': 'closed', 'message': 'La sesión ha terminado.'})
    try:
        await send_json({'type': 'status', 'status': 'ready', 'message': 'WebSocket conectada.'})
        while True:
            payload = json.loads(await websocket.receive_text())
            msg_type = str(payload.get('type') or '')
            if msg_type == 'ping':
                await send_json({'type': 'pong'})
                continue
            if msg_type in {'start', 'restart'}:
                if session is not None:
                    try: session.close()
                    except Exception: pass
                    session = None
                stop_event.clear()
                try:
                    session = SessionFactory.create(str(payload.get('target_id') or ''), payload.get('credentials') or {}, int(payload.get('cols') or 120), int(payload.get('rows') or 30))
                    threading.Thread(target=reader_worker, daemon=True).start()
                    await send_json({'type': 'status', 'status': 'connected', 'message': f"Sesión activa en {payload.get('target_id')}.", 'target_id': payload.get('target_id')})
                except Exception as exc:
                    traceback.print_exc()
                    await send_json({'type': 'status', 'status': 'error', 'message': f'{type(exc).__name__}: {exc}'})
                continue
            if msg_type == 'input':
                if session is None:
                    await send_json({'type': 'status', 'status': 'error', 'message': 'No hay sesión activa.'})
                else:
                    session.write(str(payload.get('data') or ''))
                continue
            if msg_type == 'resize':
                if session is not None:
                    session.resize(int(payload.get('cols') or 120), int(payload.get('rows') or 30))
                continue
            if msg_type == 'close':
                if session is not None:
                    session.close(); session = None
                await send_json({'type': 'status', 'status': 'closed', 'message': 'Sesión cerrada.'})
                continue
            await send_json({'type': 'status', 'status': 'error', 'message': f'Mensaje no soportado: {msg_type}'})
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        traceback.print_exc()
        try: await send_json({'type': 'status', 'status': 'error', 'message': f'{type(exc).__name__}: {exc}'})
        except Exception: pass
    finally:
        stop_event.set()
        if session is not None:
            try: session.close()
            except Exception: pass
        try: await websocket.close()
        except Exception: pass


def self_check() -> tuple[bool, list[str]]:
    messages = []
    ok = True
    if not WEB_DIR.exists(): ok=False; messages.append('Falta la carpeta web')
    if not (WEB_DIR/'index.html').exists(): ok=False; messages.append('Falta web/index.html')
    if AUTH_MODE == 'password' and not str((CONFIG.get('auth') or {}).get('app_password') or ''):
        ok=False; messages.append('auth.app_password está vacío')
    for target in get_targets():
        mode = str(target.get('mode') or '')
        target_id = str(target.get('id') or '')
        if not target_id: ok=False; messages.append('Hay un target sin id')
        if mode in {'ssh_password','ssh_key'}:
            if not target.get('host') or not target.get('username'):
                ok=False; messages.append(f'Target {target_id}: host/username obligatorios')
            if mode == 'ssh_key' and not target.get('private_key_path'):
                ok=False; messages.append(f'Target {target_id}: private_key_path obligatorio en ssh_key')
    return ok, messages


def open_browser(url: str) -> None:
    try: webbrowser.open(url)
    except Exception: pass


def main() -> None:
    ok, messages = self_check()
    if not ok:
        for message in messages: print('CHECK:', message, file=sys.stderr)
        sys.exit(1)
    for message in messages: print('CHECK:', message)
    server_cfg = CONFIG.get('server') or {}
    host = str(server_cfg.get('host') or '127.0.0.1')
    port = int(server_cfg.get('port') or 8765)
    if bool(server_cfg.get('auto_port_if_busy', True)):
        port = find_free_port(host, port)
    url = f'http://{host}:{port}'
    print(f'{APP_TITLE} disponible en {url}')
    if bool(server_cfg.get('open_browser', True)):
        timer = threading.Timer(0.75, open_browser, args=(url,))
        timer.daemon = True
        timer.start()
    uvicorn.run(APP, host=host, port=port, log_level='info')

if __name__ == '__main__':
    main()
