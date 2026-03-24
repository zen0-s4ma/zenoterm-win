from __future__ import annotations

import asyncio
import hashlib
import hmac
import io
import json
import os
import platform
import secrets
import socket
import subprocess
import shutil
import sys
import threading
import time
import signal
import struct
import traceback
import webbrowser
import shlex
import re
import base64
import tempfile
import zipfile
from datetime import datetime, timedelta, time as dt_time
from zoneinfo import ZoneInfo
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Request, Response, WebSocket, WebSocketDisconnect, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from starlette.background import BackgroundTask
from fastapi.staticfiles import StaticFiles
import uvicorn

if sys.platform.startswith("win") and hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except Exception:
        pass

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
    try:
        import fcntl
        import pty
        import termios
    except Exception:
        fcntl = None
        pty = None
        termios = None

APP_DIR = Path(__file__).resolve().parent
WEB_DIR = APP_DIR / "web"
CONFIG_PATH = APP_DIR / "zenoterm.config.json"
KNOWN_HOSTS_PATH = APP_DIR / "known_hosts"
SCRIPTS_DIR = APP_DIR / "scripts"
DOCKER_SCRIPTS_DIR = SCRIPTS_DIR / "docker"
COOKIE_NAME = "zenoterm_session"
SESSION_STORE: dict[str, dict[str, Any]] = {}
SESSION_LOCK = threading.Lock()


def get_auth_config() -> dict[str, Any]:
    return CONFIG.get("auth") or {}


ROLE_DEFINITIONS: dict[str, dict[str, Any]] = {
    "administrator": {
        "label": "Administrador",
        "permissions": {
            "is_admin": True,
            "manage_administration": True,
            "manage_config": True,
            "manage_scripts": True,
            "manage_scheduler": True,
            "use_local_terminals": True,
            "use_remote_terminals": True,
            "use_docker": True,
        },
    },
    "total": {
        "label": "Usuario total",
        "permissions": {
            "is_admin": False,
            "manage_administration": False,
            "manage_config": False,
            "manage_scripts": False,
            "manage_scheduler": False,
            "use_local_terminals": True,
            "use_remote_terminals": True,
            "use_docker": True,
        },
    },
    "no_docker": {
        "label": "Usuario sin Docker",
        "permissions": {
            "is_admin": False,
            "manage_administration": False,
            "manage_config": False,
            "manage_scripts": False,
            "manage_scheduler": False,
            "use_local_terminals": True,
            "use_remote_terminals": True,
            "use_docker": False,
        },
    },
    "remote_only": {
        "label": "Usuario para remoto",
        "permissions": {
            "is_admin": False,
            "manage_administration": False,
            "manage_config": False,
            "manage_scripts": False,
            "manage_scheduler": False,
            "use_local_terminals": False,
            "use_remote_terminals": True,
            "use_docker": False,
        },
    },
    "docker_only": {
        "label": "Usuario solo Docker",
        "permissions": {
            "is_admin": False,
            "manage_administration": False,
            "manage_config": False,
            "manage_scripts": False,
            "manage_scheduler": False,
            "use_local_terminals": False,
            "use_remote_terminals": True,
            "use_docker": True,
        },
    },
}
ROLE_ALIASES = {
    "admin": "administrator",
    "administrator": "administrator",
    "total": "total",
    "usuario_total": "total",
    "user_total": "total",
    "no_docker": "no_docker",
    "sin_docker": "no_docker",
    "usuario_sin_docker": "no_docker",
    "remote_only": "remote_only",
    "solo_remoto": "remote_only",
    "remoto": "remote_only",
    "docker_only": "docker_only",
    "solo_docker": "docker_only",
}
EXPLORER_ACCESS_VALUES = {"read_only", "read_write"}


def normalize_role(value: str | None) -> str:
    raw = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return ROLE_ALIASES.get(raw, raw if raw in ROLE_DEFINITIONS else "no_docker")


def sanitize_username(value: str | None, fallback: str = "user") -> str:
    raw = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip().lower()).strip("._-")
    return raw or fallback


def hash_password(password: str, salt_b64: str | None = None, iterations: int | None = None) -> dict[str, Any]:
    raw_salt = base64.b64decode(salt_b64.encode("utf-8")) if salt_b64 else secrets.token_bytes(16)
    rounds = int(iterations or 310000)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), raw_salt, rounds)
    return {
        "password_salt": base64.b64encode(raw_salt).decode("utf-8"),
        "password_hash": base64.b64encode(digest).decode("utf-8"),
        "password_iterations": rounds,
    }


def verify_password_hash(password: str, stored_hash: str, stored_salt: str, iterations: int = 310000) -> bool:
    if not stored_hash or not stored_salt:
        return False
    candidate = hash_password(password, salt_b64=stored_salt, iterations=iterations)["password_hash"]
    return hmac.compare_digest(candidate, stored_hash)


def normalize_explorer_entry(item: Any) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    raw_path = str(item.get("path") or "").strip()
    if not raw_path:
        return None
    try:
        resolved = str(Path(os.path.expanduser(raw_path)).resolve())
    except Exception:
        return None
    access = str(item.get("access") or "read_only").strip().lower()
    if access not in EXPLORER_ACCESS_VALUES:
        access = "read_only"
    label = str(item.get("label") or Path(resolved).name or resolved)
    return {"path": resolved, "label": label, "access": access}


def default_explorer_entries_for_role(role: str) -> list[dict[str, Any]]:
    app_root = str(APP_DIR.resolve())
    access = "read_write" if role in {"administrator", "total", "no_docker"} else "read_only"
    return [{"path": app_root, "label": "Proyecto ZenoRemote", "access": access}]



def normalize_optional_session_id(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip("-._")


def normalize_user_terminal_sessions(raw: Any) -> list[dict[str, str]]:
    sessions: list[dict[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            raw_name = str(item.get("name") or "").strip()
            session_id = normalize_optional_session_id(item.get("id") or raw_name or "")
            if not session_id or not raw_name:
                continue
            if any(existing["id"] == session_id for existing in sessions):
                continue
            sessions.append({"id": session_id, "name": raw_name})
    return sessions


def normalize_session_override_map(raw: Any, valid_session_ids: set[str]) -> dict[str, dict[str, dict[str, Any]]]:
    if not isinstance(raw, dict):
        return {}
    result: dict[str, dict[str, dict[str, Any]]] = {}
    allowed_fields = {
        "name", "scope", "auth_type", "target_os", "shell_family", "host", "port", "username",
        "private_key_path", "strict_host_key", "startup_command", "command_file_content",
        "launch_command", "open_by_default"
    }
    for session_id, mapping in raw.items():
        normalized_session_id = normalize_optional_session_id(session_id)
        if normalized_session_id not in valid_session_ids or not isinstance(mapping, dict):
            continue
        session_map: dict[str, dict[str, Any]] = {}
        for preset_id, override in mapping.items():
            if not isinstance(override, dict):
                continue
            normalized_override = {key: override[key] for key in allowed_fields if key in override}
            if normalized_override:
                session_map[str(preset_id)] = normalized_override
        if session_map:
            result[normalized_session_id] = session_map
    return result


def make_user_record(
    user_id: str,
    username: str,
    display_name: str,
    role: str,
    password: str,
    explorer_entries: list[dict[str, Any]] | None = None,
    enabled: bool = True,
    terminal_sessions: list[dict[str, Any]] | None = None,
    default_session_id: str | None = None,
    session_terminal_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized_role = normalize_role(role)
    hashed = hash_password(password)
    entries = [entry for entry in (normalize_explorer_entry(item) for item in (explorer_entries or default_explorer_entries_for_role(normalized_role))) if entry]
    session_items = normalize_user_terminal_sessions(terminal_sessions or [])
    session_ids = {item["id"] for item in session_items}
    normalized_default_session = normalize_optional_session_id(default_session_id)
    if normalized_default_session not in session_ids:
        normalized_default_session = ""
    session_overrides = normalize_session_override_map(session_terminal_overrides or {}, session_ids)
    return {
        "id": str(user_id or secrets.token_hex(8)),
        "username": sanitize_username(username, "user"),
        "display_name": str(display_name or username or "Usuario").strip(),
        "role": normalized_role,
        "enabled": bool(enabled),
        **hashed,
        "explorer_entries": entries,
        "terminal_sessions": session_items,
        "default_session_id": normalized_default_session,
        "session_terminal_overrides": session_overrides,
    }


def default_user_store() -> dict[str, Any]:
    return {
        "users": [
            make_user_record(
                "user-admin",
                "admin",
                "Administrador",
                "administrator",
                "admin",
                explorer_entries=[],
                terminal_sessions=[{"id": "test-auto-sesion", "name": "test-auto-sesion"}],
                default_session_id="test-auto-sesion",
                session_terminal_overrides={
                    "test-auto-sesion": {
                        "local::powershell": {"name": "test-auto-sesion-pws", "startup_command": "ls", "open_by_default": True},
                        "local::cmd": {"name": "test-auto-sesion-cmd", "startup_command": "dir", "open_by_default": True},
                    }
                },
            ),
            make_user_record("user-total", "total", "Usuario total", "total", "user"),
            make_user_record("user-no-docker", "sin-docker", "Usuario sin Docker", "no_docker", "user"),
            make_user_record("user-remote", "remoto", "Usuario para remoto", "remote_only", "user"),
            make_user_record("user-docker", "solo-docker", "Usuario solo Docker", "docker_only", "user"),
        ]
    }


def get_user_store() -> dict[str, Any]:
    raw = CONFIG.get("user_management") or {}
    return raw if isinstance(raw, dict) else {"users": []}


def get_users() -> list[dict[str, Any]]:
    raw_users = get_user_store().get("users") or []
    users: list[dict[str, Any]] = []
    for index, item in enumerate(raw_users):
        if not isinstance(item, dict):
            continue
        username = sanitize_username(item.get("username"), f"user-{index + 1}")
        role = normalize_role(item.get("role"))
        display_name = str(item.get("display_name") or username).strip() or username
        entries = [entry for entry in (normalize_explorer_entry(entry) for entry in (item.get("explorer_entries") or [])) if entry]
        terminal_sessions = normalize_user_terminal_sessions(item.get("terminal_sessions") or [])
        session_ids = {entry["id"] for entry in terminal_sessions}
        default_session_id = normalize_optional_session_id(item.get("default_session_id"))
        if default_session_id not in session_ids:
            default_session_id = ""
        users.append({
            "id": str(item.get("id") or f"user-{index + 1}"),
            "username": username,
            "display_name": display_name,
            "role": role,
            "enabled": bool(item.get("enabled", True)),
            "password_salt": str(item.get("password_salt") or ""),
            "password_hash": str(item.get("password_hash") or ""),
            "password_iterations": int(item.get("password_iterations") or 310000),
            "explorer_entries": entries,
            "terminal_sessions": terminal_sessions,
            "default_session_id": default_session_id,
            "session_terminal_overrides": normalize_session_override_map(item.get("session_terminal_overrides") or {}, session_ids),
        })
    return users


def find_user_by_username(username: str) -> dict[str, Any] | None:
    target = sanitize_username(username)
    for user in get_users():
        if user["username"] == target:
            return user
    return None


def find_user_by_id(user_id: str) -> dict[str, Any] | None:
    for user in get_users():
        if str(user.get("id") or "") == str(user_id or ""):
            return user
    return None


def role_permissions(role: str) -> dict[str, Any]:
    definition = ROLE_DEFINITIONS.get(normalize_role(role), ROLE_DEFINITIONS["no_docker"])
    return dict(definition.get("permissions") or {})


def serialize_explorer_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "path": str(item.get("path") or ""),
            "label": str(item.get("label") or Path(str(item.get("path") or "")).name or str(item.get("path") or "")),
            "access": str(item.get("access") or "read_only"),
        }
        for item in entries or []
        if str(item.get("path") or "").strip()
    ]


def serialize_current_user(user: dict[str, Any] | None) -> dict[str, Any] | None:
    if not user:
        return None
    permissions = role_permissions(str(user.get("role") or ""))
    explorer_entries = serialize_explorer_entries(user.get("explorer_entries") or [])
    permissions["use_explorer"] = bool(permissions.get("is_admin") or explorer_entries)
    return {
        "id": str(user.get("id") or ""),
        "username": str(user.get("username") or ""),
        "display_name": str(user.get("display_name") or ""),
        "role": normalize_role(str(user.get("role") or "")),
        "role_label": str(ROLE_DEFINITIONS.get(normalize_role(str(user.get("role") or "")), {}).get("label") or "Usuario"),
        "enabled": bool(user.get("enabled", True)),
        "permissions": permissions,
        "explorer_entries": [] if permissions.get("is_admin") else explorer_entries,
        "terminal_sessions": get_terminal_sessions(user),
        "default_session_id": get_user_default_session_id(user),
        "session_terminal_overrides": get_user_session_terminal_overrides(user),
    }


def serialize_user_for_admin(user: dict[str, Any]) -> dict[str, Any]:
    payload = serialize_current_user(user) or {}
    payload.update({"new_password": ""})
    return payload

def ensure_auth_config_shape() -> None:
    auth = CONFIG.setdefault("auth", {})
    auth.setdefault("mode", "password")
    auth.setdefault("session_secret", secrets.token_urlsafe(24))
    auth.setdefault("session_ttl_seconds", 43200)
    auth.setdefault("admin_username", "admin")
    plain_password = str(auth.get("app_password") or "")
    if plain_password and not auth.get("password_hash"):
        hashed = hash_password(plain_password)
        auth.update(hashed)
        auth.pop("app_password", None)
        save_config(CONFIG)


def ensure_user_management_shape() -> None:
    changed = False
    user_store = CONFIG.get("user_management")
    if not isinstance(user_store, dict) or not isinstance(user_store.get("users"), list) or not user_store.get("users"):
        CONFIG["user_management"] = default_user_store()
        changed = True
        normalized_users = get_users()
    else:
        normalized_users = get_users()
        if not normalized_users:
            CONFIG["user_management"] = default_user_store()
            normalized_users = get_users()
            changed = True
        else:
            stored_users = user_store.get("users") or []
            if stored_users != normalized_users:
                CONFIG["user_management"] = {"users": normalized_users}
                changed = True
    auth = CONFIG.setdefault("auth", {})
    first_admin = next((item for item in normalized_users if normalize_role(item.get("role")) == "administrator" and item.get("enabled", True)), None)
    desired_admin_username = str(first_admin.get("username") or "admin") if first_admin else "admin"
    if str(auth.get("admin_username") or "").strip() != desired_admin_username:
        auth["admin_username"] = desired_admin_username
        changed = True
    if changed:
        save_config(CONFIG)


def verify_login_credentials(username: str, password: str) -> dict[str, Any] | None:
    user = find_user_by_username(username)
    if not user or not user.get("enabled", True):
        return None
    if verify_password_hash(
        password,
        str(user.get("password_hash") or ""),
        str(user.get("password_salt") or ""),
        int(user.get("password_iterations") or 310000),
    ):
        return user
    return None


def build_administration_state(user: dict[str, Any] | None) -> dict[str, Any]:
    serialized = serialize_current_user(user)
    permissions = serialized.get("permissions") if serialized else {}
    if not permissions or not permissions.get("manage_administration"):
        return {"enabled": False, "roles": [], "users": []}
    role_options = [
        {"id": role_id, "label": str(definition.get("label") or role_id), "permissions": dict(definition.get("permissions") or {})}
        for role_id, definition in ROLE_DEFINITIONS.items()
    ]
    return {
        "enabled": True,
        "roles": role_options,
        "users": [serialize_user_for_admin(item) for item in get_users()],
    }


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        raise RuntimeError(f"No existe el fichero de configuración: {CONFIG_PATH}")
    with CONFIG_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_config(data: dict[str, Any]) -> None:
    with CONFIG_PATH.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
        fh.write("\n")


CONFIG = load_config()
ensure_auth_config_shape()
ensure_user_management_shape()
APP_TITLE = str(CONFIG.get("app", {}).get("title") or "ZenoRemote")
AUTH_MODE = str(CONFIG.get("auth", {}).get("mode") or "password")
SESSION_TTL_SECONDS = int(CONFIG.get("auth", {}).get("session_ttl_seconds") or 43200)
SESSION_SECRET = str(CONFIG.get("auth", {}).get("session_secret") or "change-me")


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


def detect_wsl_distributions() -> list[str]:
    if os.name != "nt":
        return []
    wsl_exe = shutil_which_windows("wsl.exe")
    if not wsl_exe:
        return []
    try:
        result = subprocess.run(
            [wsl_exe, "-l", "-q"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception:
        return []
    if result.returncode != 0:
        return []
    names: list[str] = []
    for raw in result.stdout.splitlines():
        name = raw.strip().replace("\x00", "")
        if name and name not in names:
            names.append(name)
    return names


def detect_host_os() -> str:
    platform_name = (platform.system() or "").strip().lower()
    if os.environ.get("ANDROID_ROOT") or os.environ.get("ANDROID_DATA") or os.environ.get("TERMUX_VERSION"):
        return "android"
    if platform_name == "windows":
        return "windows"
    if platform_name == "darwin":
        return "macos"
    if platform_name == "linux":
        return "linux"
    return platform_name or "unknown"


TARGET_OS_LABELS: dict[str, str] = {
    "windows": "Windows",
    "linux": "Linux",
    "macos": "macOS",
    "android": "Android",
    "unknown": "Sistema actual",
}


HOST_OS = detect_host_os()


GENERIC_SHELL_SPECS: dict[str, list[dict[str, str]]] = {
    "windows": [
        {"id": "pwsh", "label": "PowerShell 7"},
        {"id": "powershell", "label": "PowerShell 5.1"},
        {"id": "cmd", "label": "CMD"},
        {"id": "gitbash", "label": "Git Bash"},
    ],
    "linux": [
        {"id": "bash", "label": "Bash"},
        {"id": "zsh", "label": "Zsh"},
        {"id": "fish", "label": "Fish"},
        {"id": "sh", "label": "POSIX sh"},
        {"id": "dash", "label": "Dash"},
    ],
    "macos": [
        {"id": "zsh", "label": "Zsh"},
        {"id": "bash", "label": "Bash"},
        {"id": "fish", "label": "Fish"},
        {"id": "sh", "label": "POSIX sh"},
    ],
    "android": [
        {"id": "sh", "label": "POSIX sh"},
        {"id": "bash", "label": "Bash"},
        {"id": "zsh", "label": "Zsh"},
        {"id": "ash", "label": "Ash"},
        {"id": "fish", "label": "Fish"},
    ],
}


def target_os_options() -> list[dict[str, str]]:
    order = ["windows", "linux", "macos", "android"]
    if HOST_OS not in order:
        order.append(HOST_OS)
    return [{"id": key, "label": TARGET_OS_LABELS.get(key, key)} for key in order]


TARGET_OS_OPTIONS = target_os_options()


def shell_catalog_entry(shell_id: str, label: str, target_os: str, **extra: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "id": shell_id,
        "label": label,
        "target_os": target_os,
        "target_os_label": TARGET_OS_LABELS.get(target_os, target_os),
        "kind": "direct",
    }
    item.update(extra)
    return item


def detect_windows_shells() -> dict[str, dict[str, Any]]:
    shells: dict[str, dict[str, Any]] = {}
    if os.name != "nt":
        return shells

    cmd_path = shutil_which_windows("cmd.exe")
    pwsh_path = shutil_which_windows("pwsh")
    powershell_path = shutil_which_windows("powershell.exe")
    gitbash_path = detect_git_bash()
    wsl_path = shutil_which_windows("wsl.exe")

    if pwsh_path:
        shells["pwsh"] = shell_catalog_entry("pwsh", "PowerShell 7", "windows", path=pwsh_path)
    if powershell_path:
        shells["powershell"] = shell_catalog_entry("powershell", "PowerShell 5.1", "windows", path=powershell_path)
    if cmd_path:
        shells["cmd"] = shell_catalog_entry("cmd", "CMD", "windows", path=cmd_path)
    if gitbash_path:
        shells["gitbash"] = shell_catalog_entry("gitbash", "Git Bash", "windows", path=gitbash_path)
    if wsl_path:
        for distro in detect_wsl_distributions():
            shell_id = f"wsl::{distro}"
            shells[shell_id] = shell_catalog_entry(
                shell_id,
                f"WSL2 {distro}",
                "windows",
                path=wsl_path,
                profile="wsl",
                distro=distro,
            )
    return shells


def detect_posix_shells(target_os: str) -> dict[str, dict[str, Any]]:
    shells: dict[str, dict[str, Any]] = {}
    env_shell = os.environ.get("SHELL") or ""
    candidates: list[tuple[str, str]] = []
    if env_shell:
        env_name = Path(env_shell).name.strip()
        if env_name:
            candidates.append((env_name, env_name.upper() if env_name == "sh" else env_name.capitalize()))
    for spec in GENERIC_SHELL_SPECS.get(target_os, GENERIC_SHELL_SPECS.get("linux", [])):
        candidates.append((str(spec["id"]), str(spec["label"])))
    seen: set[str] = set()
    for shell_id, label in candidates:
        if shell_id in seen:
            continue
        seen.add(shell_id)
        resolved = shutil.which(shell_id)
        if not resolved:
            continue
        shells[shell_id] = shell_catalog_entry(shell_id, label, target_os, path=resolved)
    return shells


def build_local_shell_catalog() -> dict[str, dict[str, dict[str, Any]]]:
    catalog: dict[str, dict[str, dict[str, Any]]] = {key: {} for key in [item["id"] for item in TARGET_OS_OPTIONS]}
    if HOST_OS == "windows":
        catalog["windows"] = detect_windows_shells()
    elif HOST_OS in {"linux", "macos", "android"}:
        catalog[HOST_OS] = detect_posix_shells(HOST_OS)
    else:
        catalog[HOST_OS] = detect_posix_shells(HOST_OS)
    return catalog


def build_generic_shell_catalog() -> dict[str, dict[str, dict[str, Any]]]:
    catalog: dict[str, dict[str, dict[str, Any]]] = {}
    for option in TARGET_OS_OPTIONS:
        target_os = str(option["id"])
        items: dict[str, dict[str, Any]] = {}
        for spec in GENERIC_SHELL_SPECS.get(target_os, []):
            shell_id = str(spec["id"])
            items[shell_id] = shell_catalog_entry(shell_id, str(spec["label"]), target_os)
        catalog[target_os] = items
    return catalog


def infer_target_os_for_shell(shell_family: str) -> str:
    family = str(shell_family or "")
    lowered = family.lower()
    if lowered.startswith("wsl::") or lowered in {"pwsh", "powershell", "cmd", "gitbash"}:
        return "windows"
    if lowered in {"zsh"}:
        return "macos" if HOST_OS == "macos" else "linux"
    if lowered in {"bash", "sh", "fish", "dash", "ash"}:
        if HOST_OS in {"linux", "macos", "android"}:
            return HOST_OS
        return "linux"
    return HOST_OS


LOCAL_SHELL_CATALOG = build_local_shell_catalog()
GENERIC_SHELL_CATALOG = build_generic_shell_catalog()
LOCAL_SHELLS = LOCAL_SHELL_CATALOG.get(HOST_OS, {})
WINDOWS_SHELLS = LOCAL_SHELL_CATALOG.get("windows", {})
DEFAULT_LOCAL_SHELL = next(iter(LOCAL_SHELLS), None)
if HOST_OS == "windows":
    DEFAULT_LOCAL_SHELL = "pwsh" if "pwsh" in LOCAL_SHELLS else ("powershell" if "powershell" in LOCAL_SHELLS else DEFAULT_LOCAL_SHELL)
elif HOST_OS == "macos":
    DEFAULT_LOCAL_SHELL = "zsh" if "zsh" in LOCAL_SHELLS else ("bash" if "bash" in LOCAL_SHELLS else DEFAULT_LOCAL_SHELL)
else:
    DEFAULT_LOCAL_SHELL = "bash" if "bash" in LOCAL_SHELLS else ("sh" if "sh" in LOCAL_SHELLS else DEFAULT_LOCAL_SHELL)


def shell_definitions_for_scope(scope: str, target_os: str) -> dict[str, dict[str, Any]]:
    actual_target_os = target_os or HOST_OS
    if scope == "local":
        return LOCAL_SHELL_CATALOG.get(actual_target_os, {}) if actual_target_os == HOST_OS else {}
    return GENERIC_SHELL_CATALOG.get(actual_target_os, {})


def docker_cli_path() -> str | None:
    if os.name == "nt":
        return shutil_which_windows("docker.exe") or shutil.which("docker")
    return shutil.which("docker")


_DOCKER_STATUS_CACHE: dict[str, Any] = {"expires_at": 0.0, "value": None}


def docker_socket_candidates() -> list[str]:
    raw_candidates = [
        os.environ.get("ZENOTERM_DOCKER_SOCKET", ""),
        os.environ.get("DOCKER_SOCKET", ""),
        "/var/run/docker.sock",
        "/run/docker.sock",
        str(APP_DIR / ".docker" / "run" / "docker.sock"),
    ]
    values: list[str] = []
    for raw in raw_candidates:
        value = str(raw or "").strip()
        if not value:
            continue
        if value.startswith("unix://"):
            value = value[7:]
        if value not in values:
            values.append(value)
    return values


def docker_host_to_socket_path(host: str) -> str | None:
    value = str(host or "").strip()
    if not value:
        return None
    if value.startswith("unix://"):
        return value[7:]
    return None


def docker_socket_http_request(socket_path: str, path: str, method: str = "GET") -> tuple[int, bytes]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(8)
    try:
        client.connect(socket_path)
        request = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: docker\r\n"
            f"User-Agent: zenoterm\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("utf-8")
        client.sendall(request)
        chunks: list[bytes] = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
    finally:
        client.close()
    header_blob, _, body = raw.partition(b"\r\n\r\n")
    header_text = header_blob.decode("utf-8", errors="replace")
    status_line = header_text.splitlines()[0] if header_text else "HTTP/1.1 500 Error"
    try:
        status_code = int(status_line.split()[1])
    except Exception:
        status_code = 500
    return status_code, body


def docker_socket_json(socket_path: str, path: str) -> Any:
    status_code, body = docker_socket_http_request(socket_path, path)
    if status_code >= 400:
        raise RuntimeError(f"Docker socket respondió HTTP {status_code} para {path}")
    return json.loads(body.decode("utf-8", errors="replace") or "null")


def parse_docker_labels(raw_labels: Any) -> dict[str, str]:
    if isinstance(raw_labels, dict):
        return {str(key): str(value) for key, value in raw_labels.items()}
    labels: dict[str, str] = {}
    for part in str(raw_labels or "").split(","):
        item = part.strip()
        if not item:
            continue
        if "=" in item:
            key, value = item.split("=", 1)
            labels[key.strip()] = value.strip()
        else:
            labels[item] = ""
    return labels


def docker_connection_hints() -> dict[str, str]:
    hints: dict[str, str] = {}
    docker_host = str(os.environ.get("DOCKER_HOST") or "").strip()
    if docker_host:
        hints["docker_host"] = docker_host
        socket_path = docker_host_to_socket_path(docker_host)
        if socket_path:
            hints["socket_path"] = socket_path
    return hints


def run_docker_cli(
    args: list[str],
    timeout: int = 20,
    cwd: str | None = None,
    *,
    context: str | None = None,
    host: str | None = None,
) -> subprocess.CompletedProcess[str]:
    docker_bin = docker_cli_path()
    if not docker_bin:
        raise RuntimeError("No se ha encontrado el binario de Docker en el PATH del host.")
    cmd = [docker_bin]
    if host:
        cmd.extend(["--host", host])
    elif context:
        cmd.extend(["--context", context])
    cmd.extend(args)
    extra: dict[str, Any] = {"capture_output": True, "text": True, "timeout": timeout}
    if cwd:
        extra["cwd"] = cwd
    if os.name == "nt":
        extra["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(cmd, **extra)


def docker_cli_contexts() -> list[str]:
    docker_bin = docker_cli_path()
    if not docker_bin:
        return []
    preferred: list[str] = []
    try:
        current = run_docker_cli(["context", "show"], timeout=8)
        if current.returncode == 0:
            value = current.stdout.strip()
            if value:
                preferred.append(value)
    except Exception:
        pass
    try:
        listed = run_docker_cli(["context", "ls", "--format", "{{json .}}"], timeout=10)
        if listed.returncode == 0:
            for line in listed.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except Exception:
                    continue
                name = str(payload.get("Name") or "").replace("*", "").strip()
                if name and name not in preferred:
                    preferred.append(name)
    except Exception:
        pass
    for fallback in ["default", "desktop-linux", "desktop-windows"]:
        if fallback not in preferred:
            preferred.append(fallback)
    return preferred


def docker_socket_engine_status(socket_path: str) -> dict[str, Any] | None:
    try:
        payload = docker_socket_json(socket_path, "/version")
        if not isinstance(payload, dict):
            return None
        return {
            "available": True,
            "connected": True,
            "message": f"Docker Engine conectado vía socket ({socket_path}).",
            "cli_path": docker_cli_path() or "",
            "server_version": str(payload.get("Version") or ""),
            "client_version": "",
            "context": f"socket:{socket_path}",
            "connection_mode": "socket",
            "socket_path": socket_path,
            "docker_host": f"unix://{socket_path}",
        }
    except Exception:
        return None


def docker_cli_engine_status(context: str | None = None, host: str | None = None) -> dict[str, Any] | None:
    docker_bin = docker_cli_path()
    if not docker_bin:
        return None
    try:
        version = run_docker_cli(["version", "--format", "{{json .}}"], timeout=15, context=context, host=host)
        if version.returncode != 0 or not version.stdout.strip():
            return None
        payload = json.loads(version.stdout.strip())
        client = payload.get("Client") or {}
        server = payload.get("Server") or {}
        connected = bool(server)
        if not connected:
            return None
        status = {
            "available": True,
            "connected": True,
            "message": "Docker Engine conectado.",
            "cli_path": docker_bin,
            "server_version": str(server.get("Version") or ""),
            "client_version": str(client.get("Version") or ""),
            "context": context or "",
            "connection_mode": "cli",
            "socket_path": "",
            "docker_host": host or "",
        }
        if host:
            status["message"] = f"Docker Engine conectado vía host {host}."
        elif context:
            status["message"] = f"Docker Engine conectado vía contexto {context}."
        return status
    except Exception:
        return None


def docker_engine_status(force_refresh: bool = False) -> dict[str, Any]:
    now = time.time()
    cached = _DOCKER_STATUS_CACHE.get("value")
    if cached and not force_refresh and now < float(_DOCKER_STATUS_CACHE.get("expires_at") or 0):
        return cached
    docker_bin = docker_cli_path()
    unavailable = {
        "available": bool(docker_bin),
        "connected": False,
        "message": "Docker no está disponible en este host.",
        "cli_path": docker_bin or "",
        "server_version": "",
        "client_version": "",
        "context": "",
        "connection_mode": "none",
        "socket_path": "",
        "docker_host": "",
    }
    hints = docker_connection_hints()
    socket_candidates = []
    hinted_socket = hints.get("socket_path")
    if hinted_socket:
        socket_candidates.append(hinted_socket)
    for item in docker_socket_candidates():
        if item not in socket_candidates:
            socket_candidates.append(item)
    for socket_path in socket_candidates:
        if not socket_path or not Path(socket_path).exists():
            continue
        status = docker_socket_engine_status(socket_path)
        if status:
            _DOCKER_STATUS_CACHE["value"] = status
            _DOCKER_STATUS_CACHE["expires_at"] = now + 5
            return status
    docker_host = hints.get("docker_host") or ""
    if docker_host:
        status = docker_cli_engine_status(host=docker_host)
        if status:
            _DOCKER_STATUS_CACHE["value"] = status
            _DOCKER_STATUS_CACHE["expires_at"] = now + 5
            return status
    for context_name in docker_cli_contexts():
        status = docker_cli_engine_status(context=context_name)
        if status:
            _DOCKER_STATUS_CACHE["value"] = status
            _DOCKER_STATUS_CACHE["expires_at"] = now + 5
            return status
    if docker_bin:
        unavailable["message"] = "Docker CLI detectado, pero no se pudo conectar al engine."
    _DOCKER_STATUS_CACHE["value"] = unavailable
    _DOCKER_STATUS_CACHE["expires_at"] = now + 5
    return unavailable


def docker_cli_connection_kwargs() -> dict[str, str]:
    status = docker_engine_status()
    host = str(status.get("docker_host") or "").strip()
    if host:
        return {"host": host}
    context = str(status.get("context") or "").strip()
    if context and not context.startswith("socket:"):
        return {"context": context}
    return {}


def docker_command_prefix_args(status: dict[str, Any] | None = None) -> list[str]:
    effective_status = status or docker_engine_status()
    host = str(effective_status.get("docker_host") or "").strip()
    if host:
        return ["docker", "--host", host]
    context = str(effective_status.get("context") or "").strip()
    if context and not context.startswith("socket:"):
        return ["docker", "--context", context]
    return ["docker"]


def docker_command_prefix_string(status: dict[str, Any] | None = None) -> str:
    return " ".join(shlex.quote(part) for part in docker_command_prefix_args(status)) + " "


def docker_format_ports_from_socket(raw_ports: Any) -> list[str]:
    items: list[str] = []
    if not isinstance(raw_ports, list):
        return items
    for port in raw_ports:
        if not isinstance(port, dict):
            continue
        private = str(port.get("PrivatePort") or "")
        kind = str(port.get("Type") or "tcp")
        container_side = f"{private}/{kind}" if private else kind
        public = str(port.get("PublicPort") or "")
        ip = str(port.get("IP") or "")
        if public:
            host_part = f"{ip}:" if ip and ip not in {"0.0.0.0", "::"} else ""
            items.append(f"{host_part}{public}->{container_side}")
        elif container_side:
            items.append(container_side)
    return items


def normalize_socket_container_summary(raw: dict[str, Any]) -> dict[str, Any]:
    labels = parse_docker_labels(raw.get("Labels") or {})
    image_name = str(raw.get("Image") or "")
    name = str((raw.get("Names") or [""])[0] or "").lstrip("/")
    compose_files_raw = str(labels.get("com.docker.compose.project.config_files") or "")
    compose_files = [part.strip() for part in compose_files_raw.split(",") if part.strip()]
    compose_working_dir = str(labels.get("com.docker.compose.project.working_dir") or "").strip()
    compose_project = str(labels.get("com.docker.compose.project") or "").strip()
    compose_service = str(labels.get("com.docker.compose.service") or "").strip()
    container_os = container_guess_os(image_name, raw)
    shell_family = default_container_shell_for_os(container_os)
    status = docker_engine_status()
    startup_prefix = docker_command_prefix_string(status)
    mounts = []
    for mount in raw.get("Mounts") or []:
        if not isinstance(mount, dict):
            continue
        mounts.append({
            "source": str(mount.get("Source") or ""),
            "destination": str(mount.get("Destination") or ""),
            "type": str(mount.get("Type") or ""),
        })
    return {
        "id": str(raw.get("Id") or ""),
        "short_id": str(raw.get("Id") or "")[:12],
        "name": name,
        "image": image_name,
        "created": str(raw.get("Created") or ""),
        "running": str(raw.get("State") or "").lower() == "running",
        "state": str(raw.get("State") or "unknown"),
        "status_text": str(raw.get("Status") or raw.get("State") or "unknown"),
        "exit_code": 0,
        "started_at": "",
        "finished_at": "",
        "compose_project": compose_project,
        "compose_service": compose_service,
        "compose_working_dir": compose_working_dir,
        "compose_files": compose_files,
        "stack_key": f"{compose_project}|{compose_working_dir}|{'|'.join(compose_files)}" if (compose_project or compose_working_dir or compose_files) else "",
        "shell_family": shell_family,
        "container_os": container_os,
        "startup_command": docker_exec_startup_command(name, container_os, shell_family, docker_prefix=startup_prefix),
        "mounts": mounts,
        "ports": docker_format_ports_from_socket(raw.get("Ports") or []),
        "labels": labels,
    }


def normalize_cli_container_summary(raw: dict[str, Any]) -> dict[str, Any]:
    labels = parse_docker_labels(raw.get("Labels") or raw.get("Label") or "")
    image_name = str(raw.get("Image") or "")
    name = str(raw.get("Names") or raw.get("Name") or "").strip()
    compose_files_raw = str(labels.get("com.docker.compose.project.config_files") or "")
    compose_files = [part.strip() for part in compose_files_raw.split(",") if part.strip()]
    compose_working_dir = str(labels.get("com.docker.compose.project.working_dir") or "").strip()
    compose_project = str(labels.get("com.docker.compose.project") or "").strip()
    compose_service = str(labels.get("com.docker.compose.service") or "").strip()
    container_os = container_guess_os(image_name, raw)
    shell_family = default_container_shell_for_os(container_os)
    status = docker_engine_status()
    startup_prefix = docker_command_prefix_string(status)
    state = str(raw.get("State") or "").strip().lower()
    return {
        "id": str(raw.get("ID") or raw.get("Id") or ""),
        "short_id": str(raw.get("ID") or raw.get("Id") or "")[:12],
        "name": name,
        "image": image_name,
        "created": str(raw.get("CreatedAt") or ""),
        "running": state == "running",
        "state": state or str(raw.get("Status") or "unknown").split(" ", 1)[0].lower(),
        "status_text": str(raw.get("Status") or state or "unknown"),
        "exit_code": 0,
        "started_at": "",
        "finished_at": "",
        "compose_project": compose_project,
        "compose_service": compose_service,
        "compose_working_dir": compose_working_dir,
        "compose_files": compose_files,
        "stack_key": f"{compose_project}|{compose_working_dir}|{'|'.join(compose_files)}" if (compose_project or compose_working_dir or compose_files) else "",
        "shell_family": shell_family,
        "container_os": container_os,
        "startup_command": docker_exec_startup_command(name, container_os, shell_family, docker_prefix=startup_prefix),
        "mounts": [],
        "ports": [part.strip() for part in str(raw.get("Ports") or "").split(",") if part.strip()],
        "labels": labels,
    }


def list_docker_containers_via_socket(socket_path: str, include_stopped: bool = True) -> list[dict[str, Any]]:
    payload = docker_socket_json(socket_path, f"/containers/json?all={1 if include_stopped else 0}")
    if not isinstance(payload, list):
        return []
    return [normalize_socket_container_summary(item) for item in payload if isinstance(item, dict)]


def list_docker_containers_via_cli(include_stopped: bool = True) -> list[dict[str, Any]]:
    args = ["ps"]
    if include_stopped:
        args.append("-a")
    args.extend(["--no-trunc", "--format", "{{json .}}"])
    result = run_docker_cli(args, timeout=20, **docker_cli_connection_kwargs())
    if result.returncode != 0:
        return []
    items: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except Exception:
            continue
        if isinstance(payload, dict):
            items.append(normalize_cli_container_summary(payload))
    return items


def list_docker_containers(include_stopped: bool = True) -> list[dict[str, Any]]:
    status = docker_engine_status()
    if not status.get("connected"):
        return []
    try:
        if str(status.get("connection_mode") or "") == "socket" and str(status.get("socket_path") or ""):
            items = list_docker_containers_via_socket(str(status.get("socket_path") or ""), include_stopped=include_stopped)
        else:
            items = list_docker_containers_via_cli(include_stopped=include_stopped)
    except Exception:
        items = []
    items.sort(key=lambda item: (0 if item.get("running") else 1, str(item.get("compose_project") or "~"), str(item.get("name") or "")))
    return items


def container_guess_os(image_name: str, inspect_data: dict[str, Any]) -> str:
    image_lower = str(image_name or "").lower()
    path_value = str(inspect_data.get("Path") or "")
    args_value = " ".join(str(part) for part in (inspect_data.get("Args") or []))
    combined = f"{path_value} {args_value} {image_lower}".lower()
    if any(token in combined for token in ["powershell", "pwsh", "cmd.exe", "nanoserver", "windowsservercore"]):
        return "windows"
    return "linux"


def default_container_shell_for_os(container_os: str) -> str:
    if container_os == "windows":
        return "pwsh" if HOST_OS == "windows" else "powershell"
    return "bash"


def docker_exec_startup_command(container_name: str, container_os: str, shell_family: str, docker_prefix: str = "docker ") -> str:
    safe_name = str(container_name or "").strip()
    prefix = docker_prefix if docker_prefix.endswith(" ") else f"{docker_prefix} "
    if container_os == "windows":
        shell = shell_family if shell_family in {"pwsh", "powershell", "cmd"} else "powershell"
        command = "pwsh" if shell == "pwsh" else ("cmd.exe" if shell == "cmd" else "powershell.exe")
        return f'{prefix}exec -it "{safe_name}" {command}'
    shell = shell_family if shell_family in {"bash", "sh", "ash", "zsh", "fish", "dash"} else "bash"
    if shell == "bash":
        return f'{prefix}exec -it "{safe_name}" sh -lc "command -v bash >/dev/null 2>&1 && exec bash || exec sh"'
    if shell == "ash":
        return f'{prefix}exec -it "{safe_name}" sh -lc "command -v ash >/dev/null 2>&1 && exec ash || exec sh"'
    return f'{prefix}exec -it "{safe_name}" {shell}'


def list_docker_containers(include_stopped: bool = True) -> list[dict[str, Any]]:
    status = docker_engine_status()
    if not status.get("connected"):
        return []
    try:
        if str(status.get("connection_mode") or "") == "socket" and str(status.get("socket_path") or ""):
            items = list_docker_containers_via_socket(str(status.get("socket_path") or ""), include_stopped=include_stopped)
        else:
            items = list_docker_containers_via_cli(include_stopped=include_stopped)
    except Exception:
        items = []
    items.sort(key=lambda item: (0 if item.get("running") else 1, str(item.get("compose_project") or "~"), str(item.get("name") or "")))
    return items


def build_docker_targets(session_id: str | None = None) -> list[dict[str, Any]]:
    effective_session_id = normalize_terminal_session_id(session_id or get_active_session_id())
    host_shell = DEFAULT_LOCAL_SHELL or next(iter(LOCAL_SHELLS), "")
    if not host_shell:
        return []
    host_launch_command = build_default_launch_command(host_shell)
    items: list[dict[str, Any]] = []
    for container in list_docker_containers(include_stopped=False):
        items.append({
            "id": f"docker::{container['id']}",
            "label": f"Docker: {container['name']}",
            "mode": "direct",
            "connection_scope": "docker",
            "auth_type": "none",
            "description": f"{container['image']} · {container['state']}" + (f" · stack {container['compose_project']}" if container.get('compose_project') else ""),
            "shell_id": host_shell,
            "shell_family": str(container.get("shell_family") or "bash"),
            "target_os": HOST_OS,
            "startup_command": str(container.get("startup_command") or ""),
            "command_file_content": "",
            "preset_name": str(container.get("name") or ""),
            "shell_label": f"Contenedor {container['name']}",
            "launch_command": host_launch_command,
            "alias_support": alias_capability_for_shell(str(container.get("shell_family") or "bash")),
            "workspace_dir": str(container.get("compose_working_dir") or APP_DIR),
            "detected_local": True,
            "open_by_default": False,
            "session_id": effective_session_id,
            "docker_container_id": str(container.get("id") or ""),
            "docker_container_name": str(container.get("name") or ""),
            "docker_image": str(container.get("image") or ""),
            "docker_state": str(container.get("state") or "unknown"),
        })
    return items


def normalize_docker_group_entry(item: Any, order_index: int = 0) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    container_id = str(item.get("container_id") or item.get("id") or "").strip()
    name = str(item.get("name") or item.get("container_name") or "").strip()
    if not container_id and not name:
        return None
    compose_files = [str(value).strip() for value in (item.get("compose_files") or []) if str(value).strip()]
    try:
        order_number = int(item.get("order"))
    except Exception:
        order_number = order_index + 1
    return {
        "container_id": container_id,
        "name": name,
        "image": str(item.get("image") or "").strip(),
        "order": max(1, order_number),
        "compose_project": str(item.get("compose_project") or "").strip(),
        "compose_service": str(item.get("compose_service") or "").strip(),
        "compose_working_dir": str(item.get("compose_working_dir") or "").strip(),
        "compose_files": compose_files,
        "stack_key": str(item.get("stack_key") or "").strip(),
    }


def normalize_docker_group(item: Any, index: int = 0) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    name = str(item.get("name") or "").strip()
    if not name:
        return None
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry_index, raw in enumerate(item.get("entries") or []):
        normalized = normalize_docker_group_entry(raw, entry_index)
        if not normalized:
            continue
        key = normalized.get("container_id") or normalized.get("name")
        if key in seen:
            continue
        seen.add(str(key))
        entries.append(normalized)
    entries.sort(key=lambda entry: (int(entry.get("order") or 9999), str(entry.get("name") or entry.get("container_id") or "")))
    return {
        "id": str(item.get("id") or f"docker-group-{index + 1}"),
        "name": name,
        "description": str(item.get("description") or "").strip(),
        "default_run_mode": str(item.get("default_run_mode") or "normal").strip() or "normal",
        "entries": entries,
        "script_name": str(item.get("script_name") or "").strip(),
    }


def get_docker_groups() -> list[dict[str, Any]]:
    raw = (CONFIG.get("docker_management") or {}).get("groups") or []
    groups = [normalize_docker_group(item, index) for index, item in enumerate(raw)]
    return [item for item in groups if item]


def save_docker_groups(groups: list[dict[str, Any]]) -> None:
    current = load_config()
    docker_section = current.get("docker_management") or {}
    clean_groups: list[dict[str, Any]] = []
    for index, item in enumerate(groups or []):
        normalized = normalize_docker_group(item, index)
        if normalized:
            clean_groups.append(normalized)
    docker_section["groups"] = clean_groups
    current["docker_management"] = docker_section
    save_config(current)
    global CONFIG
    CONFIG = current


def build_docker_overview() -> dict[str, Any]:
    engine = docker_engine_status()
    containers = list_docker_containers(include_stopped=True)
    running = [item for item in containers if item.get("running")]
    stopped = [item for item in containers if not item.get("running")]
    return {
        "engine": engine,
        "host_os": HOST_OS,
        "host_os_label": TARGET_OS_LABELS.get(HOST_OS, HOST_OS),
        "containers": containers,
        "running_count": len(running),
        "stopped_count": len(stopped),
        "groups": get_docker_groups(),
        "targets": [item for item in public_targets() if str(item.get("connection_scope") or "") == "docker"],
    }


def docker_compose_command_prefix(entry: dict[str, Any]) -> list[str] | None:
    compose_working_dir = str(entry.get("compose_working_dir") or "").strip()
    compose_files = [str(item).strip() for item in (entry.get("compose_files") or []) if str(item).strip()]
    compose_project = str(entry.get("compose_project") or "").strip()
    if not compose_working_dir and not compose_files and not compose_project:
        return None
    command = ["compose"]
    if compose_project:
        command.extend(["-p", compose_project])
    for compose_file in compose_files:
        command.extend(["-f", compose_file])
    return command


def build_group_command(entry: dict[str, Any], run_mode: str) -> tuple[list[str], str | None]:
    container_name = str(entry.get("name") or entry.get("container_id") or "").strip()
    compose_prefix = docker_compose_command_prefix(entry)
    if compose_prefix and entry.get("compose_service"):
        cmd = [*compose_prefix, "up", "-d"]
        if "pull" in run_mode:
            cmd.extend(["--pull", "always"])
        if "force" in run_mode:
            cmd.append("--force-recreate")
        cmd.append(str(entry.get("compose_service") or ""))
        return cmd, str(entry.get("compose_working_dir") or "") or None
    return ["start", container_name], None


def run_docker_group(group_id: str, requested_mode: str = "") -> dict[str, Any]:
    groups = {str(item.get("id") or ""): item for item in get_docker_groups()}
    group = groups.get(group_id)
    if not group:
        raise RuntimeError("Grupo Docker no encontrado.")
    run_mode = str(requested_mode or group.get("default_run_mode") or "normal").strip() or "normal"
    logs: list[dict[str, Any]] = []
    success = True
    for entry in sorted(group.get("entries") or [], key=lambda item: (int(item.get("order") or 9999), str(item.get("name") or item.get("container_id") or ""))):
        command, cwd = build_group_command(entry, run_mode)
        result = run_docker_cli(command, timeout=180, cwd=cwd, **docker_cli_connection_kwargs())
        ok = result.returncode == 0
        success = success and ok
        logs.append({
            "entry": str(entry.get("name") or entry.get("container_id") or ""),
            "order": int(entry.get("order") or 0),
            "ok": ok,
            "command": "docker " + " ".join(command),
            "stdout": str(result.stdout or "").strip(),
            "stderr": str(result.stderr or "").strip(),
        })
    return {"ok": success, "group": group, "run_mode": run_mode, "logs": logs}


def create_group_script_file(group_id: str, import_to_app: bool = True) -> dict[str, Any]:
    groups = {str(item.get("id") or ""): item for item in get_docker_groups()}
    group = groups.get(group_id)
    if not group:
        raise RuntimeError("Grupo Docker no encontrado.")
    DOCKER_SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", str(group.get("name") or group_id)).strip("._-") or group_id
    script_filename = f"{safe_name}.py"
    script_path = DOCKER_SCRIPTS_DIR / script_filename
    payload = json.dumps(group, ensure_ascii=False, indent=2)
    docker_base = json.dumps(docker_command_prefix_args(), ensure_ascii=False)
    script_template = '''from __future__ import annotations

import json
import subprocess
import sys

GROUP = json.loads(r"""__PAYLOAD__""")
DOCKER_BASE = json.loads(r"""__DOCKER_BASE__""")
RUN_MODE = sys.argv[1] if len(sys.argv) > 1 else str(GROUP.get("default_run_mode") or "normal")


def run(cmd, cwd=None):
    print("[docker-script]", " ".join([*DOCKER_BASE, *cmd]))
    completed = subprocess.run([*DOCKER_BASE, *cmd], cwd=cwd or None, text=True)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def compose_prefix(entry):
    command = ["compose"]
    if entry.get("compose_project"):
        command += ["-p", entry["compose_project"]]
    for compose_file in entry.get("compose_files") or []:
        command += ["-f", compose_file]
    return command


def build_command(entry, run_mode):
    if entry.get("compose_service") and (entry.get("compose_working_dir") or entry.get("compose_files") or entry.get("compose_project")):
        cmd = compose_prefix(entry) + ["up", "-d"]
        if "pull" in run_mode:
            cmd += ["--pull", "always"]
        if "force" in run_mode:
            cmd += ["--force-recreate"]
        cmd += [entry["compose_service"]]
        return cmd, entry.get("compose_working_dir") or None
    return ["start", entry.get("name") or entry.get("container_id") or ""], None


def main():
    entries = sorted(GROUP.get("entries") or [], key=lambda item: (int(item.get("order") or 9999), str(item.get("name") or item.get("container_id") or "")))
    if not entries:
        print("El grupo no tiene contenedores.")
        return
    for entry in entries:
        cmd, cwd = build_command(entry, RUN_MODE)
        run(cmd, cwd)
    print(f"Grupo Docker lanzado: {GROUP.get('name')} · modo={RUN_MODE}")


if __name__ == "__main__":
    main()
'''
    script_path.write_text(script_template.replace('__PAYLOAD__', payload).replace('__DOCKER_BASE__', docker_base), encoding='utf-8')
    if import_to_app:
        current = load_config()
        current.setdefault("docker_management", {})
        for item in current["docker_management"].get("groups") or []:
            if str(item.get("id") or "") == group_id:
                item["script_name"] = script_filename
        save_config(current)
        global CONFIG
        CONFIG = current
    return {"ok": True, "group": group, "script_path": str(script_path), "script_name": script_filename}


def refresh_target_cache(session_id: str | None = None) -> list[dict[str, Any]]:
    global TARGETS, TARGETS_BY_ID
    TARGETS = build_targets(session_id or get_active_session_id())
    TARGETS_BY_ID = {str(item["id"]): item for item in TARGETS}
    return TARGETS


def windows_to_posix_path(path_value: str) -> str:
    value = str(path_value or '').replace('\\', '/')
    if len(value) >= 2 and value[1] == ':':
        return f"/{value[0].lower()}{value[2:]}"
    return value


def build_default_launch_command(shell_family: str) -> str:
    if shell_family.startswith("wsl::"):
        distro = shell_family.split("::", 1)[1]
        return f'wsl.exe -d "{distro}"'
    mapping = {
        "pwsh": "pwsh",
        "powershell": "powershell.exe",
        "cmd": "cmd.exe",
        "gitbash": "bash",
        "bash": "bash",
        "zsh": "zsh",
        "fish": "fish",
        "sh": "sh",
        "dash": "dash",
        "ash": "ash",
    }
    return mapping.get(shell_family, shell_family or "")


def alias_capability_for_shell(shell_family: str) -> str:
    family = str(shell_family or "").lower()
    if family in {"pwsh", "powershell"}:
        return "powershell"
    if family == "cmd":
        return "cmd"
    if family in {"gitbash", "bash", "zsh", "fish", "sh", "dash", "ash"} or family.startswith("wsl::") or family == "wsl":
        return "posix"
    return family or "generic"


def alias_group_label(alias_group: str) -> str:
    mapping = {
        "powershell": "PowerShell",
        "cmd": "CMD",
        "posix": "POSIX / Bash / WSL",
        "generic": "Genérico",
    }
    return mapping.get(alias_group, alias_group)


def get_alias_store() -> dict[str, list[dict[str, str]]]:
    raw = CONFIG.get("app_aliases") or {}
    if not isinstance(raw, dict):
        return {}
    store: dict[str, list[dict[str, str]]] = {}
    for key, items in raw.items():
        if not isinstance(key, str) or not isinstance(items, list):
            continue
        normalized_items: list[dict[str, str]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            command = str(item.get("command") or "").strip()
            if not name or not command:
                continue
            normalized_items.append({
                "id": str(item.get("id") or secrets.token_hex(8)),
                "name": name,
                "command": command,
                "folder": normalize_alias_folder(str(item.get("folder") or "")),
                "terminal_type": str(item.get("terminal_type") or key),
            })
        store[key] = normalized_items
    return store


def save_alias_store(store: dict[str, list[dict[str, str]]]) -> None:
    global CONFIG
    current = load_config()
    current["app_aliases"] = store
    save_config(current)
    CONFIG = current


def alias_group_for_target(target: dict[str, Any]) -> str:
    return alias_capability_for_shell(str(target.get("shell_family") or ""))


def normalize_alias_folder(folder: str) -> str:
    value = str(folder or "").strip().replace("\\", "/")
    while "//" in value:
        value = value.replace("//", "/")
    value = value.strip("/")
    return value or "default-group"

def list_aliases_for_target(target: dict[str, Any]) -> list[dict[str, str]]:
    alias_group = alias_group_for_target(target)
    items = list(get_alias_store().get(alias_group, []))
    return sorted(items, key=lambda item: (normalize_alias_folder(str(item.get("folder") or "")).casefold(), str(item.get("name") or "").casefold(), str(item.get("command") or "").casefold()))


def create_alias_for_target(target: dict[str, Any], alias_name: str, command_text: str, folder: str = "") -> dict[str, str]:
    alias_group = alias_group_for_target(target)
    store = get_alias_store()
    items = list(store.get(alias_group, []))
    lowered = alias_name.casefold()
    normalized_folder = normalize_alias_folder(folder)
    items = [item for item in items if not (str(item.get("name") or "").casefold() == lowered and normalize_alias_folder(str(item.get("folder") or "")) == normalized_folder)]
    entry = {
        "id": secrets.token_hex(8),
        "name": alias_name,
        "command": command_text,
        "folder": normalized_folder,
        "terminal_type": alias_group,
    }
    items.insert(0, entry)
    store[alias_group] = items
    save_alias_store(store)
    return entry


def delete_alias_for_target(target: dict[str, Any], alias_id: str) -> bool:
    alias_group = alias_group_for_target(target)
    store = get_alias_store()
    items = list(store.get(alias_group, []))
    filtered = [item for item in items if str(item.get("id") or "") != alias_id]
    if len(filtered) == len(items):
        return False
    store[alias_group] = filtered
    save_alias_store(store)
    return True


def shell_launch_input_for_profile(profile: str, distro: str | None = None) -> str | None:
    mapping = {
        "pwsh": "pwsh",
        "powershell": "powershell.exe",
        "cmd": "cmd.exe",
        "gitbash": "bash",
        "bash": "bash",
        "zsh": "zsh",
        "fish": "fish",
        "sh": "sh",
        "dash": "dash",
        "ash": "ash",
    }
    if profile in mapping:
        return mapping[profile]
    if profile.startswith("wsl:") or profile.startswith("wsl::") or profile == "wsl" or distro:
        actual = distro or (profile.split("::", 1)[1] if "::" in profile else (profile.split(":", 1)[1] if ":" in profile else ""))
        if actual:
            return f'wsl.exe -d "{actual}"'
        return "wsl.exe"
    return None


def get_ui_config() -> dict[str, Any]:
    ui = CONFIG.get("ui") or {}
    return {
        "default_scrollback": int(ui.get("default_scrollback") or 20000),
        "command_history_limit": max(1, int(ui.get("command_history_limit") or 50)),
    }


def legacy_local_override_for_shell(shell_id: str) -> dict[str, Any]:
    presets = CONFIG.get("terminal_presets")
    if not isinstance(presets, list):
        return {}
    for item in presets:
        if not isinstance(item, dict):
            continue
        if str(item.get("scope") or "local") != "local":
            continue
        if str(item.get("shell_family") or "") != shell_id:
            continue
        return item
    return {}


def build_detected_local_presets() -> list[dict[str, Any]]:
    presets: list[dict[str, Any]] = []
    overrides = CONFIG.get("local_terminal_overrides") or {}
    if not isinstance(overrides, dict):
        overrides = {}

    for shell_id, shell in LOCAL_SHELLS.items():
        raw_override = overrides.get(shell_id) or legacy_local_override_for_shell(shell_id) or {}
        if not isinstance(raw_override, dict):
            raw_override = {}
        presets.append({
            "id": f"local::{shell_id}",
            "name": str(raw_override.get("name") or shell.get("label") or shell_id),
            "scope": "local",
            "auth_type": "none",
            "target_os": HOST_OS,
            "shell_family": shell_id,
            "host": "",
            "port": 22,
            "username": "",
            "private_key_path": "",
            "strict_host_key": False,
            "startup_command": str(raw_override.get("startup_command") or ""),
            "command_file_content": str(raw_override.get("command_file_content") or ""),
            "launch_command": str(raw_override.get("launch_command") or build_default_launch_command(shell_id)),
            "detected_local": True,
            "editable_scope": False,
            "editable_target_os": False,
            "editable_remove": False,
            "open_by_default": bool(raw_override.get("open_by_default", False)),
        })
    return presets


def build_default_remote_terminal_presets() -> list[dict[str, Any]]:
    presets: list[dict[str, Any]] = []
    remote_defaults = CONFIG.get("remote_defaults") or {}
    default_host = str(remote_defaults.get("host") or "")
    default_port = int(remote_defaults.get("port") or 22)
    default_username = str(remote_defaults.get("username") or "")
    default_key_path = str(remote_defaults.get("private_key_path") or "")
    default_strict = bool(remote_defaults.get("strict_host_key", True))

    default_remote_os = "linux" if "linux" in GENERIC_SHELL_CATALOG else (HOST_OS if HOST_OS in GENERIC_SHELL_CATALOG else next(iter(GENERIC_SHELL_CATALOG), HOST_OS))
    default_remote_shells = GENERIC_SHELL_CATALOG.get(default_remote_os) or {}
    default_shell_id = "bash" if "bash" in default_remote_shells else ("sh" if "sh" in default_remote_shells else next(iter(default_remote_shells), ""))
    launch_command = shell_launch_input_for_profile(default_shell_id) or ""

    presets.append({
        "id": "remote-password",
        "name": "SSH Remote · User/Pass",
        "scope": "remote",
        "auth_type": "password",
        "target_os": default_remote_os,
        "shell_family": default_shell_id,
        "host": default_host,
        "port": default_port,
        "username": default_username,
        "private_key_path": "",
        "strict_host_key": default_strict,
        "startup_command": launch_command,
        "command_file_content": "",
        "launch_command": build_default_launch_command(default_shell_id),
        "detected_local": False,
        "editable_scope": True,
        "editable_target_os": True,
        "editable_remove": True,
        "open_by_default": False,
    })
    presets.append({
        "id": "remote-key",
        "name": "SSH Remote · Public/Private Key",
        "scope": "remote",
        "auth_type": "key",
        "target_os": default_remote_os,
        "shell_family": default_shell_id,
        "host": default_host,
        "port": default_port,
        "username": default_username,
        "private_key_path": default_key_path,
        "strict_host_key": default_strict,
        "startup_command": launch_command,
        "command_file_content": "",
        "launch_command": build_default_launch_command(default_shell_id),
        "detected_local": False,
        "editable_scope": True,
        "editable_target_os": True,
        "editable_remove": True,
        "open_by_default": False,
    })
    return presets



NO_SESSION_TARGET_TOKEN = "__no_session__"


def normalize_terminal_session_id(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip("-._")
    return clean or "default"


def normalize_optional_session_id(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip("-._")


def normalize_user_terminal_sessions(raw: Any) -> list[dict[str, str]]:
    sessions: list[dict[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            raw_name = str(item.get("name") or "").strip()
            session_id = normalize_optional_session_id(item.get("id") or raw_name or "")
            if not session_id or not raw_name:
                continue
            if any(existing["id"] == session_id for existing in sessions):
                continue
            sessions.append({"id": session_id, "name": raw_name})
    return sessions


def normalize_session_override_map(raw: Any, valid_session_ids: set[str]) -> dict[str, dict[str, dict[str, Any]]]:
    if not isinstance(raw, dict):
        return {}
    result: dict[str, dict[str, dict[str, Any]]] = {}
    allowed_fields = {
        "name", "scope", "auth_type", "target_os", "shell_family", "host", "port", "username",
        "private_key_path", "strict_host_key", "startup_command", "command_file_content",
        "launch_command", "open_by_default"
    }
    for session_id, mapping in raw.items():
        normalized_session_id = normalize_optional_session_id(session_id)
        if normalized_session_id not in valid_session_ids or not isinstance(mapping, dict):
            continue
        session_map: dict[str, dict[str, Any]] = {}
        for preset_id, override in mapping.items():
            if not isinstance(override, dict):
                continue
            normalized_override = {key: override[key] for key in allowed_fields if key in override}
            if normalized_override:
                session_map[str(preset_id)] = normalized_override
        if session_map:
            result[normalized_session_id] = session_map
    return result


def get_terminal_sessions(user: dict[str, Any] | None = None) -> list[dict[str, str]]:
    if user is not None:
        return normalize_user_terminal_sessions(user.get("terminal_sessions") or [])
    raw = CONFIG.get("terminal_sessions")
    sessions: list[dict[str, str]] = []
    if isinstance(raw, list):
        for item in raw:
            if not isinstance(item, dict):
                continue
            session_id = normalize_terminal_session_id(str(item.get("id") or item.get("name") or ""))
            name = str(item.get("name") or session_id).strip() or session_id
            if not any(existing["id"] == session_id for existing in sessions):
                sessions.append({"id": session_id, "name": name})
    if not any(item["id"] == "default" for item in sessions):
        sessions.insert(0, {"id": "default", "name": "Sesión principal"})
    return sessions or [{"id": "default", "name": "Sesión principal"}]


def get_user_default_session_id(user: dict[str, Any] | None) -> str:
    if not user:
        return ""
    valid_ids = {item["id"] for item in get_terminal_sessions(user)}
    default_session_id = normalize_optional_session_id(user.get("default_session_id"))
    return default_session_id if default_session_id in valid_ids else ""


def get_session_terminal_overrides(user: dict[str, Any] | None = None) -> dict[str, dict[str, dict[str, Any]]]:
    if user is not None:
        valid_sessions = {item["id"] for item in get_terminal_sessions(user)}
        return normalize_session_override_map(user.get("session_terminal_overrides") or {}, valid_sessions)
    raw = CONFIG.get("session_terminal_overrides") or {}
    valid_sessions = {item["id"] for item in get_terminal_sessions()}
    return normalize_session_override_map(raw, valid_sessions)


def get_user_session_terminal_overrides(user: dict[str, Any] | None) -> dict[str, dict[str, dict[str, Any]]]:
    return get_session_terminal_overrides(user)


def get_active_session_id(user: dict[str, Any] | None = None, session_record: dict[str, Any] | None = None) -> str:
    if user is not None:
        valid_ids = {item["id"] for item in get_terminal_sessions(user)}
        candidate = normalize_optional_session_id((session_record or {}).get("active_session_id"))
        if candidate and candidate in valid_ids:
            return candidate
        default_session_id = get_user_default_session_id(user)
        return default_session_id if default_session_id in valid_ids else ""
    active = normalize_terminal_session_id(str(CONFIG.get("active_session_id") or "default"))
    valid_ids = {item["id"] for item in get_terminal_sessions()}
    return active if active in valid_ids else "default"


def session_target_scope_token(session_id: str | None) -> str:
    normalized = normalize_optional_session_id(session_id)
    return normalized or NO_SESSION_TARGET_TOKEN


def make_scoped_target_id(session_id: str | None, base_target_id: str) -> str:
    return f"session::{session_target_scope_token(session_id)}@@{base_target_id}"


def split_scoped_target_id(target_id: str) -> tuple[str | None, str]:
    raw = str(target_id or "").strip()
    if raw.startswith("session::") and "@@" in raw:
        token, base_target_id = raw.split("@@", 1)
        token_value = token.split("session::", 1)[1]
        return ("" if token_value == NO_SESSION_TARGET_TOKEN else normalize_optional_session_id(token_value)), base_target_id
    return None, raw


def get_stored_user_presets() -> list[dict[str, Any]]:
    presets = CONFIG.get("terminal_presets")
    if not isinstance(presets, list):
        return []
    items: list[dict[str, Any]] = []
    for item in presets:
        if isinstance(item, dict):
            items.append(item)
    return items


def get_base_terminal_presets() -> list[dict[str, Any]]:
    user_presets = get_stored_user_presets()
    has_remote = any(str(item.get("scope") or "local") == "remote" for item in user_presets)
    if not has_remote:
        user_presets = user_presets + build_default_remote_terminal_presets()
    return build_detected_local_presets() + user_presets


def apply_session_override_to_preset(
    preset: dict[str, Any],
    session_id: str | None = None,
    user: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if user is not None:
        active_session = normalize_optional_session_id(session_id)
        if not active_session:
            return normalize_preset(preset, 0)
        overrides = get_session_terminal_overrides(user).get(active_session) or {}
    else:
        active_session = normalize_terminal_session_id(session_id or get_active_session_id())
        if active_session == "default":
            return normalize_preset(preset, 0)
        overrides = get_session_terminal_overrides().get(active_session) or {}
    override = overrides.get(str(preset.get("id") or "")) or {}
    merged = dict(preset)
    merged.update(override)
    merged["id"] = str(preset.get("id") or merged.get("id") or "")
    merged["detected_local"] = bool(preset.get("detected_local") or merged.get("detected_local"))
    merged["editable_scope"] = bool(preset.get("editable_scope", merged.get("editable_scope", True)))
    merged["editable_target_os"] = bool(preset.get("editable_target_os", merged.get("editable_target_os", True)))
    merged["editable_remove"] = bool(preset.get("editable_remove", merged.get("editable_remove", True)))
    return normalize_preset(merged, 0)


def get_effective_terminal_presets(
    session_id: str | None = None,
    user: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    return [apply_session_override_to_preset(item, session_id, user=user) for item in get_base_terminal_presets()]

SCRIPT_VARIANT_KEYS = ("default", "powershell", "cmd", "posix", "generic")
DISCOVERABLE_SCRIPT_EXTENSIONS = {".py", ".ps1", ".sh", ".bash", ".cmd", ".bat"}


def normalize_script_variant(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        item = {}
    path_value = str(item.get("path") or "").strip()
    command_value = str(item.get("command") or "").strip()
    args_value = str(item.get("args") or item.get("flags") or item.get("params") or "").strip()
    enabled = bool(item.get("enabled", bool(path_value or command_value or args_value)))
    return {"enabled": enabled, "path": path_value, "command": command_value, "args": args_value}


def prettify_script_name(value: str) -> str:
    text_value = re.sub(r"[_\-]+", " ", value).strip()
    return text_value[:1].upper() + text_value[1:] if text_value else "Script"


def normalize_script_source_path(value: str) -> str:
    normalized = str(value or "").replace('\\', '/').strip().strip('/')
    return normalized


def build_script_variant_defaults(relative_path: str) -> dict[str, dict[str, Any]]:
    suffix = Path(relative_path).suffix.lower()
    rel_arg = relative_path.replace('\\', '/')
    base_path = str(APP_DIR)
    if suffix == '.py':
        return {
            'default': {'enabled': True, 'path': base_path, 'command': 'python', 'args': rel_arg},
            'powershell': {'enabled': True, 'path': base_path, 'command': 'python', 'args': rel_arg},
            'cmd': {'enabled': True, 'path': base_path, 'command': 'python', 'args': rel_arg},
            'posix': {'enabled': True, 'path': base_path, 'command': 'python3', 'args': rel_arg},
            'generic': {'enabled': True, 'path': base_path, 'command': 'python3', 'args': rel_arg},
        }
    if suffix == '.ps1':
        quoted = rel_arg.replace('"', '`"')
        return {
            'default': {'enabled': True, 'path': base_path, 'command': 'pwsh', 'args': f'-File "{quoted}"'},
            'powershell': {'enabled': True, 'path': base_path, 'command': 'pwsh', 'args': f'-File "{quoted}"'},
            'cmd': {'enabled': True, 'path': base_path, 'command': 'powershell', 'args': f'-ExecutionPolicy Bypass -File "{rel_arg}"'},
            'posix': {'enabled': False, 'path': base_path, 'command': '', 'args': ''},
            'generic': {'enabled': False, 'path': base_path, 'command': '', 'args': ''},
        }
    if suffix in {'.sh', '.bash'}:
        quoted = rel_arg.replace('"', '\"')
        return {
            'default': {'enabled': True, 'path': base_path, 'command': 'bash', 'args': quoted},
            'powershell': {'enabled': True, 'path': base_path, 'command': 'bash', 'args': quoted},
            'cmd': {'enabled': True, 'path': base_path, 'command': 'bash', 'args': quoted},
            'posix': {'enabled': True, 'path': base_path, 'command': 'bash', 'args': quoted},
            'generic': {'enabled': True, 'path': base_path, 'command': 'bash', 'args': quoted},
        }
    if suffix in {'.cmd', '.bat'}:
        quoted = rel_arg.replace('"', '\"')
        return {
            'default': {'enabled': True, 'path': base_path, 'command': quoted, 'args': ''},
            'powershell': {'enabled': True, 'path': base_path, 'command': quoted, 'args': ''},
            'cmd': {'enabled': True, 'path': base_path, 'command': quoted, 'args': ''},
            'posix': {'enabled': False, 'path': base_path, 'command': '', 'args': ''},
            'generic': {'enabled': False, 'path': base_path, 'command': '', 'args': ''},
        }
    return {key: {'enabled': False, 'path': base_path, 'command': '', 'args': ''} for key in SCRIPT_VARIANT_KEYS}


def default_script_description(path: Path) -> str:
    name = path.stem.lower()
    known = {
        'demo_cli_flags': 'Script de prueba para validar flags, parámetros, repeticiones y salida opcional a fichero.',
        'demo_counter': 'Script de prueba con salida progresiva para comprobar ejecuciones largas, streaming y temporización.',
        'demo_json_report': 'Script de prueba que genera un informe JSON o texto y puede guardarlo en disco.',
        'demo_session_probe': 'Script de prueba para mostrar datos de sesión, terminal, perfil activo, plataforma y entorno.',
    }
    if name in known:
        return known[name]
    pretty = prettify_script_name(path.stem)
    return f'Script autodetectado preparado para lanzarse desde ZenoRemote: {pretty}.'


def build_discovered_script_entry(path: Path) -> dict[str, Any]:
    relative_path = path.relative_to(APP_DIR).as_posix()
    relative_inside_scripts = path.relative_to(SCRIPTS_DIR).as_posix()
    parts = Path(relative_inside_scripts).parts
    category = parts[0] if len(parts) >= 2 else 'General'
    subcategory = parts[1] if len(parts) >= 3 else 'General'
    script_id = 'auto-' + re.sub(r'[^a-z0-9._-]+', '-', relative_inside_scripts.lower()).strip('-')
    return {
        'id': script_id or f'auto-script-{abs(hash(relative_inside_scripts))}',
        'name': prettify_script_name(path.stem),
        'category': category or 'General',
        'subcategory': subcategory or 'General',
        'description': default_script_description(path),
        'include_all_targets': True,
        'target_ids': [],
        'variants': build_script_variant_defaults(relative_path),
        'source_path': normalize_script_source_path(relative_path),
        'auto_discovered': True,
    }


def discover_scripts_from_directory() -> list[dict[str, Any]]:
    if not SCRIPTS_DIR.exists():
        return []
    scripts: list[dict[str, Any]] = []
    for path in sorted(SCRIPTS_DIR.rglob('*')):
        if not path.is_file() or path.name.startswith('.'):
            continue
        if path.suffix.lower() not in DISCOVERABLE_SCRIPT_EXTENSIONS:
            continue
        scripts.append(build_discovered_script_entry(path))
    return scripts


def normalize_script_entry(item: Any, index: int = 0) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    name = str(item.get("name") or "").strip()
    if not name:
        return None
    include_all_targets = bool(item.get("include_all_targets", True))
    target_ids: list[str] = []
    for value in item.get("target_ids") or []:
        target_id = str(value or "").strip()
        if target_id and target_id not in target_ids:
            target_ids.append(target_id)
    variants_raw = item.get("variants") if isinstance(item.get("variants"), dict) else {}
    default_seed = {
        "path": str(item.get("path") or ""),
        "command": str(item.get("command") or ""),
        "args": str(item.get("args") or item.get("flags") or item.get("params") or ""),
        "enabled": True,
    }
    variants = {key: normalize_script_variant(variants_raw.get(key) or {}) for key in SCRIPT_VARIANT_KEYS}
    variants["default"] = normalize_script_variant({**default_seed, **(variants_raw.get("default") or {})})
    return {
        "id": str(item.get("id") or f"script-{index + 1}"),
        "name": name,
        "category": str(item.get("category") or "General").strip() or "General",
        "subcategory": str(item.get("subcategory") or "General").strip() or "General",
        "description": str(item.get("description") or "").strip(),
        "include_all_targets": include_all_targets or not target_ids,
        "target_ids": [] if (include_all_targets or not target_ids) else target_ids,
        "variants": variants,
        "source_path": normalize_script_source_path(str(item.get("source_path") or "")),
        "auto_discovered": bool(item.get("auto_discovered", False)),
    }


def merge_script_store_with_discovery(configured_scripts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized_configured = [normalize_script_entry(item, index) for index, item in enumerate(configured_scripts or [])]
    configured_clean = [item for item in normalized_configured if item]
    discovered = [normalize_script_entry(item, index) for index, item in enumerate(discover_scripts_from_directory())]
    discovered_clean = [item for item in discovered if item]
    by_source = {item.get('source_path'): item for item in discovered_clean if item.get('source_path')}
    merged: list[dict[str, Any]] = []
    used_sources: set[str] = set()

    for item in configured_clean:
        source_path = item.get('source_path') or ''
        discovered_item = by_source.get(source_path) if source_path else None
        if discovered_item:
            combined = dict(discovered_item)
            combined.update({
                'id': item.get('id') or discovered_item.get('id'),
                'name': item.get('name') or discovered_item.get('name'),
                'category': item.get('category') or discovered_item.get('category'),
                'subcategory': item.get('subcategory') or discovered_item.get('subcategory'),
                'description': item.get('description') or discovered_item.get('description') or '',
                'include_all_targets': item.get('include_all_targets', True),
                'target_ids': item.get('target_ids') or [],
                'variants': item.get('variants') or discovered_item.get('variants'),
                'auto_discovered': True,
            })
            merged.append(normalize_script_entry(combined, len(merged)) or combined)
            used_sources.add(source_path)
        else:
            merged.append(item)

    for item in discovered_clean:
        source_path = item.get('source_path') or ''
        if source_path and source_path in used_sources:
            continue
        merged.append(item)

    return [item for item in merged if item]


def get_script_store() -> list[dict[str, Any]]:
    raw = CONFIG.get("app_scripts")
    configured = raw if isinstance(raw, list) else []
    return merge_script_store_with_discovery(configured)


def save_script_store(scripts: list[dict[str, Any]]) -> None:
    global CONFIG
    current = load_config()
    current["app_scripts"] = merge_script_store_with_discovery(scripts)
    save_config(current)
    CONFIG = current


def normalize_preset(item: dict[str, Any], index: int) -> dict[str, Any]:
    scope = "remote" if str(item.get("scope") or "local") == "remote" else "local"
    auth_type = str(item.get("auth_type") or ("none" if scope == "local" else "password"))
    detected_local = bool(item.get("detected_local") or scope == "local")
    if scope == "local":
        auth_type = "none"
    elif auth_type not in {"password", "key"}:
        auth_type = "password"

    target_os = str(item.get("target_os") or infer_target_os_for_shell(str(item.get("shell_family") or "")) or HOST_OS)
    if scope == "local":
        target_os = HOST_OS
    if target_os not in {opt["id"] for opt in TARGET_OS_OPTIONS}:
        target_os = HOST_OS

    shell_defs = shell_definitions_for_scope(scope, target_os)
    fallback_shell = DEFAULT_LOCAL_SHELL if scope == "local" else next(iter(shell_defs), "")
    shell_family = str(item.get("shell_family") or fallback_shell or "")
    if shell_family not in shell_defs:
        if scope == "local":
            target_os = HOST_OS
            shell_defs = shell_definitions_for_scope(scope, target_os)
            shell_family = shell_family if shell_family in shell_defs else (DEFAULT_LOCAL_SHELL or next(iter(shell_defs), ""))
        else:
            shell_family = fallback_shell or shell_family

    preset_id = str(item.get("id") or (f"local::{shell_family}" if scope == "local" else f"preset-{index}"))
    return {
        "id": preset_id,
        "name": str(item.get("name") or f"Terminal {index + 1}"),
        "scope": scope,
        "auth_type": auth_type,
        "target_os": target_os,
        "shell_family": shell_family,
        "host": str(item.get("host") or ""),
        "port": int(item.get("port") or 22),
        "username": str(item.get("username") or ""),
        "private_key_path": str(item.get("private_key_path") or ""),
        "strict_host_key": bool(item.get("strict_host_key", True)) if scope == "remote" else False,
        "startup_command": str(item.get("startup_command") or ""),
        "command_file_content": str(item.get("command_file_content") or ""),
        "launch_command": str(item.get("launch_command") or build_default_launch_command(shell_family)),
        "detected_local": detected_local,
        "editable_scope": bool(item.get("editable_scope", scope == "remote")),
        "editable_target_os": bool(item.get("editable_target_os", scope == "remote")),
        "editable_remove": bool(item.get("editable_remove", scope == "remote")),
        "open_by_default": bool(item.get("open_by_default", False)),
    }



def build_targets(session_id: str | None = None, user: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    effective_session_id = normalize_optional_session_id(session_id) if user is not None else normalize_terminal_session_id(session_id or get_active_session_id())
    for index, raw in enumerate(get_effective_terminal_presets(effective_session_id, user=user)):
        preset = normalize_preset(raw, index)
        shell = shell_definitions_for_scope(preset["scope"], preset["target_os"]).get(preset["shell_family"], {})
        base_target_id = str(preset["id"])
        target_id = make_scoped_target_id(effective_session_id, base_target_id) if user is not None else base_target_id
        if preset["scope"] == "local":
            targets.append({
                "id": target_id,
                "_base_id": base_target_id,
                "label": f"Local: {preset['name']}",
                "mode": "direct",
                "connection_scope": "local",
                "auth_type": "none",
                "description": f"Shell local detectada automáticamente en el host actual ({TARGET_OS_LABELS.get(HOST_OS, HOST_OS)}).",
                "shell_id": preset["shell_family"],
                "shell_family": preset["shell_family"],
                "target_os": preset["target_os"],
                "startup_command": preset["startup_command"],
                "command_file_content": preset["command_file_content"],
                "preset_name": preset["name"],
                "shell_label": shell.get("label") or preset["shell_family"],
                "launch_command": preset["launch_command"],
                "alias_support": alias_capability_for_shell(preset["shell_family"]),
                "workspace_dir": str(APP_DIR),
                "detected_local": True,
                "open_by_default": bool(preset.get("open_by_default", False)),
                "session_id": effective_session_id,
            })
        else:
            mode = "ssh_key" if preset["auth_type"] == "key" else "ssh_password"
            targets.append({
                "id": target_id,
                "_base_id": base_target_id,
                "label": f"Remote: {preset['name']}",
                "mode": mode,
                "connection_scope": "remote",
                "auth_type": preset["auth_type"],
                "description": f"Destino remoto configurable por pestaña para {TARGET_OS_LABELS.get(preset['target_os'], preset['target_os'])}.",
                "host": preset["host"],
                "port": preset["port"],
                "username": preset["username"],
                "private_key_path": preset["private_key_path"],
                "strict_host_key": preset["strict_host_key"],
                "startup_command": preset["startup_command"],
                "command_file_content": preset["command_file_content"],
                "shell_family": preset["shell_family"],
                "target_os": preset["target_os"],
                "preset_name": preset["name"],
                "shell_label": shell.get("label") or preset["shell_family"],
                "launch_command": preset["launch_command"],
                "alias_support": alias_capability_for_shell(preset["shell_family"]),
                "workspace_dir": str(APP_DIR),
                "detected_local": False,
                "open_by_default": bool(preset.get("open_by_default", False)),
                "session_id": effective_session_id,
            })
    docker_targets = build_docker_targets(effective_session_id)
    if user is not None:
        for item in docker_targets:
            scoped_item = dict(item)
            scoped_item["_base_id"] = str(item.get("id") or "")
            scoped_item["id"] = make_scoped_target_id(effective_session_id, scoped_item["_base_id"])
            scoped_item["session_id"] = effective_session_id
            targets.append(scoped_item)
    else:
        targets.extend(docker_targets)
    return targets


TARGETS = build_targets(get_active_session_id())
TARGETS_BY_ID = {str(item["id"]): item for item in TARGETS}


def public_targets(targets: list[dict[str, Any]] | None = None, active_session_id: str | None = None) -> list[dict[str, Any]]:
    items = []
    source_targets = targets if targets is not None else TARGETS
    default_active = normalize_optional_session_id(active_session_id) if active_session_id is not None else ""
    for target in source_targets:
        mode = str(target.get("mode") or "direct")
        items.append({
            "id": str(target.get("id") or ""),
            "label": str(target.get("label") or target.get("id") or "Destino"),
            "mode": mode,
            "description": str(target.get("description") or ""),
            "connection_scope": str(target.get("connection_scope") or ("local" if mode == "direct" else "remote")),
            "auth_type": str(target.get("auth_type") or ("none" if mode == "direct" else "password")),
            "host": str(target.get("host") or "") if mode.startswith("ssh") else "",
            "port": int(target.get("port") or 22) if mode.startswith("ssh") else None,
            "username": str(target.get("username") or "") if mode.startswith("ssh") else "",
            "shell_id": str(target.get("shell_id") or DEFAULT_LOCAL_SHELL or "") if mode == "direct" else "",
            "prompt_password": bool(target.get("prompt_password") or mode == "ssh_password"),
            "prompt_passphrase": bool(target.get("prompt_passphrase") or False),
            "private_key_path": str(target.get("private_key_path") or "") if mode == "ssh_key" else "",
            "strict_host_key": bool(target.get("strict_host_key", True)) if mode.startswith("ssh") else False,
            "startup_command": str(target.get("startup_command") or ""),
            "command_file_content": str(target.get("command_file_content") or ""),
            "shell_family": str(target.get("shell_family") or ""),
            "target_os": str(target.get("target_os") or HOST_OS),
            "target_os_label": TARGET_OS_LABELS.get(str(target.get("target_os") or HOST_OS), str(target.get("target_os") or HOST_OS)),
            "preset_name": str(target.get("preset_name") or ""),
            "shell_label": str(target.get("shell_label") or ""),
            "launch_command": str(target.get("launch_command") or ""),
            "alias_support": str(target.get("alias_support") or "none"),
            "workspace_dir": str(target.get("workspace_dir") or APP_DIR),
            "detected_local": bool(target.get("detected_local") or False),
            "open_by_default": bool(target.get("open_by_default") or False),
            "session_id": str(target.get("session_id") or default_active),
        })
    return items

class WindowsLocalPtySession(SessionBase):
    def __init__(self, shell_id: str, cols: int, rows: int, launch_command: str | None = None) -> None:
        if PTY is None:
            raise RuntimeError("Falta pywinpty. Instala: python -m pip install pywinpty")
        shell = LOCAL_SHELLS.get(shell_id)
        if not shell:
            raise RuntimeError(f"Shell no soportada en Windows: {shell_id}")
        self.cols = max(20, int(cols))
        self.rows = max(5, int(rows))
        self.proc = PTY(self.cols, self.rows)
        self._closed = False
        self.spawn_local_shell(shell, launch_command or build_default_launch_command(shell_id))
        post_start = shell.get("post_start_input")
        if post_start:
            time.sleep(0.15)
            try:
                self.proc.write(post_start)
            except Exception:
                pass

    def spawn_local_shell(self, shell: dict[str, Any], launch_command: str) -> None:
        working_dir = str(APP_DIR)
        candidates: list[tuple[str, dict[str, Any]]] = []
        launch_command = str(launch_command or '').strip()

        if shell.get("profile") == "wsl" and shell.get("distro"):
            distro = str(shell.get("distro") or "").strip().replace(chr(0), "").replace("﻿", "")
            if distro:
                quoted_distro = subprocess.list2cmdline([distro])
                candidates.append((str(shell["path"]), {"cwd": working_dir, "cmdline": f" -d {quoted_distro}"}))
                candidates.append((str(shell["path"]), {"cwd": working_dir, "cmdline": f" --distribution {quoted_distro}"}))
                cmd_launcher = shutil_which_windows("cmd.exe")
                if cmd_launcher:
                    candidates.append((str(cmd_launcher), {"cwd": working_dir, "cmdline": f" /k wsl.exe -d {quoted_distro}"}))
                    candidates.append((str(cmd_launcher), {"cwd": working_dir, "cmdline": f" /k wsl.exe --distribution {quoted_distro}"}))

        if launch_command:
            match = re.match(r'^\s*(?:"([^"]+)"|(\S+))(.*)$', launch_command)
            if match:
                cmd = (match.group(1) or match.group(2) or '').strip()
                tail = match.group(3) or ''
                if cmd:
                    kwargs: dict[str, Any] = {"cwd": working_dir}
                    if tail.strip():
                        kwargs["cmdline"] = tail
                    candidates.append((cmd, kwargs))

        candidates.append((str(shell["path"]), {"cwd": working_dir}))
        last_error: Exception | None = None
        for command, kwargs in candidates:
            try:
                self.proc.spawn(command, **kwargs)
                return
            except TypeError:
                try:
                    self.proc.spawn(command)
                    return
                except Exception as exc:
                    last_error = exc
            except Exception as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        raise RuntimeError("No se pudo lanzar la shell local en Windows.")


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


class PosixLocalPtySession(SessionBase):
    def __init__(self, shell_id: str, cols: int, rows: int, launch_command: str | None = None) -> None:
        if pty is None or fcntl is None or termios is None:
            raise RuntimeError("El host POSIX no tiene soporte PTY disponible.")
        shell = LOCAL_SHELLS.get(shell_id)
        if not shell:
            raise RuntimeError(f"Shell POSIX no soportada: {shell_id}")
        self.cols = max(20, int(cols))
        self.rows = max(5, int(rows))
        self._closed = False
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            try:
                os.chdir(str(APP_DIR))
                command = str(launch_command or build_default_launch_command(shell_id) or shell.get("path") or "").strip()
                argv = shlex.split(command, posix=True) if command else []
                if not argv:
                    argv = [str(shell.get("path") or shell_id)]
                executable = argv[0]
                if executable in {"bash", "zsh", "fish", "sh", "dash", "ash"}:
                    resolved = shutil.which(executable) or executable
                    argv[0] = resolved
                    executable = resolved
                elif not os.path.isabs(executable):
                    executable = shutil.which(executable) or executable
                    argv[0] = executable
                env = os.environ.copy()
                env.setdefault("TERM", "xterm-256color")
                os.execvpe(executable, argv, env)
            except Exception:
                os._exit(1)
        flags = fcntl.fcntl(self.fd, fcntl.F_GETFL)
        fcntl.fcntl(self.fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        self.resize(self.cols, self.rows)

    def read(self) -> str:
        if self._closed:
            return ""
        try:
            data = os.read(self.fd, 4096)
        except BlockingIOError:
            return ""
        except OSError:
            self._closed = True
            return ""
        return data.decode("utf-8", errors="replace") if data else ""

    def write(self, text: str) -> None:
        if self._closed or not text:
            return
        os.write(self.fd, text.encode("utf-8", errors="replace"))

    def resize(self, cols: int, rows: int) -> None:
        if self._closed:
            return
        self.cols = max(20, int(cols))
        self.rows = max(5, int(rows))
        winsize = struct.pack("HHHH", self.rows, self.cols, 0, 0)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, winsize)

    def is_alive(self) -> bool:
        if self._closed:
            return False
        try:
            pid, _ = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self._closed = True
            return False
        return pid == 0

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            os.kill(self.pid, signal.SIGTERM)
        except Exception:
            pass
        try:
            os.close(self.fd)
        except Exception:
            pass


class LocalPtySession(SessionBase):
    def __init__(self, shell_id: str, cols: int, rows: int, launch_command: str | None = None) -> None:
        if HOST_OS == "windows":
            self.impl: SessionBase = WindowsLocalPtySession(shell_id, cols, rows, launch_command)
        elif HOST_OS in {"linux", "macos", "android"}:
            self.impl = PosixLocalPtySession(shell_id, cols, rows, launch_command)
        else:
            raise RuntimeError(f"La sesión local directa no está soportada en este host: {HOST_OS}")

    def read(self) -> str:
        return self.impl.read()

    def write(self, text: str) -> None:
        self.impl.write(text)

    def resize(self, cols: int, rows: int) -> None:
        self.impl.resize(cols, rows)

    def is_alive(self) -> bool:
        return self.impl.is_alive()

    def close(self) -> None:
        self.impl.close()


@dataclass
class LoadedPrivateKey:
    key: Any
    key_type: str


def load_private_key(path: str | None, content: str | None, passphrase: str | None) -> LoadedPrivateKey:
    if paramiko is None:
        raise RuntimeError("Falta paramiko. Instala: python -m pip install paramiko")
    classes = [getattr(paramiko, n, None) for n in ("RSAKey", "ECDSAKey", "Ed25519Key", "DSSKey")]
    errors = []
    for cls in classes:
        if cls is None:
            continue
        try:
            if content:
                key = cls.from_private_key(io.StringIO(content), password=passphrase)
            else:
                key = cls.from_private_key_file(str(path), password=passphrase)
            return LoadedPrivateKey(key=key, key_type=cls.__name__)
        except Exception as exc:
            errors.append(f"{cls.__name__}: {exc}")
    raise RuntimeError("No se pudo cargar la clave privada: " + " | ".join(errors))


class ParamikoShellSession(SessionBase):
    def __init__(self, host: str, port: int, username: str, password: str | None, private_key_path: str | None, private_key_content: str | None, passphrase: str | None, strict_host_key: bool, cols: int, rows: int) -> None:
        if paramiko is None:
            raise RuntimeError("Falta paramiko. Instala: python -m pip install paramiko")
        if not host or not username:
            raise RuntimeError("Host y username son obligatorios para SSH.")
        self.cols = max(20, int(cols))
        self.rows = max(5, int(rows))
        self.client = paramiko.SSHClient()
        if strict_host_key:
            self.client.load_host_keys(str(KNOWN_HOSTS_PATH))
            self.client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs: dict[str, Any] = {
            "hostname": host,
            "port": int(port or 22),
            "username": username,
            "timeout": 12,
            "banner_timeout": 12,
            "auth_timeout": 12,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if private_key_path or private_key_content:
            loaded = load_private_key(private_key_path, private_key_content, passphrase)
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
            self.cols = max(20, int(cols))
            self.rows = max(5, int(rows))
            try:
                self.channel.resize_pty(width=self.cols, height=self.rows)
            except Exception:
                pass

    def is_alive(self) -> bool:
        return not self._closed and not self.channel.closed

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self.channel.close()
            except Exception:
                pass
            try:
                self.client.close()
            except Exception:
                pass


def combine_start_commands(*parts: str) -> str:
    cleaned = [str(part or "").replace("\r\n", "\n").replace("\r", "\n").strip("\n") for part in parts if str(part or "").strip()]
    return "\n".join(cleaned).strip()


def to_session_input(text: str) -> str:
    normalized = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    if not normalized.strip():
        return ""
    return normalized.replace("\n", "\r") + "\r"


def session_start_command_delay_seconds(target: dict[str, Any] | None = None) -> float:
    shell_family = str((target or {}).get("shell_family") or "").strip().lower()
    mode = str((target or {}).get("mode") or "").strip().lower()
    if mode == "direct" and shell_family in {"powershell", "powershell7", "pwsh"}:
        return 0.85
    return 0.3


def execute_session_start_commands(session: SessionBase, command_text: str, target: dict[str, Any] | None = None) -> None:
    payload = to_session_input(command_text)
    if not payload:
        return
    time.sleep(session_start_command_delay_seconds(target))
    session.write(payload)




def build_download_zip_filename(path_obj: Path) -> str:
    safe_base = re.sub(r"[^A-Za-z0-9._-]+", "_", path_obj.name or "carpeta").strip("._-") or "carpeta"
    stamp = time.strftime("%Y%m%d-%H%M%S")
    return f"{safe_base}_{stamp}.zip"


def zip_directory_to_file(source_dir: Path, zip_path: Path) -> None:
    source_dir = source_dir.resolve()
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for root, dirnames, filenames in os.walk(source_dir):
            root_path = Path(root)
            dirnames[:] = [name for name in dirnames if name not in {"__pycache__"}]
            for filename in filenames:
                file_path = root_path / filename
                try:
                    if not file_path.is_file() or file_path.is_symlink():
                        continue
                except OSError:
                    continue
                arcname = file_path.relative_to(source_dir)
                archive.write(file_path, arcname.as_posix())
        if not archive.namelist():
            archive.writestr('.empty', '')


def list_host_roots() -> list[dict[str, Any]]:
    roots: list[dict[str, Any]] = []
    seen: set[str] = set()
    if os.name == "nt":
        for code in range(ord("A"), ord("Z") + 1):
            drive = f"{chr(code)}:/"
            path_obj = Path(drive)
            if path_obj.exists():
                resolved = str(path_obj.resolve())
                if resolved not in seen:
                    seen.add(resolved)
                    roots.append({"path": resolved, "label": drive})
    else:
        for candidate in [Path.home(), Path('/'), APP_DIR]:
            try:
                resolved = str(candidate.resolve())
            except Exception:
                continue
            if resolved not in seen and Path(resolved).exists():
                seen.add(resolved)
                roots.append({"path": resolved, "label": resolved})
    if str(APP_DIR.resolve()) not in seen:
        roots.append({"path": str(APP_DIR.resolve()), "label": str(APP_DIR.resolve())})
    return roots


def path_within(base: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(base)
        return True
    except Exception:
        return False


def explorer_entries_for_user(user: dict[str, Any] | None) -> list[dict[str, Any]]:
    payload = serialize_current_user(user) or {}
    permissions = payload.get("permissions") or {}
    if permissions.get("is_admin"):
        return [{"path": item["path"], "label": item["label"], "access": "read_write"} for item in list_host_roots()]
    return serialize_explorer_entries(user.get("explorer_entries") or []) if user else []


def list_host_roots_for_user(user: dict[str, Any] | None) -> list[dict[str, Any]]:
    payload = serialize_current_user(user) or {}
    permissions = payload.get("permissions") or {}
    if permissions.get("is_admin"):
        return list_host_roots()
    return explorer_entries_for_user(user)


def explorer_permission_for_path(user: dict[str, Any] | None, raw_path: str | None) -> dict[str, Any]:
    payload = serialize_current_user(user) or {}
    permissions = payload.get("permissions") or {}
    if permissions.get("is_admin"):
        candidate = Path(os.path.expanduser(str(raw_path or "") or str(APP_DIR))).resolve()
        return {"allowed": True, "path": str(candidate), "root_path": str(candidate.anchor or candidate), "root_label": str(candidate.anchor or candidate), "access": "read_write", "can_write": True}
    entries = explorer_entries_for_user(user)
    if not entries:
        return {"allowed": False, "message": "Este usuario no tiene rutas del Explorer asignadas."}
    if not str(raw_path or "").strip():
        first = entries[0]
        return {"allowed": True, "path": str(first["path"]), "root_path": str(first["path"]), "root_label": str(first.get("label") or first["path"]), "access": str(first.get("access") or "read_only"), "can_write": str(first.get("access") or "read_only") == "read_write"}
    try:
        candidate = Path(os.path.expanduser(str(raw_path or ""))).resolve()
    except Exception as exc:
        return {"allowed": False, "message": f"Ruta inválida: {exc}"}
    best_match: dict[str, Any] | None = None
    best_length = -1
    for entry in entries:
        base = Path(str(entry.get("path") or "")).resolve()
        if path_within(base, candidate):
            length = len(base.parts)
            if length > best_length:
                best_length = length
                best_match = entry
    if not best_match:
        return {"allowed": False, "message": "La ruta no está permitida para este usuario."}
    access = str(best_match.get("access") or "read_only")
    return {
        "allowed": True,
        "path": str(candidate),
        "root_path": str(best_match.get("path") or ""),
        "root_label": str(best_match.get("label") or best_match.get("path") or ""),
        "access": access,
        "can_write": access == "read_write",
    }


def resolve_explorer_path_for_user(user: dict[str, Any] | None, raw_path: str | None, require_write: bool = False) -> tuple[Path, dict[str, Any]]:
    info = explorer_permission_for_path(user, raw_path)
    if not info.get("allowed"):
        raise PermissionError(str(info.get("message") or "Ruta no permitida."))
    if require_write and not info.get("can_write"):
        raise PermissionError("La ruta es de solo lectura para este usuario.")
    return Path(str(info.get("path") or "")).resolve(), info


def format_size(num: int) -> str:
    size = float(max(0, int(num or 0)))
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024 or unit == 'TB':
            return f"{size:.0f} {unit}" if unit == 'B' else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


def guess_text_mode(path_obj: Path) -> tuple[bool, str, str]:
    suffix = path_obj.suffix.lower()
    markdown_suffixes = {'.md', '.markdown', '.mdown'}
    text_suffixes = {'.txt', '.py', '.ps1', '.sh', '.bash', '.zsh', '.json', '.yaml', '.yml', '.toml', '.ini', '.cfg', '.conf', '.log', '.csv', '.xml', '.html', '.css', '.js', '.ts', '.tsx', '.jsx', '.java', '.c', '.cpp', '.h', '.hpp', '.rs', '.go', '.sql', '.env', '.properties'}
    if suffix in markdown_suffixes:
        return True, 'markdown', suffix.lstrip('.') or 'markdown'
    if suffix in text_suffixes:
        return True, 'text', suffix.lstrip('.') or 'plaintext'
    try:
        with path_obj.open('rb') as fh:
            sample = fh.read(4096)
        if b'\x00' in sample:
            return False, 'binary', 'binary'
        sample.decode('utf-8')
        return True, 'text', suffix.lstrip('.') or 'plaintext'
    except Exception:
        return False, 'binary', 'binary'


def build_explorer_entry(path_obj: Path) -> dict[str, Any]:
    stat = path_obj.stat()
    is_dir = path_obj.is_dir()
    text_mode, preview_mode, language = guess_text_mode(path_obj) if not is_dir else (False, 'directory', 'directory')
    return {
        'name': path_obj.name or str(path_obj),
        'path': str(path_obj),
        'parent': str(path_obj.parent),
        'is_dir': is_dir,
        'size': 0 if is_dir else int(stat.st_size),
        'size_label': '-' if is_dir else format_size(int(stat.st_size)),
        'modified_ts': float(stat.st_mtime),
        'modified_label': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime)),
        'previewable': bool(text_mode),
        'preview_mode': preview_mode,
        'language': language,
        'draggable_download': not is_dir,
    }


def list_directory_entries_for_user(path_obj: Path, user: dict[str, Any] | None, permission: dict[str, Any]) -> dict[str, Any]:
    if not path_obj.exists():
        raise FileNotFoundError(f'La ruta no existe: {path_obj}')
    if not path_obj.is_dir():
        raise NotADirectoryError(f'La ruta no es una carpeta: {path_obj}')
    entries: list[dict[str, Any]] = []
    for child in sorted(path_obj.iterdir(), key=lambda item: (not item.is_dir(), item.name.lower())):
        try:
            child_permission = explorer_permission_for_path(user, str(child))
            if child_permission.get('allowed'):
                entries.append(build_explorer_entry(child))
        except Exception:
            continue
    parents = []
    cursor = path_obj
    root_path = Path(str(permission.get('root_path') or path_obj)).resolve()
    while True:
        parents.append({'path': str(cursor), 'label': cursor.name or str(cursor)})
        if cursor == root_path or cursor.parent == cursor:
            break
        cursor = cursor.parent
    parents.reverse()
    roots = list_host_roots_for_user(user)
    return {'path': str(path_obj), 'entries': entries, 'breadcrumbs': parents, 'roots': roots, 'permission': {
        'root_path': str(permission.get('root_path') or ''),
        'root_label': str(permission.get('root_label') or ''),
        'access': str(permission.get('access') or 'read_only'),
        'can_write': bool(permission.get('can_write')),
    }}


def zip_single_path_to_file(source_path: Path, zip_path: Path) -> None:
    source_path = source_path.resolve()
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        if source_path.is_dir():
            for root, dirnames, filenames in os.walk(source_path):
                root_path = Path(root)
                dirnames[:] = [name for name in dirnames if name not in {'__pycache__'}]
                for filename in filenames:
                    file_path = root_path / filename
                    try:
                        if not file_path.is_file() or file_path.is_symlink():
                            continue
                    except OSError:
                        continue
                    archive.write(file_path, file_path.relative_to(source_path.parent).as_posix())
            if not archive.namelist():
                archive.writestr(f"{source_path.name}/.empty", '')
        else:
            archive.write(source_path, source_path.name)


def copy_path_item(source_path: Path, destination_dir: Path, overwrite: bool = False) -> dict[str, Any]:
    if not source_path.exists():
        raise FileNotFoundError(f'No existe el origen: {source_path}')
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination_path = destination_dir / source_path.name
    if source_path.resolve() == destination_dir.resolve() or destination_path.resolve() == source_path.resolve():
        raise ValueError('El origen y el destino coinciden.')
    if destination_path.exists():
        if not overwrite:
            raise FileExistsError(f'Ya existe: {destination_path}')
        if destination_path.is_dir() and not source_path.is_dir():
            shutil.rmtree(destination_path)
        elif destination_path.is_file() and source_path.is_dir():
            destination_path.unlink()
        elif destination_path.is_dir():
            shutil.rmtree(destination_path)
        else:
            destination_path.unlink()
    if source_path.is_dir():
        shutil.copytree(source_path, destination_path)
    else:
        shutil.copy2(source_path, destination_path)
    return {'path': str(destination_path), 'name': destination_path.name}



SCHEDULER_TZ = ZoneInfo("Europe/Madrid")
SCHEDULER_STATE_LOCK = threading.Lock()


def scheduler_now() -> datetime:
    return datetime.now(SCHEDULER_TZ)


def scheduler_iso(dt_value: datetime | None) -> str:
    if not dt_value:
        return ""
    if dt_value.tzinfo is None:
        dt_value = dt_value.replace(tzinfo=SCHEDULER_TZ)
    return dt_value.astimezone(SCHEDULER_TZ).isoformat()


def scheduler_parse_datetime(value: Any) -> datetime | None:
    text_value = str(value or '').strip()
    if not text_value:
        return None
    try:
        dt_value = datetime.fromisoformat(text_value.replace('Z', '+00:00'))
    except Exception:
        return None
    if dt_value.tzinfo is None:
        dt_value = dt_value.replace(tzinfo=SCHEDULER_TZ)
    return dt_value.astimezone(SCHEDULER_TZ)


def scheduler_parse_time(value: Any) -> tuple[int, int]:
    text_value = str(value or '').strip()
    if not text_value:
        return 0, 0
    parts = text_value.split(':')
    try:
        hour = max(0, min(23, int(parts[0])))
    except Exception:
        hour = 0
    try:
        minute = max(0, min(59, int(parts[1] if len(parts) > 1 else 0)))
    except Exception:
        minute = 0
    return hour, minute


def scheduler_format_stamp(dt_value: datetime | None = None) -> str:
    target = dt_value.astimezone(SCHEDULER_TZ) if dt_value else scheduler_now()
    return target.strftime('%Y-%m-%d %H:%M:%S')


def scheduler_log_line(level: str, source: str, message: str, when: datetime | None = None) -> str:
    return f"[{scheduler_format_stamp(when)}] [{str(level or 'INFO').upper()}] [{source}] {message}"


def normalize_scheduler_task(item: Any, index: int = 0) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        return None
    name = str(item.get('name') or '').strip()
    if not name:
        return None
    now_iso = scheduler_iso(scheduler_now())
    session_ids = {entry['id'] for entry in get_terminal_sessions()}
    session_id = normalize_terminal_session_id(str(item.get('session_id') or 'default'))
    if session_id not in session_ids:
        session_id = 'default'
    dispatch_scope = str(item.get('dispatch_scope') or 'terminal').strip().lower()
    if dispatch_scope not in {'terminal', 'session'}:
        dispatch_scope = 'terminal'
    launch_type = str(item.get('launch_type') or 'command').strip().lower()
    if launch_type not in {'command', 'script', 'docker_group'}:
        launch_type = 'command'
    schedule_type = str(item.get('schedule_type') or 'once').strip().lower()
    if schedule_type not in {'once', 'delay', 'interval', 'daily', 'weekly', 'event'}:
        schedule_type = 'once'
    target_ids = []
    seen_targets: set[str] = set()
    for raw_target_id in item.get('target_ids') or []:
        target_id = str(raw_target_id or '').strip()
        if target_id and target_id not in seen_targets:
            seen_targets.add(target_id)
            target_ids.append(target_id)
    weekly_days = []
    seen_days: set[int] = set()
    for raw_day in item.get('weekly_days') or []:
        try:
            day_value = int(raw_day)
        except Exception:
            continue
        if 0 <= day_value <= 6 and day_value not in seen_days:
            seen_days.add(day_value)
            weekly_days.append(day_value)
    weekly_days.sort()
    try:
        timeout_seconds = max(0, int(item.get('timeout_seconds') or 0))
    except Exception:
        timeout_seconds = 0
    try:
        delay_minutes = max(0, int(item.get('delay_minutes') or 0))
    except Exception:
        delay_minutes = 0
    try:
        interval_minutes = max(1, int(item.get('interval_minutes') or 60))
    except Exception:
        interval_minutes = 60
    return {
        'id': str(item.get('id') or f'scheduler-task-{index + 1}'),
        'name': name,
        'enabled': bool(item.get('enabled', True)),
        'category': str(item.get('category') or 'General').strip() or 'General',
        'subcategory': str(item.get('subcategory') or 'General').strip() or 'General',
        'description': str(item.get('description') or '').strip(),
        'dispatch_scope': dispatch_scope,
        'session_id': session_id,
        'target_ids': target_ids,
        'launch_type': launch_type,
        'command_text': str(item.get('command_text') or '').strip(),
        'script_id': str(item.get('script_id') or '').strip(),
        'docker_group_id': str(item.get('docker_group_id') or '').strip(),
        'schedule_type': schedule_type,
        'run_at': str(item.get('run_at') or '').strip(),
        'delay_minutes': delay_minutes,
        'interval_minutes': interval_minutes,
        'daily_time': str(item.get('daily_time') or '00:00').strip() or '00:00',
        'weekly_time': str(item.get('weekly_time') or '00:00').strip() or '00:00',
        'weekly_days': weekly_days,
        'event_key': str(item.get('event_key') or '').strip(),
        'timeout_seconds': timeout_seconds,
        'allow_overlap': bool(item.get('allow_overlap', False)),
        'keep_log_tab_open': bool(item.get('keep_log_tab_open', True)),
        'last_run_at': str(item.get('last_run_at') or '').strip(),
        'last_finished_at': str(item.get('last_finished_at') or '').strip(),
        'last_status': str(item.get('last_status') or 'idle').strip() or 'idle',
        'last_message': str(item.get('last_message') or '').strip(),
        'last_duration_seconds': float(item.get('last_duration_seconds') or 0.0),
        'created_at': str(item.get('created_at') or now_iso),
        'updated_at': str(item.get('updated_at') or now_iso),
        'schedule_anchor_at': str(item.get('schedule_anchor_at') or item.get('created_at') or now_iso),
    }


def get_scheduler_store() -> list[dict[str, Any]]:
    raw = (CONFIG.get('scheduler_management') or {}).get('tasks') or []
    tasks = [normalize_scheduler_task(item, index) for index, item in enumerate(raw)]
    return [item for item in tasks if item]


def save_scheduler_store(tasks: list[dict[str, Any]]) -> None:
    global CONFIG
    current = load_config()
    current.setdefault('scheduler_management', {})
    current['scheduler_management']['tasks'] = tasks
    save_config(current)
    CONFIG = current


def script_variant_for_target(script: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    variant_key = str(target.get('alias_support') or 'generic')
    candidate = (script.get('variants') or {}).get(variant_key) or {}
    if candidate.get('enabled') and (candidate.get('path') or candidate.get('command') or candidate.get('args')):
        return candidate
    return (script.get('variants') or {}).get('default') or {'enabled': True, 'path': '', 'command': '', 'args': ''}


def scheduler_shell_command_for_target(target: dict[str, Any], variant: dict[str, Any]) -> str:
    path_value = str(variant.get('path') or '').strip()
    command_value = str(variant.get('command') or '').strip()
    args_value = str(variant.get('args') or '').strip()
    full_command = ' '.join([part for part in [command_value, args_value] if part]).strip()
    if not path_value and not full_command:
        return ''
    family = str(target.get('shell_family') or '').lower()
    os_name = str(target.get('target_os') or HOST_OS).lower()
    if family in {'pwsh', 'powershell'}:
        safe_path = path_value.replace('"', '`"')
        if path_value and full_command:
            return f'Set-Location -LiteralPath "{safe_path}"; {full_command}'
        if path_value:
            return f'Set-Location -LiteralPath "{safe_path}"'
        return full_command
    if family == 'cmd' or os_name == 'windows':
        if path_value and full_command:
            return f'cd /d "{path_value}" && {full_command}'
        if path_value:
            return f'cd /d "{path_value}"'
        return full_command
    safe_path = path_value.replace('"', '\"')
    if path_value and full_command:
        return f'cd "{safe_path}" && {full_command}'
    if path_value:
        return f'cd "{safe_path}"'
    return full_command


def scheduler_command_from_task(task: dict[str, Any], target: dict[str, Any]) -> str:
    launch_type = str(task.get('launch_type') or 'command')
    if launch_type == 'command':
        return str(task.get('command_text') or '').strip()
    if launch_type == 'script':
        scripts = {str(item.get('id') or ''): item for item in get_script_store()}
        script = scripts.get(str(task.get('script_id') or ''))
        if not script:
            raise RuntimeError('Script no encontrado para la tarea programada.')
        if not script.get('include_all_targets') and str(target.get('id') or '') not in {str(item) for item in script.get('target_ids') or []}:
            raise RuntimeError('El script seleccionado no está visible para esta terminal.')
        variant = script_variant_for_target(script, target)
        command = scheduler_shell_command_for_target(target, variant)
        if not command:
            raise RuntimeError('El script no tiene ningún comando válido para esta terminal.')
        return command
    raise RuntimeError('Tipo de lanzamiento no soportado para este target.')


def scheduler_local_command_args(target: dict[str, Any], command_text: str) -> tuple[list[str], str | None]:
    family = str(target.get('shell_family') or '').strip().lower()
    workspace_dir = str(target.get('workspace_dir') or APP_DIR)
    if family == 'pwsh':
        resolved = shutil_which_windows('pwsh') or shutil.which('pwsh') or 'pwsh'
        return [resolved, '-NoLogo', '-NoProfile', '-Command', command_text], workspace_dir
    if family == 'powershell':
        resolved = shutil_which_windows('powershell.exe') or shutil.which('powershell') or 'powershell.exe'
        return [resolved, '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', command_text], workspace_dir
    if family == 'cmd':
        resolved = shutil_which_windows('cmd.exe') or 'cmd.exe'
        return [resolved, '/d', '/c', command_text], workspace_dir
    if family.startswith('wsl::'):
        distro = family.split('::', 1)[1]
        resolved = shutil_which_windows('wsl.exe') or 'wsl.exe'
        return [resolved, '-d', distro, 'sh', '-lc', command_text], workspace_dir
    if family == 'gitbash':
        resolved = detect_git_bash() or shutil.which('bash') or 'bash'
        return [resolved, '-lc', command_text], workspace_dir
    shell_path = (LOCAL_SHELLS.get(family) or {}).get('path') or shutil.which(family) or family or 'sh'
    if family == 'fish':
        return [str(shell_path), '-c', command_text], workspace_dir
    return [str(shell_path), '-lc', command_text], workspace_dir


def scheduler_remote_exec(target: dict[str, Any], command_text: str, timeout_seconds: int, on_line) -> int:
    if paramiko is None:
        raise RuntimeError('Falta paramiko. Instala: python -m pip install paramiko')
    host = str(target.get('host') or '').strip()
    username = str(target.get('username') or '').strip()
    if not host or not username:
        raise RuntimeError('Host y usuario son obligatorios para la ejecución remota.')
    if str(target.get('auth_type') or '') != 'key':
        raise RuntimeError('Las tareas programadas remotas solo soportan por ahora presets SSH con clave.')
    private_key_path = str(target.get('private_key_path') or '').strip()
    if not private_key_path:
        raise RuntimeError('El preset remoto necesita private_key_path para ejecutarse desde Scheduler.')
    loaded = load_private_key(private_key_path, None, None)
    client = paramiko.SSHClient()
    if bool(target.get('strict_host_key', True)):
        client.load_host_keys(str(KNOWN_HOSTS_PATH))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=int(target.get('port') or 22),
        username=username,
        pkey=loaded.key,
        timeout=12,
        banner_timeout=12,
        auth_timeout=12,
        look_for_keys=False,
        allow_agent=False,
    )
    try:
        stdin, stdout, stderr = client.exec_command(command_text, timeout=timeout_seconds or None, get_pty=True)
        stdin.close()
        while True:
            had_data = False
            if stdout.channel.recv_ready():
                chunk = stdout.channel.recv(4096).decode('utf-8', errors='replace')
                for line in chunk.replace("\r", "").split("\n"):
                    if line:
                        on_line('OUT', line)
                had_data = True
            if stdout.channel.recv_stderr_ready():
                chunk = stdout.channel.recv_stderr(4096).decode('utf-8', errors='replace')
                for line in chunk.replace("\r", "").split("\n"):
                    if line:
                        on_line('ERR', line)
                had_data = True
            if stdout.channel.exit_status_ready() and not stdout.channel.recv_ready() and not stdout.channel.recv_stderr_ready():
                return int(stdout.channel.recv_exit_status())
            if not had_data:
                time.sleep(0.05)
    finally:
        client.close()

def scheduler_docker_exec(target: dict[str, Any], command_text: str, timeout_seconds: int, on_line) -> int:
    container_name = str(target.get('docker_container_name') or target.get('preset_name') or target.get('id') or '').strip()
    shell_family = str(target.get('shell_family') or 'sh').strip().lower()
    shell_program = 'bash' if shell_family in {'bash', 'zsh', 'fish'} else 'sh'
    base_cmd = [*docker_command_prefix_args(), 'exec', container_name, shell_program, '-lc', command_text]
    process = subprocess.Popen(
        base_cmd,
        cwd=str(target.get('workspace_dir') or APP_DIR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
    )
    start_monotonic = time.monotonic()
    try:
        assert process.stdout is not None
        for raw_line in process.stdout:
            line = str(raw_line or '').rstrip("\r\n")
            if line:
                on_line('OUT', line)
            if timeout_seconds and (time.monotonic() - start_monotonic) > timeout_seconds:
                process.kill()
                on_line('ERR', f'Timeout alcanzado ({timeout_seconds}s).')
                return 124
        return int(process.wait())
    finally:
        try:
            if process.stdout:
                process.stdout.close()
        except Exception:
            pass

def scheduler_local_exec(target: dict[str, Any], command_text: str, timeout_seconds: int, on_line) -> int:
    args, cwd = scheduler_local_command_args(target, command_text)
    process = subprocess.Popen(
        args,
        cwd=cwd or None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
    )
    start_monotonic = time.monotonic()
    try:
        assert process.stdout is not None
        for raw_line in process.stdout:
            line = str(raw_line or '').rstrip("\r\n")
            if line:
                on_line('OUT', line)
            if timeout_seconds and (time.monotonic() - start_monotonic) > timeout_seconds:
                process.kill()
                on_line('ERR', f'Timeout alcanzado ({timeout_seconds}s).')
                return 124
        return int(process.wait())
    finally:
        try:
            if process.stdout:
                process.stdout.close()
        except Exception:
            pass

def resolve_scheduler_targets(task: dict[str, Any]) -> list[dict[str, Any]]:
    session_id = normalize_terminal_session_id(str(task.get('session_id') or 'default'))
    targets = build_targets(session_id)
    if str(task.get('dispatch_scope') or 'terminal') == 'session':
        return targets
    selected = {str(item) for item in task.get('target_ids') or []}
    return [item for item in targets if str(item.get('id') or '') in selected]


class SchedulerRuntime:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True, name='zenoterm-scheduler')
        self.tasks: dict[str, dict[str, Any]] = {}
        self.runtime: dict[str, dict[str, Any]] = {}
        self.running: dict[str, int] = {}
        self.log_tabs: dict[str, dict[str, Any]] = {}
        self.last_event_key = ''
        self.last_event_at = ''
        self.started = False

    def start(self) -> None:
        if self.started:
            return
        self.started = True
        self.thread.start()

    def _catalog_tabs(self) -> dict[str, dict[str, Any]]:
        tabs: dict[str, dict[str, Any]] = {
            'scheduler-system': {'id': 'scheduler-system', 'title': 'Scheduler', 'subtitle': 'Sistema', 'session_id': '', 'target_id': '', 'is_open': True, 'lines': [], 'next_seq': 1, 'running_count': 0, 'last_line_at': '', 'line_count': 0},
            'scheduler-docker-host': {'id': 'scheduler-docker-host', 'title': 'Docker host', 'subtitle': 'Grupos Docker', 'session_id': '', 'target_id': '', 'is_open': True, 'lines': [], 'next_seq': 1, 'running_count': 0, 'last_line_at': '', 'line_count': 0},
        }
        for session in get_terminal_sessions():
            for target in build_targets(session['id']):
                tab_id = self.tab_id_for_target(session['id'], str(target.get('id') or ''))
                tabs[tab_id] = {
                    'id': tab_id,
                    'title': str(target.get('preset_name') or target.get('label') or target.get('id') or 'Terminal'),
                    'subtitle': f"{session['name']} · {str(target.get('connection_scope') or 'terminal')}",
                    'session_id': session['id'],
                    'target_id': str(target.get('id') or ''),
                    'is_open': False,
                    'lines': [],
                    'next_seq': 1,
                    'running_count': 0,
                    'last_line_at': '',
                    'line_count': 0,
                }
        return tabs

    def reload_from_config(self, config: dict[str, Any] | None = None) -> None:
        tasks = [normalize_scheduler_task(item, index) for index, item in enumerate(((config or CONFIG).get('scheduler_management') or {}).get('tasks') or [])]
        filtered = [item for item in tasks if item]
        now_value = scheduler_now()
        with self.lock:
            self.tasks = {str(item['id']): item for item in filtered}
            self.runtime = {}
            for item in filtered:
                self.runtime[item['id']] = {'next_run_at': self.compute_initial_next_run(item, now_value)}
            existing_tabs = self.log_tabs
            self.log_tabs = self._catalog_tabs()
            for tab_id, existing in existing_tabs.items():
                if tab_id not in self.log_tabs:
                    self.log_tabs[tab_id] = existing
                    continue
                self.log_tabs[tab_id]['lines'] = existing.get('lines', [])
                self.log_tabs[tab_id]['next_seq'] = existing.get('next_seq', 1)
                self.log_tabs[tab_id]['last_line_at'] = existing.get('last_line_at', '')
                self.log_tabs[tab_id]['line_count'] = existing.get('line_count', len(existing.get('lines', [])))
                self.log_tabs[tab_id]['is_open'] = existing.get('is_open', False)
                self.log_tabs[tab_id]['running_count'] = existing.get('running_count', 0)

    def compute_initial_next_run(self, task: dict[str, Any], now_value: datetime | None = None) -> datetime | None:
        now_value = now_value or scheduler_now()
        schedule_type = str(task.get('schedule_type') or 'once')
        if not bool(task.get('enabled', True)):
            return None
        if schedule_type == 'once':
            if task.get('last_run_at'):
                return None
            return scheduler_parse_datetime(task.get('run_at'))
        if schedule_type == 'delay':
            if task.get('last_run_at'):
                return None
            anchor = scheduler_parse_datetime(task.get('schedule_anchor_at')) or now_value
            return anchor + timedelta(minutes=int(task.get('delay_minutes') or 0))
        if schedule_type == 'interval':
            anchor = scheduler_parse_datetime(task.get('schedule_anchor_at')) or now_value
            step = timedelta(minutes=max(1, int(task.get('interval_minutes') or 60)))
            next_run = anchor + step
            while next_run <= now_value:
                next_run += step
            return next_run
        if schedule_type == 'daily':
            hour, minute = scheduler_parse_time(task.get('daily_time'))
            candidate = now_value.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if candidate <= now_value:
                candidate += timedelta(days=1)
            return candidate
        if schedule_type == 'weekly':
            weekly_days = list(task.get('weekly_days') or [])
            if not weekly_days:
                return None
            hour, minute = scheduler_parse_time(task.get('weekly_time'))
            base = now_value.replace(second=0, microsecond=0)
            for delta_days in range(0, 14):
                candidate = (base + timedelta(days=delta_days)).replace(hour=hour, minute=minute)
                if candidate.weekday() in weekly_days and candidate > now_value:
                    return candidate
            return None
        return None

    def compute_following_run(self, task: dict[str, Any], current_run: datetime | None) -> datetime | None:
        if not current_run:
            return self.compute_initial_next_run(task, scheduler_now())
        schedule_type = str(task.get('schedule_type') or 'once')
        if schedule_type in {'once', 'delay', 'event'}:
            return None
        if schedule_type == 'interval':
            return current_run + timedelta(minutes=max(1, int(task.get('interval_minutes') or 60)))
        if schedule_type == 'daily':
            return (current_run + timedelta(days=1)).replace(second=0, microsecond=0)
        if schedule_type == 'weekly':
            weekly_days = list(task.get('weekly_days') or [])
            if not weekly_days:
                return None
            hour, minute = scheduler_parse_time(task.get('weekly_time'))
            base = current_run + timedelta(minutes=1)
            for delta_days in range(0, 14):
                candidate = (base + timedelta(days=delta_days)).replace(hour=hour, minute=minute, second=0, microsecond=0)
                if candidate.weekday() in weekly_days and candidate > current_run:
                    return candidate
            return None
        return None

    def tab_id_for_target(self, session_id: str, target_id: str) -> str:
        return f'scheduler-target::{normalize_terminal_session_id(session_id)}::{target_id}'

    def _ensure_tab(self, tab_id: str, title: str, subtitle: str, session_id: str = '', target_id: str = '') -> dict[str, Any]:
        with self.lock:
            tab = self.log_tabs.get(tab_id)
            if not tab:
                tab = {
                    'id': tab_id,
                    'title': title,
                    'subtitle': subtitle,
                    'session_id': session_id,
                    'target_id': target_id,
                    'is_open': False,
                    'lines': [],
                    'next_seq': 1,
                    'running_count': 0,
                    'last_line_at': '',
                    'line_count': 0,
                }
                self.log_tabs[tab_id] = tab
            return tab

    def append_log(self, tab_id: str, title: str, subtitle: str, source: str, message: str, level: str = 'INFO', session_id: str = '', target_id: str = '') -> None:
        tab = self._ensure_tab(tab_id, title, subtitle, session_id=session_id, target_id=target_id)
        with self.lock:
            line = scheduler_log_line(level, source, message)
            entry = {'seq': int(tab['next_seq']), 'line': line, 'timestamp': scheduler_iso(scheduler_now()), 'level': str(level).upper()}
            tab['next_seq'] = int(tab['next_seq']) + 1
            tab['lines'].append(entry)
            if len(tab['lines']) > 800:
                tab['lines'] = tab['lines'][-800:]
            tab['line_count'] = len(tab['lines'])
            tab['last_line_at'] = entry['timestamp']
            tab['is_open'] = True

    def public_state(self) -> dict[str, Any]:
        with self.lock:
            now_value = scheduler_now()
            tasks_public = []
            enabled_count = 0
            running_count = 0
            event_task_count = 0
            next_run_candidates: list[datetime] = []
            for task_id, task in self.tasks.items():
                runtime = self.runtime.get(task_id) or {}
                next_run = runtime.get('next_run_at')
                running = int(self.running.get(task_id, 0))
                if task.get('enabled'):
                    enabled_count += 1
                if running:
                    running_count += running
                if str(task.get('schedule_type') or '') == 'event':
                    event_task_count += 1
                if isinstance(next_run, datetime):
                    next_run_candidates.append(next_run)
                tasks_public.append({
                    **task,
                    'next_run_at': scheduler_iso(next_run),
                    'running_count': running,
                })
            tabs_public = []
            for tab in self.log_tabs.values():
                tabs_public.append({
                    'id': tab['id'],
                    'title': tab['title'],
                    'subtitle': tab['subtitle'],
                    'session_id': tab.get('session_id') or '',
                    'target_id': tab.get('target_id') or '',
                    'is_open': bool(tab.get('is_open', False) or tab.get('running_count', 0)),
                    'running_count': int(tab.get('running_count') or 0),
                    'last_seq': int(tab.get('next_seq') or 1) - 1,
                    'last_line_at': str(tab.get('last_line_at') or ''),
                    'line_count': int(tab.get('line_count') or 0),
                })
            catalog_targets = {}
            for session in get_terminal_sessions():
                catalog_targets[session['id']] = [
                    {
                        'id': str(target.get('id') or ''),
                        'label': str(target.get('label') or target.get('id') or ''),
                        'preset_name': str(target.get('preset_name') or ''),
                        'connection_scope': str(target.get('connection_scope') or ''),
                        'auth_type': str(target.get('auth_type') or ''),
                    }
                    for target in build_targets(session['id'])
                ]
            event_keys = sorted({str(task.get('event_key') or '').strip() for task in self.tasks.values() if str(task.get('event_key') or '').strip()})
            return {
                'tasks': sorted(tasks_public, key=lambda item: (str(item.get('category') or '').casefold(), str(item.get('subcategory') or '').casefold(), str(item.get('name') or '').casefold())),
                'stats': {
                    'enabled_count': enabled_count,
                    'running_count': running_count,
                    'event_task_count': event_task_count,
                    'next_run_at': scheduler_iso(min(next_run_candidates) if next_run_candidates else None),
                    'last_event_key': self.last_event_key,
                    'last_event_at': self.last_event_at,
                    'server_time': scheduler_iso(now_value),
                },
                'catalog': {
                    'sessions': get_terminal_sessions(),
                    'targets_by_session': catalog_targets,
                    'script_options': [
                        {'id': str(item.get('id') or ''), 'name': str(item.get('name') or ''), 'category': str(item.get('category') or 'General'), 'subcategory': str(item.get('subcategory') or 'General')}
                        for item in get_script_store()
                    ],
                    'docker_group_options': [
                        {'id': str(item.get('id') or ''), 'name': str(item.get('name') or '')}
                        for item in get_docker_groups()
                    ],
                    'event_keys': event_keys,
                },
                'log_tabs': sorted(tabs_public, key=lambda item: (0 if item['is_open'] else 1, str(item.get('title') or '').casefold())),
            }

    def get_log_lines(self, tab_id: str, after_seq: int = 0) -> dict[str, Any]:
        with self.lock:
            tab = self.log_tabs.get(tab_id)
            if not tab:
                return {'tab_id': tab_id, 'lines': [], 'last_seq': 0}
            lines = [item for item in tab.get('lines', []) if int(item.get('seq') or 0) > int(after_seq or 0)]
            return {'tab_id': tab_id, 'lines': lines, 'last_seq': int(tab.get('next_seq') or 1) - 1}

    def run_now(self, task_id: str, reason: str = 'manual') -> None:
        with self.lock:
            task = self.tasks.get(task_id)
            if not task:
                raise RuntimeError('Tarea no encontrada.')
            if not task.get('allow_overlap') and self.running.get(task_id, 0):
                raise RuntimeError('La tarea ya se está ejecutando.')
        threading.Thread(target=self._execute_task, args=(task_id, reason), daemon=True).start()

    def fire_event(self, event_key: str) -> int:
        key = str(event_key or '').strip()
        if not key:
            raise RuntimeError('Indica una clave de evento.')
        matched = []
        with self.lock:
            for task_id, task in self.tasks.items():
                if str(task.get('schedule_type') or '') == 'event' and str(task.get('event_key') or '').strip() == key and task.get('enabled'):
                    matched.append(task_id)
            self.last_event_key = key
            self.last_event_at = scheduler_iso(scheduler_now())
        for task_id in matched:
            try:
                self.run_now(task_id, reason=f'event:{key}')
            except Exception:
                pass
        self.append_log('scheduler-system', 'Scheduler', 'Sistema', 'Scheduler', f'Evento disparado: {key} · tareas={len(matched)}', 'INFO')
        return len(matched)

    def _persist_task_state(self, task_id: str, **updates: Any) -> None:
        global CONFIG
        with SCHEDULER_STATE_LOCK:
            current = load_config()
            tasks = [normalize_scheduler_task(item, index) for index, item in enumerate(((current.get('scheduler_management') or {}).get('tasks') or []))]
            changed = False
            for index, task in enumerate(tasks):
                if not task or str(task.get('id') or '') != task_id:
                    continue
                task.update(updates)
                task['updated_at'] = scheduler_iso(scheduler_now())
                tasks[index] = task
                changed = True
                break
            if changed:
                current.setdefault('scheduler_management', {})
                current['scheduler_management']['tasks'] = [item for item in tasks if item]
                save_config(current)
                CONFIG = current
                with self.lock:
                    if task_id in self.tasks:
                        self.tasks[task_id].update(updates)
                        self.tasks[task_id]['updated_at'] = scheduler_iso(scheduler_now())

    def _execute_task(self, task_id: str, reason: str) -> None:
        with self.lock:
            task = dict(self.tasks.get(task_id) or {})
            if not task:
                return
            self.running[task_id] = int(self.running.get(task_id, 0)) + 1
        started_at = scheduler_now()
        self._persist_task_state(task_id, last_status='running', last_run_at=scheduler_iso(started_at), last_message=f'Ejecutándose ({reason})')
        source_name = str(task.get('name') or task_id)
        had_error = False
        try:
            if str(task.get('launch_type') or '') == 'docker_group':
                tab_id = 'scheduler-docker-host'
                self._ensure_tab(tab_id, 'Docker host', 'Grupos Docker')
                with self.lock:
                    self.log_tabs[tab_id]['running_count'] = int(self.log_tabs[tab_id].get('running_count') or 0) + 1
                    self.log_tabs[tab_id]['is_open'] = True
                self.append_log(tab_id, 'Docker host', 'Grupos Docker', source_name, f'Arranque de grupo Docker ({reason})', 'INFO')
                result = run_docker_group(str(task.get('docker_group_id') or ''))
                for item in result.get('logs') or []:
                    self.append_log(tab_id, 'Docker host', 'Grupos Docker', source_name, item.get('command') or item.get('entry') or 'docker', 'INFO' if item.get('ok') else 'ERR')
                    if item.get('stdout'):
                        for line in str(item.get('stdout') or '').splitlines():
                            if line:
                                self.append_log(tab_id, 'Docker host', 'Grupos Docker', source_name, line, 'OUT')
                    if item.get('stderr'):
                        for line in str(item.get('stderr') or '').splitlines():
                            if line:
                                self.append_log(tab_id, 'Docker host', 'Grupos Docker', source_name, line, 'ERR')
                if not result.get('ok'):
                    had_error = True
                    raise RuntimeError('El grupo Docker devolvió errores en uno o más pasos.')
            else:
                targets = resolve_scheduler_targets(task)
                if not targets:
                    raise RuntimeError('La tarea no tiene terminales destino válidas.')
                for target in targets:
                    tab_id = self.tab_id_for_target(str(task.get('session_id') or 'default'), str(target.get('id') or ''))
                    title = str(target.get('preset_name') or target.get('label') or target.get('id') or 'Terminal')
                    subtitle = f"{str(task.get('session_id') or 'default')} · {str(target.get('connection_scope') or 'terminal')}"
                    self._ensure_tab(tab_id, title, subtitle, session_id=str(task.get('session_id') or ''), target_id=str(target.get('id') or ''))
                    with self.lock:
                        self.log_tabs[tab_id]['running_count'] = int(self.log_tabs[tab_id].get('running_count') or 0) + 1
                        self.log_tabs[tab_id]['is_open'] = True
                    self.append_log(tab_id, title, subtitle, source_name, f"Inicio ({reason}) en {title}", 'INFO', session_id=str(task.get('session_id') or ''), target_id=str(target.get('id') or ''))
                    command_text = scheduler_command_from_task(task, target)
                    self.append_log(tab_id, title, subtitle, source_name, f'Comando: {command_text}', 'PROC', session_id=str(task.get('session_id') or ''), target_id=str(target.get('id') or ''))
                    def on_line(level, line):
                        self.append_log(tab_id, title, subtitle, source_name, line, level, session_id=str(task.get('session_id') or ''), target_id=str(target.get('id') or ''))
                    timeout_seconds = int(task.get('timeout_seconds') or 0)
                    scope = str(target.get('connection_scope') or 'local')
                    if scope == 'remote':
                        exit_code = scheduler_remote_exec(target, command_text, timeout_seconds, on_line)
                    elif scope == 'docker':
                        exit_code = scheduler_docker_exec(target, command_text, timeout_seconds, on_line)
                    else:
                        exit_code = scheduler_local_exec(target, command_text, timeout_seconds, on_line)
                    if exit_code != 0:
                        had_error = True
                        self.append_log(tab_id, title, subtitle, source_name, f'Finalizado con código {exit_code}', 'ERR', session_id=str(task.get('session_id') or ''), target_id=str(target.get('id') or ''))
                    else:
                        self.append_log(tab_id, title, subtitle, source_name, 'Finalizado correctamente', 'OK', session_id=str(task.get('session_id') or ''), target_id=str(target.get('id') or ''))
                    with self.lock:
                        self.log_tabs[tab_id]['running_count'] = max(0, int(self.log_tabs[tab_id].get('running_count') or 0) - 1)
                        if not bool(task.get('keep_log_tab_open', True)) and not self.log_tabs[tab_id]['running_count']:
                            self.log_tabs[tab_id]['is_open'] = False
        except Exception as exc:
            had_error = True
            self.append_log('scheduler-system', 'Scheduler', 'Sistema', source_name, f'{type(exc).__name__}: {exc}', 'ERR')
        finally:
            finished_at = scheduler_now()
            duration = max(0.0, (finished_at - started_at).total_seconds())
            status = 'error' if had_error else 'success'
            message = 'Finalizado con errores.' if had_error else 'Finalizado correctamente.'
            self._persist_task_state(task_id, last_status=status, last_finished_at=scheduler_iso(finished_at), last_message=message, last_duration_seconds=round(duration, 3))
            with self.lock:
                self.running[task_id] = max(0, int(self.running.get(task_id, 0)) - 1)
                if self.running[task_id] == 0:
                    self.running.pop(task_id, None)
                docker_tab = self.log_tabs.get('scheduler-docker-host')
                if docker_tab and docker_tab.get('running_count'):
                    docker_tab['running_count'] = max(0, int(docker_tab.get('running_count') or 0) - 1)
                    if not bool(task.get('keep_log_tab_open', True)) and not docker_tab['running_count']:
                        docker_tab['is_open'] = False

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            now_value = scheduler_now()
            due: list[tuple[str, datetime]] = []
            with self.lock:
                for task_id, task in list(self.tasks.items()):
                    runtime = self.runtime.setdefault(task_id, {'next_run_at': self.compute_initial_next_run(task, now_value)})
                    next_run = runtime.get('next_run_at')
                    if not task.get('enabled') or not isinstance(next_run, datetime):
                        continue
                    if next_run <= now_value:
                        runtime['next_run_at'] = self.compute_following_run(task, next_run)
                        if not task.get('allow_overlap') and self.running.get(task_id, 0):
                            self._persist_task_state(task_id, last_status='skipped', last_message='Omitida por solape con otra ejecución activa.')
                            continue
                        due.append((task_id, next_run))
            for task_id, _ in due:
                threading.Thread(target=self._execute_task, args=(task_id, 'schedule'), daemon=True).start()
            time.sleep(1.0)


SCHEDULER_RUNTIME = SchedulerRuntime()
SCHEDULER_RUNTIME.start()
SCHEDULER_RUNTIME.reload_from_config(CONFIG)


def user_has_permission(user: dict[str, Any] | None, permission: str) -> bool:
    payload = serialize_current_user(user) or {}
    return bool((payload.get("permissions") or {}).get(permission))


def target_allowed_for_user(user: dict[str, Any] | None, target: dict[str, Any]) -> bool:
    if not user:
        return AUTH_MODE == "none"
    scope = str(target.get("connection_scope") or ("local" if str(target.get("mode") or "") == "direct" else "remote"))
    if scope == "local":
        return user_has_permission(user, "use_local_terminals")
    if scope == "remote":
        return user_has_permission(user, "use_remote_terminals")
    if scope == "docker":
        return user_has_permission(user, "use_docker")
    return False



def filtered_public_targets(user: dict[str, Any] | None, active_session_id: str | None = None) -> list[dict[str, Any]]:
    runtime_targets = build_targets(active_session_id, user=user) if user is not None else TARGETS
    return [item for item in public_targets(runtime_targets, active_session_id=active_session_id) if target_allowed_for_user(user, item)]

def empty_scheduler_state() -> dict[str, Any]:
    return {
        "tasks": [],
        "log_tabs": [],
        "catalog": {"sessions": [], "targets_by_session": {}, "script_options": [], "docker_group_options": [], "event_keys": []},
        "stats": {},
    }



def build_docker_overview_for_user(user: dict[str, Any] | None, active_session_id: str | None = None) -> dict[str, Any]:
    if not user_has_permission(user, "use_docker"):
        return {
            "engine": {"connected": False, "message": "Docker no disponible para este perfil."},
            "host_os": HOST_OS,
            "host_os_label": TARGET_OS_LABELS.get(HOST_OS, HOST_OS),
            "containers": [],
            "running_count": 0,
            "stopped_count": 0,
            "groups": [],
            "targets": [],
        }
    overview = build_docker_overview()
    if user is not None:
        overview["targets"] = [item for item in filtered_public_targets(user, active_session_id=active_session_id) if str(item.get("connection_scope") or "") == "docker"]
    return overview

def build_runtime_config(user: dict[str, Any] | None = None, active_session_id: str | None = None) -> dict[str, Any]:
    effective_active_session = normalize_optional_session_id(active_session_id) if user is not None else get_active_session_id()
    auth_payload = {
        "mode": AUTH_MODE,
        "login_required": AUTH_MODE != "none",
        "session_ttl_seconds": SESSION_TTL_SECONDS,
        "admin_username": str((CONFIG.get("auth") or {}).get("admin_username") or "admin"),
    }
    if AUTH_MODE != "none" and user is None:
        return {
            "title": APP_TITLE,
            "auth": auth_payload,
            "current_user": None,
            "host_os": HOST_OS,
            "host_os_label": TARGET_OS_LABELS.get(HOST_OS, HOST_OS),
            "supported_target_oses": TARGET_OS_OPTIONS,
            "targets": [],
            "windows_shells": list(WINDOWS_SHELLS.values()),
            "local_shells": list(LOCAL_SHELLS.values()),
            "local_shells_by_os": {key: list(value.values()) for key, value in LOCAL_SHELL_CATALOG.items()},
            "shell_catalog": {key: list(value.values()) for key, value in GENERIC_SHELL_CATALOG.items()},
            "ui": get_ui_config(),
            "remote_defaults": CONFIG.get("remote_defaults") or {},
            "terminal_presets": [],
            "terminal_sessions": [],
            "active_session_id": "",
            "session_terminal_overrides": {},
            "app_scripts": [],
            "docker_management": build_docker_overview_for_user(None),
            "scheduler_management": empty_scheduler_state(),
            "workspace_dir": str(APP_DIR),
            "scripts_dir": str(SCRIPTS_DIR),
            "administration": {"enabled": False, "roles": [], "users": []},
        }
    permissions = (serialize_current_user(user) or {}).get("permissions") or {}
    return {
        "title": APP_TITLE,
        "auth": auth_payload,
        "current_user": serialize_current_user(user),
        "host_os": HOST_OS,
        "host_os_label": TARGET_OS_LABELS.get(HOST_OS, HOST_OS),
        "supported_target_oses": TARGET_OS_OPTIONS,
        "targets": filtered_public_targets(user, active_session_id=effective_active_session),
        "windows_shells": list(WINDOWS_SHELLS.values()),
        "local_shells": list(LOCAL_SHELLS.values()),
        "local_shells_by_os": {key: list(value.values()) for key, value in LOCAL_SHELL_CATALOG.items()},
        "shell_catalog": {key: list(value.values()) for key, value in GENERIC_SHELL_CATALOG.items()},
        "ui": get_ui_config(),
        "remote_defaults": CONFIG.get("remote_defaults") or {},
        "terminal_presets": [normalize_preset(item, i) for i, item in enumerate(get_base_terminal_presets())],
        "terminal_sessions": get_terminal_sessions(user),
        "active_session_id": effective_active_session,
        "session_terminal_overrides": get_session_terminal_overrides(user),
        "app_scripts": get_script_store(),
        "docker_management": build_docker_overview_for_user(user, effective_active_session),
        "scheduler_management": SCHEDULER_RUNTIME.public_state() if permissions.get("manage_scheduler") else empty_scheduler_state(),
        "workspace_dir": str(APP_DIR),
        "scripts_dir": str(SCRIPTS_DIR),
        "administration": build_administration_state(user),
    }



def get_active_session_id_from_signed_cookie(signed_cookie: str | None, user: dict[str, Any] | None = None) -> str:
    if user is None:
        return get_active_session_id()
    record = get_session_record_from_signed_cookie(signed_cookie) if signed_cookie else None
    return get_active_session_id(user=user, session_record=record)


def runtime_config_for_request(request: Request, user: dict[str, Any] | None) -> dict[str, Any]:
    return build_runtime_config(user, get_active_session_id_from_signed_cookie(request.cookies.get(COOKIE_NAME), user))


def update_signed_session_record(signed_cookie: str | None, **updates: Any) -> dict[str, Any] | None:
    if not signed_cookie or "." not in str(signed_cookie):
        return None
    token = str(signed_cookie).rsplit(".", 1)[0]
    with SESSION_LOCK:
        record = SESSION_STORE.get(token)
        if not record:
            return None
        record.update(updates)
        SESSION_STORE[token] = record
        return dict(record)


def persist_user_session_preferences(user: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    current = load_config()
    user_store = current.get("user_management") or {}
    raw_users = user_store.get("users") or []
    updated_users: list[dict[str, Any]] = []
    session_items = normalize_user_terminal_sessions(data.get("terminal_sessions") or [])
    valid_session_ids = {item["id"] for item in session_items}
    default_session_id = normalize_optional_session_id(data.get("default_session_id"))
    if default_session_id not in valid_session_ids:
        default_session_id = ""
    session_overrides = normalize_session_override_map(data.get("session_terminal_overrides") or {}, valid_session_ids)
    target_user_id = str(user.get("id") or "")
    for raw in raw_users:
        if not isinstance(raw, dict):
            continue
        next_item = dict(raw)
        if str(raw.get("id") or "") == target_user_id:
            next_item["terminal_sessions"] = session_items
            next_item["default_session_id"] = default_session_id
            next_item["session_terminal_overrides"] = session_overrides
        updated_users.append(next_item)
    user_store["users"] = updated_users
    current["user_management"] = user_store
    save_config(current)
    global CONFIG
    CONFIG = current
    refreshed_user = find_user_by_id(target_user_id) or find_user_by_username(str(user.get("username") or ""))
    return refreshed_user or user


def resolve_target_for_user(user: dict[str, Any] | None, target_id: str, active_session_id: str | None = None) -> dict[str, Any] | None:
    raw_target_id = str(target_id or "").strip()
    if not raw_target_id:
        return None
    session_hint, base_target_id = split_scoped_target_id(raw_target_id)
    if user is not None:
        candidate_sessions: list[str] = []
        normalized_active = normalize_optional_session_id(active_session_id)
        for candidate in [session_hint, normalized_active, get_user_default_session_id(user), ""]:
            if candidate is None:
                continue
            normalized_candidate = normalize_optional_session_id(candidate)
            if normalized_candidate not in candidate_sessions:
                candidate_sessions.append(normalized_candidate)
        for candidate_session_id in candidate_sessions:
            for target in build_targets(candidate_session_id, user=user):
                if str(target.get("id") or "") == raw_target_id:
                    return target
                if str(target.get("_base_id") or "") == base_target_id and session_target_scope_token(target.get("session_id")) == session_target_scope_token(session_hint):
                    return target
        return None
    target = TARGETS_BY_ID.get(raw_target_id)
    if target:
        return target
    if session_hint is not None:
        return TARGETS_BY_ID.get(base_target_id)
    return None


APP = FastAPI(title=APP_TITLE)
if WEB_DIR.exists():
    APP.mount("/web", StaticFiles(directory=str(WEB_DIR)), name="web")


@APP.get("/")
async def index() -> Any:
    p = WEB_DIR / "index.html"
    return FileResponse(p) if p.exists() else JSONResponse({"error": "Falta web/index.html"}, status_code=500)


@APP.get("/api/config")
async def api_config(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    return JSONResponse(runtime_config_for_request(request, user))


@APP.get("/api/aliases")
async def api_aliases(target_id: str, request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    target = resolve_target_for_user(user, target_id, get_active_session_id_from_signed_cookie(request.cookies.get(COOKIE_NAME), user))
    if not target:
        return JSONResponse({"ok": False, "message": "Target no encontrado."}, status_code=404)
    if not target_allowed_for_user(user, target):
        return JSONResponse({"ok": False, "message": "El perfil actual no puede usar este target."}, status_code=403)
    alias_group = alias_group_for_target(target)
    return JSONResponse({
        "ok": True,
        "aliases": list_aliases_for_target(target),
        "alias_support": str(target.get("alias_support") or "generic"),
        "alias_group": alias_group,
        "alias_group_label": alias_group_label(alias_group),
    })


@APP.post("/api/aliases")
async def api_aliases_create(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    data = await request.json()
    target_id = str(data.get("target_id") or "")
    alias_name = str(data.get("alias_name") or "").strip()
    command_text = str(data.get("command_text") or "").strip()
    folder = normalize_alias_folder(str(data.get("folder") or data.get("group") or ""))
    if not alias_name or not command_text:
        return JSONResponse({"ok": False, "message": "Alias y comando son obligatorios."}, status_code=400)
    target = resolve_target_for_user(user, target_id, get_active_session_id_from_signed_cookie(request.cookies.get(COOKIE_NAME), user))
    if not target:
        return JSONResponse({"ok": False, "message": "Target no encontrado."}, status_code=404)
    if not target_allowed_for_user(user, target):
        return JSONResponse({"ok": False, "message": "El perfil actual no puede usar este target."}, status_code=403)
    entry = create_alias_for_target(target, alias_name, command_text, folder)
    alias_group = alias_group_for_target(target)
    return JSONResponse({"ok": True, "alias": entry, "alias_group": alias_group, "alias_group_label": alias_group_label(alias_group)})


@APP.delete("/api/aliases/{alias_id}")
async def api_aliases_delete(alias_id: str, target_id: str, request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    target = resolve_target_for_user(user, target_id, get_active_session_id_from_signed_cookie(request.cookies.get(COOKIE_NAME), user))
    if not target:
        return JSONResponse({"ok": False, "message": "Target no encontrado."}, status_code=404)
    if not target_allowed_for_user(user, target):
        return JSONResponse({"ok": False, "message": "El perfil actual no puede usar este target."}, status_code=403)
    deleted = delete_alias_for_target(target, alias_id)
    if not deleted:
        return JSONResponse({"ok": False, "message": "Alias no encontrado."}, status_code=404)
    return JSONResponse({"ok": True})


@APP.post("/api/session/select")
async def api_session_select(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    data = await request.json()
    requested_session = normalize_optional_session_id(data.get("session_id"))
    sessions = get_terminal_sessions(user)
    valid_ids = {item["id"] for item in sessions}
    if requested_session and requested_session not in valid_ids:
        return JSONResponse({"ok": False, "message": "La sesión seleccionada no existe para este usuario."}, status_code=404)
    update_signed_session_record(request.cookies.get(COOKIE_NAME), active_session_id=requested_session)
    refreshed_user = find_user_by_id(str(user.get("id") or "")) or user
    return JSONResponse({"ok": True, "config": build_runtime_config(refreshed_user, requested_session)})

@APP.post("/api/session/preferences/save")
async def api_session_preferences_save(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    data = await request.json()
    saved_user = persist_user_session_preferences(user, data)
    requested_active_session = normalize_optional_session_id(data.get("active_session_id"))
    valid_ids = {item["id"] for item in get_terminal_sessions(saved_user)}
    if requested_active_session not in valid_ids:
        requested_active_session = get_user_default_session_id(saved_user)
    update_signed_session_record(request.cookies.get(COOKIE_NAME), active_session_id=requested_active_session)
    return JSONResponse({"ok": True, "config": build_runtime_config(saved_user, requested_active_session)})


@APP.post("/api/scripts/save")
async def api_scripts_save(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    if not user_has_permission(user, "manage_scripts"):
        return JSONResponse({"ok": False, "message": "Solo el administrador puede guardar scripts globales."}, status_code=403)
    data = await request.json()
    incoming_scripts = data.get("scripts") or []
    normalized_scripts: list[dict[str, Any]] = []
    for index, item in enumerate(incoming_scripts):
        normalized = normalize_script_entry(item, index)
        if normalized:
            normalized_scripts.append(normalized)
    current = load_config()
    current["app_scripts"] = merge_script_store_with_discovery(normalized_scripts)
    save_config(current)
    global CONFIG
    CONFIG = current
    return JSONResponse({"ok": True, "config": runtime_config_for_request(request, user)})


@APP.post("/api/config/save")
async def api_config_save(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    data = await request.json()
    if user_has_permission(user, "manage_config"):
        current = load_config()
        current["ui"] = {
            **(current.get("ui") or {}),
            "default_scrollback": int((data.get("ui") or {}).get("default_scrollback") or 20000),
            "command_history_limit": max(1, int((data.get("ui") or {}).get("command_history_limit") or 50)),
        }
        remote_defaults = data.get("remote_defaults") or {}
        current["remote_defaults"] = {
            "host": str(remote_defaults.get("host") or ""),
            "port": int(remote_defaults.get("port") or 22),
            "username": str(remote_defaults.get("username") or ""),
            "private_key_path": str(remote_defaults.get("private_key_path") or ""),
            "strict_host_key": bool(remote_defaults.get("strict_host_key", True)),
        }
        incoming_presets = data.get("terminal_presets") or []
        normalized = [normalize_preset(item, i) for i, item in enumerate(incoming_presets)]
        local_overrides: dict[str, dict[str, Any]] = {}
        remote_presets: list[dict[str, Any]] = []
        for preset in normalized:
            if preset["scope"] == "local":
                shell_id = str(preset.get("shell_family") or "")
                if shell_id:
                    local_overrides[shell_id] = {
                        "name": str(preset.get("name") or ""),
                        "startup_command": str(preset.get("startup_command") or ""),
                        "command_file_content": str(preset.get("command_file_content") or ""),
                        "launch_command": str(preset.get("launch_command") or ""),
                    }
            else:
                remote_presets.append({
                    "id": preset["id"],
                    "name": preset["name"],
                    "scope": "remote",
                    "auth_type": preset["auth_type"],
                    "target_os": preset["target_os"],
                    "shell_family": preset["shell_family"],
                    "host": preset["host"],
                    "port": preset["port"],
                    "username": preset["username"],
                    "private_key_path": preset["private_key_path"],
                    "strict_host_key": preset["strict_host_key"],
                    "startup_command": preset["startup_command"],
                    "command_file_content": preset["command_file_content"],
                    "launch_command": preset["launch_command"],
                })
        current["local_terminal_overrides"] = local_overrides
        current["terminal_presets"] = remote_presets
        save_config(current)
        global CONFIG
        CONFIG = current
    saved_user = persist_user_session_preferences(user, data)
    requested_active_session = normalize_optional_session_id(data.get("active_session_id"))
    valid_ids = {item["id"] for item in get_terminal_sessions(saved_user)}
    if requested_active_session not in valid_ids:
        requested_active_session = get_user_default_session_id(saved_user)
    update_signed_session_record(request.cookies.get(COOKIE_NAME), active_session_id=requested_active_session)
    return JSONResponse({"ok": True, "config": build_runtime_config(saved_user, requested_active_session)})

@APP.post("/api/administration/save")
async def api_administration_save(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    if not user_has_permission(user, "manage_administration"):
        return JSONResponse({"ok": False, "message": "Solo el administrador puede gestionar usuarios y permisos."}, status_code=403)
    data = await request.json()
    incoming_users = data.get("users") or []
    existing_by_id = {str(item.get("id") or ""): item for item in get_users()}
    normalized_users: list[dict[str, Any]] = []
    used_usernames: set[str] = set()
    enabled_admins = 0
    for index, raw in enumerate(incoming_users):
        if not isinstance(raw, dict):
            continue
        user_id = str(raw.get("id") or f"user-{index + 1}")
        username = sanitize_username(raw.get("username"), f"user-{index + 1}")
        display_name = str(raw.get("display_name") or username or f"Usuario {index + 1}").strip() or username
        role = normalize_role(raw.get("role"))
        enabled = bool(raw.get("enabled", True))
        if username in used_usernames:
            return JSONResponse({"ok": False, "message": f"El usuario '{username}' está repetido."}, status_code=400)
        used_usernames.add(username)
        explorer_entries = [entry for entry in (normalize_explorer_entry(item) for item in (raw.get("explorer_entries") or [])) if entry]
        if role == "administrator":
            enabled_admins += 1 if enabled else 0
            explorer_entries = []
        existing = existing_by_id.get(user_id) or {}
        password_salt = str(existing.get("password_salt") or "")
        password_hash = str(existing.get("password_hash") or "")
        password_iterations = int(existing.get("password_iterations") or 310000)
        new_password = str(raw.get("new_password") or "")
        if new_password:
            password_payload = hash_password(new_password)
            password_salt = password_payload["password_salt"]
            password_hash = password_payload["password_hash"]
            password_iterations = int(password_payload["password_iterations"])
        elif not password_hash or not password_salt:
            default_password = "admin" if role == "administrator" else "user"
            password_payload = hash_password(default_password)
            password_salt = password_payload["password_salt"]
            password_hash = password_payload["password_hash"]
            password_iterations = int(password_payload["password_iterations"])
        terminal_sessions = normalize_user_terminal_sessions(raw.get("terminal_sessions") if "terminal_sessions" in raw else existing.get("terminal_sessions") or [])
        valid_session_ids = {item["id"] for item in terminal_sessions}
        default_session_id = normalize_optional_session_id(raw.get("default_session_id") if "default_session_id" in raw else existing.get("default_session_id"))
        if default_session_id not in valid_session_ids:
            default_session_id = ""
        session_terminal_overrides = normalize_session_override_map(raw.get("session_terminal_overrides") if "session_terminal_overrides" in raw else existing.get("session_terminal_overrides") or {}, valid_session_ids)
        normalized_users.append({
            "id": user_id,
            "username": username,
            "display_name": display_name,
            "role": role,
            "enabled": enabled,
            "password_salt": password_salt,
            "password_hash": password_hash,
            "password_iterations": password_iterations,
            "explorer_entries": explorer_entries,
            "terminal_sessions": terminal_sessions,
            "default_session_id": default_session_id,
            "session_terminal_overrides": session_terminal_overrides,
        })
    if not normalized_users:
        return JSONResponse({"ok": False, "message": "Debe existir al menos un usuario."}, status_code=400)
    if enabled_admins < 1:
        return JSONResponse({"ok": False, "message": "Debe existir al menos un administrador habilitado."}, status_code=400)
    current = load_config()
    current["user_management"] = {"users": normalized_users}
    first_admin = next((item for item in normalized_users if item.get("role") == "administrator" and item.get("enabled", True)), None)
    auth = current.get("auth") or {}
    auth["admin_username"] = str(first_admin.get("username") or "admin") if first_admin else "admin"
    current["auth"] = auth
    save_config(current)
    global CONFIG
    CONFIG = current
    saved_user = find_user_by_id(str(user.get("id") or "")) or find_user_by_username(str(user.get("username") or ""))
    active_session_id = get_active_session_id_from_signed_cookie(request.cookies.get(COOKIE_NAME), saved_user)
    return JSONResponse({"ok": True, "config": build_runtime_config(saved_user, active_session_id)})

@APP.post("/api/download/current-path")
async def api_download_current_path(request: Request) -> Response:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    data = await request.json()
    target_id = str(data.get("target_id") or "").strip()
    current_path = str(data.get("current_path") or "").strip()
    if not target_id:
        return JSONResponse({"ok": False, "message": "Falta target_id."}, status_code=400)
    if not current_path:
        return JSONResponse({"ok": False, "message": "No se pudo detectar la ruta actual de la terminal."}, status_code=400)
    target = resolve_target_for_user(user, target_id, get_active_session_id_from_signed_cookie(request.cookies.get(COOKIE_NAME), user)) or {}
    if not target or not target_allowed_for_user(user, target):
        return JSONResponse({"ok": False, "message": "El perfil actual no puede usar este target."}, status_code=403)
    if str(target.get("connection_scope") or "local") != "local":
        return JSONResponse({"ok": False, "message": "La descarga en zip solo está soportada para terminales locales del host actual."}, status_code=400)
    resolved_path = Path(os.path.expanduser(current_path)).resolve()
    if not resolved_path.exists():
        return JSONResponse({"ok": False, "message": f"La ruta no existe en el host actual: {resolved_path}"}, status_code=404)
    if not resolved_path.is_dir():
        return JSONResponse({"ok": False, "message": f"La ruta no es una carpeta: {resolved_path}"}, status_code=400)
    temp_file = tempfile.NamedTemporaryFile(prefix="zenoterm-download-", suffix=".zip", delete=False)
    temp_file_path = Path(temp_file.name)
    temp_file.close()
    try:
        zip_directory_to_file(resolved_path, temp_file_path)
    except Exception as exc:
        try:
            temp_file_path.unlink(missing_ok=True)
        except Exception:
            pass
        return JSONResponse({"ok": False, "message": f"No se pudo generar el zip: {type(exc).__name__}: {exc}"}, status_code=500)
    download_name = build_download_zip_filename(resolved_path)
    return FileResponse(
        path=temp_file_path,
        media_type="application/zip",
        filename=download_name,
        background=BackgroundTask(lambda p=str(temp_file_path): os.path.exists(p) and os.unlink(p)),
    )

def store_uploaded_files_in_temp(files: list[Any]) -> Path:
    temp_root = Path(tempfile.mkdtemp(prefix="zenoterm-import-"))
    normalized_entries: list[tuple[list[str], Any]] = []
    root_candidates: list[str] = []

    for upload in files:
        raw_name = str(getattr(upload, "filename", "") or "").replace("\\", "/").strip("/")
        if not raw_name:
            continue
        relative_path = Path(raw_name)
        safe_parts: list[str] = []
        for part in relative_path.parts:
            cleaned = str(part or "").strip()
            if not cleaned or cleaned in {".", ".."}:
                continue
            safe_parts.append(cleaned)
        if not safe_parts:
            continue
        normalized_entries.append((safe_parts, upload))
        if len(safe_parts) > 1:
            root_candidates.append(safe_parts[0])

    strip_common_root = False
    if normalized_entries and root_candidates and len(root_candidates) == len(normalized_entries):
        first_root = root_candidates[0]
        strip_common_root = all(candidate == first_root for candidate in root_candidates)

    for safe_parts, upload in normalized_entries:
        effective_parts = safe_parts[1:] if strip_common_root and len(safe_parts) > 1 else safe_parts
        if not effective_parts:
            effective_parts = [safe_parts[-1]]
        destination = temp_root.joinpath(*effective_parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        upload.file.seek(0)
        with destination.open("wb") as fh:
            shutil.copyfileobj(upload.file, fh)
    return temp_root


def copy_directory_contents(source_dir: Path, destination_dir: Path, overwrite: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "copied": 0,
        "overwritten": 0,
        "skipped": 0,
        "details": {"copied": [], "overwritten": [], "skipped": []},
    }
    details = result["details"]

    for root, _, filenames in os.walk(source_dir):
        root_path = Path(root)
        for filename in filenames:
            src_file = root_path / filename
            rel_path = src_file.relative_to(source_dir)
            dest_file = destination_dir / rel_path
            rel_text = rel_path.as_posix()

            existed_before = dest_file.exists()
            if existed_before and not overwrite:
                result["skipped"] += 1
                details["skipped"].append(rel_text)
                continue

            if dest_file.parent.exists() and dest_file.parent.is_file():
                if overwrite:
                    dest_file.parent.unlink()
                else:
                    result["skipped"] += 1
                    details["skipped"].append(rel_text)
                    continue

            dest_file.parent.mkdir(parents=True, exist_ok=True)

            if existed_before and overwrite:
                dest_file.unlink(missing_ok=True)
                shutil.copy2(src_file, dest_file)
                result["overwritten"] += 1
                details["overwritten"].append(rel_text)
            else:
                shutil.copy2(src_file, dest_file)
                result["copied"] += 1
                details["copied"].append(rel_text)

    return result



@APP.post("/api/import/current-path")
async def api_import_current_path(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)

    form = await request.form()
    target_id = str(form.get("target_id") or "").strip()
    current_path = str(form.get("current_path") or "").strip()
    overwrite = str(form.get("overwrite") or "false").strip().lower() in {"1", "true", "yes", "on"}
    files = list(form.getlist("files"))

    if not target_id:
        return JSONResponse({"ok": False, "message": "Falta target_id."}, status_code=400)
    if not current_path:
        return JSONResponse({"ok": False, "message": "No se pudo detectar la ruta actual de la terminal."}, status_code=400)
    if not files:
        return JSONResponse({"ok": False, "message": "No se seleccionó ninguna carpeta o no había archivos para copiar."}, status_code=400)

    target = resolve_target_for_user(user, target_id, get_active_session_id_from_signed_cookie(request.cookies.get(COOKIE_NAME), user)) or {}
    if not target or not target_allowed_for_user(user, target):
        return JSONResponse({"ok": False, "message": "El perfil actual no puede usar este target."}, status_code=403)
    if str(target.get("connection_scope") or "local") != "local":
        return JSONResponse({"ok": False, "message": "La importación de carpetas solo está soportada para terminales locales del host actual."}, status_code=400)

    destination_dir = Path(os.path.expanduser(current_path)).resolve()
    if not destination_dir.exists():
        return JSONResponse({"ok": False, "message": f"La ruta no existe en el host actual: {destination_dir}"}, status_code=404)
    if not destination_dir.is_dir():
        return JSONResponse({"ok": False, "message": f"La ruta no es una carpeta: {destination_dir}"}, status_code=400)

    temp_root: Path | None = None
    try:
        temp_root = store_uploaded_files_in_temp(files)
        result = copy_directory_contents(temp_root, destination_dir, overwrite=overwrite)
        mode_text = "sobrescribiendo duplicados" if overwrite else "sin sobrescribir duplicados"
        return JSONResponse({
            "ok": True,
            "message": f"Importación completada ({mode_text}). Copiados: {result['copied']}, sobrescritos: {result['overwritten']}, omitidos: {result['skipped']}.",
            "result": result,
        })
    except Exception as exc:
        return JSONResponse({"ok": False, "message": f"No se pudo copiar la carpeta seleccionada: {type(exc).__name__}: {exc}"}, status_code=500)
    finally:
        if temp_root is not None:
            shutil.rmtree(temp_root, ignore_errors=True)



@APP.get('/api/explorer/list')
async def api_explorer_list(request: Request, path: str = '') -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({'ok': False, 'message': 'No autenticado.'}, status_code=401)
    try:
        resolved, permission = resolve_explorer_path_for_user(user, path)
        payload = list_directory_entries_for_user(resolved, user, permission)
        return JSONResponse({'ok': True, **payload})
    except PermissionError as exc:
        return JSONResponse({'ok': False, 'message': str(exc)}, status_code=403)
    except Exception as exc:
        return JSONResponse({'ok': False, 'message': f'{type(exc).__name__}: {exc}'}, status_code=400)


@APP.get('/api/explorer/read-text')
async def api_explorer_read_text(path: str, request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({'ok': False, 'message': 'No autenticado.'}, status_code=401)
    try:
        resolved, permission = resolve_explorer_path_for_user(user, path)
        if not resolved.exists() or not resolved.is_file():
            return JSONResponse({'ok': False, 'message': 'El archivo no existe.'}, status_code=404)
        previewable, preview_mode, language = guess_text_mode(resolved)
        if not previewable:
            return JSONResponse({'ok': False, 'message': 'El archivo no es de texto o markdown.'}, status_code=400)
        content = resolved.read_text(encoding='utf-8')
        return JSONResponse({'ok': True, 'path': str(resolved), 'name': resolved.name, 'content': content, 'preview_mode': preview_mode, 'language': language, 'permission': {'access': str(permission.get('access') or 'read_only'), 'can_write': bool(permission.get('can_write'))}})
    except PermissionError as exc:
        return JSONResponse({'ok': False, 'message': str(exc)}, status_code=403)
    except UnicodeDecodeError:
        return JSONResponse({'ok': False, 'message': 'El archivo no parece UTF-8.'}, status_code=400)
    except Exception as exc:
        return JSONResponse({'ok': False, 'message': f'{type(exc).__name__}: {exc}'}, status_code=400)


@APP.post('/api/explorer/save-text')
async def api_explorer_save_text(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({'ok': False, 'message': 'No autenticado.'}, status_code=401)
    data = await request.json()
    try:
        resolved, _ = resolve_explorer_path_for_user(user, str(data.get('path') or ''), require_write=True)
        content = str(data.get('content') or '')
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding='utf-8')
        return JSONResponse({'ok': True, 'message': f'Archivo guardado: {resolved.name}'})
    except PermissionError as exc:
        return JSONResponse({'ok': False, 'message': str(exc)}, status_code=403)
    except Exception as exc:
        return JSONResponse({'ok': False, 'message': f'{type(exc).__name__}: {exc}'}, status_code=400)


@APP.post('/api/explorer/mkdir')
async def api_explorer_mkdir(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({'ok': False, 'message': 'No autenticado.'}, status_code=401)
    data = await request.json()
    try:
        base_dir, _ = resolve_explorer_path_for_user(user, str(data.get('path') or ''), require_write=True)
        name = str(data.get('name') or '').strip().strip('/\\')
        if not name:
            return JSONResponse({'ok': False, 'message': 'Falta el nombre de carpeta.'}, status_code=400)
        target = (base_dir / name).resolve()
        resolve_explorer_path_for_user(user, str(target), require_write=True)
        target.mkdir(parents=False, exist_ok=False)
        return JSONResponse({'ok': True, 'message': f'Carpeta creada: {target.name}', 'path': str(target)})
    except PermissionError as exc:
        return JSONResponse({'ok': False, 'message': str(exc)}, status_code=403)
    except Exception as exc:
        return JSONResponse({'ok': False, 'message': f'{type(exc).__name__}: {exc}'}, status_code=400)


@APP.post('/api/explorer/rename')
async def api_explorer_rename(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({'ok': False, 'message': 'No autenticado.'}, status_code=401)
    data = await request.json()
    try:
        source, _ = resolve_explorer_path_for_user(user, str(data.get('path') or ''), require_write=True)
        new_name = str(data.get('new_name') or '').strip().strip('/\\')
        if not source.exists():
            return JSONResponse({'ok': False, 'message': 'La ruta origen no existe.'}, status_code=404)
        if not new_name:
            return JSONResponse({'ok': False, 'message': 'Falta el nuevo nombre.'}, status_code=400)
        destination = source.with_name(new_name)
        resolve_explorer_path_for_user(user, str(destination), require_write=True)
        source.rename(destination)
        return JSONResponse({'ok': True, 'message': f'Renombrado a {destination.name}', 'path': str(destination)})
    except PermissionError as exc:
        return JSONResponse({'ok': False, 'message': str(exc)}, status_code=403)
    except Exception as exc:
        return JSONResponse({'ok': False, 'message': f'{type(exc).__name__}: {exc}'}, status_code=400)


@APP.post('/api/explorer/delete')
async def api_explorer_delete(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({'ok': False, 'message': 'No autenticado.'}, status_code=401)
    data = await request.json()
    try:
        target, _ = resolve_explorer_path_for_user(user, str(data.get('path') or ''), require_write=True)
        if not target.exists():
            return JSONResponse({'ok': False, 'message': 'La ruta no existe.'}, status_code=404)
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
        return JSONResponse({'ok': True, 'message': f'Eliminado: {target.name}'})
    except PermissionError as exc:
        return JSONResponse({'ok': False, 'message': str(exc)}, status_code=403)
    except Exception as exc:
        return JSONResponse({'ok': False, 'message': f'{type(exc).__name__}: {exc}'}, status_code=400)


@APP.post('/api/explorer/copy')
async def api_explorer_copy(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({'ok': False, 'message': 'No autenticado.'}, status_code=401)
    data = await request.json()
    try:
        source, _ = resolve_explorer_path_for_user(user, str(data.get('source_path') or ''))
        destination_dir, _ = resolve_explorer_path_for_user(user, str(data.get('destination_dir') or ''), require_write=True)
        overwrite = bool(data.get('overwrite', False))
        result = copy_path_item(source, destination_dir, overwrite=overwrite)
        return JSONResponse({'ok': True, 'message': f'Copiado: {result["name"]}', 'result': result})
    except PermissionError as exc:
        return JSONResponse({'ok': False, 'message': str(exc)}, status_code=403)
    except Exception as exc:
        return JSONResponse({'ok': False, 'message': f'{type(exc).__name__}: {exc}'}, status_code=400)


@APP.post('/api/explorer/move')
async def api_explorer_move(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({'ok': False, 'message': 'No autenticado.'}, status_code=401)
    data = await request.json()
    try:
        source, _ = resolve_explorer_path_for_user(user, str(data.get('source_path') or ''), require_write=True)
        destination_dir, _ = resolve_explorer_path_for_user(user, str(data.get('destination_dir') or ''), require_write=True)
        overwrite = bool(data.get('overwrite', False))
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination = destination_dir / source.name
        resolve_explorer_path_for_user(user, str(destination), require_write=True)
        if destination.exists():
            if not overwrite:
                raise FileExistsError(f'Ya existe: {destination}')
            if destination.is_dir():
                shutil.rmtree(destination)
            else:
                destination.unlink()
        shutil.move(str(source), str(destination))
        return JSONResponse({'ok': True, 'message': f'Movido: {destination.name}', 'path': str(destination)})
    except PermissionError as exc:
        return JSONResponse({'ok': False, 'message': str(exc)}, status_code=403)
    except Exception as exc:
        return JSONResponse({'ok': False, 'message': f'{type(exc).__name__}: {exc}'}, status_code=400)


@APP.get('/api/explorer/download')
async def api_explorer_download(path: str, request: Request) -> Response:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({'ok': False, 'message': 'No autenticado.'}, status_code=401)
    try:
        resolved, _ = resolve_explorer_path_for_user(user, path)
    except PermissionError as exc:
        return JSONResponse({'ok': False, 'message': str(exc)}, status_code=403)
    if not resolved.exists():
        return JSONResponse({'ok': False, 'message': 'La ruta no existe.'}, status_code=404)
    if resolved.is_file():
        return FileResponse(path=resolved, filename=resolved.name)
    temp_file = tempfile.NamedTemporaryFile(prefix='zenoterm-explorer-', suffix='.zip', delete=False)
    temp_file_path = Path(temp_file.name)
    temp_file.close()
    try:
        zip_single_path_to_file(resolved, temp_file_path)
        return FileResponse(path=temp_file_path, media_type='application/zip', filename=build_download_zip_filename(resolved), background=BackgroundTask(lambda p=str(temp_file_path): os.path.exists(p) and os.unlink(p)))
    except Exception as exc:
        try:
            temp_file_path.unlink(missing_ok=True)
        except Exception:
            pass
        return JSONResponse({'ok': False, 'message': f'No se pudo descargar: {type(exc).__name__}: {exc}'}, status_code=500)


@APP.post('/api/explorer/upload')
async def api_explorer_upload(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({'ok': False, 'message': 'No autenticado.'}, status_code=401)
    form = await request.form()
    destination_path = str(form.get('path') or '').strip()
    overwrite = str(form.get('overwrite') or 'false').strip().lower() in {'1', 'true', 'yes', 'on'}
    files = list(form.getlist('files'))
    if not destination_path:
        return JSONResponse({'ok': False, 'message': 'Falta la ruta destino.'}, status_code=400)
    if not files:
        return JSONResponse({'ok': False, 'message': 'No se recibió ningún archivo.'}, status_code=400)
    try:
        destination_dir, _ = resolve_explorer_path_for_user(user, destination_path, require_write=True)
    except PermissionError as exc:
        return JSONResponse({'ok': False, 'message': str(exc)}, status_code=403)
    if not destination_dir.exists() or not destination_dir.is_dir():
        return JSONResponse({'ok': False, 'message': 'La carpeta destino no existe.'}, status_code=400)
    temp_root: Path | None = None
    try:
        temp_root = store_uploaded_files_in_temp(files)
        result = copy_directory_contents(temp_root, destination_dir, overwrite=overwrite)
        return JSONResponse({'ok': True, 'message': f'Subida completada. Copiados: {result["copied"]}, sobrescritos: {result["overwritten"]}, omitidos: {result["skipped"]}.', 'result': result})
    except Exception as exc:
        return JSONResponse({'ok': False, 'message': f'No se pudo subir: {type(exc).__name__}: {exc}'}, status_code=500)
    finally:
        if temp_root is not None:
            shutil.rmtree(temp_root, ignore_errors=True)


@APP.get("/api/docker/overview")
async def api_docker_overview(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    if not user_has_permission(user, "use_docker"):
        return JSONResponse({"ok": False, "message": "El perfil actual no tiene acceso a Docker."}, status_code=403)
    effective_active_session = get_active_session_id_from_signed_cookie(request.cookies.get(COOKIE_NAME), user)
    refresh_target_cache(effective_active_session)
    return JSONResponse({"ok": True, "docker_management": build_docker_overview_for_user(user, effective_active_session), "config": runtime_config_for_request(request, user)})


@APP.post("/api/docker/groups/save")
async def api_docker_groups_save(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    if not user_has_permission(user, "use_docker"):
        return JSONResponse({"ok": False, "message": "El perfil actual no tiene acceso a Docker."}, status_code=403)
    data = await request.json()
    incoming = data.get("groups") or []
    groups = []
    for index, item in enumerate(incoming):
        normalized = normalize_docker_group(item, index)
        if normalized:
            groups.append(normalized)
    save_docker_groups(groups)
    effective_active_session = get_active_session_id_from_signed_cookie(request.cookies.get(COOKIE_NAME), user)
    refresh_target_cache(effective_active_session)
    return JSONResponse({"ok": True, "docker_management": build_docker_overview_for_user(user, effective_active_session), "config": runtime_config_for_request(request, user)})


@APP.post("/api/docker/groups/run")
async def api_docker_groups_run(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    if not user_has_permission(user, "use_docker"):
        return JSONResponse({"ok": False, "message": "El perfil actual no tiene acceso a Docker."}, status_code=403)
    data = await request.json()
    group_id = str(data.get("group_id") or "").strip()
    if not group_id:
        return JSONResponse({"ok": False, "message": "Falta group_id."}, status_code=400)
    try:
        result = run_docker_group(group_id, str(data.get("run_mode") or ""))
    except Exception as exc:
        return JSONResponse({"ok": False, "message": str(exc)}, status_code=400)
    effective_active_session = get_active_session_id_from_signed_cookie(request.cookies.get(COOKIE_NAME), user)
    refresh_target_cache(effective_active_session)
    return JSONResponse({**result, "docker_management": build_docker_overview_for_user(user, effective_active_session), "config": runtime_config_for_request(request, user)})


@APP.post("/api/docker/groups/generate-script")
async def api_docker_groups_generate_script(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    if not user_has_permission(user, "use_docker"):
        return JSONResponse({"ok": False, "message": "El perfil actual no tiene acceso a Docker."}, status_code=403)
    data = await request.json()
    group_id = str(data.get("group_id") or "").strip()
    if not group_id:
        return JSONResponse({"ok": False, "message": "Falta group_id."}, status_code=400)
    try:
        result = create_group_script_file(group_id, import_to_app=bool(data.get("import_to_app", True)))
    except Exception as exc:
        return JSONResponse({"ok": False, "message": str(exc)}, status_code=400)
    effective_active_session = get_active_session_id_from_signed_cookie(request.cookies.get(COOKIE_NAME), user)
    refresh_target_cache(effective_active_session)
    return JSONResponse({**result, "docker_management": build_docker_overview_for_user(user, effective_active_session), "config": runtime_config_for_request(request, user)})


@APP.post("/api/docker/container/action")
async def api_docker_container_action(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    if not user_has_permission(user, "use_docker"):
        return JSONResponse({"ok": False, "message": "El perfil actual no tiene acceso a Docker."}, status_code=403)
    data = await request.json()
    container_name = str(data.get("container_name") or data.get("container_id") or "").strip()
    action = str(data.get("action") or "").strip().lower()
    if not container_name or action not in {"start", "stop", "restart", "pull"}:
        return JSONResponse({"ok": False, "message": "Acción Docker no válida."}, status_code=400)
    containers = {item.get("id"): item for item in list_docker_containers(include_stopped=True)}
    by_name = {item.get("name"): item for item in containers.values()}
    container = containers.get(container_name) or by_name.get(container_name)
    if action == "pull" and container:
        compose_prefix = docker_compose_command_prefix(container)
        if compose_prefix and container.get("compose_service"):
            cmd = [*compose_prefix, "pull", str(container.get("compose_service") or "")]
            cwd = str(container.get("compose_working_dir") or "") or None
        else:
            image_name = str(container.get("image") or "")
            if not image_name:
                return JSONResponse({"ok": False, "message": "No se pudo resolver la imagen del contenedor."}, status_code=400)
            cmd = ["pull", image_name]
            cwd = None
    else:
        cmd = [action, container_name]
        cwd = None
    result = run_docker_cli(cmd, timeout=180, cwd=cwd, **docker_cli_connection_kwargs())
    effective_active_session = get_active_session_id_from_signed_cookie(request.cookies.get(COOKIE_NAME), user)
    refresh_target_cache(effective_active_session)
    return JSONResponse({
        "ok": result.returncode == 0,
        "action": action,
        "container": container_name,
        "stdout": str(result.stdout or "").strip(),
        "stderr": str(result.stderr or "").strip(),
        "docker_management": build_docker_overview_for_user(user, effective_active_session),
        "config": runtime_config_for_request(request, user),
    })


@APP.get("/api/docker/container/logs")
async def api_docker_container_logs(container_id: str, request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    if not user_has_permission(user, "use_docker"):
        return JSONResponse({"ok": False, "message": "El perfil actual no tiene acceso a Docker."}, status_code=403)
    if not container_id:
        return JSONResponse({"ok": False, "message": "Falta container_id."}, status_code=400)
    result = run_docker_cli(["logs", "--tail", "200", container_id], timeout=30, **docker_cli_connection_kwargs())
    combined = str(result.stdout or "")
    if result.stderr:
        combined = (combined + "\n" + str(result.stderr)).strip()
    return JSONResponse({
        "ok": result.returncode == 0,
        "container_id": container_id,
        "logs": combined.strip(),
    })


@APP.get("/api/scheduler/state")
async def api_scheduler_state(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    if not user_has_permission(user, "manage_scheduler"):
        return JSONResponse({"ok": False, "message": "Solo el administrador puede gestionar Scheduler."}, status_code=403)
    return JSONResponse({"ok": True, "scheduler_management": SCHEDULER_RUNTIME.public_state(), "config": runtime_config_for_request(request, user)})


@APP.get("/api/scheduler/logs")
async def api_scheduler_logs(request: Request, tab_id: str, after_seq: int = 0) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    if not user_has_permission(user, "manage_scheduler"):
        return JSONResponse({"ok": False, "message": "Solo el administrador puede gestionar Scheduler."}, status_code=403)
    return JSONResponse({"ok": True, **SCHEDULER_RUNTIME.get_log_lines(tab_id, after_seq)})


@APP.post("/api/scheduler/save")
async def api_scheduler_save(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    if not user_has_permission(user, "manage_scheduler"):
        return JSONResponse({"ok": False, "message": "Solo el administrador puede gestionar Scheduler."}, status_code=403)
    data = await request.json()
    incoming = data.get('tasks') or []
    normalized = [normalize_scheduler_task(item, index) for index, item in enumerate(incoming)]
    tasks = [item for item in normalized if item]
    save_scheduler_store(tasks)
    SCHEDULER_RUNTIME.reload_from_config(CONFIG)
    return JSONResponse({"ok": True, "scheduler_management": SCHEDULER_RUNTIME.public_state(), "config": runtime_config_for_request(request, user)})


@APP.post("/api/scheduler/run-now")
async def api_scheduler_run_now(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    if not user_has_permission(user, "manage_scheduler"):
        return JSONResponse({"ok": False, "message": "Solo el administrador puede gestionar Scheduler."}, status_code=403)
    data = await request.json()
    task_id = str(data.get('task_id') or '').strip()
    if not task_id:
        return JSONResponse({"ok": False, "message": "Falta task_id."}, status_code=400)
    try:
        SCHEDULER_RUNTIME.run_now(task_id, reason='manual')
    except Exception as exc:
        return JSONResponse({"ok": False, "message": str(exc)}, status_code=400)
    return JSONResponse({"ok": True, "message": "Tarea lanzada manualmente.", "scheduler_management": SCHEDULER_RUNTIME.public_state(), "config": runtime_config_for_request(request, user)})


@APP.post("/api/scheduler/event/fire")
async def api_scheduler_fire_event(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    if not user:
        return JSONResponse({"ok": False, "message": "No autenticado."}, status_code=401)
    if not user_has_permission(user, "manage_scheduler"):
        return JSONResponse({"ok": False, "message": "Solo el administrador puede gestionar Scheduler."}, status_code=403)
    data = await request.json()
    event_key = str(data.get('event_key') or '').strip()
    try:
        count = SCHEDULER_RUNTIME.fire_event(event_key)
    except Exception as exc:
        return JSONResponse({"ok": False, "message": str(exc)}, status_code=400)
    return JSONResponse({"ok": True, "message": f"Evento disparado. Tareas lanzadas: {count}.", "scheduler_management": SCHEDULER_RUNTIME.public_state(), "config": runtime_config_for_request(request, user)})



@APP.get("/api/auth/status")
async def auth_status(request: Request) -> JSONResponse:
    user = get_authenticated_user_from_request(request)
    return JSONResponse({"authenticated": bool(user), "current_user": serialize_current_user(user)})


@APP.post("/api/auth/login")
async def auth_login(request: Request) -> JSONResponse:
    data = await request.json()
    if AUTH_MODE == "none":
        default_user = find_user_by_username("admin") or {"id": "anonymous", "username": "anonymous", "display_name": "Anonymous", "role": "administrator", "enabled": True, "explorer_entries": []}
        response = JSONResponse({"ok": True, "authenticated": True, "current_user": serialize_current_user(default_user)})
        set_auth_cookie(response, create_session(default_user))
        return response
    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    user = verify_login_credentials(username, password)
    if not user:
        return JSONResponse({"ok": False, "message": "Usuario o contraseña incorrectos."}, status_code=401)
    response = JSONResponse({"ok": True, "authenticated": True, "current_user": serialize_current_user(user)})
    set_auth_cookie(response, create_session(user))
    return response


@APP.post("/api/auth/logout")
async def auth_logout(request: Request) -> JSONResponse:
    token = request.cookies.get(COOKIE_NAME)
    if token:
        delete_session(token)
    response = JSONResponse({"ok": True, "authenticated": False})
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


@APP.get("/api/health")
async def health() -> JSONResponse:
    return JSONResponse({"ok": True, "app": APP_TITLE})


def create_signature(token: str) -> str:
    return hmac.new(SESSION_SECRET.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()



def create_session(user: dict[str, Any] | str) -> str:
    if isinstance(user, str):
        record = {"user_id": "", "username": user, "role": "", "active_session_id": "", "expires_at": time.time() + SESSION_TTL_SECONDS}
    else:
        record = {
            "user_id": str(user.get("id") or ""),
            "username": str(user.get("username") or ""),
            "role": str(user.get("role") or ""),
            "active_session_id": get_user_default_session_id(user),
            "expires_at": time.time() + SESSION_TTL_SECONDS,
        }
    token = secrets.token_urlsafe(32)
    with SESSION_LOCK:
        SESSION_STORE[token] = record
    return f"{token}.{create_signature(token)}"

def get_session_record_from_signed_cookie(signed_cookie: str | None) -> dict[str, Any] | None:
    if not signed_cookie or "." not in signed_cookie:
        return None
    token, signature = signed_cookie.rsplit(".", 1)
    if not hmac.compare_digest(signature, create_signature(token)):
        return None
    with SESSION_LOCK:
        record = SESSION_STORE.get(token)
        if not record:
            return None
        if record.get("expires_at", 0) < time.time():
            SESSION_STORE.pop(token, None)
            return None
        return dict(record)


def validate_signed_cookie(signed_cookie: str | None) -> bool:
    return get_session_record_from_signed_cookie(signed_cookie) is not None


def get_authenticated_user_from_signed_cookie(signed_cookie: str | None) -> dict[str, Any] | None:
    if AUTH_MODE == "none":
        return find_user_by_username("admin")
    record = get_session_record_from_signed_cookie(signed_cookie)
    if not record:
        return None
    user = find_user_by_id(str(record.get("user_id") or "")) if record.get("user_id") else None
    if not user and record.get("username"):
        user = find_user_by_username(str(record.get("username") or ""))
    if not user or not user.get("enabled", True):
        return None
    return user


def delete_session(signed_cookie: str) -> None:
    if "." in signed_cookie:
        token = signed_cookie.rsplit(".", 1)[0]
        with SESSION_LOCK:
            SESSION_STORE.pop(token, None)


def set_auth_cookie(response: Response, signed_cookie: str) -> None:
    response.set_cookie(COOKIE_NAME, signed_cookie, httponly=True, samesite="lax", secure=False, path="/", max_age=SESSION_TTL_SECONDS)


def get_authenticated_user_from_request(request: Request) -> dict[str, Any] | None:
    return get_authenticated_user_from_signed_cookie(request.cookies.get(COOKIE_NAME))


def get_authenticated_user_from_websocket(websocket: WebSocket) -> dict[str, Any] | None:
    return get_authenticated_user_from_signed_cookie(websocket.cookies.get(COOKIE_NAME))


def is_request_authenticated(request: Request) -> bool:
    return True if AUTH_MODE == "none" else get_authenticated_user_from_request(request) is not None


def is_websocket_authenticated(websocket: WebSocket) -> bool:
    return True if AUTH_MODE == "none" else get_authenticated_user_from_websocket(websocket) is not None



class SessionFactory:
    @staticmethod
    def create_from_target(target: dict[str, Any], creds: dict[str, Any], cols: int, rows: int) -> SessionBase:
        if not target:
            raise RuntimeError("Target no encontrado.")
        mode = str(target.get("mode") or "direct")
        if mode == "direct":
            shell_id = str(target.get("shell_id") or DEFAULT_LOCAL_SHELL or "")
            if not shell_id:
                raise RuntimeError("No hay shell local disponible configurada para este target en el host actual.")
            return LocalPtySession(shell_id=shell_id, cols=cols, rows=rows, launch_command=str(target.get("launch_command") or ""))
        if mode == "ssh_password":
            host = str(creds.get("host") or target.get("host") or "")
            username = str(creds.get("username") or target.get("username") or "")
            password = str(creds.get("password") or "")
            port = int(creds.get("port") or target.get("port") or 22)
            if not password:
                raise RuntimeError("Este target requiere contraseña SSH efímera.")
            return ParamikoShellSession(host, port, username, password, None, None, None, bool(target.get("strict_host_key", True)), cols, rows)
        if mode == "ssh_key":
            host = str(creds.get("host") or target.get("host") or "")
            username = str(creds.get("username") or target.get("username") or "")
            port = int(creds.get("port") or target.get("port") or 22)
            key_path = str(creds.get("private_key_path") or target.get("private_key_path") or "")
            key_content = str(creds.get("private_key_content") or "")
            if not key_path and not key_content:
                raise RuntimeError("Este target requiere private_key_path o un fichero de clave privada cargado.")
            return ParamikoShellSession(host, port, username, None, key_path or None, key_content or None, (str(creds.get("passphrase") or "") or None), bool(target.get("strict_host_key", True)), cols, rows)
        raise RuntimeError(f"Modo no soportado: {mode}")

    @staticmethod
    def create(target_id: str, creds: dict[str, Any], cols: int, rows: int, user: dict[str, Any] | None = None, active_session_id: str | None = None) -> SessionBase:
        target = resolve_target_for_user(user, target_id, active_session_id)
        if not target and str(target_id).startswith("docker::"):
            refresh_target_cache(get_active_session_id())
            target = resolve_target_for_user(user, target_id, active_session_id)
        return SessionFactory.create_from_target(target or {}, creds, cols, rows)

@APP.websocket("/ws")
async def websocket_terminal(websocket: WebSocket) -> None:
    if not is_websocket_authenticated(websocket):
        await websocket.close(code=4401)
        return
    user = get_authenticated_user_from_websocket(websocket)
    await websocket.accept()
    loop = asyncio.get_running_loop()
    stop_event = threading.Event()
    session: Optional[SessionBase] = None

    async def send_json(payload: dict[str, Any]) -> None:
        if stop_event.is_set():
            return
        try:
            await websocket.send_text(json.dumps(payload))
        except Exception:
            stop_event.set()

    def schedule_send(payload: dict[str, Any]) -> None:
        if stop_event.is_set():
            return
        def _schedule() -> None:
            if stop_event.is_set():
                return
            task = asyncio.create_task(send_json(payload))
            def _consume_result(done_task: asyncio.Task) -> None:
                try:
                    done_task.result()
                except Exception:
                    stop_event.set()
            task.add_done_callback(_consume_result)
        try:
            loop.call_soon_threadsafe(_schedule)
        except RuntimeError:
            stop_event.set()

    def reader_worker() -> None:
        nonlocal session
        try:
            while not stop_event.is_set() and session is not None and session.is_alive():
                chunk = session.read()
                if chunk:
                    schedule_send({"type": "output", "data": chunk})
                else:
                    time.sleep(0.02)
        except Exception as exc:
            schedule_send({"type": "status", "status": "error", "message": f"{type(exc).__name__}: {exc}"})
        finally:
            if not stop_event.is_set():
                schedule_send({"type": "status", "status": "closed", "message": "La sesión ha terminado."})

    try:
        await send_json({"type": "status", "status": "ready", "message": "WebSocket conectada."})
        while True:
            payload = json.loads(await websocket.receive_text())
            msg_type = str(payload.get("type") or "")
            if msg_type == "ping":
                await send_json({"type": "pong"})
                continue
            if msg_type in {"start", "restart"}:
                if session is not None:
                    try:
                        session.close()
                    except Exception:
                        pass
                    session = None
                stop_event.clear()
                try:
                    target_id = str(payload.get("target_id") or "")
                    creds = payload.get("credentials") or {}
                    active_session_id = get_active_session_id_from_signed_cookie(websocket.cookies.get(COOKIE_NAME), user)
                    target = resolve_target_for_user(user, target_id, active_session_id)
                    if not target or not target_allowed_for_user(user, target):
                        raise PermissionError("El perfil actual no puede abrir esta terminal.")
                    session = SessionFactory.create(target_id, creds, int(payload.get("cols") or 120), int(payload.get("rows") or 30), user=user, active_session_id=active_session_id)
                    start_commands = combine_start_commands(
                        str((target or {}).get("startup_command") or ""),
                        str((target or {}).get("command_file_content") or ""),
                        str(creds.get("connect_command") or ""),
                        str(creds.get("command_file_content") or ""),
                    )
                    defer_startup_commands = bool(payload.get("defer_startup_commands") or False)
                    if start_commands and not defer_startup_commands:
                        threading.Thread(target=execute_session_start_commands, args=(session, start_commands, target or {}), daemon=True).start()
                    threading.Thread(target=reader_worker, daemon=True).start()
                    await send_json({"type": "status", "status": "connected", "message": f"Sesión activa en {target_id}.", "target_id": target_id})
                except Exception as exc:
                    traceback.print_exc()
                    await send_json({"type": "status", "status": "error", "message": f"{type(exc).__name__}: {exc}"})
                continue
            if msg_type == "run_startup":
                if session is None:
                    await send_json({"type": "status", "status": "error", "message": "No hay sesión activa para ejecutar el arranque."})
                    continue
                try:
                    target_id = str(payload.get("target_id") or "")
                    creds = payload.get("credentials") or {}
                    active_session_id = get_active_session_id_from_signed_cookie(websocket.cookies.get(COOKIE_NAME), user)
                    target = resolve_target_for_user(user, target_id, active_session_id)
                    if not target or not target_allowed_for_user(user, target):
                        raise PermissionError("El perfil actual no puede ejecutar el arranque de esta terminal.")
                    start_commands = combine_start_commands(
                        str((target or {}).get("startup_command") or ""),
                        str((target or {}).get("command_file_content") or ""),
                        str(creds.get("connect_command") or ""),
                        str(creds.get("command_file_content") or ""),
                    )
                    if start_commands:
                        threading.Thread(target=execute_session_start_commands, args=(session, start_commands, target or {}), daemon=True).start()
                    else:
                        await send_json({"type": "status", "status": "ready", "message": "La terminal no tiene comando de arranque pendiente."})
                except Exception as exc:
                    traceback.print_exc()
                    await send_json({"type": "status", "status": "error", "message": f"{type(exc).__name__}: {exc}"})
                continue
            if msg_type == "input":
                if session is None:
                    await send_json({"type": "status", "status": "error", "message": "No hay sesión activa."})
                else:
                    session.write(str(payload.get("data") or ""))
                continue
            if msg_type == "resize":
                if session is not None:
                    session.resize(int(payload.get("cols") or 120), int(payload.get("rows") or 30))
                continue
            if msg_type == "close":
                break
            await send_json({"type": "status", "status": "error", "message": f"Mensaje no soportado: {msg_type}"})
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        traceback.print_exc()
        try:
            await send_json({"type": "status", "status": "error", "message": f"{type(exc).__name__}: {exc}"})
        except Exception:
            pass
    finally:
        stop_event.set()
        if session is not None:
            try:
                session.close()
            except Exception:
                pass
        try:
            await websocket.close()
        except Exception:
            pass


def open_browser(url: str) -> None:
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main() -> None:
    if not WEB_DIR.exists():
        print("ERROR: no existe la carpeta 'web' junto a app.py", file=sys.stderr)
        sys.exit(1)
    server = CONFIG.get("server") or {}
    host = str(server.get("host") or "127.0.0.1")
    preferred_port = int(server.get("port") or 8765)
    auto_port = bool(server.get("auto_port_if_busy", True))
    port = find_free_port(host, preferred_port) if auto_port else preferred_port
    url = f"http://{host}:{port}"
    print(f"{APP_TITLE} disponible en {url}")
    if bool(server.get("open_browser", True)):
        timer = threading.Timer(0.75, open_browser, args=(url,))
        timer.daemon = True
        timer.start()
    uvicorn.run(APP, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
