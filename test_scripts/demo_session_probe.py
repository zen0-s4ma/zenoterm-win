from __future__ import annotations

import argparse
import platform
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Imprime datos útiles para comprobar sesiones y terminales activas.")
    parser.add_argument("--session", default="sin-sesion", help="Nombre lógico de la sesión")
    parser.add_argument("--terminal", default="sin-terminal", help="Nombre lógico de la terminal")
    parser.add_argument("--profile", default="general", help="Perfil lógico de prueba")
    parser.add_argument("--marker", default="OK", help="Marcador visible en la salida")
    parser.add_argument("--repeat", type=int, default=1, help="Número de bloques a imprimir")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    for index in range(1, max(1, args.repeat) + 1):
        print(f"SESSION: {args.session}", flush=True)
        print(f"TERMINAL: {args.terminal}", flush=True)
        print(f"PROFILE: {args.profile}", flush=True)
        print(f"MARKER: {args.marker}", flush=True)
        print(f"PLATFORM: {platform.platform()}", flush=True)
        print(f"PYTHON: {sys.executable}", flush=True)
        print(f"CWD: {Path.cwd()}", flush=True)
        print(f"BLOCK: {index}/{max(1, args.repeat)}", flush=True)
        print("---", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
