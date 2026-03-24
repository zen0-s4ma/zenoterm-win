from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Script de prueba para validar flags, parámetros, repeticiones y escritura opcional a fichero."
    )
    parser.add_argument("--name", default="demo", help="Nombre lógico de la ejecución")
    parser.add_argument("--mode", choices=["quick", "full", "audit"], default="quick", help="Modo de ejecución")
    parser.add_argument("--repeat", type=int, default=1, help="Número de iteraciones de salida")
    parser.add_argument("--tag", action="append", default=[], help="Tag repetible. Se puede usar varias veces")
    parser.add_argument("--sleep", type=float, default=0.0, help="Espera en segundos entre iteraciones")
    parser.add_argument("--out", default="", help="Ruta de salida opcional para guardar un resumen JSON")
    parser.add_argument("--cwd", action="store_true", help="Muestra el directorio actual")
    parser.add_argument("--upper", action="store_true", help="Muestra el nombre en mayúsculas")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    current_name = args.name.upper() if args.upper else args.name
    payload = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "python": sys.executable,
        "script": Path(__file__).name,
        "name": current_name,
        "mode": args.mode,
        "repeat": args.repeat,
        "tags": args.tag,
        "cwd": str(Path.cwd()),
    }

    print("=== DEMO CLI FLAGS ===", flush=True)
    for index in range(1, max(1, args.repeat) + 1):
        print(f"Iteración {index}/{max(1, args.repeat)}", flush=True)
        print(f"Alias lógico: {current_name}", flush=True)
        print(f"Modo: {args.mode}", flush=True)
        print(f"Tags: {', '.join(args.tag) if args.tag else '(sin tags)'}", flush=True)
        if args.cwd:
            print(f"CWD: {Path.cwd()}", flush=True)
        if args.sleep > 0 and index < max(1, args.repeat):
            time.sleep(args.sleep)

    if args.out:
        output_path = Path(args.out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Resumen guardado en: {output_path}", flush=True)

    print("=== FIN DEMO CLI FLAGS ===", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
