from __future__ import annotations

import argparse
import time
from datetime import datetime


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Script simple con salida progresiva para ver ejecuciones largas y repetidas.")
    parser.add_argument("--seconds", type=int, default=3, help="Segundos de cuenta atrás")
    parser.add_argument("--label", default="contador", help="Etiqueta visible")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    total = max(0, args.seconds)
    print(f"[{datetime.now().isoformat(timespec='seconds')}] Inicio {args.label}", flush=True)
    for remaining in range(total, -1, -1):
        print(f"{args.label}: {remaining}", flush=True)
        if remaining > 0:
            time.sleep(1)
    print(f"[{datetime.now().isoformat(timespec='seconds')}] Fin {args.label}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
