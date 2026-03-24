from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Genera un pequeño informe JSON o texto para probar parámetros variados.")
    parser.add_argument("--title", default="Informe demo", help="Título del informe")
    parser.add_argument("--item", action="append", default=[], help="Elemento repetible del informe")
    parser.add_argument("--format", choices=["json", "text"], default="json", help="Formato de salida por consola")
    parser.add_argument("--save", default="", help="Ruta opcional para guardar el informe")
    parser.add_argument("--owner", default="zenoterm", help="Nombre del propietario del informe")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    payload = {
        "title": args.title,
        "owner": args.owner,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "items": args.item,
        "item_count": len(args.item),
        "cwd": str(Path.cwd()),
    }

    if args.format == "json":
        rendered = json.dumps(payload, indent=2, ensure_ascii=False)
    else:
        rendered = "\n".join([
            f"Título: {payload['title']}",
            f"Propietario: {payload['owner']}",
            f"Creado: {payload['created_at']}",
            f"Items: {', '.join(args.item) if args.item else '(ninguno)'}",
            f"Cantidad: {payload['item_count']}",
            f"CWD: {payload['cwd']}",
        ])

    print(rendered, flush=True)
    if args.save:
        out_path = Path(args.save)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
        print(f"Guardado en: {out_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
