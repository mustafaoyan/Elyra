"""Local, safe Elyra AI assistant entry point.

The first installable assistant release is deliberately evidence-bound: it
can explain a scanner evidence JSON document, but it cannot execute files,
change policy, quarantine data, or contact a cloud service.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .analyst import EvidenceAnalyst
from .updater import check_for_update, download_and_launch

CURRENT_VERSION = "1.1.0"


def _load_evidence(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("evidence JSON must contain an object")
    return value


def _print_analysis(result: dict[str, Any]) -> None:
    print(json.dumps(result, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="elyra-ai",
        description="Elyra local evidence assistant (no cloud, no file execution).",
    )
    parser.add_argument("--evidence", type=Path, help="an existing scanner evidence JSON file")
    parser.add_argument("--version", action="version", version=f"elyra-ai {CURRENT_VERSION}")
    parser.add_argument("--no-update-check", action="store_true", help="skip the startup update check")
    args = parser.parse_args(argv)
    analyst = EvidenceAnalyst()

    if not args.no_update_check:
        try:
            update = check_for_update(CURRENT_VERSION)
            if update:
                print(f"Yeni Elyra AI güncellemesi var: {update.current_version} -> {update.latest_version}.")
                if input("Güncellemeyi indirip kurulum başlatılsın mı? [y/N] ").strip().lower() in {"y", "yes", "e", "evet"}:
                    installer = download_and_launch(update)
                    print(f"Kurulum başlatıldı: {installer}")
                    return 0
        except Exception as exc:  # Update failure must never block local analysis.
            print(f"Güncelleme kontrolü yapılamadı; mevcut sürümle devam ediliyor: {exc}")

    if args.evidence:
        try:
            _print_analysis(analyst.analyze(_load_evidence(args.evidence)))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            parser.error(str(exc))
        return 0

    print("Elyra AI hazır. Kanıt JSON dosyasını analiz etmek için --evidence <dosya> kullanın.")
    print("Çıkmak için Ctrl+C veya 'quit' yazın.")
    try:
        while True:
            command = input("elyra-ai> ").strip()
            if command.lower() in {"quit", "exit", "çıkış"}:
                return 0
            if not command:
                continue
            if command.startswith("analyze "):
                try:
                    _print_analysis(analyst.analyze(_load_evidence(Path(command[8:].strip()))))
                except (OSError, ValueError, json.JSONDecodeError) as exc:
                    print(f"Analiz yapılamadı: {exc}")
            else:
                print("Şu an yalnızca yerel kanıt JSON analizi destekleniyor: analyze <dosya>")
    except (EOFError, KeyboardInterrupt):
        print()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
