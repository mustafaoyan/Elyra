#!/usr/bin/env python3
"""Measure Stage 3 analysis time using harmless deterministic synthetic files."""

from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from elliot.analyzer.static_analyzer import StaticFileScanner


def create_pattern_file(path: Path, size: int) -> None:
    pattern = bytes(range(256))
    full, remainder = divmod(size, len(pattern))
    with path.open("wb") as stream:
        for _ in range(full):
            stream.write(pattern)
        stream.write(pattern[:remainder])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    scanner = StaticFileScanner()
    sizes = [1024, 1024 * 1024, 8 * 1024 * 1024]
    records: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="elliot-stage3-") as directory:
        root = Path(directory)
        for size in sizes:
            target = root / f"synthetic-{size}.bin"
            create_pattern_file(target, size)
            started = time.perf_counter()
            result = scanner.scan(target)
            elapsed_ms = (time.perf_counter() - started) * 1000
            records.append(
                {
                    "size_bytes": size,
                    "status": result.status,
                    "elapsed_ms": round(elapsed_ms, 3),
                    "whole_file_entropy": result.entropy_summary.get(
                        "whole_file_entropy"
                    ),
                    "block_count": result.entropy_summary.get("block_count"),
                }
            )

    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "method": "deterministic bytes 0..255 repeated; harmless synthetic data",
        "results": records,
    }
    output = json.dumps(payload, indent=2, ensure_ascii=False)
    print(output)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
    return 0 if all(record["status"] == "OK" for record in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
