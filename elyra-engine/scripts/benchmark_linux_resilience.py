#!/usr/bin/env python3
"""Run a harmless, repeatable Linux analysis resilience benchmark.

The benchmark uses synthetic bytes only. It measures scanner latency percentiles,
parser exception safety and bounded eBPF user-space queue drops; it never loads
a probe, opens fanotify, executes a file or claims malware-detection accuracy.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
import time
from pathlib import Path
from statistics import mean

from elyra.analyzer.static_analyzer import StaticFileScanner
from elyra.monitor.ebpf.collector import EBPFCollector
from elyra.monitor.ebpf.events import EbpfEvent


def percentile(values: list[float], percentile_value: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((percentile_value / 100) * (len(ordered) - 1)))))
    return round(ordered[index], 3)


def run(iterations: int) -> dict[str, object]:
    scanner = StaticFileScanner()
    latencies: list[float] = []
    statuses: list[str] = []
    parser_errors = 0
    with tempfile.TemporaryDirectory(prefix="elyra-l6-") as directory:
        root = Path(directory)
        target = root / "synthetic.bin"
        target.write_bytes(bytes(range(256)) * 128)
        malformed = root / "malformed.elf"
        malformed.write_bytes(b"\x7fELF" + b"\xff" * 511)
        for _ in range(iterations):
            started = time.perf_counter()
            result = scanner.scan(target)
            latencies.append((time.perf_counter() - started) * 1000)
            statuses.append(result.status)
            try:
                malformed_result = scanner.scan(malformed)
                parser_errors += int(malformed_result.status in {"OK", "PARTIAL", "ERROR"})
            except Exception:
                parser_errors += 1

        collector = EBPFCollector("unused", queue_size=2)
        event = EbpfEvent("PROCESS_EXEC", 1, 1, 1, 0, 0, "synthetic")
        accepted = [collector.publish_event(event) for _ in range(4)]
        drop_count = collector.status()["dropped_events"]

    return {
        "schema_version": 1,
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "iterations": iterations,
        "method": "synthetic bytes; no probe attach, fanotify, malware or execution",
        "scanner": {
            "statuses": statuses,
            "latency_ms": {"mean": round(mean(latencies), 3), "p50": percentile(latencies, 50), "p95": percentile(latencies, 95)},
            "parser_exception_count": parser_errors,
        },
        "bounded_event_queue": {
            "accepted": sum(accepted),
            "dropped_events": drop_count,
            "queue_capacity": 2,
        },
        "overall_status": "RESILIENCE_CONTRACT_READY" if parser_errors == iterations and statuses and all(status in {"OK", "PARTIAL"} for status in statuses) and drop_count == 2 else "NOT_READY",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=8)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not 1 <= args.iterations <= 100:
        parser.error("--iterations must be from 1 to 100")
    payload = run(args.iterations)
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    print(text, end="")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    return 0 if payload["overall_status"] == "RESILIENCE_CONTRACT_READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
