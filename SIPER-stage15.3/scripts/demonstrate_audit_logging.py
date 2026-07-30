#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from elliot.audit.audit_logger import AuditLogger, verify_audit_directory


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        payload = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _tamper(log_dir: Path) -> None:
    segments = sorted(log_dir.glob("audit.jsonl.*"))
    target = segments[0] if segments else log_dir / "audit.jsonl"
    lines = target.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["payload"]["tampered_for_safe_test"] = True
    lines[0] = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe Stage 12 audit-log demonstration")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)

    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="elliot-stage12-audit-") as temp:
        root = Path(temp)
        primary_dir = root / "primary"
        logger = AuditLogger(str(primary_dir), max_bytes=900, backup_count=20)
        for index in range(10):
            logger.record(
                "safe_demo",
                "structured_event",
                {
                    "index": index,
                    "action": "ALLOW" if index % 2 == 0 else "WARN",
                    "padding": "x" * 160,
                },
            )

        records = list(logger.iter_records())
        structured_ok = all(
            {
                "schema_version",
                "record_id",
                "sequence",
                "timestamp",
                "timestamp_utc",
                "source",
                "subject",
                "payload",
                "prev_hash",
                "record_hash",
            }.issubset(record)
            for record in records
        )
        results.append(
            {"scenario": "structured_json_records", "status": "OK" if structured_ok else "FAIL"}
        )

        modes_ok = (
            stat.S_IMODE(primary_dir.stat().st_mode) == 0o750
            and stat.S_IMODE((primary_dir / "audit.jsonl").stat().st_mode) == 0o640
            and stat.S_IMODE((primary_dir / ".audit.jsonl.lock").stat().st_mode) == 0o600
        )
        results.append(
            {
                "scenario": "protected_permissions",
                "status": "OK" if modes_ok else "FAIL",
                "directory_mode": oct(stat.S_IMODE(primary_dir.stat().st_mode)),
                "file_mode": oct(stat.S_IMODE((primary_dir / "audit.jsonl").stat().st_mode)),
                "lock_mode": oct(
                    stat.S_IMODE((primary_dir / ".audit.jsonl.lock").stat().st_mode)
                ),
            }
        )

        chain = logger.verify_integrity()
        results.append(
            {
                "scenario": "hash_chain_verification",
                "status": "OK" if chain.valid and chain.record_count == 10 else "FAIL",
                "integrity": chain.to_dict(),
            }
        )
        rotated = sorted(path.name for path in primary_dir.glob("audit.jsonl.*"))
        results.append(
            {
                "scenario": "rotation_preserves_chain",
                "status": "OK" if rotated and chain.valid else "FAIL",
                "rotated_segments": rotated,
            }
        )

        reopened = AuditLogger(str(primary_dir), max_bytes=900, backup_count=20)
        startup = reopened.startup_integrity_report
        results.append(
            {
                "scenario": "startup_integrity_check",
                "status": "OK" if startup.valid and startup.record_count == 10 else "FAIL",
                "startup_integrity": startup.to_dict(),
            }
        )

        tamper_dir = root / "tamper"
        shutil.copytree(primary_dir, tamper_dir)
        _tamper(tamper_dir)
        tamper_report = verify_audit_directory(tamper_dir)
        results.append(
            {
                "scenario": "tamper_detection",
                "status": "OK" if not tamper_report.valid else "FAIL",
                "detected_error": tamper_report.error,
            }
        )

        partial_dir = root / "partial"
        partial = AuditLogger(str(partial_dir))
        partial.record("safe_demo", "complete_record", {"value": 1})
        with (partial_dir / "audit.jsonl").open("ab") as handle:
            handle.write(b'{"interrupted":')
            handle.flush()
            os.fsync(handle.fileno())
        recovered_partial = AuditLogger(str(partial_dir), repair_trailing_partial=True)
        partial_report = recovered_partial.startup_integrity_report
        results.append(
            {
                "scenario": "trailing_partial_recovery",
                "status": (
                    "OK"
                    if partial_report.valid and partial_report.repaired_trailing_partial
                    else "FAIL"
                ),
                "recovery_artifact": partial_report.recovery_artifact,
            }
        )

        quarantined_dir = root / "quarantine-corruption"
        quarantined = AuditLogger(str(quarantined_dir))
        quarantined.record("safe_demo", "before_corruption", {"value": 1})
        _tamper(quarantined_dir)
        new_chain = AuditLogger(str(quarantined_dir), corruption_policy="quarantine")
        recovery_records = list(new_chain.iter_records())
        recovery_ok = (
            not new_chain.startup_integrity_report.valid
            and new_chain.verify_integrity().valid
            and len(recovery_records) == 1
            and recovery_records[0]["subject"] == "corruption_recovery"
        )
        results.append(
            {
                "scenario": "corrupt_log_quarantine",
                "status": "OK" if recovery_ok else "FAIL",
                "new_chain_records": len(recovery_records),
                "preserved_artifact": recovery_records[0]["payload"].get("quarantined_to"),
            }
        )

        threat_model = logger.status()["threat_model"]
        limitation_ok = "privileged attacker" in threat_model and "recomputing" in threat_model
        results.append(
            {
                "scenario": "threat_model_limitation_disclosed",
                "status": "OK" if limitation_ok else "FAIL",
                "statement": threat_model,
            }
        )

    overall = "OK" if all(result["status"] == "OK" for result in results) else "FAIL"
    evidence = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "method": (
            "temporary JSONL logs only; no root, kernel hooks, network listener, malware, "
            "or persistent user files"
        ),
        "schema_version": "2.0",
        "results": results,
        "overall_status": overall,
    }
    _write_json_atomic(output, evidence)
    for result in results:
        print(f"{result['scenario']}: {result['status']}")
    print(f"overall_status: {overall}")
    print(f"Evidence written to: {output}")
    return 0 if overall == "OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
