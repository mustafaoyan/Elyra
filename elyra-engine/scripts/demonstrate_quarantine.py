#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import platform
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from elyra.response import (
    QuarantineConflictError,
    QuarantineError,
    QuarantineManager,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run safe synthetic Stage 5 quarantine and restoration checks."
    )
    parser.add_argument(
        "--output",
        required=True,
        help="JSON evidence file to create.",
    )
    return parser


def _mode(path: Path) -> str:
    return oct(stat.S_IMODE(path.stat().st_mode))


def main() -> int:
    args = _build_parser().parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    report: dict = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "method": "harmless temporary files only; no malware and no persistent user files",
        "results": [],
    }

    try:
        with tempfile.TemporaryDirectory(prefix="elyra-stage5-") as temporary_root:
            root = Path(temporary_root)
            manager = QuarantineManager(
                quarantine_dir=root / "protected" / "quarantine",
                metadata_dir=root / "protected" / "metadata",
            )

            # Scenario 1: normal quarantine and restoration.
            source = root / "work" / "safe_sample.bin"
            source.parent.mkdir(parents=True)
            content = b"ELYRA Stage 5 harmless synthetic sample\n"
            source.write_bytes(content)
            source.chmod(0o640)
            expected_hash = manager.sha256_file(source)
            record = manager.quarantine_file(
                source,
                expected_sha256=expected_hash,
                reason="Safe Stage 5 demonstration",
                related_pid=os.getpid(),
                triggered_rules=[{"rule": "SAFE_DEMO_FIXTURE", "weight": 0}],
                process_info={"synthetic": True, "command": "demonstrate_quarantine.py"},
            )
            payload = manager.quarantine_dir / record.quarantine_id
            metadata = manager.metadata_dir / f"{record.quarantine_id}.json"
            quarantined_ok = (
                not source.exists()
                and payload.exists()
                and manager.sha256_file(payload) == expected_hash
            )
            restored = manager.restore_file(record.quarantine_id)
            restored_ok = (
                source.read_bytes() == content
                and restored.restoration_status == "restored"
            )
            report["results"].append(
                {
                    "scenario": "basic_quarantine_restore",
                    "status": "OK" if quarantined_ok and restored_ok else "FAILED",
                    "quarantine_id": record.quarantine_id,
                    "sha256": record.sha256,
                    "payload_mode": _mode(payload),
                    "metadata_mode": _mode(metadata),
                    "restored_mode": _mode(source),
                    "restoration_status": restored.restoration_status,
                }
            )

            # Scenario 2: identical bytes at different paths remain distinct records.
            identical = b"same harmless content"
            first_path = root / "duplicates" / "first.bin"
            second_path = root / "duplicates" / "second.bin"
            first_path.parent.mkdir(parents=True)
            first_path.write_bytes(identical)
            second_path.write_bytes(identical)
            first = manager.quarantine_file(
                first_path,
                expected_sha256=manager.sha256_file(first_path),
                reason="Identical-content demonstration",
                related_pid=None,
                triggered_rules=[],
            )
            second = manager.quarantine_file(
                second_path,
                expected_sha256=manager.sha256_file(second_path),
                reason="Identical-content demonstration",
                related_pid=None,
                triggered_rules=[],
            )
            distinct_ok = (
                first.sha256 == second.sha256
                and first.quarantine_id != second.quarantine_id
                and first.original_path != second.original_path
            )
            report["results"].append(
                {
                    "scenario": "identical_content_distinct_paths",
                    "status": "OK" if distinct_ok else "FAILED",
                    "same_hash": first.sha256 == second.sha256,
                    "distinct_quarantine_ids": first.quarantine_id != second.quarantine_id,
                    "distinct_original_paths": first.original_path != second.original_path,
                }
            )

            # Scenario 3: restoration refuses to overwrite a replacement path.
            conflict_path = root / "work" / "conflict.bin"
            conflict_path.write_bytes(b"quarantine me")
            conflict_record = manager.quarantine_file(
                conflict_path,
                expected_sha256=manager.sha256_file(conflict_path),
                reason="Restore-conflict demonstration",
                related_pid=None,
                triggered_rules=[],
            )
            conflict_path.write_bytes(b"new legitimate replacement")
            conflict_rejected = False
            try:
                manager.restore_file(conflict_record.quarantine_id)
            except QuarantineConflictError:
                conflict_rejected = True
            report["results"].append(
                {
                    "scenario": "existing_destination_conflict",
                    "status": "OK"
                    if conflict_rejected
                    and conflict_path.read_bytes() == b"new legitimate replacement"
                    else "FAILED",
                    "overwrite_rejected": conflict_rejected,
                    "replacement_preserved": conflict_path.read_bytes()
                    == b"new legitimate replacement",
                }
            )

            # Scenario 4: symbolic-link sources are rejected.
            real_path = root / "work" / "real.bin"
            symlink_path = root / "work" / "link.bin"
            real_path.write_bytes(b"real harmless file")
            symlink_path.symlink_to(real_path)
            symlink_rejected = False
            try:
                manager.quarantine_file(
                    symlink_path,
                    expected_sha256=None,
                    reason="Symlink demonstration",
                    related_pid=None,
                    triggered_rules=[],
                )
            except QuarantineError:
                symlink_rejected = True
            report["results"].append(
                {
                    "scenario": "symlink_source_rejection",
                    "status": "OK"
                    if symlink_rejected and real_path.exists() and symlink_path.is_symlink()
                    else "FAILED",
                    "symlink_rejected": symlink_rejected,
                    "target_preserved": real_path.read_bytes() == b"real harmless file",
                }
            )

    except (OSError, QuarantineError, ValueError, TypeError) as exc:
        report["fatal_error"] = str(exc)

    statuses = [item["status"] for item in report["results"]]
    report["overall_status"] = (
        "OK" if statuses and all(status == "OK" for status in statuses) else "FAILED"
    )
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    for item in report["results"]:
        print(f"{item['scenario']}: {item['status']}")
    print(f"overall_status: {report['overall_status']}")
    print(f"Evidence written to: {output}")
    return 0 if report["overall_status"] == "OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
