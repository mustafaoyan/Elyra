from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from pathlib import Path

import pytest

from elliot.audit.audit_logger import (
    AuditIntegrityError,
    AuditLogger,
    AuditSecurityError,
    ZERO_HASH,
    verify_audit_directory,
)


def _records(log_dir: Path) -> list[dict]:
    logger = AuditLogger(str(log_dir))
    return list(logger.iter_records())


def _tamper_first_payload(log_dir: Path) -> None:
    segments = sorted(log_dir.glob("audit.jsonl.*"))
    active = log_dir / "audit.jsonl"
    target = segments[0] if segments else active
    lines = target.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["payload"]["tampered"] = True
    lines[0] = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_structured_record_and_chain(tmp_path: Path) -> None:
    logger = AuditLogger(str(tmp_path / "audit"), clock=lambda: 1_700_000_000.0)
    record_hash = logger.record("response", "allow", {"score": 0})
    report = logger.verify_integrity()
    record = list(logger.iter_records())[0]

    assert report.valid is True
    assert report.record_count == 1
    assert report.coverage == "FULL_FROM_GENESIS"
    assert record_hash == record["record_hash"]
    assert record["schema_version"] == "2.0"
    assert record["sequence"] == 1
    assert record["timestamp_utc"].endswith("+00:00")
    assert record["prev_hash"] == ZERO_HASH
    assert record["payload"] == {"score": 0}


def test_directory_file_and_lock_permissions(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    logger = AuditLogger(str(log_dir))
    logger.record("test", "permissions", {})

    assert stat.S_IMODE(log_dir.stat().st_mode) == 0o750
    assert stat.S_IMODE((log_dir / "audit.jsonl").stat().st_mode) == 0o640
    assert stat.S_IMODE((log_dir / ".audit.jsonl.lock").stat().st_mode) == 0o600


def test_recursive_json_safety_is_structured(tmp_path: Path) -> None:
    logger = AuditLogger(str(tmp_path / "audit"))
    logger.record(
        "test",
        "json_safe",
        {
            "path": Path("/tmp/example"),
            "bytes": b"ab",
            "nested": [{"values": {3, 1, 2}}],
        },
    )
    payload = list(logger.iter_records())[0]["payload"]
    assert payload["path"] == "/tmp/example"
    assert payload["bytes"] == {"type": "bytes", "hex": "6162"}
    assert payload["nested"][0]["values"] == [1, 2, 3]


def test_tampering_is_detected(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    logger = AuditLogger(str(log_dir))
    logger.record("test", "one", {"value": 1})
    logger.record("test", "two", {"value": 2})
    _tamper_first_payload(log_dir)

    report = verify_audit_directory(log_dir)
    assert report.valid is False
    assert report.error == "RECORD_HASH_MISMATCH"


def test_startup_integrity_failure_raises(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    logger = AuditLogger(str(log_dir))
    logger.record("test", "one", {"value": 1})
    _tamper_first_payload(log_dir)

    with pytest.raises(AuditIntegrityError) as exc_info:
        AuditLogger(str(log_dir))
    assert exc_info.value.report.error == "RECORD_HASH_MISMATCH"


def test_corruption_quarantine_preserves_artifact_and_starts_new_chain(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    logger = AuditLogger(str(log_dir))
    logger.record("test", "one", {"value": 1})
    _tamper_first_payload(log_dir)

    recovered = AuditLogger(str(log_dir), corruption_policy="quarantine")
    report = recovered.verify_integrity()
    records = list(recovered.iter_records())

    assert recovered.startup_integrity_report.valid is False
    assert report.valid is True
    assert report.record_count == 1
    assert records[0]["subject"] == "corruption_recovery"
    artifact = Path(records[0]["payload"]["quarantined_to"])
    assert artifact.is_dir()
    assert (artifact / "integrity-report.json").exists()
    assert (artifact / "audit.jsonl").exists()


def test_trailing_partial_record_is_recovered(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    logger = AuditLogger(str(log_dir))
    logger.record("test", "complete", {"value": 1})
    with (log_dir / "audit.jsonl").open("ab") as handle:
        handle.write(b'{"partial":')
        handle.flush()
        os.fsync(handle.fileno())

    reopened = AuditLogger(str(log_dir), repair_trailing_partial=True)
    assert reopened.startup_integrity_report.valid is True
    assert reopened.startup_integrity_report.repaired_trailing_partial is True
    artifact = Path(reopened.startup_integrity_report.recovery_artifact or "")
    assert artifact.read_bytes() == b'{"partial":'
    reopened.record("test", "after_recovery", {})
    assert reopened.verify_chain() == (True, 2)


def test_rotation_preserves_hash_chain(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    logger = AuditLogger(str(log_dir), max_bytes=700, backup_count=20)
    for index in range(12):
        logger.record("test", "rotation", {"index": index, "padding": "x" * 180})

    report = logger.verify_integrity()
    assert report.valid is True
    assert report.record_count == 12
    assert report.segment_count > 1
    assert report.coverage == "FULL_FROM_GENESIS"
    assert list(log_dir.glob("audit.jsonl.*"))


def test_rotation_retention_reports_retained_window(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    logger = AuditLogger(str(log_dir), max_bytes=700, backup_count=1)
    for index in range(20):
        logger.record("test", "retention", {"index": index, "padding": "x" * 180})

    report = logger.verify_integrity()
    assert report.valid is True
    assert report.coverage == "RETAINED_WINDOW"
    assert len(list(log_dir.glob("audit.jsonl.*"))) <= 1


def test_manual_rotation(tmp_path: Path) -> None:
    logger = AuditLogger(str(tmp_path / "audit"))
    logger.record("test", "before", {})
    rotated = logger.rotate()
    logger.record("test", "after", {})

    assert rotated is not None
    assert Path(rotated).exists()
    assert logger.verify_chain() == (True, 2)


def test_log_symlink_is_rejected(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    target = tmp_path / "target"
    target.write_text("", encoding="utf-8")
    (log_dir / "audit.jsonl").symlink_to(target)

    with pytest.raises(AuditSecurityError):
        AuditLogger(str(log_dir))


def test_directory_symlink_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(AuditSecurityError):
        AuditLogger(str(alias))


def test_record_input_validation(tmp_path: Path) -> None:
    logger = AuditLogger(str(tmp_path / "audit"))
    with pytest.raises(ValueError):
        logger.record("", "subject", {})
    with pytest.raises(ValueError):
        logger.record("source", "bad\nsubject", {})
    with pytest.raises(TypeError):
        logger.record("source", "subject", [])  # type: ignore[arg-type]


def test_max_record_size_is_enforced(tmp_path: Path) -> None:
    logger = AuditLogger(str(tmp_path / "audit"), max_record_bytes=512)
    with pytest.raises(ValueError, match="max_record_bytes"):
        logger.record("test", "large", {"data": "x" * 2000})
    assert logger.verify_chain() == (True, 0)


def test_two_logger_instances_serialize_records(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    first = AuditLogger(str(log_dir))
    second = AuditLogger(str(log_dir))

    def write(logger: AuditLogger, prefix: str) -> None:
        for index in range(15):
            logger.record("thread", prefix, {"index": index})

    threads = [
        threading.Thread(target=write, args=(first, "first")),
        threading.Thread(target=write, args=(second, "second")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert first.verify_chain() == (True, 30)
    sequences = [record["sequence"] for record in first.iter_records()]
    assert sequences == list(range(1, 31))


def test_legacy_stage11_record_is_verified_and_extended(tmp_path: Path) -> None:
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    legacy = {
        "timestamp": 1.0,
        "source": "legacy",
        "subject": "record",
        "payload": {"value": 1},
        "prev_hash": ZERO_HASH,
    }
    serialized = json.dumps(legacy, sort_keys=True, ensure_ascii=False)
    legacy["record_hash"] = hashlib.sha256((ZERO_HASH + serialized).encode()).hexdigest()
    (log_dir / "audit.jsonl").write_text(
        json.dumps(legacy, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    logger = AuditLogger(str(log_dir))
    logger.record("new", "record", {"value": 2})
    assert logger.verify_chain() == (True, 2)
    assert list(logger.iter_records())[-1]["sequence"] == 2


def test_iter_records_limit_and_status_threat_model(tmp_path: Path) -> None:
    logger = AuditLogger(str(tmp_path / "audit"))
    for index in range(5):
        logger.record("test", "item", {"index": index})
    records = list(logger.iter_records(limit=2))
    status = logger.status()

    assert [record["payload"]["index"] for record in records] == [3, 4]
    assert status["startup_integrity"]["valid"] is True
    assert "privileged attacker" in status["threat_model"]
    assert status["directory_mode"] == "0o0750"
