from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from elyra.response.quarantine_manager import (
    QuarantineConflictError,
    QuarantineError,
    QuarantineIntegrityError,
    QuarantineManager,
    QuarantineMetadataError,
)


def make_manager(tmp_path: Path) -> QuarantineManager:
    return QuarantineManager(
        quarantine_dir=tmp_path / "protected" / "quarantine",
        metadata_dir=tmp_path / "protected" / "metadata",
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def quarantine_sample(
    manager: QuarantineManager,
    source: Path,
    data: bytes = b"safe synthetic sample\n",
):
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_bytes(data)
    source.chmod(0o640)
    return manager.quarantine_file(
        source,
        expected_sha256=sha256(data),
        reason="Safe Stage 5 unit test",
        related_pid=1234,
        triggered_rules=[{"rule": "SAFE_TEST_FIXTURE", "weight": 0}],
        process_info={"command": "pytest", "synthetic": True},
    )


def test_basic_quarantine_and_restore(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    source = tmp_path / "work" / "sample.bin"
    content = b"ELYRA safe quarantine fixture\n"

    record = quarantine_sample(manager, source, content)

    payload = manager.quarantine_dir / record.quarantine_id
    metadata = manager.metadata_dir / f"{record.quarantine_id}.json"
    assert not source.exists()
    assert payload.read_bytes() == content
    assert record.sha256 == sha256(content)
    assert record.original_path == str(source)
    assert record.related_pid == 1234
    assert record.process_info["synthetic"] is True
    assert stat.S_IMODE(payload.stat().st_mode) == 0o600
    assert stat.S_IMODE(metadata.stat().st_mode) == 0o600
    assert stat.S_IMODE(manager.quarantine_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(manager.metadata_dir.stat().st_mode) == 0o700

    restored = manager.restore_file(record.quarantine_id)

    assert source.read_bytes() == content
    assert restored.restoration_status == "restored"
    assert restored.restored_path == str(source)
    assert restored.restored_mode == 0o640
    assert stat.S_IMODE(source.stat().st_mode) == 0o640
    assert payload.exists(), "The protected payload remains available after restoration"
    assert manager.get_record(record.quarantine_id).restoration_status == "restored"


def test_audit_write_failure_is_visible_after_committed_quarantine(tmp_path: Path) -> None:
    class BrokenAudit:
        def record(self, *_args, **_kwargs):
            raise OSError("synthetic full disk")

    manager = QuarantineManager(
        quarantine_dir=tmp_path / "q",
        metadata_dir=tmp_path / "m",
        audit_log=BrokenAudit(),
    )
    source = tmp_path / "work" / "sample.bin"
    record = quarantine_sample(manager, source, b"audit failure fixture")
    assert record.restoration_status == "quarantined"
    assert manager.audit_status["status"] == "DEGRADED_AUDIT_WRITE_FAILED"
    assert "full disk" in str(manager.audit_status["error"])


def test_identical_files_from_different_paths_get_distinct_records(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    content = b"identical safe bytes"
    first_path = tmp_path / "a" / "same.bin"
    second_path = tmp_path / "b" / "same.bin"

    first = quarantine_sample(manager, first_path, content)
    second = quarantine_sample(manager, second_path, content)

    assert first.sha256 == second.sha256
    assert first.quarantine_id != second.quarantine_id
    assert first.original_path != second.original_path
    assert (manager.quarantine_dir / first.quarantine_id).exists()
    assert (manager.quarantine_dir / second.quarantine_id).exists()
    assert len(manager.list_quarantine()) == 2


def test_restore_never_overwrites_existing_destination(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    source = tmp_path / "work" / "conflict.bin"
    record = quarantine_sample(manager, source, b"quarantined content")
    source.write_bytes(b"new legitimate content")

    with pytest.raises(QuarantineConflictError, match="will not be overwritten"):
        manager.restore_file(record.quarantine_id)

    assert source.read_bytes() == b"new legitimate content"
    assert manager.get_record(record.quarantine_id).restoration_status == "quarantined"


def test_expected_hash_mismatch_preserves_original(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    source = tmp_path / "work" / "changed.bin"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"current bytes")

    with pytest.raises(QuarantineIntegrityError, match="Source hash changed"):
        manager.quarantine_file(
            source,
            expected_sha256="0" * 64,
            reason="Expected mismatch test",
            related_pid=None,
            triggered_rules=[],
        )

    assert source.read_bytes() == b"current bytes"
    assert list(manager.quarantine_dir.iterdir()) == []
    assert list(manager.metadata_dir.iterdir()) == []


def test_tampered_payload_blocks_restoration(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    source = tmp_path / "work" / "payload.bin"
    record = quarantine_sample(manager, source, b"verified payload")
    payload = manager.quarantine_dir / record.quarantine_id
    payload.write_bytes(b"tampered")
    destination = tmp_path / "work" / "restored.bin"

    with pytest.raises(QuarantineIntegrityError, match="integrity verification failed"):
        manager.restore_file(record.quarantine_id, destination)

    assert not destination.exists()
    assert manager.get_record(record.quarantine_id).restoration_status == "quarantined"


def test_corrupt_metadata_is_reported_explicitly(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    source = tmp_path / "work" / "metadata.bin"
    record = quarantine_sample(manager, source)
    metadata = manager.metadata_dir / f"{record.quarantine_id}.json"
    metadata.write_text("{not-valid-json", encoding="utf-8")

    with pytest.raises(QuarantineMetadataError, match="cannot be read"):
        manager.restore_file(record.quarantine_id)

    with pytest.raises(QuarantineMetadataError):
        manager.list_quarantine()
    assert manager.list_quarantine(strict=False) == []


def test_interrupted_quarantine_rolls_back_original_and_partial_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = make_manager(tmp_path)
    source = tmp_path / "work" / "rollback.bin"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"must survive interrupted quarantine")

    def fail_metadata_write(_record) -> None:
        raise OSError("simulated metadata storage failure")

    monkeypatch.setattr(manager, "_write_metadata_atomic", fail_metadata_write)

    with pytest.raises(QuarantineError, match="failed safely"):
        manager.quarantine_file(
            source,
            expected_sha256=sha256(source.read_bytes()),
            reason="Interrupted operation test",
            related_pid=None,
            triggered_rules=[],
        )

    assert source.read_bytes() == b"must survive interrupted quarantine"
    assert list(manager.quarantine_dir.iterdir()) == []
    assert list(manager.metadata_dir.iterdir()) == []
    assert list(source.parent.glob(".elyra-*.pending")) == []


def test_interrupted_restore_removes_partial_target_and_restores_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manager = make_manager(tmp_path)
    source = tmp_path / "work" / "restore-rollback.bin"
    record = quarantine_sample(manager, source, b"restore transaction")
    destination = tmp_path / "work" / "new-destination.bin"
    original_writer = manager._write_metadata_atomic
    calls = 0

    def fail_first_write(updated_record) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("simulated restore metadata failure")
        original_writer(updated_record)

    monkeypatch.setattr(manager, "_write_metadata_atomic", fail_first_write)

    with pytest.raises(QuarantineError, match="failed safely"):
        manager.restore_file(record.quarantine_id, destination)

    assert not destination.exists()
    stored = manager.get_record(record.quarantine_id)
    assert stored.restoration_status == "quarantined"
    assert stored.restored_path is None


def test_symbolic_link_source_is_rejected(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    target = tmp_path / "work" / "real.bin"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"real file remains untouched")
    link = tmp_path / "work" / "link.bin"
    link.symlink_to(target)

    with pytest.raises(QuarantineError, match="Symbolic-link"):
        manager.quarantine_file(
            link,
            expected_sha256=None,
            reason="Symlink rejection test",
            related_pid=None,
            triggered_rules=[],
        )

    assert link.is_symlink()
    assert target.read_bytes() == b"real file remains untouched"


def test_missing_quarantine_payload_blocks_restoration(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    source = tmp_path / "work" / "missing.bin"
    record = quarantine_sample(manager, source)
    (manager.quarantine_dir / record.quarantine_id).unlink()

    with pytest.raises(QuarantineError, match="does not exist"):
        manager.restore_file(record.quarantine_id)


def test_restore_destination_must_be_absolute(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    source = tmp_path / "work" / "relative.bin"
    record = quarantine_sample(manager, source)

    with pytest.raises(QuarantineConflictError, match="absolute path"):
        manager.restore_file(record.quarantine_id, "relative-output.bin")


def test_directory_input_is_rejected(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    directory = tmp_path / "work" / "folder"
    directory.mkdir(parents=True)

    with pytest.raises(QuarantineError, match="regular files"):
        manager.quarantine_file(
            directory,
            expected_sha256=None,
            reason="Directory rejection test",
            related_pid=None,
            triggered_rules=[],
        )


def test_invalid_quarantine_id_cannot_escape_storage(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)

    with pytest.raises(QuarantineMetadataError, match="Invalid quarantine ID"):
        manager.restore_file("../../outside")


def test_metadata_contains_required_stage5_fields(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    source = tmp_path / "work" / "fields.bin"
    record = quarantine_sample(manager, source)
    metadata_path = manager.metadata_dir / f"{record.quarantine_id}.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

    required = {
        "schema_version",
        "quarantine_id",
        "original_path",
        "sha256",
        "size_bytes",
        "file_type",
        "timestamp",
        "timestamp_utc",
        "reason",
        "related_pid",
        "process_info",
        "triggered_rules",
        "restoration_status",
    }
    assert required.issubset(metadata)
    assert metadata["restoration_status"] == "quarantined"


def test_permanent_delete_updates_metadata_and_removes_payload(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    source = tmp_path / "work" / "delete.bin"
    record = quarantine_sample(manager, source)

    manager.delete_permanently(record.quarantine_id)

    assert not (manager.quarantine_dir / record.quarantine_id).exists()
    deleted = manager.get_record(record.quarantine_id)
    assert deleted.restoration_status == "deleted"
    assert deleted.deleted_at is not None


def test_non_json_rule_data_is_rejected_before_source_is_moved(tmp_path: Path) -> None:
    manager = make_manager(tmp_path)
    source = tmp_path / "work" / "invalid-rules.bin"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"safe")

    with pytest.raises(QuarantineError, match="JSON-serialisable"):
        manager.quarantine_file(
            source,
            expected_sha256=None,
            reason="Invalid rule test",
            related_pid=None,
            triggered_rules=[{"bad": {1, 2, 3}}],
        )

    assert source.exists()


def test_multiple_hard_links_are_rejected_without_removing_either_path(
    tmp_path: Path,
) -> None:
    manager = make_manager(tmp_path)
    source = tmp_path / "work" / "original.bin"
    alias = tmp_path / "work" / "alias.bin"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"hard-link safety")
    os.link(source, alias)

    with pytest.raises(QuarantineError, match="multiple hard links"):
        manager.quarantine_file(
            source,
            expected_sha256=sha256(source.read_bytes()),
            reason="Hard-link safety test",
            related_pid=None,
            triggered_rules=[],
        )

    assert source.exists()
    assert alias.exists()
    assert source.stat().st_ino == alias.stat().st_ino
