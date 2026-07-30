from __future__ import annotations

from pathlib import Path

from elliot.correlation.engine import ExecutionCorrelationEngine
from elliot.response.quarantine_manager import QuarantineIntegrityError, QuarantineManager


def test_correlation_records_stage11_result_on_exact_generation() -> None:
    engine = ExecutionCorrelationEngine(id_factory=lambda: "corr-stage11")
    created = engine.register_pre_execution(
        {
            "pid": 444,
            "path": "/tmp/safe",
            "score": 10,
            "requested_decision": "ALLOW_MONITOR",
            "final_action": "ALLOW",
            "indicators": [],
        }
    )["state"]
    assert created["action_execution_status"] == "NOT_EXECUTED_STAGE11"
    assert engine.record_action_result(
        444,
        "corr-stage11",
        {"status": "SUCCEEDED", "executed_action": "ALLOW_MONITOR"},
    ) is True
    updated = engine.get_state(444)
    assert updated is not None
    assert updated["action_execution_status"] == "SUCCEEDED"
    assert updated["last_action_result"]["executed_action"] == "ALLOW_MONITOR"
    assert engine.record_action_result(444, "wrong-generation", {"status": "SUCCEEDED"}) is False


def test_quarantine_rejects_expected_inode_mismatch(tmp_path: Path) -> None:
    source = tmp_path / "source.bin"
    source.write_bytes(b"harmless")
    manager = QuarantineManager(
        quarantine_dir=tmp_path / "quarantine",
        metadata_dir=tmp_path / "metadata",
    )
    info = source.stat()
    try:
        manager.quarantine_file(
            source,
            None,
            "test mismatch",
            None,
            [],
            expected_device=info.st_dev,
            expected_inode=info.st_ino + 1,
        )
    except QuarantineIntegrityError as exc:
        assert "identity changed" in str(exc)
    else:
        raise AssertionError("quarantine accepted a mismatched inode")
    assert source.exists()


def test_daemon_routes_correlation_into_stage11_response_engine() -> None:
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "elliot"
        / "service"
        / "daemon.py"
    ).read_text(encoding="utf-8")
    assert "ResponseEngine(" in source
    assert "execute_recommendation(state)" in source
    assert "record_action_result(" in source
    assert "--execute-responses" in source
    assert "NOT_EXECUTED_STAGE10" not in source
