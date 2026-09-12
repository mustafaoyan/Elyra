from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from elyra.audit.audit_logger import AuditLogger
from elyra.response.engine import (
    FileIdentity,
    PidfdProcessController,
    ProcessIdentity,
    ResponseEngine,
    ResponsePolicy,
)
from elyra.response.quarantine_manager import QuarantineManager


class MemoryAudit:
    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict]] = []

    def record(self, source: str, subject: str, payload: dict) -> str:
        self.records.append((source, subject, payload))
        return "a" * 64


class FakeInspector:
    def __init__(self, identity: ProcessIdentity | None = None) -> None:
        self.identity = identity

    def capture(self, pid: int) -> ProcessIdentity:
        if self.identity is None:
            raise RuntimeError("unexpected capture")
        assert pid == self.identity.pid
        return self.identity


class FakeController:
    def __init__(self) -> None:
        self.calls: list[ProcessIdentity] = []

    def terminate(self, identity: ProcessIdentity, policy: ResponsePolicy) -> dict:
        self.calls.append(identity)
        return {"signal": "SIGTERM", "escalated": False, "process_already_exited": False}


def _identity(pid: int = 7001) -> ProcessIdentity:
    return ProcessIdentity(
        pid=pid,
        start_time_ticks=12345,
        executable_path="/tmp/safe-exec",
        executable_device=8,
        executable_inode=99,
        uid=1000,
    )


def _state(action: str, *, correlation_id: str = "corr-1", pid: int = 7001, path: str | None = None) -> dict:
    return {
        "correlation_id": correlation_id,
        "pid": pid,
        "tgid": pid,
        "status": "ACTIVE",
        "executable_path": path,
        "combined_score": {"ALLOW": 0, "CONTINUE_MONITORING": 10, "ALERT": 50, "DENY": 100, "TERMINATE": 75, "QUARANTINE": 95}.get(action, 0),
        "recommended_action": action,
        "pre_execution_indicators": [{"rule": "PRE", "weight": 10}],
        "runtime_indicators": [{"rule": "RUNTIME", "weight": 20}],
    }


def _engine(tmp_path: Path, *, enabled: bool = True, identity: ProcessIdentity | None = None):
    audit = MemoryAudit()
    quarantine = QuarantineManager(
        quarantine_dir=tmp_path / "quarantine",
        metadata_dir=tmp_path / "metadata",
        audit_log=audit,
    )
    controller = FakeController()
    policy = ResponsePolicy.load().with_runtime_actions(enabled)
    engine = ResponseEngine(
        quarantine,
        audit_logger=audit,
        policy=policy,
        process_inspector=FakeInspector(identity),
        process_controller=controller,  # type: ignore[arg-type]
        id_factory=iter([f"action-{i}" for i in range(100)]).__next__,
    )
    return engine, quarantine, controller, audit


def test_policy_is_provisional_and_destructive_actions_default_off() -> None:
    policy = ResponsePolicy.load()
    assert policy.policy_status == "PROVISIONAL_NOT_CALIBRATED"
    assert policy.automatic_runtime_actions is False
    assert policy.require_pidfd is True
    assert {0, 1}.issubset(policy.protected_pids)


@pytest.mark.parametrize(
    ("recommendation", "executed"),
    [
        ("ALLOW", "ALLOW"),
        ("CONTINUE_MONITORING", "ALLOW_MONITOR"),
        ("ALERT", "WARN"),
    ],
)
def test_non_destructive_responses_execute_and_are_audited(
    tmp_path: Path, recommendation: str, executed: str
) -> None:
    engine, _, _, audit = _engine(tmp_path)
    result = engine.execute_recommendation(_state(recommendation))
    assert result.status == "SUCCEEDED"
    assert result.executed_action == executed
    assert audit.records[-1][0] == "response"
    assert audit.records[-1][2]["score"] >= 0
    assert audit.records[-1][2]["triggered_rules"]


def test_warning_is_sent_to_event_sink(tmp_path: Path) -> None:
    engine, _, _, _ = _engine(tmp_path)
    events: list[dict] = []
    engine.event_sink = events.append
    result = engine.execute_recommendation(_state("ALERT"))
    assert result.executed_action == "WARN"
    assert events[-1]["source"] == "response"
    assert events[-1]["status"] == "SUCCEEDED"


def test_deny_only_acknowledges_confirmed_fanotify_denial(tmp_path: Path) -> None:
    engine, _, _, _ = _engine(tmp_path)
    unconfirmed = engine.execute_recommendation(_state("DENY"))
    confirmed_state = _state("DENY", correlation_id="corr-denied")
    confirmed_state["status"] = "DENIED_PRE_EXECUTION"
    confirmed = engine.execute_recommendation(confirmed_state)
    assert unconfirmed.status == "REFUSED"
    assert unconfirmed.failure_explanation == "DENY_NOT_CONFIRMED_BY_FANOTIFY"
    assert confirmed.status == "SUCCEEDED"


def test_destructive_action_is_skipped_when_policy_is_disabled(tmp_path: Path) -> None:
    engine, _, _, _ = _engine(tmp_path, enabled=False)
    result = engine.execute_recommendation(_state("TERMINATE"))
    assert result.status == "SKIPPED_POLICY_DISABLED"
    assert result.executed_action == "TERMINATE"


def test_bound_termination_uses_exact_process_identity(tmp_path: Path) -> None:
    identity = _identity()
    engine, _, controller, _ = _engine(tmp_path, identity=identity)
    state = _state("TERMINATE")
    engine.bind_state(state)
    result = engine.execute_recommendation(state)
    assert result.status == "SUCCEEDED"
    assert controller.calls == [identity]
    assert result.details["process_identity"]["start_time_ticks"] == 12345


def test_quarantine_uses_bound_file_identity_and_can_restore(tmp_path: Path) -> None:
    source = tmp_path / "safe.bin"
    source.write_bytes(b"harmless-stage11-data")
    identity = _identity()
    engine, quarantine, controller, _ = _engine(tmp_path, identity=identity)
    state = _state("QUARANTINE", path=str(source))
    engine.bind_state(state)
    result = engine.execute_recommendation(state)
    assert result.status == "SUCCEEDED"
    assert not source.exists()
    assert controller.calls == [identity]
    record = result.details["quarantine_record"]
    restored, restore_result = engine.restore(
        record["quarantine_id"], None, actor="unit-test", requester_pid=os.getpid()
    )
    assert source.read_bytes() == b"harmless-stage11-data"
    assert restored.restoration_status == "restored"
    assert restore_result.status == "SUCCEEDED"


def test_path_replacement_is_refused_even_when_content_is_identical(tmp_path: Path) -> None:
    source = tmp_path / "replace.bin"
    source.write_bytes(b"same-content")
    engine, _, _, _ = _engine(tmp_path, identity=None)
    state = _state("QUARANTINE", pid=0, path=str(source))
    engine.bind_state(state)
    source.unlink()
    source.write_bytes(b"same-content")
    result = engine.execute_recommendation(state)
    assert result.status == "REFUSED"
    assert "identity changed" in (result.failure_explanation or "")
    assert source.exists()


def test_duplicate_equal_response_is_suppressed(tmp_path: Path) -> None:
    engine, _, _, _ = _engine(tmp_path)
    state = _state("CONTINUE_MONITORING")
    first = engine.execute_recommendation(state)
    second = engine.execute_recommendation(state)
    assert first.status == "SUCCEEDED"
    assert second.status == "DUPLICATE_SUPPRESSED"


def test_file_identity_contains_hash_inode_and_mtime(tmp_path: Path) -> None:
    path = tmp_path / "identity.bin"
    path.write_bytes(b"identity")
    identity = ResponseEngine.capture_file_identity(path)
    assert isinstance(identity, FileIdentity)
    assert identity.inode == path.stat().st_ino
    assert identity.mtime_ns == path.stat().st_mtime_ns
    assert len(identity.sha256) == 64


def test_pidfd_identity_comparison_rejects_reuse() -> None:
    original = _identity()
    changed = ProcessIdentity(
        pid=original.pid,
        start_time_ticks=original.start_time_ticks + 1,
        executable_path=original.executable_path,
        executable_device=original.executable_device,
        executable_inode=original.executable_inode,
        uid=original.uid,
    )
    assert PidfdProcessController._same_identity(original, original) is True
    assert PidfdProcessController._same_identity(original, changed) is False


def test_audit_log_contains_reason_score_rules_timestamp_and_result(tmp_path: Path) -> None:
    audit = AuditLogger(log_dir=str(tmp_path / "audit"))
    quarantine = QuarantineManager(
        quarantine_dir=tmp_path / "quarantine",
        metadata_dir=tmp_path / "metadata",
        audit_log=audit,
    )
    engine = ResponseEngine(quarantine, audit_logger=audit)
    result = engine.execute_recommendation(_state("ALERT"))
    line = json.loads(audit.log_path.read_text(encoding="utf-8").splitlines()[-1])
    payload = line["payload"]
    assert payload["reason"] == result.reason
    assert payload["score"] == 50
    assert payload["triggered_rules"]
    assert payload["timestamp"] > 0
    assert payload["status"] == "SUCCEEDED"
