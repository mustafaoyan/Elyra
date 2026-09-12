from __future__ import annotations

import json
from importlib.resources import files

import pytest

from elyra.correlation.engine import (
    CorrelationPolicy,
    ExecutionCorrelationEngine,
    InvalidCorrelationConfiguration,
)


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _engine(clock: FakeClock | None = None) -> ExecutionCorrelationEngine:
    ids = iter(f"correlation-{index}" for index in range(1, 100))
    return ExecutionCorrelationEngine(
        clock=clock or FakeClock(),
        id_factory=lambda: next(ids),
    )


def _fanotify(pid: int, score: int, *, path: str | None = None, final: str = "ALLOW") -> dict:
    return {
        "pid": pid,
        "path": path or f"/tmp/process-{pid}",
        "score": score,
        "risk_score": f"{score}/100",
        "requested_decision": "WARN" if score >= 40 else "ALLOW_MONITOR",
        "final_action": final,
        "indicators": [{"rule": "TEST_PRE_EXEC", "weight": score}],
    }


def _exec(pid: int, *, ppid: int = 1, path: str | None = None, timestamp: int = 1) -> dict:
    return {
        "event_type": "PROCESS_EXEC",
        "pid": pid,
        "tgid": pid,
        "ppid": ppid,
        "uid": 1000,
        "timestamp_ns": timestamp,
        "executable_identifier": path or f"/tmp/process-{pid}",
    }


def _event(kind: str, pid: int, **changes: object) -> dict:
    event = {
        "event_type": kind,
        "pid": pid,
        "tgid": pid,
        "ppid": 1,
        "uid": 1000,
        "timestamp_ns": 2,
    }
    event.update(changes)
    return event


def test_policy_is_provisional_and_all_thresholds_are_reachable() -> None:
    policy = CorrelationPolicy.load()
    maximum_runtime = sum(
        rule.maximum_contribution for rule in policy.runtime_rules.values()
    )
    assert policy.policy_status == "PROVISIONAL_NOT_CALIBRATED"
    assert maximum_runtime >= policy.decision_thresholds["quarantine_min"]


def test_pre_execution_state_binds_to_same_process_exec() -> None:
    engine = _engine()
    first = engine.register_pre_execution(_fanotify(101, 26))
    bound = engine.ingest_runtime_event(_exec(101))

    assert first["state"]["status"] == "PENDING_EXEC"
    assert bound["state"]["status"] == "ACTIVE"
    assert bound["state"]["pre_execution_score"] == 26
    assert bound["state"]["executable_identifier"] == "/tmp/process-101"
    assert bound["state"]["combined_score"] == 26


def test_late_fanotify_result_enriches_runtime_only_state() -> None:
    engine = _engine()
    runtime = engine.ingest_runtime_event(_exec(102))
    correlation_id = runtime["state"]["correlation_id"]
    late = engine.register_pre_execution(_fanotify(102, 38))

    assert late["late_bound"] is True
    assert late["state"]["correlation_id"] == correlation_id
    assert late["state"]["source"] == "FANOTIFY_LATE_BOUND"
    assert late["state"]["pre_execution_score"] == 38


def test_combination_formula_is_direct_and_bounded() -> None:
    engine = _engine()
    engine.register_pre_execution(_fanotify(103, 60))
    engine.ingest_runtime_event(_exec(103))
    result = engine.ingest_runtime_event(
        _event("NETWORK_CONNECT", 103, destination_address="127.0.0.1", destination_port=8000)
    )["state"]

    assert result["runtime_score"] == 20
    assert result["combined_score"] == 80
    assert engine.summary()["combination_formula"] == (
        "combined_score=min(100, pre_execution_score+runtime_score)"
    )


def test_continue_monitoring_transition_is_reachable() -> None:
    engine = _engine()
    engine.register_pre_execution(_fanotify(110, 10))
    state = engine.ingest_runtime_event(_exec(110))["state"]
    assert state["recommended_action"] == "CONTINUE_MONITORING"


def test_alert_transition_is_reachable() -> None:
    engine = _engine()
    engine.register_pre_execution(_fanotify(111, 26))
    engine.ingest_runtime_event(_exec(111))
    state = engine.ingest_runtime_event(
        _event("NETWORK_CONNECT", 111, destination_address="127.0.0.1", destination_port=8080)
    )["state"]
    assert state["combined_score"] == 46
    assert state["recommended_action"] == "ALERT"


def test_terminate_transition_is_reachable() -> None:
    engine = _engine()
    engine.register_pre_execution(_fanotify(112, 38))
    engine.ingest_runtime_event(_exec(112))
    engine.ingest_runtime_event(
        _event("NETWORK_CONNECT", 112, destination_address="127.0.0.1", destination_port=8080)
    )
    state = engine.ingest_runtime_event(
        _event("FILE_RENAME", 112, executable_identifier="rename-source-a")
    )["state"]
    assert state["combined_score"] == 73
    assert state["recommended_action"] == "TERMINATE"


def test_quarantine_transition_is_reachable() -> None:
    engine = _engine()
    engine.register_pre_execution(_fanotify(113, 60))
    engine.ingest_runtime_event(_exec(113))
    engine.ingest_runtime_event(
        _event("NETWORK_CONNECT", 113, destination_address="127.0.0.1", destination_port=8080)
    )
    state = engine.ingest_runtime_event(
        _event("FILE_RENAME", 113, executable_identifier="rename-source-a")
    )["state"]
    assert state["combined_score"] == 95
    assert state["recommended_action"] == "QUARANTINE"
    assert state["action_execution_status"] == "NOT_EXECUTED_STAGE11"


def test_duplicate_file_writes_do_not_inflate_runtime_score() -> None:
    engine = _engine()
    engine.ingest_runtime_event(_exec(114))
    first = engine.ingest_runtime_event(
        _event("FILE_WRITE", 114, distinct_file_key="1:2")
    )["state"]
    second = engine.ingest_runtime_event(
        _event("FILE_WRITE", 114, distinct_file_key="1:2")
    )["state"]
    assert first["runtime_score"] == 8
    assert second["runtime_score"] == 8
    assert second["runtime_counters"]["distinct_files"] == 1


def test_duplicate_network_endpoint_is_counted_once() -> None:
    engine = _engine()
    engine.ingest_runtime_event(_exec(115))
    event = _event(
        "NETWORK_CONNECT", 115, destination_address="127.0.0.1", destination_port=9000
    )
    engine.ingest_runtime_event(event)
    state = engine.ingest_runtime_event(event)["state"]
    assert state["runtime_score"] == 20
    assert state["runtime_counters"]["outbound_connections"] == 1


def test_runtime_only_child_is_linked_to_monitored_parent() -> None:
    engine = _engine()
    engine.register_pre_execution(_fanotify(120, 10))
    parent = engine.ingest_runtime_event(_exec(120))["state"]
    child = engine.ingest_runtime_event(_exec(121, ppid=120))["state"]

    assert child["parent_correlation_id"] == parent["correlation_id"]
    assert child["runtime_score"] == 10
    assert child["runtime_indicators"][0]["rule"] == "CHILD_PROCESS_EXEC"


def test_executable_identifier_mismatch_is_visible() -> None:
    engine = _engine()
    engine.register_pre_execution(_fanotify(122, 10, path="/tmp/original"))
    state = engine.ingest_runtime_event(_exec(122, path="/tmp/replaced"))["state"]
    assert state["runtime_score"] == 20
    assert state["runtime_indicators"][0]["rule"] == "EXECUTABLE_IDENTIFIER_MISMATCH"


def test_pre_execution_denial_is_terminal_and_does_not_claim_action_execution() -> None:
    engine = _engine()
    state = engine.register_pre_execution(_fanotify(123, 100, final="DENY"))["state"]
    assert state["status"] == "DENIED_PRE_EXECUTION"
    assert state["recommended_action"] == "DENY"
    assert state["action_execution_status"] == "NOT_EXECUTED_STAGE11"


def test_exit_state_is_retained_then_expires() -> None:
    clock = FakeClock()
    engine = _engine(clock)
    engine.ingest_runtime_event(_exec(124))
    exited = engine.ingest_runtime_event(_event("PROCESS_EXIT", 124, timestamp_ns=99))["state"]
    assert exited["status"] == "EXITED"
    assert engine.get_state(124) is not None

    clock.advance(engine.policy.exited_state_ttl_seconds + 0.1)
    assert engine.expire() == 1
    assert engine.get_state(124) is None
    assert engine.archived[-1]["terminal_reason"] == "EXITED_STATE_TTL_EXPIRED"


def test_active_state_ttl_expiration_is_bounded() -> None:
    clock = FakeClock()
    engine = _engine(clock)
    engine.ingest_runtime_event(_exec(125))
    clock.advance(engine.policy.state_ttl_seconds + 0.1)
    assert engine.expire() == 1
    assert engine.get_state(125) is None


def test_second_exec_on_same_pid_creates_new_generation() -> None:
    engine = _engine()
    first = engine.ingest_runtime_event(_exec(126, path="/bin/first", timestamp=10))["state"]
    second = engine.ingest_runtime_event(_exec(126, path="/bin/second", timestamp=20))["state"]
    assert first["generation"] == 1
    assert second["generation"] == 2
    assert second["correlation_id"] != first["correlation_id"]
    assert engine.archived[-1]["terminal_reason"] == "PID_EXEC_GENERATION_REPLACED"


def test_invalid_unreachable_policy_is_rejected() -> None:
    data = json.loads(
        files("elyra.config").joinpath("runtime_correlation.default.json").read_text(
            encoding="utf-8"
        )
    )
    data["decision_thresholds"]["quarantine_min"] = 100
    for rule in data["runtime_rules"].values():
        rule["weight"] = 1
        rule["max_occurrences"] = 1
    with pytest.raises(InvalidCorrelationConfiguration, match="cannot reach"):
        CorrelationPolicy.from_mapping(data)


def test_actions_never_deescalate_as_runtime_score_grows() -> None:
    engine = _engine()
    engine.register_pre_execution(_fanotify(127, 38))
    engine.ingest_runtime_event(_exec(127))
    states = []
    states.append(engine.ingest_runtime_event(
        _event("NETWORK_CONNECT", 127, destination_address="127.0.0.1", destination_port=1)
    )["state"])
    states.append(engine.ingest_runtime_event(
        _event("FILE_RENAME", 127, executable_identifier="a")
    )["state"])
    states.append(engine.ingest_runtime_event(
        _event("NETWORK_CONNECT", 127, destination_address="127.0.0.1", destination_port=2)
    )["state"])
    assert [item["recommended_action"] for item in states] == [
        "ALERT",
        "TERMINATE",
        "QUARANTINE",
    ]


def test_concurrent_fanotify_and_runtime_updates_are_serialized() -> None:
    from concurrent.futures import ThreadPoolExecutor

    engine = _engine()
    engine.register_pre_execution(_fanotify(130, 10))
    engine.ingest_runtime_event(_exec(130))

    events = [
        _event("FILE_WRITE", 130, distinct_file_key=f"1:{index}")
        for index in range(20)
    ] + [
        _event(
            "NETWORK_CONNECT",
            130,
            destination_address="127.0.0.1",
            destination_port=9000 + index,
        )
        for index in range(10)
    ]
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(engine.ingest_runtime_event, events))

    state = engine.get_state(130)
    assert state is not None
    assert state["runtime_counters"]["rule_occurrences"] == {
        "DISTINCT_FILE_WRITE": 4,
        "OUTBOUND_CONNECTION": 2,
    }
    assert state["runtime_score"] == 72
    assert state["combined_score"] == 82
    assert state["recommended_action"] == "TERMINATE"
