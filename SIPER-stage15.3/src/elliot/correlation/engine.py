"""Stage 10 pre-execution/runtime correlation and evolving risk state.

This module joins a fanotify pre-execution decision to subsequent eBPF events.
It recommends response actions but deliberately does not execute terminate or
quarantine operations; those actions belong to Stage 11.
"""

from __future__ import annotations

import json
import os
import time
import uuid
import threading
from collections import deque
from dataclasses import asdict, dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Callable, Mapping


class InvalidCorrelationConfiguration(ValueError):
    """Raised when the Stage 10 policy is incomplete or unreachable."""


@dataclass(frozen=True, slots=True)
class RuntimeRuleSpec:
    rule: str
    weight: int
    max_occurrences: int
    description: str

    @property
    def maximum_contribution(self) -> int:
        return self.weight * self.max_occurrences


@dataclass(frozen=True, slots=True)
class CorrelationPolicy:
    schema_version: str
    policy_name: str
    policy_status: str
    score_minimum: int
    score_maximum: int
    state_ttl_seconds: float
    exited_state_ttl_seconds: float
    late_binding_window_seconds: float
    inheritance_window_seconds: float
    max_states: int
    decision_thresholds: Mapping[str, int]
    runtime_rules: Mapping[str, RuntimeRuleSpec]

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CorrelationPolicy":
        try:
            raw_rules = data["runtime_rules"]
            rules = {
                str(rule_id): RuntimeRuleSpec(
                    rule=str(rule_id),
                    weight=int(spec["weight"]),
                    max_occurrences=int(spec["max_occurrences"]),
                    description=str(spec["description"]),
                )
                for rule_id, spec in raw_rules.items()
            }
            policy = cls(
                schema_version=str(data["schema_version"]),
                policy_name=str(data["policy_name"]),
                policy_status=str(data["policy_status"]),
                score_minimum=int(data["score_minimum"]),
                score_maximum=int(data["score_maximum"]),
                state_ttl_seconds=float(data["state_ttl_seconds"]),
                exited_state_ttl_seconds=float(data["exited_state_ttl_seconds"]),
                late_binding_window_seconds=float(data["late_binding_window_seconds"]),
                inheritance_window_seconds=float(data["inheritance_window_seconds"]),
                max_states=int(data["max_states"]),
                decision_thresholds={
                    str(name): int(value)
                    for name, value in data["decision_thresholds"].items()
                },
                runtime_rules=rules,
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise InvalidCorrelationConfiguration(
                f"invalid runtime-correlation configuration: {exc}"
            ) from exc
        policy.validate()
        return policy

    @classmethod
    def load(cls, path: str | Path | None = None) -> "CorrelationPolicy":
        if path is None:
            text = files("elliot.config").joinpath(
                "runtime_correlation.default.json"
            ).read_text(encoding="utf-8")
        else:
            text = Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise InvalidCorrelationConfiguration(
                f"runtime-correlation configuration is not valid JSON: {exc}"
            ) from exc
        if not isinstance(data, dict):
            raise InvalidCorrelationConfiguration(
                "runtime-correlation configuration root must be an object"
            )
        return cls.from_mapping(data)

    def validate(self) -> None:
        if self.policy_status != "PROVISIONAL_NOT_CALIBRATED":
            raise InvalidCorrelationConfiguration(
                "Stage 10 policy must be labelled PROVISIONAL_NOT_CALIBRATED"
            )
        if (self.score_minimum, self.score_maximum) != (0, 100):
            raise InvalidCorrelationConfiguration("score range must be 0..100")
        if min(
            self.state_ttl_seconds,
            self.exited_state_ttl_seconds,
            self.late_binding_window_seconds,
            self.inheritance_window_seconds,
        ) <= 0:
            raise InvalidCorrelationConfiguration("all time windows must be positive")
        if self.max_states <= 0:
            raise InvalidCorrelationConfiguration("max_states must be positive")

        expected = {"alert_min", "terminate_min", "quarantine_min"}
        if set(self.decision_thresholds) != expected:
            raise InvalidCorrelationConfiguration(
                "decision thresholds must define alert_min, terminate_min and quarantine_min"
            )
        alert = self.decision_thresholds["alert_min"]
        terminate = self.decision_thresholds["terminate_min"]
        quarantine = self.decision_thresholds["quarantine_min"]
        if not (0 < alert < terminate < quarantine <= self.score_maximum):
            raise InvalidCorrelationConfiguration(
                "decision thresholds must increase within the 0..100 score range"
            )

        required_rules = {
            "DISTINCT_FILE_WRITE",
            "FILE_RENAME",
            "OUTBOUND_CONNECTION",
            "CHILD_PROCESS_EXEC",
            "EXECUTABLE_IDENTIFIER_MISMATCH",
        }
        if set(self.runtime_rules) != required_rules:
            raise InvalidCorrelationConfiguration(
                "runtime rules do not match the Stage 10 canonical rule set"
            )
        for rule_id, rule in self.runtime_rules.items():
            if rule.rule != rule_id:
                raise InvalidCorrelationConfiguration(
                    f"rule key differs from embedded name: {rule_id}"
                )
            if rule.weight <= 0 or rule.max_occurrences <= 0:
                raise InvalidCorrelationConfiguration(
                    f"rule {rule_id} must have positive weight and occurrence cap"
                )
            if not rule.description.strip():
                raise InvalidCorrelationConfiguration(
                    f"rule {rule_id} has an empty description"
                )

        # A runtime-only process must be capable of reaching every configured
        # transition. This makes mathematically unreachable response thresholds
        # a configuration error rather than a hidden integration defect.
        maximum_runtime = sum(
            rule.maximum_contribution for rule in self.runtime_rules.values()
        )
        if maximum_runtime < quarantine:
            raise InvalidCorrelationConfiguration(
                "runtime rule maxima cannot reach quarantine_min"
            )


@dataclass(frozen=True, slots=True)
class RuntimeIndicator:
    rule: str
    weight: int
    occurrence: int
    maximum_occurrences: int
    evidence: Any
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ExecutionState:
    correlation_id: str
    generation: int
    pid: int
    tgid: int
    ppid: int
    uid: int
    source: str
    status: str
    executable_path: str | None
    executable_identifier: str | None
    pre_execution_score: int
    pre_execution_decision: str
    pre_execution_indicators: list[dict[str, Any]]
    runtime_score: int
    combined_score: int
    recommended_action: str
    parent_correlation_id: str | None
    created_monotonic: float
    last_seen_monotonic: float
    exec_timestamp_ns: int | None = None
    exit_timestamp_ns: int | None = None
    exited_monotonic: float | None = None
    runtime_indicators: list[RuntimeIndicator] = field(default_factory=list)
    rule_occurrences: dict[str, int] = field(default_factory=dict)
    distinct_files: set[str] = field(default_factory=set)
    rename_identifiers: set[str] = field(default_factory=set)
    outbound_connections: set[str] = field(default_factory=set)
    transitions: list[dict[str, Any]] = field(default_factory=list)
    terminal_reason: str | None = None
    action_execution_status: str = "NOT_EXECUTED_STAGE11"
    last_action_result: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "correlation_id": self.correlation_id,
            "generation": self.generation,
            "pid": self.pid,
            "tgid": self.tgid,
            "ppid": self.ppid,
            "uid": self.uid,
            "source": self.source,
            "status": self.status,
            "executable_path": self.executable_path,
            "executable_identifier": self.executable_identifier,
            "pre_execution_score": self.pre_execution_score,
            "runtime_score": self.runtime_score,
            "combined_score": self.combined_score,
            "pre_execution_decision": self.pre_execution_decision,
            "recommended_action": self.recommended_action,
            "action_execution_status": self.action_execution_status,
            "last_action_result": dict(self.last_action_result) if self.last_action_result else None,
            "parent_correlation_id": self.parent_correlation_id,
            "exec_timestamp_ns": self.exec_timestamp_ns,
            "exit_timestamp_ns": self.exit_timestamp_ns,
            "pre_execution_indicators": list(self.pre_execution_indicators),
            "runtime_indicators": [item.to_dict() for item in self.runtime_indicators],
            "runtime_counters": {
                "distinct_files": len(self.distinct_files),
                "rename_identifiers": len(self.rename_identifiers),
                "outbound_connections": len(self.outbound_connections),
                "rule_occurrences": dict(self.rule_occurrences),
            },
            "transitions": list(self.transitions),
            "terminal_reason": self.terminal_reason,
        }


_ACTION_RANK = {
    "CONTINUE_MONITORING": 0,
    "ALERT": 1,
    "TERMINATE": 2,
    "QUARANTINE": 3,
    "DENY": 4,
}


class ExecutionCorrelationEngine:
    """Join fanotify decisions and eBPF events into bounded process states."""

    def __init__(
        self,
        policy: CorrelationPolicy | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.policy = policy or CorrelationPolicy.load()
        self._clock = clock
        self._id_factory = id_factory or (lambda: uuid.uuid4().hex)
        self._lock = threading.RLock()
        self.states: dict[int, ExecutionState] = {}
        self.archived: deque[dict[str, Any]] = deque(maxlen=1024)
        self._generation_by_pid: dict[int, int] = {}

    @staticmethod
    def _score(value: Any) -> int:
        if isinstance(value, bool):
            return 0
        if isinstance(value, (int, float)):
            return max(0, min(100, int(value)))
        if isinstance(value, str):
            head = value.split("/", 1)[0]
            try:
                return max(0, min(100, int(float(head))))
            except ValueError:
                return 0
        return 0

    @staticmethod
    def _pid(record: Mapping[str, Any]) -> int:
        value = record.get("tgid") or record.get("pid") or 0
        if isinstance(value, bool):
            return 0
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    def _new_state(
        self,
        *,
        pid: int,
        ppid: int = 0,
        uid: int = 0,
        source: str,
        status: str,
        executable_path: str | None = None,
        pre_execution_score: int = 0,
        pre_execution_decision: str = "UNKNOWN",
        pre_execution_indicators: list[dict[str, Any]] | None = None,
        parent_correlation_id: str | None = None,
    ) -> ExecutionState:
        if len(self.states) >= self.policy.max_states:
            oldest_pid = min(
                self.states,
                key=lambda item: self.states[item].last_seen_monotonic,
            )
            self._archive(oldest_pid, "MAX_STATES_EVICTION")
        generation = self._generation_by_pid.get(pid, 0) + 1
        self._generation_by_pid[pid] = generation
        now = self._clock()
        state = ExecutionState(
            correlation_id=self._id_factory(),
            generation=generation,
            pid=pid,
            tgid=pid,
            ppid=ppid,
            uid=uid,
            source=source,
            status=status,
            executable_path=executable_path,
            executable_identifier=None,
            pre_execution_score=pre_execution_score,
            pre_execution_decision=pre_execution_decision,
            pre_execution_indicators=list(pre_execution_indicators or []),
            runtime_score=0,
            combined_score=pre_execution_score,
            recommended_action="CONTINUE_MONITORING",
            parent_correlation_id=parent_correlation_id,
            created_monotonic=now,
            last_seen_monotonic=now,
        )
        self.states[pid] = state
        self._recalculate(state, reason="STATE_CREATED")
        return state

    def _archive(self, pid: int, reason: str) -> None:
        state = self.states.pop(pid, None)
        if state is None:
            return
        state.terminal_reason = reason
        self.archived.append(state.to_dict())

    def _action_for(self, state: ExecutionState) -> str:
        if state.status == "DENIED_PRE_EXECUTION":
            return "DENY"
        thresholds = self.policy.decision_thresholds
        if state.combined_score >= thresholds["quarantine_min"]:
            return "QUARANTINE"
        if state.combined_score >= thresholds["terminate_min"]:
            return "TERMINATE"
        if state.combined_score >= thresholds["alert_min"]:
            return "ALERT"
        return "CONTINUE_MONITORING"

    def _recalculate(self, state: ExecutionState, *, reason: str) -> None:
        state.runtime_score = min(
            self.policy.score_maximum,
            sum(item.weight for item in state.runtime_indicators),
        )
        state.combined_score = min(
            self.policy.score_maximum,
            state.pre_execution_score + state.runtime_score,
        )
        candidate = self._action_for(state)
        previous = state.recommended_action
        if _ACTION_RANK[candidate] < _ACTION_RANK[previous]:
            candidate = previous
        state.recommended_action = candidate
        if candidate != previous or not state.transitions:
            state.transitions.append(
                {
                    "from": previous,
                    "to": candidate,
                    "reason": reason,
                    "combined_score": state.combined_score,
                    "timestamp_monotonic": round(self._clock(), 6),
                }
            )

    def register_pre_execution(self, record: Mapping[str, Any]) -> dict[str, Any]:
        """Register one fanotify result, including late binding after eBPF exec."""
        with self._lock:
            return self._register_pre_execution(record)

    def _register_pre_execution(self, record: Mapping[str, Any]) -> dict[str, Any]:
        self.expire()
        pid = self._pid(record)
        if pid <= 0:
            return {"accepted": False, "reason": "MISSING_PROCESS_ID"}
        now = self._clock()
        current = self.states.get(pid)
        late_bind = (
            current is not None
            and current.source == "RUNTIME_ONLY"
            and current.status in {"ACTIVE", "PENDING_EXEC"}
            and now - current.created_monotonic
            <= self.policy.late_binding_window_seconds
        )
        score = self._score(record.get("score", record.get("risk_score", 0)))
        final_action = str(record.get("final_action", "ALLOW")).upper()
        requested = str(record.get("requested_decision", "UNKNOWN")).upper()
        indicators = record.get("indicators")
        safe_indicators = [dict(item) for item in indicators] if isinstance(indicators, list) else []
        path = record.get("path")
        executable_path = str(path) if isinstance(path, str) and path else None

        if late_bind and current is not None:
            state = current
            state.source = "FANOTIFY_LATE_BOUND"
            state.executable_path = executable_path or state.executable_path
            state.pre_execution_score = score
            state.pre_execution_decision = requested
            state.pre_execution_indicators = safe_indicators
            state.last_seen_monotonic = now
            if final_action == "DENY":
                state.status = "DENIED_PRE_EXECUTION"
            self._recalculate(state, reason="FANOTIFY_LATE_BINDING")
            return {"accepted": True, "late_bound": True, "state": state.to_dict()}

        if current is not None:
            self._archive(pid, "SUPERSEDED_BY_NEW_PRE_EXECUTION")
        status = "DENIED_PRE_EXECUTION" if final_action == "DENY" else "PENDING_EXEC"
        state = self._new_state(
            pid=pid,
            source="FANOTIFY",
            status=status,
            executable_path=executable_path,
            pre_execution_score=score,
            pre_execution_decision=requested,
            pre_execution_indicators=safe_indicators,
        )
        return {"accepted": True, "late_bound": False, "state": state.to_dict()}

    def _runtime_state(self, event: Mapping[str, Any]) -> ExecutionState | None:
        pid = self._pid(event)
        if pid <= 0:
            return None
        state = self.states.get(pid)
        if state is not None:
            return state
        ppid = int(event.get("ppid") or 0)
        parent = self.states.get(ppid)
        parent_id = None
        if parent is not None:
            age = self._clock() - parent.last_seen_monotonic
            if age <= self.policy.inheritance_window_seconds:
                parent_id = parent.correlation_id
        state = self._new_state(
            pid=pid,
            ppid=ppid,
            uid=int(event.get("uid") or 0),
            source="RUNTIME_ONLY",
            status="ACTIVE",
            parent_correlation_id=parent_id,
        )
        if parent_id is not None and str(event.get("event_type")) == "PROCESS_EXEC":
            self._apply_rule(
                state,
                "CHILD_PROCESS_EXEC",
                {"parent_pid": ppid, "parent_correlation_id": parent_id},
            )
        return state

    @staticmethod
    def _lexically_same(left: str | None, right: str | None) -> bool:
        if not left or not right:
            return True
        return os.path.normpath(left) == os.path.normpath(right)

    def _apply_rule(self, state: ExecutionState, rule_id: str, evidence: Any) -> bool:
        spec = self.policy.runtime_rules[rule_id]
        occurrence = state.rule_occurrences.get(rule_id, 0)
        if occurrence >= spec.max_occurrences:
            return False
        occurrence += 1
        state.rule_occurrences[rule_id] = occurrence
        state.runtime_indicators.append(
            RuntimeIndicator(
                rule=rule_id,
                weight=spec.weight,
                occurrence=occurrence,
                maximum_occurrences=spec.max_occurrences,
                evidence=evidence,
                description=spec.description,
            )
        )
        self._recalculate(state, reason=rule_id)
        return True

    def ingest_runtime_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """Ingest one decoded eBPF event and return the current state snapshot."""
        with self._lock:
            return self._ingest_runtime_event(event)

    def _ingest_runtime_event(self, event: Mapping[str, Any]) -> dict[str, Any]:
        self.expire()
        state = self._runtime_state(event)
        if state is None:
            return {"accepted": False, "reason": "MISSING_PROCESS_ID"}
        now = self._clock()
        state.last_seen_monotonic = now
        state.ppid = int(event.get("ppid") or state.ppid)
        state.uid = int(event.get("uid") or state.uid)
        kind = str(event.get("event_type", ""))

        if kind == "PROCESS_EXEC":
            timestamp = int(event.get("timestamp_ns") or 0)
            if state.exec_timestamp_ns is not None and timestamp > state.exec_timestamp_ns:
                # A second exec on the same PID starts a new generation unless a
                # fresh fanotify record has already replaced the state.
                self._archive(state.pid, "PID_EXEC_GENERATION_REPLACED")
                state = self._runtime_state(event)
                assert state is not None
            state.status = "ACTIVE"
            state.exec_timestamp_ns = timestamp or state.exec_timestamp_ns
            identifier = event.get("executable_identifier")
            state.executable_identifier = (
                str(identifier) if isinstance(identifier, str) and identifier else None
            )
            if not self._lexically_same(
                state.executable_path, state.executable_identifier
            ):
                self._apply_rule(
                    state,
                    "EXECUTABLE_IDENTIFIER_MISMATCH",
                    {
                        "fanotify_path": state.executable_path,
                        "ebpf_identifier": state.executable_identifier,
                    },
                )
        elif kind == "FILE_WRITE":
            key = event.get("distinct_file_key")
            if key is not None and str(key) not in state.distinct_files:
                state.distinct_files.add(str(key))
                self._apply_rule(
                    state,
                    "DISTINCT_FILE_WRITE",
                    {"distinct_file_key": str(key)},
                )
        elif kind == "FILE_RENAME":
            identifier = str(event.get("executable_identifier") or "UNKNOWN_IDENTIFIER")
            if identifier not in state.rename_identifiers:
                state.rename_identifiers.add(identifier)
                self._apply_rule(
                    state,
                    "FILE_RENAME",
                    {"identifier": identifier, "path_capability": "IDENTIFIER_ONLY"},
                )
        elif kind == "NETWORK_CONNECT":
            endpoint = (
                f"{event.get('destination_address') or 'unknown'}:"
                f"{event.get('destination_port') or 0}"
            )
            if endpoint not in state.outbound_connections:
                state.outbound_connections.add(endpoint)
                self._apply_rule(
                    state,
                    "OUTBOUND_CONNECTION",
                    {"endpoint": endpoint},
                )
        elif kind == "PROCESS_EXIT":
            state.status = "EXITED"
            state.exit_timestamp_ns = int(event.get("timestamp_ns") or 0) or None
            state.exited_monotonic = now
            state.terminal_reason = "PROCESS_EXIT_OBSERVED"

        self._recalculate(state, reason=f"EVENT_{kind or 'UNKNOWN'}")
        return {"accepted": True, "state": state.to_dict()}

    def expire(self, now: float | None = None) -> int:
        with self._lock:
            return self._expire(now)

    def _expire(self, now: float | None = None) -> int:
        current = self._clock() if now is None else now
        expired: list[tuple[int, str]] = []
        for pid, state in self.states.items():
            if state.status == "EXITED" and state.exited_monotonic is not None:
                if current - state.exited_monotonic > self.policy.exited_state_ttl_seconds:
                    expired.append((pid, "EXITED_STATE_TTL_EXPIRED"))
            elif current - state.last_seen_monotonic > self.policy.state_ttl_seconds:
                expired.append((pid, "ACTIVE_STATE_TTL_EXPIRED"))
        for pid, reason in expired:
            self._archive(pid, reason)
        return len(expired)


    def record_action_result(
        self,
        pid: int,
        correlation_id: str,
        result: Mapping[str, Any],
    ) -> bool:
        """Attach one Stage 11 action result to the exact PID generation."""

        with self._lock:
            state = self.states.get(int(pid))
            if state is None or state.correlation_id != str(correlation_id):
                return False
            safe = dict(result)
            state.last_action_result = safe
            state.action_execution_status = str(safe.get("status") or "UNKNOWN")
            state.last_seen_monotonic = self._clock()
            return True

    def get_state(self, pid: int) -> dict[str, Any] | None:
        with self._lock:
            state = self.states.get(int(pid))
            return state.to_dict() if state is not None else None

    def list_states(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            bounded = max(1, min(200, int(limit)))
            ordered = sorted(
                self.states.values(),
                key=lambda state: state.last_seen_monotonic,
                reverse=True,
            )
            return [state.to_dict() for state in ordered[:bounded]]

    def summary(self) -> dict[str, Any]:
        with self._lock:
            counts: dict[str, int] = {}
            actions: dict[str, int] = {}
            for state in self.states.values():
                counts[state.status] = counts.get(state.status, 0) + 1
                actions[state.recommended_action] = actions.get(state.recommended_action, 0) + 1
            return {
                "policy_name": self.policy.policy_name,
                "policy_status": self.policy.policy_status,
                "active_state_count": len(self.states),
                "archived_state_count": len(self.archived),
                "status_counts": counts,
                "recommended_action_counts": actions,
                "decision_thresholds": dict(self.policy.decision_thresholds),
                "combination_formula": "combined_score=min(100, pre_execution_score+runtime_score)",
                "actions_executed": any(
                    state.action_execution_status == "SUCCEEDED"
                    for state in self.states.values()
                ),
            }
