"""Bounded user-space aggregation for runtime telemetry."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProcessTelemetryState:
    tgid: int
    executable_identifier: str | None = None
    parent_pid: int = 0
    uid: int = 0
    last_seen_monotonic: float = field(default_factory=time.monotonic)
    distinct_files: set[str] = field(default_factory=set)
    outbound_connections: int = 0
    event_count: int = 0


class RuntimeTelemetryAggregator:
    """Correlate events in user space without creating per-process threads."""

    def __init__(self, *, state_ttl_seconds: float = 300.0, max_states: int = 4096,
                 max_distinct_files_per_process: int = 2048) -> None:
        self.state_ttl_seconds = state_ttl_seconds
        self.max_states = max_states
        self.max_distinct_files_per_process = max_distinct_files_per_process
        self.states: dict[int, ProcessTelemetryState] = {}
        self.recent_events: deque[dict[str, Any]] = deque(maxlen=4096)

    def ingest(self, event: dict[str, Any]) -> dict[str, Any]:
        now = time.monotonic()
        self.expire(now)
        tgid = int(event.get("tgid") or event.get("pid") or 0)
        if tgid <= 0:
            return {"accepted": False, "reason": "MISSING_PROCESS_ID"}
        state = self.states.get(tgid)
        if state is None:
            if len(self.states) >= self.max_states:
                oldest = min(self.states, key=lambda key: self.states[key].last_seen_monotonic)
                self.states.pop(oldest, None)
            state = ProcessTelemetryState(tgid=tgid)
            self.states[tgid] = state
        state.last_seen_monotonic = now
        state.event_count += 1
        state.parent_pid = int(event.get("ppid") or state.parent_pid)
        state.uid = int(event.get("uid") or state.uid)
        if event.get("event_type") == "PROCESS_EXEC":
            state.executable_identifier = event.get("executable_identifier")
        file_key = event.get("distinct_file_key")
        if file_key and len(state.distinct_files) < self.max_distinct_files_per_process:
            state.distinct_files.add(str(file_key))
        if event.get("event_type") == "NETWORK_CONNECT":
            state.outbound_connections += 1
        summary = {
            "accepted": True,
            "tgid": tgid,
            "distinct_files_modified": len(state.distinct_files),
            "outbound_connection_attempts": state.outbound_connections,
            "event_count": state.event_count,
            "executable_identifier": state.executable_identifier,
        }
        enriched = {**event, "runtime_summary": summary}
        self.recent_events.append(enriched)
        if event.get("event_type") == "PROCESS_EXIT":
            self.states.pop(tgid, None)
        return summary

    def expire(self, now: float | None = None) -> int:
        current = time.monotonic() if now is None else now
        expired = [tgid for tgid, state in self.states.items()
                   if current - state.last_seen_monotonic > self.state_ttl_seconds]
        for tgid in expired:
            self.states.pop(tgid, None)
        return len(expired)
