"""Pure presentation helpers for the unprivileged ELLIOT GUI.

The helpers accept only daemon API results and return display-ready values. They
never invent telemetry, entropy values, scores, decisions, or actions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


def _sequence(value: Any) -> list[Any]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return list(value)
    return []


def _number(value: Any, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    return default


def dashboard_projection(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Project a multi-call model snapshot into explicit GUI fields."""

    connected = bool(snapshot.get("connected"))
    status = _mapping(snapshot.get("status"))
    policy = _mapping(snapshot.get("policy"))
    events = [_mapping(item) for item in _sequence(snapshot.get("events"))]
    quarantine = [_mapping(item) for item in _sequence(snapshot.get("quarantine"))]
    errors = [_mapping(item) for item in _sequence(snapshot.get("errors"))]

    degraded = [str(item) for item in _sequence(status.get("degraded_components"))]
    component_states = {
        "fanotify": bool(status.get("fanotify_active")),
        "ebpf": bool(status.get("ebpf_active")),
    }
    if not connected:
        service_state = "DISCONNECTED"
    elif degraded:
        service_state = "DEGRADED"
    else:
        service_state = "CONNECTED"

    return {
        "connected": connected,
        "service_state": service_state,
        "api_version": status.get("api_version"),
        "component_states": component_states,
        "degraded_components": degraded,
        "policy_mode": str(policy.get("mode", "UNKNOWN")),
        "events": events,
        "quarantine": quarantine,
        "errors": errors,
    }


def scan_projection(result: Mapping[str, Any]) -> dict[str, Any]:
    """Extract only real analyser/scoring values from a ``scan_file`` response."""

    scan = _mapping(result)
    scoring = _mapping(scan.get("pre_execution_scoring"))
    entropy_summary = _mapping(scan.get("entropy_summary"))
    block_rows = [_mapping(item) for item in _sequence(scan.get("block_entropies"))]
    indicators = [_mapping(item) for item in _sequence(scoring.get("indicators"))]

    block_entropies: list[float] = []
    block_indices: list[int] = []
    for position, row in enumerate(block_rows):
        entropy = row.get("entropy")
        if isinstance(entropy, (int, float)) and not isinstance(entropy, bool):
            block_entropies.append(float(entropy))
            index = row.get("index", position)
            block_indices.append(int(index) if isinstance(index, int) else position)

    runtime_score = scan.get("runtime_score")
    if not isinstance(runtime_score, (int, float)) or isinstance(runtime_score, bool):
        runtime_score = None

    return {
        "filepath": str(scan.get("filepath", "")),
        "status": str(scan.get("status", "UNKNOWN")),
        "mime_type": str(scan.get("mime_type", "unknown")),
        "mime_extension_consistency": str(
            scan.get("mime_extension_consistency", "UNKNOWN")
        ),
        "is_elf": bool(scan.get("is_elf")),
        "whole_file_entropy": entropy_summary.get("whole_file_entropy"),
        "block_indices": block_indices,
        "block_entropies": block_entropies,
        "blocks_truncated": bool(entropy_summary.get("blocks_truncated")),
        "pre_execution_score": int(_number(scoring.get("score"), 0.0)),
        "runtime_score": runtime_score,
        "decision": str(scoring.get("decision", "UNKNOWN")),
        "indicators": indicators,
        "warnings": [_mapping(item) for item in _sequence(scan.get("warnings"))],
        "errors": [_mapping(item) for item in _sequence(scan.get("errors"))],
        "duration_ms": _number(scan.get("duration_ms"), 0.0),
    }


def format_event(event: Mapping[str, Any]) -> str:
    """Return a stable, bounded text representation of a daemon event."""

    source = str(event.get("source", "unknown"))
    timestamp = str(event.get("timestamp_utc", event.get("timestamp", "unknown-time")))
    path = event.get("filepath", event.get("path", event.get("target_file", "")))
    correlation = _mapping(event.get("correlation"))
    correlation_state = _mapping(correlation.get("state"))
    decision = event.get("decision", correlation_state.get("recommended_action", ""))
    score = event.get("risk_score", event.get("score", correlation_state.get("combined_score", "")))
    parts = [f"[{timestamp}] source={source}"]
    if path:
        parts.append(f"path={path}")
    if score != "":
        parts.append(f"score={score}")
    if decision:
        parts.append(f"decision={decision}")
    if len(parts) == 1:
        compact = json.dumps(dict(event), ensure_ascii=False, sort_keys=True)
        parts.append(compact[:1000])
    return " | ".join(parts)


def quarantine_label(item: Mapping[str, Any]) -> str:
    quarantine_id = str(item.get("quarantine_id", "unknown"))
    original_path = str(item.get("original_path", "unknown-path"))
    status = str(item.get("restoration_status", "unknown"))
    return f"{quarantine_id} | {Path(original_path).name} | {status}"


def format_indicator(indicator: Mapping[str, Any]) -> str:
    rule = str(indicator.get("rule", "UNKNOWN_RULE"))
    weight = indicator.get("weight", 0)
    category = str(indicator.get("category", "unknown"))
    evidence = indicator.get("evidence")
    return f"{rule} [{category}] +{weight}: {evidence!r}"
