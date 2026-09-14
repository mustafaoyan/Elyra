"""Pure presentation helpers for the unprivileged ELYRA GUI.

The helpers accept only daemon API results and return display-ready values. They
never invent telemetry, entropy values, scores, decisions, or actions.
"""

from __future__ import annotations

import json
import math
from datetime import datetime, timezone
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
    if isinstance(value, (int, float)) and math.isfinite(value):
        return float(value)
    return default


def _event_score(event: Mapping[str, Any]) -> float | None:
    """Read a real risk value from an event without manufacturing one.

    Runtime events have evolved across ELYRA releases.  The dashboard accepts
    the documented top-level fields as well as a correlation-state score, but
    returns ``None`` when an event has no score.  That distinction is important
    for a security dashboard: an absent score must never be displayed as a
    benign score of zero.
    """

    if event.get("assessment") == "INCONCLUSIVE":
        return None
    correlation = _mapping(event.get("correlation"))
    state = _mapping(correlation.get("state"))
    for candidate in (
        event.get("risk_score"),
        event.get("score"),
        state.get("combined_score"),
    ):
        if (
            isinstance(candidate, (int, float))
            and not isinstance(candidate, bool)
            and math.isfinite(candidate)
        ):
            return max(0.0, min(100.0, float(candidate)))
    return None


def _event_telemetry(events: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Produce display metrics from daemon events only.

    Values in this projection are intentionally derived from the received
    event list.  The GUI uses them for chart labels and never treats a lack of
    events as proof that endpoint monitoring is active or healthy.
    """

    sources: dict[str, int] = {}
    risk_bands = {"low": 0, "elevated": 0, "high": 0}
    scored_events = 0
    highest_score: float | None = None
    for event in events:
        source = str(event.get("source", "unknown"))[:48] or "unknown"
        sources[source] = sources.get(source, 0) + 1
        score = _event_score(event)
        if score is None:
            continue
        scored_events += 1
        highest_score = score if highest_score is None else max(highest_score, score)
        if score >= 70:
            risk_bands["high"] += 1
        elif score >= 40:
            risk_bands["elevated"] += 1
        else:
            risk_bands["low"] += 1
    return {
        "event_count": len(events),
        "scored_event_count": scored_events,
        "source_counts": sources,
        "risk_bands": risk_bands,
        "highest_score": highest_score,
        "high_risk_count": risk_bands["high"],
    }


def dashboard_projection(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Project a multi-call model snapshot into explicit GUI fields."""

    connected = bool(snapshot.get("connected"))
    status = _mapping(snapshot.get("status"))
    policy = _mapping(snapshot.get("policy"))
    events = [_mapping(item) for item in _sequence(snapshot.get("events"))]
    quarantine = [_mapping(item) for item in _sequence(snapshot.get("quarantine"))]
    errors = [_mapping(item) for item in _sequence(snapshot.get("errors"))]

    degraded = [str(item) for item in _sequence(status.get("degraded_components"))]
    platform_name = str(status.get("platform", "LINUX")).upper()
    component_states = (
        {"windows_monitor": bool(status.get("windows_monitor_active"))}
        if platform_name == "WINDOWS"
        else {
            "fanotify": bool(status.get("fanotify_active")),
            "ebpf": bool(status.get("ebpf_active")),
        }
    )
    if not connected:
        service_state = "DISCONNECTED"
    elif degraded:
        service_state = "DEGRADED"
    else:
        service_state = "CONNECTED"

    return {
        "connected": connected,
        "platform": platform_name,
        "monitor_kind": str(status.get("monitor_kind", "fanotify + eBPF")),
        "service_state": service_state,
        "api_version": status.get("api_version"),
        "component_states": component_states,
        "degraded_components": degraded,
        "policy_mode": str(policy.get("mode", "UNKNOWN")),
        "events": events,
        "quarantine": quarantine,
        "errors": errors,
        "telemetry": _event_telemetry(events),
    }


def scan_projection(result: Mapping[str, Any]) -> dict[str, Any]:
    """Extract only real analyser/scoring values from a ``scan_file`` response."""

    scan = _mapping(result)
    scoring = _mapping(scan.get("pre_execution_scoring"))
    ai_analysis = _mapping(scan.get("ai_analysis") or scoring.get("ai_analysis"))
    entropy_summary = _mapping(scan.get("entropy_summary"))
    block_rows = [_mapping(item) for item in _sequence(scan.get("block_entropies"))]
    indicators = [_mapping(item) for item in _sequence(scoring.get("indicators"))]
    pe_summary = _mapping(scan.get("pe_summary"))
    assessment = str(scan.get("assessment", "NOT_REPORTED"))
    incomplete = (
        assessment == "INCONCLUSIVE"
        or scan.get("status") in {"ERROR", "PARTIAL"}
        or scoring.get("scoring_status") in {"DEGRADED", "INCOMPLETE", "ERROR", "UNAVAILABLE"}
        or pe_summary.get("status") in {"INCOMPLETE", "UNSUPPORTED", "ERROR"}
    )
    score = None if incomplete else _event_score({"score": scoring.get("score")})
    if incomplete:
        assessment = "INCONCLUSIVE"

    block_entropies: list[float] = []
    block_indices: list[int] = []
    for position, row in enumerate(block_rows):
        entropy = row.get("entropy")
        if (
            isinstance(entropy, (int, float))
            and not isinstance(entropy, bool)
            and math.isfinite(entropy)
        ):
            block_entropies.append(float(entropy))
            index = row.get("index", position)
            block_indices.append(int(index) if isinstance(index, int) else position)

    runtime_score = scan.get("runtime_score")
    if (
        not isinstance(runtime_score, (int, float))
        or isinstance(runtime_score, bool)
        or not math.isfinite(runtime_score)
    ):
        runtime_score = None

    return {
        "filepath": str(scan.get("filepath", "")),
        "status": str(scan.get("status", "UNKNOWN")),
        "mime_type": str(scan.get("mime_type", "unknown")),
        "mime_extension_consistency": str(
            scan.get("mime_extension_consistency", "UNKNOWN")
        ),
        "is_elf": bool(scan.get("is_elf")),
        "is_pe": bool(scan.get("is_pe")),
        "pe_summary": pe_summary,
        "pe_anomalies": [str(item) for item in _sequence(scan.get("pe_anomalies"))],
        "assessment": assessment,
        "enforced_action": str(scan.get("enforced_action", "NOT_REPORTED")),
        "score_kind": str(scan.get("score_kind", "PROVISIONAL_HEURISTIC_NOT_PROBABILITY")),
        "limitations": [str(item) for item in _sequence(scan.get("limitations"))],
        "reasons": [str(item) for item in _sequence(scan.get("reasons"))],
        "whole_file_entropy": entropy_summary.get("whole_file_entropy"),
        "block_indices": block_indices,
        "block_entropies": block_entropies,
        "blocks_truncated": bool(entropy_summary.get("blocks_truncated")),
        "pre_execution_score": None if score is None else int(score),
        "runtime_score": runtime_score,
        "decision": str(scan.get("recommended_decision", scoring.get("decision", "UNKNOWN"))),
        "ai_analysis": ai_analysis,
        "indicators": indicators,
        "warnings": [_mapping(item) for item in _sequence(scan.get("warnings"))],
        "errors": [_mapping(item) for item in _sequence(scan.get("errors"))],
        "duration_ms": _number(scan.get("duration_ms"), 0.0),
    }


def _event_timestamp(event: Mapping[str, Any]) -> str:
    for key in ("timestamp_utc", "timestamp"):
        value = event.get(key)
        if value is not None and value != "":
            return str(value)
    nanoseconds = event.get("timestamp_ns")
    if isinstance(nanoseconds, int) and not isinstance(nanoseconds, bool) and nanoseconds >= 0:
        try:
            seconds, remainder = divmod(nanoseconds, 1_000_000_000)
            return datetime.fromtimestamp(seconds, timezone.utc).replace(
                microsecond=remainder // 1000
            ).isoformat().replace("+00:00", "Z")
        except (ValueError, OverflowError, OSError):
            pass
    return "unknown-time"


def format_event(event: Mapping[str, Any]) -> str:
    """Return a stable, bounded text representation of a daemon event."""

    source = str(event.get("source", "unknown"))
    timestamp = _event_timestamp(event)
    path = event.get("filepath", event.get("path", event.get("target_file", "")))
    correlation = _mapping(event.get("correlation"))
    correlation_state = _mapping(correlation.get("state"))
    decision = event.get("recommended_decision", event.get("decision", correlation_state.get("recommended_action", "")))
    score = _event_score(event)
    parts = [f"[{timestamp}] source={source}"]
    if path:
        parts.append(f"path={path}")
    if score is not None:
        parts.append(f"score={score:g}")
    elif "risk_score" in event or "score" in event:
        parts.append("score=N/A")
    if decision:
        label = "recommendation" if "recommended_decision" in event else "decision"
        parts.append(f"{label}={decision}")
    if event.get("assessment"):
        parts.append(f"assessment={event['assessment']}")
    if event.get("enforced_action"):
        parts.append(f"enforced_action={event['enforced_action']}")
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
