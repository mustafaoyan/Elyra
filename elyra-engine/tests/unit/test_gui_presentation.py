from __future__ import annotations

import pytest

from elyra.gui.presentation import (
    dashboard_projection,
    format_event,
    format_indicator,
    quarantine_label,
    scan_projection,
)


def test_dashboard_projection_reports_disconnected() -> None:
    projected = dashboard_projection({"connected": False, "errors": []})
    assert projected["service_state"] == "DISCONNECTED"
    assert projected["component_states"] == {"fanotify": False, "ebpf": False}


def test_dashboard_projection_reports_degraded_components() -> None:
    projected = dashboard_projection(
        {
            "connected": True,
            "status": {
                "fanotify_active": True,
                "ebpf_active": False,
                "degraded_components": ["ebpf"],
            },
            "policy": {"mode": "MONITOR_ONLY"},
            "events": [],
            "quarantine": [],
            "errors": [],
        }
    )
    assert projected["service_state"] == "DEGRADED"
    assert projected["component_states"]["fanotify"] is True
    assert projected["policy_mode"] == "MONITOR_ONLY"


def test_dashboard_projection_keeps_windows_monitor_distinct_from_ebpf() -> None:
    projected = dashboard_projection(
        {
            "connected": True,
            "status": {
                "platform": "WINDOWS",
                "monitor_kind": "ReadDirectoryChangesW",
                "fanotify_active": False,
                "ebpf_active": False,
                "windows_monitor_active": True,
            },
            "policy": {"mode": "MONITOR_ONLY"},
            "events": [],
            "quarantine": [],
            "errors": [],
        }
    )
    assert projected["component_states"] == {"windows_monitor": True}
    assert projected["monitor_kind"] == "ReadDirectoryChangesW"


def test_scan_projection_uses_exact_block_values() -> None:
    projected = scan_projection(
        {
            "filepath": "/tmp/safe.bin",
            "status": "OK",
            "entropy_summary": {"whole_file_entropy": 7.125, "blocks_truncated": False},
            "block_entropies": [
                {"index": 2, "entropy": 1.25},
                {"index": 3, "entropy": 7.75},
            ],
            "pre_execution_scoring": {
                "score": 26,
                "decision": "ALLOW_MONITOR",
                "indicators": [],
            },
        }
    )
    assert projected["block_indices"] == [2, 3]
    assert projected["block_entropies"] == [1.25, 7.75]
    assert projected["whole_file_entropy"] == 7.125
    assert projected["pre_execution_score"] == 26


def test_scan_projection_does_not_invent_runtime_score() -> None:
    projected = scan_projection({"pre_execution_scoring": {"score": 0, "decision": "ALLOW"}})
    assert projected["runtime_score"] is None


def test_format_event_uses_real_fields() -> None:
    line = format_event(
        {
            "source": "fanotify",
            "timestamp_utc": "2026-07-28T10:00:00Z",
            "path": "/tmp/a",
            "score": 20,
            "decision": "ALLOW_MONITOR",
        }
    )
    assert "source=fanotify" in line
    assert "path=/tmp/a" in line
    assert "score=20" in line


def test_quarantine_label_is_stable() -> None:
    label = quarantine_label(
        {
            "quarantine_id": "123",
            "original_path": "/home/user/sample.bin",
            "restoration_status": "quarantined",
        }
    )
    assert label == "123 | sample.bin | quarantined"


def test_format_indicator_preserves_evidence() -> None:
    line = format_indicator(
        {"rule": "HIGH_ENTROPY", "category": "entropy", "weight": 10, "evidence": 0.9}
    )
    assert "HIGH_ENTROPY" in line
    assert "+10" in line
    assert "0.9" in line


@pytest.mark.parametrize("result", [
    {},
    {"pre_execution_scoring": {"score": None}},
    {"pre_execution_scoring": {"score": True}},
    {"pre_execution_scoring": {"score": float("nan")}},
    {"pre_execution_scoring": {"score": float("inf")}},
    {"status": "ERROR", "pre_execution_scoring": {"score": 0}},
    {"status": "PARTIAL", "pre_execution_scoring": {"score": 26}},
    {"pre_execution_scoring": {"score": 0, "scoring_status": "DEGRADED"}},
    {"pre_execution_scoring": {"score": 0, "scoring_status": "INCOMPLETE"}},
    {"assessment": "INCONCLUSIVE", "pre_execution_scoring": {"score": 0}},
    {"pe_summary": {"status": "INCOMPLETE"}, "pre_execution_scoring": {"score": 0}},
    {"pe_summary": {"status": "UNSUPPORTED"}, "pre_execution_scoring": {"score": 0}},
])
def test_unavailable_scan_score_is_not_shown_as_measured_zero(result) -> None:
    assert scan_projection(result)["pre_execution_score"] is None


def test_complete_pe_evidence_keeps_trust_and_enforcement_distinct() -> None:
    pe = {"status": "COMPLETE", "scope": "headers_and_sections", "format": "PE32+",
          "architecture": "x64", "certificate_table_present": True,
          "signature_verification": "NOT_PERFORMED"}
    projected = scan_projection({
        "status": "OK", "is_pe": True, "pe_summary": pe,
        "pe_anomalies": ["PE_WRITABLE_EXECUTABLE_SECTION:0"],
        "assessment": "SUSPICIOUS", "recommended_decision": "WARN",
        "enforced_action": "NONE", "pre_execution_scoring": {"score": 50},
        "limitations": ["AUTHENTICODE_NOT_VERIFIED"],
    })
    assert projected["pre_execution_score"] == 50
    assert projected["pe_summary"] == pe
    assert projected["pe_anomalies"] == ["PE_WRITABLE_EXECUTABLE_SECTION:0"]
    assert projected["decision"] == "WARN"
    assert projected["enforced_action"] == "NONE"
    assert projected["score_kind"] == "PROVISIONAL_HEURISTIC_NOT_PROBABILITY"
    assert projected["limitations"] == ["AUTHENTICODE_NOT_VERIFIED"]


def test_incomplete_pe_overrides_legacy_low_risk_assessment() -> None:
    projected = scan_projection({"status": "OK", "assessment": "NO_HIGH_RISK_INDICATORS",
                                 "pe_summary": {"status": "INCOMPLETE"},
                                 "pre_execution_scoring": {"score": 0}})
    assert projected["assessment"] == "INCONCLUSIVE"
    assert projected["pre_execution_score"] is None


def test_dashboard_does_not_count_inconclusive_or_nonfinite_scores_as_low_risk() -> None:
    projected = dashboard_projection({"events": [
        {"source": "windows-monitor", "assessment": "INCONCLUSIVE", "score": 0},
        {"source": "windows-monitor", "risk_score": None},
        {"source": "windows-monitor", "risk_score": float("nan")},
        {"source": "windows-monitor", "risk_score": 0},
    ]})
    assert projected["telemetry"]["event_count"] == 4
    assert projected["telemetry"]["scored_event_count"] == 1
    assert projected["telemetry"]["risk_bands"] == {"low": 1, "elevated": 0, "high": 0}


def test_windows_event_displays_observed_time_recommendation_and_no_enforcement() -> None:
    line = format_event({"source": "windows-monitor", "timestamp_ns": 1_500_000_000,
                         "assessment": "INCONCLUSIVE", "risk_score": None,
                         "recommended_decision": "INCONCLUSIVE", "enforced_action": "NONE"})
    assert "1970-01-01T00:00:01.500000Z" in line
    assert "score=N/A" in line
    assert "recommendation=INCONCLUSIVE" in line
    assert "enforced_action=NONE" in line


@pytest.mark.parametrize("timestamp", [-1, 10 ** 100, None, True])
def test_invalid_event_time_is_unknown_not_current_time(timestamp) -> None:
    assert "[unknown-time]" in format_event({"timestamp_ns": timestamp})
