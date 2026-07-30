from __future__ import annotations

from elliot.gui.presentation import (
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
