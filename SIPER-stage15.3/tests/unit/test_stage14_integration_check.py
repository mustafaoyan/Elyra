from __future__ import annotations

from pathlib import Path

from elliot.service.integration_check import (
    event_matches_fixture,
    event_process_id,
    gui_projection_fixture_status,
    journal_has_forbidden_error,
    state_matches_fixture,
)

ROOT = Path(__file__).resolve().parents[2]


def test_event_process_id_prefers_tgid() -> None:
    assert event_process_id({"pid": 12, "tgid": 34}) == 34


def test_event_process_id_rejects_invalid_values() -> None:
    assert event_process_id({"pid": True}) is None
    assert event_process_id({"pid": "not-a-pid"}) is None


def test_fanotify_fixture_match_requires_exact_path() -> None:
    event = {
        "source": "fanotify",
        "event_type": "PRE_EXECUTION_DECISION",
        "pid": 99,
        "path": "/tmp/safe",
    }
    assert event_matches_fixture(
        event,
        pid=99,
        executable_path="/tmp/safe",
        source="fanotify",
        event_type="PRE_EXECUTION_DECISION",
    )
    assert not event_matches_fixture(
        event,
        pid=99,
        executable_path="/tmp/other",
        source="fanotify",
        event_type="PRE_EXECUTION_DECISION",
    )


def test_ebpf_fixture_match_uses_process_and_type() -> None:
    event = {
        "source": "ebpf",
        "event_type": "PROCESS_EXEC",
        "pid": 77,
        "tgid": 77,
    }
    assert event_matches_fixture(
        event,
        pid=77,
        executable_path="/tmp/safe",
        source="ebpf",
        event_type="PROCESS_EXEC",
    )
    assert not event_matches_fixture(
        event,
        pid=77,
        executable_path="/tmp/safe",
        source="ebpf",
        event_type="PROCESS_EXIT",
    )


def test_state_match_accepts_exact_or_unavailable_path() -> None:
    assert state_matches_fixture(
        {"pid": 55, "executable_path": "/tmp/safe"},
        pid=55,
        executable_path="/tmp/safe",
    )
    assert state_matches_fixture(
        {"pid": 55, "executable_path": None},
        pid=55,
        executable_path="/tmp/safe",
    )
    assert not state_matches_fixture(
        {"pid": 56, "executable_path": "/tmp/safe"},
        pid=55,
        executable_path="/tmp/safe",
    )


def test_journal_error_detector_reports_forbidden_markers() -> None:
    failed, markers = journal_has_forbidden_error(
        "Traceback (most recent call last)\nTypeError: bad callback"
    )
    assert failed is True
    assert "Traceback (most recent call last)" in markers
    assert "TypeError:" in markers


def test_journal_error_detector_accepts_normal_monitor_logs() -> None:
    failed, markers = journal_has_forbidden_error(
        "INFO elliot.monitor.fanotify.controller: fanotify ALLOW: path=/tmp/safe"
    )
    assert failed is False
    assert markers == []


def test_stage14_checker_preserves_safe_production_defaults() -> None:
    source = (ROOT / "src/elliot/service/integration_check.py").read_text(encoding="utf-8")
    assert 'policy.get("mode") == "MONITOR_ONLY"' in source
    assert "--execute-responses" not in source
    assert "--enforce" not in source
    assert "/bin/sleep" in source
    assert "no malware" in source


def test_stage14_pyproject_exposes_installed_integration_check() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'elliot-integration-check = "elliot.service.integration_check:main"' in pyproject


def test_stage14_evidence_directory_is_documented() -> None:
    readme = (ROOT / "evidence/integration/README.md").read_text(encoding="utf-8")
    assert "Stage 14" in readme
    assert "no malware" in readme.lower()


def test_gui_projection_accepts_fixture_from_live_dashboard() -> None:
    ok, detail = gui_projection_fixture_status(
        {
            "connected": True,
            "status": {"fanotify_active": True, "ebpf_active": True},
            "policy": {"mode": "MONITOR_ONLY"},
            "events": [{"source": "ebpf", "event_type": "PROCESS_EXEC", "pid": 77}],
            "quarantine": [],
            "errors": [],
        },
        captured_events=[],
        pid=77,
    )
    assert ok is True
    assert detail["event_source"] == "LIVE_DASHBOARD"
    assert detail["live_dashboard_event_seen"] is True


def test_gui_projection_accepts_captured_official_event_after_buffer_eviction() -> None:
    ok, detail = gui_projection_fixture_status(
        {
            "connected": True,
            "status": {"fanotify_active": True, "ebpf_active": True},
            "policy": {"mode": "MONITOR_ONLY"},
            "events": [{"source": "fanotify", "pid": 999}],
            "quarantine": [],
            "errors": [],
        },
        captured_events=[
            {"source": "fanotify", "event_type": "PRE_EXECUTION_DECISION", "pid": 77},
            {"source": "ebpf", "event_type": "PROCESS_EXEC", "pid": 77, "tgid": 77},
        ],
        pid=77,
    )
    assert ok is True
    assert detail["event_source"] == "CAPTURED_OFFICIAL_GUI_API"
    assert detail["live_dashboard_event_seen"] is False
    assert detail["captured_official_event_seen"] is True


def test_gui_projection_rejects_event_api_failure() -> None:
    ok, detail = gui_projection_fixture_status(
        {
            "connected": True,
            "status": {},
            "policy": {"mode": "MONITOR_ONLY"},
            "events": [],
            "quarantine": [],
            "errors": [
                {"section": "events", "code": "IPC_UNAVAILABLE", "message": "failed"}
            ],
        },
        captured_events=[{"source": "ebpf", "event_type": "PROCESS_EXEC", "pid": 77}],
        pid=77,
    )
    assert ok is False
    assert detail["event_seen"] is True
    assert detail["errors"]
