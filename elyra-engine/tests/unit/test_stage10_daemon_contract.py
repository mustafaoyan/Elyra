from __future__ import annotations

from pathlib import Path

from elyra.service.ipc_protocol import build_request


def test_runtime_state_ipc_action_is_versioned_and_bounded() -> None:
    request = build_request("list_runtime_states", {"limit": 25})
    assert request["action"] == "list_runtime_states"
    assert request["params"] == {"limit": 25}


def test_daemon_routes_both_fanotify_and_ebpf_into_correlation() -> None:
    source = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "elyra"
        / "service"
        / "daemon.py"
    ).read_text(encoding="utf-8")
    assert "register_pre_execution(event)" in source
    assert "ingest_runtime_event(event)" in source
    assert "NOT_EXECUTED_STAGE11" in source
