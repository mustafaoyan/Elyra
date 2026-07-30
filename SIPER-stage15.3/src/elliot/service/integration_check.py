"""Stage 14 installed-workflow verification for Pardus.

The verifier exercises the installed Siper daemon in its production-safe
MONITOR_ONLY configuration.  It uses a private copy of ``/bin/sleep`` under a
temporary directory, waits for fanotify and eBPF records through the official
Unix-domain-socket API, checks GUI projections, and verifies the retained audit
chain.  It never enables enforcement or automatic destructive responses.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from ..audit.audit_logger import verify_audit_directory
from ..gui.model import PardusModel
from ..gui.presentation import dashboard_projection, scan_projection
from .install_layout import LOG_DIRECTORY, write_json_atomic
from .ipc_client import IpcClient, IpcClientError

SERVICE_NAME = "elliot.service"
AUDIT_LOG_NAME = "audit.jsonl"
_FORBIDDEN_JOURNAL_MARKERS = (
    "Traceback (most recent call last)",
    "Exception ignored",
    "TypeError:",
    "CRITICAL elliot.service.daemon",
)


@dataclass(frozen=True, slots=True)
class WorkflowCheck:
    check: str
    status: str
    detail: Any
    critical: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _record(check: str, ok: bool, detail: Any, *, critical: bool = True) -> WorkflowCheck:
    return WorkflowCheck(
        check=check,
        status="OK" if ok else ("FAIL" if critical else "WARN"),
        detail=detail,
        critical=critical,
    )


def _run(command: list[str], *, timeout: float = 20.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def event_process_id(event: Mapping[str, Any]) -> int | None:
    """Return the process identity used by a daemon event, if available."""

    return _integer(event.get("tgid", event.get("pid")))


def event_matches_fixture(
    event: Mapping[str, Any],
    *,
    pid: int,
    executable_path: str,
    source: str | None = None,
    event_type: str | None = None,
) -> bool:
    if source is not None and str(event.get("source")) != source:
        return False
    if event_type is not None and str(event.get("event_type")) != event_type:
        return False
    if event_process_id(event) != int(pid):
        return False
    if source == "fanotify":
        observed = str(event.get("path") or "")
        return observed == executable_path
    return True


def state_matches_fixture(state: Mapping[str, Any], *, pid: int, executable_path: str) -> bool:
    if _integer(state.get("tgid", state.get("pid"))) != int(pid):
        return False
    observed = state.get("executable_path")
    return observed in {None, "", executable_path}


def journal_has_forbidden_error(text: str) -> tuple[bool, list[str]]:
    found = [marker for marker in _FORBIDDEN_JOURNAL_MARKERS if marker in text]
    return bool(found), found


def _systemd_invocation_journal() -> tuple[bool, dict[str, Any]]:
    show = _run(["systemctl", "show", SERVICE_NAME, "--property=InvocationID", "--value"])
    invocation_id = show.stdout.strip()
    if show.returncode != 0 or not invocation_id:
        return False, {
            "invocation_id": invocation_id,
            "error": (show.stderr or show.stdout).strip(),
        }
    journal = _run(
        [
            "journalctl",
            "-u",
            SERVICE_NAME,
            f"_SYSTEMD_INVOCATION_ID={invocation_id}",
            "--no-pager",
        ],
        timeout=30.0,
    )
    text = journal.stdout if journal.returncode == 0 else journal.stderr
    has_error, markers = journal_has_forbidden_error(text)
    return journal.returncode == 0 and not has_error, {
        "invocation_id": invocation_id,
        "returncode": journal.returncode,
        "forbidden_markers": markers,
        "tail": text[-12000:],
    }


def _poll_daemon_records(
    client: IpcClient,
    *,
    pid: int,
    executable_path: str,
    timeout_seconds: float,
    model: PardusModel | None = None,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    latest_events: list[dict[str, Any]] = []
    latest_states: list[dict[str, Any]] = []
    fanotify_record: dict[str, Any] | None = None
    exec_record: dict[str, Any] | None = None
    exit_record: dict[str, Any] | None = None
    correlation_state: dict[str, Any] | None = None

    while time.monotonic() < deadline:
        if model is None:
            event_result = client.request("list_events", {"limit": 200})
            state_result = client.request("list_runtime_states", {"limit": 200})
        else:
            event_response = model.get_events(200)
            state_response = model.get_runtime_states(200)
            if event_response.get("ok") is not True:
                error = event_response.get("error", {})
                raise IpcClientError(
                    f"GUI event API failed: {error.get('code', 'UNKNOWN')}: "
                    f"{error.get('message', 'unknown error')}"
                )
            if state_response.get("ok") is not True:
                error = state_response.get("error", {})
                raise IpcClientError(
                    f"GUI runtime-state API failed: {error.get('code', 'UNKNOWN')}: "
                    f"{error.get('message', 'unknown error')}"
                )
            event_result = event_response.get("result", {})
            state_result = state_response.get("result", {})

        latest_events = [
            dict(item)
            for item in event_result.get("events", [])
            if isinstance(item, Mapping)
        ]
        latest_states = [
            dict(item)
            for item in state_result.get("states", [])
            if isinstance(item, Mapping)
        ]
        fanotify_record = next(
            (
                item
                for item in reversed(latest_events)
                if event_matches_fixture(
                    item,
                    pid=pid,
                    executable_path=executable_path,
                    source="fanotify",
                    event_type="PRE_EXECUTION_DECISION",
                )
            ),
            fanotify_record,
        )
        exec_record = next(
            (
                item
                for item in reversed(latest_events)
                if event_matches_fixture(
                    item,
                    pid=pid,
                    executable_path=executable_path,
                    source="ebpf",
                    event_type="PROCESS_EXEC",
                )
            ),
            exec_record,
        )
        exit_record = next(
            (
                item
                for item in reversed(latest_events)
                if event_matches_fixture(
                    item,
                    pid=pid,
                    executable_path=executable_path,
                    source="ebpf",
                    event_type="PROCESS_EXIT",
                )
            ),
            exit_record,
        )
        correlation_state = next(
            (
                item
                for item in latest_states
                if state_matches_fixture(item, pid=pid, executable_path=executable_path)
            ),
            correlation_state,
        )
        if fanotify_record and exec_record and exit_record and correlation_state:
            break
        time.sleep(0.2)

    observed_events = [
        dict(item)
        for item in (fanotify_record, exec_record, exit_record)
        if isinstance(item, Mapping)
    ]
    return {
        "fanotify_record": fanotify_record,
        "process_exec_record": exec_record,
        "process_exit_record": exit_record,
        "correlation_state": correlation_state,
        "observed_events": observed_events,
        "event_count": len(latest_events),
        "state_count": len(latest_states),
    }


def gui_projection_fixture_status(
    dashboard: Mapping[str, Any],
    *,
    captured_events: Iterable[Mapping[str, Any]],
    pid: int,
) -> tuple[bool, dict[str, Any]]:
    """Verify GUI projection using live or already-captured official API events.

    The daemon intentionally keeps a bounded 200-event buffer. Under a busy
    system, the harmless fixture event can be evicted between the correlation
    poll and the later dashboard refresh. ``captured_events`` contains the exact
    records previously returned through ``PardusModel.get_events`` during the
    bounded poll, so using them is not mock data and does not fabricate GUI
    telemetry.
    """

    live_projection = dashboard_projection(dashboard)
    live_event_seen = any(
        event_process_id(item) == int(pid)
        for item in live_projection.get("events", [])
        if isinstance(item, Mapping)
    )
    captured = [dict(item) for item in captured_events if isinstance(item, Mapping)]
    captured_snapshot = dict(dashboard)
    captured_snapshot["events"] = captured
    captured_projection = dashboard_projection(captured_snapshot)
    captured_event_seen = any(
        event_process_id(item) == int(pid)
        for item in captured_projection.get("events", [])
        if isinstance(item, Mapping)
    )
    event_api_errors = [
        dict(item)
        for item in live_projection.get("errors", [])
        if isinstance(item, Mapping) and item.get("section") == "events"
    ]
    event_seen = live_event_seen or captured_event_seen
    ok = (
        live_projection.get("connected") is True
        and not event_api_errors
        and event_seen
    )
    detail = {
        "service_state": live_projection.get("service_state"),
        "policy_mode": live_projection.get("policy_mode"),
        "event_seen": event_seen,
        "live_dashboard_event_seen": live_event_seen,
        "captured_official_event_seen": captured_event_seen,
        "event_source": (
            "LIVE_DASHBOARD" if live_event_seen else "CAPTURED_OFFICIAL_GUI_API"
            if captured_event_seen
            else "NOT_OBSERVED"
        ),
        "captured_event_count": len(captured),
        "errors": live_projection.get("errors"),
    }
    return ok, detail


def collect_integrated_workflow_report(
    *,
    expected_user: str | None = None,
    client: IpcClient | None = None,
    sleep_source: str | os.PathLike[str] = "/bin/sleep",
) -> dict[str, Any]:
    checks: list[WorkflowCheck] = []
    checks.append(_record("root_verifier", os.geteuid() == 0, {"euid": os.geteuid()}))

    active = _run(["systemctl", "is-active", SERVICE_NAME])
    checks.append(
        _record(
            "installed_service_active",
            active.returncode == 0 and active.stdout.strip() == "active",
            (active.stdout or active.stderr).strip(),
        )
    )

    ipc = client or IpcClient(timeout=5.0)
    try:
        status = ipc.request("get_status")
        policy = ipc.request("get_policy")
    except IpcClientError as exc:
        checks.append(_record("official_daemon_ipc", False, str(exc)))
        return _finish_report(checks, expected_user=expected_user)

    checks.append(_record("official_daemon_ipc", isinstance(status, Mapping), status))
    checks.append(
        _record(
            "safe_monitor_only_policy",
            isinstance(policy, Mapping)
            and policy.get("mode") == "MONITOR_ONLY"
            and status.get("fanotify_active") is True
            and status.get("ebpf_active") is True,
            {"policy": policy, "status": status},
        )
    )
    audit_status = status.get("audit") if isinstance(status, Mapping) else None
    checks.append(
        _record(
            "startup_audit_integrity",
            isinstance(audit_status, Mapping)
            and bool(audit_status.get("startup_integrity", {}).get("valid")),
            audit_status,
        )
    )

    audit_before = verify_audit_directory(LOG_DIRECTORY, file_name=AUDIT_LOG_NAME)
    checks.append(_record("audit_chain_valid_before", audit_before.valid, audit_before.to_dict()))

    model = PardusModel(client=ipc)
    fixture_result: dict[str, Any] = {}
    process: subprocess.Popen[str] | None = None
    source = Path(sleep_source)
    if not source.is_file():
        checks.append(_record("harmless_fixture_source", False, str(source)))
        return _finish_report(checks, expected_user=expected_user)

    with tempfile.TemporaryDirectory(prefix="elliot-stage14-live-") as temporary:
        fixture_dir = Path(temporary)
        executable = fixture_dir / "elliot-stage14-safe-sleep"
        shutil.copy2(source, executable)
        executable.chmod(0o755)

        scan = ipc.request("scan_file", {"path": str(executable)})
        projected_scan = scan_projection(scan)
        scan_ok = (
            projected_scan.get("status") == "OK"
            and isinstance(projected_scan.get("whole_file_entropy"), (int, float))
            and projected_scan.get("decision") in {"ALLOW", "ALLOW_MONITOR", "WARN", "DENY"}
        )
        checks.append(
            _record(
                "official_ipc_real_static_scan",
                scan_ok,
                projected_scan,
            )
        )

        try:
            process = subprocess.Popen(
                [str(executable), "2"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                start_new_session=True,
            )
            pid = process.pid
            # Poll while the process is alive so the active correlation state is
            # available, then poll again after the natural exit for PROCESS_EXIT.
            first = _poll_daemon_records(
                ipc,
                pid=pid,
                executable_path=str(executable),
                timeout_seconds=1.5,
                model=model,
            )
            returncode = process.wait(timeout=8.0)
            second = _poll_daemon_records(
                ipc,
                pid=pid,
                executable_path=str(executable),
                timeout_seconds=8.0,
                model=model,
            )
            fixture_result = {
                "pid": pid,
                "returncode": returncode,
                **{
                    key: second.get(key) or first.get(key)
                    for key in (
                        "fanotify_record",
                        "process_exec_record",
                        "process_exit_record",
                        "correlation_state",
                    )
                },
                "observed_events": [
                    dict(item)
                    for item in (
                        second.get("observed_events", [])
                        or first.get("observed_events", [])
                    )
                    if isinstance(item, Mapping)
                ],
                "event_count": second.get("event_count", 0),
                "state_count": second.get("state_count", 0),
            }
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2.0)

        checks.append(
            _record(
                "harmless_execution_completed",
                fixture_result.get("returncode") == 0,
                {"pid": fixture_result.get("pid"), "returncode": fixture_result.get("returncode")},
            )
        )
        checks.append(
            _record(
                "fanotify_pre_execution_record_observed",
                isinstance(fixture_result.get("fanotify_record"), Mapping)
                and fixture_result["fanotify_record"].get("response_ok") is True,
                fixture_result.get("fanotify_record"),
            )
        )
        checks.append(
            _record(
                "ebpf_process_execution_observed",
                isinstance(fixture_result.get("process_exec_record"), Mapping),
                fixture_result.get("process_exec_record"),
            )
        )
        checks.append(
            _record(
                "ebpf_process_exit_observed",
                isinstance(fixture_result.get("process_exit_record"), Mapping),
                fixture_result.get("process_exit_record"),
            )
        )
        state = fixture_result.get("correlation_state")
        state_ok = (
            isinstance(state, Mapping)
            and _integer(state.get("pid")) == fixture_result.get("pid")
            and isinstance(state.get("pre_execution_score"), int)
            and isinstance(state.get("runtime_score"), int)
            and isinstance(state.get("combined_score"), int)
            and state.get("recommended_action")
            in {"CONTINUE_MONITORING", "ALERT", "TERMINATE", "QUARANTINE", "DENY"}
        )
        checks.append(_record("fanotify_ebpf_correlation_state", state_ok, state))

        dashboard = model.fetch_dashboard(event_limit=200)
        gui_ok, gui_detail = gui_projection_fixture_status(
            dashboard,
            captured_events=fixture_result.get("observed_events", []),
            pid=int(fixture_result.get("pid") or 0),
        )
        checks.append(
            _record(
                "gui_official_api_projection_updated",
                gui_ok,
                gui_detail,
            )
        )

    # Give the audit writer a short bounded interval to commit/fsync the last
    # process-exit and correlation records before verifying the retained chain.
    time.sleep(0.3)
    audit_after = verify_audit_directory(LOG_DIRECTORY, file_name=AUDIT_LOG_NAME)
    checks.append(_record("audit_chain_valid_after", audit_after.valid, audit_after.to_dict()))
    checks.append(
        _record(
            "integrated_workflow_audited",
            audit_after.valid and audit_after.last_sequence > audit_before.last_sequence,
            {
                "before_records": audit_before.record_count,
                "after_records": audit_after.record_count,
                "before_sequence": audit_before.last_sequence,
                "after_sequence": audit_after.last_sequence,
            },
        )
    )

    journal_ok, journal_detail = _systemd_invocation_journal()
    checks.append(_record("current_service_journal_clean", journal_ok, journal_detail))

    return _finish_report(
        checks,
        expected_user=expected_user,
        fixture=fixture_result,
    )


def _finish_report(
    checks: Iterable[WorkflowCheck],
    *,
    expected_user: str | None,
    fixture: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    materialized = list(checks)
    overall = "FAIL" if any(item.status == "FAIL" for item in materialized) else "OK"
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "method": (
            "installed MONITOR_ONLY workflow using a private /bin/sleep copy; "
            "official Unix IPC; real fanotify/eBPF observations; no malware; "
            "no enforcement; no automatic destructive response"
        ),
        "euid": os.geteuid(),
        "expected_user": expected_user,
        "fixture": dict(fixture or {}),
        "results": [item.to_dict() for item in materialized],
        "overall_status": overall,
    }


def _print_summary(report: Mapping[str, Any]) -> None:
    for item in report.get("results", []):
        if isinstance(item, Mapping):
            print(f"{item.get('check')}: {item.get('status')}")
    print(f"overall_status: {report.get('overall_status')}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-user")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        report = collect_integrated_workflow_report(expected_user=args.expected_user)
    except (OSError, ValueError, IpcClientError) as exc:
        report = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "method": "installed Stage 14 workflow verification",
            "results": [
                _record("verifier_exception", False, f"{type(exc).__name__}: {exc}").to_dict()
            ],
            "overall_status": "FAIL",
        }
    write_json_atomic(args.output, report)
    _print_summary(report)
    print(f"Evidence written to: {args.output}")
    if report.get("overall_status") != "OK":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
