#!/usr/bin/env python3
"""Run a harmless Stage 14 in-process integration demonstration.

The demonstration connects real Stage 3/4 analysis, Stage 10 correlation,
Stage 11 response execution, Stage 12 audit logging, and the Stage 6/7 official
Unix-socket GUI API.  Runtime risk records are explicitly synthetic; the only
process is a private copy of ``/bin/sleep`` created in a temporary directory.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from elyra.analyzer.static_analyzer import StaticFileScanner
from elyra.audit.audit_logger import AuditLogger, verify_audit_directory
from elyra.correlation.engine import ExecutionCorrelationEngine
from elyra.gui.model import PardusModel
from elyra.gui.presentation import dashboard_projection, scan_projection
from elyra.response.engine import ResponseEngine, ResponsePolicy
from elyra.response.quarantine_manager import QuarantineManager
from elyra.scoring.engine import PreExecutionScoringEngine
from elyra.service.install_layout import write_json_atomic
from elyra.service.ipc_client import IpcClient
from elyra.service.ipc_server import IpcServer


def _scenario(name: str, ok: bool, **detail: Any) -> dict[str, Any]:
    return {"scenario": name, "status": "OK" if ok else "FAIL", **detail}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    results: list[dict[str, Any]] = []
    event_stream: list[dict[str, Any]] = []
    process: subprocess.Popen[str] | None = None

    with tempfile.TemporaryDirectory(prefix="elyra-stage14-integrated-") as temporary:
        root = Path(temporary)
        work = root / "work"
        work.mkdir(mode=0o700)
        audit_dir = root / "audit"
        quarantine_dir = root / "protected" / "quarantine"
        metadata_dir = root / "protected" / "metadata"
        socket_path = root / "run" / "elyra.sock"

        audit = AuditLogger(str(audit_dir), max_bytes=64 * 1024, backup_count=2)
        quarantine = QuarantineManager(
            quarantine_dir=quarantine_dir,
            metadata_dir=metadata_dir,
            audit_log=audit,
        )
        response = ResponseEngine(
            quarantine,
            audit_logger=audit,
            policy=ResponsePolicy.load().with_runtime_actions(True),
            event_sink=lambda item: event_stream.append(dict(item)),
        )
        correlation = ExecutionCorrelationEngine()
        scanner = StaticFileScanner()
        scoring = PreExecutionScoringEngine()

        source = Path("/bin/sleep")
        executable = work / "elyra-stage14-safe-sleep"
        shutil.copy2(source, executable)
        executable.chmod(0o755)

        scan = scanner.scan(executable)
        score = scoring.score(scan).to_dict()
        scan_payload = scan.to_dict()
        scan_payload["pre_execution_scoring"] = score
        projected_scan = scan_projection(scan_payload)
        results.append(
            _scenario(
                "real_static_analysis_and_explainable_score",
                scan.status == "OK"
                and isinstance(projected_scan["whole_file_entropy"], (int, float))
                and isinstance(projected_scan["pre_execution_score"], int),
                scan=projected_scan,
            )
        )

        process = subprocess.Popen(
            [str(executable), "30"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
        pid = process.pid

        # A fixed high pre-execution score is used only to exercise the complete
        # response path with a harmless fixture. It is never presented as the
        # real scanner's conclusion.
        fanotify_fixture = {
            "event_type": "PRE_EXECUTION_DECISION",
            "pid": pid,
            "path": str(executable),
            "score": 60,
            "risk_score": "60/100",
            "requested_decision": "WARN",
            "final_action": "ALLOW",
            "response_ok": True,
            "indicators": [
                {
                    "rule": "SAFE_SYNTHETIC_PREEXEC_INTEGRATION_FIXTURE",
                    "category": "test",
                    "weight": 60,
                    "evidence": "harmless copied /bin/sleep",
                }
            ],
            "fixture_label": "SYNTHETIC_RISK_FOR_SAFE_INTEGRATION_ONLY",
        }
        pre_result = correlation.register_pre_execution(fanotify_fixture)
        state = pre_result["state"]
        response.bind_state(state)
        event_stream.append({"source": "fanotify", **fanotify_fixture, "correlation": pre_result})

        exec_result = correlation.ingest_runtime_event(
            {
                "event_type": "PROCESS_EXEC",
                "timestamp_ns": time.time_ns(),
                "pid": pid,
                "tgid": pid,
                "ppid": os.getpid(),
                "uid": os.getuid(),
                "comm": executable.name,
                "executable_identifier": str(executable),
            }
        )
        event_stream.append(
            {
                "source": "ebpf",
                "event_type": "PROCESS_EXEC",
                "pid": pid,
                "tgid": pid,
                "path_capability": "SAFE_SYNTHETIC_DECODED_EVENT",
                "correlation": exec_result,
            }
        )
        rename_result = correlation.ingest_runtime_event(
            {
                "event_type": "FILE_RENAME",
                "timestamp_ns": time.time_ns(),
                "pid": pid,
                "tgid": pid,
                "ppid": os.getpid(),
                "uid": os.getuid(),
                "comm": executable.name,
                "executable_identifier": "safe-test-rename-identifier",
            }
        )
        event_stream.append(
            {
                "source": "ebpf",
                "event_type": "FILE_RENAME",
                "pid": pid,
                "tgid": pid,
                "correlation": rename_result,
            }
        )
        network_result = correlation.ingest_runtime_event(
            {
                "event_type": "NETWORK_CONNECT",
                "timestamp_ns": time.time_ns(),
                "pid": pid,
                "tgid": pid,
                "ppid": os.getpid(),
                "uid": os.getuid(),
                "comm": executable.name,
                "destination_address": "127.0.0.1",
                "destination_port": 9,
            }
        )
        final_state = network_result["state"]
        event_stream.append(
            {
                "source": "ebpf",
                "event_type": "NETWORK_CONNECT",
                "pid": pid,
                "tgid": pid,
                "correlation": network_result,
            }
        )
        results.append(
            _scenario(
                "fanotify_runtime_correlation_reaches_quarantine",
                final_state["pre_execution_score"] == 60
                and final_state["runtime_score"] == 35
                and final_state["combined_score"] == 95
                and final_state["recommended_action"] == "QUARANTINE",
                state=final_state,
            )
        )

        action = response.execute_recommendation(final_state)
        if process.poll() is None:
            try:
                process.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)
        record_payload = action.details.get("quarantine_record", {})
        quarantine_id = str(record_payload.get("quarantine_id", ""))
        results.append(
            _scenario(
                "authorised_terminate_and_quarantine",
                action.status == "SUCCEEDED"
                and action.executed_action == "QUARANTINE"
                and not executable.exists()
                and bool(quarantine_id),
                action=action.to_dict(),
            )
        )

        restored, restore_action = response.restore(
            quarantine_id,
            executable,
            actor="stage14-safe-demonstration",
            requester_pid=os.getpid(),
        )
        results.append(
            _scenario(
                "authorised_safe_restore",
                restore_action.status == "SUCCEEDED"
                and restored.restoration_status == "restored"
                and executable.exists(),
                restore=restore_action.to_dict(),
            )
        )

        def handler(action_name: str, params: dict[str, Any], _requester) -> dict[str, Any]:
            if action_name == "get_status":
                return {
                    "api_version": 1,
                    "fanotify_active": True,
                    "ebpf_active": True,
                    "degraded_components": [],
                    "audit": audit.status(),
                }
            if action_name == "get_policy":
                return {"mode": "MONITOR_ONLY"}
            if action_name == "list_events":
                return {"events": event_stream[-int(params["limit"]):]}
            if action_name == "list_quarantine":
                return {"items": [item.to_dict() for item in quarantine.list_quarantine()]}
            if action_name == "scan_file":
                target_scan = scanner.scan(str(params["path"]))
                payload = target_scan.to_dict()
                payload["pre_execution_scoring"] = scoring.score(target_scan).to_dict()
                return payload
            raise ValueError(f"unsupported safe-demo action: {action_name}")

        server = IpcServer(
            handler,
            socket_path=socket_path,
            socket_group=None,
            authorizer=lambda _requester, _action: None,
        )
        server.start()
        thread = threading.Thread(target=server.run_forever, daemon=True)
        thread.start()
        try:
            model = PardusModel(IpcClient(socket_path, timeout=3.0))
            dashboard = dashboard_projection(model.fetch_dashboard(event_limit=100))
            gui_scan_response = model.scan_file(str(executable))
            gui_scan = scan_projection(gui_scan_response.get("result", {}))
            results.append(
                _scenario(
                    "official_ipc_gui_projection",
                    dashboard["connected"] is True
                    and dashboard["service_state"] == "CONNECTED"
                    and len(dashboard["events"]) >= 4
                    and isinstance(gui_scan["whole_file_entropy"], (int, float)),
                    dashboard={
                        "service_state": dashboard["service_state"],
                        "policy_mode": dashboard["policy_mode"],
                        "event_count": len(dashboard["events"]),
                    },
                    scan=gui_scan,
                )
            )
        finally:
            server.stop()
            thread.join(timeout=2.0)

        integrity = verify_audit_directory(audit_dir)
        results.append(
            _scenario(
                "structured_tamper_evident_audit_chain",
                integrity.valid and integrity.record_count >= 2,
                integrity=integrity.to_dict(),
            )
        )
        response.close()

    overall = "OK" if all(item["status"] == "OK" for item in results) else "FAIL"
    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "method": (
            "harmless temporary /bin/sleep copy; real analysis/IPC/GUI/audit/"
            "pidfd/quarantine/restore; synthetic fanotify/eBPF risk records; no malware; no root"
        ),
        "fixture_label": "SYNTHETIC_RUNTIME_EVIDENCE_SAFE_FIXTURE_NOT_LIVE_KERNEL_TELEMETRY",
        "results": results,
        "overall_status": overall,
    }
    write_json_atomic(args.output, report)
    for item in results:
        print(f"{item['scenario']}: {item['status']}")
    print(f"overall_status: {overall}")
    print(f"Evidence written to: {args.output}")
    if overall != "OK":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
