#!/usr/bin/env python3
"""Headless Stage 7 proof using the official IPC client and a temporary server.

No privileged daemon, kernel hook, network listener, persistent file, or malware
is used. The temporary server is explicitly a safe GUI demonstration fixture.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from elliot.analyzer.static_analyzer import StaticFileScanner
from elliot.gui.model import PardusModel
from elliot.gui.presentation import dashboard_projection, scan_projection
from elliot.scoring.engine import PreExecutionScoringEngine
from elliot.service.ipc_client import IpcClient
from elliot.service.ipc_server import IpcServer


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="elliot-stage7-") as temporary:
        root = Path(temporary)
        socket_path = root / "run" / "elliot.sock"
        safe_file = root / "safe_gui_sample.txt"
        safe_file.write_text("ELLIOT safe GUI demonstration\n" * 64, encoding="utf-8")
        scanner = StaticFileScanner()
        scorer = PreExecutionScoringEngine()
        events = [
            {
                "source": "safe_gui_demo",
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "fixture_kind": "SAFE_GUI_DEMONSTRATION_NOT_LIVE_TELEMETRY",
                "message": "Temporary IPC server is available",
            }
        ]

        def handler(action: str, params: dict, requester) -> dict:
            if action == "get_status":
                return {
                    "api_version": 1,
                    "fanotify_active": False,
                    "ebpf_active": False,
                    "degraded_components": ["fanotify", "ebpf"],
                    "recent_event_count": len(events),
                    "recent_events": list(events),
                    "fixture_kind": "SAFE_GUI_DEMONSTRATION_NOT_LIVE_PROTECTION",
                }
            if action == "list_events":
                return {"events": list(events[-int(params["limit"]):])}
            if action == "list_quarantine":
                return {"items": []}
            if action == "get_policy":
                return {
                    "mode": "MONITOR_ONLY",
                    "monitored_paths": [],
                    "excluded_paths": [],
                }
            if action == "scan_file":
                scan = scanner.scan(str(params["path"]))
                result = scan.to_dict()
                result["pre_execution_scoring"] = scorer.score(scan).to_dict()
                events.append(
                    {
                        "source": "manual_scan",
                        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                        "filepath": result["filepath"],
                        "score": result["pre_execution_scoring"]["score"],
                        "decision": result["pre_execution_scoring"]["decision"],
                    }
                )
                return result
            if action == "restore_file":
                raise ValueError("Safe GUI demonstration contains no quarantine record")
            raise ValueError(f"Unsupported demo action: {action}")

        server = IpcServer(
            handler,
            socket_path=socket_path,
            socket_group=None,
            authorizer=lambda _requester, _action: None,
        )
        server.start()
        server_thread = threading.Thread(target=server.run_forever, daemon=True)
        server_thread.start()
        try:
            model = PardusModel(IpcClient(socket_path=socket_path))
            dashboard = model.fetch_dashboard()
            scan_response = model.scan_file(str(safe_file))
            dashboard_view = dashboard_projection(dashboard)
            scan_view = scan_projection(scan_response.get("result", {}))

            results = [
                {
                    "scenario": "official_model_over_unix_socket",
                    "status": "OK" if dashboard_view["connected"] else "FAILED",
                },
                {
                    "scenario": "degraded_components_are_visible",
                    "status": "OK"
                    if dashboard_view["service_state"] == "DEGRADED"
                    and set(dashboard_view["degraded_components"]) == {"fanotify", "ebpf"}
                    else "FAILED",
                },
                {
                    "scenario": "real_static_scan_values_projected",
                    "status": "OK"
                    if scan_response.get("ok") is True
                    and scan_view["filepath"] == str(safe_file)
                    and scan_view["whole_file_entropy"] is not None
                    else "FAILED",
                    "score": scan_view["pre_execution_score"],
                    "decision": scan_view["decision"],
                    "whole_file_entropy": scan_view["whole_file_entropy"],
                    "reported_block_count": len(scan_view["block_entropies"]),
                },
                {
                    "scenario": "runtime_score_not_fabricated",
                    "status": "OK" if scan_view["runtime_score"] is None else "FAILED",
                },
            ]
            overall = "OK" if all(item["status"] == "OK" for item in results) else "FAILED"
            evidence = {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "method": (
                    "temporary Unix socket and harmless text file; no root, kernel hooks, "
                    "network listener, quarantine action, or malware"
                ),
                "fixture_label": "SAFE_GUI_DEMONSTRATION_NOT_LIVE_PROTECTION",
                "results": results,
                "overall_status": overall,
            }
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
            for item in results:
                print(f"{item['scenario']}: {item['status']}")
            print(f"overall_status: {overall}")
            print(f"Evidence written to: {output}")
            return 0 if overall == "OK" else 1
        finally:
            server.stop()
            server_thread.join(timeout=2.0)


if __name__ == "__main__":
    raise SystemExit(main())
