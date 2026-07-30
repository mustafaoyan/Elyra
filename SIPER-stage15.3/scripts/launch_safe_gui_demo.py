#!/usr/bin/env python3
"""Launch the real Stage 7 GUI against a clearly labelled temporary IPC server."""

from __future__ import annotations

import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from elliot.analyzer.static_analyzer import StaticFileScanner
from elliot.gui.controller import PardusController
from elliot.gui.model import PardusModel
from elliot.gui.view import PardusView
from elliot.scoring.engine import PreExecutionScoringEngine
from elliot.service.ipc_client import IpcClient
from elliot.service.ipc_server import IpcServer


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="elliot-stage7-visual-") as temporary:
        socket_path = Path(temporary) / "run" / "elliot.sock"
        scanner = StaticFileScanner()
        scorer = PreExecutionScoringEngine()
        events = [
            {
                "source": "safe_gui_demo",
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "fixture_kind": "SAFE_GUI_DEMONSTRATION_NOT_LIVE_TELEMETRY",
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
                }
            if action == "list_events":
                return {"events": list(events[-int(params["limit"]):])}
            if action == "list_quarantine":
                return {"items": []}
            if action == "get_policy":
                return {"mode": "MONITOR_ONLY", "monitored_paths": [], "excluded_paths": []}
            if action == "scan_file":
                scan = scanner.scan(str(params["path"]))
                result = scan.to_dict()
                result["pre_execution_scoring"] = scorer.score(scan).to_dict()
                return result
            if action == "restore_file":
                raise ValueError("Safe visual demonstration contains no quarantine record")
            raise ValueError(f"Unsupported demo action: {action}")

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
            model = PardusModel(IpcClient(socket_path=socket_path))
            view = PardusView(banner_text="SAFE IPC DEMO — NOT LIVE PROTECTION")
            PardusController(model, view).run()
        finally:
            server.stop()
            thread.join(timeout=2.0)


if __name__ == "__main__":
    main()
