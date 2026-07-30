from __future__ import annotations

import threading

from elliot.gui.model import PardusModel
from elliot.gui.presentation import dashboard_projection
from elliot.service.ipc_client import IpcClient
from elliot.service.ipc_server import IpcServer


def test_gui_model_round_trip_over_official_unix_socket(tmp_path) -> None:
    socket_path = tmp_path / "run" / "elliot.sock"

    def handler(action, params, requester):
        if action == "get_status":
            return {"api_version": 1, "fanotify_active": False, "ebpf_active": False, "degraded_components": ["fanotify", "ebpf"]}
        if action == "list_events":
            return {"events": []}
        if action == "list_quarantine":
            return {"items": []}
        if action == "get_policy":
            return {"mode": "MONITOR_ONLY", "monitored_paths": [], "excluded_paths": []}
        raise ValueError(action)

    server = IpcServer(handler, socket_path=socket_path, socket_group=None)
    server.start()
    thread = threading.Thread(target=server.run_forever, daemon=True)
    thread.start()
    try:
        snapshot = PardusModel(IpcClient(socket_path=socket_path)).fetch_dashboard()
        projected = dashboard_projection(snapshot)
        assert projected["connected"] is True
        assert projected["service_state"] == "DEGRADED"
    finally:
        server.stop()
        thread.join(timeout=2)
