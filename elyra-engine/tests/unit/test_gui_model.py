from __future__ import annotations

from elyra.gui.model import PardusModel
from elyra.service.ipc_client import IpcClientError, IpcRemoteError


class FakeClient:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def request(self, action, params=None):
        self.calls.append((action, params))
        response = self.responses[action]
        if isinstance(response, Exception):
            raise response
        return response


def test_model_scan_uses_official_action() -> None:
    client = FakeClient({"scan_file": {"status": "OK"}})
    model = PardusModel(client)
    response = model.scan_file("/tmp/a")
    assert response == {"ok": True, "result": {"status": "OK"}}
    assert client.calls == [("scan_file", {"path": "/tmp/a"})]


def test_model_preserves_remote_authorization_error() -> None:
    client = FakeClient({"restore_file": IpcRemoteError("AUTHORIZATION_DENIED", "no")})
    response = PardusModel(client).restore_file("id")
    assert response["ok"] is False
    assert response["error"]["code"] == "AUTHORIZATION_DENIED"


def test_model_reports_ipc_unavailable() -> None:
    client = FakeClient({"get_status": IpcClientError("socket missing")})
    response = PardusModel(client).get_status()
    assert response["error"]["code"] == "IPC_UNAVAILABLE"


def test_fetch_dashboard_supports_partial_failure() -> None:
    client = FakeClient(
        {
            "get_status": {"api_version": 1},
            "list_events": IpcClientError("events unavailable"),
            "list_quarantine": {"items": []},
            "get_policy": {"mode": "MONITOR_ONLY"},
        }
    )
    snapshot = PardusModel(client).fetch_dashboard()
    assert snapshot["connected"] is True
    assert snapshot["status"]["api_version"] == 1
    assert snapshot["events"] == []
    assert snapshot["errors"][0]["section"] == "events"


def test_model_rejects_non_object_daemon_result() -> None:
    client = FakeClient({"get_status": [1, 2]})
    response = PardusModel(client).get_status()
    assert response["ok"] is False
    assert response["error"]["code"] == "INVALID_DAEMON_RESULT"
