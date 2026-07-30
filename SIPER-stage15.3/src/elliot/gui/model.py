"""Unprivileged GUI model using only ELLIOT's official Unix-socket API."""

from __future__ import annotations

import logging
from typing import Any, Callable

from ..service.ipc_client import IpcClient, IpcClientError, IpcRemoteError

logger = logging.getLogger("elliot.gui.model")


class PardusModel:
    def __init__(self, client: IpcClient | None = None) -> None:
        self.client = client or IpcClient()

    def _send_request(self, action: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            result = self.client.request(action, params)
            if not isinstance(result, dict):
                return {
                    "ok": False,
                    "error": {
                        "code": "INVALID_DAEMON_RESULT",
                        "message": f"Daemon result for '{action}' is not an object",
                    },
                }
            return {"ok": True, "result": result}
        except IpcRemoteError as exc:
            logger.warning("Daemon rejected %s: %s", action, exc)
            return {"ok": False, "error": {"code": exc.code, "message": exc.message}}
        except IpcClientError as exc:
            logger.error("Siper IPC error during %s: %s", action, exc)
            return {
                "ok": False,
                "error": {"code": "IPC_UNAVAILABLE", "message": str(exc)},
            }

    def get_status(self) -> dict[str, Any]:
        return self._send_request("get_status")

    def get_events(self, limit: int = 50) -> dict[str, Any]:
        return self._send_request("list_events", {"limit": limit})

    def get_runtime_states(self, limit: int = 50) -> dict[str, Any]:
        return self._send_request("list_runtime_states", {"limit": limit})

    def get_quarantine_list(self) -> dict[str, Any]:
        return self._send_request("list_quarantine")

    def get_policy(self) -> dict[str, Any]:
        return self._send_request("get_policy")

    def scan_file(self, path: str) -> dict[str, Any]:
        return self._send_request("scan_file", {"path": path})

    def restore_file(self, quarantine_id: str, destination: str | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"quarantine_id": quarantine_id}
        if destination is not None:
            params["destination"] = destination
        return self._send_request("restore_file", params)

    def fetch_dashboard(self, event_limit: int = 50) -> dict[str, Any]:
        """Fetch independent dashboard sections while preserving partial failures."""

        calls: tuple[tuple[str, Callable[[], dict[str, Any]], str, Any], ...] = (
            ("status", self.get_status, "", {}),
            ("events", lambda: self.get_events(event_limit), "events", []),
            ("quarantine", self.get_quarantine_list, "items", []),
            ("policy", self.get_policy, "", {}),
        )
        snapshot: dict[str, Any] = {
            "connected": False,
            "status": {},
            "events": [],
            "quarantine": [],
            "policy": {},
            "errors": [],
        }
        for section, call, nested_key, fallback in calls:
            response = call()
            if response.get("ok") is True:
                result = response.get("result", {})
                if nested_key:
                    result = result.get(nested_key, fallback) if isinstance(result, dict) else fallback
                snapshot[section] = result
                if section == "status":
                    snapshot["connected"] = True
            else:
                error = response.get("error", {})
                snapshot["errors"].append(
                    {
                        "section": section,
                        "code": str(error.get("code", "UNKNOWN")),
                        "message": str(error.get("message", "Unknown GUI API failure")),
                    }
                )
        return snapshot
