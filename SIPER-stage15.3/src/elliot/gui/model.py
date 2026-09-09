"""Unprivileged GUI model using only ELLIOT's official Unix-socket API."""

from __future__ import annotations

import logging
from typing import Any, Callable

from ..service.ipc_client import IpcClient, IpcClientError, IpcRemoteError
from ..service.windows_local import WindowsLocalService

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


class WindowsModel:
    """GUI model for the local Windows monitor; no cloud or socket transport."""

    def __init__(self, service: WindowsLocalService | None = None) -> None:
        self.service = service or WindowsLocalService()
        self.service.start()

    @staticmethod
    def _success(result: dict[str, Any]) -> dict[str, Any]:
        return {"ok": True, "result": result}

    def get_status(self) -> dict[str, Any]:
        return self._success(self.service.get_status())

    def get_events(self, limit: int = 50) -> dict[str, Any]:
        return self._success(self.service.list_events(limit))

    def get_quarantine_list(self) -> dict[str, Any]:
        return self._success(self.service.list_quarantine())

    def get_policy(self) -> dict[str, Any]:
        return self._success(self.service.get_policy())

    def scan_file(self, path: str) -> dict[str, Any]:
        try:
            return self._success(self.service.scan_file(path))
        except (OSError, ValueError) as exc:
            return {"ok": False, "error": {"code": "LOCAL_SCAN_FAILED", "message": str(exc)}}

    def restore_file(self, quarantine_id: str, destination: str | None = None) -> dict[str, Any]:
        del quarantine_id, destination
        return {
            "ok": False,
            "error": {
                "code": "WINDOWS_RESPONSE_UNAVAILABLE",
                "message": "Windows local monitoring is monitor-only until a signed minifilter response component is installed.",
            },
        }

    def fetch_dashboard(self, event_limit: int = 50) -> dict[str, Any]:
        return {
            "connected": True,
            "status": self.service.get_status(),
            "events": self.service.list_events(event_limit).get("events", []),
            "quarantine": [],
            "policy": self.service.get_policy(),
            "errors": [],
        }

    def close(self) -> None:
        self.service.stop()
