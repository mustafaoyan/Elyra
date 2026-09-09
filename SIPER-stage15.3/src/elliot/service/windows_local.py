"""Windows local-only service facade used by the desktop GUI.

Unlike the Linux daemon, Windows operation does not expose a Unix socket or
pretend to provide fanotify enforcement.  The GUI owns a local monitor session
and calls this facade in-process.  No events, paths, scan results, or account
data leave the endpoint.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from ..analyzer.static_analyzer import StaticFileScanner
from ..monitor.windows.controller import WindowsMonitorController
from ..monitor.windows.policy import WindowsMonitorPolicy
from ..scoring.engine import PreExecutionScoringEngine
from .ipc_protocol import PROTOCOL_VERSION


logger = logging.getLogger("elliot.service.windows_local")


class WindowsLocalService:
    """Minimal local service API with the same read/scan shape as the Linux GUI.

    It is deliberately monitor-only.  A production Windows execution-blocking
    path requires a separately packaged, signed minifilter and must not be
    silently enabled by this user-space service.
    """

    def __init__(
        self,
        *,
        monitor: WindowsMonitorController | None = None,
        scanner: StaticFileScanner | None = None,
        scoring_engine: PreExecutionScoringEngine | None = None,
    ) -> None:
        self.monitor = monitor or WindowsMonitorController(WindowsMonitorPolicy())
        self.scanner = scanner or StaticFileScanner()
        self.scoring_engine = scoring_engine or PreExecutionScoringEngine()
        self._started = False

    def start(self) -> bool:
        if self._started:
            return True
        self._started = self.monitor.start()
        return self._started

    def stop(self) -> None:
        self.monitor.stop()
        self._started = False

    def get_status(self) -> dict[str, Any]:
        status = self.monitor.status()
        active = bool(status.get("active"))
        backend = status.get("backend", {})
        active_backend = backend.get("active_backend") if isinstance(backend, dict) else None
        monitor_kind = (
            "ETW (local adapter)"
            if active_backend == "EtwBackend"
            else (
                "ReadDirectoryChangesW"
                if active_backend == "ReadDirectoryChangesBackend"
                else "Windows local monitor"
            )
        )
        return {
            "api_version": PROTOCOL_VERSION,
            "platform": "WINDOWS",
            "monitor_kind": monitor_kind,
            "fanotify_active": False,
            # eBPF is a Linux sensor.  The Windows UI uses the dedicated
            # windows_monitor_active field and must never relabel a directory
            # notification backend as eBPF.
            "ebpf_active": False,
            "windows_monitor_active": active,
            "degraded_components": [] if active else ["windows_local_monitor"],
            "recent_event_count": int(status.get("recent_record_count", 0)),
            "local_only": True,
            "monitor_mode": "MONITOR_ONLY",
            "enforcement_capability": "SIGNED_MINIFILTER_REQUIRED",
            "backend": backend if isinstance(backend, dict) else {},
        }

    def list_events(self, limit: int = 50) -> dict[str, list[dict[str, Any]]]:
        events: list[dict[str, Any]] = []
        for record in self.monitor.recent_records(limit):
            raw_event = record.get("event")
            if not isinstance(raw_event, dict):
                continue
            analysis = record.get("analysis")
            event: dict[str, Any] = {
                "source": "windows-monitor",
                "event_type": raw_event.get("event_type"),
                "timestamp_ns": raw_event.get("timestamp_ns"),
                "path": raw_event.get("path"),
                "previous_path": raw_event.get("previous_path"),
                "provider": raw_event.get("provider"),
                "process_id": raw_event.get("process_id"),
                "status": record.get("status"),
                "reason": record.get("reason"),
                "local_only": True,
            }
            if isinstance(analysis, dict):
                entropy = analysis.get("entropy")
                if isinstance(entropy, dict):
                    summary = entropy.get("whole_file_entropy")
                    if isinstance(summary, (int, float)) and not isinstance(summary, bool):
                        event["entropy_bits_per_byte"] = float(summary)
            events.append(event)
        return {"events": events}

    def get_policy(self) -> dict[str, Any]:
        snapshot = self.monitor.policy_snapshot()
        return {
            "mode": "MONITOR_ONLY",
            "monitored_paths": list(snapshot.get("monitored_paths", [])),
            "excluded_paths": list(snapshot.get("excluded_paths", [])),
            "max_preexec_file_bytes": snapshot.get("max_file_bytes"),
            "enforcement_capability": "SIGNED_MINIFILTER_REQUIRED",
            "local_only": True,
        }

    def list_quarantine(self) -> dict[str, list[dict[str, Any]]]:
        # Windows response actions are intentionally out of scope until a
        # reviewed minifilter/installer policy exists.  Do not emulate or
        # mislabel Linux quarantine semantics as Windows kernel enforcement.
        return {"items": []}

    def scan_file(self, path: str) -> dict[str, Any]:
        target = os.path.abspath(path)
        scan = self.scanner.scan(target)
        result = scan.to_dict()
        result["pre_execution_scoring"] = self.scoring_engine.score(scan).to_dict()
        result["local_only"] = True
        result["platform"] = "WINDOWS"
        return result


def main() -> None:
    """Start a local Windows monitor for diagnostic use from a console."""

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if os.name != "nt":
        raise SystemExit("elliot-windows-local can only run on Windows")
    service = WindowsLocalService()
    if not service.start():
        logger.error("Windows local monitor did not start: %s", service.get_status())
        raise SystemExit(1)
    logger.info("ELLIOT Windows local monitor started; press Ctrl+C to stop")
    try:
        import time

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        service.stop()
