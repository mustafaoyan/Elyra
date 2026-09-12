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
from ..monitor.windows.analysis import WindowsStaticAnalyzer
from ..monitor.windows.controller import WindowsMonitorController
from ..monitor.windows.policy import WindowsMonitorPolicy
from ..scoring.engine import PreExecutionScoringEngine
from .ipc_protocol import PROTOCOL_VERSION


logger = logging.getLogger("elyra.service.windows_local")


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
        existing = getattr(self.monitor, "analyzer", None)
        if isinstance(existing, WindowsStaticAnalyzer) and scanner is None and scoring_engine is None:
            self.analyzer = existing
        else:
            policy = self.monitor.policy_snapshot()
            self.analyzer = WindowsStaticAnalyzer(
                scanner=scanner,
                scoring_engine=scoring_engine,
                max_file_bytes=int(policy.get("max_file_bytes", 128 * 1024 * 1024)),
                retry_attempts=int(policy.get("retry_attempts", 2)),
                retry_delay_seconds=float(policy.get("retry_delay_seconds", 0.15)),
            )
            if isinstance(self.monitor, WindowsMonitorController) and (
                isinstance(existing, WindowsStaticAnalyzer) or scanner is not None or scoring_engine is not None
            ):
                self.monitor.analyzer = self.analyzer
        self.scanner = self.analyzer.scanner
        self.scoring_engine = self.analyzer.scoring_engine
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
                "assessment": record.get("assessment", "INCONCLUSIVE"),
                "risk_score": record.get("risk_score"),
                "recommended_decision": record.get("recommended_decision", "INCONCLUSIVE"),
                "decision": record.get("recommended_decision", "INCONCLUSIVE"),
                "reasons": record.get("reasons", []),
                "score_is_probability": False,
                "score_kind": "PROVISIONAL_HEURISTIC_NOT_PROBABILITY",
                "enforced_action": "NONE",
                "monitor_mode": "MONITOR_ONLY",
            }
            if isinstance(analysis, dict):
                for key in ("assessment", "risk_score", "recommended_decision", "decision",
                            "reasons", "limitations", "static_scan", "pre_execution_scoring"):
                    if key in analysis:
                        event[key] = analysis[key]
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
        analysis = self.analyzer.analyze(path).to_dict()
        static = analysis.get("static_scan")
        result = dict(static) if isinstance(static, dict) else {
            "filepath": analysis["path"], "status": "ERROR", "warnings": [],
            "errors": [{"code": analysis["status"], "message": analysis["reason"]}],
        }
        # Preserve the manual scan's flattened static result and status while
        # exposing the same full assessment used by automatic notifications.
        result.update({key: value for key, value in analysis.items() if key != "status"})
        result["analysis_status"] = analysis["status"]
        result["local_only"] = True
        result["platform"] = "WINDOWS"
        return result


def main() -> None:
    """Start a local Windows monitor for diagnostic use from a console."""

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if os.name != "nt":
        raise SystemExit("elyra-windows-local can only run on Windows")
    service = WindowsLocalService()
    if not service.start():
        logger.error("Windows local monitor did not start: %s", service.get_status())
        raise SystemExit(1)
    logger.info("ELYRA Windows local monitor started; press Ctrl+C to stop")
    try:
        import time

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        service.stop()
