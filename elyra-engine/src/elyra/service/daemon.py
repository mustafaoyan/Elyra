"""Privileged Elyra daemon entry point.

Stage 6 establishes one protected, versioned Unix-domain-socket API. Kernel
fanotify/eBPF behaviour is still reported as degraded unless separately verified.
"""

from __future__ import annotations

import logging
import os
import queue
import signal
import sys
import threading
from dataclasses import asdict
from typing import Any

from ..analyzer.static_analyzer import StaticFileScanner
from ..correlation.engine import ExecutionCorrelationEngine
from ..audit.audit_logger import AuditIntegrityError, AuditLogger
from ..monitor.ebpf.aggregator import RuntimeTelemetryAggregator
from ..monitor.ebpf.loader import EBPFLoader
from ..monitor.fanotify.controller import FanotifyController
from ..response.engine import ResponseEngine, ResponsePolicy, ResponseSafetyError
from ..response.quarantine_manager import QuarantineManager
from ..scoring.engine import PreExecutionScoringEngine
from ..update.checker import UpdateDecision, check_latest
from .authorization import Requester, authorize_manual_scan_path
from .ipc_protocol import PROTOCOL_VERSION
from .ipc_server import IpcServer

logger = logging.getLogger("elyra.service.daemon")


class ElyraDaemonState:
    def __init__(self) -> None:
        self.fanotify_active = False
        self.ebpf_active = False
        self.degraded_components: list[str] = []
        self.recent_events: list[dict[str, Any]] = []
        self.update_status: dict[str, Any] = {"status": "CHECK_DISABLED", "can_defer": True}
        self._lock = threading.Lock()

    def set_component(self, name: str, active: bool) -> None:
        with self._lock:
            if name == "fanotify":
                self.fanotify_active = active
            elif name == "ebpf":
                self.ebpf_active = active
            if active:
                self.degraded_components = [item for item in self.degraded_components if item != name]
            elif name not in self.degraded_components:
                self.degraded_components.append(name)

    def note_event(self, entry: dict[str, Any], max_events: int = 200) -> None:
        with self._lock:
            self.recent_events.append(entry)
            if len(self.recent_events) > max_events:
                self.recent_events = self.recent_events[-max_events:]

    def recent(self, limit: int) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.recent_events[-limit:])

    def snapshot(self, *, correlation_summary: dict[str, Any] | None = None) -> dict[str, Any]:
        with self._lock:
            return {
                "api_version": PROTOCOL_VERSION,
                "fanotify_active": self.fanotify_active,
                "ebpf_active": self.ebpf_active,
                "degraded_components": list(self.degraded_components),
                "recent_event_count": len(self.recent_events),
                "recent_events": list(self.recent_events[-20:]),
                "correlation": dict(correlation_summary or {}),
                "update": dict(self.update_status),
            }


class ElyraDaemon:
    """Own privileged components and expose the official IPC API."""

    def __init__(
        self,
        enforcement: bool = False,
        *,
        execute_responses: bool = False,
    ) -> None:
        self.audit_log = AuditLogger()
        self.state = ElyraDaemonState()
        self.quarantine = QuarantineManager(audit_log=self.audit_log)
        self.static_scanner = StaticFileScanner()
        self.scoring_engine = PreExecutionScoringEngine()
        self._fanotify_events: queue.Queue[dict[str, Any]] = queue.Queue()

        self.fanotify_controller = FanotifyController(
            olay_kuyrugu=self._fanotify_events, audit_logger=self.audit_log
        )
        self.fanotify_controller.policy.set_mode(
            "ENFORCEMENT" if enforcement else "MONITOR_ONLY"
        )
        self.ebpf_loader = EBPFLoader()
        self.runtime_telemetry = RuntimeTelemetryAggregator()
        self.execution_correlation = ExecutionCorrelationEngine()
        manifest_url = os.environ.get("ELYRA_UPDATE_MANIFEST_URL", "").strip()
        if manifest_url:
            self.state.update_status = check_latest(manifest_url).to_dict()
        response_policy = ResponsePolicy.load().with_runtime_actions(execute_responses)
        self.response_engine = ResponseEngine(
            self.quarantine,
            audit_logger=self.audit_log,
            policy=response_policy,
            event_sink=self.state.note_event,
        )
        self.ipc = IpcServer(handler=self._handle_ipc_action)

        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()

    def start(self) -> None:
        if os.geteuid() != 0:
            raise PermissionError("Elyra daemon must run as root or with documented Linux capabilities")

        logger.info("Starting Elyra daemon")
        if self.state.update_status.get("status") in {"UPDATE_AVAILABLE", "UPDATE_REQUIRED"}:
            logger.warning(
                "ELYRA update notification: %s (defer=%s)",
                self.state.update_status.get("status"),
                self.state.update_status.get("can_defer"),
            )
        self.audit_log.record(
            "audit",
            "daemon_startup_integrity",
            self.audit_log.startup_integrity_report.to_dict(),
        )
        fanotify_ok = self.fanotify_controller.baslat()
        self.state.set_component("fanotify", fanotify_ok)
        if not fanotify_ok:
            logger.warning("fanotify unavailable; component marked degraded")

        try:
            ebpf_ok = self.ebpf_loader.initialize()
        except Exception as exc:
            ebpf_ok = False
            logger.warning("eBPF unavailable; degraded mode: %s", exc)
        self.state.set_component("ebpf", ebpf_ok)

        self.ipc.start()
        self._threads.append(self._spawn(self.ipc.run_forever, "ipc"))
        self._threads.append(self._spawn(self._consume_fanotify_events, "fanotify-events"))
        if ebpf_ok:
            self._threads.append(self._spawn(self._consume_ebpf_events, "ebpf-events"))

    def _spawn(self, target, name: str) -> threading.Thread:
        thread = threading.Thread(target=target, name=f"elyra-{name}", daemon=True)
        thread.start()
        return thread

    def run_forever(self) -> None:
        signal.signal(signal.SIGTERM, lambda *_: self.stop())
        signal.signal(signal.SIGINT, lambda *_: self.stop())
        self._stop.wait()

    def stop(self) -> None:
        logger.info("Stopping Elyra daemon")
        self.fanotify_controller.durdur()
        self.ebpf_loader.shutdown()
        self.ipc.stop()
        self.response_engine.close()
        self._stop.set()

    def _consume_fanotify_events(self) -> None:
        while not self._stop.is_set():
            try:
                event = self._fanotify_events.get(timeout=0.5)
            except queue.Empty:
                continue
            correlation = self.execution_correlation.register_pre_execution(event)
            enriched = {"source": "fanotify", **event, "correlation": correlation}
            self.state.note_event(enriched)
            self._audit_correlation("fanotify", correlation)
            self._execute_correlated_response(correlation, bind=True)

    def _consume_ebpf_events(self) -> None:
        while not self._stop.is_set():
            event = self.ebpf_loader.fetch_event()
            if event:
                summary = self.runtime_telemetry.ingest(event)
                correlation = self.execution_correlation.ingest_runtime_event(event)
                enriched = {
                    "source": "ebpf",
                    **event,
                    "runtime_summary": summary,
                    "correlation": correlation,
                }
                self.state.note_event(enriched)
                self._audit_correlation("ebpf", correlation)
                self._execute_correlated_response(
                    correlation,
                    bind=str(event.get("event_type")) == "PROCESS_EXEC",
                )

    def _execute_correlated_response(
        self, result: dict[str, Any], *, bind: bool
    ) -> None:
        if result.get("accepted") is not True:
            return
        state = result.get("state")
        if not isinstance(state, dict):
            return
        if bind and state.get("correlation_id"):
            try:
                self.response_engine.bind_state(state)
            except ResponseSafetyError as exc:
                logger.info("response target binding unavailable: %s", exc)
        action_result = self.response_engine.execute_recommendation(state)
        pid = state.get("pid")
        correlation_id = state.get("correlation_id")
        if pid and correlation_id:
            self.execution_correlation.record_action_result(
                int(pid), str(correlation_id), action_result.to_dict()
            )

    def _audit_correlation(self, source: str, result: dict[str, Any]) -> None:
        if result.get("accepted") is not True:
            return
        state = result.get("state")
        if not isinstance(state, dict):
            return
        try:
            self.audit_log.record(
                "correlation",
                "state_update",
                {
                    "source": source,
                    "correlation_id": state.get("correlation_id"),
                    "pid": state.get("pid"),
                    "combined_score": state.get("combined_score"),
                    "recommended_action": state.get("recommended_action"),
                    "action_execution_status": state.get(
                        "action_execution_status", "NOT_EXECUTED_STAGE11"
                    ),
                },
            )
        except (OSError, TypeError, ValueError) as exc:
            logger.error("correlation audit record failed: %s", exc)

    def _handle_ipc_action(self, action: str, params: dict, requester: Requester) -> dict:
        logger.info(
            "IPC request: pid=%s uid=%s user=%s action=%s",
            requester.pid,
            requester.uid,
            requester.username,
            action,
        )

        if action == "get_status":
            status = self.state.snapshot(
                correlation_summary=self.execution_correlation.summary()
            )
            status["audit"] = self.audit_log.status()
            return status
        if action == "list_events":
            return {"events": self.state.recent(int(params["limit"]))}
        if action == "list_runtime_states":
            return {"states": self.execution_correlation.list_states(int(params["limit"]))}
        if action == "list_quarantine":
            return {"items": [asdict(record) for record in self.quarantine.list_quarantine()]}
        if action == "get_policy":
            return {
                "mode": self.fanotify_controller.policy.mode,
                "monitored_paths": list(self.fanotify_controller.policy.monitored_paths),
                "excluded_paths": list(self.fanotify_controller.policy.excluded_paths),
                "fail_policy": self.fanotify_controller.policy.default_fail_policy,
                "fail_closed_paths": list(self.fanotify_controller.policy.fail_closed_paths),
                "max_response_seconds": self.fanotify_controller.policy.max_response_seconds,
                "max_preexec_file_bytes": self.fanotify_controller.policy.max_preexec_file_bytes,
            }
        if action == "scan_file":
            target = authorize_manual_scan_path(requester, str(params["path"]))
            scan = self.static_scanner.scan(target)
            result = scan.to_dict()
            result["pre_execution_scoring"] = self.scoring_engine.score(scan).to_dict()
            return result
        if action == "restore_file":
            record, response = self.response_engine.restore(
                str(params["quarantine_id"]),
                params.get("destination"),
                actor=requester.username,
                requester_pid=requester.pid,
            )
            return {**asdict(record), "response_action": response.to_dict()}
        if action == "delete_permanently":
            response = self.response_engine.delete_permanently(
                str(params["quarantine_id"]),
                actor=requester.username,
                requester_pid=requester.pid,
            )
            return {"deleted": True, "response_action": response.to_dict()}
        if action == "update_enforcement_policy":
            mode = str(params["mode"])
            self.fanotify_controller.policy.set_mode(mode)
            self.audit_log.record(
                "policy",
                "enforcement_mode",
                {
                    "changed_by": requester.username,
                    "requester_pid": requester.pid,
                    "new_mode": mode,
                },
            )
            return {"mode": mode}
        raise ValueError(f"Unsupported action: {action}")


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        daemon = ElyraDaemon(
            enforcement="--enforce" in sys.argv,
            execute_responses="--execute-responses" in sys.argv,
        )
        daemon.start()
        daemon.run_forever()
    except (PermissionError, AuditIntegrityError) as exc:
        logger.critical("%s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
