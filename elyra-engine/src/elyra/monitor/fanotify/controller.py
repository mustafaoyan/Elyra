"""Stage 8 fanotify pre-execution controller.

The controller guarantees a best-effort permission response for every valid
permission event, uses separate event and analysis executors, and records the
reason for every allow/deny action.
"""

from __future__ import annotations

import logging
import os
import queue
import stat
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ...analyzer.pre_execution import PreExecutionAnalyzer
from ...audit.audit_logger import AuditLogger
from .policy import FanotifyPolicy
from .syscalls import (
    FAN_ALLOW,
    FAN_DENY,
    FanotifyEvent,
    FanotifyInterface,
    FanotifySystemError,
)

logger = logging.getLogger("elyra.monitor.fanotify.controller")


def _parent_pid(pid: int) -> int | None:
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as stream:
            for line in stream:
                if line.startswith("PPid:"):
                    return int(line.split(":", 1)[1].strip())
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
        return None
    return None


def is_process_or_descendant(pid: int, ancestor_pid: int, max_depth: int = 64) -> bool:
    """Best-effort process ancestry check using procfs."""

    current = pid
    seen: set[int] = set()
    for _ in range(max_depth):
        if current == ancestor_pid:
            return True
        if current <= 1 or current in seen:
            return False
        seen.add(current)
        parent = _parent_pid(current)
        if parent is None:
            return False
        current = parent
    return False


def classify_open_file(fd: int) -> str:
    """Classify the open execution target without changing its file offset."""

    try:
        head = os.pread(fd, 128, 0)
    except OSError:
        return "UNREADABLE"
    if head.startswith(b"\x7fELF"):
        return "ELF"
    if head.startswith(b"#!"):
        return "SCRIPT"
    return "OTHER"


class FanotifyController:
    def __init__(
        self,
        olay_kuyrugu: queue.Queue[dict[str, Any]] | None = None,
        *,
        event_queue: queue.Queue[dict[str, Any]] | None = None,
        interface: FanotifyInterface | None = None,
        policy: FanotifyPolicy | None = None,
        analyzer: PreExecutionAnalyzer | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.interface = interface or FanotifyInterface()
        self.policy = policy or FanotifyPolicy()
        self.analyzer = analyzer or PreExecutionAnalyzer(
            max_w=max(2, self.policy.event_workers // 2),
            timeout=max(0.1, self.policy.max_response_seconds * 0.8),
        )
        self._owns_analyzer = analyzer is None
        self.audit_logger = audit_logger
        self.event_queue = event_queue if event_queue is not None else olay_kuyrugu
        self.event_executor = ThreadPoolExecutor(
            max_workers=self.policy.event_workers,
            thread_name_prefix="ElyraFanotifyEvent",
        )
        self._pending_slots = threading.BoundedSemaphore(
            self.policy.max_pending_events
        )
        self._running = threading.Event()
        self._loop_thread: threading.Thread | None = None
        self.daemon_pid = os.getpid()
        self.marked_targets: list[str] = []

        # Historical attributes retained during the repository migration.
        self.arayuz = self.interface
        self.analizci = self.analyzer
        self.olay_kuyrugu = self.event_queue

    def start(self) -> bool:
        if self._running.is_set():
            return True
        try:
            self.interface.initialize()
            self.marked_targets = self.interface.add_marks(
                self.policy.mark_targets()
            )
        except (FanotifySystemError, OSError, RuntimeError) as exc:
            logger.error("fanotify initialization failed: %s", exc)
            self.interface.close()
            return False
        if not self.marked_targets:
            logger.error("fanotify initialized but no monitored target was marked")
            self.interface.close()
            return False

        for target in self.marked_targets:
            logger.info("fanotify mark active: %s", target)
        self._running.set()
        self._loop_thread = threading.Thread(
            target=self._event_loop,
            name="ElyraFanotifyReader",
            daemon=True,
        )
        self._loop_thread.start()
        return True

    def stop(self) -> None:
        self._running.clear()
        self.interface.close()
        if self._loop_thread and self._loop_thread.is_alive():
            self._loop_thread.join(timeout=2.0)
        self.event_executor.shutdown(wait=True, cancel_futures=False)
        if self._owns_analyzer:
            self.analyzer.close()

    def _event_loop(self) -> None:
        while self._running.is_set():
            try:
                events = self.interface.read_events(timeout=0.25)
            except OSError as exc:
                if self._running.is_set():
                    logger.error("fanotify event read failed: %s", exc)
                continue
            for event in events:
                if event.is_overflow:
                    self._record_overflow(event)
                    continue
                if not event.is_exec_permission:
                    self.interface.close_event_fd(event.fd)
                    continue
                if not self._pending_slots.acquire(blocking=False):
                    self._respond_saturated(event)
                    continue
                future = self.event_executor.submit(self._handle_event, event)
                future.add_done_callback(lambda _future: self._pending_slots.release())

    def _respond_saturated(self, event: FanotifyEvent) -> None:
        logger.critical(
            "fanotify event queue saturated; fail-open response used: %s", event.path
        )
        record = self._base_record(event)
        record.update(
            {
                "requested_decision": "ALLOW_MONITOR",
                "final_action": "ALLOW",
                "kernel_response": "FAN_ALLOW",
                "reason": "EVENT_QUEUE_SATURATED_FAIL_OPEN",
                "response_ok": self.interface.respond(event.fd, FAN_ALLOW),
            }
        )
        self._emit_record(record)

    def _record_overflow(self, event: FanotifyEvent) -> None:
        logger.critical("fanotify queue overflow reported by kernel")
        record = self._base_record(event)
        record.update(
            {
                "requested_decision": "UNKNOWN",
                "final_action": "DEGRADED",
                "kernel_response": "NONE",
                "reason": "FANOTIFY_QUEUE_OVERFLOW",
                "response_ok": True,
            }
        )
        self._emit_record(record)

    def _base_record(self, event: FanotifyEvent) -> dict[str, Any]:
        return {
            "event_type": "PRE_EXECUTION_DECISION",
            "pid": event.pid,
            "path": event.path,
            "mask": event.mask,
            "mode": self.policy.mode,
            "received_monotonic": event.received_monotonic,
            "executable_kind": classify_open_file(event.fd) if event.fd >= 0 else "NONE",
        }

    def _handle_event(self, event: FanotifyEvent) -> None:
        record = self._base_record(event)
        response_sent = False
        response_attempted = False
        response_value = FAN_ALLOW
        try:
            requested_decision, reason, analysis = self._evaluate_event(event)
            final_action = self.policy.get_final_action(requested_decision)
            response_value = FAN_DENY if final_action == "DENY" else FAN_ALLOW
            record.update(
                {
                    "requested_decision": requested_decision,
                    "final_action": final_action,
                    "kernel_response": "FAN_DENY" if response_value == FAN_DENY else "FAN_ALLOW",
                    "reason": reason,
                    "score": analysis.get("score"),
                    "risk_score": analysis.get("risk_score"),
                    "indicators": analysis.get("indicators", []),
                    "analysis_status": analysis.get("scoring_status", analysis.get("scan_status")),
                }
            )
            response_attempted = True
            response_sent = self.interface.respond(event.fd, response_value)
            record["response_ok"] = response_sent
            if not response_sent:
                logger.critical("fanotify permission response write failed: %s", event.path)
            elif response_value == FAN_DENY:
                logger.warning("fanotify DENY: path=%s pid=%s", event.path, event.pid)
            else:
                logger.info("fanotify ALLOW: path=%s pid=%s", event.path, event.pid)
        except (OSError, RuntimeError, ValueError) as exc:
            logger.exception("fanotify event processing failed; fail-open used: %s", exc)
            record.update(
                {
                    "requested_decision": "ALLOW_MONITOR",
                    "final_action": "ALLOW",
                    "kernel_response": "FAN_ALLOW",
                    "reason": "CONTROLLER_EXCEPTION_FAIL_OPEN",
                    "error_type": type(exc).__name__,
                }
            )
        finally:
            if not response_attempted:
                try:
                    response_attempted = True
                    response_sent = self.interface.respond(event.fd, FAN_ALLOW)
                except (OSError, RuntimeError, ValueError) as exc:
                    logger.critical(
                        "final fail-open response failed for fd=%s: %s", event.fd, exc
                    )
                    response_sent = False
                record["response_ok"] = response_sent
                record["kernel_response"] = "FAN_ALLOW"
                record["final_action"] = "ALLOW"
                record.setdefault("reason", "FINAL_GUARD_FAIL_OPEN")
            record["response_latency_ms"] = round(
                (time.monotonic() - event.received_monotonic) * 1000, 3
            )
            self._emit_record(record)

    def _evaluate_event(
        self, event: FanotifyEvent
    ) -> tuple[str, str, dict[str, Any]]:
        if event.parse_error:
            return self._failure_decision(event.path, event.parse_error)
        if event.pid == self.daemon_pid or (
            self.policy.exclude_daemon_descendants
            and is_process_or_descendant(event.pid, self.daemon_pid)
        ):
            return "ALLOW", "ELYRA_PROCESS_EXCLUDED", {}
        if self.policy.is_excluded_path(event.path):
            return "ALLOW", "ELYRA_OR_SYSTEM_PATH_EXCLUDED", {}
        if not self.policy.should_monitor(event.path):
            return "ALLOW", "OUTSIDE_CONFIGURED_MONITORED_PATHS", {}

        try:
            metadata = os.fstat(event.fd)
        except OSError:
            return self._failure_decision(event.path, "EVENT_FSTAT_FAILED")
        if not stat.S_ISREG(metadata.st_mode):
            return "ALLOW", "NON_REGULAR_EXECUTION_TARGET", {}
        if metadata.st_size > self.policy.max_preexec_file_bytes:
            return (
                "ALLOW_MONITOR",
                "LARGE_FILE_DEFERRED_FAIL_OPEN",
                {
                    "score": 0,
                    "risk_score": "0/100",
                    "scoring_status": "DEGRADED",
                    "indicators": [
                        {
                            "rule": "LARGE_FILE_DEFERRED_FAIL_OPEN",
                            "evidence": {
                                "file_size": metadata.st_size,
                                "limit": self.policy.max_preexec_file_bytes,
                            },
                        }
                    ],
                },
            )

        remaining = (
            event.received_monotonic
            + self.policy.max_response_seconds
            - time.monotonic()
        )
        if remaining <= 0:
            return self._failure_decision(event.path, "RESPONSE_DEADLINE_EXCEEDED")

        analysis = self.analyzer.analyze_open_fd_async(
            event.fd,
            event.path or f"/proc/self/fd/{event.fd}",
            timeout=remaining,
        )
        if time.monotonic() >= event.received_monotonic + self.policy.max_response_seconds:
            return self._failure_decision(
                event.path, "RESPONSE_DEADLINE_EXCEEDED", analysis
            )
        if analysis.get("error"):
            return self._failure_decision(
                event.path,
                f"ANALYSIS_{str(analysis['error']).upper()}",
                analysis,
            )
        decision = str(analysis.get("decision", "ALLOW")).upper()
        if decision not in {"ALLOW", "ALLOW_MONITOR", "WARN", "DENY"}:
            return self._failure_decision(event.path, "INVALID_ANALYZER_DECISION", analysis)
        return decision, "EXPLAINABLE_STATIC_SCORING", analysis

    def _failure_decision(
        self,
        path: str | None,
        reason: str,
        analysis: dict[str, Any] | None = None,
    ) -> tuple[str, str, dict[str, Any]]:
        fail_policy = self.policy.get_fail_policy(path)
        if fail_policy == "FAIL_CLOSED" and self.policy.is_enforcement_active():
            logger.critical("%s: explicit FAIL_CLOSED used for %s", reason, path)
            return "DENY", f"{reason}_FAIL_CLOSED", analysis or {}
        logger.critical("%s: FAIL_OPEN used for %s", reason, path)
        return "ALLOW_MONITOR", f"{reason}_FAIL_OPEN", analysis or {}

    def _emit_record(self, record: dict[str, Any]) -> None:
        if self.audit_logger is not None:
            try:
                self.audit_logger.record("fanotify", "pre_execution_decision", record)
            except (OSError, ValueError, TypeError) as exc:
                logger.error("fanotify audit record failed: %s", exc)
        if self.event_queue is not None:
            self.event_queue.put(dict(record))

    # Historical method names retained for compatibility.
    baslat = start
    durdur = stop
    dongu_baslat = _event_loop
    olay_isle = _handle_event
