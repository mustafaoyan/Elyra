"""Bounded, local-only Windows monitoring orchestration.

This controller turns local ETW/minifilter-adapter or ReadDirectoryChangesW
notifications into bounded static-analysis and scoring jobs. It intentionally has no
network client, cloud queue, or remote logging path.  User-space Windows
observation is monitor-only; execution blocking belongs in a separately
signed and reviewed minifilter implementation.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from concurrent.futures import Executor, ThreadPoolExecutor
from dataclasses import asdict
from typing import Callable, Deque

from .backends import AutoWindowsBackend, WindowsMonitorBackend
from .analysis import WindowsStaticAnalyzer
from .entropy import WindowsEntropyAnalyzer
from .events import OVERFLOW, WindowsMonitorEvent, WindowsMonitorRecord
from .policy import WindowsMonitorPolicy


logger = logging.getLogger("elliot.monitor.windows.controller")
RecordSink = Callable[[WindowsMonitorRecord], None]


class WindowsMonitorController:
    """Coordinate a local Windows event backend and canonical static analysis.

    The pending-job semaphore is acquired *before* an executor job is created;
    event bursts therefore have a visible bounded-loss result instead of
    unbounded memory growth.  Every retained record says whether it was merely
    observed, analysed, skipped, or dropped and can safely be displayed in the
    ELLIOT GUI without implying enforcement.
    """

    def __init__(
        self,
        policy: WindowsMonitorPolicy | None = None,
        *,
        backend: WindowsMonitorBackend | None = None,
        analyzer: WindowsStaticAnalyzer | WindowsEntropyAnalyzer | None = None,
        event_sink: RecordSink | None = None,
        executor: Executor | None = None,
        clock_ns: Callable[[], int] = time.monotonic_ns,
    ) -> None:
        self.policy = policy or WindowsMonitorPolicy()
        self.backend = backend or AutoWindowsBackend(
            self.policy.backend_roots(), recursive=self.policy.recursive
        )
        self.analyzer = analyzer or WindowsStaticAnalyzer(
            max_file_bytes=self.policy.max_file_bytes,
            retry_attempts=self.policy.retry_attempts,
            retry_delay_seconds=self.policy.retry_delay_seconds,
        )
        self._event_sink = event_sink
        self._executor = executor or ThreadPoolExecutor(
            max_workers=self.policy.analysis_workers,
            thread_name_prefix="elliot-windows-analysis",
        )
        self._owns_executor = executor is None
        self._clock_ns = clock_ns
        self._pending = threading.BoundedSemaphore(self.policy.max_pending_events)
        self._records: Deque[WindowsMonitorRecord] = deque(
            maxlen=self.policy.max_reported_events
        )
        self._lock = threading.Lock()
        self._running = False
        self._dropped_backpressure = 0
        self._out_of_scope = 0
        self._analysis_errors = 0

    def start(self) -> bool:
        """Start local collection; return False with explicit backend status on failure."""

        with self._lock:
            if self._running:
                return True
        started = self.backend.start(self.handle_event)
        with self._lock:
            self._running = bool(started)
        return bool(started)

    def stop(self) -> None:
        with self._lock:
            self._running = False
        self.backend.stop()
        if self._owns_executor:
            self._executor.shutdown(wait=True, cancel_futures=False)

    def handle_event(self, event: WindowsMonitorEvent) -> None:
        """Accept one local backend event without blocking its notification thread."""

        if event.event_type == OVERFLOW:
            self._append(
                WindowsMonitorRecord(
                    event=event,
                    status="RECOVERY_REQUIRED",
                    reason="EVENT_BUFFER_OVERFLOW_RESCAN_RECOMMENDED",
                )
            )
            return
        if not self.policy.should_monitor(event.path):
            with self._lock:
                self._out_of_scope += 1
            self._append(
                WindowsMonitorRecord(
                    event=event,
                    status="IGNORED_OUT_OF_SCOPE",
                    reason="PATH_IS_NOT_IN_LOCAL_MONITOR_POLICY",
                )
            )
            return
        if not event.is_entropy_eligible:
            self._append(
                WindowsMonitorRecord(
                    event=event,
                    status="OBSERVED",
                    reason="EVENT_TYPE_DOES_NOT_REQUIRE_STATIC_ANALYSIS",
                )
            )
            return
        if not self._pending.acquire(blocking=False):
            with self._lock:
                self._dropped_backpressure += 1
            self._append(
                WindowsMonitorRecord(
                    event=event,
                    status="DROPPED_BACKPRESSURE",
                    reason="PENDING_ANALYSIS_LIMIT_REACHED",
                )
            )
            return
        try:
            self._executor.submit(self._analyze_event, event)
        except RuntimeError as exc:
            self._pending.release()
            with self._lock:
                self._analysis_errors += 1
            self._append(
                WindowsMonitorRecord(
                    event=event,
                    status="ERROR",
                    reason=f"ANALYSIS_EXECUTOR_UNAVAILABLE:{type(exc).__name__}",
                )
            )

    def _analyze_event(self, event: WindowsMonitorEvent) -> None:
        started = self._clock_ns()
        try:
            result = self.analyzer.analyze(event.path or "")
            analysis = result.to_dict()
            status = "ANALYZED" if result.status == "ANALYZED" else result.status
            record = WindowsMonitorRecord(
                event=event,
                status=status,
                analysis=analysis,
                reason=result.reason,
                processing_latency_ms=round((self._clock_ns() - started) / 1_000_000, 3),
            )
        except Exception as exc:  # Boundary protection for capture threads.
            logger.exception("local Windows static analysis failed")
            with self._lock:
                self._analysis_errors += 1
            record = WindowsMonitorRecord(
                event=event,
                status="ERROR",
                reason=f"ANALYSIS_FAILED:{type(exc).__name__}",
                processing_latency_ms=round((self._clock_ns() - started) / 1_000_000, 3),
            )
        finally:
            self._pending.release()
        self._append(record)

    def _append(self, record: WindowsMonitorRecord) -> None:
        with self._lock:
            self._records.append(record)
        if self._event_sink is not None:
            try:
                self._event_sink(record)
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                logger.warning("Windows monitor record sink rejected local record: %s", exc)

    def recent_records(self, limit: int = 50) -> list[dict[str, object]]:
        if not 1 <= limit <= self.policy.max_reported_events:
            raise ValueError("limit must fit within the configured record capacity")
        with self._lock:
            return [record.to_dict() for record in list(self._records)[-limit:]]

    def status(self) -> dict[str, object]:
        """Return a local capability/status snapshot suitable for the GUI."""

        with self._lock:
            return {
                "platform": "WINDOWS",
                "active": self._running,
                "local_only": True,
                "monitor_mode": "MONITOR_ONLY",
                "enforcement_capability": "SIGNED_MINIFILTER_REQUIRED",
                "monitored_paths": list(self.policy.monitored_paths),
                "excluded_paths": list(self.policy.excluded_paths),
                "recent_record_count": len(self._records),
                "dropped_backpressure": self._dropped_backpressure,
                "out_of_scope_events": self._out_of_scope,
                "analysis_errors": self._analysis_errors,
                "backend": self.backend.status(),
            }

    def policy_snapshot(self) -> dict[str, object]:
        """Expose configuration for local diagnostics without a remote endpoint."""

        return asdict(self.policy)
