from __future__ import annotations

import os
import queue
import threading
import time
from pathlib import Path

from elliot.audit.audit_logger import AuditLogger
from elliot.monitor.fanotify.controller import FanotifyController
from elliot.monitor.fanotify.policy import FanotifyPolicy
from elliot.monitor.fanotify.syscalls import (
    FAN_ALLOW,
    FAN_DENY,
    FAN_OPEN_EXEC_PERM,
    FANOTIFY_METADATA_VERSION,
    FanotifyEvent,
)


class FakeInterface:
    def __init__(self, events=None):
        self.events = list(events or [])
        self.responses: list[tuple[int, int]] = []
        self.lock = threading.Lock()
        self.closed = False

    def initialize(self):
        return True

    def add_marks(self, paths):
        return list(paths)

    def read_events(self, timeout=0.25):
        with self.lock:
            if self.events:
                result = self.events
                self.events = []
                return result
        time.sleep(min(timeout, 0.01))
        return []

    def respond(self, fd, response):
        with self.lock:
            self.responses.append((fd, response))
        try:
            os.close(fd)
        except OSError:
            pass
        return True

    def close_event_fd(self, fd):
        try:
            os.close(fd)
        except OSError:
            pass

    def close(self):
        self.closed = True


class FakeAnalyzer:
    def __init__(self, result, delay=0.0):
        self.result = result
        self.delay = delay
        self.calls = []

    def analyze_open_fd_async(self, fd, original_path, timeout=None):
        self.calls.append((fd, original_path, timeout))
        if self.delay:
            time.sleep(self.delay)
        return dict(self.result)


ALLOW_RESULT = {
    "score": 0,
    "risk_score": "0/100",
    "decision": "ALLOW",
    "scoring_status": "OK",
    "indicators": [],
}
DENY_RESULT = {
    "score": 90,
    "risk_score": "90/100",
    "decision": "DENY",
    "scoring_status": "OK",
    "indicators": [{"rule": "SAFE_SYNTHETIC_DENY_FIXTURE"}],
}


def _event(path: Path, pid: int = 99999) -> FanotifyEvent:
    fd = os.open(path, os.O_RDONLY)
    return FanotifyEvent(
        fd=fd,
        pid=pid,
        path=str(path),
        mask=FAN_OPEN_EXEC_PERM,
        event_len=24,
        metadata_len=24,
        version=FANOTIFY_METADATA_VERSION,
        received_monotonic=time.monotonic(),
    )


def _policy(tmp_path, **overrides):
    values = dict(
        mode="ENFORCEMENT",
        monitored_paths=[str(tmp_path)],
        excluded_paths=[],
        fail_closed_paths=[],
        exclude_daemon_descendants=False,
        max_response_seconds=0.2,
    )
    values.update(overrides)
    return FanotifyPolicy(**values)


def test_harmless_event_is_allowed_and_audited(tmp_path):
    candidate = tmp_path / "safe.bin"
    candidate.write_bytes(b"safe")
    interface = FakeInterface()
    events = queue.Queue()
    controller = FanotifyController(
        event_queue=events,
        interface=interface,
        policy=_policy(tmp_path),
        analyzer=FakeAnalyzer(ALLOW_RESULT),
        audit_logger=AuditLogger(str(tmp_path / "audit")),
    )
    controller._handle_event(_event(candidate))

    record = events.get_nowait()
    assert interface.responses[0][1] == FAN_ALLOW
    assert record["final_action"] == "ALLOW"
    assert record["reason"] == "EXPLAINABLE_STATIC_SCORING"
    assert controller.audit_logger.verify_chain() == (True, 1)


def test_safe_synthetic_deny_fixture_is_denied_in_enforcement(tmp_path):
    candidate = tmp_path / "safe.bin"
    candidate.write_bytes(b"safe")
    interface = FakeInterface()
    events = queue.Queue()
    controller = FanotifyController(
        event_queue=events,
        interface=interface,
        policy=_policy(tmp_path),
        analyzer=FakeAnalyzer(DENY_RESULT),
    )
    controller._handle_event(_event(candidate))
    assert interface.responses[0][1] == FAN_DENY
    assert events.get_nowait()["final_action"] == "DENY"


def test_monitor_only_converts_deny_to_allow(tmp_path):
    candidate = tmp_path / "safe.bin"
    candidate.write_bytes(b"safe")
    interface = FakeInterface()
    events = queue.Queue()
    controller = FanotifyController(
        event_queue=events,
        interface=interface,
        policy=_policy(tmp_path, mode="MONITOR_ONLY"),
        analyzer=FakeAnalyzer(DENY_RESULT),
    )
    controller._handle_event(_event(candidate))
    record = events.get_nowait()
    assert record["requested_decision"] == "DENY"
    assert record["final_action"] == "ALLOW"
    assert interface.responses[0][1] == FAN_ALLOW


def test_analysis_deadline_failure_is_fail_open_by_default(tmp_path):
    candidate = tmp_path / "safe.bin"
    candidate.write_bytes(b"safe")
    interface = FakeInterface()
    events = queue.Queue()
    controller = FanotifyController(
        event_queue=events,
        interface=interface,
        policy=_policy(tmp_path, max_response_seconds=0.01),
        analyzer=FakeAnalyzer(DENY_RESULT, delay=0.02),
    )
    controller._handle_event(_event(candidate))
    record = events.get_nowait()
    assert interface.responses[0][1] == FAN_ALLOW
    assert record["reason"] == "RESPONSE_DEADLINE_EXCEEDED_FAIL_OPEN"


def test_elliot_own_pid_is_allowed_without_analysis(tmp_path):
    candidate = tmp_path / "safe.bin"
    candidate.write_bytes(b"safe")
    interface = FakeInterface()
    analyzer = FakeAnalyzer(DENY_RESULT)
    events = queue.Queue()
    controller = FanotifyController(
        event_queue=events,
        interface=interface,
        policy=_policy(tmp_path),
        analyzer=analyzer,
    )
    controller._handle_event(_event(candidate, pid=os.getpid()))
    assert analyzer.calls == []
    assert interface.responses[0][1] == FAN_ALLOW
    assert events.get_nowait()["reason"] == "ELLIOT_PROCESS_EXCLUDED"


def test_large_file_policy_defers_and_allows(tmp_path):
    candidate = tmp_path / "large.bin"
    candidate.write_bytes(b"0123456789")
    interface = FakeInterface()
    analyzer = FakeAnalyzer(DENY_RESULT)
    events = queue.Queue()
    controller = FanotifyController(
        event_queue=events,
        interface=interface,
        policy=_policy(tmp_path, max_preexec_file_bytes=4),
        analyzer=analyzer,
    )
    controller._handle_event(_event(candidate))
    record = events.get_nowait()
    assert analyzer.calls == []
    assert interface.responses[0][1] == FAN_ALLOW
    assert record["reason"] == "LARGE_FILE_DEFERRED_FAIL_OPEN"


def test_concurrent_events_all_receive_responses_without_shared_pool_deadlock(tmp_path):
    paths = []
    for index in range(12):
        candidate = tmp_path / f"safe-{index}.bin"
        candidate.write_bytes(b"safe")
        paths.append(candidate)
    kernel_events = [_event(path) for path in paths]
    interface = FakeInterface(kernel_events)
    records = queue.Queue()
    controller = FanotifyController(
        event_queue=records,
        interface=interface,
        policy=_policy(
            tmp_path,
            event_workers=4,
            max_pending_events=4,
            max_response_seconds=1.0,
        ),
        analyzer=FakeAnalyzer(ALLOW_RESULT, delay=0.01),
    )
    assert controller.start() is True
    deadline = time.monotonic() + 3.0
    while len(interface.responses) < len(kernel_events) and time.monotonic() < deadline:
        time.sleep(0.01)
    controller.stop()

    assert len(interface.responses) == len(kernel_events)
    assert all(response == FAN_ALLOW for _, response in interface.responses)
    assert records.qsize() == len(kernel_events)
