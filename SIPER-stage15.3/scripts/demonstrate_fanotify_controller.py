#!/usr/bin/env python3
"""Safe Stage 8 controller demonstration with no kernel hooks or root.

The script uses harmless temporary files and a fake syscall boundary.  It proves
controller policy, response guarantees and concurrency; it does not claim real
fanotify kernel support.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

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


class DemoInterface:
    def __init__(self, events=None) -> None:
        self.events = list(events or [])
        self.responses: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def initialize(self) -> bool:
        return True

    def add_marks(self, paths):
        return list(paths)

    def read_events(self, timeout=0.25):
        with self._lock:
            if self.events:
                events = self.events
                self.events = []
                return events
        time.sleep(min(timeout, 0.01))
        return []

    def respond(self, fd, response):
        with self._lock:
            self.responses.append(
                {"fd": fd, "response": "FAN_DENY" if response == FAN_DENY else "FAN_ALLOW"}
            )
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
        return None


class DemoAnalyzer:
    def __init__(self, result: dict[str, Any], delay: float = 0.0) -> None:
        self.result = result
        self.delay = delay
        self.calls = 0

    def analyze_open_fd_async(self, fd, original_path, timeout=None):
        self.calls += 1
        if self.delay:
            time.sleep(self.delay)
        return dict(self.result)


def event_for(path: Path, pid: int = 99123) -> FanotifyEvent:
    return FanotifyEvent(
        fd=os.open(path, os.O_RDONLY),
        pid=pid,
        path=str(path),
        mask=FAN_OPEN_EXEC_PERM,
        event_len=24,
        metadata_len=24,
        version=FANOTIFY_METADATA_VERSION,
        received_monotonic=time.monotonic(),
    )


def policy(root: Path, *, mode: str = "ENFORCEMENT", **kwargs) -> FanotifyPolicy:
    return FanotifyPolicy(
        mode=mode,
        monitored_paths=[str(root)],
        excluded_paths=[],
        fail_closed_paths=[],
        exclude_daemon_descendants=False,
        **kwargs,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    allow_result = {
        "score": 0,
        "risk_score": "0/100",
        "decision": "ALLOW",
        "scoring_status": "OK",
        "indicators": [],
    }
    deny_result = {
        "score": 90,
        "risk_score": "90/100",
        "decision": "DENY",
        "scoring_status": "OK",
        "indicators": [{"rule": "SAFE_SYNTHETIC_DENY_FIXTURE"}],
    }

    results: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="elliot-stage8-controller-") as temp:
        root = Path(temp)
        safe_file = root / "safe.bin"
        safe_file.write_bytes(b"harmless temporary bytes")

        # Monitor-only must never deny at the kernel boundary.
        interface = DemoInterface()
        records: queue.Queue[dict[str, Any]] = queue.Queue()
        controller = FanotifyController(
            event_queue=records,
            interface=interface,
            policy=policy(root, mode="MONITOR_ONLY"),
            analyzer=DemoAnalyzer(deny_result),
        )
        controller._handle_event(event_for(safe_file))
        record = records.get_nowait()
        ok = record["requested_decision"] == "DENY" and record["final_action"] == "ALLOW"
        results.append({"scenario": "monitor_only_never_denies", "status": "OK" if ok else "FAIL"})

        # Enforcement deny path is reachable using a labelled synthetic result.
        interface = DemoInterface()
        records = queue.Queue()
        controller = FanotifyController(
            event_queue=records,
            interface=interface,
            policy=policy(root),
            analyzer=DemoAnalyzer(deny_result),
        )
        controller._handle_event(event_for(safe_file))
        record = records.get_nowait()
        ok = record["final_action"] == "DENY" and interface.responses[0]["response"] == "FAN_DENY"
        results.append({"scenario": "enforcement_deny_path", "status": "OK" if ok else "FAIL"})

        # A missed response deadline must fail open by default.
        interface = DemoInterface()
        records = queue.Queue()
        controller = FanotifyController(
            event_queue=records,
            interface=interface,
            policy=policy(root, max_response_seconds=0.01),
            analyzer=DemoAnalyzer(deny_result, delay=0.02),
        )
        controller._handle_event(event_for(safe_file))
        record = records.get_nowait()
        ok = record["final_action"] == "ALLOW" and record["reason"].endswith("FAIL_OPEN")
        results.append({"scenario": "deadline_failure_fail_open", "status": "OK" if ok else "FAIL"})

        # Self events bypass analysis and are allowed.
        interface = DemoInterface()
        records = queue.Queue()
        analyzer = DemoAnalyzer(deny_result)
        self_policy = policy(root)
        self_policy.exclude_daemon_descendants = True
        controller = FanotifyController(
            event_queue=records,
            interface=interface,
            policy=self_policy,
            analyzer=analyzer,
        )
        controller._handle_event(event_for(safe_file, pid=os.getpid()))
        record = records.get_nowait()
        ok = analyzer.calls == 0 and record["reason"] == "ELLIOT_PROCESS_EXCLUDED"
        results.append({"scenario": "elliot_self_exclusion", "status": "OK" if ok else "FAIL"})

        # Concurrent event handling uses a separate executor and responds to all.
        concurrent_files = []
        for index in range(12):
            item = root / f"concurrent-{index}.bin"
            item.write_bytes(b"safe")
            concurrent_files.append(item)
        kernel_events = [event_for(item) for item in concurrent_files]
        interface = DemoInterface(kernel_events)
        records = queue.Queue()
        audit = AuditLogger(str(root / "audit"))
        controller = FanotifyController(
            event_queue=records,
            interface=interface,
            policy=policy(
                root,
                event_workers=4,
                max_pending_events=4,
                max_response_seconds=1.0,
            ),
            analyzer=DemoAnalyzer(allow_result, delay=0.01),
            audit_logger=audit,
        )
        started = controller.start()
        deadline = time.monotonic() + 3.0
        while len(interface.responses) < len(kernel_events) and time.monotonic() < deadline:
            time.sleep(0.01)
        controller.stop()
        ok = (
            started
            and len(interface.responses) == len(kernel_events)
            and records.qsize() == len(kernel_events)
            and audit.verify_chain() == (True, len(kernel_events))
        )
        results.append({"scenario": "concurrent_events_all_responded_and_audited", "status": "OK" if ok else "FAIL"})

    overall = "OK" if all(item["status"] == "OK" for item in results) else "FAIL"
    evidence = {
        "timestamp_utc": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "method": "safe fake syscall boundary; harmless temporary files; no root, kernel hook, network listener or malware",
        "results": results,
        "overall_status": overall,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for item in results:
        print(f"{item['scenario']}: {item['status']}")
    print(f"overall_status: {overall}")
    print(f"Evidence written to: {output}")
    return 0 if overall == "OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
