"""Harmless native notification-to-analysis check; never executes a sample."""

from __future__ import annotations

import os
import threading
import time

import pytest

from elyra.monitor.windows.controller import WindowsMonitorController
from elyra.monitor.windows.policy import WindowsMonitorPolicy
from elyra.service.windows_local import WindowsLocalService


@pytest.mark.integration
@pytest.mark.skipif(os.name != "nt", reason="ReadDirectoryChangesW needs native Windows")
def test_native_notifications_reach_shared_static_scanner(tmp_path):
    ready = threading.Event()
    records = []

    def receive(record):
        if record.status == "ANALYZED" and record.event.path.endswith(".txt"):
            records.append(record.to_dict())
            ready.set()

    controller = WindowsMonitorController(
        WindowsMonitorPolicy(monitored_paths=[str(tmp_path)], excluded_paths=[],
                             analysis_workers=1, max_pending_events=16,
                             retry_attempts=2, retry_delay_seconds=0.05),
        event_sink=receive,
    )
    service = WindowsLocalService(monitor=controller)
    try:
        assert service.start(), controller.status()
        assert controller.status()["backend"]["active_backend"] == "ReadDirectoryChangesBackend"
        # No fake callback injection: the native directory API must deliver a
        # real creation/write notification. Repeated unique benign files cover
        # the small startup race before the worker enters its first native read.
        deadline = time.monotonic() + 8.0
        index = 0
        while not ready.is_set() and time.monotonic() < deadline:
            (tmp_path / f"harmless-{index}.txt").write_bytes(b"%PDF-1.4\nHarmless signature fixture\n")
            index += 1
            ready.wait(0.1)
        assert ready.is_set(), controller.status()
        automatic = records[0]["analysis"]
        assert records[0]["event"]["provider"] == "READ_DIRECTORY_CHANGES_W"
        assert automatic["static_scan"]["mime_extension_consistency"] == "INCONSISTENT"
        assert automatic["pre_execution_scoring"]["category_scores"]["static"] > 0
        assert automatic["enforced_action"] == "NONE"
        assert automatic["monitor_mode"] == "MONITOR_ONLY"
        assert automatic["score_is_probability"] is False
        # Stop capture and drain queued work before the manual comparison so
        # the test also exercises native-handle and worker shutdown.
        service.stop()
        manual = service.scan_file(automatic["path"])
        for key in ("assessment", "risk_score", "pre_execution_scoring", "reasons"):
            assert manual[key] == automatic[key]
        assert manual["entropy_summary"] == automatic["static_scan"]["entropy_summary"]
        assert not controller.status()["active"]
    finally:
        service.stop()
