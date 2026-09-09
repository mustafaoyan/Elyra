from __future__ import annotations

import struct
import threading
import os
from concurrent.futures import Executor, Future
from pathlib import Path

import pytest

from elliot.monitor.windows.backends import EtwBackend, ReadDirectoryChangesBackend
from elliot.monitor.windows.controller import WindowsMonitorController
from elliot.monitor.windows.entropy import WindowsEntropyAnalyzer
from elliot.monitor.windows.events import FILE_MODIFIED, OVERFLOW, WindowsMonitorEvent
from elliot.monitor.windows.policy import WindowsMonitorPolicy
from elliot.gui.model import WindowsModel
from elliot.service.windows_local import WindowsLocalService


class ImmediateExecutor(Executor):
    def submit(self, fn, /, *args, **kwargs):
        future = Future()
        try:
            future.set_result(fn(*args, **kwargs))
        except Exception as exc:
            future.set_exception(exc)
        return future


class FakeBackend:
    def __init__(self) -> None:
        self.callback = None
        self.active = False

    def start(self, callback):
        self.callback = callback
        self.active = True
        return True

    def stop(self):
        self.active = False

    def status(self):
        return {"active": self.active, "local_only": True}


class FakeEntropyResult:
    status = "ANALYZED"
    reason = None

    def to_dict(self):
        return {"status": "ANALYZED", "entropy": {"whole_file_entropy": 7.5}}


class FakeAnalyzer:
    def __init__(self) -> None:
        self.paths: list[str] = []

    def analyze(self, path):
        self.paths.append(str(path))
        return FakeEntropyResult()


def test_windows_policy_is_monitor_only_and_bounded(tmp_path: Path) -> None:
    policy = WindowsMonitorPolicy(
        monitored_paths=[str(tmp_path / "watched")],
        excluded_paths=[str(tmp_path / "watched" / "private")],
    )
    assert policy.should_monitor(tmp_path / "watched" / "file.bin") is True
    assert policy.should_monitor(tmp_path / "watched" / "private" / "file.bin") is False
    with pytest.raises(ValueError, match="minifilter"):
        WindowsMonitorPolicy(monitor_only=False)


def test_windows_entropy_uses_canonical_engine_for_regular_file(tmp_path: Path) -> None:
    target = tmp_path / "entropy.bin"
    target.write_bytes(bytes(range(256)) * 4)
    result = WindowsEntropyAnalyzer(
        filesystem_type_resolver=lambda _: "NTFS",
        retry_attempts=0,
    ).analyze(target)
    assert result.status == "ANALYZED"
    assert result.is_ntfs is True
    assert result.entropy is not None
    assert result.entropy["whole_file_entropy"] > 7.0


def test_etw_backend_is_explicit_on_non_windows() -> None:
    backend = EtwBackend(is_windows=lambda: False)
    assert backend.start(lambda _event: None) is False
    assert backend.status()["degraded_reason"] == "WINDOWS_ONLY"
    assert backend.status()["local_only"] is True


def test_directory_change_record_parser_rejects_invalid_bounds() -> None:
    good_name = "report.bin".encode("utf-16-le")
    record = struct.pack("<III", 0, 3, len(good_name)) + good_name
    assert ReadDirectoryChangesBackend.parse_native_records(record) == [(3, "report.bin")]
    with pytest.raises(OSError, match="filename length"):
        ReadDirectoryChangesBackend.parse_native_records(struct.pack("<III", 0, 3, 5) + b"abcde")


@pytest.mark.skipif(os.name != "nt", reason="ReadDirectoryChangesW is a Windows kernel API")
def test_directory_changes_backend_receives_native_local_event(tmp_path: Path) -> None:
    observed: list[WindowsMonitorEvent] = []
    received = threading.Event()

    def on_event(event: WindowsMonitorEvent) -> None:
        observed.append(event)
        if event.path and Path(event.path).name == "native-change.bin":
            received.set()

    backend = ReadDirectoryChangesBackend([str(tmp_path)], buffer_size=4096)
    assert backend.start(on_event) is True
    try:
        (tmp_path / "native-change.bin").write_bytes(b"harmless local monitor fixture")
        assert received.wait(5.0), backend.status()
    finally:
        backend.stop()
    assert any(event.provider == "READ_DIRECTORY_CHANGES_W" for event in observed)


def test_controller_analyzes_only_scoped_entropy_events(tmp_path: Path) -> None:
    watched = tmp_path / "watched"
    watched.mkdir()
    backend = FakeBackend()
    analyzer = FakeAnalyzer()
    controller = WindowsMonitorController(
        WindowsMonitorPolicy(monitored_paths=[str(watched)], excluded_paths=[]),
        backend=backend,
        analyzer=analyzer,
        executor=ImmediateExecutor(),
    )
    assert controller.start() is True
    event = WindowsMonitorEvent(event_type=FILE_MODIFIED, path=str(watched / "sample.bin"))
    controller.handle_event(event)
    assert analyzer.paths == [str(watched / "sample.bin")]
    records = controller.recent_records()
    assert records[-1]["status"] == "ANALYZED"
    status = controller.status()
    assert status["local_only"] is True
    assert status["monitor_mode"] == "MONITOR_ONLY"
    controller.stop()


def test_controller_reports_overflow_without_inventing_analysis(tmp_path: Path) -> None:
    watched = tmp_path / "watched"
    watched.mkdir()
    controller = WindowsMonitorController(
        WindowsMonitorPolicy(monitored_paths=[str(watched)], excluded_paths=[]),
        backend=FakeBackend(),
        analyzer=FakeAnalyzer(),
        executor=ImmediateExecutor(),
    )
    controller.handle_event(WindowsMonitorEvent(event_type=OVERFLOW, path=str(watched)))
    record = controller.recent_records()[-1]
    assert record["status"] == "RECOVERY_REQUIRED"
    assert record["analysis"] is None


class FakeLocalWindowsService:
    def __init__(self) -> None:
        self.started = False
        self.stopped = False

    def start(self) -> bool:
        self.started = True
        return True

    def stop(self) -> None:
        self.stopped = True

    @staticmethod
    def get_status() -> dict[str, object]:
        return {"platform": "WINDOWS", "local_only": True, "windows_monitor_active": True}

    @staticmethod
    def list_events(_limit: int) -> dict[str, list[object]]:
        return {"events": []}

    @staticmethod
    def list_quarantine() -> dict[str, list[object]]:
        return {"items": []}

    @staticmethod
    def get_policy() -> dict[str, object]:
        return {"mode": "MONITOR_ONLY", "local_only": True}

    @staticmethod
    def scan_file(path: str) -> dict[str, object]:
        return {"path": path, "local_only": True}


def test_windows_model_uses_in_process_local_service_without_ipc() -> None:
    service = FakeLocalWindowsService()
    model = WindowsModel(service=service)  # type: ignore[arg-type]
    snapshot = model.fetch_dashboard()
    assert service.started is True
    assert snapshot["connected"] is True
    assert snapshot["status"]["platform"] == "WINDOWS"
    assert model.scan_file(r"C:\\Users\\operator\\Downloads\\sample.bin")["ok"] is True
    model.close()
    assert service.stopped is True


class FakeWindowsMonitor:
    @staticmethod
    def status() -> dict[str, object]:
        return {
            "active": True,
            "recent_record_count": 0,
            "backend": {"active_backend": "ReadDirectoryChangesBackend"},
        }

    @staticmethod
    def recent_records(_limit: int) -> list[dict[str, object]]:
        return []

    @staticmethod
    def policy_snapshot() -> dict[str, object]:
        return {"monitored_paths": [], "excluded_paths": [], "max_file_bytes": 1024}

    @staticmethod
    def start() -> bool:
        return True

    @staticmethod
    def stop() -> None:
        return None


def test_windows_local_service_never_relabels_a_directory_watcher_as_ebpf() -> None:
    service = WindowsLocalService(monitor=FakeWindowsMonitor())  # type: ignore[arg-type]
    status = service.get_status()
    assert status["monitor_kind"] == "ReadDirectoryChangesW"
    assert status["windows_monitor_active"] is True
    assert status["ebpf_active"] is False
    assert status["fanotify_active"] is False
    assert status["local_only"] is True
