from __future__ import annotations

import io
import os
from concurrent.futures import Executor, Future
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace

import pytest

from elliot.analyzer.entropy import EntropyEngine, FileAccessError
from elliot.analyzer.static_analyzer import StaticFileScanner, StaticScanResult
from elliot.monitor.windows import analysis as analysis_module
from elliot.monitor.windows import policy as policy_module
from elliot.monitor.windows.analysis import WindowsStaticAnalyzer, _BoundedEntropyEngine
from elliot.monitor.windows.backends import ReadDirectoryChangesBackend
from elliot.monitor.windows.controller import WindowsMonitorController
from elliot.monitor.windows.entropy import WindowsEntropyAnalyzer
from elliot.monitor.windows.events import FILE_MODIFIED, WindowsMonitorEvent
from elliot.monitor.windows.policy import WindowsMonitorPolicy
from elliot.service.windows_local import WindowsLocalService


class ImmediateExecutor(Executor):
    def submit(self, fn, /, *args, **kwargs):
        future = Future()
        future.set_result(fn(*args, **kwargs))
        return future


class FakeBackend:
    def start(self, _callback):
        return True

    def stop(self):
        pass

    def status(self):
        return {"active": True}


def controller_for(tmp_path, **kwargs):
    return WindowsMonitorController(
        WindowsMonitorPolicy(monitored_paths=[str(tmp_path)], excluded_paths=[],
                             retry_attempts=0, retry_delay_seconds=0),
        backend=FakeBackend(), executor=ImmediateExecutor(), **kwargs)


def test_default_controller_extracts_static_evidence_and_reuses_entropy(tmp_path, monkeypatch):
    target = tmp_path / "harmless-signature.txt"
    target.write_bytes(b"%PDF-1.4\nHarmless signature-only fixture\n")
    controller = controller_for(tmp_path)
    assert isinstance(controller.analyzer, WindowsStaticAnalyzer)
    engine = controller.analyzer.scanner.entropy_engine
    real_analyze = engine.analyze
    calls = []

    def count_entropy(path):
        calls.append(path)
        return real_analyze(path)

    monkeypatch.setattr(engine, "analyze", count_entropy)
    controller.handle_event(WindowsMonitorEvent(FILE_MODIFIED, str(target)))
    record = controller.recent_records()[-1]
    analysis = record["analysis"]
    assert record["status"] == "ANALYZED"
    assert len(calls) == 1
    assert analysis["static_scan"]["mime_extension_consistency"] == "INCONSISTENT"
    assert analysis["pre_execution_scoring"]["category_scores"]["static"] > 0
    assert analysis["entropy"]["whole_file_entropy"] == analysis["static_scan"]["entropy_summary"]["whole_file_entropy"]
    assert analysis["entropy"]["reported_blocks"] == analysis["static_scan"]["block_entropies"]
    assert record["enforced_action"] == "NONE"


def test_manual_and_automatic_scans_share_analyzer_and_evidence(tmp_path):
    target = tmp_path / "sample.txt"
    target.write_text("A harmless local document.\n" * 16, encoding="utf-8")
    controller = controller_for(tmp_path)
    service = WindowsLocalService(monitor=controller)
    assert service.analyzer is controller.analyzer
    assert service.scanner is controller.analyzer.scanner
    assert service.scoring_engine is controller.analyzer.scoring_engine
    manual = service.scan_file(str(target))
    controller.handle_event(WindowsMonitorEvent(FILE_MODIFIED, str(target)))
    event = service.list_events()["events"][-1]
    for key in ("assessment", "risk_score", "recommended_decision", "reasons", "pre_execution_scoring"):
        assert manual[key] == event[key]
    manual_static = dict(manual["static_scan"])
    event_static = dict(event["static_scan"])
    manual_static.pop("duration_ms")
    event_static.pop("duration_ms")
    assert manual_static == event_static
    assert manual["status"] == "OK"
    assert manual["assessment"] == "NO_HIGH_RISK_INDICATORS"
    assert manual["score_is_probability"] is False


def test_service_scanner_and_engine_injections_apply_to_both_paths(tmp_path):
    target = tmp_path / "injected.txt"
    target.write_bytes(b"fixture")
    scanner = StaticFileScanner()
    controller = controller_for(tmp_path)
    scorer = controller.analyzer.scoring_engine
    service = WindowsLocalService(monitor=controller, scanner=scanner, scoring_engine=scorer)
    assert controller.analyzer is service.analyzer
    assert controller.analyzer.scanner is scanner
    assert controller.analyzer.scoring_engine is scorer
    assert service.scan_file(str(target))["assessment"] == "NO_HIGH_RISK_INDICATORS"


@pytest.mark.parametrize("kind", ["missing", "large", "directory", "read_error", "partial", "missing_entropy", "incomplete_pe"])
def test_unavailable_or_incomplete_analysis_never_reports_clean_or_zero_risk(tmp_path, monkeypatch, kind):
    target = tmp_path / "fixture.bin"
    if kind != "missing":
        target.write_bytes(b"fixture")
    if kind == "directory":
        target = tmp_path
    analyzer = WindowsStaticAnalyzer(max_file_bytes=2 if kind == "large" else 1024,
                                     retry_attempts=0, retry_delay_seconds=0)
    if kind == "read_error":
        def unreadable(_path):
            raise PermissionError("fixture sharing violation")
        monkeypatch.setattr(analyzer.scanner, "scan", unreadable)
    if kind in {"partial", "missing_entropy", "incomplete_pe"}:
        scan = StaticScanResult(str(target), status="PARTIAL" if kind == "partial" else "OK")
        if kind != "missing_entropy":
            scan.entropy_summary = {"bytes_analyzed": 7, "whole_file_entropy": 0.0}
        if kind == "incomplete_pe":
            scan.pe_summary = {"status": "INCOMPLETE"}
        monkeypatch.setattr(analyzer.scanner, "scan", lambda _path: scan)
    result = analyzer.analyze(target).to_dict()
    assert result["assessment"] == "INCONCLUSIVE"
    assert result["risk_score"] is None
    assert result["recommended_decision"] == "INCONCLUSIVE"
    assert result["pre_execution_scoring"]["score"] is None
    assert result["pre_execution_scoring"]["risk_score"] is None
    assert result["enforced_action"] == "NONE"
    assert result["reason"]


def test_transient_static_read_failure_retries_before_scoring_success(tmp_path, monkeypatch):
    target = tmp_path / "locked.txt"
    target.write_bytes(b"harmless document")
    analyzer = WindowsStaticAnalyzer(retry_attempts=1, retry_delay_seconds=0)
    original = analyzer.scanner.scan
    calls = []

    def transient(path):
        calls.append(path)
        if len(calls) == 1:
            return StaticScanResult(str(path), errors=[{"code": "FILE_READ_FAILED", "message": "locked"}])
        return original(path)

    monkeypatch.setattr(analyzer.scanner, "scan", transient)
    result = analyzer.analyze(target)
    assert result.status == "ANALYZED"
    assert result.attempts == 2
    assert len(calls) == 2


def test_file_changed_during_scan_is_inconclusive(tmp_path, monkeypatch):
    target = tmp_path / "changing.txt"
    target.write_bytes(b"fixture")
    analyzer = WindowsStaticAnalyzer(retry_attempts=0)
    original = analyzer.scanner.scan
    monkeypatch.setattr(analysis_module, "_windows_read_guard", lambda _path: nullcontext())

    def changed(path):
        scan = original(path)
        target.write_bytes(b"changed fixture")
        return scan

    monkeypatch.setattr(analyzer.scanner, "scan", changed)
    result = analyzer.analyze(target)
    assert result.assessment == "INCONCLUSIVE"
    assert result.risk_score is None
    assert "FILE_CHANGED_DURING_ANALYSIS" in result.reason


def test_growing_entropy_stream_is_bounded():
    stream = io.BytesIO(b"a" * 5000)
    engine = _BoundedEntropyEngine(EntropyEngine(), limit=32)
    with pytest.raises(FileAccessError, match="BYTE_LIMIT"):
        engine._analyze_stream(stream, 16, "growing fixture")
    assert stream.closed


@pytest.mark.parametrize("target", [r"\\server\share\file.txt", r"\\?\UNC\server\share\file.txt", "//server/share/file.txt"])
def test_remote_paths_rejected_before_filesystem_access(target, monkeypatch):
    def forbidden(*_args):
        pytest.fail("UNC path reached filesystem")
    monkeypatch.setattr(Path, "lstat", forbidden)
    analyzer = WindowsStaticAnalyzer(filesystem_type_resolver=forbidden)
    result = analyzer.analyze(target)
    assert result.status == "SKIPPED_NONLOCAL_PATH"
    assert result.assessment == "INCONCLUSIVE"


def test_ancestor_reparse_point_is_rejected_before_leaf_scan(tmp_path, monkeypatch):
    target = tmp_path / "junction" / "target.txt"
    original = Path.lstat

    def reparse(path, *args, **kwargs):
        if path == target.parent:
            return SimpleNamespace(st_mode=0o040755, st_file_attributes=0x400)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", reparse)
    monkeypatch.setattr(analysis_module, "_windows_read_guard", lambda _path: nullcontext())
    result = WindowsStaticAnalyzer(retry_attempts=0).analyze(target)
    assert result.reason == "REPARSE_POINT_NOT_SCANNED"
    assert result.risk_score is None


def test_symbolic_link_target_is_not_scanned(tmp_path):
    target = tmp_path / "regular.txt"
    target.write_bytes(b"fixture")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("creating symlinks requires Windows developer mode or privilege")
    result = WindowsStaticAnalyzer(retry_attempts=0).analyze(link)
    assert result.reason in {"SYMLINK_NOT_SCANNED", "REPARSE_POINT_NOT_SCANNED"}
    assert result.static_scan is None
    assert result.assessment == "INCONCLUSIVE"


def test_entropy_only_evidence_does_not_recommend_deny(tmp_path):
    target = tmp_path / "distribution.bin"
    target.write_bytes(bytes(range(256)) * 32)
    result = WindowsStaticAnalyzer(retry_attempts=0).analyze(target)
    assert result.status == "ANALYZED"
    assert result.entropy["whole_file_entropy"] == pytest.approx(8.0)
    assert result.recommended_decision != "DENY"
    assert result.enforced_action == "NONE"


def test_legacy_entropy_analyzer_injection_remains_supported(tmp_path):
    target = tmp_path / "legacy.bin"
    target.write_bytes(bytes(range(256)))
    controller = controller_for(tmp_path, analyzer=WindowsEntropyAnalyzer(retry_attempts=0))
    controller.handle_event(WindowsMonitorEvent(FILE_MODIFIED, str(target)))
    record = controller.recent_records()[-1]
    assert record["status"] == "ANALYZED"
    assert record["analysis"]["entropy"]["whole_file_entropy"] == pytest.approx(8.0)
    assert record["assessment"] == "INCONCLUSIVE"
    assert record["risk_score"] is None
    assert record["decision"] != "DENY"


def test_pending_queue_remains_bounded_and_dropped_events_are_inconclusive(tmp_path):
    class HeldExecutor(Executor):
        def __init__(self):
            self.jobs = []

        def submit(self, fn, /, *args, **kwargs):
            self.jobs.append((fn, args, kwargs))
            return Future()

    executor = HeldExecutor()
    controller = WindowsMonitorController(
        WindowsMonitorPolicy(monitored_paths=[str(tmp_path)], excluded_paths=[], max_pending_events=1),
        backend=FakeBackend(), executor=executor)
    event = WindowsMonitorEvent(FILE_MODIFIED, str(tmp_path / "queued.txt"))
    controller.handle_event(event)
    controller.handle_event(event)
    assert len(executor.jobs) == 1
    dropped = controller.recent_records()[-1]
    assert dropped["status"] == "DROPPED_BACKPRESSURE"
    assert dropped["assessment"] == "INCONCLUSIVE"
    assert dropped["risk_score"] is None
    fn, args, kwargs = executor.jobs[0]
    fn(*args, **kwargs)
    controller.handle_event(event)
    assert len(executor.jobs) == 2


@pytest.mark.parametrize("target", [r"\\server\share", r"\\?\C:\local", "//server/share"])
def test_policy_and_native_backend_reject_remote_roots_before_stat(target, monkeypatch):
    def forbidden(*_args):
        pytest.fail("rejected watcher root reached filesystem or native API")

    policy = WindowsMonitorPolicy(monitored_paths=[], excluded_paths=[])
    policy.monitored_paths = [target]
    backend = ReadDirectoryChangesBackend([], is_windows=lambda: True)
    backend.roots = [target]
    monkeypatch.setattr(Path, "lstat", forbidden)
    monkeypatch.setattr(os.path, "isdir", forbidden)
    monkeypatch.setattr(backend, "_load_windows_api", forbidden)
    assert policy.backend_roots() == []
    assert backend.start(lambda _event: None) is False
    assert backend.status()["degraded_reason"] == "NO_VALID_MONITOR_ROOTS"


def test_mapped_remote_volume_rejected_by_scan_and_watcher_before_stat(tmp_path, monkeypatch):
    def forbidden(*_args):
        pytest.fail("remote drive reached filesystem")

    policy = WindowsMonitorPolicy(monitored_paths=[str(tmp_path)], excluded_paths=[])
    backend = ReadDirectoryChangesBackend([str(tmp_path)], is_windows=lambda: True)
    analyzer = WindowsStaticAnalyzer(retry_attempts=0)
    monkeypatch.setattr(policy_module, "_volume_is_local", lambda _path: False)
    monkeypatch.setattr(Path, "lstat", forbidden)
    monkeypatch.setattr(os.path, "isdir", forbidden)
    assert policy.backend_roots() == []
    assert backend.start(lambda _event: None) is False
    result = analyzer.analyze(tmp_path / "remote.txt")
    assert result.reason == "LOCAL_VOLUME_NOT_VERIFIED"
    assert result.assessment == "INCONCLUSIVE"


def test_policy_preserves_local_root_but_rejects_ancestor_reparse(tmp_path, monkeypatch):
    local = tmp_path / "local"
    local.mkdir()
    junction = tmp_path / "junction"
    policy = WindowsMonitorPolicy(monitored_paths=[str(local), str(junction)], excluded_paths=[])
    original = Path.lstat

    def reparse(path, *args, **kwargs):
        if path == junction:
            return SimpleNamespace(st_mode=0o040755, st_file_attributes=0x400)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", reparse)
    assert policy.backend_roots() == [os.path.normcase(str(local))]


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing modes require native handles")
def test_native_open_writer_produces_bounded_inconclusive_result(tmp_path):
    target = tmp_path / "open-writer.txt"
    target.write_bytes(b"harmless locked fixture")
    analyzer = WindowsStaticAnalyzer(retry_attempts=1, retry_delay_seconds=0)
    with target.open("r+b"):
        result = analyzer.analyze(target)
    assert result.attempts == 2
    assert result.assessment == "INCONCLUSIVE"
    assert result.risk_score is None
    assert result.static_scan is None
    assert analyzer.analyze(target).status == "ANALYZED"
