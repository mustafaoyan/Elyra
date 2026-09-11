"""Bounded Windows adapter for the canonical static scanner and risk rules.

Manual scans and filesystem notifications use this same adapter. Results are
observations, never execution enforcement or a calibrated malware probability.
"""

from __future__ import annotations

import ctypes
import os
import stat
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

from ...analyzer.entropy import EntropyEngine, FileAccessError, UnsupportedFileTypeError
from ...analyzer.static_analyzer import StaticFileScanner, StaticScanResult
from ...scoring.engine import PreExecutionScoringEngine
from .entropy import filesystem_type
from .policy import local_path_rejection


class _ScanPolicyError(Exception):
    def __init__(self, status: str, reason: str) -> None:
        self.status, self.reason = status, reason
        super().__init__(reason)


class _LimitedReader:
    """Stop a growing file at the policy limit without a second entropy pass."""

    def __init__(self, stream: BinaryIO, limit: int) -> None:
        self.stream, self.remaining = stream, limit

    def __enter__(self) -> "_LimitedReader":
        return self

    def __exit__(self, *args: object) -> None:
        self.stream.close()

    def read(self, size: int) -> bytes:
        data = self.stream.read(min(size, self.remaining + 1))
        if len(data) > self.remaining:
            raise FileAccessError("FILE_GREW_BEYOND_ANALYSIS_BYTE_LIMIT")
        self.remaining -= len(data)
        return data


class _BoundedEntropyEngine(EntropyEngine):
    def __init__(self, original: EntropyEngine, limit: int) -> None:
        super().__init__(original.config)
        self.limit = limit

    def _analyze_stream(self, stream: BinaryIO, file_size: int, label: str):
        if file_size > self.limit:
            stream.close()
            raise FileAccessError("FILE_SIZE_EXCEEDS_ANALYSIS_BYTE_LIMIT")
        return super()._analyze_stream(_LimitedReader(stream, self.limit), file_size, label)


@dataclass(frozen=True, slots=True)
class WindowsAnalysisResult:
    path: str
    status: str
    filesystem_type: str = "UNKNOWN"
    is_ntfs: bool = False
    attempts: int = 0
    entropy: dict[str, Any] | None = None
    reason: str | None = None
    static_scan: dict[str, Any] | None = None
    pre_execution_scoring: dict[str, Any] | None = None
    assessment: str = "INCONCLUSIVE"
    risk_score: int | None = None
    recommended_decision: str = "INCONCLUSIVE"
    reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    score_is_probability: bool = False
    score_kind: str = "PROVISIONAL_HEURISTIC_NOT_PROBABILITY"
    enforced_action: str = "NONE"
    monitor_mode: str = "MONITOR_ONLY"
    local_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        # Existing UI clients use decision; it is explicitly a recommendation.
        result["decision"] = self.recommended_decision
        return result


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def _reject_remote_path(filepath: str | os.PathLike[str]) -> Path:
    reason = local_path_rejection(filepath, inspect_components=False)
    if reason is not None:
        status = ("SKIPPED_UNSUPPORTED_FILE_TYPE" if reason == "ALTERNATE_DATA_STREAM_NOT_SCANNED"
                  else "SKIPPED_NONLOCAL_PATH")
        raise _ScanPolicyError(status, reason)
    return Path(os.path.abspath(os.fspath(filepath)))


def _check_components(path: Path) -> os.stat_result:
    # lstat each ancestor: checking only the leaf follows junctions and symlink
    # directories before the local-only policy can see the real target.
    for component in (*reversed(path.parents), path):
        metadata = component.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise _ScanPolicyError("SKIPPED_UNSUPPORTED_FILE_TYPE", "SYMLINK_NOT_SCANNED")
        if getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise _ScanPolicyError("SKIPPED_UNSUPPORTED_FILE_TYPE", "REPARSE_POINT_NOT_SCANNED")
    return metadata


@contextmanager
def _windows_read_guard(path: Path) -> Iterator[None]:
    """Hold Windows path components against replacement and the file against writes.

    OPEN_REPARSE_POINT prevents following a newly substituted link. Ancestor
    handles deny deletion/rename; the leaf additionally denies writes. Existing
    writers cause a sharing violation and follow the ordinary bounded retry path.
    """
    if os.name != "nt":
        yield
        return
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    get_information = kernel32.GetFileInformationByHandleEx
    get_information.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    get_information.restype = wintypes.BOOL

    class AttributeTagInfo(ctypes.Structure):
        _fields_ = [("attributes", wintypes.DWORD), ("tag", wintypes.DWORD)]

    handles: list[Any] = []
    try:
        for component in (*reversed(path.parents), path):
            leaf = component == path
            handle = create_file(str(component), 0x80000000 if leaf else 0,
                                 1 if leaf else 3, None, 3, 0x02200000, None)
            if handle == ctypes.c_void_p(-1).value:
                raise ctypes.WinError(ctypes.get_last_error())
            handles.append(handle)
            info = AttributeTagInfo()
            if not get_information(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
                raise ctypes.WinError(ctypes.get_last_error())
            if info.attributes & 0x400:
                raise _ScanPolicyError("SKIPPED_UNSUPPORTED_FILE_TYPE", "REPARSE_POINT_NOT_SCANNED")
        yield
    finally:
        for handle in reversed(handles):
            close_handle(handle)


class WindowsStaticAnalyzer:
    """Run one canonical static scan, derive entropy, then score its evidence."""

    def __init__(self, *, scanner: StaticFileScanner | None = None,
                 scoring_engine: PreExecutionScoringEngine | None = None,
                 max_file_bytes: int = 128 * 1024 * 1024,
                 retry_attempts: int = 2, retry_delay_seconds: float = 0.15,
                 filesystem_type_resolver: Callable[[Path], str] = filesystem_type,
                 sleeper: Callable[[float], None] = time.sleep) -> None:
        if max_file_bytes <= 0 or retry_attempts < 0 or retry_delay_seconds < 0:
            raise ValueError("file limit must be positive; retry settings must be non-negative")
        self.scanner = scanner or StaticFileScanner()
        if scanner is None:
            self.scanner.entropy_engine = _BoundedEntropyEngine(self.scanner.entropy_engine, max_file_bytes)
        self.scoring_engine = scoring_engine or PreExecutionScoringEngine()
        self.max_file_bytes = max_file_bytes
        self.retry_attempts = retry_attempts
        self.retry_delay_seconds = retry_delay_seconds
        self.filesystem_type_resolver = filesystem_type_resolver
        self._sleeper = sleeper

    def _result(self, path: str, status: str, attempts: int, volume: str = "UNKNOWN",
                reason: str | None = None, scan: StaticScanResult | None = None,
                scoring: dict[str, Any] | None = None) -> WindowsAnalysisResult:
        static = scan.to_dict() if scan is not None else None
        entropy = None
        if scan is not None and scan.entropy_summary:
            entropy = dict(scan.entropy_summary)
            entropy["reported_blocks"] = list(scan.block_entropies)
        scoring = dict(scoring or {})
        complete = status == "ANALYZED" and scoring.get("scoring_status") == "OK"
        reasons = list(scoring.get("contributing_indicators", []))
        if reason:
            reasons.insert(0, reason)
        limitations = ["STATIC_ANALYSIS_ONLY", "HEURISTIC_RULES_NOT_CALIBRATED",
                       "NO_MALWARE_PROBABILITY_OR_CLEAN_CERTIFICATION", "NO_EXECUTION_ENFORCEMENT"]
        if scan is not None:
            limitations.extend(str(item.get("code", "UNKNOWN_WARNING")) for item in scan.warnings)
            reasons.extend(str(item.get("code", "UNKNOWN_ERROR")) for item in scan.errors)
            if getattr(scan, "is_pe", False):
                limitations.extend(["AUTHENTICODE_NOT_VERIFIED", "PE_HEADERS_AND_SECTIONS_ONLY"])
        decision = str(scoring.get("decision", "INCONCLUSIVE")) if complete else "INCONCLUSIVE"
        risk = scoring.get("score") if complete else None
        assessment = ("SUSPICIOUS" if decision in {"WARN", "DENY"}
                      else "NO_HIGH_RISK_INDICATORS") if complete else "INCONCLUSIVE"
        if not complete:
            # A fail-open placeholder of zero is not a measured risk score.
            scoring.update(score=None, risk_score=None, decision="INCONCLUSIVE", scoring_status="INCOMPLETE")
        scoring.update(assessment=assessment, recommended_decision=decision,
                       enforced_action="NONE", score_is_probability=False,
                       score_kind="PROVISIONAL_HEURISTIC_NOT_PROBABILITY")
        return WindowsAnalysisResult(
            path=path, status=status, attempts=attempts, filesystem_type=volume,
            is_ntfs=volume == "NTFS", entropy=entropy, reason=reason,
            static_scan=static, pre_execution_scoring=scoring, assessment=assessment,
            risk_score=risk, recommended_decision=decision,
            reasons=list(dict.fromkeys(reasons)), limitations=list(dict.fromkeys(limitations)))

    def analyze(self, filepath: str | os.PathLike[str]) -> WindowsAnalysisResult:
        label = os.fspath(filepath)
        volume = "UNKNOWN"
        try:
            path = _reject_remote_path(filepath)
        except _ScanPolicyError as exc:
            return self._result(label, exc.status, 0, reason=exc.reason)
        label = str(path)
        last_scan = None
        last_reason = "UNKNOWN_ANALYSIS_ERROR"
        for attempt in range(1, self.retry_attempts + 2):
            try:
                with _windows_read_guard(path):
                    # Guard each ancestor before looking through it. This
                    # avoids a local directory being swapped for a remote
                    # junction between an earlier path check and this scan.
                    before = _check_components(path)
                    if not stat.S_ISREG(before.st_mode):
                        raise _ScanPolicyError("SKIPPED_UNSUPPORTED_FILE_TYPE", "NOT_A_REGULAR_FILE")
                    if before.st_size > self.max_file_bytes:
                        raise _ScanPolicyError("SKIPPED_FILE_TOO_LARGE", f"FILE_SIZE_EXCEEDS_{self.max_file_bytes}_BYTE_LIMIT")
                    try:
                        volume = str(self.filesystem_type_resolver(path) or "UNKNOWN").upper()
                    except (OSError, RuntimeError, ValueError):
                        volume = "UNKNOWN"
                    last_scan = self.scanner.scan(label)
                    after = _check_components(path)
                if _identity(before) != _identity(after):
                    last_reason = "FILE_CHANGED_DURING_ANALYSIS"
                    raise FileAccessError(last_reason)
                if after.st_size > self.max_file_bytes:
                    raise _ScanPolicyError("SKIPPED_FILE_TOO_LARGE", "FILE_GREW_BEYOND_ANALYSIS_BYTE_LIMIT")
                scoring = self.scoring_engine.score(last_scan).to_dict()
                codes = {str(item.get("code", "")) for item in last_scan.errors}
                if codes & {"FILE_READ_FAILED", "STAT_PERMISSION_DENIED", "STAT_FAILED",
                            "ENTROPY_ANALYSIS_FAILED", "ELF_READ_ERROR", "PE_READ_ERROR"}:
                    last_reason = "STATIC_FILE_READ_INCOMPLETE"
                    raise FileAccessError(last_reason)
                pe_status = getattr(last_scan, "pe_summary", {}).get("status", "NOT_PE")
                entropy_bytes = last_scan.entropy_summary.get("bytes_analyzed")
                complete = (last_scan.status == "OK" and not last_scan.errors
                            and entropy_bytes == after.st_size
                            and (not last_scan.is_elf or last_scan.elf_valid is not None)
                            and pe_status in {"NOT_PE", "COMPLETE"}
                            and scoring.get("scoring_status") == "OK")
                return self._result(label, "ANALYZED" if complete else "PARTIAL", attempt, volume,
                                    None if complete else "STATIC_ANALYSIS_INCOMPLETE", last_scan, scoring)
            except _ScanPolicyError as exc:
                return self._result(label, exc.status, attempt, volume, exc.reason, last_scan)
            except FileNotFoundError:
                return self._result(label, "SKIPPED_NOT_FOUND", attempt, volume,
                                    "FILE_CHANGED_BEFORE_ANALYSIS", last_scan)
            except UnsupportedFileTypeError as exc:
                return self._result(label, "SKIPPED_UNSUPPORTED_FILE_TYPE", attempt, volume,
                                    str(exc), last_scan)
            except (FileAccessError, PermissionError, OSError) as exc:
                last_reason = f"{type(exc).__name__}: {exc}"
                if attempt <= self.retry_attempts:
                    if self.retry_delay_seconds:
                        self._sleeper(self.retry_delay_seconds)
                    continue
            except Exception as exc:
                return self._result(label, "ERROR", attempt, volume,
                                    f"ANALYSIS_FAILED:{type(exc).__name__}", last_scan)
        return self._result(label, "ERROR", attempt, volume, last_reason, last_scan)
