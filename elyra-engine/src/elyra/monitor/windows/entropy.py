"""NTFS-safe adapter around ELYRA's canonical entropy engine.

There is deliberately one entropy implementation in the project.  This module
only adds Windows-specific filesystem capability reporting and bounded retry
handling for files that are briefly locked by another local process.
"""

from __future__ import annotations

import ctypes
import os
import stat
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from ...analyzer.entropy import (
    EntropyEngine,
    FileAccessError,
    UnsupportedFileTypeError,
)


def filesystem_type(path: Path) -> str:
    """Return the Windows filesystem type for *path*, or ``UNKNOWN`` safely.

    ``GetVolumeInformationW`` is local-only and does not require pywin32.  On
    a non-Windows host it intentionally reports ``UNKNOWN`` rather than making
    the package unimportable; this is important for CI and cross-platform
    source validation.
    """

    if os.name != "nt":
        return "UNKNOWN"
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_volume_path_name = kernel32.GetVolumePathNameW
        get_volume_path_name.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        get_volume_path_name.restype = ctypes.c_int
        get_volume_information = kernel32.GetVolumeInformationW
        get_volume_information.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_wchar_p,
            ctypes.c_uint32,
        ]
        get_volume_information.restype = ctypes.c_int

        # A deleted event can arrive after the path disappears.  Use the first
        # existing parent so filesystem reporting itself never changes analysis
        # behaviour or creates a noisy secondary error.
        query_path = path
        while not query_path.exists() and query_path.parent != query_path:
            query_path = query_path.parent
        volume_root = ctypes.create_unicode_buffer(32768)
        if not get_volume_path_name(str(query_path), volume_root, len(volume_root)):
            return "UNKNOWN"
        name = ctypes.create_unicode_buffer(261)
        if not get_volume_information(
            volume_root.value,
            None,
            0,
            None,
            None,
            None,
            name,
            len(name),
        ):
            return "UNKNOWN"
        return name.value.upper() or "UNKNOWN"
    except (AttributeError, OSError):
        return "UNKNOWN"


@dataclass(frozen=True, slots=True)
class WindowsEntropyResult:
    """A JSON-ready result from a local filesystem entropy scan."""

    path: str
    status: str
    filesystem_type: str
    is_ntfs: bool
    attempts: int
    entropy: dict[str, Any] | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class WindowsEntropyAnalyzer:
    """Run the existing byte-level entropy analysis for a changed NTFS file.

    The analyzer has no upload client, network code, or persistence target.
    Its retry path handles transient sharing violations while retaining the
    canonical :class:`EntropyEngine` results unchanged.
    """

    def __init__(
        self,
        *,
        entropy_engine: EntropyEngine | None = None,
        max_file_bytes: int = 128 * 1024 * 1024,
        retry_attempts: int = 2,
        retry_delay_seconds: float = 0.15,
        filesystem_type_resolver: Callable[[Path], str] = filesystem_type,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        if max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be greater than zero")
        if retry_attempts < 0:
            raise ValueError("retry_attempts must not be negative")
        if retry_delay_seconds < 0:
            raise ValueError("retry_delay_seconds must not be negative")
        self.entropy_engine = entropy_engine or EntropyEngine()
        self.max_file_bytes = max_file_bytes
        self.retry_attempts = retry_attempts
        self.retry_delay_seconds = retry_delay_seconds
        self.filesystem_type_resolver = filesystem_type_resolver
        self._sleeper = sleeper

    def analyze(self, filepath: str | os.PathLike[str]) -> WindowsEntropyResult:
        path = Path(filepath)
        try:
            volume_type = str(self.filesystem_type_resolver(path) or "UNKNOWN").upper()
        except (OSError, RuntimeError, ValueError):
            volume_type = "UNKNOWN"

        attempts = 0
        last_error: Exception | None = None
        for attempts in range(1, self.retry_attempts + 2):
            try:
                metadata = path.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    return self._result(
                        path,
                        "SKIPPED_UNSUPPORTED_FILE_TYPE",
                        volume_type,
                        attempts,
                        reason="SYMLINK_NOT_SCANNED",
                    )
                if not stat.S_ISREG(metadata.st_mode):
                    return self._result(
                        path,
                        "SKIPPED_UNSUPPORTED_FILE_TYPE",
                        volume_type,
                        attempts,
                        reason="NOT_A_REGULAR_FILE",
                    )
                if metadata.st_size > self.max_file_bytes:
                    return self._result(
                        path,
                        "SKIPPED_FILE_TOO_LARGE",
                        volume_type,
                        attempts,
                        reason=f"FILE_SIZE_EXCEEDS_{self.max_file_bytes}_BYTE_LIMIT",
                    )
                report = self.entropy_engine.analyze(path)
                return self._result(
                    path,
                    "ANALYZED",
                    volume_type,
                    attempts,
                    entropy=report.to_dict(),
                )
            except FileNotFoundError:
                # A delete/rename race is expected in an asynchronous monitor.
                return self._result(
                    path,
                    "SKIPPED_NOT_FOUND",
                    volume_type,
                    attempts,
                    reason="FILE_CHANGED_BEFORE_ANALYSIS",
                )
            except UnsupportedFileTypeError as exc:
                return self._result(
                    path,
                    "SKIPPED_UNSUPPORTED_FILE_TYPE",
                    volume_type,
                    attempts,
                    reason=type(exc).__name__,
                )
            except (FileAccessError, PermissionError, OSError) as exc:
                last_error = exc
                if attempts <= self.retry_attempts:
                    if self.retry_delay_seconds:
                        self._sleeper(self.retry_delay_seconds)
                    continue

        return self._result(
            path,
            "ERROR",
            volume_type,
            attempts,
            reason=(
                f"{type(last_error).__name__}: {last_error}"
                if last_error is not None
                else "UNKNOWN_ANALYSIS_ERROR"
            ),
        )

    @staticmethod
    def _result(
        path: Path,
        status: str,
        volume_type: str,
        attempts: int,
        *,
        entropy: dict[str, Any] | None = None,
        reason: str | None = None,
    ) -> WindowsEntropyResult:
        return WindowsEntropyResult(
            path=str(path),
            status=status,
            filesystem_type=volume_type,
            is_ntfs=volume_type == "NTFS",
            attempts=attempts,
            entropy=entropy,
            reason=reason,
        )
