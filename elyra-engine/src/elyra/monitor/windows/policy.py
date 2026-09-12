"""Local-only policy for Windows filesystem observation.

Windows pre-execution blocking requires a signed, separately deployed kernel
minifilter.  This package intentionally does not pretend that user-space ETW
or directory notifications can enforce execution decisions.  Its safe default
is therefore monitor-only analysis with no network transport.
"""

from __future__ import annotations

import ctypes
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


def _normalise(path: str | os.PathLike[str]) -> str:
    """Return a comparison-safe absolute path without resolving symlinks."""

    return os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(path))))


def _contains(parent: str, child: str) -> bool:
    """Return whether *child* is *parent* or below it, without prefix bugs."""

    try:
        return os.path.commonpath((parent, child)) == parent
    except ValueError:
        # Different Windows drives cannot contain one another.
        return False


def _volume_is_local(path: str) -> bool:
    if os.name != "nt":
        return True
    drive, _ = os.path.splitdrive(path)
    if not drive:
        return False
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_drive_type = kernel32.GetDriveTypeW
        get_drive_type.argtypes = [ctypes.c_wchar_p]
        get_drive_type.restype = ctypes.c_uint32
        # Reject DRIVE_REMOTE and unverified/invalid drive types before stat.
        return get_drive_type(drive + "\\") in {2, 3, 5, 6}
    except (AttributeError, OSError):
        return False


def local_path_rejection(path: str | os.PathLike[str], *, inspect_components: bool = True) -> str | None:
    """Check local enrollment without following UNC, devices, links or junctions.

    The cheap lexical/volume part also applies to queued scan paths. Full
    component validation is performed before enrolling a directory watcher;
    the analyzer separately guards components throughout each bounded read.
    """
    supplied = os.fspath(path)
    if supplied.replace("/", "\\").startswith("\\\\"):
        return "UNC_OR_DEVICE_PATH_NOT_SCANNED"
    absolute = os.path.abspath(supplied)
    if os.name == "nt" and ":" in os.path.splitdrive(absolute)[1]:
        return "ALTERNATE_DATA_STREAM_NOT_SCANNED"
    if not _volume_is_local(absolute):
        return "LOCAL_VOLUME_NOT_VERIFIED"
    if inspect_components:
        target = Path(absolute)
        try:
            for component in (*reversed(target.parents), target):
                metadata = component.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    return "SYMLINK_NOT_SCANNED"
                if getattr(metadata, "st_file_attributes", 0) & 0x400:
                    return "REPARSE_POINT_NOT_SCANNED"
        except (OSError, ValueError):
            return "LOCAL_PATH_NOT_ACCESSIBLE"
    return None


def default_monitored_paths() -> list[str]:
    """Return conservative local user-data roots for a fresh installation."""

    home = Path.home()
    candidates = (home / "Downloads", home / "Desktop", home / "Documents")
    existing = [str(path) for path in candidates
                if local_path_rejection(path) is None and path.is_dir()]
    # Do not silently widen monitoring to a whole drive when profile folders do
    # not exist (for example under a service account).
    return [_normalise(path) for path in existing]


def default_excluded_paths() -> list[str]:
    """Avoid recursively observing the operating system and ELYRA data roots."""

    candidates = [
        os.environ.get("SystemRoot", r"C:\Windows"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ]
    program_data = os.environ.get("ProgramData")
    if program_data:
        candidates.append(os.path.join(program_data, "ELYRA"))
    return list(dict.fromkeys(_normalise(path) for path in candidates if path))


@dataclass(slots=True)
class WindowsMonitorPolicy:
    """Bounded, monitor-only controls for the local Windows backend."""

    monitored_paths: list[str] = field(default_factory=default_monitored_paths)
    excluded_paths: list[str] = field(default_factory=default_excluded_paths)
    max_file_bytes: int = 128 * 1024 * 1024
    analysis_workers: int = 4
    max_pending_events: int = 128
    max_reported_events: int = 512
    retry_attempts: int = 2
    retry_delay_seconds: float = 0.15
    recursive: bool = True
    monitor_only: bool = True

    def __post_init__(self) -> None:
        if not self.monitor_only:
            raise ValueError(
                "Windows user-space monitoring is monitor-only; "
                "a signed minifilter is required for enforcement"
            )
        if self.max_file_bytes <= 0:
            raise ValueError("max_file_bytes must be greater than zero")
        if self.analysis_workers <= 0:
            raise ValueError("analysis_workers must be greater than zero")
        if self.max_pending_events <= 0 or self.max_reported_events <= 0:
            raise ValueError("event limits must be greater than zero")
        if self.retry_attempts < 0:
            raise ValueError("retry_attempts must not be negative")
        if self.retry_delay_seconds < 0:
            raise ValueError("retry_delay_seconds must not be negative")
        self.monitored_paths = self._normalise_many(self.monitored_paths)
        self.excluded_paths = self._normalise_many(self.excluded_paths)

    @staticmethod
    def _normalise_many(paths: Iterable[str | os.PathLike[str]]) -> list[str]:
        return list(dict.fromkeys(_normalise(path) for path in paths))

    def should_monitor(self, path: str | os.PathLike[str] | None) -> bool:
        if not path:
            return False
        if local_path_rejection(path, inspect_components=False) is not None:
            return False
        candidate = _normalise(path)
        if any(_contains(excluded, candidate) for excluded in self.excluded_paths):
            return False
        return any(_contains(root, candidate) for root in self.monitored_paths)

    def is_excluded_path(self, path: str | os.PathLike[str] | None) -> bool:
        if not path:
            return False
        candidate = _normalise(path)
        return any(_contains(excluded, candidate) for excluded in self.excluded_paths)

    def backend_roots(self) -> list[str]:
        """Return valid roots only; invalid configuration becomes explicit status."""

        return [root for root in self.monitored_paths
                if local_path_rejection(root) is None and os.path.isdir(root)]
