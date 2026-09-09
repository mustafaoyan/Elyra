"""Local-only policy for Windows filesystem observation.

Windows pre-execution blocking requires a signed, separately deployed kernel
minifilter.  This package intentionally does not pretend that user-space ETW
or directory notifications can enforce execution decisions.  Its safe default
is therefore monitor-only analysis with no network transport.
"""

from __future__ import annotations

import os
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


def default_monitored_paths() -> list[str]:
    """Return conservative local user-data roots for a fresh installation."""

    home = Path.home()
    candidates = (home / "Downloads", home / "Desktop", home / "Documents")
    existing = [str(path) for path in candidates if path.is_dir()]
    # Do not silently widen monitoring to a whole drive when profile folders do
    # not exist (for example under a service account).
    return [_normalise(path) for path in existing]


def default_excluded_paths() -> list[str]:
    """Avoid recursively observing the operating system and ELLIOT data roots."""

    candidates = [
        os.environ.get("SystemRoot", r"C:\Windows"),
        os.environ.get("ProgramFiles", r"C:\Program Files"),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    ]
    program_data = os.environ.get("ProgramData")
    if program_data:
        candidates.append(os.path.join(program_data, "ELLIOT"))
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

        return [root for root in self.monitored_paths if os.path.isdir(root)]
