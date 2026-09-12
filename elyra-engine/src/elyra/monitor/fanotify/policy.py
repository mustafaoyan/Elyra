"""fanotify monitoring and enforcement policy.

Stage 8 keeps policy values explicit and provisional.  MONITOR_ONLY and
FAIL_OPEN are the safe defaults; selected fail-closed paths must be configured
explicitly after laboratory verification.
"""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

VALID_MODES = {"MONITOR_ONLY", "ENFORCEMENT"}
VALID_FAIL_POLICIES = {"FAIL_OPEN", "FAIL_CLOSED"}


def _normalise(path: str | os.PathLike[str]) -> str:
    return os.path.normpath(os.path.abspath(os.fspath(path)))


def _contains(parent: str, child: str) -> bool:
    """Return True when *child* is *parent* or is inside it.

    ``startswith`` is deliberately avoided because ``/tmp/a`` must not match
    ``/tmp/ab``.
    """

    try:
        return os.path.commonpath((parent, child)) == parent
    except ValueError:
        return False


def default_monitored_paths() -> list[str]:
    paths = ["/tmp", "/var/tmp"]
    for user_dir in sorted(glob.glob("/home/*")):
        if not os.path.isdir(user_dir):
            continue
        paths.append(user_dir)
        for name in ("Downloads", "İndirilenler"):
            candidate = os.path.join(user_dir, name)
            if os.path.isdir(candidate):
                paths.append(candidate)
    for candidate in ("/media", "/mnt", "/run/media"):
        if os.path.exists(candidate):
            paths.append(candidate)
    return list(dict.fromkeys(_normalise(path) for path in paths))


def default_excluded_paths() -> list[str]:
    return [
        "/opt/elyra",
        "/var/log/elyra",
        "/var/lib/elyra",
        "/run/elyra",
        "/usr/lib",
        "/usr/lib64",
        "/lib",
        "/lib64",
        "/usr/bin",
        "/bin",
        "/sbin",
        "/usr/sbin",
    ]


@dataclass(slots=True)
class FanotifyPolicy:
    """Configurable Stage 8 fanotify policy.

    Thresholds are operational safeguards rather than validated malware
    thresholds.
    """

    mode: str = "MONITOR_ONLY"
    default_fail_policy: str = "FAIL_OPEN"
    monitored_paths: list[str] = field(default_factory=default_monitored_paths)
    excluded_paths: list[str] = field(default_factory=default_excluded_paths)
    fail_closed_paths: list[str] = field(default_factory=list)
    max_response_seconds: float = 2.5
    max_preexec_file_bytes: int = 128 * 1024 * 1024
    max_pending_events: int = 64
    event_workers: int = 8
    exclude_daemon_descendants: bool = True

    def __post_init__(self) -> None:
        self.mode = self.mode.upper()
        self.default_fail_policy = self.default_fail_policy.upper()
        if self.mode not in VALID_MODES:
            raise ValueError(f"unsupported fanotify mode: {self.mode}")
        if self.default_fail_policy not in VALID_FAIL_POLICIES:
            raise ValueError(
                f"unsupported default fail policy: {self.default_fail_policy}"
            )
        if self.max_response_seconds <= 0:
            raise ValueError("max_response_seconds must be greater than zero")
        if self.max_preexec_file_bytes <= 0:
            raise ValueError("max_preexec_file_bytes must be greater than zero")
        if self.max_pending_events <= 0 or self.event_workers <= 0:
            raise ValueError("event worker and pending-event limits must be positive")
        self.monitored_paths = self._normalise_many(self.monitored_paths)
        self.excluded_paths = self._normalise_many(self.excluded_paths)
        self.fail_closed_paths = self._normalise_many(self.fail_closed_paths)

    @staticmethod
    def _normalise_many(paths: Iterable[str]) -> list[str]:
        return list(dict.fromkeys(_normalise(path) for path in paths))

    def should_monitor(self, filepath: str | None) -> bool:
        if not filepath:
            return False
        candidate = _normalise(filepath)
        if any(_contains(excluded, candidate) for excluded in self.excluded_paths):
            return False
        return any(_contains(included, candidate) for included in self.monitored_paths)

    def is_excluded_path(self, filepath: str | None) -> bool:
        if not filepath:
            return False
        candidate = _normalise(filepath)
        return any(_contains(excluded, candidate) for excluded in self.excluded_paths)

    def get_fail_policy(self, filepath: str | None) -> str:
        if filepath:
            candidate = _normalise(filepath)
            if any(_contains(path, candidate) for path in self.fail_closed_paths):
                return "FAIL_CLOSED"
        return self.default_fail_policy

    def is_enforcement_active(self) -> bool:
        return self.mode == "ENFORCEMENT"

    def get_final_action(self, decision: str) -> str:
        decision = str(decision).upper()
        if self.mode == "MONITOR_ONLY":
            return "ALLOW"
        return "DENY" if decision == "DENY" else "ALLOW"

    def set_mode(self, mode: str) -> None:
        candidate = str(mode).upper()
        if candidate not in VALID_MODES:
            raise ValueError(f"unsupported fanotify mode: {candidate}")
        self.mode = candidate

    def mark_targets(self) -> list[str]:
        """Return existing monitored paths to be passed to the interface.

        The interface de-duplicates mount marks by device identifier.
        """

        return [path for path in self.monitored_paths if Path(path).exists()]


# Historical name retained while callers migrate to the English class name.
PolicyManager = FanotifyPolicy
