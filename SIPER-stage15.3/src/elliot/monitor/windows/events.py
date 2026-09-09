"""Platform-neutral event contracts for the local Windows monitor.

The Windows monitor deliberately keeps its event schema independent from a
specific capture mechanism.  A local ETW adapter, a signed minifilter bridge,
or the built-in ReadDirectoryChangesW fallback can therefore feed the same
entropy-analysis pipeline without changing policy or reporting semantics.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping


FILE_CREATED = "FILE_CREATED"
FILE_MODIFIED = "FILE_MODIFIED"
FILE_RENAMED = "FILE_RENAMED"
FILE_DELETED = "FILE_DELETED"
PROCESS_STARTED = "PROCESS_STARTED"
PROCESS_EXITED = "PROCESS_EXITED"
OVERFLOW = "OVERFLOW"

FILE_EVENT_TYPES = frozenset(
    {FILE_CREATED, FILE_MODIFIED, FILE_RENAMED, FILE_DELETED}
)
ENTROPY_ELIGIBLE_EVENT_TYPES = frozenset(
    {FILE_CREATED, FILE_MODIFIED, FILE_RENAMED}
)
ALL_EVENT_TYPES = frozenset(
    {*FILE_EVENT_TYPES, PROCESS_STARTED, PROCESS_EXITED, OVERFLOW}
)


@dataclass(frozen=True, slots=True)
class WindowsMonitorEvent:
    """A locally-observed Windows filesystem or process event.

    ``path`` is the post-operation path for a rename.  ``previous_path`` is
    populated only when the producer can reliably pair the old and new rename
    notifications.  Metadata must be JSON-compatible so that an application
    can display it locally without a central telemetry service.
    """

    event_type: str
    path: str | None = None
    timestamp_ns: int = field(default_factory=time.time_ns)
    provider: str = "WINDOWS_LOCAL"
    process_id: int | None = None
    process_name: str | None = None
    previous_path: str | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized = str(self.event_type).upper()
        if normalized not in ALL_EVENT_TYPES:
            raise ValueError(f"unsupported Windows monitor event type: {self.event_type}")
        object.__setattr__(self, "event_type", normalized)
        if self.timestamp_ns < 0:
            raise ValueError("timestamp_ns must be non-negative")
        if self.process_id is not None and self.process_id < 0:
            raise ValueError("process_id must be non-negative")
        # Take an immutable snapshot from potentially mutable producer input.
        object.__setattr__(self, "metadata", dict(self.metadata))

    @property
    def is_entropy_eligible(self) -> bool:
        return self.event_type in ENTROPY_ELIGIBLE_EVENT_TYPES and bool(self.path)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class WindowsMonitorRecord:
    """A local analysis result emitted by :class:`WindowsMonitorController`."""

    event: WindowsMonitorEvent
    status: str
    local_only: bool = True
    analysis: Mapping[str, object] | None = None
    reason: str | None = None
    processing_latency_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "source": "windows-monitor",
            "event": self.event.to_dict(),
            "status": self.status,
            "local_only": self.local_only,
            "analysis": dict(self.analysis) if self.analysis is not None else None,
            "reason": self.reason,
            "processing_latency_ms": self.processing_latency_ms,
        }
        return result
