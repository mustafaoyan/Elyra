"""Safety policy for a disposable Linux behavior-analysis laboratory."""

from __future__ import annotations

from dataclasses import dataclass


class UnsafeLabConfiguration(ValueError):
    """Raised when a lab configuration could expose the host or network."""


@dataclass(frozen=True, slots=True)
class LabPolicy:
    network_mode: str = "disabled"
    host_shares: bool = False
    clipboard_sharing: bool = False
    snapshot_required: bool = True
    max_duration_seconds: int = 120
    allow_real_artifacts: bool = False

    def validate(self) -> None:
        if self.network_mode not in {"disabled", "isolated"}:
            raise UnsafeLabConfiguration("network must be disabled or isolated")
        if self.host_shares or self.clipboard_sharing:
            raise UnsafeLabConfiguration("host shares and clipboard sharing are forbidden")
        if not self.snapshot_required:
            raise UnsafeLabConfiguration("a disposable snapshot is required")
        if not 1 <= self.max_duration_seconds <= 300:
            raise UnsafeLabConfiguration("lab duration must be between 1 and 300 seconds")
        if self.allow_real_artifacts:
            raise UnsafeLabConfiguration("real artifacts are not allowed in the default lab")
