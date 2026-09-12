"""Read-only eBPF/tracefs capability assessment for the Linux sensor."""

from __future__ import annotations

import importlib.util
import os
import platform
from dataclasses import dataclass
from pathlib import Path

from .kernel_headers import assess_kernel_headers


@dataclass(frozen=True, slots=True)
class EbpfCapability:
    status: str
    system: str
    bcc_importable: bool
    tracefs_available: bool
    privileged: bool
    header_status: str
    issues: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        return self.status == "READY"

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "system": self.system,
            "bcc_importable": self.bcc_importable,
            "tracefs_available": self.tracefs_available,
            "privileged": self.privileged,
            "header_status": self.header_status,
            "issues": list(self.issues),
            "ready": self.ready,
        }


def assess_ebpf_capability(
    *,
    system_name: str | None = None,
    tracefs_paths: tuple[Path, ...] = (
        Path("/sys/kernel/tracing/events"),
        Path("/sys/kernel/debug/tracing/events"),
    ),
    bcc_importable: bool | None = None,
    privileged: bool | None = None,
) -> EbpfCapability:
    """Check eBPF prerequisites without loading BCC or attaching a probe."""

    system = system_name or platform.system()
    if system != "Linux":
        return EbpfCapability(
            "UNAVAILABLE", system, False, False, False, "UNSUPPORTED_PLATFORM",
            ("LINUX_EBPF_REQUIRES_LINUX_HOST",),
        )
    bcc_ok = (
        bool(bcc_importable)
        if bcc_importable is not None
        else importlib.util.find_spec("bcc") is not None
    )
    tracefs_ok = any(path.is_dir() for path in tracefs_paths)
    privileged_ok = (
        bool(privileged)
        if privileged is not None
        else bool(hasattr(os, "geteuid") and os.geteuid() == 0)
    )
    try:
        headers = assess_kernel_headers(system_name="Linux")
        header_status = headers.status
    except (OSError, RuntimeError):
        header_status = "ASSESSMENT_FAILED"
    issues: list[str] = []
    if not bcc_ok:
        issues.append("BCC_PYTHON_BINDINGS_UNAVAILABLE")
    if not tracefs_ok:
        issues.append("TRACEFS_EVENTS_UNAVAILABLE")
    if not privileged_ok:
        issues.append("ROOT_OR_BPF_CAPABILITY_REQUIRED")
    if header_status != "READY":
        issues.append(f"KERNEL_HEADERS_{header_status}")
    return EbpfCapability(
        "READY" if not issues else "DEGRADED",
        system,
        bcc_ok,
        tracefs_ok,
        privileged_ok,
        header_status,
        tuple(issues),
    )
