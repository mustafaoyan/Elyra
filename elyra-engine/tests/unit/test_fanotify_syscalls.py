from __future__ import annotations

import os
import struct
from pathlib import Path

from elyra.monitor.fanotify.syscalls import (
    FAN_EVENT_METADATA_LEN,
    FAN_OPEN_EXEC_PERM,
    FAN_Q_OVERFLOW,
    FANOTIFY_METADATA_VERSION,
    FanotifyInterface,
    assess_fanotify_capability,
)


def test_fanotify_capability_is_explicit_on_non_linux() -> None:
    capability = assess_fanotify_capability(system_name="Windows")
    assert capability.status == "UNAVAILABLE"
    assert capability.ready is False
    assert "LINUX_FANOTIFY_REQUIRES_LINUX_HOST" in capability.issues


def test_fanotify_capability_reports_fixture_prerequisites(tmp_path: Path) -> None:
    filesystems = tmp_path / "filesystems"
    filesystems.write_text("nodev\tfanotify\n", encoding="utf-8")
    permission_api = tmp_path / "fanotify"
    permission_api.mkdir()
    capability = assess_fanotify_capability(
        system_name="Linux",
        proc_filesystems=filesystems,
        permission_api=permission_api,
        effective_uid=0,
    )
    assert capability.ready is True
    assert capability.to_dict()["ready"] is True


def _metadata(mask: int, fd: int, pid: int, version: int = FANOTIFY_METADATA_VERSION) -> bytes:
    return struct.pack(
        "@I B B H Q i i",
        FAN_EVENT_METADATA_LEN,
        version,
        0,
        FAN_EVENT_METADATA_LEN,
        mask,
        fd,
        pid,
    )


def test_parse_multiple_events_and_preserve_open_fd(tmp_path):
    candidate = tmp_path / "safe.bin"
    candidate.write_bytes(b"safe")
    fd = os.open(candidate, os.O_RDONLY)
    try:
        data = _metadata(FAN_OPEN_EXEC_PERM, fd, 1234) + _metadata(FAN_Q_OVERFLOW, -1, 0)
        events = FanotifyInterface.parse_events(data)
        assert len(events) == 2
        assert events[0].is_exec_permission is True
        assert events[0].path == str(candidate)
        assert events[1].is_overflow is True
    finally:
        os.close(fd)


def test_unsupported_metadata_version_is_explicit(tmp_path):
    candidate = tmp_path / "safe.bin"
    candidate.write_bytes(b"safe")
    fd = os.open(candidate, os.O_RDONLY)
    try:
        event = FanotifyInterface.parse_events(
            _metadata(FAN_OPEN_EXEC_PERM, fd, 1, version=99)
        )[0]
        assert event.parse_error == "UNSUPPORTED_METADATA_VERSION"
    finally:
        os.close(fd)
