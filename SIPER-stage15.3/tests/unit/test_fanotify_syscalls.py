from __future__ import annotations

import os
import struct

from elliot.monitor.fanotify.syscalls import (
    FAN_EVENT_METADATA_LEN,
    FAN_OPEN_EXEC_PERM,
    FAN_Q_OVERFLOW,
    FANOTIFY_METADATA_VERSION,
    FanotifyInterface,
)


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
