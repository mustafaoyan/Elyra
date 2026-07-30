"""Minimal, explicit Linux fanotify syscall boundary for Stage 8.

The module intentionally performs no scoring.  It parses kernel metadata,
resolves the event descriptor to a path for contextual evidence, and sends the
mandatory permission response chosen by the controller.
"""

from __future__ import annotations

import ctypes
import errno
import os
import select
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
libc.fanotify_init.restype = ctypes.c_int
libc.fanotify_mark.argtypes = [
    ctypes.c_int,
    ctypes.c_uint,
    ctypes.c_uint64,
    ctypes.c_int,
    ctypes.c_char_p,
]
libc.fanotify_mark.restype = ctypes.c_int

FAN_CLOEXEC = 0x00000001
FAN_NONBLOCK = 0x00000002
FAN_CLASS_PRE_CONTENT = 0x00000008

FAN_MARK_ADD = 0x00000001
FAN_MARK_DONT_FOLLOW = 0x00000004
FAN_MARK_ONLYDIR = 0x00000008
FAN_MARK_MOUNT = 0x00000010

FAN_OPEN_EXEC_PERM = 0x00040000
FAN_EVENT_ON_CHILD = 0x08000000
FAN_Q_OVERFLOW = 0x00004000

FAN_ALLOW = 0x01
FAN_DENY = 0x02
FAN_NOFD = -1
FANOTIFY_METADATA_VERSION = 3
FAN_EVENT_METADATA_LEN = 24

_METADATA = struct.Struct("@I B B H Q i i")
_RESPONSE = struct.Struct("@i I")


class FanotifySystemError(OSError):
    """Raised when a fanotify syscall fails with a concrete errno."""


@dataclass(slots=True)
class FanotifyEvent:
    fd: int
    pid: int
    path: str | None
    mask: int
    event_len: int
    metadata_len: int
    version: int
    received_monotonic: float
    parse_error: str | None = None

    @property
    def is_overflow(self) -> bool:
        return bool(self.mask & FAN_Q_OVERFLOW)

    @property
    def is_exec_permission(self) -> bool:
        return bool(self.mask & FAN_OPEN_EXEC_PERM) and self.fd >= 0

    @property
    def proc_fd_path(self) -> str | None:
        return f"/proc/self/fd/{self.fd}" if self.fd >= 0 else None


class FanotifyInterface:
    """Own one fanotify descriptor and provide bounded event reads.

    ``mark_scope='mount'`` is the production default because recursive directory
    inode marks are not provided by fanotify.  The controller still filters every
    event against the configured monitored and excluded paths.  ``inode`` is
    used only by the isolated Stage 8 laboratory verifier.
    """

    def __init__(self, *, mark_scope: str = "mount") -> None:
        if mark_scope not in {"mount", "inode"}:
            raise ValueError("mark_scope must be 'mount' or 'inode'")
        self.fd = -1
        self.mark_scope = mark_scope
        self._marked_devices: set[int] = set()
        self._marked_paths: set[str] = set()

    def initialize(self) -> bool:
        if self.fd >= 0:
            return True
        flags = FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK
        event_flags = os.O_RDONLY | getattr(os, "O_LARGEFILE", 0) | os.O_CLOEXEC
        descriptor = libc.fanotify_init(flags, event_flags)
        if descriptor < 0:
            error = ctypes.get_errno()
            raise FanotifySystemError(error, os.strerror(error), "fanotify_init")
        self.fd = descriptor
        return True

    def add_mark(self, path: str | os.PathLike[str]) -> bool:
        if self.fd < 0:
            raise RuntimeError("fanotify interface is not initialized")
        resolved = os.path.abspath(os.fspath(path))
        metadata = os.stat(resolved)

        if self.mark_scope == "mount":
            if metadata.st_dev in self._marked_devices:
                return False
            mark_flags = FAN_MARK_ADD | FAN_MARK_MOUNT
            mask = FAN_OPEN_EXEC_PERM
        else:
            if resolved in self._marked_paths:
                return False
            if not Path(resolved).is_dir():
                raise NotADirectoryError(resolved)
            mark_flags = (
                FAN_MARK_ADD | FAN_MARK_DONT_FOLLOW | FAN_MARK_ONLYDIR
            )
            mask = FAN_OPEN_EXEC_PERM | FAN_EVENT_ON_CHILD

        result = libc.fanotify_mark(
            self.fd,
            mark_flags,
            ctypes.c_uint64(mask),
            -1,
            resolved.encode("utf-8", errors="surrogateescape"),
        )
        if result < 0:
            error = ctypes.get_errno()
            raise FanotifySystemError(error, os.strerror(error), resolved)

        self._marked_devices.add(metadata.st_dev)
        self._marked_paths.add(resolved)
        return True

    def add_marks(self, paths: Iterable[str]) -> list[str]:
        marked: list[str] = []
        for path in paths:
            if self.add_mark(path):
                marked.append(os.path.abspath(path))
        return marked

    def read_events(self, timeout: float = 0.25) -> list[FanotifyEvent]:
        if self.fd < 0:
            return []
        readable, _, _ = select.select([self.fd], [], [], max(0.0, timeout))
        if not readable:
            return []
        try:
            data = os.read(self.fd, 64 * 1024)
        except BlockingIOError:
            return []
        except OSError as exc:
            if exc.errno in {errno.EBADF, errno.EINVAL}:
                return []
            raise
        return self.parse_events(data)

    @staticmethod
    def parse_events(data: bytes) -> list[FanotifyEvent]:
        events: list[FanotifyEvent] = []
        offset = 0
        now = time.monotonic
        while offset + FAN_EVENT_METADATA_LEN <= len(data):
            (
                event_len,
                version,
                _reserved,
                metadata_len,
                mask,
                event_fd,
                pid,
            ) = _METADATA.unpack_from(data, offset)

            parse_error: str | None = None
            if event_len < FAN_EVENT_METADATA_LEN or metadata_len < FAN_EVENT_METADATA_LEN:
                parse_error = "INVALID_METADATA_LENGTH"
                event_len = FAN_EVENT_METADATA_LEN
            elif offset + event_len > len(data):
                parse_error = "TRUNCATED_EVENT"
                event_len = len(data) - offset
            if version != FANOTIFY_METADATA_VERSION:
                parse_error = "UNSUPPORTED_METADATA_VERSION"

            path: str | None = None
            if event_fd >= 0:
                try:
                    path = os.readlink(f"/proc/self/fd/{event_fd}")
                except OSError:
                    parse_error = parse_error or "EVENT_PATH_UNAVAILABLE"

            events.append(
                FanotifyEvent(
                    fd=event_fd,
                    pid=pid,
                    path=path,
                    mask=mask,
                    event_len=event_len,
                    metadata_len=metadata_len,
                    version=version,
                    received_monotonic=now(),
                    parse_error=parse_error,
                )
            )
            if event_len <= 0:
                break
            offset += event_len
        return events

    def respond(self, event_fd: int, response: int) -> bool:
        if event_fd < 0:
            return False
        if response not in {FAN_ALLOW, FAN_DENY}:
            raise ValueError("fanotify response must be FAN_ALLOW or FAN_DENY")
        success = False
        try:
            if self.fd < 0:
                return False
            written = os.write(self.fd, _RESPONSE.pack(event_fd, response))
            success = written == _RESPONSE.size
            return success
        finally:
            try:
                os.close(event_fd)
            except OSError:
                pass

    def close_event_fd(self, event_fd: int) -> None:
        if event_fd >= 0:
            try:
                os.close(event_fd)
            except OSError:
                pass

    def close(self) -> None:
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1
        self._marked_devices.clear()
        self._marked_paths.clear()

    # Historical method names retained for compatibility with older callers.
    kurulum_yap = initialize
    dizin_ekle = add_mark

    def olay_bekle(self) -> FanotifyEvent | None:
        events = self.read_events()
        return events[0] if events else None

    def yanitla(self, fd: int, response: int) -> bool:
        return self.respond(fd, response)

    kapat = close


# Historical class name retained for compatibility.
FanotifyArayuzu = FanotifyInterface
