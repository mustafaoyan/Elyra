"""Local capture backends for the Windows monitor.

``EtwBackend`` is an adapter boundary for a locally-installed ETW consumer or
signed minifilter service.  It is intentionally opt-in: this repository does
not ship a kernel driver and never sends events to a cloud endpoint.

``ReadDirectoryChangesBackend`` is a fully local, built-in fallback.  It uses
the Windows directory-change API through pywin32 when available and otherwise
through ``ctypes``, so ordinary Windows installations do not need an extra
Python package merely to receive NTFS change notifications.
"""

from __future__ import annotations

import ctypes
import logging
import os
import struct
import threading
import time
from collections.abc import Callable, Iterable
from typing import Any, Protocol

from .events import (
    FILE_CREATED,
    FILE_DELETED,
    FILE_MODIFIED,
    FILE_RENAMED,
    OVERFLOW,
    WindowsMonitorEvent,
)

logger = logging.getLogger("elliot.monitor.windows.backends")

EventCallback = Callable[[WindowsMonitorEvent], None]


class WindowsMonitorBackend(Protocol):
    """Small contract shared by ETW and local filesystem event producers."""

    def start(self, callback: EventCallback) -> bool:
        """Start local collection and invoke *callback* for each event."""

    def stop(self) -> None:
        """Stop collection and release local operating-system handles."""

    def status(self) -> dict[str, object]:
        """Return a JSON-ready local capability snapshot."""


class LocalEtwSession(Protocol):
    """Protocol implemented by an application-owned local ETW adapter.

    An adapter may use Microsoft ETW APIs, a signed minifilter bridge, or a
    separately reviewed native service.  It must keep data on the endpoint and
    convert provider records to :class:`WindowsMonitorEvent` instances.
    """

    def start(self, callback: EventCallback) -> bool | None:
        """Start the local ETW session."""

    def stop(self) -> None:
        """Stop the local ETW session."""

    def status(self) -> dict[str, object]:
        """Return local session status."""


class EtwBackend:
    """Optional bridge to an explicitly supplied, local ETW session.

    No session factory is configured by default.  That makes the absence of a
    driver/ETW consumer an explicit degraded state rather than silently using
    a network agent or claiming kernel enforcement that does not exist.
    """

    def __init__(
        self,
        session_factory: Callable[[], LocalEtwSession] | None = None,
        *,
        is_windows: Callable[[], bool] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._is_windows = is_windows or (lambda: os.name == "nt")
        self._session: LocalEtwSession | None = None
        self._active = False
        self._degraded_reason: str | None = None

    def start(self, callback: EventCallback) -> bool:
        if not self._is_windows():
            self._degraded_reason = "WINDOWS_ONLY"
            return False
        if self._session_factory is None:
            self._degraded_reason = "ETW_LOCAL_ADAPTER_NOT_CONFIGURED"
            return False
        try:
            session = self._session_factory()
            started = session.start(callback)
            if started is False:
                self._degraded_reason = "ETW_SESSION_REJECTED_START"
                return False
            self._session = session
            self._active = True
            self._degraded_reason = None
            return True
        except (OSError, RuntimeError, ValueError) as exc:
            self._degraded_reason = f"ETW_SESSION_START_FAILED:{type(exc).__name__}"
            logger.warning("local ETW session unavailable: %s", exc)
            return False

    def stop(self) -> None:
        session, self._session = self._session, None
        self._active = False
        if session is not None:
            try:
                session.stop()
            except (OSError, RuntimeError, ValueError) as exc:
                logger.warning("local ETW session stop failed: %s", exc)

    def status(self) -> dict[str, object]:
        session_status: dict[str, object] = {}
        if self._session is not None:
            try:
                session_status = dict(self._session.status())
            except (OSError, RuntimeError, ValueError, TypeError) as exc:
                session_status = {"status_error": type(exc).__name__}
        return {
            "backend": "ETW",
            "active": self._active,
            "degraded_reason": self._degraded_reason,
            "local_only": True,
            "session": session_status,
        }


class ReadDirectoryChangesBackend:
    """Native, local-only Windows directory-change monitor.

    This is a detection backend, not a pre-execution enforcement mechanism.
    It observes NTFS changes through Windows kernel notifications and provides
    file paths to the entropy pipeline.  A signed minifilter remains necessary
    for reliable execution blocking.
    """

    FILE_LIST_DIRECTORY = 0x0001
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000

    FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
    FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
    FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
    FILE_NOTIFY_CHANGE_SIZE = 0x00000008
    FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
    FILE_NOTIFY_CHANGE_CREATION = 0x00000040
    FILE_NOTIFY_CHANGE_SECURITY = 0x00000100
    NOTIFY_FILTER = (
        FILE_NOTIFY_CHANGE_FILE_NAME
        | FILE_NOTIFY_CHANGE_DIR_NAME
        | FILE_NOTIFY_CHANGE_ATTRIBUTES
        | FILE_NOTIFY_CHANGE_SIZE
        | FILE_NOTIFY_CHANGE_LAST_WRITE
        | FILE_NOTIFY_CHANGE_CREATION
        | FILE_NOTIFY_CHANGE_SECURITY
    )

    ACTION_ADDED = 1
    ACTION_REMOVED = 2
    ACTION_MODIFIED = 3
    ACTION_RENAMED_OLD_NAME = 4
    ACTION_RENAMED_NEW_NAME = 5
    _ACTION_TO_EVENT = {
        ACTION_ADDED: FILE_CREATED,
        ACTION_REMOVED: FILE_DELETED,
        ACTION_MODIFIED: FILE_MODIFIED,
    }

    def __init__(
        self,
        roots: Iterable[str],
        *,
        recursive: bool = True,
        buffer_size: int = 64 * 1024,
        is_windows: Callable[[], bool] | None = None,
    ) -> None:
        if buffer_size < 1024:
            raise ValueError("buffer_size must be at least 1024 bytes")
        self.roots = list(dict.fromkeys(os.path.abspath(os.fspath(root)) for root in roots))
        self.recursive = recursive
        self.buffer_size = buffer_size
        self._is_windows = is_windows or (lambda: os.name == "nt")
        self._callback: EventCallback | None = None
        self._running = threading.Event()
        self._handles: dict[str, object] = {}
        self._threads: list[threading.Thread] = []
        self._handle_lock = threading.Lock()
        self._implementation: str | None = None
        self._win32file: Any | None = None
        self._win32con: Any | None = None
        self._kernel32: Any | None = None
        self._degraded_reason: str | None = None
        self._read_errors = 0
        self._events_seen = 0
        self._overflows = 0

    def start(self, callback: EventCallback) -> bool:
        if self._running.is_set():
            return True
        if not self._is_windows():
            self._degraded_reason = "WINDOWS_ONLY"
            return False
        roots = [root for root in self.roots if os.path.isdir(root)]
        if not roots:
            self._degraded_reason = "NO_VALID_MONITOR_ROOTS"
            return False
        try:
            self._load_windows_api()
            opened: dict[str, object] = {}
            for root in roots:
                opened[root] = self._open_directory(root)
        except (OSError, RuntimeError, ValueError) as exc:
            for handle in locals().get("opened", {}).values():
                self._close_handle(handle)
            self._degraded_reason = f"DIRECTORY_WATCH_START_FAILED:{type(exc).__name__}"
            logger.warning("Windows directory monitor unavailable: %s", exc)
            return False

        self._callback = callback
        self._handles = opened
        self._running.set()
        self._degraded_reason = None
        self._threads = [
            threading.Thread(
                target=self._watch_root,
                args=(root, handle),
                name=f"ElliotWindowsWatch-{index}",
                daemon=True,
            )
            for index, (root, handle) in enumerate(opened.items(), start=1)
        ]
        for thread in self._threads:
            thread.start()
        return True

    def stop(self) -> None:
        self._running.clear()
        with self._handle_lock:
            handles = list(self._handles.values())
            self._handles.clear()
        for handle in handles:
            self._cancel_handle(handle)
            self._close_handle(handle)
        for thread in self._threads:
            if thread.is_alive():
                thread.join(timeout=2.0)
        self._threads = []
        self._callback = None

    def status(self) -> dict[str, object]:
        return {
            "backend": "READ_DIRECTORY_CHANGES_W",
            "active": self._running.is_set(),
            "implementation": self._implementation,
            "roots": list(self._handles),
            "recursive": self.recursive,
            "buffer_size": self.buffer_size,
            "degraded_reason": self._degraded_reason,
            "read_errors": self._read_errors,
            "events_seen": self._events_seen,
            "overflows": self._overflows,
            "local_only": True,
            "enforcement_capability": "MONITOR_ONLY",
        }

    def _load_windows_api(self) -> None:
        try:
            import win32con  # type: ignore[import-not-found]
            import win32file  # type: ignore[import-not-found]

            self._win32con = win32con
            self._win32file = win32file
            self._implementation = "PYWIN32"
            return
        except ImportError:
            pass

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        # Explicit signatures prevent pointer-width truncation on 64-bit hosts.
        kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.ReadDirectoryChangesW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        kernel32.ReadDirectoryChangesW.restype = ctypes.c_int
        kernel32.CancelIoEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        kernel32.CancelIoEx.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        self._kernel32 = kernel32
        self._implementation = "CTYPES"

    def _open_directory(self, root: str) -> object:
        if self._implementation == "PYWIN32":
            assert self._win32file is not None and self._win32con is not None
            return self._win32file.CreateFile(
                root,
                self.FILE_LIST_DIRECTORY,
                self.FILE_SHARE_READ | self.FILE_SHARE_WRITE | self.FILE_SHARE_DELETE,
                None,
                self.OPEN_EXISTING,
                self.FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        assert self._kernel32 is not None
        handle = self._kernel32.CreateFileW(
            root,
            self.FILE_LIST_DIRECTORY,
            self.FILE_SHARE_READ | self.FILE_SHARE_WRITE | self.FILE_SHARE_DELETE,
            None,
            self.OPEN_EXISTING,
            self.FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        invalid_handle_value = ctypes.c_void_p(-1).value
        if handle in (None, invalid_handle_value):
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def _watch_root(self, root: str, handle: object) -> None:
        pending_old_name: str | None = None
        while self._running.is_set():
            try:
                changes = self._read_changes(handle)
            except OSError as exc:
                if not self._running.is_set():
                    return
                self._read_errors += 1
                logger.warning("directory-change read failed for %s: %s", root, exc)
                self._emit_overflow(root, "READ_DIRECTORY_CHANGES_FAILED")
                time.sleep(0.05)
                continue

            if not self._running.is_set():
                return
            if not changes:
                self._emit_overflow(root, "KERNEL_NOTIFICATION_BUFFER_OVERFLOW")
                continue

            for action, relative_name in changes:
                path = self._join_root(root, relative_name)
                if path is None:
                    self._emit_overflow(root, "INVALID_RELATIVE_PATH_FROM_PROVIDER")
                    continue
                if action == self.ACTION_RENAMED_OLD_NAME:
                    # The API guarantees ordering within one buffer; preserve a
                    # single pending old name across a buffer boundary as well.
                    if pending_old_name is not None:
                        self._emit(FILE_DELETED, pending_old_name, root=root)
                    pending_old_name = path
                    continue
                if action == self.ACTION_RENAMED_NEW_NAME:
                    self._emit(
                        FILE_RENAMED,
                        path,
                        root=root,
                        previous_path=pending_old_name,
                    )
                    pending_old_name = None
                    continue
                if pending_old_name is not None:
                    self._emit(FILE_DELETED, pending_old_name, root=root)
                    pending_old_name = None
                event_type = self._ACTION_TO_EVENT.get(action)
                if event_type is not None:
                    self._emit(event_type, path, root=root)

        if pending_old_name is not None:
            self._emit(FILE_DELETED, pending_old_name, root=root)

    def _read_changes(self, handle: object) -> list[tuple[int, str]]:
        if self._implementation == "PYWIN32":
            assert self._win32file is not None
            changes = self._win32file.ReadDirectoryChangesW(
                handle,
                self.buffer_size,
                self.recursive,
                self.NOTIFY_FILTER,
                None,
                None,
            )
            return [(int(action), str(name)) for action, name in changes]

        assert self._kernel32 is not None
        buffer = ctypes.create_string_buffer(self.buffer_size)
        returned = ctypes.c_uint32(0)
        success = self._kernel32.ReadDirectoryChangesW(
            handle,
            ctypes.byref(buffer),
            self.buffer_size,
            bool(self.recursive),
            self.NOTIFY_FILTER,
            ctypes.byref(returned),
            None,
            None,
        )
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())
        return self.parse_native_records(buffer.raw[: returned.value])

    @staticmethod
    def parse_native_records(buffer: bytes) -> list[tuple[int, str]]:
        """Decode one ReadDirectoryChangesW buffer with strict bounds checks."""

        records: list[tuple[int, str]] = []
        offset = 0
        size = len(buffer)
        while offset < size:
            if size - offset < 12:
                raise OSError("truncated FILE_NOTIFY_INFORMATION header")
            next_offset, action, filename_length = struct.unpack_from("<III", buffer, offset)
            end = offset + 12 + filename_length
            if filename_length % 2 or end > size:
                raise OSError("invalid FILE_NOTIFY_INFORMATION filename length")
            try:
                filename = buffer[offset + 12 : end].decode("utf-16-le", "strict")
            except UnicodeDecodeError as exc:
                raise OSError("invalid UTF-16 filename from Windows notification") from exc
            records.append((action, filename))
            if next_offset == 0:
                break
            if next_offset < 12 or offset + next_offset > size:
                raise OSError("invalid FILE_NOTIFY_INFORMATION next offset")
            offset += next_offset
        return records

    @staticmethod
    def _join_root(root: str, relative_name: str) -> str | None:
        candidate = os.path.normpath(os.path.abspath(os.path.join(root, relative_name)))
        normalized_root = os.path.normcase(os.path.normpath(os.path.abspath(root)))
        try:
            if os.path.commonpath((normalized_root, os.path.normcase(candidate))) != normalized_root:
                return None
        except ValueError:
            return None
        return candidate

    def _emit(
        self,
        event_type: str,
        path: str,
        *,
        root: str,
        previous_path: str | None = None,
    ) -> None:
        self._events_seen += 1
        callback = self._callback
        if callback is None:
            return
        try:
            callback(
                WindowsMonitorEvent(
                    event_type=event_type,
                    path=path,
                    previous_path=previous_path,
                    provider="READ_DIRECTORY_CHANGES_W",
                    metadata={"watch_root": root},
                )
            )
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            logger.warning("Windows event callback failed: %s", exc)

    def _emit_overflow(self, root: str, reason: str) -> None:
        self._overflows += 1
        callback = self._callback
        if callback is None:
            return
        try:
            callback(
                WindowsMonitorEvent(
                    event_type=OVERFLOW,
                    path=root,
                    provider="READ_DIRECTORY_CHANGES_W",
                    metadata={"watch_root": root, "reason": reason},
                )
            )
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            logger.warning("Windows overflow callback failed: %s", exc)

    def _cancel_handle(self, handle: object) -> None:
        if self._implementation == "CTYPES" and self._kernel32 is not None:
            # Cancelling a synchronous ReadDirectoryChangesW allows stop() to
            # return promptly without waiting for another filesystem event.
            self._kernel32.CancelIoEx(handle, None)

    def _close_handle(self, handle: object) -> None:
        try:
            if self._implementation == "PYWIN32" and self._win32file is not None:
                self._win32file.CloseHandle(handle)
            elif self._implementation == "CTYPES" and self._kernel32 is not None:
                self._kernel32.CloseHandle(handle)
        except (OSError, RuntimeError, ValueError):
            # Shutdown is best-effort; an invalid handle can be expected after
            # a concurrent cancellation on older Windows releases.
            pass


class AutoWindowsBackend:
    """Prefer an injected local ETW backend and fall back to NTFS notifications."""

    def __init__(
        self,
        roots: Iterable[str],
        *,
        recursive: bool = True,
        etw_backend: WindowsMonitorBackend | None = None,
        directory_backend: WindowsMonitorBackend | None = None,
    ) -> None:
        self.etw_backend = etw_backend or EtwBackend()
        self.directory_backend = directory_backend or ReadDirectoryChangesBackend(
            roots, recursive=recursive
        )
        self._active_backend: WindowsMonitorBackend | None = None

    def start(self, callback: EventCallback) -> bool:
        for backend in (self.etw_backend, self.directory_backend):
            if backend.start(callback):
                self._active_backend = backend
                return True
        return False

    def stop(self) -> None:
        active, self._active_backend = self._active_backend, None
        if active is not None:
            active.stop()

    def status(self) -> dict[str, object]:
        return {
            "backend": "AUTO_WINDOWS",
            "active_backend": (
                type(self._active_backend).__name__ if self._active_backend is not None else None
            ),
            "active": self._active_backend is not None,
            "local_only": True,
            "etw": self.etw_backend.status(),
            "directory_changes": self.directory_backend.status(),
        }
