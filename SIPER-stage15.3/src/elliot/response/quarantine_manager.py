from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import logging
import mimetypes
import os
import stat
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("elliot.quarantine")

QUARANTINE_DIR = "/var/lib/elliot/quarantine"
METADATA_DIR = "/var/lib/elliot/metadata"
_METADATA_SCHEMA_VERSION = 1
_COPY_CHUNK_SIZE = 1024 * 1024
_AT_FDCWD = -100
_RENAME_NOREPLACE = 1


class QuarantineError(RuntimeError):
    """Base error for quarantine and restoration failures."""


class QuarantineIntegrityError(QuarantineError):
    """Raised when a source, payload, or restored file fails integrity checks."""


class QuarantineConflictError(QuarantineError):
    """Raised when a requested path already exists or cannot be used safely."""


class QuarantineMetadataError(QuarantineError):
    """Raised when quarantine metadata is missing, corrupt, or invalid."""


@dataclass
class QuarantineRecord:
    schema_version: int
    quarantine_id: str
    original_path: str
    sha256: str
    size_bytes: int
    file_type: str
    timestamp: float
    timestamp_utc: str
    reason: str
    related_pid: Optional[int]
    process_info: dict[str, Any]
    triggered_rules: list[Any]
    original_mode: int
    original_uid: int
    original_gid: int
    source_device: int
    source_inode: int
    source_link_count: int
    restoration_status: str = "quarantined"
    restored_at: Optional[float] = None
    restored_at_utc: Optional[str] = None
    restored_path: Optional[str] = None
    restored_mode: Optional[int] = None
    ownership_restored: bool = False
    deleted_at: Optional[float] = None
    deleted_at_utc: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class QuarantineManager:
    """Safely quarantine and restore regular files.

    The manager rejects symbolic-link inputs, verifies source and payload hashes,
    uses protected directories and files, writes metadata atomically, and never
    overwrites an existing restoration destination.

    The path-only quarantine API mitigates TOCTOU races by opening the source
    with ``O_NOFOLLOW`` and moving it to a private holding name before copying.
    A future fanotify integration should pass the kernel-provided file
    descriptor to remove the remaining path-resolution dependency entirely.
    """

    def __init__(
        self,
        quarantine_dir: str | os.PathLike[str] = QUARANTINE_DIR,
        metadata_dir: str | os.PathLike[str] = METADATA_DIR,
        audit_log: Any = None,
    ) -> None:
        self.quarantine_dir = Path(quarantine_dir)
        self.metadata_dir = Path(metadata_dir)
        self.audit_log = audit_log
        self._prepare_private_directory(self.quarantine_dir)
        self._prepare_private_directory(self.metadata_dir)

    def quarantine_file(
        self,
        path: str | os.PathLike[str],
        expected_sha256: Optional[str],
        reason: str,
        related_pid: Optional[int],
        triggered_rules: list[Any],
        process_info: Optional[dict[str, Any]] = None,
        *,
        expected_device: Optional[int] = None,
        expected_inode: Optional[int] = None,
        expected_size: Optional[int] = None,
        expected_mtime_ns: Optional[int] = None,
        expected_ctime_ns: Optional[int] = None,
    ) -> QuarantineRecord:
        """Move a regular file into protected quarantine storage.

        The original path is removed only after the source is moved to a private
        holding name, the protected payload is copied and verified, and metadata
        is written successfully. On a recoverable failure, the holding file is
        moved back to the original path and partial quarantine artifacts are
        removed.
        """

        source_path = self._canonical_source_path(path)
        self._validate_expected_hash(expected_sha256)
        safe_reason = self._require_nonempty_text(reason, "reason")
        if not isinstance(triggered_rules, list):
            raise QuarantineError("triggered_rules must be a list")
        safe_rules = self._require_json_value(triggered_rules, "triggered_rules")
        if process_info is not None and not isinstance(process_info, dict):
            raise QuarantineError("process_info must be an object")
        safe_process = self._require_json_value(process_info or {}, "process_info")
        safe_pid = self._validate_pid(related_pid)

        source_fd: Optional[int] = None
        holding_path: Optional[Path] = None
        temporary_payload: Optional[Path] = None
        final_payload: Optional[Path] = None
        metadata_path: Optional[Path] = None

        try:
            source_fd, source_stat = self._open_regular_nofollow(source_path)
            expected_identity = (expected_device, expected_inode)
            if any(value is not None for value in expected_identity):
                if None in expected_identity:
                    raise QuarantineError(
                        "expected_device and expected_inode must be supplied together"
                    )
                if (source_stat.st_dev, source_stat.st_ino) != expected_identity:
                    raise QuarantineIntegrityError(
                        "Source file identity changed before quarantine; no file was removed"
                    )
            if expected_size is not None and source_stat.st_size != int(expected_size):
                raise QuarantineIntegrityError(
                    "Source file size changed before quarantine; no file was removed"
                )
            if expected_mtime_ns is not None and source_stat.st_mtime_ns != int(expected_mtime_ns):
                raise QuarantineIntegrityError(
                    "Source file modification time changed before quarantine; no file was removed"
                )
            if expected_ctime_ns is not None and source_stat.st_ctime_ns != int(expected_ctime_ns):
                raise QuarantineIntegrityError(
                    "Source file change time changed before quarantine; no file was removed"
                )
            if source_stat.st_nlink != 1:
                raise QuarantineError(
                    "Source has multiple hard links; path-only quarantine cannot isolate all aliases"
                )
            source_hash = self._hash_fd(source_fd)
            self._assert_fd_unchanged(source_fd, source_stat, "hash calculation")

            if expected_sha256 and source_hash != expected_sha256.lower():
                raise QuarantineIntegrityError(
                    "Source hash changed before quarantine; the original file was not removed"
                )

            quarantine_id = str(uuid.uuid4())
            holding_path = source_path.parent / f".elliot-{quarantine_id}.pending"
            self._move_noreplace(source_path, holding_path)
            self._assert_path_matches_fd(holding_path, source_fd, source_stat)
            held_stat = os.fstat(source_fd)
            if (
                held_stat.st_size != source_stat.st_size
                or held_stat.st_mtime_ns != source_stat.st_mtime_ns
            ):
                raise QuarantineIntegrityError(
                    "Source content changed during protected move"
                )

            final_payload = self._payload_path(quarantine_id)
            temporary_payload = self.quarantine_dir / f".{quarantine_id}.{uuid.uuid4().hex}.tmp"
            copied_hash, copied_size = self._copy_fd_to_new_file(source_fd, temporary_payload)

            if copied_hash != source_hash or copied_size != source_stat.st_size:
                raise QuarantineIntegrityError(
                    "Protected quarantine copy does not match the opened source file"
                )
            self._assert_fd_unchanged(source_fd, held_stat, "quarantine copy")

            self._move_noreplace(temporary_payload, final_payload)
            temporary_payload = None
            os.chmod(final_payload, 0o600)
            self._fsync_directory(self.quarantine_dir)

            now = time.time()
            record = QuarantineRecord(
                schema_version=_METADATA_SCHEMA_VERSION,
                quarantine_id=quarantine_id,
                original_path=str(source_path),
                sha256=source_hash,
                size_bytes=source_stat.st_size,
                file_type=self._detect_file_type(final_payload),
                timestamp=now,
                timestamp_utc=self._utc_iso(now),
                reason=safe_reason,
                related_pid=safe_pid,
                process_info=safe_process,
                triggered_rules=safe_rules,
                original_mode=stat.S_IMODE(source_stat.st_mode),
                original_uid=source_stat.st_uid,
                original_gid=source_stat.st_gid,
                source_device=source_stat.st_dev,
                source_inode=source_stat.st_ino,
                source_link_count=source_stat.st_nlink,
            )
            self._validate_record(record)
            metadata_path = self._metadata_path(quarantine_id)
            self._write_metadata_atomic(record)

            holding_path.unlink()
            holding_path = None
            try:
                self._fsync_directory(source_path.parent)
            except OSError as exc:
                logger.error(
                    "Quarantine committed but source-directory fsync failed: %s", exc
                )

        except (OSError, ValueError, TypeError, QuarantineError) as exc:
            recovery_error = self._rollback_quarantine(
                original_path=source_path,
                holding_path=holding_path,
                temporary_payload=temporary_payload,
                final_payload=final_payload,
                metadata_path=metadata_path,
            )
            if recovery_error:
                raise QuarantineError(
                    f"Quarantine failed and automatic rollback was incomplete: {recovery_error}"
                ) from exc
            if isinstance(exc, QuarantineError):
                raise
            raise QuarantineError(f"Quarantine failed safely: {exc}") from exc
        finally:
            if source_fd is not None:
                os.close(source_fd)

        logger.warning(
            "File quarantined: %s -> %s (id=%s)",
            record.original_path,
            final_payload,
            record.quarantine_id,
        )
        self._audit("quarantine", record.original_path, record.to_dict())
        return record

    def restore_file(
        self,
        quarantine_id: str,
        destination: Optional[str | os.PathLike[str]] = None,
    ) -> QuarantineRecord:
        """Restore a quarantined payload without overwriting any existing path."""

        record = self._load_metadata(quarantine_id)
        if record.restoration_status == "deleted":
            raise QuarantineError(f"Quarantine item has been permanently deleted: {quarantine_id}")

        payload_path = self._payload_path(record.quarantine_id)
        if not os.path.lexists(payload_path):
            raise QuarantineError(
                f"Quarantine payload does not exist: {record.quarantine_id}"
            )
        payload_fd: Optional[int] = None
        target_fd: Optional[int] = None
        target_path: Optional[Path] = None
        target_identity: Optional[tuple[int, int]] = None
        previous_record = QuarantineRecord(**record.to_dict())

        try:
            payload_fd, payload_stat = self._open_regular_nofollow(payload_path)
            payload_hash = self._hash_fd(payload_fd)
            self._assert_fd_unchanged(payload_fd, payload_stat, "restore verification")
            if payload_hash != record.sha256 or payload_stat.st_size != record.size_bytes:
                raise QuarantineIntegrityError(
                    "Quarantine payload integrity verification failed; restoration was aborted"
                )

            target_path = self._prepare_restore_target(destination, record.original_path)
            target_fd = self._open_exclusive_restore_target(target_path)
            opened_target_stat = os.fstat(target_fd)
            target_identity = (opened_target_stat.st_dev, opened_target_stat.st_ino)
            target_hash, target_size = self._copy_between_fds(payload_fd, target_fd)
            if target_hash != record.sha256 or target_size != record.size_bytes:
                raise QuarantineIntegrityError(
                    "Restored file does not match quarantine metadata"
                )

            restored_mode = record.original_mode & 0o0777
            os.fchmod(target_fd, restored_mode)
            ownership_restored = self._restore_ownership_if_privileged(
                target_fd, record.original_uid, record.original_gid
            )
            os.fsync(target_fd)
            target_stat = os.fstat(target_fd)
            target_identity = (target_stat.st_dev, target_stat.st_ino)

            now = time.time()
            record.restoration_status = "restored"
            record.restored_at = now
            record.restored_at_utc = self._utc_iso(now)
            record.restored_path = str(target_path)
            record.restored_mode = restored_mode
            record.ownership_restored = ownership_restored
            self._write_metadata_atomic(record)
            self._fsync_directory(target_path.parent)

        except (OSError, ValueError, TypeError, QuarantineError) as exc:
            rollback_error = None
            if target_fd is not None:
                try:
                    os.close(target_fd)
                finally:
                    target_fd = None
            if target_path is not None and target_identity is not None:
                try:
                    self._unlink_if_identity_matches(target_path, target_identity)
                except OSError as rollback_exc:
                    rollback_error = str(rollback_exc)
            try:
                if previous_record.to_dict() != record.to_dict():
                    self._write_metadata_atomic(previous_record)
            except (OSError, ValueError, TypeError, QuarantineError) as metadata_exc:
                rollback_error = rollback_error or f"metadata rollback failed: {metadata_exc}"

            if rollback_error:
                raise QuarantineError(
                    f"Restoration failed and rollback was incomplete: {rollback_error}"
                ) from exc
            if isinstance(exc, QuarantineError):
                raise
            raise QuarantineError(f"Restoration failed safely: {exc}") from exc
        finally:
            if target_fd is not None:
                os.close(target_fd)
            if payload_fd is not None:
                os.close(payload_fd)

        logger.warning("File restored: %s -> %s", record.quarantine_id, target_path)
        self._audit(
            "quarantine",
            str(target_path),
            {"action": "restore", **record.to_dict()},
        )
        return record

    def delete_permanently(self, quarantine_id: str) -> None:
        """Delete a quarantine payload using a rollback-capable pending rename."""

        record = self._load_metadata(quarantine_id)
        if record.restoration_status == "deleted":
            return

        payload_path = self._payload_path(record.quarantine_id)
        if not os.path.lexists(payload_path):
            raise QuarantineError(f"Quarantine payload is missing: {record.quarantine_id}")

        pending_path = self.quarantine_dir / f".{record.quarantine_id}.delete-pending"
        previous_record = QuarantineRecord(**record.to_dict())
        self._move_noreplace(payload_path, pending_path)

        try:
            now = time.time()
            record.restoration_status = "deleted"
            record.deleted_at = now
            record.deleted_at_utc = self._utc_iso(now)
            self._write_metadata_atomic(record)
            pending_path.unlink()
            self._fsync_directory(self.quarantine_dir)
        except (OSError, ValueError, TypeError, QuarantineError) as exc:
            try:
                if os.path.lexists(pending_path) and not os.path.lexists(payload_path):
                    self._move_noreplace(pending_path, payload_path)
                self._write_metadata_atomic(previous_record)
            except (OSError, ValueError, TypeError, QuarantineError) as rollback_exc:
                raise QuarantineError(
                    f"Permanent deletion failed and rollback was incomplete: {rollback_exc}"
                ) from exc
            if isinstance(exc, QuarantineError):
                raise
            raise QuarantineError(f"Permanent deletion failed safely: {exc}") from exc

        self._audit(
            "quarantine",
            record.original_path,
            {"action": "delete", **record.to_dict()},
        )

    def list_quarantine(self, *, strict: bool = True) -> list[QuarantineRecord]:
        """Return metadata records sorted newest first.

        In strict mode, corrupt metadata raises an explicit error instead of being
        silently omitted. ``strict=False`` logs corrupt entries and returns the
        remaining valid records.
        """

        records: list[QuarantineRecord] = []
        errors: list[str] = []
        for metadata_file in sorted(self.metadata_dir.glob("*.json")):
            try:
                records.append(self._load_metadata(metadata_file.stem))
            except QuarantineMetadataError as exc:
                errors.append(f"{metadata_file.name}: {exc}")

        if errors and strict:
            raise QuarantineMetadataError("; ".join(errors))
        for error in errors:
            logger.error("Skipping invalid quarantine metadata: %s", error)
        return sorted(records, key=lambda item: item.timestamp, reverse=True)

    def get_record(self, quarantine_id: str) -> QuarantineRecord:
        return self._load_metadata(quarantine_id)

    @staticmethod
    def sha256_file(path: str | os.PathLike[str]) -> str:
        """Return a file SHA-256 hash for authorised analysis workflows."""

        source = Path(path)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(source, flags)
        except OSError as exc:
            raise QuarantineError(f"Cannot open file for hashing: {source}: {exc}") from exc
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise QuarantineError(f"Only regular files can be hashed: {source}")
            return QuarantineManager._hash_fd(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _prepare_private_directory(path: Path) -> None:
        if os.path.lexists(path):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise QuarantineError(f"Protected path is not a real directory: {path}")
        else:
            path.mkdir(parents=True, mode=0o700)
        info = path.lstat()
        if info.st_uid != os.geteuid():
            raise QuarantineError(
                f"Protected directory is not owned by the current service user: {path}"
            )
        os.chmod(path, 0o700)

    @staticmethod
    def _canonical_source_path(path: str | os.PathLike[str]) -> Path:
        raw = Path(path).expanduser()
        if not raw.is_absolute():
            raw = Path.cwd() / raw
        if not os.path.lexists(raw):
            raise QuarantineError(f"Source file does not exist: {raw}")
        if stat.S_ISLNK(raw.lstat().st_mode):
            raise QuarantineError(f"Symbolic-link sources are not accepted: {raw}")
        try:
            parent = raw.parent.resolve(strict=True)
        except OSError as exc:
            raise QuarantineError(f"Cannot resolve source parent directory: {raw.parent}") from exc
        canonical = parent / raw.name
        if not os.path.lexists(canonical):
            raise QuarantineError(f"Source file disappeared before quarantine: {canonical}")
        return canonical

    @staticmethod
    def _open_regular_nofollow(path: Path) -> tuple[int, os.stat_result]:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise QuarantineError(f"Symbolic-link path rejected: {path}") from exc
            raise QuarantineError(f"Cannot securely open file: {path}: {exc}") from exc

        try:
            opened_stat = os.fstat(fd)
            if not stat.S_ISREG(opened_stat.st_mode):
                raise QuarantineError(f"Only regular files can be quarantined: {path}")
            path_stat = path.lstat()
            if stat.S_ISLNK(path_stat.st_mode):
                raise QuarantineError(f"Symbolic-link path rejected: {path}")
            if (path_stat.st_dev, path_stat.st_ino) != (
                opened_stat.st_dev,
                opened_stat.st_ino,
            ):
                raise QuarantineIntegrityError(
                    f"File identity changed while opening: {path}"
                )
            return fd, opened_stat
        except (OSError, QuarantineError):
            os.close(fd)
            raise

    @staticmethod
    def _hash_fd(fd: int) -> str:
        digest = hashlib.sha256()
        os.lseek(fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(fd, _COPY_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
        os.lseek(fd, 0, os.SEEK_SET)
        return digest.hexdigest()

    @staticmethod
    def _assert_fd_unchanged(
        fd: int, initial: os.stat_result, operation: str
    ) -> None:
        current = os.fstat(fd)
        stable_fields = (
            current.st_dev == initial.st_dev,
            current.st_ino == initial.st_ino,
            current.st_size == initial.st_size,
            current.st_mtime_ns == initial.st_mtime_ns,
            current.st_ctime_ns == initial.st_ctime_ns,
        )
        if not all(stable_fields):
            raise QuarantineIntegrityError(
                f"Source changed during {operation}; quarantine was aborted"
            )

    @staticmethod
    def _assert_path_matches_fd(
        path: Path, fd: int, initial: os.stat_result
    ) -> None:
        path_stat = path.lstat()
        fd_stat = os.fstat(fd)
        expected = (initial.st_dev, initial.st_ino)
        if stat.S_ISLNK(path_stat.st_mode):
            raise QuarantineIntegrityError(f"Holding path became a symbolic link: {path}")
        if (path_stat.st_dev, path_stat.st_ino) != expected:
            raise QuarantineIntegrityError("Source identity changed during protected move")
        if (fd_stat.st_dev, fd_stat.st_ino) != expected:
            raise QuarantineIntegrityError("Opened source identity changed unexpectedly")

    def _copy_fd_to_new_file(self, source_fd: int, destination: Path) -> tuple[str, int]:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        destination_fd = os.open(destination, flags, 0o600)
        try:
            digest, total = self._copy_between_fds(source_fd, destination_fd)
            os.fchmod(destination_fd, 0o600)
            os.fsync(destination_fd)
            return digest, total
        finally:
            os.close(destination_fd)

    @staticmethod
    def _copy_between_fds(source_fd: int, destination_fd: int) -> tuple[str, int]:
        digest = hashlib.sha256()
        total = 0
        os.lseek(source_fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(source_fd, _COPY_CHUNK_SIZE)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    raise OSError("Short write while copying protected file")
                view = view[written:]
            digest.update(chunk)
            total += len(chunk)
        os.lseek(source_fd, 0, os.SEEK_SET)
        return digest.hexdigest(), total

    @staticmethod
    def _move_noreplace(source: Path, destination: Path) -> None:
        if os.path.lexists(destination):
            raise QuarantineConflictError(f"Destination already exists: {destination}")

        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is not None:
            renameat2.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameat2.restype = ctypes.c_int
            result = renameat2(
                _AT_FDCWD,
                os.fsencode(source),
                _AT_FDCWD,
                os.fsencode(destination),
                _RENAME_NOREPLACE,
            )
            if result == 0:
                return
            error_number = ctypes.get_errno()
            if error_number not in {errno.ENOSYS, errno.EINVAL}:
                raise OSError(error_number, os.strerror(error_number), str(source))

        # Portable no-overwrite fallback for files on the same filesystem.
        link_created = False
        try:
            os.link(source, destination, follow_symlinks=False)
            link_created = True
            os.unlink(source)
        except OSError:
            if link_created:
                try:
                    destination.unlink(missing_ok=True)
                except OSError:
                    logger.critical("Could not clean failed move destination: %s", destination)
            raise

    def _write_metadata_atomic(self, record: QuarantineRecord) -> None:
        self._validate_record(record)
        destination = self._metadata_path(record.quarantine_id)
        if os.path.lexists(destination):
            destination_stat = destination.lstat()
            if stat.S_ISLNK(destination_stat.st_mode) or not stat.S_ISREG(
                destination_stat.st_mode
            ):
                raise QuarantineMetadataError(
                    f"Metadata destination is not a regular file: {destination}"
                )

        payload = json.dumps(
            record.to_dict(),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        temporary = self.metadata_dir / f".{record.quarantine_id}.{uuid.uuid4().hex}.tmp"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        fd = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("Short write while saving quarantine metadata")
                view = view[written:]
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        except OSError:
            os.close(fd)
            temporary.unlink(missing_ok=True)
            raise
        else:
            os.close(fd)

        try:
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
            self._fsync_directory(self.metadata_dir)
        except OSError:
            temporary.unlink(missing_ok=True)
            raise

    def _load_metadata(self, quarantine_id: str) -> QuarantineRecord:
        safe_id = self._validate_quarantine_id(quarantine_id)
        path = self._metadata_path(safe_id)
        if not os.path.lexists(path):
            raise QuarantineMetadataError(f"Metadata not found: {safe_id}")
        path_stat = path.lstat()
        if stat.S_ISLNK(path_stat.st_mode) or not stat.S_ISREG(path_stat.st_mode):
            raise QuarantineMetadataError(f"Metadata path is unsafe: {path}")

        try:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise QuarantineMetadataError(f"Metadata cannot be read: {safe_id}: {exc}") from exc

        if not isinstance(data, dict):
            raise QuarantineMetadataError(f"Metadata root must be an object: {safe_id}")
        try:
            record = QuarantineRecord(**data)
        except TypeError as exc:
            raise QuarantineMetadataError(
                f"Metadata fields are incomplete or unsupported: {safe_id}"
            ) from exc
        self._validate_record(record)
        if record.quarantine_id != safe_id:
            raise QuarantineMetadataError("Metadata ID does not match its filename")
        return record

    @staticmethod
    def _validate_record(record: QuarantineRecord) -> None:
        if record.schema_version != _METADATA_SCHEMA_VERSION:
            raise QuarantineMetadataError(
                f"Unsupported metadata schema: {record.schema_version}"
            )
        QuarantineManager._validate_quarantine_id(record.quarantine_id)
        if not Path(record.original_path).is_absolute():
            raise QuarantineMetadataError("Original path must be absolute")
        if len(record.sha256) != 64 or any(
            character not in "0123456789abcdef" for character in record.sha256
        ):
            raise QuarantineMetadataError("Invalid SHA-256 value in metadata")
        if not isinstance(record.size_bytes, int) or record.size_bytes < 0:
            raise QuarantineMetadataError("Invalid file size in metadata")
        if record.restoration_status not in {"quarantined", "restored", "deleted"}:
            raise QuarantineMetadataError("Invalid restoration status")
        if not isinstance(record.triggered_rules, list):
            raise QuarantineMetadataError("triggered_rules must be a list")
        if not isinstance(record.process_info, dict):
            raise QuarantineMetadataError("process_info must be an object")
        QuarantineManager._require_json_value(record.to_dict(), "metadata")

    @staticmethod
    def _validate_quarantine_id(quarantine_id: str) -> str:
        if not isinstance(quarantine_id, str):
            raise QuarantineMetadataError("Quarantine ID must be a string")
        try:
            parsed = uuid.UUID(quarantine_id)
        except (ValueError, AttributeError) as exc:
            raise QuarantineMetadataError("Invalid quarantine ID") from exc
        canonical = str(parsed)
        if quarantine_id.lower() != canonical:
            raise QuarantineMetadataError("Quarantine ID is not canonical")
        return canonical

    @staticmethod
    def _validate_expected_hash(value: Optional[str]) -> None:
        if value is None:
            return
        if not isinstance(value, str) or len(value) != 64 or any(
            character not in "0123456789abcdefABCDEF" for character in value
        ):
            raise QuarantineError("expected_sha256 must contain 64 hexadecimal characters")

    @staticmethod
    def _validate_pid(value: Optional[int]) -> Optional[int]:
        if value is None:
            return None
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise QuarantineError("related_pid must be a positive integer or null")
        return value

    @staticmethod
    def _require_nonempty_text(value: Any, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise QuarantineError(f"{name} must be a non-empty string")
        return value.strip()

    @staticmethod
    def _require_json_value(value: Any, name: str) -> Any:
        try:
            json.dumps(value, ensure_ascii=False, allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise QuarantineError(f"{name} must be JSON-serialisable") from exc
        return value

    def _prepare_restore_target(
        self,
        destination: Optional[str | os.PathLike[str]],
        original_path: str,
    ) -> Path:
        raw = Path(destination) if destination is not None else Path(original_path)
        raw = raw.expanduser()
        if not raw.is_absolute():
            raise QuarantineConflictError("Restore destination must be an absolute path")
        if os.path.lexists(raw):
            raise QuarantineConflictError(
                f"Restore destination already exists and will not be overwritten: {raw}"
            )
        try:
            parent = raw.parent.resolve(strict=True)
        except OSError as exc:
            raise QuarantineConflictError(
                f"Restore parent directory does not exist or is inaccessible: {raw.parent}"
            ) from exc
        if not parent.is_dir():
            raise QuarantineConflictError(f"Restore parent is not a directory: {parent}")
        target = parent / raw.name
        if os.path.lexists(target):
            raise QuarantineConflictError(
                f"Restore destination already exists and will not be overwritten: {target}"
            )
        return target

    @staticmethod
    def _open_exclusive_restore_target(path: Path) -> int:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            return os.open(path, flags, 0o600)
        except FileExistsError as exc:
            raise QuarantineConflictError(
                f"Restore destination already exists and will not be overwritten: {path}"
            ) from exc

    @staticmethod
    def _restore_ownership_if_privileged(fd: int, uid: int, gid: int) -> bool:
        if os.geteuid() != 0:
            return False
        os.fchown(fd, uid, gid)
        return True

    @staticmethod
    def _unlink_if_identity_matches(path: Path, identity: tuple[int, int]) -> None:
        if not os.path.lexists(path):
            return
        info = path.lstat()
        if (info.st_dev, info.st_ino) != identity:
            raise OSError(f"Refusing to remove replacement path during rollback: {path}")
        path.unlink()

    def _rollback_quarantine(
        self,
        *,
        original_path: Path,
        holding_path: Optional[Path],
        temporary_payload: Optional[Path],
        final_payload: Optional[Path],
        metadata_path: Optional[Path],
    ) -> Optional[str]:
        try:
            if holding_path is not None and os.path.lexists(holding_path):
                if os.path.lexists(original_path):
                    return (
                        f"original path is occupied; recovery file retained at {holding_path}"
                    )
                self._move_noreplace(holding_path, original_path)
                self._fsync_directory(original_path.parent)
            if temporary_payload is not None:
                temporary_payload.unlink(missing_ok=True)
            if metadata_path is not None:
                metadata_path.unlink(missing_ok=True)
            if final_payload is not None:
                final_payload.unlink(missing_ok=True)
            self._fsync_directory(self.quarantine_dir)
            self._fsync_directory(self.metadata_dir)
            return None
        except OSError as exc:
            logger.critical("Quarantine rollback failed: %s", exc)
            return str(exc)

    def _payload_path(self, quarantine_id: str) -> Path:
        return self.quarantine_dir / self._validate_quarantine_id(quarantine_id)

    def _metadata_path(self, quarantine_id: str) -> Path:
        return self.metadata_dir / f"{self._validate_quarantine_id(quarantine_id)}.json"

    @staticmethod
    def _detect_file_type(path: Path) -> str:
        try:
            with path.open("rb") as handle:
                if handle.read(4) == b"\x7fELF":
                    return "application/x-elf"
        except OSError:
            return "application/octet-stream"

        try:
            import magic

            detected = magic.from_file(str(path), mime=True)
            if isinstance(detected, str) and detected:
                return detected
        except (ImportError, OSError, AttributeError):
            pass
        guessed, _ = mimetypes.guess_type(path.name)
        return guessed or "application/octet-stream"

    @staticmethod
    def _utc_iso(timestamp: float) -> str:
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError as exc:
            if exc.errno not in {errno.EINVAL, errno.EROFS}:
                raise
        finally:
            os.close(fd)

    def _audit(self, event_type: str, target: str, details: dict[str, Any]) -> None:
        if self.audit_log is None:
            return
        try:
            self.audit_log.record(event_type, target, details)
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            logger.error("Audit recording failed after committed action: %s", exc)
