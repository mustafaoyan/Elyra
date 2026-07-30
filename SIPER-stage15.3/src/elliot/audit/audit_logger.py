from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import stat
import threading
import time
import uuid
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

DEFAULT_LOG_DIR = "/var/log/elliot"
DEFAULT_LOG_FILE = "audit.jsonl"
ZERO_HASH = "0" * 64
SCHEMA_VERSION = "2.0"


class AuditError(RuntimeError):
    """Base class for audit-log failures."""


class AuditIntegrityError(AuditError):
    """Raised when an existing audit chain cannot be trusted."""

    def __init__(self, report: "IntegrityReport") -> None:
        self.report = report
        super().__init__(
            f"audit integrity check failed at {report.error_segment or '<unknown>'}:"
            f"{report.error_line or 0}: {report.error or 'unknown error'}"
        )


class AuditSecurityError(AuditError):
    """Raised for unsafe paths, symlinks, or file types."""


@dataclass(frozen=True)
class IntegrityReport:
    valid: bool
    record_count: int
    segment_count: int
    coverage: str
    first_prev_hash: str
    last_hash: str
    last_sequence: int
    error: str | None = None
    error_segment: str | None = None
    error_line: int | None = None
    repaired_trailing_partial: bool = False
    recovery_artifact: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AuditStatus:
    log_path: str
    directory_mode: str
    file_mode: str | None
    max_bytes: int
    backup_count: int
    startup_integrity: dict[str, Any]
    threat_model: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _canonical_json(value: Mapping[str, Any], *, legacy: bool = False) -> str:
    if legacy:
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def _record_hash(entry_without_hash: Mapping[str, Any]) -> str:
    if entry_without_hash.get("schema_version") == SCHEMA_VERSION:
        encoded = _canonical_json(entry_without_hash).encode("utf-8")
    else:
        # Stage 1–11 compatibility. The historical implementation prefixed the
        # previous hash in addition to storing it inside the JSON object.
        prev_hash = str(entry_without_hash.get("prev_hash", ZERO_HASH))
        encoded = (prev_hash + _canonical_json(entry_without_hash, legacy=True)).encode(
            "utf-8"
        )
    return hashlib.sha256(encoded).hexdigest()


def _safe_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            return str(value)
        return value
    if isinstance(value, bytes):
        return {"type": "bytes", "hex": value.hex()}
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return _safe_value(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _safe_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_safe_value(item) for item in value), key=repr)
    return {"type": type(value).__name__, "repr": repr(value)}


def _validate_hex_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _segment_index(path: Path, file_name: str) -> int | None:
    prefix = f"{file_name}."
    if not path.name.startswith(prefix):
        return None
    suffix = path.name[len(prefix) :]
    if len(suffix) != 6 or not suffix.isdigit():
        return None
    return int(suffix)


def _segments_for(log_dir: Path, file_name: str) -> list[Path]:
    rotated: list[tuple[int, Path]] = []
    if log_dir.exists():
        for candidate in log_dir.iterdir():
            index = _segment_index(candidate, file_name)
            if index is not None:
                rotated.append((index, candidate))
    rotated.sort(key=lambda item: item[0])
    result = [path for _, path in rotated]
    active = log_dir / file_name
    if active.exists() or active.is_symlink():
        result.append(active)
    return result


def _assert_regular_nosymlink(path: Path, *, allow_missing: bool = False) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if allow_missing:
            return
        raise
    if stat.S_ISLNK(metadata.st_mode):
        raise AuditSecurityError(f"audit path must not be a symbolic link: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        raise AuditSecurityError(f"audit path must be a regular file: {path}")


def verify_audit_directory(
    log_dir: str | os.PathLike[str],
    *,
    file_name: str = DEFAULT_LOG_FILE,
    repaired_trailing_partial: bool = False,
    recovery_artifact: str | None = None,
) -> IntegrityReport:
    directory = Path(log_dir)
    segments = _segments_for(directory, file_name)
    previous_hash: str | None = None
    first_prev_hash = ZERO_HASH
    last_hash = ZERO_HASH
    last_sequence = 0
    record_count = 0

    for segment in segments:
        try:
            _assert_regular_nosymlink(segment)
            raw = segment.read_bytes()
        except (OSError, AuditSecurityError) as exc:
            return IntegrityReport(
                False,
                record_count,
                len(segments),
                "UNKNOWN",
                first_prev_hash,
                last_hash,
                last_sequence,
                error=f"SEGMENT_READ_FAILED:{type(exc).__name__}:{exc}",
                error_segment=str(segment),
                repaired_trailing_partial=repaired_trailing_partial,
                recovery_artifact=recovery_artifact,
            )

        if raw and not raw.endswith(b"\n"):
            return IntegrityReport(
                False,
                record_count,
                len(segments),
                "UNKNOWN",
                first_prev_hash,
                last_hash,
                last_sequence,
                error="TRAILING_PARTIAL_RECORD",
                error_segment=str(segment),
                error_line=raw.count(b"\n") + 1,
                repaired_trailing_partial=repaired_trailing_partial,
                recovery_artifact=recovery_artifact,
            )

        for line_number, raw_line in enumerate(raw.splitlines(), start=1):
            if not raw_line.strip():
                continue
            try:
                decoded = json.loads(raw_line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                return IntegrityReport(
                    False,
                    record_count,
                    len(segments),
                    "UNKNOWN",
                    first_prev_hash,
                    last_hash,
                    last_sequence,
                    error=f"INVALID_JSON:{exc}",
                    error_segment=str(segment),
                    error_line=line_number,
                    repaired_trailing_partial=repaired_trailing_partial,
                    recovery_artifact=recovery_artifact,
                )
            if not isinstance(decoded, dict):
                return IntegrityReport(
                    False,
                    record_count,
                    len(segments),
                    "UNKNOWN",
                    first_prev_hash,
                    last_hash,
                    last_sequence,
                    error="RECORD_NOT_OBJECT",
                    error_segment=str(segment),
                    error_line=line_number,
                    repaired_trailing_partial=repaired_trailing_partial,
                    recovery_artifact=recovery_artifact,
                )
            required = {"timestamp", "source", "subject", "payload", "prev_hash", "record_hash"}
            missing = sorted(required.difference(decoded))
            if missing:
                return IntegrityReport(
                    False,
                    record_count,
                    len(segments),
                    "UNKNOWN",
                    first_prev_hash,
                    last_hash,
                    last_sequence,
                    error=f"MISSING_FIELDS:{','.join(missing)}",
                    error_segment=str(segment),
                    error_line=line_number,
                    repaired_trailing_partial=repaired_trailing_partial,
                    recovery_artifact=recovery_artifact,
                )

            stored_hash = decoded.get("record_hash")
            record_prev = decoded.get("prev_hash")
            if not _validate_hex_hash(stored_hash) or not _validate_hex_hash(record_prev):
                return IntegrityReport(
                    False,
                    record_count,
                    len(segments),
                    "UNKNOWN",
                    first_prev_hash,
                    last_hash,
                    last_sequence,
                    error="INVALID_HASH_ENCODING",
                    error_segment=str(segment),
                    error_line=line_number,
                    repaired_trailing_partial=repaired_trailing_partial,
                    recovery_artifact=recovery_artifact,
                )
            if previous_hash is None:
                first_prev_hash = str(record_prev)
                previous_hash = str(record_prev)
            if record_prev != previous_hash:
                return IntegrityReport(
                    False,
                    record_count,
                    len(segments),
                    "UNKNOWN",
                    first_prev_hash,
                    last_hash,
                    last_sequence,
                    error="PREVIOUS_HASH_MISMATCH",
                    error_segment=str(segment),
                    error_line=line_number,
                    repaired_trailing_partial=repaired_trailing_partial,
                    recovery_artifact=recovery_artifact,
                )

            unhashed = dict(decoded)
            unhashed.pop("record_hash", None)
            recomputed = _record_hash(unhashed)
            if recomputed != stored_hash:
                return IntegrityReport(
                    False,
                    record_count,
                    len(segments),
                    "UNKNOWN",
                    first_prev_hash,
                    last_hash,
                    last_sequence,
                    error="RECORD_HASH_MISMATCH",
                    error_segment=str(segment),
                    error_line=line_number,
                    repaired_trailing_partial=repaired_trailing_partial,
                    recovery_artifact=recovery_artifact,
                )

            sequence = decoded.get("sequence")
            if sequence is not None:
                if not isinstance(sequence, int) or sequence <= last_sequence:
                    return IntegrityReport(
                        False,
                        record_count,
                        len(segments),
                        "UNKNOWN",
                        first_prev_hash,
                        last_hash,
                        last_sequence,
                        error="NON_MONOTONIC_SEQUENCE",
                        error_segment=str(segment),
                        error_line=line_number,
                        repaired_trailing_partial=repaired_trailing_partial,
                        recovery_artifact=recovery_artifact,
                    )
                last_sequence = sequence
            else:
                last_sequence += 1

            previous_hash = str(stored_hash)
            last_hash = str(stored_hash)
            record_count += 1

    coverage = "FULL_FROM_GENESIS" if first_prev_hash == ZERO_HASH else "RETAINED_WINDOW"
    return IntegrityReport(
        True,
        record_count,
        len(segments),
        coverage,
        first_prev_hash,
        last_hash,
        last_sequence,
        repaired_trailing_partial=repaired_trailing_partial,
        recovery_artifact=recovery_artifact,
    )


class AuditLogger:
    """Crash-resilient JSONL audit writer with a SHA-256 hash chain.

    The chain is tamper-evident for accidental or post-write modification inside
    the retained log window. It is not an append-only hardware root of trust and
    cannot stop a privileged attacker from replacing the complete log set and
    recomputing every hash.
    """

    def __init__(
        self,
        log_dir: str = DEFAULT_LOG_DIR,
        *,
        file_name: str = DEFAULT_LOG_FILE,
        dir_mode: int = 0o750,
        file_mode: int = 0o640,
        max_bytes: int = 10 * 1024 * 1024,
        backup_count: int = 10,
        max_record_bytes: int = 1024 * 1024,
        corruption_policy: str = "raise",
        repair_trailing_partial: bool = True,
        clock: Any = time.time,
    ) -> None:
        if max_bytes < 512:
            raise ValueError("max_bytes must be at least 512")
        if backup_count < 0:
            raise ValueError("backup_count cannot be negative")
        if max_record_bytes < 256:
            raise ValueError("max_record_bytes must be at least 256")
        if corruption_policy not in {"raise", "quarantine"}:
            raise ValueError("corruption_policy must be 'raise' or 'quarantine'")
        if Path(file_name).name != file_name or not file_name:
            raise ValueError("file_name must be a simple filename")

        self.log_dir = Path(log_dir)
        self.file_name = file_name
        self.log_path = self.log_dir / file_name
        self.lock_path = self.log_dir / f".{file_name}.lock"
        self.dir_mode = dir_mode
        self.file_mode = file_mode
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self.max_record_bytes = max_record_bytes
        self.corruption_policy = corruption_policy
        self.repair_trailing_partial = repair_trailing_partial
        self._clock = clock
        self._thread_lock = threading.RLock()
        self._last_hash = ZERO_HASH
        self._last_sequence = 0
        self._repaired_partial = False
        self._recovery_artifact: str | None = None

        self._ensure_secure_directory()
        self._ensure_lock_file()
        with self._exclusive_process_lock():
            self._enforce_segment_permissions_locked()
            if self.repair_trailing_partial:
                self._repair_active_trailing_partial_locked()
            report = verify_audit_directory(
                self.log_dir,
                file_name=self.file_name,
                repaired_trailing_partial=self._repaired_partial,
                recovery_artifact=self._recovery_artifact,
            )
            if not report.valid:
                if self.corruption_policy == "raise":
                    raise AuditIntegrityError(report)
                artifact = self._quarantine_corrupt_segments_locked(report)
                self._recovery_artifact = str(artifact)
                self._last_hash = ZERO_HASH
                self._last_sequence = 0
                self.startup_integrity_report = report
                self._append_record_locked(
                    "audit",
                    "corruption_recovery",
                    {
                        "previous_integrity": report.to_dict(),
                        "quarantined_to": str(artifact),
                        "limitation": (
                            "A new chain was started. The prior corrupted chain is preserved "
                            "for forensic review but is not trusted."
                        ),
                    },
                )
            else:
                self._last_hash = report.last_hash
                self._last_sequence = report.last_sequence
                self.startup_integrity_report = report

    def _ensure_secure_directory(self) -> None:
        if self.log_dir.exists() or self.log_dir.is_symlink():
            metadata = self.log_dir.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise AuditSecurityError(f"audit directory must not be a symlink: {self.log_dir}")
            if not stat.S_ISDIR(metadata.st_mode):
                raise AuditSecurityError(f"audit path is not a directory: {self.log_dir}")
        else:
            self.log_dir.mkdir(parents=True, mode=self.dir_mode)
        os.chmod(self.log_dir, self.dir_mode)

    def _open_secure(self, path: Path, flags: int, mode: int) -> int:
        safe_flags = flags | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, safe_flags, mode)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(descriptor)
            raise AuditSecurityError(f"audit path is not a regular file: {path}")
        return descriptor

    def _ensure_lock_file(self) -> None:
        descriptor = self._open_secure(
            self.lock_path,
            os.O_CREAT | os.O_RDWR,
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @contextlib.contextmanager
    def _exclusive_process_lock(self) -> Iterator[None]:
        descriptor = self._open_secure(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _fsync_directory(self, directory: Path | None = None) -> None:
        target = directory or self.log_dir
        descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _enforce_segment_permissions_locked(self) -> None:
        for segment in _segments_for(self.log_dir, self.file_name):
            _assert_regular_nosymlink(segment)
            os.chmod(segment, self.file_mode)

    def _repair_active_trailing_partial_locked(self) -> None:
        if not self.log_path.exists():
            return
        _assert_regular_nosymlink(self.log_path)
        data = self.log_path.read_bytes()
        if not data or data.endswith(b"\n"):
            return
        last_newline = data.rfind(b"\n")
        valid_length = last_newline + 1 if last_newline >= 0 else 0
        fragment = data[valid_length:]
        corrupt_dir = self.log_dir / "corrupt"
        corrupt_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(corrupt_dir, 0o700)
        artifact = corrupt_dir / f"trailing-partial-{time.time_ns()}.bin"
        descriptor = self._open_secure(
            artifact,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        try:
            os.write(descriptor, fragment)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        descriptor = self._open_secure(self.log_path, os.O_RDWR, self.file_mode)
        try:
            os.ftruncate(descriptor, valid_length)
            os.fchmod(descriptor, self.file_mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._fsync_directory(corrupt_dir)
        self._fsync_directory()
        self._repaired_partial = True
        self._recovery_artifact = str(artifact)

    def _quarantine_corrupt_segments_locked(self, report: IntegrityReport) -> Path:
        corrupt_root = self.log_dir / "corrupt"
        corrupt_root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(corrupt_root, 0o700)
        destination = corrupt_root / f"chain-{time.time_ns()}"
        destination.mkdir(mode=0o700)
        for segment in _segments_for(self.log_dir, self.file_name):
            _assert_regular_nosymlink(segment)
            os.replace(segment, destination / segment.name)
        report_path = destination / "integrity-report.json"
        descriptor = self._open_secure(
            report_path,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        try:
            payload = (
                json.dumps(report.to_dict(), indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
            )
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._fsync_directory(destination)
        self._fsync_directory(corrupt_root)
        self._fsync_directory()
        return destination

    def _tail_state_locked(self) -> tuple[str, int]:
        segments = _segments_for(self.log_dir, self.file_name)
        for segment in reversed(segments):
            _assert_regular_nosymlink(segment)
            with segment.open("rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - 1024 * 1024))
                lines = [line for line in handle.read().splitlines() if line.strip()]
            if not lines:
                continue
            try:
                entry = json.loads(lines[-1].decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AuditIntegrityError(
                    IntegrityReport(
                        False,
                        0,
                        len(segments),
                        "UNKNOWN",
                        ZERO_HASH,
                        ZERO_HASH,
                        0,
                        error=f"INVALID_TAIL:{exc}",
                        error_segment=str(segment),
                    )
                ) from exc
            record_hash = entry.get("record_hash")
            if not _validate_hex_hash(record_hash):
                raise AuditSecurityError("last audit record has an invalid record_hash")
            sequence = entry.get("sequence")
            if not isinstance(sequence, int):
                # Legacy logs had no sequence. The full startup check established
                # their count, so continue from the in-memory value.
                sequence = self._last_sequence
            return str(record_hash), sequence
        return ZERO_HASH, 0

    def _next_rotation_index_locked(self) -> int:
        indices = [
            index
            for path in self.log_dir.iterdir()
            if (index := _segment_index(path, self.file_name)) is not None
        ]
        return max(indices, default=0) + 1

    def _rotate_locked(self) -> Path | None:
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return None
        _assert_regular_nosymlink(self.log_path)
        rotated = self.log_dir / f"{self.file_name}.{self._next_rotation_index_locked():06d}"
        os.replace(self.log_path, rotated)
        os.chmod(rotated, self.file_mode)
        self._fsync_directory()

        rotated_segments = [
            path
            for path in _segments_for(self.log_dir, self.file_name)
            if path != self.log_path
        ]
        while len(rotated_segments) > self.backup_count:
            oldest = rotated_segments.pop(0)
            oldest.unlink()
            self._fsync_directory()
        return rotated

    def rotate(self) -> str | None:
        with self._thread_lock, self._exclusive_process_lock():
            rotated = self._rotate_locked()
            return str(rotated) if rotated else None

    def _append_bytes_locked(self, encoded_line: bytes) -> None:
        descriptor = self._open_secure(
            self.log_path,
            os.O_CREAT | os.O_APPEND | os.O_WRONLY,
            self.file_mode,
        )
        try:
            os.fchmod(descriptor, self.file_mode)
            view = memoryview(encoded_line)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("audit append made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._fsync_directory()

    def _build_entry(
        self,
        source: str,
        subject: str,
        payload: Mapping[str, Any],
    ) -> dict[str, Any]:
        timestamp = float(self._clock())
        entry: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "record_id": uuid.uuid4().hex,
            "sequence": self._last_sequence + 1,
            "timestamp": timestamp,
            "timestamp_utc": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
            "source": source,
            "subject": subject,
            "payload": _safe_value(payload),
            "prev_hash": self._last_hash,
        }
        entry["record_hash"] = _record_hash(entry)
        return entry

    def _validate_record_input(
        self, source: str, subject: str, payload: Mapping[str, Any]
    ) -> None:
        for name, value in (("source", source), ("subject", subject)):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")
            if len(value) > 128:
                raise ValueError(f"{name} exceeds 128 characters")
            if any(ord(character) < 32 for character in value):
                raise ValueError(f"{name} contains control characters")
        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping")

    def _append_record_locked(
        self, source: str, subject: str, payload: Mapping[str, Any]
    ) -> str:
        self._validate_record_input(source, subject, payload)
        self._last_hash, self._last_sequence = self._tail_state_locked()
        entry = self._build_entry(source, subject, payload)
        encoded = (
            json.dumps(entry, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            + "\n"
        ).encode("utf-8")
        if len(encoded) > self.max_record_bytes:
            raise ValueError(
                f"audit record exceeds max_record_bytes ({len(encoded)} > {self.max_record_bytes})"
            )
        active_size = self.log_path.stat().st_size if self.log_path.exists() else 0
        if active_size and active_size + len(encoded) > self.max_bytes:
            self._rotate_locked()
        self._append_bytes_locked(encoded)
        self._last_hash = str(entry["record_hash"])
        self._last_sequence = int(entry["sequence"])
        return self._last_hash

    def record(self, source: str, subject: str, payload: dict[str, Any]) -> str:
        with self._thread_lock, self._exclusive_process_lock():
            return self._append_record_locked(source, subject, payload)

    def verify_integrity(self) -> IntegrityReport:
        with self._thread_lock, self._exclusive_process_lock():
            return verify_audit_directory(
                self.log_dir,
                file_name=self.file_name,
                repaired_trailing_partial=self._repaired_partial,
                recovery_artifact=self._recovery_artifact,
            )

    def verify_chain(self) -> tuple[bool, int]:
        report = self.verify_integrity()
        return report.valid, report.record_count

    def iter_records(self, *, limit: int | None = None) -> Iterator[dict[str, Any]]:
        if limit is not None and limit <= 0:
            return iter(())
        records: list[dict[str, Any]] = []
        with self._thread_lock, self._exclusive_process_lock():
            for segment in _segments_for(self.log_dir, self.file_name):
                _assert_regular_nosymlink(segment)
                with segment.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        if line.strip():
                            value = json.loads(line)
                            if isinstance(value, dict):
                                records.append(value)
        if limit is not None:
            records = records[-limit:]
        return iter(records)

    def status(self) -> dict[str, Any]:
        file_mode: str | None = None
        if self.log_path.exists():
            file_mode = f"0o{stat.S_IMODE(self.log_path.stat().st_mode):04o}"
        status = AuditStatus(
            log_path=str(self.log_path),
            directory_mode=f"0o{stat.S_IMODE(self.log_dir.stat().st_mode):04o}",
            file_mode=file_mode,
            max_bytes=self.max_bytes,
            backup_count=self.backup_count,
            startup_integrity=self.startup_integrity_report.to_dict(),
            threat_model=(
                "SHA-256 chaining is tamper-evident for the retained records but does not "
                "prevent a privileged attacker from replacing all logs and recomputing the chain."
            ),
        )
        return status.to_dict()


def _json_safe(payload: dict[str, Any]) -> dict[str, Any]:
    """Compatibility wrapper retained for older imports."""

    return _safe_value(payload)
