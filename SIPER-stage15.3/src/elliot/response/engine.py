"""Authorised Stage 11 response execution for ELLIOT.

The engine consumes a correlated Stage 10 state.  It never accepts an arbitrary
PID/path pair from IPC.  Destructive runtime actions require an earlier binding
to the exact correlation identifier and are protected with Linux pidfds and
file-identity checks.
"""

from __future__ import annotations

import hashlib
import json
import os
import select
import signal
import stat
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .quarantine_manager import QuarantineError, QuarantineManager, QuarantineRecord


class ResponseConfigurationError(ValueError):
    """Raised when the Stage 11 policy is invalid."""


class ResponseSafetyError(RuntimeError):
    """Raised when process or file identity cannot be guaranteed."""


@dataclass(frozen=True, slots=True)
class ResponsePolicy:
    schema_version: str
    policy_name: str
    policy_status: str
    automatic_runtime_actions: bool
    terminate_grace_seconds: float
    kill_grace_seconds: float
    escalate_to_sigkill: bool
    require_pidfd: bool
    protected_pids: tuple[int, ...]
    protected_path_prefixes: tuple[str, ...]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ResponsePolicy":
        try:
            policy = cls(
                schema_version=str(value["schema_version"]),
                policy_name=str(value["policy_name"]),
                policy_status=str(value["policy_status"]),
                automatic_runtime_actions=bool(value["automatic_runtime_actions"]),
                terminate_grace_seconds=float(value["terminate_grace_seconds"]),
                kill_grace_seconds=float(value["kill_grace_seconds"]),
                escalate_to_sigkill=bool(value["escalate_to_sigkill"]),
                require_pidfd=bool(value["require_pidfd"]),
                protected_pids=tuple(int(item) for item in value["protected_pids"]),
                protected_path_prefixes=tuple(
                    str(item) for item in value["protected_path_prefixes"]
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ResponseConfigurationError(f"invalid response policy: {exc}") from exc
        policy.validate()
        return policy

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> "ResponsePolicy":
        if path is None:
            text = files("elliot.config").joinpath("response.default.json").read_text(
                encoding="utf-8"
            )
        else:
            text = Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ResponseConfigurationError(f"response policy is not valid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ResponseConfigurationError("response policy root must be an object")
        return cls.from_mapping(data)

    def validate(self) -> None:
        if self.policy_status != "PROVISIONAL_NOT_CALIBRATED":
            raise ResponseConfigurationError(
                "Stage 11 policy must be labelled PROVISIONAL_NOT_CALIBRATED"
            )
        if self.terminate_grace_seconds <= 0 or self.kill_grace_seconds <= 0:
            raise ResponseConfigurationError("process termination timeouts must be positive")
        if 0 not in self.protected_pids or 1 not in self.protected_pids:
            raise ResponseConfigurationError("PID 0 and PID 1 must remain protected")
        if any(not prefix.startswith("/") for prefix in self.protected_path_prefixes):
            raise ResponseConfigurationError("protected path prefixes must be absolute")

    def with_runtime_actions(self, enabled: bool) -> "ResponsePolicy":
        return replace(self, automatic_runtime_actions=bool(enabled))


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    start_time_ticks: int
    executable_path: str
    executable_device: int
    executable_inode: int
    uid: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class FileIdentity:
    path: str
    device: int
    inode: int
    size_bytes: int
    mtime_ns: int
    ctime_ns: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class BoundTarget:
    correlation_id: str
    pid: int
    process: ProcessIdentity | None
    file: FileIdentity | None
    file_fd: int | None
    bound_at_monotonic: float


@dataclass(frozen=True, slots=True)
class ActionResult:
    schema_version: str
    action_id: str
    correlation_id: str | None
    requested_action: str
    executed_action: str
    status: str
    timestamp: float
    timestamp_utc: str
    score: int
    reason: str
    triggered_rules: list[dict[str, Any]]
    pid: int | None
    path: str | None
    details: dict[str, Any] = field(default_factory=dict)
    failure_explanation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ProcessInspectorProtocol(Protocol):
    def capture(self, pid: int) -> ProcessIdentity: ...


class ProcessInspector:
    """Capture Linux process identity from procfs."""

    def __init__(self, proc_root: str | os.PathLike[str] = "/proc") -> None:
        self.proc_root = Path(proc_root)

    def capture(self, pid: int) -> ProcessIdentity:
        if isinstance(pid, bool) or int(pid) <= 0:
            raise ResponseSafetyError("process PID must be positive")
        pid = int(pid)
        root = self.proc_root / str(pid)
        try:
            stat_text = (root / "stat").read_text(encoding="utf-8")
            closing = stat_text.rfind(")")
            if closing < 0:
                raise ValueError("malformed proc stat record")
            fields_after_comm = stat_text[closing + 2 :].split()
            # /proc/PID/stat field 22 is starttime. fields_after_comm begins at field 3.
            start_time_ticks = int(fields_after_comm[19])
            executable_path = os.readlink(root / "exe")
            executable_stat = os.stat(root / "exe")
            uid = root.stat().st_uid
        except (FileNotFoundError, ProcessLookupError) as exc:
            raise ResponseSafetyError(f"process no longer exists: {pid}") from exc
        except (OSError, ValueError, IndexError) as exc:
            raise ResponseSafetyError(f"cannot capture process identity for PID {pid}: {exc}") from exc
        return ProcessIdentity(
            pid=pid,
            start_time_ticks=start_time_ticks,
            executable_path=executable_path,
            executable_device=executable_stat.st_dev,
            executable_inode=executable_stat.st_ino,
            uid=uid,
        )


class PidfdProcessController:
    """Terminate the exact Linux process represented by a pidfd."""

    def __init__(self, inspector: ProcessInspectorProtocol) -> None:
        self.inspector = inspector

    @staticmethod
    def _same_identity(expected: ProcessIdentity, current: ProcessIdentity) -> bool:
        return (
            expected.pid == current.pid
            and expected.start_time_ticks == current.start_time_ticks
            and expected.executable_device == current.executable_device
            and expected.executable_inode == current.executable_inode
        )

    @staticmethod
    def _wait_pidfd(pidfd: int, timeout_seconds: float) -> bool:
        poller = select.poll()
        poller.register(pidfd, select.POLLIN)
        return bool(poller.poll(max(1, int(timeout_seconds * 1000))))

    def terminate(self, expected: ProcessIdentity, policy: ResponsePolicy) -> dict[str, Any]:
        if expected.pid in set(policy.protected_pids) or expected.pid == os.getpid():
            raise ResponseSafetyError(f"refusing to terminate protected PID {expected.pid}")
        normalized_executable = os.path.normpath(expected.executable_path)
        if any(
            normalized_executable == prefix
            or normalized_executable.startswith(prefix.rstrip("/") + "/")
            for prefix in policy.protected_path_prefixes
        ):
            raise ResponseSafetyError("refusing to terminate an ELLIOT protected executable")
        if policy.require_pidfd and not hasattr(os, "pidfd_open"):
            raise ResponseSafetyError("pidfd_open is unavailable; safe termination is refused")
        if not hasattr(signal, "pidfd_send_signal"):
            raise ResponseSafetyError("pidfd_send_signal is unavailable; safe termination is refused")

        try:
            pidfd = os.pidfd_open(expected.pid, 0)
        except ProcessLookupError:
            return {"process_already_exited": True, "signal": None, "escalated": False}
        except OSError as exc:
            raise ResponseSafetyError(f"cannot open pidfd for PID {expected.pid}: {exc}") from exc

        try:
            current = self.inspector.capture(expected.pid)
            if not self._same_identity(expected, current):
                raise ResponseSafetyError(
                    "PID identity changed after correlation; termination was refused"
                )
            signal.pidfd_send_signal(pidfd, signal.SIGTERM, None, 0)
            if self._wait_pidfd(pidfd, policy.terminate_grace_seconds):
                return {
                    "process_already_exited": False,
                    "signal": "SIGTERM",
                    "escalated": False,
                }
            if not policy.escalate_to_sigkill:
                raise ResponseSafetyError("process did not exit after SIGTERM")
            signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
            if not self._wait_pidfd(pidfd, policy.kill_grace_seconds):
                raise ResponseSafetyError("process did not exit after SIGKILL")
            return {
                "process_already_exited": False,
                "signal": "SIGKILL",
                "escalated": True,
            }
        finally:
            os.close(pidfd)


_ACTION_MAP = {
    "CONTINUE_MONITORING": "ALLOW_MONITOR",
    "ALERT": "WARN",
    "TERMINATE": "TERMINATE",
    "QUARANTINE": "QUARANTINE",
    "DENY": "DENY",
    "ALLOW": "ALLOW",
    "ALLOW_MONITOR": "ALLOW_MONITOR",
    "WARN": "WARN",
}
_ACTION_RANK = {
    "ALLOW": 0,
    "ALLOW_MONITOR": 1,
    "WARN": 2,
    "DENY": 3,
    "TERMINATE": 4,
    "QUARANTINE": 5,
}


class ResponseEngine:
    """Execute authorised responses against correlation-bound identities."""

    def __init__(
        self,
        quarantine_manager: QuarantineManager,
        *,
        audit_logger: Any,
        policy: ResponsePolicy | None = None,
        process_inspector: ProcessInspectorProtocol | None = None,
        process_controller: PidfdProcessController | None = None,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        self.quarantine = quarantine_manager
        self.audit_logger = audit_logger
        self.policy = policy or ResponsePolicy.load()
        self.process_inspector = process_inspector or ProcessInspector()
        self.process_controller = process_controller or PidfdProcessController(
            self.process_inspector
        )
        self.event_sink = event_sink
        self._clock = clock
        self._monotonic = monotonic
        self._id_factory = id_factory or (lambda: uuid.uuid4().hex)
        self._bindings: dict[str, BoundTarget] = {}
        self._highest_executed_rank: dict[str, int] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _rules(state: Mapping[str, Any]) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        for key in ("pre_execution_indicators", "runtime_indicators", "indicators"):
            value = state.get(key)
            if isinstance(value, list):
                rules.extend(dict(item) for item in value if isinstance(item, Mapping))
        return rules

    @staticmethod
    def _score(state: Mapping[str, Any]) -> int:
        value = state.get("combined_score", state.get("score", 0))
        if isinstance(value, bool):
            return 0
        try:
            return max(0, min(100, int(float(value))))
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _path(state: Mapping[str, Any]) -> str | None:
        for key in ("executable_path", "path"):
            value = state.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    @staticmethod
    def _pid(state: Mapping[str, Any]) -> int | None:
        value = state.get("tgid", state.get("pid"))
        if isinstance(value, bool) or value is None:
            return None
        try:
            pid = int(value)
        except (TypeError, ValueError):
            return None
        return pid if pid > 0 else None

    @staticmethod
    def _open_file_identity(
        path: str | os.PathLike[str],
    ) -> tuple[FileIdentity, int]:
        target = Path(path)
        try:
            metadata = target.lstat()
        except OSError as exc:
            raise ResponseSafetyError(f"cannot inspect response target file: {target}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise ResponseSafetyError("response target must be a non-symlink regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(target, flags)
        except OSError as exc:
            raise ResponseSafetyError(f"cannot securely open response target: {target}: {exc}") from exc
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise ResponseSafetyError("response target identity changed while opening")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
            os.lseek(fd, 0, os.SEEK_SET)
            after = os.fstat(fd)
            if (
                after.st_size != opened.st_size
                or after.st_mtime_ns != opened.st_mtime_ns
                or after.st_ctime_ns != opened.st_ctime_ns
                or after.st_ino != opened.st_ino
            ):
                raise ResponseSafetyError("response target changed while hashing")
            identity = FileIdentity(
                path=str(target.resolve(strict=True)),
                device=opened.st_dev,
                inode=opened.st_ino,
                size_bytes=opened.st_size,
                mtime_ns=opened.st_mtime_ns,
                ctime_ns=opened.st_ctime_ns,
                sha256=digest.hexdigest(),
            )
            return identity, fd
        except Exception:
            os.close(fd)
            raise

    @classmethod
    def capture_file_identity(cls, path: str | os.PathLike[str]) -> FileIdentity:
        identity, fd = cls._open_file_identity(path)
        os.close(fd)
        return identity

    def bind_state(self, state: Mapping[str, Any]) -> dict[str, Any]:
        """Bind live process/file identities to one correlation generation."""

        correlation_id = str(state.get("correlation_id") or "")
        if not correlation_id:
            raise ResponseSafetyError("correlation_id is required before response binding")
        pid = self._pid(state)
        process: ProcessIdentity | None = None
        if pid is not None:
            try:
                process = self.process_inspector.capture(pid)
            except ResponseSafetyError:
                process = None
        target_path = self._path(state)
        file_identity: FileIdentity | None = None
        file_fd: int | None = None
        if target_path:
            try:
                file_identity, file_fd = self._open_file_identity(target_path)
            except ResponseSafetyError:
                file_identity = None
                file_fd = None
        if process is None and file_identity is None:
            raise ResponseSafetyError("neither process nor file identity could be bound")
        binding = BoundTarget(
            correlation_id=correlation_id,
            pid=pid or 0,
            process=process,
            file=file_identity,
            file_fd=file_fd,
            bound_at_monotonic=self._monotonic(),
        )
        with self._lock:
            previous = self._bindings.pop(correlation_id, None)
            if previous is not None and previous.file_fd is not None:
                os.close(previous.file_fd)
            while len(self._bindings) >= 1024:
                oldest_key = min(
                    self._bindings,
                    key=lambda key: self._bindings[key].bound_at_monotonic,
                )
                old = self._bindings.pop(oldest_key)
                if old.file_fd is not None:
                    os.close(old.file_fd)
            self._bindings[correlation_id] = binding
        return {
            "correlation_id": correlation_id,
            "process": process.to_dict() if process else None,
            "file": file_identity.to_dict() if file_identity else None,
        }

    def release_binding(self, correlation_id: str) -> None:
        with self._lock:
            binding = self._bindings.pop(str(correlation_id), None)
        if binding is not None and binding.file_fd is not None:
            os.close(binding.file_fd)

    def close(self) -> None:
        with self._lock:
            keys = list(self._bindings)
        for key in keys:
            self.release_binding(key)

    def _result(
        self,
        state: Mapping[str, Any],
        *,
        requested_action: str,
        executed_action: str,
        status: str,
        reason: str,
        details: Mapping[str, Any] | None = None,
        failure: str | None = None,
    ) -> ActionResult:
        timestamp = self._clock()
        result = ActionResult(
            schema_version="1.0",
            action_id=self._id_factory(),
            correlation_id=(str(state.get("correlation_id")) if state.get("correlation_id") else None),
            requested_action=requested_action,
            executed_action=executed_action,
            status=status,
            timestamp=timestamp,
            timestamp_utc=datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
            score=self._score(state),
            reason=reason,
            triggered_rules=self._rules(state),
            pid=self._pid(state),
            path=self._path(state),
            details=dict(details or {}),
            failure_explanation=failure,
        )
        payload = result.to_dict()
        self.audit_logger.record("response", executed_action.lower(), payload)
        if self.event_sink is not None:
            self.event_sink({"source": "response", **payload})
        return result

    def _protected_path(self, path: str) -> bool:
        resolved = os.path.normpath(path)
        return any(
            resolved == prefix or resolved.startswith(prefix.rstrip("/") + "/")
            for prefix in self.policy.protected_path_prefixes
        )

    def execute_recommendation(self, state: Mapping[str, Any]) -> ActionResult:
        recommendation = str(state.get("recommended_action") or "").upper()
        action = _ACTION_MAP.get(recommendation)
        if action is None:
            return self._result(
                state,
                requested_action=recommendation or "UNKNOWN",
                executed_action="NONE",
                status="REFUSED",
                reason="Unsupported response recommendation",
                failure="UNKNOWN_RECOMMENDATION",
            )

        correlation_id = str(state.get("correlation_id") or "")
        rank = _ACTION_RANK[action]
        with self._lock:
            previous = self._highest_executed_rank.get(correlation_id, -1)
            if correlation_id and rank <= previous:
                return self._result(
                    state,
                    requested_action=recommendation,
                    executed_action=action,
                    status="DUPLICATE_SUPPRESSED",
                    reason="This correlation already executed an equal or stronger response",
                )

        if action == "ALLOW":
            result = self._result(
                state,
                requested_action=recommendation,
                executed_action=action,
                status="SUCCEEDED",
                reason="Execution was allowed by the current policy",
            )
        elif action == "ALLOW_MONITOR":
            result = self._result(
                state,
                requested_action=recommendation,
                executed_action=action,
                status="SUCCEEDED",
                reason="Execution continues under runtime monitoring",
            )
        elif action == "WARN":
            result = self._result(
                state,
                requested_action=recommendation,
                executed_action=action,
                status="SUCCEEDED",
                reason="A warning event was emitted for the correlated execution",
            )
        elif action == "DENY":
            if str(state.get("status")) != "DENIED_PRE_EXECUTION":
                result = self._result(
                    state,
                    requested_action=recommendation,
                    executed_action=action,
                    status="REFUSED",
                    reason="Deny can only acknowledge a fanotify denial already applied",
                    failure="DENY_NOT_CONFIRMED_BY_FANOTIFY",
                )
            else:
                result = self._result(
                    state,
                    requested_action=recommendation,
                    executed_action=action,
                    status="SUCCEEDED",
                    reason="fanotify pre-execution denial was confirmed and recorded",
                )
        elif not self.policy.automatic_runtime_actions:
            result = self._result(
                state,
                requested_action=recommendation,
                executed_action=action,
                status="SKIPPED_POLICY_DISABLED",
                reason="Automatic destructive runtime responses are disabled",
            )
        elif action == "TERMINATE":
            result = self._execute_terminate(state, recommendation)
        else:
            result = self._execute_quarantine(state, recommendation)

        if correlation_id and result.status in {
            "SUCCEEDED",
            "DUPLICATE_SUPPRESSED",
            "SKIPPED_POLICY_DISABLED",
        }:
            with self._lock:
                if result.status == "SUCCEEDED":
                    self._highest_executed_rank[correlation_id] = max(previous, rank)
        return result

    def _binding(self, state: Mapping[str, Any]) -> BoundTarget:
        correlation_id = str(state.get("correlation_id") or "")
        with self._lock:
            binding = self._bindings.get(correlation_id)
        if binding is None:
            raise ResponseSafetyError("response target was not bound to this correlation")
        pid = self._pid(state) or 0
        if binding.pid not in {0, pid}:
            raise ResponseSafetyError("bound PID does not match the current correlation state")
        return binding

    def _execute_terminate(self, state: Mapping[str, Any], recommendation: str) -> ActionResult:
        try:
            binding = self._binding(state)
            if binding.process is None:
                raise ResponseSafetyError("no process identity is bound for termination")
            details = self.process_controller.terminate(binding.process, self.policy)
            return self._result(
                state,
                requested_action=recommendation,
                executed_action="TERMINATE",
                status="SUCCEEDED",
                reason="The correlation-bound process was terminated using a pidfd",
                details={"process_identity": binding.process.to_dict(), **details},
            )
        except ResponseSafetyError as exc:
            return self._result(
                state,
                requested_action=recommendation,
                executed_action="TERMINATE",
                status="REFUSED",
                reason="Safe process termination requirements were not satisfied",
                failure=str(exc),
            )

    def _execute_quarantine(self, state: Mapping[str, Any], recommendation: str) -> ActionResult:
        try:
            binding = self._binding(state)
            if binding.file is None:
                raise ResponseSafetyError("no file identity is bound for quarantine")
            if self._protected_path(binding.file.path):
                raise ResponseSafetyError("ELLIOT protected paths cannot be quarantined")
            termination: dict[str, Any] | None = None
            if binding.process is not None:
                termination = self.process_controller.terminate(binding.process, self.policy)
            record = self.quarantine.quarantine_file(
                binding.file.path,
                binding.file.sha256,
                reason=f"Stage 11 correlated response: score={self._score(state)}",
                related_pid=binding.pid or None,
                triggered_rules=self._rules(state),
                process_info={
                    "correlation_id": binding.correlation_id,
                    "process_identity": (
                        binding.process.to_dict() if binding.process else None
                    ),
                },
                expected_device=binding.file.device,
                expected_inode=binding.file.inode,
                expected_size=binding.file.size_bytes,
                expected_mtime_ns=binding.file.mtime_ns,
                expected_ctime_ns=binding.file.ctime_ns,
            )
            result = self._result(
                state,
                requested_action=recommendation,
                executed_action="QUARANTINE",
                status="SUCCEEDED",
                reason="The correlation-bound file was placed in protected quarantine",
                details={
                    "termination": termination,
                    "quarantine_record": record.to_dict(),
                },
            )
            self.release_binding(str(state.get("correlation_id") or ""))
            return result
        except (ResponseSafetyError, QuarantineError) as exc:
            result = self._result(
                state,
                requested_action=recommendation,
                executed_action="QUARANTINE",
                status="REFUSED",
                reason="Safe quarantine requirements were not satisfied",
                failure=str(exc),
            )
            self.release_binding(str(state.get("correlation_id") or ""))
            return result

    def restore(
        self,
        quarantine_id: str,
        destination: str | os.PathLike[str] | None,
        *,
        actor: str,
        requester_pid: int | None = None,
    ) -> tuple[QuarantineRecord, ActionResult]:
        synthetic = {
            "correlation_id": None,
            "recommended_action": "RESTORE",
            "combined_score": 0,
            "pid": requester_pid,
        }
        try:
            record = self.quarantine.restore_file(quarantine_id, destination)
            result = self._result(
                synthetic,
                requested_action="RESTORE",
                executed_action="RESTORE",
                status="SUCCEEDED",
                reason="An authorised quarantine restoration completed",
                details={"actor": actor, "quarantine_record": record.to_dict()},
            )
            return record, result
        except QuarantineError as exc:
            self._result(
                synthetic,
                requested_action="RESTORE",
                executed_action="RESTORE",
                status="FAILED",
                reason="Authorised restoration failed safely",
                details={"actor": actor, "quarantine_id": quarantine_id},
                failure=str(exc),
            )
            raise

    def delete_permanently(
        self,
        quarantine_id: str,
        *,
        actor: str,
        requester_pid: int | None = None,
    ) -> ActionResult:
        synthetic = {
            "correlation_id": None,
            "recommended_action": "DELETE_PERMANENTLY",
            "combined_score": 0,
            "pid": requester_pid,
        }
        try:
            self.quarantine.delete_permanently(quarantine_id)
            return self._result(
                synthetic,
                requested_action="DELETE_PERMANENTLY",
                executed_action="DELETE_PERMANENTLY",
                status="SUCCEEDED",
                reason="An authorised permanent quarantine deletion completed",
                details={"actor": actor, "quarantine_id": quarantine_id},
            )
        except QuarantineError as exc:
            self._result(
                synthetic,
                requested_action="DELETE_PERMANENTLY",
                executed_action="DELETE_PERMANENTLY",
                status="FAILED",
                reason="Authorised permanent deletion failed safely",
                details={"actor": actor, "quarantine_id": quarantine_id},
                failure=str(exc),
            )
            raise
