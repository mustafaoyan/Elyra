"""Peer-credential authorization and manual-scan path policy."""

from __future__ import annotations

import grp
import os
import pwd
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class ActionLevel(str, Enum):
    READ_ONLY = "read_only"
    STANDARD = "standard"
    SENSITIVE = "sensitive"


READ_ONLY_ACTIONS = {
    "get_status",
    "list_events",
    "list_runtime_states",
    "list_quarantine",
    "get_policy",
}
STANDARD_ACTIONS = {"scan_file"}
SENSITIVE_ACTIONS = {"restore_file", "delete_permanently", "update_enforcement_policy"}

ACTION_LEVELS: dict[str, ActionLevel] = {
    **{action: ActionLevel.READ_ONLY for action in READ_ONLY_ACTIONS},
    **{action: ActionLevel.STANDARD for action in STANDARD_ACTIONS},
    **{action: ActionLevel.SENSITIVE for action in SENSITIVE_ACTIONS},
}

IPC_GROUP = "elyra"
REQUIRED_GROUP_FOR_SENSITIVE = "elyra-admin"
MAX_MANUAL_SCAN_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Requester:
    pid: int
    uid: int
    gid: int

    @property
    def username(self) -> str:
        try:
            return pwd.getpwuid(self.uid).pw_name
        except KeyError:
            return f"uid:{self.uid}"

    @property
    def home_directory(self) -> Path | None:
        try:
            return Path(pwd.getpwuid(self.uid).pw_dir).resolve(strict=False)
        except KeyError:
            return None

    def is_root(self) -> bool:
        return self.uid == 0

    def group_ids(self) -> set[int]:
        try:
            return set(os.getgrouplist(self.username, self.gid))
        except (KeyError, OSError):
            return {self.gid}

    def in_group(self, group_name: str) -> bool:
        try:
            group_id = grp.getgrnam(group_name).gr_gid
        except KeyError:
            return False
        return group_id in self.group_ids()

    def in_admin_group(self) -> bool:
        return self.in_group(REQUIRED_GROUP_FOR_SENSITIVE)


class AuthorizationError(PermissionError):
    """Raised when a peer is not permitted to perform an action."""


class ScanTargetError(AuthorizationError):
    """Raised when a manual file-scan target violates path policy."""


def action_level(action: str) -> ActionLevel:
    try:
        return ACTION_LEVELS[action]
    except KeyError as exc:
        raise AuthorizationError(f"Unknown action: {action}") from exc


def authorize(requester: Requester, action: str) -> None:
    level = action_level(action)
    if level in {ActionLevel.READ_ONLY, ActionLevel.STANDARD}:
        return
    if requester.is_root() or requester.in_admin_group():
        return
    raise AuthorizationError(
        f"Action '{action}' requires root or membership in "
        f"'{REQUIRED_GROUP_FOR_SENSITIVE}'."
    )


def _is_beneath(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def allowed_manual_scan_roots(requester: Requester) -> tuple[Path, ...]:
    roots: list[Path] = [Path("/tmp"), Path("/var/tmp"), Path(f"/run/user/{requester.uid}")]
    home = requester.home_directory
    if home is not None:
        roots.extend(
            [
                home,
                Path("/media") / requester.username,
                Path("/run/media") / requester.username,
            ]
        )
    return tuple(root.resolve(strict=False) for root in roots)


def authorize_manual_scan_path(
    requester: Requester,
    path_value: str,
    *,
    maximum_size: int = MAX_MANUAL_SCAN_BYTES,
) -> Path:
    """Authorize a manual scan and return its canonical regular-file path.

    Non-root peers may scan only regular files they own beneath their home,
    private runtime directory, temporary directories, or their removable-media
    mount roots. Symbolic-link final components are rejected. The static scanner
    performs its own second lstat check; complete race elimination is deferred to
    fanotify file-descriptor integration.
    """

    candidate = Path(path_value)
    if not candidate.is_absolute():
        raise ScanTargetError("Manual scan paths must be absolute")
    try:
        metadata = candidate.lstat()
    except FileNotFoundError as exc:
        raise ScanTargetError("Manual scan target does not exist") from exc
    except OSError as exc:
        raise ScanTargetError(f"Manual scan target cannot be inspected: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise ScanTargetError("Symbolic-link scan targets are not permitted")
    if not stat.S_ISREG(metadata.st_mode):
        raise ScanTargetError("Manual scan target must be a regular file")
    if metadata.st_size > maximum_size:
        raise ScanTargetError(
            f"Manual scan target exceeds the {maximum_size}-byte IPC policy limit"
        )

    resolved = candidate.resolve(strict=True)
    if requester.is_root() or requester.in_admin_group():
        return resolved
    if metadata.st_uid != requester.uid:
        raise ScanTargetError("Non-privileged peers may scan only files they own")
    if not any(_is_beneath(resolved, root) for root in allowed_manual_scan_roots(requester)):
        raise ScanTargetError("Manual scan target is outside the permitted roots")
    return resolved
