from __future__ import annotations

import os
from pathlib import Path

import pytest

from elliot.service.authorization import (
    ACTION_LEVELS,
    ActionLevel,
    AuthorizationError,
    Requester,
    ScanTargetError,
    authorize,
    authorize_manual_scan_path,
)
from elliot.service.ipc_protocol import _ACTION_PARAMS


def test_sensitive_action_requires_root_or_admin(monkeypatch: pytest.MonkeyPatch) -> None:
    requester = Requester(pid=123, uid=12345, gid=12345)
    monkeypatch.setattr(Requester, "in_admin_group", lambda self: False)
    with pytest.raises(AuthorizationError):
        authorize(requester, "restore_file")
    authorize(requester, "get_status")
    authorize(requester, "scan_file")


def test_runtime_state_listing_is_read_only() -> None:
    requester = Requester(pid=123, uid=12345, gid=12345)
    authorize(requester, "list_runtime_states")
    assert ACTION_LEVELS["list_runtime_states"] is ActionLevel.READ_ONLY


def test_protocol_and_authorization_action_sets_match() -> None:
    assert set(_ACTION_PARAMS) == set(ACTION_LEVELS)


def test_root_is_authorized_for_sensitive_action() -> None:
    authorize(Requester(pid=1, uid=0, gid=0), "update_enforcement_policy")


def test_manual_scan_rejects_relative_symlink_and_directory(tmp_path: Path) -> None:
    requester = Requester(pid=os.getpid(), uid=0, gid=0)
    with pytest.raises(ScanTargetError, match="absolute"):
        authorize_manual_scan_path(requester, "relative.bin")
    with pytest.raises(ScanTargetError, match="regular"):
        authorize_manual_scan_path(requester, str(tmp_path))

    target = tmp_path / "target.bin"
    target.write_bytes(b"safe")
    link = tmp_path / "link.bin"
    link.symlink_to(target)
    with pytest.raises(ScanTargetError, match="Symbolic"):
        authorize_manual_scan_path(requester, str(link))


def test_root_manual_scan_accepts_regular_file(tmp_path: Path) -> None:
    target = tmp_path / "safe.bin"
    target.write_bytes(b"safe")
    resolved = authorize_manual_scan_path(
        Requester(pid=os.getpid(), uid=0, gid=0), str(target)
    )
    assert resolved == target.resolve()
