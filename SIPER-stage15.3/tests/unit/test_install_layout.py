from __future__ import annotations

import json
import os
from pathlib import Path

from elliot.service.install_layout import (
    CURRENT_LINK,
    INSTALL_ROOT,
    IPC_SOCKET,
    installation_manifest,
    inspect_path,
    read_project_version,
    write_json_atomic,
)

ROOT = Path(__file__).resolve().parents[2]


def test_final_project_version() -> None:
    assert read_project_version(ROOT / "pyproject.toml") == "1.0.0"


def test_production_paths_are_absolute_and_consistent() -> None:
    assert INSTALL_ROOT == Path("/opt/elliot")
    assert CURRENT_LINK == INSTALL_ROOT / "current"
    assert IPC_SOCKET == Path("/run/elliot/elliot.sock")
    assert all(path.is_absolute() for path in (INSTALL_ROOT, CURRENT_LINK, IPC_SOCKET))


def test_installation_manifest_records_safe_defaults() -> None:
    payload = installation_manifest(
        version="0.1.0.dev13",
        release_name="demo",
        source_directory="/source",
        installed_at_utc="2026-07-29T00:00:00+00:00",
    )
    assert payload["project"] == "ELLIOT"
    assert payload["application"] == "Siper"
    assert payload["automatic_runtime_actions"] is False
    assert payload["fanotify_policy"] == "MONITOR_ONLY"
    assert payload["daemon_entry_point"].endswith("/.venv/bin/siper-daemon")


def test_inspect_path_rejects_world_writable_directory(tmp_path: Path) -> None:
    directory = tmp_path / "unsafe"
    directory.mkdir(mode=0o777)
    directory.chmod(0o777)
    result = inspect_path(directory, expected_kind="directory")
    assert result.safe is False
    assert result.reason == "WORLD_WRITABLE"


def test_inspect_path_distinguishes_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "current"
    link.symlink_to(target)
    result = inspect_path(link, expected_kind="symlink", reject_world_writable=False)
    assert result.safe is True
    assert result.kind == "symlink"


def test_write_json_atomic_creates_parseable_file(tmp_path: Path) -> None:
    path = tmp_path / "evidence" / "record.json"
    write_json_atomic(path, {"overall_status": "OK", "value": 3})
    assert json.loads(path.read_text(encoding="utf-8"))["value"] == 3
    assert path.stat().st_mode & 0o777 == 0o644
    assert not list(path.parent.glob(".*.tmp"))
