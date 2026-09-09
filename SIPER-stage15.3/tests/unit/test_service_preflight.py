from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from elliot.service import preflight


requires_linux_install_layout = pytest.mark.skipif(
    os.name == "nt",
    reason="the Linux release-layout contract uses privileged POSIX symlinks",
)


def _prepared_layout(tmp_path: Path):
    release = tmp_path / "releases" / "demo"
    release.mkdir(parents=True)
    (release / "INSTALLATION.json").write_text("{}\n", encoding="utf-8")
    current = tmp_path / "current"
    current.symlink_to(release)
    runtime = tmp_path / "run"
    state = tmp_path / "state"
    logs = tmp_path / "logs"
    runtime.mkdir(mode=0o750)
    state.mkdir(mode=0o700)
    logs.mkdir(mode=0o750)
    runtime.chmod(0o750)
    state.chmod(0o700)
    logs.chmod(0o750)
    return current, runtime, state, logs


@requires_linux_install_layout
def test_preflight_accepts_safe_layout_with_optional_warnings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current, runtime, state, logs = _prepared_layout(tmp_path)
    monkeypatch.setattr(preflight, "_group_exists", lambda _name: True)
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 0)
    results = preflight.run_preflight(
        service_mode=True,
        current_link=current,
        runtime_directory=runtime,
        state_directory=state,
        log_directory=logs,
    )
    assert preflight.overall_status(results) == "OK"
    assert not [item for item in results if item.status == "FAIL"]


@requires_linux_install_layout
def test_preflight_service_mode_requires_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current, runtime, state, logs = _prepared_layout(tmp_path)
    monkeypatch.setattr(preflight, "_group_exists", lambda _name: True)
    monkeypatch.setattr(preflight.os, "geteuid", lambda: 1000)
    results = preflight.run_preflight(
        service_mode=True,
        current_link=current,
        runtime_directory=runtime,
        state_directory=state,
        log_directory=logs,
    )
    root = next(item for item in results if item.check == "root_service_identity")
    assert root.status == "FAIL"
    assert preflight.overall_status(results) == "FAIL"


@requires_linux_install_layout
def test_preflight_requires_both_groups(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    current, runtime, state, logs = _prepared_layout(tmp_path)
    monkeypatch.setattr(preflight, "_group_exists", lambda name: name == "elliot")
    results = preflight.run_preflight(
        current_link=current,
        runtime_directory=runtime,
        state_directory=state,
        log_directory=logs,
    )
    admin = next(item for item in results if item.check == "admin_group_exists")
    assert admin.status == "FAIL"


def test_optional_ebpf_warning_does_not_fail_preflight() -> None:
    results = [preflight.PreflightResult("bcc", "WARN", "not available")]
    assert preflight.overall_status(results) == "OK"


@requires_linux_install_layout
def test_missing_current_link_is_a_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "run"
    state = tmp_path / "state"
    logs = tmp_path / "logs"
    runtime.mkdir(mode=0o750)
    state.mkdir(mode=0o700)
    logs.mkdir(mode=0o750)
    monkeypatch.setattr(preflight, "_group_exists", lambda _name: True)
    results = preflight.run_preflight(
        current_link=tmp_path / "missing",
        runtime_directory=runtime,
        state_directory=state,
        log_directory=logs,
    )
    current = next(item for item in results if item.check == "current_release_link")
    assert current.status == "FAIL"


def test_windows_preflight_does_not_require_linux_service_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(preflight.platform, "system", lambda: "Windows")
    results = preflight.run_preflight(
        service_mode=True,
        current_link=tmp_path / "linux-only-current",
        runtime_directory=tmp_path / "linux-only-run",
        state_directory=tmp_path / "linux-only-state",
        log_directory=tmp_path / "linux-only-logs",
    )
    assert preflight.overall_status(results) == "OK"
    assert next(item for item in results if item.check == "current_release_link").status == "OK"
    assert next(item for item in results if item.check == "windows_local_monitor").status == "OK"
