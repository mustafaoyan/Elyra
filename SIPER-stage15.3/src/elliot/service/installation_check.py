"""Read-only verification of an installed ELLIOT systemd deployment."""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import socket
import stat
import subprocess
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .install_layout import (
    ADMIN_GROUP,
    CURRENT_LINK,
    DESKTOP_ENTRY_PATH,
    GUI_LAUNCHER_PATH,
    INSTALLATION_MANIFEST,
    IPC_GROUP,
    IPC_SOCKET,
    LOG_DIRECTORY,
    RUNTIME_DIRECTORY,
    SERVICE_UNIT_PATH,
    STATE_DIRECTORY,
    inspect_path,
    write_json_atomic,
)
from .ipc_client import IpcClient, IpcClientError


@dataclass(frozen=True, slots=True)
class InstallationCheck:
    check: str
    status: str
    detail: Any
    critical: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _run(command: list[str], *, timeout: float = 10.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _record(check: str, ok: bool, detail: Any, *, critical: bool = True) -> InstallationCheck:
    return InstallationCheck(check, "OK" if ok else ("FAIL" if critical else "WARN"), detail, critical)


def _group_exists(name: str) -> tuple[bool, int | None]:
    try:
        entry = grp.getgrnam(name)
    except KeyError:
        return False, None
    return True, entry.gr_gid


def _user_in_group(username: str, group_name: str) -> bool:
    try:
        user = pwd.getpwnam(username)
        group = grp.getgrnam(group_name)
    except KeyError:
        return False
    return username in group.gr_mem or user.pw_gid == group.gr_gid


def _systemctl_state(property_name: str) -> tuple[bool, str]:
    completed = _run(["systemctl", property_name, "elliot.service"])
    value = (completed.stdout or completed.stderr).strip()
    return completed.returncode == 0, value


def collect_installation_report(*, expected_user: str | None = None) -> dict[str, Any]:
    checks: list[InstallationCheck] = []

    current = inspect_path(CURRENT_LINK, expected_kind="symlink", reject_world_writable=False)
    checks.append(_record("current_release_link", current.safe, current.to_dict()))
    release: Path | None = None
    if current.safe:
        try:
            release = CURRENT_LINK.resolve(strict=True)
            release_inspection = inspect_path(release, expected_kind="directory")
            checks.append(_record("current_release_directory", release_inspection.safe, release_inspection.to_dict()))
        except OSError as exc:
            checks.append(_record("current_release_directory", False, str(exc)))

    manifest_payload: dict[str, Any] | None = None
    if release is not None:
        manifest_path = release / INSTALLATION_MANIFEST
        manifest_check = inspect_path(manifest_path, expected_kind="regular")
        checks.append(_record("installation_manifest_file", manifest_check.safe, manifest_check.to_dict()))
        if manifest_check.safe:
            try:
                manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest_ok = (
                    manifest_payload.get("project") == "ELLIOT"
                    and manifest_payload.get("automatic_runtime_actions") is False
                    and manifest_payload.get("fanotify_policy") == "MONITOR_ONLY"
                )
                checks.append(_record("installation_manifest_policy", manifest_ok, manifest_payload))
            except (OSError, json.JSONDecodeError) as exc:
                checks.append(_record("installation_manifest_policy", False, str(exc)))

    daemon_path = CURRENT_LINK / ".venv/bin/elliot-daemon"
    gui_path = CURRENT_LINK / ".venv/bin/elliot-gui"
    preflight_path = CURRENT_LINK / ".venv/bin/elliot-preflight"
    for name, path in (
        ("daemon_entry_point", daemon_path),
        ("gui_entry_point", gui_path),
        ("preflight_entry_point", preflight_path),
    ):
        inspection = inspect_path(path, expected_kind="regular")
        executable = inspection.safe and os.access(path, os.X_OK)
        checks.append(_record(name, executable, inspection.to_dict()))

    for name, path, expected_mode in (
        ("runtime_directory", RUNTIME_DIRECTORY, "0750"),
        ("state_directory", STATE_DIRECTORY, "0700"),
        ("log_directory", LOG_DIRECTORY, "0750"),
    ):
        inspection = inspect_path(path, expected_kind="directory")
        checks.append(_record(name, inspection.safe and inspection.mode == expected_mode, inspection.to_dict()))

    ipc_exists, ipc_gid = _group_exists(IPC_GROUP)
    admin_exists, _ = _group_exists(ADMIN_GROUP)
    checks.append(_record("ipc_group", ipc_exists, {"name": IPC_GROUP, "gid": ipc_gid}))
    checks.append(_record("admin_group", admin_exists, {"name": ADMIN_GROUP}))

    socket_check = inspect_path(IPC_SOCKET, expected_kind="socket")
    socket_ok = socket_check.safe and socket_check.mode == "0660" and ipc_gid == socket_check.gid
    checks.append(_record("ipc_socket", socket_ok, socket_check.to_dict()))

    unit_check = inspect_path(SERVICE_UNIT_PATH, expected_kind="regular")
    checks.append(_record("systemd_unit_file", unit_check.safe and unit_check.mode == "0644", unit_check.to_dict()))
    launcher_check = inspect_path(GUI_LAUNCHER_PATH, expected_kind="regular")
    checks.append(
        _record(
            "gui_launcher",
            launcher_check.safe and launcher_check.mode == "0755" and os.access(GUI_LAUNCHER_PATH, os.X_OK),
            launcher_check.to_dict(),
        )
    )
    desktop_check = inspect_path(DESKTOP_ENTRY_PATH, expected_kind="regular")
    checks.append(_record("desktop_entry", desktop_check.safe and desktop_check.mode == "0644", desktop_check.to_dict()))

    enabled_ok, enabled_value = _systemctl_state("is-enabled")
    active_ok, active_value = _systemctl_state("is-active")
    checks.append(_record("systemd_enabled", enabled_ok and enabled_value == "enabled", enabled_value))
    checks.append(_record("systemd_active", active_ok and active_value == "active", active_value))

    show = _run(["systemctl", "show", "elliot.service", "--property=ExecStart", "--value"])
    exec_start = show.stdout.strip()
    exec_ok = (
        show.returncode == 0
        and str(daemon_path) in exec_start
        and "--execute-responses" not in exec_start
        and "--enforce" not in exec_start
    )
    checks.append(_record("safe_systemd_execstart", exec_ok, exec_start))

    try:
        daemon_status = IpcClient(timeout=5.0).request("get_status")
        checks.append(_record("daemon_ipc_status", isinstance(daemon_status, dict), daemon_status))
        if isinstance(daemon_status, dict):
            checks.append(
                _record(
                    "daemon_fanotify_available",
                    daemon_status.get("fanotify_active") is True,
                    {
                        "fanotify_active": daemon_status.get("fanotify_active"),
                        "degraded_components": daemon_status.get("degraded_components"),
                    },
                    critical=False,
                )
            )
            try:
                policy = IpcClient(timeout=5.0).request("get_policy")
                checks.append(
                    _record(
                        "daemon_default_monitor_only",
                        isinstance(policy, dict) and policy.get("mode") == "MONITOR_ONLY",
                        policy,
                    )
                )
            except IpcClientError as exc:
                checks.append(_record("daemon_default_monitor_only", False, str(exc)))
            checks.append(
                _record(
                    "daemon_ebpf_available",
                    daemon_status.get("ebpf_active") is True,
                    {
                        "ebpf_active": daemon_status.get("ebpf_active"),
                        "degraded_components": daemon_status.get("degraded_components"),
                    },
                    critical=False,
                )
            )
            audit = daemon_status.get("audit")
            integrity_valid = isinstance(audit, dict) and bool(
                audit.get("startup_integrity", {}).get("valid")
            )
            checks.append(_record("daemon_audit_integrity", integrity_valid, audit))
    except IpcClientError as exc:
        checks.append(_record("daemon_ipc_status", False, str(exc)))

    if expected_user:
        checks.append(
            _record(
                "gui_user_ipc_membership",
                _user_in_group(expected_user, IPC_GROUP),
                {"user": expected_user, "group": IPC_GROUP},
            )
        )

    journal = _run(["journalctl", "-u", "elliot.service", "-n", "20", "--no-pager"])
    checks.append(
        _record(
            "journalctl_access",
            journal.returncode == 0,
            journal.stdout[-8000:] if journal.stdout else journal.stderr,
            critical=False,
        )
    )

    overall = "FAIL" if any(item.status == "FAIL" for item in checks) else "OK"
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "method": "read-only installed systemd, filesystem, group, IPC and journal verification",
        "euid": os.geteuid(),
        "hostname": socket.gethostname(),
        "manifest": manifest_payload,
        "results": [item.to_dict() for item in checks],
        "overall_status": overall,
    }


def _print_summary(report: dict[str, Any]) -> None:
    for item in report["results"]:
        print(f"{item['check']}: {item['status']}")
    print(f"overall_status: {report['overall_status']}")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-user")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    report = collect_installation_report(expected_user=args.expected_user)
    write_json_atomic(args.output, report)
    _print_summary(report)
    print(f"Evidence written to: {args.output}")
    if report["overall_status"] != "OK":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
