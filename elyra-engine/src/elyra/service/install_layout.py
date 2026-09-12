"""Canonical production-installation paths and validation helpers for Elyra (ELYRA project)."""

from __future__ import annotations

import json
import os
import stat
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

INSTALL_ROOT = Path("/opt/elyra")
RELEASES_DIRECTORY = INSTALL_ROOT / "releases"
CURRENT_LINK = INSTALL_ROOT / "current"
SERVICE_UNIT_PATH = Path("/etc/systemd/system/elyra.service")
GUI_LAUNCHER_PATH = Path("/usr/local/bin/elyra-gui")
DESKTOP_ENTRY_PATH = Path("/usr/share/applications/elyra.desktop")
SYSUSERS_PATH = Path("/usr/lib/sysusers.d/elyra.conf")
RUNTIME_DIRECTORY = Path("/run/elyra")
STATE_DIRECTORY = Path("/var/lib/elyra")
LOG_DIRECTORY = Path("/var/log/elyra")
IPC_SOCKET = RUNTIME_DIRECTORY / "elyra.sock"
IPC_GROUP = "elyra"
ADMIN_GROUP = "elyra-admin"
INSTALLATION_MANIFEST = "INSTALLATION.json"


@dataclass(frozen=True, slots=True)
class PathInspection:
    path: str
    exists: bool
    kind: str
    mode: str | None
    uid: int | None
    gid: int | None
    safe: bool
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def read_project_version(pyproject_path: str | os.PathLike[str]) -> str:
    """Read the PEP 621 project version without importing the package."""

    path = Path(pyproject_path)
    with path.open("rb") as stream:
        document = tomllib.load(stream)
    version = document.get("project", {}).get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError(f"Project version is missing from {path}")
    return version.strip()


def inspect_path(
    path_value: str | os.PathLike[str],
    *,
    expected_kind: str | None = None,
    reject_world_writable: bool = True,
) -> PathInspection:
    """Inspect a production path without following its final symlink.

    ``expected_kind`` may be ``directory``, ``regular``, ``socket`` or ``symlink``.
    The helper is intentionally side-effect free so both the service preflight and
    the installed-system verifier can use the same rules.
    """

    path = Path(path_value)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return PathInspection(str(path), False, "missing", None, None, None, False, "MISSING")
    except OSError as exc:
        return PathInspection(
            str(path), False, "unreadable", None, None, None, False, f"LSTAT_FAILED:{exc}"
        )

    mode = metadata.st_mode
    if stat.S_ISDIR(mode):
        kind = "directory"
    elif stat.S_ISREG(mode):
        kind = "regular"
    elif stat.S_ISSOCK(mode):
        kind = "socket"
    elif stat.S_ISLNK(mode):
        kind = "symlink"
    else:
        kind = "other"

    reason: str | None = None
    safe = True
    if expected_kind is not None and kind != expected_kind:
        safe = False
        reason = f"EXPECTED_{expected_kind.upper()}_GOT_{kind.upper()}"
    elif reject_world_writable and bool(stat.S_IMODE(mode) & stat.S_IWOTH):
        safe = False
        reason = "WORLD_WRITABLE"

    return PathInspection(
        str(path),
        True,
        kind,
        f"0{stat.S_IMODE(mode):03o}",
        metadata.st_uid,
        metadata.st_gid,
        safe,
        reason,
    )


def installation_manifest(
    *,
    version: str,
    release_name: str,
    source_directory: str,
    installed_at_utc: str,
    installer_revision: str = "STAGE_13_SYSTEMD_INSTALLATION",
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "installer_revision": installer_revision,
        "project": "ELYRA",
        "application": "Elyra",
        "version": version,
        "release_name": release_name,
        "source_directory": source_directory,
        "installed_at_utc": installed_at_utc,
        "install_root": str(INSTALL_ROOT),
        "current_link": str(CURRENT_LINK),
        "service_unit": str(SERVICE_UNIT_PATH),
        "daemon_entry_point": str(CURRENT_LINK / ".venv/bin/elyra-daemon"),
        "gui_entry_point": str(CURRENT_LINK / ".venv/bin/elyra-gui"),
        "ipc_socket": str(IPC_SOCKET),
        "automatic_runtime_actions": False,
        "fanotify_policy": "MONITOR_ONLY",
    }


def write_json_atomic(path_value: str | os.PathLike[str], payload: dict[str, Any]) -> None:
    path = Path(path_value)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    encoded = json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    with temporary.open("x", encoding="utf-8") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
