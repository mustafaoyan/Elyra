"""Fast, side-effect-free service preflight checks for the installed Elyra daemon."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    import grp
except ImportError:  # Windows has no POSIX group database.
    grp = None  # type: ignore[assignment]

from .install_layout import (
    ADMIN_GROUP,
    CURRENT_LINK,
    INSTALLATION_MANIFEST,
    IPC_GROUP,
    LOG_DIRECTORY,
    RUNTIME_DIRECTORY,
    STATE_DIRECTORY,
    inspect_path,
)
from ..monitor.ebpf.kernel_headers import assess_kernel_headers


@dataclass(frozen=True, slots=True)
class PreflightResult:
    check: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _group_exists(name: str) -> bool:
    if grp is None:
        return False
    try:
        grp.getgrnam(name)
    except KeyError:
        return False
    return True


def _effective_uid() -> int:
    """Return a POSIX effective UID, or a non-root sentinel on Windows."""

    getter = getattr(os, "geteuid", None)
    return int(getter()) if callable(getter) else -1


def _result(check: str, ok: bool, detail: str, *, warning: bool = False) -> PreflightResult:
    status = "OK" if ok else ("WARN" if warning else "FAIL")
    return PreflightResult(check, status, detail)


def run_preflight(
    *,
    service_mode: bool = False,
    current_link: Path = CURRENT_LINK,
    runtime_directory: Path = RUNTIME_DIRECTORY,
    state_directory: Path = STATE_DIRECTORY,
    log_directory: Path = LOG_DIRECTORY,
) -> list[PreflightResult]:
    """Return production readiness checks without loading fanotify or eBPF."""

    results: list[PreflightResult] = []
    is_linux = platform.system() == "Linux"
    effective_uid = _effective_uid()
    results.append(
        _result(
            "root_service_identity",
            (not service_mode) or (not is_linux) or effective_uid == 0,
            f"effective_uid={effective_uid}; platform={platform.system()}",
        )
    )
    results.append(
        _result(
            "ipc_group_exists",
            (not is_linux) or _group_exists(IPC_GROUP),
            IPC_GROUP if is_linux else "not applicable to Windows local monitor",
        )
    )
    results.append(
        _result(
            "admin_group_exists",
            (not is_linux) or _group_exists(ADMIN_GROUP),
            ADMIN_GROUP if is_linux else "not applicable to Windows local monitor",
        )
    )

    if is_linux:
        current = inspect_path(current_link, expected_kind="symlink", reject_world_writable=False)
        results.append(_result("current_release_link", current.safe, json.dumps(current.to_dict())))
        if current.safe:
            try:
                release = current_link.resolve(strict=True)
                results.append(
                    _result(
                        "current_release_directory",
                        release.is_dir(),
                        str(release),
                    )
                )
                manifest = release / INSTALLATION_MANIFEST
                manifest_check = inspect_path(manifest, expected_kind="regular")
                results.append(
                    _result(
                        "installation_manifest",
                        manifest_check.safe,
                        json.dumps(manifest_check.to_dict()),
                    )
                )
            except OSError as exc:
                results.append(_result("current_release_directory", False, str(exc)))

        for name, directory, expected_mode in (
            ("runtime_directory", runtime_directory, "0750"),
            ("state_directory", state_directory, "0700"),
            ("log_directory", log_directory, "0750"),
        ):
            inspection = inspect_path(directory, expected_kind="directory")
            ok = inspection.safe and inspection.mode == expected_mode
            results.append(_result(name, ok, json.dumps(inspection.to_dict())))
    else:
        # The Linux service installation is deliberately not treated as a
        # Windows prerequisite.  The Windows GUI owns its local monitor in
        # process and does not create /opt, /run, or Unix-socket state.
        for name in (
            "current_release_link",
            "current_release_directory",
            "installation_manifest",
            "runtime_directory",
            "state_directory",
            "log_directory",
        ):
            results.append(
                _result(name, True, "not applicable to Windows local monitor")
            )

    probe_path = Path(__file__).parents[1] / "monitor" / "ebpf" / "probes.c"
    results.append(
        _result(
            "packaged_ebpf_source",
            probe_path.is_file() if is_linux else True,
            str(probe_path) if is_linux else "not applicable to Windows local monitor",
        )
    )

    bcc_available = importlib.util.find_spec("bcc") is not None
    results.append(
        _result(
            "bcc_python_bindings",
            bcc_available or not is_linux,
            (
                "importable"
                if bcc_available
                else ("not applicable to Windows ETW/local monitor" if not is_linux else "not importable; daemon will report degraded eBPF")
            ),
            warning=True,
        )
    )
    header_assessment = assess_kernel_headers()
    results.append(
        _result(
            "running_kernel_headers",
            header_assessment.ready or not is_linux,
            (
                json.dumps(header_assessment.to_dict())
                if is_linux
                else "not applicable to Windows ETW/local monitor"
            ),
            warning=True,
        )
    )
    clang = shutil.which("clang")
    results.append(
        _result(
            "clang",
            clang is not None or not is_linux,
            clang or ("not applicable to Windows local monitor" if not is_linux else "not found; daemon will report degraded eBPF"),
            warning=True,
        )
    )
    if not is_linux:
        windows_module = importlib.util.find_spec("elyra.monitor.windows") is not None
        results.append(
            _result(
                "windows_local_monitor",
                windows_module,
                "Windows monitor package importable; ETW/minifilter adapter remains local-only",
            )
        )
    return results


def overall_status(results: Iterable[PreflightResult]) -> str:
    return "FAIL" if any(item.status == "FAIL" for item in results) else "OK"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--service", action="store_true", help="require root service identity")
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    args = parser.parse_args(argv)

    results = run_preflight(service_mode=args.service)
    status = overall_status(results)
    if args.json:
        print(
            json.dumps(
                {"results": [item.to_dict() for item in results], "overall_status": status},
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        for item in results:
            print(f"[{item.status}] {item.check}: {item.detail}")
        print(f"overall_status: {status}")
    if status != "OK":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
