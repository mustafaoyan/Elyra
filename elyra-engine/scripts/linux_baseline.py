#!/usr/bin/env python3
"""Collect a read-only Linux capability baseline for ELYRA.

This is L0 of the Linux roadmap. It never installs packages, changes kernel
links, attaches probes, opens fanotify groups, or starts the daemon. Run it on
the Linux host that will later be used for native verification:

    PYTHONPATH=src python scripts/linux_baseline.py --json-out evidence/linux/baseline.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from elyra.monitor.ebpf.kernel_headers import (  # noqa: E402
    assess_kernel_headers,
    detect_package_manager,
    detect_virtualization,
)


def _command_version(command: str, *arguments: str) -> dict[str, Any]:
    executable = shutil.which(command)
    if not executable:
        return {"available": False, "path": None, "version": None}
    try:
        completed = subprocess.run(
            [executable, *arguments], capture_output=True, text=True,
            timeout=2.0, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": True, "path": executable, "version": None,
                "error": type(exc).__name__}
    output = (completed.stdout or completed.stderr).strip().splitlines()
    return {"available": completed.returncode == 0, "path": executable,
            "version": output[0][:200] if output else None,
            "returncode": completed.returncode}


def _read_text(path: Path, limit: int = 4096) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return None


def _fanotify_baseline() -> dict[str, Any]:
    filesystems = _read_text(Path("/proc/filesystems")) or ""
    fanotify_api = Path("/proc/sys/fs/fanotify")
    return {
        "kernel_filesystem_entry": "nodev\tfanotify" in filesystems,
        "fanotify_sysctl_directory": fanotify_api.is_dir(),
        "cap_sys_admin_or_root": bool(getattr(os, "geteuid", lambda: -1)() == 0),
        "status": "READY_TO_VERIFY" if "fanotify" in filesystems else "UNAVAILABLE",
        "note": "Presence is not a proof that the requested event mask is permitted.",
    }


def _ebpf_baseline() -> dict[str, Any]:
    tracefs_candidates = (Path("/sys/kernel/tracing"), Path("/sys/kernel/debug/tracing"))
    tracefs = next((item for item in tracefs_candidates if item.is_dir()), None)
    bcc_importable = importlib.util.find_spec("bcc") is not None
    return {
        "tracefs": str(tracefs) if tracefs else None,
        "tracefs_present": tracefs is not None,
        "bcc_importable": bcc_importable,
        "clang": _command_version("clang", "--version"),
        "status": "READY_TO_VERIFY" if tracefs and bcc_importable else "DEGRADED",
        "note": "No probe is attached by this baseline command.",
    }


def collect_baseline() -> dict[str, Any]:
    system = platform.system()
    assessment = assess_kernel_headers()
    payload: dict[str, Any] = {
        "schema_version": 1,
        "tool": "elyra-linux-baseline",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": {
            "system": system,
            "release": platform.release(),
            "machine": platform.machine(),
            "distribution": platform.platform(),
            "python": sys.version.split()[0],
            "uid": getattr(os, "getuid", lambda: None)(),
            "effective_uid": getattr(os, "geteuid", lambda: None)(),
        },
        "virtualization": detect_virtualization().to_dict(),
        "package_manager": detect_package_manager(),
        "kernel_headers": assessment.to_dict(),
        "fanotify": _fanotify_baseline() if system == "Linux" else {
            "status": "UNAVAILABLE", "note": "Linux host required"
        },
        "ebpf": _ebpf_baseline() if system == "Linux" else {
            "status": "UNAVAILABLE", "note": "Linux host required"
        },
        "safety": {
            "read_only": True,
            "packages_changed": False,
            "kernel_links_changed": False,
            "probes_attached": False,
            "fanotify_group_opened": False,
            "malware_downloaded_or_executed": False,
        },
    }
    if system != "Linux":
        payload["overall_status"] = "UNAVAILABLE_NON_LINUX_HOST"
    elif assessment.ready and payload["fanotify"]["status"] == "READY_TO_VERIFY" and payload["ebpf"]["status"] == "READY_TO_VERIFY":
        payload["overall_status"] = "BASELINE_READY_FOR_NATIVE_TESTS"
    else:
        payload["overall_status"] = "BASELINE_CAPTURED_DEGRADED"
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", type=Path, help="write JSON evidence to this path")
    args = parser.parse_args(argv)
    payload = collect_baseline()
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.json_out.with_name(f".{args.json_out.name}.{os.getpid()}.tmp")
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, args.json_out)
    print(text, end="")
    if args.json_out:
        print(f"evidence: {args.json_out}")
    return 0 if payload["overall_status"] != "UNAVAILABLE_NON_LINUX_HOST" else 2


if __name__ == "__main__":
    raise SystemExit(main())
