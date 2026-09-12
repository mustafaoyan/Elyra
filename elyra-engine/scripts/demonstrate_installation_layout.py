#!/usr/bin/env python3
"""Safe Stage 13 installation-layout and systemd-contract demonstration."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from elyra.service.install_layout import (
    CURRENT_LINK,
    DESKTOP_ENTRY_PATH,
    GUI_LAUNCHER_PATH,
    INSTALL_ROOT,
    IPC_GROUP,
    SERVICE_UNIT_PATH,
    installation_manifest,
    read_project_version,
    write_json_atomic,
)

ROOT = Path(__file__).resolve().parents[1]


def scenario(name: str, ok: bool, **detail):
    return {"scenario": name, "status": "OK" if ok else "FAIL", **detail}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    pyproject = ROOT / "pyproject.toml"
    version = read_project_version(pyproject)
    unit = (ROOT / "packaging/systemd/elyra.service").read_text(encoding="utf-8")
    installer = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    launcher = (ROOT / "scripts/launch_gui.sh").read_text(encoding="utf-8")
    desktop = (ROOT / "packaging/desktop/elyra.desktop").read_text(encoding="utf-8")
    sysusers = (ROOT / "packaging/sysusers/elyra.conf").read_text(encoding="utf-8")
    project_text = pyproject.read_text(encoding="utf-8")

    results = []
    results.append(
        scenario(
            "systemd_entry_points_match_install_layout",
            f"ExecStart={CURRENT_LINK}/.venv/bin/elyra-daemon" in unit
            and f"ExecStartPre={CURRENT_LINK}/.venv/bin/elyra-preflight --service" in unit,
        )
    )
    results.append(
        scenario(
            "systemd_safe_default_policy",
            "--execute-responses" not in unit and "--enforce" not in unit,
        )
    )
    results.append(
        scenario(
            "systemd_runtime_state_log_directories",
            all(
                token in unit
                for token in (
                    "RuntimeDirectory=elyra",
                    "StateDirectory=elyra",
                    "LogsDirectory=elyra",
                    "Restart=on-failure",
                )
            ),
        )
    )
    results.append(
        scenario(
            "installer_uses_versioned_release_and_system_bcc_visibility",
            'RELEASES_DIR="$INSTALL_ROOT/releases"' in installer
            and "python3 -m venv --system-site-packages" in installer
            and "atomic_switch_current" in installer,
        )
    )
    results.append(
        scenario(
            "dedicated_ipc_and_admin_groups",
            "g elyra " in sysusers
            and "g elyra-admin " in sysusers
            and "usermod -a -G elyra" in installer
            and "usermod -a -G elyra-admin" in installer,
        )
    )
    results.append(
        scenario(
            "gui_launcher_targets_installed_console_script",
            f"ENTRY={CURRENT_LINK}/.venv/bin/elyra-gui" in launcher
            and f"Exec={GUI_LAUNCHER_PATH}" in desktop,
        )
    )
    results.append(
        scenario(
            "package_exposes_real_entry_points_and_ebpf_source",
            all(
                token in project_text
                for token in (
                    'elyra-daemon = "elyra.service.daemon:main"',
                    'elyra-gui = "elyra.gui.main:main"',
                    'elyra-preflight = "elyra.service.preflight:main"',
                    'elyra-install-check = "elyra.service.installation_check:main"',
                    '"elyra.monitor.ebpf" = ["probes.c"]',
                )
            ),
        )
    )
    results.append(
        scenario(
            "production_paths_are_consistent",
            str(INSTALL_ROOT) == "/opt/elyra"
            and str(SERVICE_UNIT_PATH) == "/etc/systemd/system/elyra.service"
            and str(DESKTOP_ENTRY_PATH) == "/usr/share/applications/elyra.desktop"
            and IPC_GROUP == "elyra",
        )
    )

    with tempfile.TemporaryDirectory(prefix="elyra-stage13-layout-") as temporary:
        release = Path(temporary) / "releases" / f"{version}-demo"
        release.mkdir(parents=True)
        manifest = installation_manifest(
            version=version,
            release_name=release.name,
            source_directory=str(ROOT),
            installed_at_utc=datetime.now(timezone.utc).isoformat(),
        )
        manifest_path = release / "INSTALLATION.json"
        write_json_atomic(manifest_path, manifest)
        decoded = json.loads(manifest_path.read_text(encoding="utf-8"))
        results.append(
            scenario(
                "installation_manifest_records_safe_defaults",
                decoded["automatic_runtime_actions"] is False
                and decoded["fanotify_policy"] == "MONITOR_ONLY",
                manifest=decoded,
            )
        )

    shell_checks = {}
    for relative in ("scripts/install.sh", "scripts/uninstall.sh"):
        completed = subprocess.run(
            ["bash", "-n", str(ROOT / relative)], capture_output=True, text=True, check=False
        )
        shell_checks[relative] = {"returncode": completed.returncode, "stderr": completed.stderr}
    completed = subprocess.run(
        ["sh", "-n", str(ROOT / "scripts/launch_gui.sh")],
        capture_output=True,
        text=True,
        check=False,
    )
    shell_checks["scripts/launch_gui.sh"] = {
        "returncode": completed.returncode,
        "stderr": completed.stderr,
    }
    results.append(
        scenario(
            "installer_launcher_shell_syntax",
            all(item["returncode"] == 0 for item in shell_checks.values()),
            checks=shell_checks,
        )
    )

    overall = "OK" if all(item["status"] == "OK" for item in results) else "FAIL"
    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "method": "temporary manifest and source-contract checks only; no root, apt, systemd changes, or daemon start",
        "version": version,
        "results": results,
        "overall_status": overall,
    }
    write_json_atomic(args.output, report)
    for item in results:
        print(f"{item['scenario']}: {item['status']}")
    print(f"overall_status: {overall}")
    print(f"Evidence written to: {args.output}")
    if overall != "OK":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
