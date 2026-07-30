from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UNIT = (ROOT / "packaging/systemd/elliot.service").read_text(encoding="utf-8")
INSTALLER = (ROOT / "scripts/install.sh").read_text(encoding="utf-8")
UNINSTALLER = (ROOT / "scripts/uninstall.sh").read_text(encoding="utf-8")
LAUNCHER = (ROOT / "scripts/launch_gui.sh").read_text(encoding="utf-8")
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_systemd_execstart_points_to_installed_console_script() -> None:
    assert "ExecStart=/opt/elliot/current/.venv/bin/siper-daemon" in UNIT
    assert "ExecStartPre=/opt/elliot/current/.venv/bin/siper-preflight --service" in UNIT
    assert "WorkingDirectory=/opt/elliot/current" in UNIT


def test_systemd_safe_defaults_do_not_enable_enforcement_or_actions() -> None:
    assert "--enforce" not in UNIT
    assert "--execute-responses" not in UNIT
    assert "Restart=on-failure" in UNIT


def test_systemd_manages_runtime_state_and_log_directories() -> None:
    for token in (
        "RuntimeDirectory=elliot",
        "RuntimeDirectoryMode=0750",
        "StateDirectory=elliot",
        "StateDirectoryMode=0700",
        "LogsDirectory=elliot",
        "LogsDirectoryMode=0750",
    ):
        assert token in UNIT


def test_installer_uses_versioned_release_and_atomic_current_link() -> None:
    assert 'RELEASES_DIR="$INSTALL_ROOT/releases"' in INSTALLER
    assert "atomic_switch_current" in INSTALLER
    assert "mv -Tf" in INSTALLER
    assert "INSTALLATION.json" not in INSTALLER or "installation_manifest" in INSTALLER


def test_installer_venv_can_see_apt_installed_bcc() -> None:
    assert "python3 -m venv --system-site-packages" in INSTALLER
    assert "--no-build-isolation --no-deps" in INSTALLER
    assert "python3-setuptools" in INSTALLER
    assert "python3-wheel" in INSTALLER
    assert "python3-bpfcc" in INSTALLER
    assert "bpfcc-tools" in INSTALLER
    assert "clang" in INSTALLER


def test_installer_handles_running_kernel_headers_without_wrong_version() -> None:
    assert '/lib/modules/$(uname -r)/build' in INSTALLER
    assert "linux-headers-amd64" in INSTALLER
    assert "exit 20" in INSTALLER


def test_installer_creates_ipc_groups_but_admin_membership_is_explicit() -> None:
    assert "systemd-sysusers" in INSTALLER
    assert "usermod -a -G elliot \"$GUI_USER\"" in INSTALLER
    assert "usermod -a -G elliot-admin \"$ADMIN_USER\"" in INSTALLER
    assert 'ADMIN_USER=""' in INSTALLER


def test_gui_launcher_targets_real_installed_entry_point() -> None:
    assert "ENTRY=/opt/elliot/current/.venv/bin/siper-gui" in LAUNCHER
    assert 'exec "$ENTRY" "$@"' in LAUNCHER
    desktop = (ROOT / "packaging/desktop/siper.desktop").read_text(encoding="utf-8")
    assert "Exec=/usr/local/bin/siper-gui" in desktop
    assert "Terminal=false" in desktop


def test_pyproject_exposes_all_production_entry_points_and_probe_data() -> None:
    for token in (
        'siper-daemon = "elliot.service.daemon:main"',
        'siper-gui = "elliot.gui.main:main"',
        'siper-preflight = "elliot.service.preflight:main"',
        'siper-install-check = "elliot.service.installation_check:main"',
        '"elliot.monitor.ebpf" = ["probes.c"]',
    ):
        assert token in PYPROJECT


def test_uninstaller_preserves_security_data_without_explicit_purge() -> None:
    assert "PURGE_DATA=0" in UNINSTALLER
    assert "Preserved /var/lib/elliot and /var/log/elliot" in UNINSTALLER
    assert "--purge-data" in UNINSTALLER


def test_installation_shell_files_have_valid_syntax() -> None:
    checks = [
        (["bash", "-n", str(ROOT / "scripts/install.sh")]),
        (["bash", "-n", str(ROOT / "scripts/uninstall.sh")]),
        (["sh", "-n", str(ROOT / "scripts/launch_gui.sh")]),
    ]
    for command in checks:
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        assert completed.returncode == 0, completed.stderr


def test_no_placeholder_repository_url_in_installation_files() -> None:
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            ROOT / "scripts/install.sh",
            ROOT / "packaging/systemd/elliot.service",
            ROOT / "packaging/desktop/elliot.desktop",
        )
    )
    assert "example.com" not in combined
    assert "github.com/USERNAME" not in combined
