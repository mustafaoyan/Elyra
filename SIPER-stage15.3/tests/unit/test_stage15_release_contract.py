from __future__ import annotations

import hashlib
import subprocess
import tomllib
from pathlib import Path

from elliot import __version__
from elliot.release.bundle import deterministic_zip, iter_release_files

ROOT = Path(__file__).resolve().parents[2]


def test_final_version_is_consistent() -> None:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        version = tomllib.load(stream)["project"]["version"]
    assert version == "1.0.0"
    assert __version__ == version


def test_readme_contains_final_operational_sections() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    for heading in (
        "## Architecture",
        "## Safety boundary",
        "## Requirements",
        "## Degraded mode",
        "## Final evidence and submission",
        "## Known limitations",
    ):
        assert heading in text
    assert "High entropy alone cannot produce a deny decision" in text


def test_required_final_documents_exist() -> None:
    for relative in (
        "SECURITY.md",
        "CHANGELOG.md",
        "RELEASE_NOTES.md",
        "docs/architecture.md",
        "docs/evidence_guide.md",
        "docs/submission_checklist.md",
        "docs/controlled_live_malware_lab.md",
    ):
        assert (ROOT / relative).is_file(), relative


def test_systemd_defaults_remain_non_destructive() -> None:
    unit = (ROOT / "packaging/systemd/elliot.service").read_text(encoding="utf-8")
    exec_line = next(line for line in unit.splitlines() if line.startswith("ExecStart="))
    assert "--enforce" not in exec_line
    assert "--execute-responses" not in exec_line


def test_debian_control_declares_kernel_and_bcc_dependencies() -> None:
    control = (ROOT / "packaging/debian/control.in").read_text(encoding="utf-8")
    for dependency in ("python3-bpfcc", "bpfcc-tools", "clang", "linux-headers-amd64", "python3-pil.imagetk"):
        assert dependency in control


def test_debian_postinst_does_not_assign_admin_group() -> None:
    postinst = (ROOT / "packaging/debian/postinst.in").read_text(encoding="utf-8")
    assert "usermod -aG elliot-admin" not in postinst
    assert "MONITOR_ONLY" in postinst


def test_debian_builder_has_valid_shell_syntax() -> None:
    completed = subprocess.run(
        ["bash", "-n", str(ROOT / "scripts/build_pardus_deb.sh")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_release_iterator_excludes_private_build_material(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("ok", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv/secret").write_text("no", encoding="utf-8")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist/old.zip").write_text("no", encoding="utf-8")
    files = [path.relative_to(tmp_path).as_posix() for path in iter_release_files(tmp_path, include_evidence=True)]
    assert files == ["README.md"]


def test_deterministic_zip_is_reproducible(tmp_path: Path) -> None:
    root = tmp_path / "SIPER"
    root.mkdir()
    (root / "a.txt").write_text("alpha", encoding="utf-8")
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    deterministic_zip(root, first, include_evidence=True)
    deterministic_zip(root, second, include_evidence=True)
    assert hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()


def test_console_scripts_include_finalization_tools() -> None:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        scripts = tomllib.load(stream)["project"]["scripts"]
    assert scripts["siper-submission-check"] == "elliot.release.submission:main"
    assert scripts["siper-release-build"] == "elliot.release.bundle:main"
    assert scripts["elliot-submission-check"] == "elliot.release.submission:main"
    assert scripts["elliot-release-build"] == "elliot.release.bundle:main"


def test_live_malware_gate_lists_required_controls() -> None:
    text = (ROOT / "docs/controlled_live_malware_lab.md").read_text(encoding="utf-8")
    for phrase in ("written", "snapshot", "network", "SHA-256", "recovery"):
        assert phrase.lower() in text.lower()


def test_gitignore_excludes_generated_submission_and_package_files() -> None:
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "*.deb" in text
    assert "evidence/submission/final_manifest.json" in text
    assert ".venv/" in text


def test_siper_public_branding_contract() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["name"] == "siper-pardus"
    scripts = pyproject["project"]["scripts"]
    assert scripts["siper-gui"] == "elliot.gui.main:main"
    assert scripts["siper-daemon"] == "elliot.service.daemon:main"
    desktop = (ROOT / "packaging/desktop/siper.desktop").read_text(encoding="utf-8")
    assert "Name=Siper Security Monitor" in desktop
    assert "Exec=/usr/local/bin/siper-gui" in desktop
    view = (ROOT / "src/elliot/gui/view.py").read_text(encoding="utf-8")
    assert "Siper — Pardus Security Monitor" in view
    assert 'text="SIPER"' in view


def test_siper_service_alias_is_declared() -> None:
    unit = (ROOT / "packaging/systemd/elliot.service").read_text(encoding="utf-8")
    assert "Description=Siper Pardus security daemon" in unit
    assert "Alias=siper.service" in unit
    assert "/.venv/bin/siper-daemon" in unit
