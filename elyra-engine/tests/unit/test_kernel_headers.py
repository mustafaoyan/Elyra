from __future__ import annotations

import shutil
from pathlib import Path

from elyra.monitor.ebpf.kernel_headers import (
    VirtualizationInfo,
    assess_kernel_headers,
    plan_kernel_header_resolution,
    resolve_kernel_headers,
)


def make_headers(source_root: Path, release: str, *, declared_release: str | None = None) -> Path:
    root = source_root / f"linux-headers-{release}"
    (root / "include" / "generated").mkdir(parents=True)
    (root / "Makefile").write_text("all:\n", encoding="utf-8")
    (root / "include" / "generated" / "utsrelease.h").write_text(
        f'#define UTS_RELEASE "{declared_release or release}"\n', encoding="utf-8"
    )
    return root


def test_matching_build_link_is_ready(tmp_path: Path) -> None:
    release = "6.12.0-elyra"
    module_root = tmp_path / "lib" / "modules"
    source_root = tmp_path / "usr" / "src"
    headers = make_headers(source_root, release)
    module_directory = module_root / release
    module_directory.mkdir(parents=True)
    shutil.copytree(headers, module_directory / "build")

    result = assess_kernel_headers(
        kernel_release=release,
        module_root=module_root,
        source_root=source_root,
        system_name="Linux",
        virtualization=VirtualizationInfo(True, "VIRTUALBOX"),
    )
    assert result.ready is True
    assert result.status == "READY"
    assert result.virtualization.kind == "VIRTUALBOX"


def test_stale_virtual_machine_build_link_is_reported_as_mismatch(tmp_path: Path) -> None:
    release = "6.12.0-guest"
    module_root = tmp_path / "lib" / "modules"
    source_root = tmp_path / "usr" / "src"
    stale = make_headers(source_root, "6.11.0-host")
    module_directory = module_root / release
    module_directory.mkdir(parents=True)
    shutil.copytree(stale, module_directory / "build")

    result = assess_kernel_headers(
        kernel_release=release,
        module_root=module_root,
        source_root=source_root,
        system_name="Linux",
        virtualization=VirtualizationInfo(True, "VIRTUALBOX"),
    )
    assert result.status == "MISMATCH"
    assert "BUILD_HEADERS_DO_NOT_MATCH_RUNNING_KERNEL" in result.issues
    assert "VIRTUALIZED_HEADER_CONFLICT" in result.issues


def test_missing_build_link_with_exact_local_headers_has_safe_link_plan(tmp_path: Path) -> None:
    release = "6.12.0-guest"
    module_root = tmp_path / "lib" / "modules"
    source_root = tmp_path / "usr" / "src"
    headers = make_headers(source_root, release)
    (module_root / release).mkdir(parents=True)
    assessment = assess_kernel_headers(
        kernel_release=release,
        module_root=module_root,
        source_root=source_root,
        system_name="Linux",
    )
    plan = plan_kernel_header_resolution(
        assessment,
        source_root=source_root,
        package_manager="apt-get",
    )
    action = plan.actions[0]
    assert action.kind == "CONFIGURE_BUILD_LINK"
    assert action.source_path is not None
    assert action.target_path is not None


def test_default_resolver_is_dry_run_and_never_changes_build_path(tmp_path: Path) -> None:
    release = "6.12.0-guest"
    module_root = tmp_path / "lib" / "modules"
    source_root = tmp_path / "usr" / "src"
    make_headers(source_root, release)
    build_path = module_root / release / "build"
    build_path.parent.mkdir(parents=True)

    result = resolve_kernel_headers(
        apply=False,
        kernel_release=release,
        module_root=module_root,
        source_root=source_root,
        system_name="Linux",
        package_manager="apt-get",
    )
    assert build_path.exists() is False
    assert result.final_assessment.status == "MISSING"
    assert result.steps[0].status == "DRY_RUN"


def test_non_linux_assessment_never_proposes_header_installation(tmp_path: Path) -> None:
    assessment = assess_kernel_headers(
        kernel_release="10.0",
        module_root=tmp_path / "modules",
        source_root=tmp_path / "headers",
        system_name="Windows",
    )
    assert assessment.status == "UNSUPPORTED_PLATFORM"
    assert plan_kernel_header_resolution(assessment).actions == ()


def test_install_plan_rejects_untrusted_kernel_release(tmp_path: Path) -> None:
    assessment = assess_kernel_headers(
        kernel_release="6.12.0;touch /tmp/pwned",
        module_root=tmp_path / "modules",
        source_root=tmp_path / "headers",
        system_name="Linux",
    )
    plan = plan_kernel_header_resolution(
        assessment,
        source_root=tmp_path / "headers",
        package_manager="apt-get",
    )
    assert plan.actions[0].kind == "MANUAL_REPAIR_REQUIRED"
    assert plan.actions[0].command == ()
