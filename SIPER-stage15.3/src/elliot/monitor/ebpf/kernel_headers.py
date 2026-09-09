"""Linux kernel-header compatibility detection and safe repair planning.

BCC compiles the ELLIOT probes against the *running* kernel.  A common
virtual-machine failure mode is a stale ``/lib/modules/<release>/build`` link
that points at headers for the host, an older guest kernel, or a removed
package.  This module makes that condition explicit and can prepare an exact
repair plan.

The library API is read-only by default.  Package installation and symlink
changes require an explicit ``apply=True`` call, root privileges, and a plan
created for the current running kernel.  It deliberately never replaces a
real directory at the ``build`` path; that condition needs an administrator's
manual review.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence


_VIRTUALIZATION_MARKERS = {
    "virtualbox": "VIRTUALBOX",
    "oracle": "VIRTUALBOX",
    "vmware": "VMWARE",
    "kvm": "KVM",
    "qemu": "QEMU",
    "xen": "XEN",
    "microsoft": "HYPER_V",
    "hyper-v": "HYPER_V",
    "parallels": "PARALLELS",
    "bhyve": "BHYVE",
}


@dataclass(frozen=True, slots=True)
class VirtualizationInfo:
    """Best-effort local virtualization signal with its supporting evidence."""

    detected: bool
    kind: str
    evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class KernelHeaderAssessment:
    """Read-only assessment of the headers used to compile eBPF probes."""

    status: str
    system: str
    kernel_release: str
    module_directory: str
    build_path: str
    build_target: str | None
    header_root: str | None
    header_release: str | None
    virtualization: VirtualizationInfo
    issues: tuple[str, ...] = ()
    local_candidates: tuple[str, ...] = ()

    @property
    def ready(self) -> bool:
        return self.status == "READY"

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["ready"] = self.ready
        return payload


@dataclass(frozen=True, slots=True)
class HeaderResolutionAction:
    """One proposed repair step.  Commands are argument vectors, never shell text."""

    kind: str
    summary: str
    command: tuple[str, ...] = ()
    source_path: str | None = None
    target_path: str | None = None
    requires_root: bool = True

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class KernelHeaderResolutionPlan:
    """A transparent, non-executing repair plan for one assessment."""

    assessment: KernelHeaderAssessment
    package_manager: str | None
    actions: tuple[HeaderResolutionAction, ...] = ()

    @property
    def actionable(self) -> bool:
        return bool(self.actions) and any(
            action.kind in {"INSTALL_HEADERS", "CONFIGURE_BUILD_LINK"}
            for action in self.actions
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "assessment": self.assessment.to_dict(),
            "package_manager": self.package_manager,
            "actions": [action.to_dict() for action in self.actions],
            "actionable": self.actionable,
        }


@dataclass(frozen=True, slots=True)
class ResolutionStepResult:
    """Result of applying (or safely previewing) one resolution action."""

    action: HeaderResolutionAction
    status: str
    detail: str
    returncode: int | None = None

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["action"] = self.action.to_dict()
        return payload


@dataclass(frozen=True, slots=True)
class KernelHeaderResolutionResult:
    """Initial plan, execution outcome and final post-condition assessment."""

    initial_plan: KernelHeaderResolutionPlan
    steps: tuple[ResolutionStepResult, ...]
    final_assessment: KernelHeaderAssessment

    @property
    def changed(self) -> bool:
        return any(step.status == "APPLIED" for step in self.steps)

    def to_dict(self) -> dict[str, object]:
        return {
            "initial_plan": self.initial_plan.to_dict(),
            "steps": [step.to_dict() for step in self.steps],
            "final_assessment": self.final_assessment.to_dict(),
            "changed": self.changed,
        }


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def _read_small_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:4096]
    except OSError:
        return None


def _normalise_virtualization(value: str) -> str | None:
    text = value.lower()
    for marker, name in _VIRTUALIZATION_MARKERS.items():
        if marker in text:
            return name
    return None


def detect_virtualization(
    *,
    dmi_paths: Iterable[Path] | None = None,
    command_runner: CommandRunner | None = None,
) -> VirtualizationInfo:
    """Inspect local DMI data and, when available, ``systemd-detect-virt``.

    Detection is advisory: it explains why a stale header link is common, but
    it never changes the compatibility decision on its own.
    """

    paths = tuple(
        dmi_paths
        or (
            Path("/sys/class/dmi/id/product_name"),
            Path("/sys/class/dmi/id/sys_vendor"),
            Path("/sys/class/dmi/id/board_vendor"),
        )
    )
    evidence: list[str] = []
    kinds: list[str] = []
    for path in paths:
        content = _read_small_text(path)
        if not content:
            continue
        value = content.strip()
        if not value:
            continue
        evidence.append(f"{path.name}={value}")
        kind = _normalise_virtualization(value)
        if kind:
            kinds.append(kind)

    runner = command_runner or subprocess.run
    tool = shutil.which("systemd-detect-virt")
    if tool:
        try:
            completed = runner(
                [tool, "--vm"],
                capture_output=True,
                text=True,
                timeout=1.0,
                check=False,
            )
            output = (completed.stdout or "").strip()
            if completed.returncode == 0 and output:
                evidence.append(f"systemd-detect-virt={output}")
                kind = _normalise_virtualization(output) or output.upper().replace("-", "_")
                kinds.append(kind)
        except (OSError, subprocess.SubprocessError):
            # Virtualization detection must never make startup or preflight fail.
            pass

    if kinds:
        return VirtualizationInfo(True, kinds[0], tuple(evidence))
    return VirtualizationInfo(False, "NONE", tuple(evidence))


def _header_tree_is_usable(root: Path) -> bool:
    return root.is_dir() and (root / "Makefile").is_file() and (root / "include").is_dir()


def _header_release(root: Path, kernel_release: str) -> str | None:
    """Read a release value when the installed tree exposes one.

    Distro header packages do not all include generated release metadata.  In
    that case an exact release in the directory name is still useful evidence,
    but absence of either marker is intentionally not called a mismatch.
    """

    for candidate in (
        root / "include" / "generated" / "utsrelease.h",
        root / "include" / "config" / "kernel.release",
    ):
        text = _read_small_text(candidate)
        if not text:
            continue
        match = re.search(r'UTS_RELEASE\s+"([^"]+)"', text)
        if match:
            return match.group(1)
        stripped = text.strip().splitlines()
        if stripped and re.fullmatch(r"[A-Za-z0-9._+~-]+", stripped[0].strip()):
            return stripped[0].strip()
    if kernel_release in root.name:
        return kernel_release
    return None


def _safe_target(path: Path) -> Path | None:
    try:
        return path.resolve(strict=True)
    except OSError:
        return None


def _header_candidates(kernel_release: str, source_root: Path) -> tuple[Path, ...]:
    """Return deterministic, exact-version local header candidates only."""

    candidates = (
        source_root / f"linux-headers-{kernel_release}",
        source_root / "kernels" / kernel_release,
        source_root / f"kernel-devel-{kernel_release}",
        source_root / kernel_release,
    )
    seen: set[Path] = set()
    usable: list[Path] = []
    for candidate in candidates:
        resolved = _safe_target(candidate) or candidate
        if resolved in seen:
            continue
        seen.add(resolved)
        if _header_tree_is_usable(resolved) and _header_release(resolved, kernel_release) == kernel_release:
            usable.append(resolved)
    return tuple(usable)


def assess_kernel_headers(
    *,
    kernel_release: str | None = None,
    module_root: Path = Path("/lib/modules"),
    source_root: Path = Path("/usr/src"),
    system_name: str | None = None,
    virtualization: VirtualizationInfo | None = None,
) -> KernelHeaderAssessment:
    """Assess whether BCC can use an exact header tree for the running kernel.

    This function is intentionally read-only and has no package-manager side
    effects.  Parameters exist so unit tests and deployment tooling can assess
    a staged root without monkeypatching global host paths.
    """

    system = system_name or platform.system()
    release = kernel_release or platform.release()
    module_directory = module_root / release
    build_path = module_directory / "build"
    vm = virtualization or detect_virtualization()

    if system != "Linux":
        return KernelHeaderAssessment(
            status="UNSUPPORTED_PLATFORM",
            system=system,
            kernel_release=release,
            module_directory=str(module_directory),
            build_path=str(build_path),
            build_target=None,
            header_root=None,
            header_release=None,
            virtualization=vm,
            issues=("LINUX_EBPF_HEADERS_NOT_APPLICABLE",),
        )

    issues: list[str] = []
    candidates = _header_candidates(release, source_root)
    if not module_directory.is_dir():
        issues.append("RUNNING_KERNEL_MODULE_DIRECTORY_MISSING")

    target = _safe_target(build_path)
    if target is None:
        if build_path.is_symlink():
            issues.append("BUILD_LINK_DANGLING")
        else:
            issues.append("BUILD_LINK_MISSING")
        return KernelHeaderAssessment(
            status="MISSING",
            system=system,
            kernel_release=release,
            module_directory=str(module_directory),
            build_path=str(build_path),
            build_target=None,
            header_root=None,
            header_release=None,
            virtualization=vm,
            issues=tuple(issues),
            local_candidates=tuple(str(item) for item in candidates),
        )

    if not _header_tree_is_usable(target):
        issues.append("BUILD_TARGET_NOT_A_USABLE_HEADER_TREE")
        return KernelHeaderAssessment(
            status="INVALID",
            system=system,
            kernel_release=release,
            module_directory=str(module_directory),
            build_path=str(build_path),
            build_target=str(target),
            header_root=str(target),
            header_release=None,
            virtualization=vm,
            issues=tuple(issues),
            local_candidates=tuple(str(item) for item in candidates),
        )

    detected_release = _header_release(target, release)
    if detected_release is not None and detected_release != release:
        issues.append("BUILD_HEADERS_DO_NOT_MATCH_RUNNING_KERNEL")
        return KernelHeaderAssessment(
            status="MISMATCH",
            system=system,
            kernel_release=release,
            module_directory=str(module_directory),
            build_path=str(build_path),
            build_target=str(target),
            header_root=str(target),
            header_release=detected_release,
            virtualization=vm,
            issues=tuple(issues),
            local_candidates=tuple(str(item) for item in candidates),
        )

    if detected_release is None:
        issues.append("HEADER_RELEASE_NOT_EXPOSED")
    return KernelHeaderAssessment(
        status="READY",
        system=system,
        kernel_release=release,
        module_directory=str(module_directory),
        build_path=str(build_path),
        build_target=str(target),
        header_root=str(target),
        header_release=detected_release,
        virtualization=vm,
        issues=tuple(issues),
        local_candidates=tuple(str(item) for item in candidates),
    )


def detect_package_manager() -> str | None:
    """Return the first supported local package manager without invoking it."""

    for name in ("apt-get", "dnf", "yum", "zypper", "pacman"):
        if shutil.which(name):
            return name
    return None


def _install_command(package_manager: str, kernel_release: str) -> tuple[str, ...] | None:
    """Build an exact-version install command appropriate for the manager."""

    if package_manager == "apt-get":
        return ("apt-get", "install", "--yes", f"linux-headers-{kernel_release}")
    if package_manager in {"dnf", "yum"}:
        return (
            package_manager,
            "install",
            "--assumeyes",
            f"kernel-devel-{kernel_release}",
            f"kernel-headers-{kernel_release}",
        )
    if package_manager == "zypper":
        return (
            "zypper",
            "--non-interactive",
            "install",
            f"kernel-default-devel={kernel_release}",
        )
    if package_manager == "pacman":
        # Arch's header package follows the installed kernel flavour; the
        # post-install assessment still enforces the exact running release.
        return ("pacman", "-S", "--needed", "--noconfirm", "linux-headers")
    return None


def plan_kernel_header_resolution(
    assessment: KernelHeaderAssessment,
    *,
    source_root: Path = Path("/usr/src"),
    package_manager: str | None = None,
) -> KernelHeaderResolutionPlan:
    """Build a repair plan without running package managers or modifying links."""

    if assessment.status == "UNSUPPORTED_PLATFORM" or assessment.ready:
        return KernelHeaderResolutionPlan(assessment, package_manager, ())

    manager = package_manager if package_manager is not None else detect_package_manager()
    candidates = _header_candidates(assessment.kernel_release, source_root)
    build_path = Path(assessment.build_path)
    actions: list[HeaderResolutionAction] = []

    if candidates:
        candidate = candidates[0]
        if build_path.exists() and not build_path.is_symlink():
            actions.append(
                HeaderResolutionAction(
                    kind="MANUAL_REPAIR_REQUIRED",
                    summary=(
                        "The build path is a real file or directory and will not be "
                        "overwritten automatically. Inspect it before replacing it with "
                        f"a link to {candidate}."
                    ),
                    source_path=str(candidate),
                    target_path=str(build_path),
                )
            )
        elif build_path.parent.is_dir():
            actions.append(
                HeaderResolutionAction(
                    kind="CONFIGURE_BUILD_LINK",
                    summary=(
                        "Point the running kernel build link at the matching local "
                        "header tree. Existing symlinks are atomically replaced; real "
                        "directories are never replaced."
                    ),
                    source_path=str(candidate),
                    target_path=str(build_path),
                )
            )
        else:
            actions.append(
                HeaderResolutionAction(
                    kind="MANUAL_REPAIR_REQUIRED",
                    summary=(
                        "The running kernel module directory is absent. Install the "
                        "matching kernel package before configuring its build link."
                    ),
                    source_path=str(candidate),
                    target_path=str(build_path),
                )
            )
    else:
        command = _install_command(manager, assessment.kernel_release) if manager else None
        if command:
            actions.append(
                HeaderResolutionAction(
                    kind="INSTALL_HEADERS",
                    summary=(
                        "Install headers for the exact running kernel. This is shown as "
                        "a dry run unless the caller explicitly requests apply=True."
                    ),
                    command=command,
                )
            )
        else:
            actions.append(
                HeaderResolutionAction(
                    kind="MANUAL_REPAIR_REQUIRED",
                    summary=(
                        "No supported package manager was found. Install an exact "
                        "kernel header/devel package, then run the resolver again."
                    ),
                )
            )

    return KernelHeaderResolutionPlan(assessment, manager, tuple(actions))


def _configure_build_link(action: HeaderResolutionAction) -> ResolutionStepResult:
    if not action.source_path or not action.target_path:
        return ResolutionStepResult(action, "FAILED", "link action is missing source or target")
    source = Path(action.source_path)
    target = Path(action.target_path)
    if not _header_tree_is_usable(source):
        return ResolutionStepResult(action, "FAILED", f"source is not a usable header tree: {source}")
    if not target.parent.is_dir():
        return ResolutionStepResult(action, "FAILED", f"target parent does not exist: {target.parent}")
    if target.exists() and not target.is_symlink():
        return ResolutionStepResult(
            action,
            "SKIPPED",
            f"refusing to replace real file or directory: {target}",
        )

    temporary = target.with_name(f".{target.name}.elliot-{os.getpid()}-new")
    try:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()
        os.symlink(source, temporary, target_is_directory=True)
        os.replace(temporary, target)
    except OSError as exc:
        try:
            if temporary.exists() or temporary.is_symlink():
                temporary.unlink()
        except OSError:
            pass
        return ResolutionStepResult(action, "FAILED", f"cannot configure build link: {exc}")
    return ResolutionStepResult(action, "APPLIED", f"{target} -> {source}")


def _run_install(
    action: HeaderResolutionAction,
    *,
    command_runner: CommandRunner,
) -> ResolutionStepResult:
    if not action.command:
        return ResolutionStepResult(action, "FAILED", "install action has no command")
    try:
        completed = command_runner(
            list(action.command),
            capture_output=True,
            text=True,
            timeout=180.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return ResolutionStepResult(action, "FAILED", f"package-manager launch failed: {exc}")
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout or "package manager returned an error").strip()
        return ResolutionStepResult(
            action,
            "FAILED",
            detail[-2000:],
            returncode=completed.returncode,
        )
    return ResolutionStepResult(
        action,
        "APPLIED",
        "package manager completed successfully",
        returncode=completed.returncode,
    )


def resolve_kernel_headers(
    *,
    apply: bool = False,
    kernel_release: str | None = None,
    module_root: Path = Path("/lib/modules"),
    source_root: Path = Path("/usr/src"),
    system_name: str | None = None,
    package_manager: str | None = None,
    command_runner: CommandRunner | None = None,
) -> KernelHeaderResolutionResult:
    """Assess and optionally repair header compatibility for the running kernel.

    ``apply=False`` is a dry run.  When ``apply=True`` this function requires
    root, installs only the exact package advertised in the plan, and only
    replaces a symlink at ``.../build``.  After installation it re-assesses and
    performs a newly safe link action if a matching local tree appeared.
    """

    initial = assess_kernel_headers(
        kernel_release=kernel_release,
        module_root=module_root,
        source_root=source_root,
        system_name=system_name,
    )
    initial_plan = plan_kernel_header_resolution(
        initial,
        source_root=source_root,
        package_manager=package_manager,
    )
    if not apply:
        steps = tuple(
            ResolutionStepResult(action, "DRY_RUN", "no system changes requested")
            for action in initial_plan.actions
        )
        return KernelHeaderResolutionResult(initial_plan, steps, initial)

    if initial.system != "Linux":
        return KernelHeaderResolutionResult(
            initial_plan,
            tuple(
                ResolutionStepResult(action, "SKIPPED", "Linux kernel headers are not applicable")
                for action in initial_plan.actions
            ),
            initial,
        )
    if os.geteuid() != 0:
        return KernelHeaderResolutionResult(
            initial_plan,
            tuple(
                ResolutionStepResult(action, "FAILED", "root privileges are required for --apply")
                for action in initial_plan.actions
            ),
            initial,
        )

    runner = command_runner or subprocess.run
    steps: list[ResolutionStepResult] = []
    for action in initial_plan.actions:
        if action.kind == "INSTALL_HEADERS":
            steps.append(_run_install(action, command_runner=runner))
        elif action.kind == "CONFIGURE_BUILD_LINK":
            steps.append(_configure_build_link(action))
        else:
            steps.append(ResolutionStepResult(action, "SKIPPED", action.summary))

    final = assess_kernel_headers(
        kernel_release=kernel_release,
        module_root=module_root,
        source_root=source_root,
        system_name=system_name,
    )
    # Package managers normally make a suitable /usr/src tree available but do
    # not always recreate /lib/modules/<release>/build. A second, freshly
    # assessed link step is safe and completes the advertised automatic repair.
    follow_up = plan_kernel_header_resolution(
        final,
        source_root=source_root,
        package_manager=package_manager,
    )
    for action in follow_up.actions:
        if action.kind == "CONFIGURE_BUILD_LINK":
            steps.append(_configure_build_link(action))
    if any(action.kind == "CONFIGURE_BUILD_LINK" for action in follow_up.actions):
        final = assess_kernel_headers(
            kernel_release=kernel_release,
            module_root=module_root,
            source_root=source_root,
            system_name=system_name,
        )

    return KernelHeaderResolutionResult(initial_plan, tuple(steps), final)
