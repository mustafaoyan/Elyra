"""Final evidence inventory and submission-manifest generation.

The module never fabricates evidence. It records missing, unreadable, malformed
or failed evidence explicitly and returns a non-zero status in strict mode.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import tomllib
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ZERO_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    key: str
    patterns: tuple[str, ...]
    description: str
    critical: bool = True
    require_ok_status: bool = True


REQUIREMENTS: tuple[EvidenceRequirement, ...] = (
    EvidenceRequirement(
        "entropy_analysis",
        ("entropy/stage3_benchmark_pardus.json",),
        "Whole-file and block-level entropy benchmark on Pardus.",
        require_ok_status=False,
    ),
    EvidenceRequirement(
        "explainable_scoring",
        ("scoring/stage4_scoring_pardus.json",),
        "Explainable pre-execution scoring demonstration.",
    ),
    EvidenceRequirement(
        "quarantine_restore",
        ("quarantine/stage5_quarantine_pardus.json",),
        "Secure quarantine and restoration verification.",
    ),
    EvidenceRequirement(
        "secure_ipc",
        ("ipc/stage6_ipc_pardus.json",),
        "Unix-domain-socket IPC and authorization verification.",
    ),
    EvidenceRequirement(
        "gui_ipc",
        ("gui/stage7_gui_ipc_pardus.json",),
        "GUI projection through the official IPC API.",
    ),
    EvidenceRequirement(
        "fanotify_root",
        ("fanotify/stage8_1_fanotify_root_pardus.json",),
        "Real root/kernel fanotify verification on Pardus.",
    ),
    EvidenceRequirement(
        "ebpf_root",
        ("ebpf/stage9_2_1_ebpf_root_pardus.json",),
        "Real BCC/eBPF process, file, rename and network telemetry.",
    ),
    EvidenceRequirement(
        "runtime_correlation",
        ("correlation/stage10_correlation_pardus.json",),
        "Pre-execution/runtime correlation and evolving score.",
    ),
    EvidenceRequirement(
        "response_engine",
        ("response/stage11_response_pardus.json",),
        "Authorized response-engine verification.",
    ),
    EvidenceRequirement(
        "audit_logging",
        ("audit/stage12_audit_pardus.json",),
        "Structured tamper-evident audit logging verification.",
    ),
    EvidenceRequirement(
        "installed_system",
        (
            "installation/stage15_installation_pardus.json",
            "installation/stage13_1_installation_pardus.json",
            "installation/stage13_installation_pardus.json",
        ),
        "Installed systemd service and production-path verification.",
    ),
    EvidenceRequirement(
        "coverage",
        ("integration/stage15_coverage_pardus.txt", "integration/stage14_coverage_pardus.txt"),
        "Final pytest coverage report.",
        require_ok_status=False,
    ),
    EvidenceRequirement(
        "safe_integrated_workflow",
        (
            "integration/stage15_safe_integrated_workflow_pardus.json",
            "integration/stage14_safe_integrated_workflow_pardus.json",
            "integration/stage14_1_safe_integrated_workflow_pardus.json",
        ),
        "Safe non-root integrated workflow.",
    ),
    EvidenceRequirement(
        "installed_integrated_workflow",
        (
            "integration/stage15_installed_workflow_pardus.json",
            "integration/stage14_1_installed_workflow_pardus.json",
            "integration/stage14_installed_workflow_pardus.json",
        ),
        "Installed fanotify/eBPF/correlation/GUI/audit workflow.",
    ),
)


@dataclass(slots=True)
class RequirementResult:
    key: str
    description: str
    critical: bool
    status: str
    path: str | None
    detail: str | None = None


@dataclass(slots=True)
class EvidenceFile:
    path: str
    size_bytes: int
    sha256: str
    mode: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_project_version(project_root: Path) -> str:
    with (project_root / "pyproject.toml").open("rb") as stream:
        return str(tomllib.load(stream)["project"]["version"])


def _git_commit(project_root: Path) -> str | None:
    completed = subprocess.run(
        ["git", "-C", str(project_root), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=False,
    )
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and len(value) == 40 else None


def _os_release() -> dict[str, str]:
    path = Path("/etc/os-release")
    if not path.exists():
        return {}
    result: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        result[key] = value.strip().strip('"')
    return result


def environment_record(project_root: Path) -> dict[str, Any]:
    effective_uid = os.geteuid() if hasattr(os, "geteuid") else None
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "project": "ELYRA",
        "project_version": _read_project_version(project_root),
        "git_commit": _git_commit(project_root),
        "pardus": _os_release(),
        "kernel": platform.release(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "effective_uid": effective_uid,
        "identity_model": "POSIX_UID" if effective_uid is not None else "WINDOWS_ACCESS_TOKEN",
        "safety_boundary": (
            "No malware was downloaded or executed by the finalization tool; "
            "the manifest inventories existing evidence only."
        ),
    }


def _atomic_write_text(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(mode)
    os.replace(temporary, path)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    _atomic_write_text(
        path,
        json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
    )


def _validate_json_status(path: Path) -> tuple[bool, str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return False, f"invalid JSON: {exc}"
    status = payload.get("overall_status")
    if status != "OK":
        return False, f"overall_status is {status!r}, expected 'OK'"
    return True, "overall_status is OK"


def _resolve_requirement(evidence_root: Path, requirement: EvidenceRequirement) -> RequirementResult:
    for relative in requirement.patterns:
        candidate = evidence_root / relative
        try:
            if candidate.is_symlink():
                return RequirementResult(
                    requirement.key,
                    requirement.description,
                    requirement.critical,
                    "FAIL",
                    relative,
                    "symbolic-link evidence is rejected",
                )
            if not candidate.is_file():
                continue
            if candidate.stat().st_size <= 0:
                return RequirementResult(
                    requirement.key,
                    requirement.description,
                    requirement.critical,
                    "FAIL",
                    relative,
                    "file is empty",
                )
            if requirement.require_ok_status and candidate.suffix.lower() == ".json":
                valid, detail = _validate_json_status(candidate)
                return RequirementResult(
                    requirement.key,
                    requirement.description,
                    requirement.critical,
                    "OK" if valid else "FAIL",
                    relative,
                    detail,
                )
            return RequirementResult(
                requirement.key,
                requirement.description,
                requirement.critical,
                "OK",
                relative,
                "file exists and is non-empty",
            )
        except OSError as exc:
            return RequirementResult(
                requirement.key,
                requirement.description,
                requirement.critical,
                "FAIL",
                relative,
                str(exc),
            )
    return RequirementResult(
        requirement.key,
        requirement.description,
        requirement.critical,
        "MISSING",
        None,
        "none of the accepted paths exists",
    )


def _iter_evidence_files(evidence_root: Path) -> Iterable[Path]:
    for path in sorted(evidence_root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(evidence_root)
        if relative.parts and relative.parts[0] == "submission":
            continue
        yield path


def collect_submission_report(project_root: str | os.PathLike[str]) -> dict[str, Any]:
    root = Path(project_root).resolve()
    evidence_root = root / "evidence"
    if not evidence_root.is_dir():
        raise FileNotFoundError(f"evidence directory not found: {evidence_root}")

    requirement_results = [
        _resolve_requirement(evidence_root, requirement) for requirement in REQUIREMENTS
    ]
    files: list[EvidenceFile] = []
    inventory_errors: list[str] = []
    for path in _iter_evidence_files(evidence_root):
        relative = path.relative_to(evidence_root).as_posix()
        try:
            stat_result = path.stat()
            files.append(
                EvidenceFile(
                    path=relative,
                    size_bytes=stat_result.st_size,
                    sha256=_sha256(path),
                    mode=f"0{stat_result.st_mode & 0o777:03o}",
                )
            )
        except OSError as exc:
            inventory_errors.append(f"{relative}: {exc}")

    critical_failures = [
        result.key
        for result in requirement_results
        if result.critical and result.status != "OK"
    ]
    overall_status = "COMPLETE" if not critical_failures and not inventory_errors else "INCOMPLETE"
    screenshots = [item.path for item in files if item.path.lower().endswith(".png")]

    return {
        "schema_version": "1.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "project": "ELYRA",
        "project_version": _read_project_version(root),
        "environment": environment_record(root),
        "requirements": [asdict(item) for item in requirement_results],
        "inventory": [asdict(item) for item in files],
        "inventory_errors": inventory_errors,
        "summary": {
            "critical_requirement_count": sum(1 for item in requirement_results if item.critical),
            "critical_failures": critical_failures,
            "evidence_file_count": len(files),
            "screenshot_count": len(screenshots),
            "screenshot_evidence_present": bool(screenshots),
        },
        "overall_status": overall_status,
        "limitations": [
            "The manifest proves the presence and hashes of retained evidence; it does not independently replay every test.",
            "A SHA-256 manifest is tamper-evident only while a trusted copy of the manifest or its hash is retained separately.",
            "Controlled live-malware validation is not included and requires separate written authorization and laboratory controls.",
        ],
    }


def _status_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ELYRA Final Submission Status",
        "",
        f"- Generated: `{report['timestamp_utc']}`",
        f"- Version: `{report['project_version']}`",
        f"- Overall status: **{report['overall_status']}**",
        f"- Evidence files: **{report['summary']['evidence_file_count']}**",
        f"- Screenshots: **{report['summary']['screenshot_count']}**",
        "",
        "## Required evidence",
        "",
        "| Requirement | Status | File | Detail |",
        "|---|---|---|---|",
    ]
    for item in report["requirements"]:
        lines.append(
            "| {key} | {status} | {path} | {detail} |".format(
                key=item["key"],
                status=item["status"],
                path=item["path"] or "—",
                detail=(item["detail"] or "").replace("|", "\\|"),
            )
        )
    lines.extend(
        [
            "",
            "## Boundary",
            "",
            "This status file inventories existing evidence. It does not authorize or perform real-malware testing.",
            "",
        ]
    )
    return "\n".join(lines)


def finalize_submission(
    project_root: str | os.PathLike[str],
    *,
    strict: bool = False,
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    environment_path = root / "evidence/environment/final_environment_pardus.json"
    _atomic_write_json(environment_path, environment_record(root))

    report = collect_submission_report(root)
    output_dir = root / "evidence/submission"
    output_dir.mkdir(parents=True, exist_ok=True)
    _atomic_write_json(output_dir / "final_manifest.json", report)
    _atomic_write_text(output_dir / "FINAL_STATUS.md", _status_markdown(report))

    checksum_lines = [
        f"{item['sha256']}  evidence/{item['path']}" for item in report["inventory"]
    ]
    _atomic_write_text(
        output_dir / "final_checksums.sha256",
        "\n".join(checksum_lines) + ("\n" if checksum_lines else ""),
    )
    inventory_lines = [
        f"{item['size_bytes']:>12}  {item['mode']}  evidence/{item['path']}"
        for item in report["inventory"]
    ]
    _atomic_write_text(
        output_dir / "final_inventory.txt",
        "\n".join(inventory_lines) + ("\n" if inventory_lines else ""),
    )
    if strict and report["overall_status"] != "COMPLETE":
        raise RuntimeError(
            "submission evidence is incomplete: "
            + ", ".join(report["summary"]["critical_failures"])
        )
    return report


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = finalize_submission(args.project_root, strict=args.strict)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"final_submission: FAIL — {exc}")
        raise SystemExit(1) from exc
    for item in report["requirements"]:
        print(f"{item['key']}: {item['status']}")
    print(f"evidence_files: {report['summary']['evidence_file_count']}")
    print(f"screenshots: {report['summary']['screenshot_count']}")
    print(f"overall_status: {report['overall_status']}")
    if args.strict and report["overall_status"] != "COMPLETE":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
