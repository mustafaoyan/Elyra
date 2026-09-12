#!/usr/bin/env python3
"""Run ELYRA's safe Linux capacity contract and write assertion evidence.

This runner never downloads or executes malware.  It first asserts the
portable entropy and kernel-header recovery contracts using disposable staged
directories.  With ``--live`` it additionally invokes the repository's
isolated root-only fanotify and eBPF verifiers, which exercise only temporary
files, a copy of ``/bin/true``, and loopback network activity.

"Full capacity" here means that every named capability assertion passed on the
current host; it is not a fabricated throughput percentage.  A lack of a
kernel feature is reported as unavailable, not as a pass.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from elyra.analyzer.entropy import EntropyEngine
from elyra.monitor.ebpf.kernel_headers import (
    VirtualizationInfo,
    assess_kernel_headers,
    plan_kernel_header_resolution,
)


@dataclass(frozen=True, slots=True)
class AssertionResult:
    name: str
    status: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _result(name: str, ok: bool, detail: str) -> AssertionResult:
    return AssertionResult(name, "PASS" if ok else "FAIL", detail)


def _make_header_tree(source_root: Path, release: str) -> Path:
    root = source_root / f"linux-headers-{release}"
    (root / "include" / "generated").mkdir(parents=True)
    (root / "Makefile").write_text("all:\n", encoding="utf-8")
    (root / "include" / "generated" / "utsrelease.h").write_text(
        f'#define UTS_RELEASE "{release}"\n', encoding="utf-8"
    )
    return root


def run_portable_assertions() -> list[AssertionResult]:
    """Exercise recovery edge cases without changing host kernel state."""

    results: list[AssertionResult] = []
    with tempfile.TemporaryDirectory(prefix="elyra-capacity-") as directory:
        root = Path(directory)
        entropy_engine = EntropyEngine()
        low = root / "low-entropy.bin"
        high = root / "high-entropy.bin"
        low.write_bytes(b"\x00" * 16384)
        high.write_bytes(bytes(range(256)) * 64)
        low_report = entropy_engine.analyze(low)
        high_report = entropy_engine.analyze(high)
        results.append(
            _result(
                "entropy_detects_low_signal_fixture",
                low_report.whole_file_entropy <= 0.01,
                f"whole_file_entropy={low_report.whole_file_entropy}",
            )
        )
        results.append(
            _result(
                "entropy_detects_high_signal_fixture",
                high_report.whole_file_entropy >= 7.99,
                f"whole_file_entropy={high_report.whole_file_entropy}",
            )
        )

        module_root = root / "lib" / "modules"
        source_root = root / "usr" / "src"
        release = "6.12.0-elyra-vm"
        stale = _make_header_tree(source_root, "6.11.0-host")
        module_directory = module_root / release
        module_directory.mkdir(parents=True)
        shutil.copytree(stale, module_directory / "build")
        mismatch = assess_kernel_headers(
            kernel_release=release,
            module_root=module_root,
            source_root=source_root,
            system_name="Linux",
            virtualization=VirtualizationInfo(True, "VIRTUALBOX"),
        )
        results.append(
            _result(
                "virtual_machine_stale_header_link_is_detected",
                mismatch.status == "MISMATCH"
                and "BUILD_HEADERS_DO_NOT_MATCH_RUNNING_KERNEL" in mismatch.issues,
                f"status={mismatch.status}; issues={','.join(mismatch.issues)}",
            )
        )

        shutil.rmtree(module_directory / "build")
        exact = _make_header_tree(source_root, release)
        missing = assess_kernel_headers(
            kernel_release=release,
            module_root=module_root,
            source_root=source_root,
            system_name="Linux",
            virtualization=VirtualizationInfo(True, "VIRTUALBOX"),
        )
        plan = plan_kernel_header_resolution(
            missing, source_root=source_root, package_manager="apt-get"
        )
        action = plan.actions[0] if plan.actions else None
        results.append(
            _result(
                "exact_local_header_tree_generates_safe_link_repair",
                bool(action)
                and action.kind == "CONFIGURE_BUILD_LINK"
                and action.source_path is not None
                and action.target_path is not None,
                action.summary if action else "no repair action generated",
            )
        )
    return results


def _run_live_verifier(name: str, script: Path, output: Path, timeout: int) -> AssertionResult:
    environment = os.environ.copy()
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(SRC_ROOT) + (os.pathsep + existing if existing else "")
    try:
        completed = subprocess.run(
            [sys.executable, str(script), "--output", str(output), "--timeout", str(timeout)]
            if script.name == "verify_ebpf_pardus.py"
            else [sys.executable, str(script), "--output", str(output)],
            cwd=PROJECT_ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=max(timeout + 20, 30),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return AssertionResult(name, "FAIL", f"verifier launch failed: {type(exc).__name__}: {exc}")
    try:
        evidence = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        evidence = {}
    verified = completed.returncode == 0 and evidence.get("overall_status") == "OK"
    detail = (
        f"returncode={completed.returncode}; evidence={evidence.get('overall_status', 'missing')}; "
        f"stdout={completed.stdout[-500:].strip()}"
    )
    return _result(name, verified, detail)


def run_live_assertions(output_directory: Path, timeout: int) -> list[AssertionResult]:
    if platform.system() != "Linux":
        return [AssertionResult("linux_live_capability", "UNAVAILABLE", "current host is not Linux")]
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return [AssertionResult("linux_live_capability", "UNAVAILABLE", "root or CAP_SYS_ADMIN is required")]
    assessment = assess_kernel_headers()
    if not assessment.ready:
        return [
            AssertionResult(
                "running_kernel_headers_ready",
                "UNAVAILABLE",
                f"status={assessment.status}; run scripts/resolve_kernel_headers.py for a dry-run repair plan",
            )
        ]
    return [
        _run_live_verifier(
            "ebpf_real_kernel_telemetry",
            PROJECT_ROOT / "scripts" / "verify_ebpf_pardus.py",
            output_directory / "ebpf.json",
            timeout,
        ),
        _run_live_verifier(
            "fanotify_pre_execution_liveness",
            PROJECT_ROOT / "scripts" / "verify_fanotify_pardus.py",
            output_directory / "fanotify.json",
            timeout,
        ),
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("evidence/capacity/linux_capacity.json"))
    parser.add_argument("--live", action="store_true", help="run root-only harmless kernel verifiers")
    parser.add_argument("--timeout", type=int, default=12, help="eBPF verifier event timeout in seconds")
    args = parser.parse_args(argv)
    if args.timeout < 2 or args.timeout > 60:
        parser.error("--timeout must be from 2 to 60 seconds")

    started = time.time()
    results = run_portable_assertions()
    live_output = args.output.parent / "live"
    if args.live:
        results.extend(run_live_assertions(live_output, args.timeout))
    portable_ok = all(result.status == "PASS" for result in results[:4])
    live_results = results[4:]
    live_ok = bool(live_results) and all(result.status == "PASS" for result in live_results)
    if args.live:
        overall = "FULL_CAPACITY_READY" if portable_ok and live_ok else "NOT_READY"
    else:
        overall = "PORTABLE_CONTRACT_READY" if portable_ok else "NOT_READY"
    payload = {
        "schema_version": 1,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(),
        "live_verification_requested": args.live,
        "assertions": [result.to_dict() for result in results],
        "overall_status": overall,
        "elapsed_seconds": round(time.time() - started, 3),
        "safety": "harmless fixtures only; no malware downloaded or executed",
    }
    _write_json(args.output, payload)
    for result in results:
        print(f"[{result.status}] {result.name}: {result.detail}")
    print(f"overall_status: {overall}")
    print(f"evidence: {args.output}")
    return 0 if overall in {"PORTABLE_CONTRACT_READY", "FULL_CAPACITY_READY"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
