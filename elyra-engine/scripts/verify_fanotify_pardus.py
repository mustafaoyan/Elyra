#!/usr/bin/env python3
"""Root/kernel Stage 8.1 fanotify verification for an isolated Pardus host.

Safety and liveness properties:
- no malware, downloads, network access, persistent system files, or systemd;
- only temporary copies of /bin/true and one harmless shell script;
- fanotify mark limited to one temporary directory and its direct children;
- every executable is launched from a dedicated forked child process;
- the verifier parent acts as an external watchdog and never blocks in exec();
- timed-out launchers are terminated and then killed if necessary;
- partial evidence is written after every scenario and on verifier failure;
- production mount-wide marks are not enabled by this verifier.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import queue
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable

from elyra.audit.audit_logger import AuditLogger
from elyra.monitor.fanotify.controller import FanotifyController
from elyra.monitor.fanotify.policy import FanotifyPolicy
from elyra.monitor.fanotify.syscalls import FanotifyInterface

EXEC_DENIED_EXIT_CODE = 126
EXEC_FAILED_EXIT_CODE = 125
WATCHDOG_TERMINATED_EXIT_CODE = 124


class ControlledFailureAnalyzer:
    """Return a labelled analysis failure to verify fail-open behaviour."""

    def analyze_open_fd_async(self, fd, original_path, timeout=None):
        return {
            "score": 0,
            "risk_score": "0/100",
            "decision": "ALLOW_MONITOR",
            "scoring_status": "DEGRADED",
            "indicators": [],
            "error": "timeout",
        }


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def _environment() -> dict[str, Any]:
    return {
        "platform": platform.platform(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "euid": os.geteuid(),
    }


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _build_evidence(
    results: list[dict[str, Any]],
    *,
    overall_status: str,
    reason: str | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "timestamp_utc": _utc_now(),
        "method": (
            "real FAN_OPEN_EXEC_PERM on one temporary directory; harmless fixtures only; "
            "external pre-started execution broker with forked launchers and watchdog"
        ),
        "verifier_revision": "STAGE_8_1_FORK_WATCHDOG",
        "environment": _environment(),
        "results": results,
        "overall_status": overall_status,
    }
    if reason:
        evidence["reason"] = reason
    return evidence


def _persist_progress(
    output: Path,
    results: list[dict[str, Any]],
    *,
    status: str = "IN_PROGRESS",
    reason: str | None = None,
) -> None:
    _atomic_write_json(
        output,
        _build_evidence(results, overall_status=status, reason=reason),
    )


def wait_for_records(
    event_queue: queue.Queue[dict[str, Any]],
    *,
    minimum: int,
    timeout: float = 4.0,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout
    while len(records) < minimum and time.monotonic() < deadline:
        try:
            records.append(event_queue.get(timeout=0.1))
        except queue.Empty:
            continue
    while True:
        try:
            records.append(event_queue.get_nowait())
        except queue.Empty:
            break
    return records


class ExecBroker:
    """Client for the pre-started, single-threaded execution watchdog broker."""

    def __init__(self) -> None:
        broker_path = Path(__file__).with_name("fanotify_exec_broker.py")
        self.process = subprocess.Popen(
            [sys.executable, str(broker_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.process.stdin is None or self.process.stdout is None:
            raise RuntimeError("execution broker pipes are unavailable")
        if self.process.poll() is not None:
            error = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError(f"execution broker exited early: {error[-500:]}")
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            error = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError(f"execution broker returned no response: {error[-500:]}")
        response = json.loads(line)
        if response.get("ok") is not True:
            raise RuntimeError(str(response.get("error", "execution broker failed")))
        return response

    def execute(
        self,
        path: Path,
        *,
        argv: Iterable[str] | None = None,
        timeout: float = 5.0,
    ) -> dict[str, Any]:
        response = self._request(
            {
                "action": "execute",
                "path": str(path),
                "argv": list(argv) if argv is not None else [str(path)],
                "timeout": timeout,
            }
        )
        return response["results"][0]

    def execute_many(
        self,
        path: Path,
        *,
        count: int,
        timeout: float = 6.0,
    ) -> list[dict[str, Any]]:
        response = self._request(
            {
                "action": "execute_many",
                "path": str(path),
                "count": count,
                "timeout": timeout,
            }
        )
        return response["results"]

    def close(self) -> None:
        if self.process.poll() is None:
            try:
                self._request({"action": "shutdown"})
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
                self.process.terminate()
        try:
            self.process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=2.0)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()

    def __enter__(self) -> "ExecBroker":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

def make_policy(root: Path, mode: str) -> FanotifyPolicy:
    return FanotifyPolicy(
        mode=mode,
        default_fail_policy="FAIL_OPEN",
        monitored_paths=[str(root)],
        excluded_paths=[],
        fail_closed_paths=[],
        max_response_seconds=2.5,
        max_preexec_file_bytes=128 * 1024 * 1024,
        max_pending_events=32,
        event_workers=8,
        exclude_daemon_descendants=False,
    )


def start_controller(
    root: Path,
    mode: str,
    *,
    analyzer=None,
) -> tuple[FanotifyController, queue.Queue[dict[str, Any]], AuditLogger]:
    events: queue.Queue[dict[str, Any]] = queue.Queue()
    audit = AuditLogger(str(root / f"audit-{mode.lower()}-{time.time_ns()}"))
    controller = FanotifyController(
        event_queue=events,
        interface=FanotifyInterface(mark_scope="inode"),
        policy=make_policy(root, mode),
        analyzer=analyzer,
        audit_logger=audit,
    )
    if not controller.start():
        raise RuntimeError(
            "fanotify controller did not start or no test-directory mark was added"
        )
    return controller, events, audit


def matching(records: list[dict[str, Any]], path: Path) -> list[dict[str, Any]]:
    expected = str(path)
    return [record for record in records if record.get("path") == expected]


def _append_result(
    output: Path,
    results: list[dict[str, Any]],
    result: dict[str, Any],
) -> None:
    results.append(result)
    print(f"{result['scenario']}: {result['status']}", flush=True)
    _persist_progress(output, results)


def run_verification(output: Path) -> tuple[list[dict[str, Any]], str]:
    if os.geteuid() != 0:
        raise PermissionError("this isolated verifier requires root/CAP_SYS_ADMIN")
    if not Path("/bin/true").is_file():
        raise FileNotFoundError("/bin/true is unavailable")

    results: list[dict[str, Any]] = []
    _persist_progress(output, results)

    # The broker is started before any fanotify controller creates threads.
    with ExecBroker() as broker, tempfile.TemporaryDirectory(
        prefix="elyra-stage8-1-", dir="/tmp"
    ) as temp:
        root = Path(temp)
        safe_elf = root / "safe_true"
        suspicious_elf = root / ".suspicious.txt"
        fail_open_elf = root / "safe_fail_open"
        concurrent_elf = root / "safe_concurrent"
        script = root / "safe_script.sh"

        for destination in (safe_elf, suspicious_elf, fail_open_elf, concurrent_elf):
            shutil.copy2("/bin/true", destination)
            destination.chmod(0o755)
        suspicious_elf.chmod(0o6777)
        script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        script.chmod(0o755)

        controller, events, audit = start_controller(root, "MONITOR_ONLY")
        try:
            elf_execution = broker.execute(safe_elf)
            elf_records = wait_for_records(events, minimum=1)
            script_execution = broker.execute(script)
            script_records = wait_for_records(events, minimum=1)
        finally:
            controller.stop()
        elf_match = matching(elf_records, safe_elf)
        script_match = matching(script_records, script)
        harmless_ok = (
            elf_execution["returncode"] == 0
            and not elf_execution["timed_out"]
            and bool(elf_match)
            and elf_match[-1].get("kernel_response") == "FAN_ALLOW"
        )
        _append_result(
            output,
            results,
            {
                "scenario": "harmless_elf_allowed_monitor_only",
                "status": "OK" if harmless_ok else "FAIL",
                "execution": elf_execution,
                "records": elf_match,
            },
        )
        script_ok = (
            script_execution["returncode"] == 0
            and not script_execution["timed_out"]
            and bool(script_match)
            and script_match[-1].get("executable_kind") == "SCRIPT"
            and script_match[-1].get("kernel_response") == "FAN_ALLOW"
        )
        _append_result(
            output,
            results,
            {
                "scenario": "interpreter_script_execution_observed",
                "status": "OK" if script_ok else "FAIL",
                "execution": script_execution,
                "records": script_match,
                "note": "Kernel behaviour is recorded rather than assumed.",
            },
        )

        controller, events, deny_audit = start_controller(root, "ENFORCEMENT")
        try:
            denied_execution = broker.execute(suspicious_elf)
            deny_records = wait_for_records(events, minimum=1)
        finally:
            controller.stop()
        deny_match = matching(deny_records, suspicious_elf)
        deny_ok = (
            denied_execution["denied_by_exec"]
            and not denied_execution["timed_out"]
            and bool(deny_match)
            and deny_match[-1].get("kernel_response") == "FAN_DENY"
            and deny_match[-1].get("final_action") == "DENY"
        )
        _append_result(
            output,
            results,
            {
                "scenario": "safe_suspicious_elf_denied_enforcement",
                "status": "OK" if deny_ok else "FAIL",
                "execution": denied_execution,
                "records": deny_match,
                "fixture": (
                    "copy of /bin/true with .txt name, hidden path, SUID/SGID and "
                    "world-writable/executable bits"
                ),
            },
        )

        controller, events, failure_audit = start_controller(
            root, "ENFORCEMENT", analyzer=ControlledFailureAnalyzer()
        )
        try:
            fail_open_execution = broker.execute(fail_open_elf)
            fail_open_records = wait_for_records(events, minimum=1)
        finally:
            controller.stop()
        fail_open_match = matching(fail_open_records, fail_open_elf)
        fail_open_ok = (
            fail_open_execution["returncode"] == 0
            and not fail_open_execution["timed_out"]
            and bool(fail_open_match)
            and fail_open_match[-1].get("kernel_response") == "FAN_ALLOW"
            and str(fail_open_match[-1].get("reason", "")).endswith("FAIL_OPEN")
        )
        _append_result(
            output,
            results,
            {
                "scenario": "analyser_failure_no_hang_fail_open",
                "status": "OK" if fail_open_ok else "FAIL",
                "execution": fail_open_execution,
                "records": fail_open_match,
            },
        )

        controller, events, concurrent_audit = start_controller(root, "MONITOR_ONLY")
        try:
            executions = broker.execute_many(concurrent_elf, count=8)
            concurrent_records = wait_for_records(events, minimum=8, timeout=6.0)
        finally:
            controller.stop()
        concurrent_match = matching(concurrent_records, concurrent_elf)
        concurrent_ok = (
            all(item["returncode"] == 0 and not item["timed_out"] for item in executions)
            and len(concurrent_match) >= 8
            and all(
                item.get("kernel_response") == "FAN_ALLOW"
                for item in concurrent_match
            )
        )
        _append_result(
            output,
            results,
            {
                "scenario": "concurrent_exec_events_all_responded",
                "status": "OK" if concurrent_ok else "FAIL",
                "executions": executions,
                "matching_record_count": len(concurrent_match),
            },
        )

        restart_runs: list[dict[str, Any]] = []
        restart_audits: list[AuditLogger] = []
        for run_number in (1, 2):
            controller, events, restart_audit = start_controller(root, "MONITOR_ONLY")
            restart_audits.append(restart_audit)
            try:
                execution = broker.execute(safe_elf)
                records = wait_for_records(events, minimum=1)
            finally:
                controller.stop()
            found = matching(records, safe_elf)
            restart_runs.append(
                {
                    "run": run_number,
                    "returncode": execution["returncode"],
                    "timed_out": execution["timed_out"],
                    "event_observed": bool(found),
                    "response": found[-1].get("kernel_response") if found else None,
                }
            )
        restart_ok = all(
            item["returncode"] == 0
            and not item["timed_out"]
            and item["event_observed"]
            and item["response"] == "FAN_ALLOW"
            for item in restart_runs
        )
        _append_result(
            output,
            results,
            {
                "scenario": "reproducible_after_controller_restart",
                "status": "OK" if restart_ok else "FAIL",
                "runs": restart_runs,
            },
        )

        audit_checks = {
            "monitor_chain": audit.verify_chain(),
            "deny_chain": deny_audit.verify_chain(),
            "failure_chain": failure_audit.verify_chain(),
            "concurrent_chain": concurrent_audit.verify_chain(),
            "restart_chains": [item.verify_chain() for item in restart_audits],
        }
        scalar_checks = [
            audit_checks["monitor_chain"],
            audit_checks["deny_chain"],
            audit_checks["failure_chain"],
            audit_checks["concurrent_chain"],
            *audit_checks["restart_chains"],
        ]
        audit_ok = all(valid and count > 0 for valid, count in scalar_checks)
        _append_result(
            output,
            results,
            {
                "scenario": "all_decision_sessions_audited",
                "status": "OK" if audit_ok else "FAIL",
                "chains": audit_checks,
            },
        )

    overall = "OK" if all(item["status"] == "OK" for item in results) else "FAIL"
    return results, overall



def _load_existing_results(output: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(output.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return []
    records = payload.get("results")
    return records if isinstance(records, list) else []

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    results: list[dict[str, Any]] = []
    try:
        results, overall = run_verification(output)
        _atomic_write_json(output, _build_evidence(results, overall_status=overall))
        print(f"overall_status: {overall}", flush=True)
        print(f"Evidence written to: {output}", flush=True)
        return 0 if overall == "OK" else 1
    except KeyboardInterrupt:
        results = _load_existing_results(output) or results
        reason = "verification interrupted by operator; child launchers were watchdog-managed"
        _atomic_write_json(
            output,
            _build_evidence(results, overall_status="INTERRUPTED", reason=reason),
        )
        print(f"INTERRUPTED: {reason}", flush=True)
        print(f"Evidence written to: {output}", flush=True)
        return 130
    except (OSError, RuntimeError, ValueError) as exc:
        results = _load_existing_results(output) or results
        reason = f"{type(exc).__name__}: {exc}"
        _atomic_write_json(
            output,
            _build_evidence(results, overall_status="UNAVAILABLE", reason=reason),
        )
        print(f"UNAVAILABLE: {reason}", flush=True)
        print(f"Evidence written to: {output}", flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
