#!/usr/bin/env python3
"""Safe Stage 11 response-engine demonstration.

Only harmless temporary files and copied system utilities are used.  The script
never targets an unrelated process or persistent user file and does not require
root privileges.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from elliot.audit.audit_logger import AuditLogger
from elliot.response.engine import ResponseEngine, ResponsePolicy
from elliot.response.quarantine_manager import QuarantineManager


def _state(
    correlation_id: str,
    action: str,
    *,
    pid: int = 0,
    path: str | None = None,
    score: int = 0,
    status: str = "ACTIVE",
) -> dict:
    return {
        "correlation_id": correlation_id,
        "pid": pid,
        "tgid": pid,
        "status": status,
        "executable_path": path,
        "combined_score": score,
        "recommended_action": action,
        "pre_execution_indicators": [
            {"rule": "SAFE_DEMO_PRE_EXEC", "weight": min(score, 20)}
        ],
        "runtime_indicators": [
            {"rule": "SAFE_DEMO_RUNTIME", "weight": max(0, score - 20)}
        ],
    }


def _record(results: list[dict], scenario: str, ok: bool, **details: object) -> None:
    entry = {"scenario": scenario, "status": "OK" if ok else "FAIL", **details}
    results.append(entry)
    print(f"{scenario}: {entry['status']}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="elliot-stage11-") as directory:
        root = Path(directory)
        audit = AuditLogger(log_dir=str(root / "audit"))
        quarantine = QuarantineManager(
            quarantine_dir=root / "protected" / "quarantine",
            metadata_dir=root / "protected" / "metadata",
            audit_log=audit,
        )
        events: list[dict] = []
        policy = ResponsePolicy.load().with_runtime_actions(True)
        engine = ResponseEngine(
            quarantine,
            audit_logger=audit,
            policy=policy,
            event_sink=events.append,
        )

        allow = engine.execute_recommendation(_state("demo-allow", "ALLOW"))
        _record(results, "allow_action", allow.status == "SUCCEEDED", result=allow.to_dict())

        monitor = engine.execute_recommendation(
            _state("demo-monitor", "CONTINUE_MONITORING", score=10)
        )
        _record(
            results,
            "allow_monitor_action",
            monitor.status == "SUCCEEDED" and monitor.executed_action == "ALLOW_MONITOR",
            result=monitor.to_dict(),
        )

        warning = engine.execute_recommendation(_state("demo-warn", "ALERT", score=50))
        _record(
            results,
            "warn_action",
            warning.status == "SUCCEEDED" and bool(events),
            result=warning.to_dict(),
        )

        deny = engine.execute_recommendation(
            _state(
                "demo-deny",
                "DENY",
                score=100,
                status="DENIED_PRE_EXECUTION",
            )
        )
        _record(
            results,
            "fanotify_deny_acknowledged",
            deny.status == "SUCCEEDED",
            result=deny.to_dict(),
        )

        sleep_source = shutil.which("sleep")
        if sleep_source is None:
            raise RuntimeError("the harmless 'sleep' utility is unavailable")

        terminate_exec = root / "terminate-safe-sleep"
        shutil.copy2(sleep_source, terminate_exec)
        terminate_exec.chmod(0o755)
        process = subprocess.Popen([str(terminate_exec), "30"])
        terminate_state = _state(
            "demo-terminate",
            "TERMINATE",
            pid=process.pid,
            path=str(terminate_exec),
            score=75,
        )
        engine.bind_state(terminate_state)
        terminate = engine.execute_recommendation(terminate_state)
        process.wait(timeout=3)
        _record(
            results,
            "pidfd_terminate_harmless_child",
            terminate.status == "SUCCEEDED" and process.returncode is not None,
            returncode=process.returncode,
            result=terminate.to_dict(),
        )

        quarantine_exec = root / "quarantine-safe-sleep"
        shutil.copy2(sleep_source, quarantine_exec)
        quarantine_exec.chmod(0o755)
        process2 = subprocess.Popen([str(quarantine_exec), "30"])
        quarantine_state = _state(
            "demo-quarantine",
            "QUARANTINE",
            pid=process2.pid,
            path=str(quarantine_exec),
            score=95,
        )
        engine.bind_state(quarantine_state)
        quarantined = engine.execute_recommendation(quarantine_state)
        process2.wait(timeout=3)
        quarantine_record = quarantined.details.get("quarantine_record", {})
        quarantined_ok = (
            quarantined.status == "SUCCEEDED"
            and not quarantine_exec.exists()
            and bool(quarantine_record.get("quarantine_id"))
        )
        _record(
            results,
            "terminate_then_quarantine_harmless_copy",
            quarantined_ok,
            returncode=process2.returncode,
            result=quarantined.to_dict(),
        )

        restored_ok = False
        restore_result_dict: dict = {}
        if quarantined_ok:
            restored, restore_result = engine.restore(
                str(quarantine_record["quarantine_id"]),
                None,
                actor="safe-stage11-demonstration",
                requester_pid=os.getpid(),
            )
            restored_ok = (
                restore_result.status == "SUCCEEDED"
                and quarantine_exec.exists()
                and restored.restoration_status == "restored"
            )
            restore_result_dict = restore_result.to_dict()
        _record(
            results,
            "authorised_safe_restore",
            restored_ok,
            result=restore_result_dict,
        )

        replacement = root / "replacement-safe.bin"
        replacement.write_bytes(b"same harmless bytes")
        replacement_state = _state(
            "demo-replacement",
            "QUARANTINE",
            path=str(replacement),
            score=95,
        )
        engine.bind_state(replacement_state)
        replacement.unlink()
        replacement.write_bytes(b"same harmless bytes")
        refused = engine.execute_recommendation(replacement_state)
        _record(
            results,
            "path_replacement_refused",
            refused.status == "REFUSED" and replacement.exists(),
            result=refused.to_dict(),
        )

        chain_ok, audit_count = audit.verify_chain()
        _record(
            results,
            "all_actions_audited",
            chain_ok and audit_count >= 8,
            audit_record_count=audit_count,
            audit_chain_valid=chain_ok,
        )

    evidence = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "method": (
            "harmless temporary files and copied /bin/sleep only; pidfd termination; "
            "protected temporary quarantine; no malware, no root, no persistent user files"
        ),
        "policy_status": policy.policy_status,
        "automatic_runtime_actions_enabled_for_demo": True,
        "results": results,
        "overall_status": "OK" if all(item["status"] == "OK" for item in results) else "FAIL",
    }
    temporary = output.with_name(f".{output.name}.tmp")
    temporary.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    os.replace(temporary, output)
    print(f"overall_status: {evidence['overall_status']}")
    print(f"Evidence written to: {output}")
    return 0 if evidence["overall_status"] == "OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
