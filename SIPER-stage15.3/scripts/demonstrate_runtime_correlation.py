#!/usr/bin/env python3
"""Generate safe Stage 10 correlation evidence from synthetic records only."""

from __future__ import annotations

import argparse
import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from elliot.correlation.engine import ExecutionCorrelationEngine


class DemoClock:
    def __init__(self) -> None:
        self.value = 1000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float = 0.01) -> None:
        self.value += seconds


def fanotify(pid: int, score: int) -> dict:
    return {
        "pid": pid,
        "path": f"/tmp/elliot-stage10-safe-{pid}",
        "score": score,
        "risk_score": f"{score}/100",
        "requested_decision": "WARN" if score >= 40 else "ALLOW_MONITOR",
        "final_action": "ALLOW",
        "indicators": [
            {
                "rule": "SYNTHETIC_PRE_EXECUTION_SCORE",
                "weight": score,
                "evidence": "safe Stage 10 demonstration fixture",
            }
        ],
    }


def event(kind: str, pid: int, **extra: object) -> dict:
    base = {
        "event_type": kind,
        "pid": pid,
        "tgid": pid,
        "ppid": 1,
        "uid": 1000,
        "timestamp_ns": pid * 1000,
    }
    base.update(extra)
    return base


def run_case(engine: ExecutionCorrelationEngine, pid: int, pre_score: int, events: list[dict]) -> dict:
    engine.register_pre_execution(fanotify(pid, pre_score))
    engine.ingest_runtime_event(
        event(
            "PROCESS_EXEC",
            pid,
            executable_identifier=f"/tmp/elliot-stage10-safe-{pid}",
        )
    )
    result = engine.get_state(pid)
    for item in events:
        result = engine.ingest_runtime_event(item)["state"]
    assert result is not None
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    clock = DemoClock()
    identifiers = iter(f"demo-correlation-{index}" for index in range(1, 100))
    engine = ExecutionCorrelationEngine(clock=clock, id_factory=lambda: next(identifiers))

    cases = {
        "continue_monitoring": run_case(engine, 4101, 10, []),
        "alert": run_case(
            engine,
            4102,
            26,
            [
                event(
                    "NETWORK_CONNECT",
                    4102,
                    destination_address="127.0.0.1",
                    destination_port=8001,
                )
            ],
        ),
        "terminate": run_case(
            engine,
            4103,
            38,
            [
                event(
                    "NETWORK_CONNECT",
                    4103,
                    destination_address="127.0.0.1",
                    destination_port=8002,
                ),
                event("FILE_RENAME", 4103, executable_identifier="safe-rename-a"),
            ],
        ),
        "quarantine": run_case(
            engine,
            4104,
            60,
            [
                event(
                    "NETWORK_CONNECT",
                    4104,
                    destination_address="127.0.0.1",
                    destination_port=8003,
                ),
                event("FILE_RENAME", 4104, executable_identifier="safe-rename-b"),
            ],
        ),
    }

    # Prove parent-child linking without claiming the child was statically analysed.
    engine.register_pre_execution(fanotify(4200, 10))
    parent = engine.ingest_runtime_event(
        event("PROCESS_EXEC", 4200, executable_identifier="/tmp/elliot-stage10-safe-4200")
    )["state"]
    child = engine.ingest_runtime_event(
        event("PROCESS_EXEC", 4201, ppid=4200, executable_identifier="/bin/true")
    )["state"]

    expected = {
        "continue_monitoring": "CONTINUE_MONITORING",
        "alert": "ALERT",
        "terminate": "TERMINATE",
        "quarantine": "QUARANTINE",
    }
    results = []
    for name, state in cases.items():
        status = "OK" if state["recommended_action"] == expected[name] else "FAIL"
        results.append(
            {
                "scenario": name,
                "status": status,
                "pre_execution_score": state["pre_execution_score"],
                "runtime_score": state["runtime_score"],
                "combined_score": state["combined_score"],
                "recommended_action": state["recommended_action"],
                "action_execution_status": state["action_execution_status"],
            }
        )
        print(
            f"{name}: {status} pre={state['pre_execution_score']} "
            f"runtime={state['runtime_score']} combined={state['combined_score']} "
            f"action={state['recommended_action']}"
        )

    child_ok = child["parent_correlation_id"] == parent["correlation_id"]
    results.append(
        {
            "scenario": "parent_child_mapping",
            "status": "OK" if child_ok else "FAIL",
            "parent_correlation_id": parent["correlation_id"],
            "child_parent_correlation_id": child["parent_correlation_id"],
            "child_source": child["source"],
        }
    )
    print(f"parent_child_mapping: {'OK' if child_ok else 'FAIL'}")

    overall = "OK" if all(item["status"] == "OK" for item in results) else "FAIL"
    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "method": "synthetic fanotify and eBPF records only; no kernel hooks, termination, quarantine, network listener, or malware",
        "platform": platform.platform(),
        "policy": engine.summary(),
        "results": results,
        "overall_status": overall,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"overall_status: {overall}")
    print(f"Evidence written to: {output}")


if __name__ == "__main__":
    main()
