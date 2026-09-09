#!/usr/bin/env python3
"""Create safe, reproducible Stage 4 scoring evidence.

No sample is executed.  Two scenarios scan harmless files.  The third scenario is
an explicitly labelled synthetic StaticScanResult used only to prove that the
provisional decision path can mathematically reach DENY.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from elliot.analyzer.static_analyzer import StaticFileScanner, StaticScanResult
from elliot.release.scoring_evidence import (
    overall_status_from_checks,
    validate_scoring_scenarios,
)
from elliot.scoring.engine import PreExecutionScoringEngine


def _scenario(
    name: str,
    scenario_type: str,
    result: dict[str, Any],
    explanation: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "scenario_type": scenario_type,
        "explanation": explanation,
        "result": result,
    }


def _synthetic_deny_fixture() -> StaticScanResult:
    scan = StaticScanResult(
        filepath="/tmp/.synthetic-stage4-fixture.txt",
        status="OK",
        mime_type="application/x-executable",
        extension=".txt",
        mime_extension_consistency="INCONSISTENT",
        expected_mime_types=["text/plain"],
    )
    scan.entropy_summary = {
        "whole_file_entropy": 8.0,
        "high_entropy_block_ratio": 1.0,
    }
    scan.elf_anomalies = ["WRITABLE_EXECUTABLE_SEGMENT:2"]
    scan.permission_anomalies = [
        "SUID_BIT_SET",
        "WORLD_WRITABLE_AND_EXECUTABLE",
    ]
    scan.permission_details = {"mode_octal": "4777"}
    scan.path_indicators = ["TEMPORARY_DIRECTORY", "HIDDEN_PATH_COMPONENT"]
    scan.path_context = {"absolute_path": scan.filepath}
    return scan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("evidence/scoring/stage4_scoring_generic_linux.json"),
    )
    args = parser.parse_args()

    scanner = StaticFileScanner()
    scorer = PreExecutionScoringEngine()
    scenarios: list[dict[str, Any]] = []

    # Use the platform temporary directory.  It works in restricted desktop
    # sessions and CI containers where a user profile may be readable but not
    # writable, while keeping all fixtures local and automatically removed.
    with tempfile.TemporaryDirectory(prefix="elliot_stage4_") as temporary_directory:
        temp = Path(temporary_directory)
        ordinary = temp / "ordinary.txt"
        ordinary.write_text("ELLIOT harmless Pardus test\n" * 100, encoding="utf-8")
        ordinary_result = scorer.score(scanner.scan(ordinary)).to_dict()
        scenarios.append(
            _scenario(
                "ordinary_text",
                "SAFE_FILE_SCAN",
                ordinary_result,
                "A harmless UTF-8 text file scanned without execution.",
            )
        )

        encrypted_like = temp / "legitimate-encrypted-like.bin"
        encrypted_like.write_bytes(random.Random(2026).randbytes(64 * 1024))
        encrypted_result = scorer.score(scanner.scan(encrypted_like)).to_dict()
        scenarios.append(
            _scenario(
                "high_entropy_only",
                "SAFE_FILE_SCAN",
                encrypted_result,
                "Deterministic synthetic bytes demonstrate that entropy-only "
                "evidence cannot produce DENY.",
            )
        )

    synthetic_result = scorer.score(_synthetic_deny_fixture()).to_dict()
    scenarios.append(
        _scenario(
            "combined_evidence_deny_path",
            "SYNTHETIC_SCORE_FIXTURE_NOT_A_REAL_FILE_SCAN",
            synthetic_result,
            "A manually constructed evidence object proves decision reachability. "
            "It is not presented as observed kernel or malware behaviour.",
        )
    )

    checks = validate_scoring_scenarios(scenarios)
    overall_status = overall_status_from_checks(checks)
    document = {
        "schema_version": "1.1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "method": "safe file scans plus one explicitly labelled synthetic score fixture",
        "policy_status": scorer.policy.policy_status,
        "scenarios": scenarios,
        "validation_checks": checks,
        "overall_status": overall_status,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    for scenario in scenarios:
        result = scenario["result"]
        print(
            f"{scenario['name']}: score={result['score']} "
            f"decision={result['decision']} type={scenario['scenario_type']}"
        )
    for check in checks:
        print(f"{check['check']}: {check['status']}")
    print(f"overall_status: {overall_status}")
    print(f"Evidence written to: {args.output}")
    return 0 if overall_status == "OK" else 1


if __name__ == "__main__":
    sys.exit(main())
