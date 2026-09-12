from __future__ import annotations

from copy import deepcopy

from elyra.release.scoring_evidence import (
    overall_status_from_checks,
    validate_scoring_scenarios,
)


def _result(
    decision: str,
    *,
    static: int = 0,
    context: int = 0,
    notes: list[str] | None = None,
) -> dict[str, object]:
    return {
        "scoring_status": "OK",
        "score": 0 if decision == "ALLOW" else 26 if decision == "ALLOW_MONITOR" else 100,
        "decision": decision,
        "category_scores": {
            "entropy": 26 if decision != "ALLOW" else 0,
            "static": static,
            "context": context,
        },
        "indicators": (
            []
            if decision != "DENY"
            else [{"rule": "SAFE_TEST_RULE", "weight": 1}]
        ),
        "notes": list(notes or []),
    }


def _scenarios() -> list[dict[str, object]]:
    return [
        {
            "name": "ordinary_text",
            "scenario_type": "SAFE_FILE_SCAN",
            "result": _result("ALLOW"),
        },
        {
            "name": "high_entropy_only",
            "scenario_type": "SAFE_FILE_SCAN",
            "result": _result(
                "ALLOW_MONITOR",
                notes=["ENTROPY_ONLY_EVIDENCE: entropy alone cannot deny"],
            ),
        },
        {
            "name": "combined_evidence_deny_path",
            "scenario_type": "SYNTHETIC_SCORE_FIXTURE_NOT_A_REAL_FILE_SCAN",
            "result": _result("DENY", static=60, context=22),
        },
    ]


def test_expected_stage4_scenarios_derive_ok_status() -> None:
    checks = validate_scoring_scenarios(_scenarios())
    assert all(item["status"] == "OK" for item in checks)
    assert overall_status_from_checks(checks) == "OK"


def test_entropy_only_deny_is_rejected() -> None:
    scenarios = deepcopy(_scenarios())
    scenarios[1]["result"]["decision"] = "DENY"
    checks = validate_scoring_scenarios(scenarios)
    item = next(x for x in checks if x["check"] == "high_entropy_alone_not_denied")
    assert item["status"] == "FAIL"
    assert overall_status_from_checks(checks) == "FAIL"


def test_combined_fixture_must_reach_deny() -> None:
    scenarios = deepcopy(_scenarios())
    scenarios[2]["result"]["decision"] = "WARN"
    checks = validate_scoring_scenarios(scenarios)
    item = next(x for x in checks if x["check"] == "combined_evidence_reaches_deny")
    assert item["status"] == "FAIL"


def test_missing_or_duplicate_scenario_is_rejected() -> None:
    scenarios = _scenarios()
    scenarios.pop()
    scenarios.append(deepcopy(scenarios[0]))
    checks = validate_scoring_scenarios(scenarios)
    item = next(x for x in checks if x["check"] == "required_scenarios_present_once")
    assert item["status"] == "FAIL"


def test_unstructured_scoring_result_is_rejected() -> None:
    scenarios = deepcopy(_scenarios())
    scenarios[0]["result"].pop("category_scores")
    checks = validate_scoring_scenarios(scenarios)
    item = next(x for x in checks if x["check"] == "all_results_structured_and_explainable")
    assert item["status"] == "FAIL"


def test_scoring_demonstration_writes_explicit_ok_schema(tmp_path) -> None:
    import json
    import os
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    output = tmp_path / "stage4_scoring.json"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(root / "src")
    completed = subprocess.run(
        [
            sys.executable,
            str(root / "scripts/demonstrate_pre_execution_scoring.py"),
            "--output",
            str(output),
        ],
        cwd=root,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "1.1"
    assert payload["overall_status"] == "OK"
    assert all(item["status"] == "OK" for item in payload["validation_checks"])
