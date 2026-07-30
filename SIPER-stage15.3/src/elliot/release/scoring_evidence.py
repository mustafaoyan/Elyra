"""Validation helpers for reproducible Stage 4 scoring evidence.

The final submission manifest requires explicit top-level evidence status.  This
module derives that status from the actual scenario results; it never inserts an
unconditional ``OK`` marker.
"""

from __future__ import annotations

from typing import Any, Iterable

VALID_DECISIONS = {"ALLOW", "ALLOW_MONITOR", "WARN", "DENY"}


def _check(name: str, passed: bool, detail: str) -> dict[str, str]:
    return {
        "check": name,
        "status": "OK" if passed else "FAIL",
        "detail": detail,
    }


def _scenario_map(
    scenarios: Iterable[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], bool]:
    mapped: dict[str, dict[str, Any]] = {}
    duplicate = False
    for scenario in scenarios:
        name = scenario.get("name")
        if not isinstance(name, str) or not name:
            continue
        if name in mapped:
            duplicate = True
        mapped[name] = scenario
    return mapped, duplicate


def _result_is_structured(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    score = result.get("score")
    decision = result.get("decision")
    return (
        result.get("scoring_status") == "OK"
        and isinstance(score, int)
        and not isinstance(score, bool)
        and 0 <= score <= 100
        and decision in VALID_DECISIONS
        and isinstance(result.get("category_scores"), dict)
        and isinstance(result.get("indicators"), list)
    )


def validate_scoring_scenarios(scenarios: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Validate the three required Stage 4 scoring scenarios.

    The checks intentionally encode the original Stage 4 acceptance criteria:

    * ordinary harmless text is allowed;
    * entropy-only evidence is not denied;
    * combined static/context evidence can reach the denial path;
    * every scenario exposes a structured, explainable scoring result.
    """

    scenario_by_name, duplicate_names = _scenario_map(scenarios)
    required_names = {
        "ordinary_text",
        "high_entropy_only",
        "combined_evidence_deny_path",
    }
    missing = sorted(required_names - set(scenario_by_name))

    checks: list[dict[str, str]] = [
        _check(
            "required_scenarios_present_once",
            not missing and not duplicate_names,
            (
                "all three required scenarios are present with unique names"
                if not missing and not duplicate_names
                else f"missing={missing}; duplicate_names={duplicate_names}"
            ),
        )
    ]

    ordinary = scenario_by_name.get("ordinary_text", {})
    ordinary_result = ordinary.get("result") if isinstance(ordinary, dict) else None
    ordinary_allowed = (
        _result_is_structured(ordinary_result)
        and ordinary.get("scenario_type") == "SAFE_FILE_SCAN"
        and ordinary_result.get("decision") == "ALLOW"
    )
    checks.append(
        _check(
            "ordinary_text_allowed",
            ordinary_allowed,
            (
                f"decision={ordinary_result.get('decision')!r}"
                if isinstance(ordinary_result, dict)
                else "structured result is missing"
            ),
        )
    )

    entropy_only = scenario_by_name.get("high_entropy_only", {})
    entropy_result = entropy_only.get("result") if isinstance(entropy_only, dict) else None
    entropy_category_scores = (
        entropy_result.get("category_scores", {})
        if isinstance(entropy_result, dict)
        else {}
    )
    entropy_notes = (
        entropy_result.get("notes", [])
        if isinstance(entropy_result, dict)
        else []
    )
    entropy_not_denied = (
        _result_is_structured(entropy_result)
        and entropy_only.get("scenario_type") == "SAFE_FILE_SCAN"
        and entropy_result.get("decision") != "DENY"
        and entropy_category_scores.get("static") == 0
        and entropy_category_scores.get("context") == 0
        and any(
            isinstance(note, str) and note.startswith("ENTROPY_ONLY_EVIDENCE")
            for note in entropy_notes
        )
    )
    checks.append(
        _check(
            "high_entropy_alone_not_denied",
            entropy_not_denied,
            (
                "decision={decision!r}; static={static!r}; context={context!r}".format(
                    decision=(
                        entropy_result.get("decision")
                        if isinstance(entropy_result, dict)
                        else None
                    ),
                    static=entropy_category_scores.get("static"),
                    context=entropy_category_scores.get("context"),
                )
            ),
        )
    )

    combined = scenario_by_name.get("combined_evidence_deny_path", {})
    combined_result = combined.get("result") if isinstance(combined, dict) else None
    combined_denied = (
        _result_is_structured(combined_result)
        and combined.get("scenario_type") == "SYNTHETIC_SCORE_FIXTURE_NOT_A_REAL_FILE_SCAN"
        and combined_result.get("decision") == "DENY"
        and bool(combined_result.get("indicators"))
    )
    checks.append(
        _check(
            "combined_evidence_reaches_deny",
            combined_denied,
            (
                f"decision={combined_result.get('decision')!r}; "
                f"indicator_count={len(combined_result.get('indicators', []))}"
                if isinstance(combined_result, dict)
                else "structured result is missing"
            ),
        )
    )

    structured = all(
        _result_is_structured(scenario_by_name.get(name, {}).get("result"))
        for name in required_names
    )
    checks.append(
        _check(
            "all_results_structured_and_explainable",
            structured,
            "every result exposes score, decision, category scores and indicators",
        )
    )
    return checks


def overall_status_from_checks(checks: Iterable[dict[str, str]]) -> str:
    """Return ``OK`` only when every derived validation check passes."""

    materialized = list(checks)
    if materialized and all(item.get("status") == "OK" for item in materialized):
        return "OK"
    return "FAIL"
