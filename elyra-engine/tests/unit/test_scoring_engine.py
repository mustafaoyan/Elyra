from __future__ import annotations

import json
from importlib.resources import files
from pathlib import Path

import pytest

from elyra.analyzer.static_analyzer import StaticScanResult
from elyra.scoring.engine import (
    InvalidScoringConfiguration,
    PreExecutionScoringEngine,
    ScoringPolicy,
)


def _scan(**changes: object) -> StaticScanResult:
    scan = StaticScanResult(filepath="/home/user/sample.bin", status="OK")
    scan.entropy_summary = {
        "whole_file_entropy": 0.0,
        "high_entropy_block_ratio": 0.0,
    }
    for name, value in changes.items():
        setattr(scan, name, value)
    return scan


def _default_mapping() -> dict[str, object]:
    text = files("elyra.config").joinpath("scoring.default.json").read_text(
        encoding="utf-8"
    )
    value = json.loads(text)
    assert isinstance(value, dict)
    return value


def test_default_policy_is_explicitly_provisional_and_valid() -> None:
    policy = ScoringPolicy.load()

    assert policy.policy_status == "PROVISIONAL_NOT_CALIBRATED"
    assert policy.score_minimum == 0
    assert policy.score_maximum == 100
    assert set(policy.category_caps) == {"entropy", "static", "context"}


def test_high_entropy_alone_cannot_deny() -> None:
    scan = _scan(
        entropy_summary={
            "whole_file_entropy": 8.0,
            "high_entropy_block_ratio": 1.0,
        }
    )

    result = PreExecutionScoringEngine().score(scan)

    assert result.category_scores == {"entropy": 26, "static": 0, "context": 0}
    assert result.score == 26
    assert result.decision == "ALLOW_MONITOR"
    assert any("ENTROPY_ONLY_EVIDENCE" in note for note in result.notes)


def test_output_schema_exposes_every_contribution() -> None:
    scan = _scan(
        mime_extension_consistency="INCONSISTENT",
        mime_type="application/x-executable",
        extension=".txt",
        expected_mime_types=["text/plain"],
        permission_anomalies=["SUID_BIT_SET"],
        permission_details={"mode_octal": "4755"},
        path_indicators=["DOWNLOAD_DIRECTORY"],
        path_context={"absolute_path": "/home/user/Downloads/sample.txt"},
    )

    result = PreExecutionScoringEngine().score(scan).to_dict()

    assert result["score"] == 38
    assert result["decision"] == "ALLOW_MONITOR"
    assert result["category_scores"] == {
        "entropy": 0,
        "static": 30,
        "context": 8,
    }
    assert result["risk_score"] == "38/100"
    assert result["score_is_probability"] is False
    assert {item["rule"] for item in result["indicators"]} == {
        "MIME_EXTENSION_INCONSISTENT",
        "SUID_BIT_SET",
        "DOWNLOAD_DIRECTORY",
    }
    assert all(
        {"rule", "category", "weight", "evidence", "description"} <= set(item)
        for item in result["indicators"]
    )


def test_scoring_is_deterministic() -> None:
    scan = _scan(
        entropy_summary={
            "whole_file_entropy": 7.8,
            "high_entropy_block_ratio": 0.75,
        },
        elf_anomalies=["ELF_ENTRY_POINT_ZERO"],
        path_indicators=["HIDDEN_PATH_COMPONENT", "TEMPORARY_DIRECTORY"],
        path_context={"absolute_path": "/tmp/.sample"},
    )
    engine = PreExecutionScoringEngine()

    first = engine.score(scan).to_dict()
    second = engine.score(scan).to_dict()

    assert first == second


def test_combined_static_and_context_evidence_can_reach_deny() -> None:
    scan = _scan(
        entropy_summary={
            "whole_file_entropy": 8.0,
            "high_entropy_block_ratio": 1.0,
        },
        mime_extension_consistency="INCONSISTENT",
        mime_type="application/x-executable",
        extension=".txt",
        expected_mime_types=["text/plain"],
        elf_anomalies=["WRITABLE_EXECUTABLE_SEGMENT:2"],
        permission_anomalies=[
            "SUID_BIT_SET",
            "WORLD_WRITABLE",
            "WORLD_WRITABLE_AND_EXECUTABLE",
        ],
        permission_details={"mode_octal": "4777"},
        path_indicators=["TEMPORARY_DIRECTORY", "HIDDEN_PATH_COMPONENT"],
        path_context={"absolute_path": "/tmp/.sample.txt"},
    )

    result = PreExecutionScoringEngine().score(scan)

    assert result.category_scores["static"] == 60
    assert result.score == 100
    assert result.decision == "DENY"
    rules = [indicator.rule for indicator in result.indicators]
    assert "WORLD_WRITABLE_AND_EXECUTABLE" in rules
    assert "WORLD_WRITABLE" not in rules


def test_deny_gate_requires_static_evidence() -> None:
    data = _default_mapping()
    thresholds = data["decision_thresholds"]
    assert isinstance(thresholds, dict)
    thresholds["deny_min"] = 50
    data["category_caps"] = {"entropy": 30, "static": 60, "context": 40}
    policy = ScoringPolicy.from_mapping(data)
    scan = _scan(
        entropy_summary={
            "whole_file_entropy": 8.0,
            "high_entropy_block_ratio": 1.0,
        },
        path_indicators=[
            "TEMPORARY_DIRECTORY",
            "REMOVABLE_OR_MOUNTED_MEDIA",
            "HIDDEN_PATH_COMPONENT",
        ],
        path_context={"absolute_path": "/mnt/.sample"},
    )

    result = PreExecutionScoringEngine(policy).score(scan)

    assert result.score >= 50
    assert result.category_scores["static"] == 0
    assert result.decision == "WARN"
    assert any("DENY_GATE_NOT_MET" in note for note in result.notes)


def test_error_scan_returns_structured_fail_open_result() -> None:
    scan = _scan(
        status="ERROR",
        errors=[{"code": "FILE_NOT_FOUND", "message": "missing"}],
    )

    result = PreExecutionScoringEngine().score(scan).to_dict()

    assert result["score"] == 0
    assert result["decision"] == "ALLOW_MONITOR"
    assert result["scoring_status"] == "DEGRADED"
    assert result["indicators"][0]["rule"] == "STATIC_ANALYSIS_INCOMPLETE"
    assert result["indicators"][0]["evidence"] == ["FILE_NOT_FOUND"]


def test_partial_scan_is_disclosed() -> None:
    scan = _scan(
        status="PARTIAL",
        errors=[{"code": "MALFORMED_ELF", "message": "bad header"}],
    )

    result = PreExecutionScoringEngine().score(scan)

    assert result.score == 25
    assert result.decision == "ALLOW_MONITOR"
    assert any("PARTIAL_STATIC_ANALYSIS" in note for note in result.notes)


def test_policy_can_be_loaded_from_an_explicit_json_file(tmp_path: Path) -> None:
    data = _default_mapping()
    rules = data["rules"]
    assert isinstance(rules, dict)
    whole_entropy = rules["HIGH_WHOLE_FILE_ENTROPY"]
    assert isinstance(whole_entropy, dict)
    whole_entropy["weight"] = 5
    path = tmp_path / "scoring.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    engine = PreExecutionScoringEngine.from_config_file(path)
    result = engine.score(
        _scan(
            entropy_summary={
                "whole_file_entropy": 8.0,
                "high_entropy_block_ratio": 0.0,
            }
        )
    )

    assert result.score == 5


def test_invalid_threshold_order_is_rejected() -> None:
    data = _default_mapping()
    thresholds = data["decision_thresholds"]
    assert isinstance(thresholds, dict)
    thresholds["warn_min"] = 10

    with pytest.raises(InvalidScoringConfiguration):
        ScoringPolicy.from_mapping(data)


def test_invalid_json_policy_file_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{not-json", encoding="utf-8")

    with pytest.raises(InvalidScoringConfiguration):
        ScoringPolicy.load(path)
