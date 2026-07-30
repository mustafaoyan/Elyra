from __future__ import annotations

import random
from pathlib import Path

from elliot.analyzer.pre_execution import PreExecutionAnalyzer


def test_high_entropy_alone_does_not_produce_deny(tmp_path: Path) -> None:
    target = tmp_path / "legitimate-encrypted-like.bin"
    target.write_bytes(random.Random(2026).randbytes(32 * 1024))
    analyzer = PreExecutionAnalyzer(timeout=5.0)
    try:
        result = analyzer.analyze_file(str(target))
    finally:
        analyzer.close()

    assert result["decision"] != "DENY"
    assert result["score"] <= 41
    assert result["category_scores"]["static"] == 0
    assert result["policy_status"] == "PROVISIONAL_NOT_CALIBRATED"


def test_missing_file_uses_controlled_fail_open_output(tmp_path: Path) -> None:
    analyzer = PreExecutionAnalyzer(timeout=5.0)
    try:
        result = analyzer.analyze_file(str(tmp_path / "missing.bin"))
    finally:
        analyzer.close()

    assert result["decision"] == "ALLOW_MONITOR"
    assert result["error"] == "scan_error"
    assert result["scoring_status"] == "DEGRADED"
    assert result["indicators"][0]["rule"] == "STATIC_ANALYSIS_INCOMPLETE"
    assert result["indicators"][0]["evidence"] == ["FILE_NOT_FOUND"]


def test_async_timeout_returns_structured_degraded_result(
    monkeypatch,
) -> None:
    import time

    analyzer = PreExecutionAnalyzer(timeout=0.001)

    def slow_analysis(filepath: str) -> dict[str, object]:
        time.sleep(0.02)
        return {"filepath": filepath}

    monkeypatch.setattr(analyzer, "analyze_file", slow_analysis)
    try:
        result = analyzer.analyze_file_async("harmless-timeout-fixture")
    finally:
        analyzer.close()

    assert result["decision"] == "ALLOW_MONITOR"
    assert result["scoring_status"] == "DEGRADED"
    assert result["error"] == "timeout"
    assert result["indicators"][0]["rule"] == "ANALYSIS_TIMEOUT_FAIL_OPEN"


def test_async_controlled_exception_returns_structured_degraded_result(
    monkeypatch,
) -> None:
    analyzer = PreExecutionAnalyzer(timeout=1.0)

    def failed_analysis(filepath: str) -> dict[str, object]:
        raise ValueError(f"controlled test failure: {filepath}")

    monkeypatch.setattr(analyzer, "analyze_file", failed_analysis)
    try:
        result = analyzer.analyze_file_async("harmless-error-fixture")
    finally:
        analyzer.close()

    assert result["decision"] == "ALLOW_MONITOR"
    assert result["scoring_status"] == "DEGRADED"
    assert result["error"] == "exception"
    assert result["indicators"][0]["rule"] == "ANALYSIS_ERROR_FAIL_OPEN"
