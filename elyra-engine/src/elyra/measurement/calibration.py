"""Offline threshold calibration; never mutates the runtime policy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class CalibrationRecord:
    score: int
    label: bool


def calibrate_deny_threshold(records: Iterable[CalibrationRecord], *, max_false_positive_rate: float = 0.01) -> dict[str, float | int | str | None]:
    """Return a measured threshold recommendation under an explicit FPR target."""
    if not 0 <= max_false_positive_rate <= 1:
        raise ValueError("max_false_positive_rate must be between 0 and 1")
    items = list(records)
    if not items:
        return {"status": "INSUFFICIENT_DATA", "threshold": None, "sample_count": 0}
    if any(not 0 <= item.score <= 100 for item in items):
        raise ValueError("scores must be in the range 0..100")
    negatives = sum(not item.label for item in items)
    positives = sum(item.label for item in items)
    if not negatives or not positives:
        return {"status": "INSUFFICIENT_CLASS_COVERAGE", "threshold": None, "sample_count": len(items)}
    feasible: list[tuple[float, float, int]] = []
    for threshold in sorted({item.score for item in items}):
        tp = sum(item.label and item.score >= threshold for item in items)
        fp = sum((not item.label) and item.score >= threshold for item in items)
        fpr = fp / negatives
        recall = tp / positives
        if fpr <= max_false_positive_rate:
            feasible.append((recall, fpr, threshold))
    if not feasible:
        return {"status": "NO_THRESHOLD_MEETS_TARGET", "threshold": None, "sample_count": len(items)}
    recall, fpr, threshold = max(feasible, key=lambda candidate: (candidate[0], -candidate[2]))
    return {"status": "RECOMMENDATION_ONLY", "threshold": threshold, "false_positive_rate": fpr, "recall": recall, "target_false_positive_rate": max_false_positive_rate, "sample_count": len(items), "policy_mutated": False}
