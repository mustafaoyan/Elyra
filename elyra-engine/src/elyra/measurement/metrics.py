"""Deterministic metrics for labelled, local evaluation datasets."""

from __future__ import annotations

from dataclasses import dataclass
from statistics import mean, quantiles
from typing import Iterable


@dataclass(frozen=True)
class EvaluationRecord:
    label: bool | None
    decision: str
    latency_ms: float


def evaluate_records(records: Iterable[EvaluationRecord]) -> dict[str, float | int | None]:
    """Compute metrics without inventing labels or treating INCONCLUSIVE as clean."""

    items = list(records)
    labelled = [item for item in items if item.label is not None]
    tp = sum(item.label is True and item.decision == "DENY" for item in labelled)
    tn = sum(item.label is False and item.decision != "DENY" for item in labelled)
    fp = sum(item.label is False and item.decision == "DENY" for item in labelled)
    fn = sum(item.label is True and item.decision != "DENY" for item in labelled)
    inconclusive = sum(item.decision == "INCONCLUSIVE" for item in items)
    latencies = sorted(item.latency_ms for item in items)
    p95 = quantiles(latencies, n=20)[18] if len(latencies) >= 2 else (latencies[0] if latencies else None)
    return {
        "sample_count": len(items),
        "labelled_count": len(labelled),
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
        "inconclusive_rate": inconclusive / len(items) if items else None,
        "latency_mean_ms": mean(latencies) if latencies else None,
        "latency_p95_ms": p95,
    }
