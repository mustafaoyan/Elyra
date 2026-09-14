"""Evaluation helpers for model predictions; no threshold mutation."""

from __future__ import annotations

from typing import Iterable


def evaluate_binary_predictions(labels: Iterable[bool], predictions: Iterable[bool]) -> dict[str, float | int | None]:
    actual = list(labels)
    predicted = list(predictions)
    if len(actual) != len(predicted) or not actual:
        raise ValueError("labels and predictions must be non-empty and equal length")
    tp = sum(a and p for a, p in zip(actual, predicted))
    tn = sum((not a) and (not p) for a, p in zip(actual, predicted))
    fp = sum((not a) and p for a, p in zip(actual, predicted))
    fn = sum(a and (not p) for a, p in zip(actual, predicted))
    return {
        "sample_count": len(actual),
        "accuracy": (tp + tn) / len(actual),
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
    }
