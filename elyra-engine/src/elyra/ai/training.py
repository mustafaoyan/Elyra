"""Small deterministic baseline trainer for local experiments only."""

from __future__ import annotations

from typing import Iterable, Sequence


def train_linear_baseline(
    samples: Iterable[Sequence[float]],
    labels: Iterable[bool],
    *,
    learning_rate: float = 0.01,
    epochs: int = 100,
) -> dict[str, object]:
    """Train a bounded linear baseline; never writes or installs a model."""

    rows = [tuple(float(value) for value in row) for row in samples]
    targets = [1.0 if label else 0.0 for label in labels]
    if not rows or len(rows) != len(targets):
        raise ValueError("samples and labels must be non-empty and have equal length")
    width = len(rows[0])
    if width == 0 or any(len(row) != width for row in rows):
        raise ValueError("all samples must have the same non-zero width")
    if epochs <= 0 or learning_rate <= 0:
        raise ValueError("learning_rate and epochs must be positive")
    weights = [0.0] * width
    bias = 0.0
    for _ in range(epochs):
        for row, target in zip(rows, targets):
            raw = bias + sum(weight * value for weight, value in zip(weights, row))
            prediction = 1.0 / (1.0 + pow(2.718281828459045, -max(-30.0, min(30.0, raw))))
            error = prediction - target
            for index, value in enumerate(row):
                weights[index] -= learning_rate * error * value
            bias -= learning_rate * error
    return {
        "model_id": "elyra-linear-baseline",
        "model_version": "0.1.0",
        "feature_schema": "elyra.features.v1",
        "weights": weights,
        "bias": bias,
        "enabled": False,
        "training_status": "EXPERIMENT_ONLY_NOT_PRODUCTION_VALIDATED",
    }
