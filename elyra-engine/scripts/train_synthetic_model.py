"""Train the Elyra linear baseline on a synthetic JSONL dataset.

This is an experiment-only command. It never enables the model for production.
The input dataset is expected to contain numeric ``elyra.features.v1`` records.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from statistics import mean, pstdev
from typing import Any

from elyra.ai.evaluation import evaluate_binary_predictions
from elyra.ai.training import train_linear_baseline

FEATURE_NAMES = (
    "whole_file_entropy",
    "high_entropy_block_ratio",
    "static_indicator_count",
    "context_indicator_count",
    "file_size_log2",
)


def _read_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("feature_schema") != "elyra.features.v1":
                raise ValueError(f"line {line_number}: unsupported feature schema")
            features = record.get("features") or {}
            if record.get("label") is None or any(features.get(name) is None for name in FEATURE_NAMES):
                continue
            values = tuple(float(features[name]) for name in FEATURE_NAMES)
            if not all(math.isfinite(value) for value in values):
                raise ValueError(f"line {line_number}: non-finite feature")
            records.append({"record": record, "values": values, "label": bool(record["label"])})
    if not records:
        raise ValueError("dataset contains no complete labelled records")
    return records


def _normalise(rows: list[tuple[float, ...]], centres: tuple[float, ...], scales: tuple[float, ...]) -> list[tuple[float, ...]]:
    return [tuple((value - centre) / scale for value, centre, scale in zip(row, centres, scales)) for row in rows]


def _sigmoid(value: float) -> float:
    bounded = max(-30.0, min(30.0, value))
    return 1.0 / (1.0 + math.exp(-bounded))


def _evaluate(model: dict[str, Any], rows: list[tuple[float, ...]], labels: list[bool], centres: tuple[float, ...], scales: tuple[float, ...]) -> dict[str, Any]:
    normalised = _normalise(rows, centres, scales)
    probabilities = [_sigmoid(model["bias"] + sum(w * x for w, x in zip(model["weights"], row))) for row in normalised]
    predictions = [probability >= 0.5 for probability in probabilities]
    metrics = evaluate_binary_predictions(labels, predictions)
    metrics["mean_predicted_risk"] = round(mean(probabilities), 6)
    return metrics


def train(input_path: Path, output_path: Path, report_path: Path) -> None:
    records = _read_records(input_path)
    by_split = {split: [item for item in records if item["record"].get("split") == split] for split in ("train", "validation", "test")}
    if any(not by_split[split] for split in ("train", "validation", "test")):
        raise ValueError("train, validation, and test splits must all contain labelled records")

    train_rows = [item["values"] for item in by_split["train"]]
    train_labels = [item["label"] for item in by_split["train"]]
    centres = tuple(mean(row[index] for row in train_rows) for index in range(len(FEATURE_NAMES)))
    scales = tuple(max(pstdev(row[index] for row in train_rows), 1e-9) for index in range(len(FEATURE_NAMES)))
    normalised_train = _normalise(train_rows, centres, scales)
    normalised_model = train_linear_baseline(normalised_train, train_labels, learning_rate=0.01, epochs=200)

    # Convert standardised weights back to the raw feature space used at runtime.
    raw_weights = [weight / scale for weight, scale in zip(normalised_model["weights"], scales)]
    raw_bias = normalised_model["bias"] - sum(weight * centre / scale for weight, centre, scale in zip(normalised_model["weights"], centres, scales))
    model = {
        "model_id": "elyra-linear-synthetic-v1",
        "model_version": "0.1.0-synthetic",
        "feature_schema": "elyra.features.v1",
        "weights": [round(value, 10) for value in raw_weights],
        "bias": round(raw_bias, 10),
        "enabled": False,
        "training_status": "EXPERIMENT_ONLY_NOT_PRODUCTION_VALIDATED",
        "training_data": input_path.name,
        "normalisation": {"centres": list(centres), "scales": list(scales)},
    }

    metrics = {
        split: _evaluate(normalised_model, [item["values"] for item in by_split[split]], [item["label"] for item in by_split[split]], centres, scales)
        for split in ("train", "validation", "test")
    }
    report = {
        "model": {key: value for key, value in model.items() if key not in {"weights", "bias"}},
        "input_record_count": len(records),
        "labelled_split_counts": {split: len(by_split[split]) for split in by_split},
        "metrics": metrics,
        "safety": {"real_malware_used": False, "model_enabled": False},
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(model, indent=2) + "\n", encoding="utf-8")
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="synthetic_samples.jsonl")
    parser.add_argument("--output", type=Path, default=Path("elyra.ai/models/artifacts/elyra-linear-synthetic-v1.json"))
    parser.add_argument("--report", type=Path, default=Path("elyra.ai/reports/synthetic-training-v1.json"))
    args = parser.parse_args()
    train(args.input, args.output, args.report)


if __name__ == "__main__":
    main()
