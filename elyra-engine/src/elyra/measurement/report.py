"""Versioned evaluation report assembly."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from .dataset import manifest_digest, validate_manifest
from .metrics import EvaluationRecord, evaluate_records


def build_evaluation_report(
    records: Iterable[EvaluationRecord],
    manifest_records: Iterable[Mapping[str, Any]],
    *,
    dataset_version: str,
) -> dict[str, Any]:
    """Build a reproducible report; never labels unlabelled samples as clean."""

    manifest = validate_manifest(manifest_records)
    return {
        "schema_version": "elyra.evaluation.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_version": dataset_version,
        "manifest_sha256": manifest_digest(manifest),
        "sample_manifest_count": len(manifest),
        "metrics": evaluate_records(records),
        "claims": {
            "detection_rate": None,
            "generalizes_to_zero_day": False,
            "production_threshold_changed": False,
        },
    }
