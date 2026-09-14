"""Stable, bounded feature extraction from existing static evidence."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class FeatureVector:
    schema_version: str
    values: tuple[float, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "values": list(self.values)}


def features_from_scan(scan: Mapping[str, Any]) -> FeatureVector:
    """Extract exactly five finite features; missing evidence remains zero-count."""

    entropy = scan.get("entropy_summary") or {}
    whole = float(entropy.get("whole_file_entropy", 0.0) or 0.0)
    ratio = float(entropy.get("high_entropy_block_ratio", 0.0) or 0.0)
    size = max(0, int(scan.get("file_size", 0) or 0))
    values = (whole, ratio, float(len(scan.get("path_indicators") or [])), float(len(scan.get("permission_anomalies") or [])), math.log2(size + 1))
    if not all(math.isfinite(value) for value in values):
        raise ValueError("feature vector contains non-finite value")
    return FeatureVector("elyra.features.v1", values)
