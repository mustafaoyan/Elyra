"""Small deterministic on-device linear model boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .features import FeatureVector


class ModelUnavailable(RuntimeError):
    """Raised when a model manifest cannot safely be used."""


@dataclass(frozen=True)
class OnDeviceModel:
    model_id: str
    model_version: str
    feature_schema: str
    weights: tuple[float, ...]
    bias: float = 0.0
    enabled: bool = False

    @classmethod
    def from_manifest(cls, manifest: Mapping[str, Any]) -> "OnDeviceModel":
        if manifest.get("feature_schema") != "elyra.features.v1":
            raise ModelUnavailable("feature schema mismatch")
        weights = manifest.get("weights")
        if not isinstance(weights, list) or len(weights) != 5 or not all(isinstance(item, (int, float)) for item in weights):
            raise ModelUnavailable("model weights are missing or invalid")
        return cls(str(manifest.get("model_id", "")), str(manifest.get("model_version", "")), str(manifest["feature_schema"]), tuple(float(item) for item in weights), float(manifest.get("bias", 0.0)), bool(manifest.get("enabled", False)))

    def score(self, vector: FeatureVector) -> dict[str, Any]:
        if not self.enabled:
            return {"status": "UNAVAILABLE", "score": None, "model_id": self.model_id, "model_version": self.model_version}
        if vector.schema_version != self.feature_schema or len(vector.values) != len(self.weights):
            raise ModelUnavailable("feature vector does not match model")
        raw = self.bias + sum(weight * value for weight, value in zip(self.weights, vector.values))
        bounded = max(0.0, min(100.0, raw))
        return {"status": "OK", "score": round(bounded, 4), "model_id": self.model_id, "model_version": self.model_version, "score_is_probability": False}
