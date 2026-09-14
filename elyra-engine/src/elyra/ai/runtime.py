"""Safe runtime boundary for optional on-device ML recommendations."""

from __future__ import annotations

from typing import Any

from .features import FeatureVector
from .model import OnDeviceModel, ModelUnavailable


def recommendation_from_model(model: OnDeviceModel, vector: FeatureVector) -> dict[str, Any]:
    """Return a non-authoritative model suggestion with deterministic fallback.

    The result never authorizes quarantine, deletion, execution blocking, or
    kernel action. Disabled, malformed, or incompatible models are explicit
    ``UNAVAILABLE`` results rather than silently trusted scores.
    """
    try:
        result = model.score(vector)
    except (ModelUnavailable, ValueError, TypeError) as exc:
        return {"schema_version": "elyra.ai.recommendation.v1", "status": "INCONCLUSIVE", "recommendation": "REVIEW", "reason": str(exc), "authoritative": False}
    if result.get("status") != "OK" or result.get("score") is None:
        return {"schema_version": "elyra.ai.recommendation.v1", "status": "UNAVAILABLE", "recommendation": "MONITOR", "authoritative": False, "model": result}
    score = float(result["score"])
    recommendation = "REVIEW" if score >= 60 else "MONITOR" if score >= 25 else "ALLOW_WITH_LOGGING"
    return {"schema_version": "elyra.ai.recommendation.v1", "status": "OK", "score": round(score, 4), "recommendation": recommendation, "authoritative": False, "model": result}
