import pytest

from elyra.ai.features import FeatureVector
from elyra.ai.model import ModelUnavailable, OnDeviceModel


def test_disabled_model_falls_back_without_score():
    model = OnDeviceModel.from_manifest({"model_id": "demo", "model_version": "0.1.0", "feature_schema": "elyra.features.v1", "weights": [1, 1, 1, 1, 1]})
    result = model.score(FeatureVector("elyra.features.v1", (1, 1, 1, 1, 1)))
    assert result["status"] == "UNAVAILABLE"
    assert result["score"] is None


def test_enabled_model_is_bounded_and_not_probability():
    model = OnDeviceModel.from_manifest({"model_id": "demo", "model_version": "0.1.0", "feature_schema": "elyra.features.v1", "weights": [100, 100, 100, 100, 100], "enabled": True})
    result = model.score(FeatureVector("elyra.features.v1", (1, 1, 1, 1, 1)))
    assert result["status"] == "OK"
    assert result["score"] == 100.0
    assert result["score_is_probability"] is False


def test_model_rejects_schema_mismatch():
    with pytest.raises(ModelUnavailable, match="schema"):
        OnDeviceModel.from_manifest({"model_id": "demo", "model_version": "0.1.0", "feature_schema": "other.v1", "weights": [1, 1, 1, 1, 1]})
