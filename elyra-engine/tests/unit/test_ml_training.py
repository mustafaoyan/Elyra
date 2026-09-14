from elyra.ai.evaluation import evaluate_binary_predictions
from elyra.ai.training import train_linear_baseline


def test_training_returns_disabled_experiment_manifest():
    manifest = train_linear_baseline([(0.0, 0.0), (1.0, 1.0)], [False, True], epochs=5)
    assert manifest["feature_schema"] == "elyra.features.v1"
    assert manifest["enabled"] is False
    assert len(manifest["weights"]) == 2


def test_binary_evaluation_reports_metrics_without_claiming_probability():
    result = evaluate_binary_predictions([True, False, True], [True, False, False])
    assert result["sample_count"] == 3
    assert result["recall"] == 0.5
    assert result["false_positive_rate"] == 0.0
