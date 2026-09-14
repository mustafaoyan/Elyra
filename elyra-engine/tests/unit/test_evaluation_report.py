from elyra.measurement.report import build_evaluation_report
from elyra.measurement.metrics import EvaluationRecord


def test_report_is_versioned_and_does_not_make_zero_day_claims():
    report = build_evaluation_report(
        [EvaluationRecord(True, "DENY", 2.0), EvaluationRecord(False, "ALLOW", 1.0)],
        [{"sample_id": "a", "sha256": "a" * 64, "split": "test", "label": True, "family": "f"}],
        dataset_version="2026.09.synthetic",
    )
    assert report["schema_version"] == "elyra.evaluation.v1"
    assert len(report["manifest_sha256"]) == 64
    assert report["claims"]["detection_rate"] is None
    assert report["claims"]["generalizes_to_zero_day"] is False
