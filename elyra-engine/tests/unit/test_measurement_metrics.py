from elyra.measurement.metrics import EvaluationRecord, evaluate_records


def test_metrics_keep_inconclusive_separate_from_clean():
    result = evaluate_records(
        [
            EvaluationRecord(True, "DENY", 2.0),
            EvaluationRecord(True, "INCONCLUSIVE", 4.0),
            EvaluationRecord(False, "ALLOW", 1.0),
            EvaluationRecord(False, "DENY", 3.0),
        ]
    )
    assert result["true_positive"] == 1
    assert result["false_negative"] == 1
    assert result["false_positive"] == 1
    assert result["inconclusive_rate"] == 0.25
    assert result["precision"] == 0.5


def test_unlabelled_records_do_not_create_performance_claims():
    result = evaluate_records([EvaluationRecord(None, "ALLOW", 1.0)])
    assert result["labelled_count"] == 0
    assert result["precision"] is None
    assert result["recall"] is None
