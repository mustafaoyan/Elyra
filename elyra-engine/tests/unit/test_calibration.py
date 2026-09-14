from elyra.measurement.calibration import CalibrationRecord, calibrate_deny_threshold


def test_calibration_is_recommendation_only():
    result = calibrate_deny_threshold([CalibrationRecord(10, False), CalibrationRecord(20, False), CalibrationRecord(80, True), CalibrationRecord(90, True)], max_false_positive_rate=0.0)
    assert result["status"] == "RECOMMENDATION_ONLY"
    assert result["threshold"] == 80
    assert result["policy_mutated"] is False


def test_calibration_reports_missing_data():
    assert calibrate_deny_threshold([])["status"] == "INSUFFICIENT_DATA"
    assert calibrate_deny_threshold([CalibrationRecord(20, False)])["status"] == "INSUFFICIENT_CLASS_COVERAGE"
