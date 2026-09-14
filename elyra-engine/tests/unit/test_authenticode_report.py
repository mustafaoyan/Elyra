from elyra.signatures.authenticode import report_authenticode


def test_certificate_presence_is_not_trust():
    report = report_authenticode({"certificate_table_present": True})
    assert report.status == "CERTIFICATE_TABLE_PRESENT"
    assert report.trust == "UNKNOWN"
    assert report.verification == "NOT_PERFORMED"


def test_missing_certificate_is_explicit():
    report = report_authenticode({"certificate_table_present": False})
    assert report.status == "NO_CERTIFICATE_TABLE"
    assert report.certificate_table_present is False
