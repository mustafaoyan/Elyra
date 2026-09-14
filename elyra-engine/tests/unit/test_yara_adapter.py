from elyra.signatures.yara import YaraXEvaluator


class FakeBackend:
    def compile(self, source):
        if "malformed" in source:
            raise ValueError("syntax error")
        return source

    def scan(self, compiled, sample):
        return ["SYNTHETIC_MATCH"] if b"marker" in sample else []


def test_benign_sample_has_no_match():
    result = YaraXEvaluator(FakeBackend()).evaluate("rule benign { condition: true }", b"safe")
    assert result.status == "NO_MATCH"
    assert result.matches == ()


def test_matching_synthetic_sample_is_reported():
    result = YaraXEvaluator(FakeBackend()).evaluate("rule marker { condition: true }", b"marker")
    assert result.status == "MATCH"
    assert result.matches == ("SYNTHETIC_MATCH",)


def test_malformed_rule_is_explicit_error():
    result = YaraXEvaluator(FakeBackend()).evaluate("malformed", b"safe")
    assert result.status == "COMPILE_OR_SCAN_ERROR"
    assert "syntax" in (result.error or "")


def test_missing_dependency_is_not_silent():
    evaluator = YaraXEvaluator(None)
    evaluator._backend = None
    evaluator._backend_error = "optional dependency yara-x is not installed"
    result = evaluator.evaluate("rule x { condition: true }", b"safe")
    assert result.status == "UNAVAILABLE_DEPENDENCY"
