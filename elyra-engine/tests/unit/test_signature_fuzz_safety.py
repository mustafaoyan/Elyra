import random

import pytest

from elyra.signatures.rules import RuleBundleError, load_bundle
from elyra.signatures.yara import YaraXEvaluator


def test_malformed_bundle_inputs_fail_closed(tmp_path):
    rng = random.Random(20260914)
    for index in range(32):
        payload = {"schema_version": "elyra.rules.v1", "rules": [rng.randbytes(16).hex()]}
        path = tmp_path / f"malformed-{index}.json"
        path.write_text(str(payload), encoding="utf-8")
        with pytest.raises(RuleBundleError):
            load_bundle(path)


def test_yara_resource_limits_are_explicit():
    evaluator = YaraXEvaluator(object())
    huge_rule = "x" * (1_048_576 + 1)
    assert evaluator.evaluate(huge_rule, b"safe").status == "RESOURCE_LIMIT"
    assert evaluator.evaluate("rule x { condition: true }", b"x" * (8 * 1_024 * 1_024 + 1)).status == "RESOURCE_LIMIT"
