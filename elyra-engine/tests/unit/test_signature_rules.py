import json

import pytest

from elyra.signatures.rules import RuleBundleError, create_bundle, load_bundle


def _bundle():
    return create_bundle(
        "elyra-local-core",
        "1.0.0",
        {"source": "elyra-maintained", "publisher": "Elyra Team"},
        [
            {
                "id": "ELF_SUSPICIOUS_HASH",
                "match_type": "sha256",
                "value": "a" * 64,
                "description": "Synthetic test rule; not a malware verdict.",
            }
        ],
    )


def test_bundle_is_versioned_and_round_trips(tmp_path):
    bundle = _bundle()
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    assert load_bundle(path, trusted_sources={"elyra-maintained"}) == bundle
    assert bundle["schema_version"] == "elyra.rules.v1"


def test_tampering_is_rejected(tmp_path):
    bundle = _bundle()
    bundle["rules"][0]["value"] = "b" * 64
    with pytest.raises(RuleBundleError, match="hash mismatch"):
        (tmp_path / "rules.json").write_text(json.dumps(bundle), encoding="utf-8")
        load_bundle(tmp_path / "rules.json")


def test_unknown_provenance_is_rejected():
    with pytest.raises(RuleBundleError, match="untrusted"):
        from elyra.signatures.rules import validate_bundle

        validate_bundle(_bundle(), trusted_sources={"other-source"})


def test_duplicate_rule_ids_are_rejected():
    with pytest.raises(RuleBundleError, match="duplicate"):
        create_bundle(
            "elyra-local-core",
            "1.0.0",
            {"source": "elyra-maintained"},
            [
                {"id": "DUPLICATE_RULE", "match_type": "literal", "value": "a", "description": "a"},
                {"id": "DUPLICATE_RULE", "match_type": "literal", "value": "b", "description": "b"},
            ],
        )
