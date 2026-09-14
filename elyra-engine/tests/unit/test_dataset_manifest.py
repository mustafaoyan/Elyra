import pytest

from elyra.measurement.dataset import DatasetManifestError, validate_manifest


def _record(split="test", family="family-a"):
    return {"sample_id": "sample-1", "sha256": "a" * 64, "split": split, "label": False, "family": family}


def test_manifest_accepts_valid_records():
    assert validate_manifest([_record()])[0]["split"] == "test"


def test_manifest_rejects_hash_leakage():
    with pytest.raises(DatasetManifestError, match="hash"):
        validate_manifest([_record("train"), dict(_record("test"), sample_id="sample-2")])


def test_manifest_rejects_family_leakage():
    with pytest.raises(DatasetManifestError, match="family"):
        validate_manifest([_record("train"), dict(_record("train", "family-b"), sha256="b" * 64), dict(_record("test"), sha256="c" * 64)])
