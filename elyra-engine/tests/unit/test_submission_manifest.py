from __future__ import annotations

import json
from pathlib import Path

import pytest

from elyra.release.submission import REQUIREMENTS, collect_submission_report, finalize_submission


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    (root / "evidence").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname="elyra-pardus"\nversion="1.0.0"\n', encoding="utf-8"
    )
    for requirement in REQUIREMENTS:
        path = root / "evidence" / requirement.patterns[0]
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".json":
            payload = {"overall_status": "OK", "scenario": requirement.key}
            path.write_text(json.dumps(payload), encoding="utf-8")
        else:
            path.write_text("TOTAL 5097 1530 70%\n223 passed\n", encoding="utf-8")
    return root


def test_complete_evidence_report(tmp_path: Path) -> None:
    report = collect_submission_report(_project(tmp_path))
    assert report["overall_status"] == "COMPLETE"
    assert not report["summary"]["critical_failures"]


def test_missing_critical_evidence_is_incomplete(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / "evidence" / REQUIREMENTS[0].patterns[0]).unlink()
    report = collect_submission_report(root)
    assert report["overall_status"] == "INCOMPLETE"
    assert REQUIREMENTS[0].key in report["summary"]["critical_failures"]


def test_failed_json_status_is_not_accepted(tmp_path: Path) -> None:
    root = _project(tmp_path)
    path = root / "evidence" / REQUIREMENTS[1].patterns[0]
    path.write_text('{"overall_status":"FAIL"}', encoding="utf-8")
    report = collect_submission_report(root)
    item = next(x for x in report["requirements"] if x["key"] == REQUIREMENTS[1].key)
    assert item["status"] == "FAIL"
    assert report["overall_status"] == "INCOMPLETE"


def test_invalid_json_is_reported(tmp_path: Path) -> None:
    root = _project(tmp_path)
    path = root / "evidence" / REQUIREMENTS[2].patterns[0]
    path.write_text("not-json", encoding="utf-8")
    report = collect_submission_report(root)
    item = next(x for x in report["requirements"] if x["key"] == REQUIREMENTS[2].key)
    assert item["status"] == "FAIL"
    assert "invalid JSON" in item["detail"]


def test_symbolic_link_evidence_is_rejected(tmp_path: Path) -> None:
    root = _project(tmp_path)
    path = root / "evidence" / REQUIREMENTS[3].patterns[0]
    target = root / "target.json"
    target.write_text('{"overall_status":"OK"}', encoding="utf-8")
    path.unlink()
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links unavailable")
    report = collect_submission_report(root)
    item = next(x for x in report["requirements"] if x["key"] == REQUIREMENTS[3].key)
    assert item["status"] == "FAIL"
    assert "symbolic-link" in item["detail"]


def test_finalizer_writes_manifest_inventory_and_checksums(tmp_path: Path) -> None:
    root = _project(tmp_path)
    report = finalize_submission(root, strict=True)
    assert report["overall_status"] == "COMPLETE"
    output = root / "evidence/submission"
    assert (output / "final_manifest.json").is_file()
    assert (output / "final_checksums.sha256").is_file()
    assert (output / "final_inventory.txt").is_file()
    assert "COMPLETE" in (output / "FINAL_STATUS.md").read_text(encoding="utf-8")


def test_finalizer_creates_environment_record(tmp_path: Path) -> None:
    root = _project(tmp_path)
    finalize_submission(root)
    payload = json.loads(
        (root / "evidence/environment/final_environment_pardus.json").read_text(encoding="utf-8")
    )
    assert payload["project"] == "ELYRA"
    assert payload["project_version"] == "1.0.0"
    assert payload["kernel"]


def test_strict_finalizer_raises_for_incomplete_evidence(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / "evidence" / REQUIREMENTS[-1].patterns[0]).unlink()
    with pytest.raises(RuntimeError, match="incomplete"):
        finalize_submission(root, strict=True)


def test_inventory_hashes_are_sha256(tmp_path: Path) -> None:
    report = collect_submission_report(_project(tmp_path))
    assert report["inventory"]
    assert all(len(item["sha256"]) == 64 for item in report["inventory"])


def test_submission_outputs_are_excluded_from_inventory(tmp_path: Path) -> None:
    root = _project(tmp_path)
    finalize_submission(root)
    report = collect_submission_report(root)
    assert all(not item["path"].startswith("submission/") for item in report["inventory"])
