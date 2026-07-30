from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_safe_integrated_workflow_demonstration(tmp_path: Path) -> None:
    output = tmp_path / "stage14.json"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/demonstrate_integrated_workflow.py"),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["overall_status"] == "OK"
    assert all(item["status"] == "OK" for item in report["results"])
    assert report["fixture_label"].startswith("SYNTHETIC_RUNTIME_EVIDENCE")
