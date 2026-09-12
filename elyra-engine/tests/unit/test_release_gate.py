from __future__ import annotations

import hashlib
from pathlib import Path

from scripts.release_gate import evaluate


def test_release_gate_blocks_missing_artifact(tmp_path: Path) -> None:
    result = evaluate(tmp_path / "dist")
    assert result["publication_allowed"] is False
    assert result["overall_status"] == "BLOCKED_PENDING_ARTIFACTS"


def test_release_gate_accepts_checksumed_deb(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "dist"
    artifact_dir.mkdir()
    artifact = artifact_dir / "elyra-pardus_1.0.0-1_amd64.deb"
    artifact.write_bytes(b"synthetic package bytes")
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    artifact.with_name(artifact.name + ".sha256").write_text(f"{digest}  {artifact.name}\n", encoding="utf-8")
    result = evaluate(artifact_dir)
    assert result["publication_allowed"] is True
    assert result["artifacts"][0]["checksum_valid"] is True
