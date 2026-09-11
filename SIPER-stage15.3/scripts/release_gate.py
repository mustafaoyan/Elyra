#!/usr/bin/env python3
"""Validate Linux release artifacts without publishing or fabricating assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
import time
from pathlib import Path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evaluate(artifact_dir: Path) -> dict[str, object]:
    artifacts = []
    issues: list[str] = []
    if artifact_dir.exists() and not artifact_dir.is_dir():
        issues.append("ARTIFACT_PATH_NOT_DIRECTORY")
    elif artifact_dir.is_dir():
        for candidate in sorted(artifact_dir.iterdir()):
            if candidate.is_symlink() or not candidate.is_file():
                continue
            if candidate.suffix != ".deb":
                continue
            digest = _sha256(candidate)
            checksum = candidate.with_name(candidate.name + ".sha256")
            checksum_ok = checksum.is_file() and digest in checksum.read_text(encoding="utf-8", errors="replace")
            artifacts.append({"path": str(candidate), "sha256": digest, "checksum_file": str(checksum), "checksum_valid": checksum_ok})
            if not checksum_ok:
                issues.append(f"CHECKSUM_MISSING_OR_INVALID:{candidate.name}")
    if not artifacts:
        issues.append("NO_SIGNED_OR_CHECKSUMMED_DEBIAN_ARTIFACT")
    return {
        "schema_version": 1,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "artifact_directory": str(artifact_dir),
        "artifacts": artifacts,
        "publication_allowed": False if issues else True,
        "signing_required_before_download_link": True,
        "issues": issues,
        "overall_status": "READY_FOR_SIGNING_AND_PUBLICATION" if not issues else "BLOCKED_PENDING_ARTIFACTS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, default=Path("dist/debian"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    payload = evaluate(args.artifact_dir)
    text = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    print(text, end="")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    return 0 if payload["overall_status"] == "READY_FOR_SIGNING_AND_PUBLICATION" else 2


if __name__ == "__main__":
    raise SystemExit(main())
