"""Deterministic release-archive helpers for Elyra (ELYRA project)."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Iterable

EXCLUDED_PARTS = {".git", ".venv", ".pytest_cache", "__pycache__", "dist", "build"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)


def iter_release_files(root: Path, *, include_evidence: bool) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.suffix in EXCLUDED_SUFFIXES:
            continue
        if not include_evidence and relative.parts and relative.parts[0] == "evidence":
            if path.name != "README.md":
                continue
        yield path


def deterministic_zip(root: Path, output: Path, *, include_evidence: bool) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    prefix = root.name
    with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in iter_release_files(root, include_evidence=include_evidence):
            relative = Path(prefix) / path.relative_to(root)
            info = zipfile.ZipInfo(relative.as_posix(), FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (path.stat().st_mode & 0xFFFF) << 16
            archive.writestr(info, path.read_bytes())
    os.replace(temporary, output)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build_release_artifacts(project_root: Path, output_dir: Path) -> list[Path]:
    project_root = project_root.resolve()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    version = __import__("tomllib").load((project_root / "pyproject.toml").open("rb"))["project"]["version"]

    source_zip = output_dir / f"elyra-pardus-{version}-source.zip"
    submission_zip = output_dir / f"ELYRA-Pardus-{version}-submission.zip"
    deterministic_zip(project_root, source_zip, include_evidence=False)
    deterministic_zip(project_root, submission_zip, include_evidence=True)

    wheel_dir = output_dir / "python"
    if wheel_dir.exists():
        shutil.rmtree(wheel_dir)
    wheel_dir.mkdir(parents=True)
    completed = subprocess.run(
        [
            os.fspath(Path(os.sys.executable)),
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            os.fspath(wheel_dir),
            os.fspath(project_root),
        ],
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError("Python wheel build failed")
    artifacts = [source_zip, submission_zip, *sorted(wheel_dir.glob("*.whl"))]
    checksum_text = "\n".join(
        f"{sha256(path)}  {path.relative_to(output_dir).as_posix()}" for path in artifacts
    ) + "\n"
    (output_dir / "SHA256SUMS").write_text(checksum_text, encoding="utf-8")
    return artifacts


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--output-dir", default="dist/final")
    args = parser.parse_args(argv)
    artifacts = build_release_artifacts(Path(args.project_root), Path(args.output_dir))
    for artifact in artifacts:
        print(f"artifact: {artifact}")
    print(f"checksums: {Path(args.output_dir) / 'SHA256SUMS'}")


if __name__ == "__main__":
    main()
