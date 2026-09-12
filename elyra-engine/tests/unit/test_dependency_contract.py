from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _requirement_names(path: Path) -> set[str]:
    names: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        for separator in ("==", ">=", "<=", "~=", "!=", ">", "<", "["):
            line = line.split(separator, 1)[0]
        names.add(line.strip().lower().replace("_", "-"))
    return names


def test_runtime_requirements_are_direct_and_minimal() -> None:
    assert _requirement_names(ROOT / "requirements.txt") == {
        "numpy",
        "customtkinter",
        "matplotlib",
        "python-magic",
        "pyelftools",
    }


def test_development_requirements_are_direct_and_minimal() -> None:
    assert _requirement_names(ROOT / "requirements-dev.txt") == {
        "pytest",
        "pytest-cov",
    }


def test_repository_text_files_are_utf8() -> None:
    text_suffixes = {".py", ".toml", ".md", ".txt", ".service", ".sh", ".c"}
    excluded_parts = {".git", ".venv", "__pycache__"}

    checked = 0
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in text_suffixes:
            continue
        if excluded_parts.intersection(path.parts):
            continue
        path.read_text(encoding="utf-8")
        checked += 1

    assert checked > 0
