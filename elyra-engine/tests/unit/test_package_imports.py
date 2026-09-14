from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

import elyra


def test_all_python_modules_are_importable() -> None:
    failures: list[str] = []
    for module in pkgutil.walk_packages(elyra.__path__, prefix="elyra."):
        try:
            importlib.import_module(module.name)
        except Exception as exc:  # Report all broken modules in one assertion.
            failures.append(f"{module.name}: {type(exc).__name__}: {exc}")
    assert not failures, "\n".join(failures)


def test_active_paths_use_elyra_name() -> None:
    root = Path(__file__).resolve().parents[2]
    active_files = [
        path.relative_to(root).as_posix()
        for path in (root / "src").rglob("*")
        if path.is_file()
    ]
    assert all("elliot" not in path.lower() and "siper" not in path.lower() for path in active_files)
