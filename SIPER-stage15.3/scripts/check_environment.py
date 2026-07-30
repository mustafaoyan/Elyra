#!/usr/bin/env python3
"""Validate ELLIOT's Stage 2 Python and system dependency contract."""

from __future__ import annotations

import argparse
import importlib
import platform
import shutil
import sys
from pathlib import Path
from typing import Callable


MIN_PYTHON = (3, 10)


def _ok(message: str) -> None:
    print(f"[OK] {message}")


def _warn(message: str) -> None:
    print(f"[DEGRADED] {message}")


def _fail(message: str) -> None:
    print(f"[FAIL] {message}")


def _module_version(module: object) -> str:
    return str(
        getattr(module, "__version__", None)
        or getattr(module, "version", None)
        or "version not exposed"
    )


def _check_import(module_name: str, label: str) -> bool:
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # report exact import/runtime loader failure
        _fail(f"{label}: {type(exc).__name__}: {exc}")
        return False
    _ok(f"{label}: {_module_version(module)}")
    return True


def _check_python_magic() -> bool:
    try:
        magic = importlib.import_module("magic")
        detector = magic.Magic(mime=True)
        detected = detector.from_file(__file__)
    except Exception as exc:
        _fail(f"python-magic/libmagic: {type(exc).__name__}: {exc}")
        return False
    _ok(f"python-magic/libmagic: detected {detected!r}")
    return True


def _check_tkinter() -> bool:
    try:
        tkinter = importlib.import_module("tkinter")
    except Exception as exc:
        _fail(f"Tkinter system module: {type(exc).__name__}: {exc}")
        return False
    _ok(f"Tkinter system module: Tk {getattr(tkinter, 'TkVersion', 'unknown')}")
    return True


def _check_bcc(required: bool) -> bool:
    try:
        importlib.import_module("bcc")
    except Exception as exc:
        message = f"BCC Python bindings unavailable: {type(exc).__name__}: {exc}"
        if required:
            _fail(message)
            return False
        _warn(message)
        return True
    _ok("BCC Python bindings importable")
    return True


def _check_kernel_headers(required: bool) -> bool:
    build_dir = Path("/lib/modules") / platform.release() / "build"
    if build_dir.exists():
        _ok(f"Running-kernel headers: {build_dir}")
        return True
    message = f"running-kernel header link is missing: {build_dir}"
    if required:
        _fail(message)
        return False
    _warn(message)
    return True


def _check_tool(name: str, required: bool) -> bool:
    path = shutil.which(name)
    if path:
        _ok(f"tool {name}: {path}")
        return True
    message = f"tool {name} is not on PATH"
    if required:
        _fail(message)
        return False
    _warn(message)
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-ebpf",
        action="store_true",
        help="fail if BCC, kernel headers or clang are unavailable",
    )
    args = parser.parse_args()

    print(f"Python: {sys.version.split()[0]}")
    print(f"Platform: {platform.platform()}")

    checks: list[Callable[[], bool]] = []
    if sys.version_info < MIN_PYTHON:
        _fail(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer is required")
        python_ok = False
    else:
        _ok("Python version is supported")
        python_ok = True

    checks.extend(
        [
            lambda: _check_import("numpy", "NumPy"),
            lambda: _check_import("customtkinter", "CustomTkinter"),
            lambda: _check_import("matplotlib", "Matplotlib"),
            _check_python_magic,
            lambda: _check_import("elftools", "pyelftools"),
            _check_tkinter,
            lambda: _check_bcc(args.require_ebpf),
            lambda: _check_kernel_headers(args.require_ebpf),
            lambda: _check_tool("clang", args.require_ebpf),
        ]
    )

    success = python_ok
    for check in checks:
        success = check() and success

    if success:
        _ok("Stage 2 dependency check completed")
        return 0
    _fail("Stage 2 dependency check failed")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
