from __future__ import annotations

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


# These modules validate POSIX-only service boundaries: Unix peer credentials,
# fanotify syscalls, fcntl-backed audit locking, and the Linux package layout.
# They remain part of the Linux CI contract.  Ignoring them *only* on native
# Windows lets the Windows entropy/monitor suite run without pretending that a
# Windows endpoint offers a Linux daemon or kernel API.
_WINDOWS_LINUX_ONLY_TESTS = frozenset(
    {
        "test_audit_logger.py",
        "test_authorization.py",
        "test_fanotify_controller.py",
        "test_fanotify_syscalls.py",
        "test_fanotify_verifier_watchdog.py",
        "test_gui_official_ipc.py",
        "test_install_layout.py",
        "test_ipc_server.py",
        "test_package_imports.py",
        "test_quarantine_manager.py",
        "test_response_engine.py",
        "test_stage11_integration_contract.py",
        "test_stage14_safe_workflow.py",
        "test_stage12_daemon_contract.py",
        "test_stage13_packaging_contract.py",
        "test_stage14_integration_check.py",
        "test_stage15_release_contract.py",
    }
)


def pytest_ignore_collect(collection_path: Path, config: object) -> bool:
    """Keep native Windows collection clear of Linux-only implementation tests."""

    del config
    return sys.platform == "win32" and collection_path.name in _WINDOWS_LINUX_ONLY_TESTS
