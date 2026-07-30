from __future__ import annotations

import inspect

from elliot.service.daemon import ElliotDaemon, main


def test_status_exposes_audit_integrity() -> None:
    source = inspect.getsource(ElliotDaemon._handle_ipc_action)
    assert 'status["audit"] = self.audit_log.status()' in source


def test_daemon_main_refuses_corrupted_startup_chain() -> None:
    source = inspect.getsource(main)
    assert "AuditIntegrityError" in source
    assert "logger.critical" in source
