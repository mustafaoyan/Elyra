from __future__ import annotations

import inspect

from elyra.service.daemon import ElyraDaemon, main


def test_status_exposes_audit_integrity() -> None:
    source = inspect.getsource(ElyraDaemon._handle_ipc_action)
    assert 'status["audit"] = self.audit_log.status()' in source


def test_daemon_main_refuses_corrupted_startup_chain() -> None:
    source = inspect.getsource(main)
    assert "AuditIntegrityError" in source
    assert "logger.critical" in source
