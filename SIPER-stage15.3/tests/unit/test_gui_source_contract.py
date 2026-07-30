from __future__ import annotations

from pathlib import Path


def test_production_view_contains_no_random_telemetry() -> None:
    source = Path("src/elliot/gui/view.py").read_text(encoding="utf-8")
    assert "import random" not in source
    assert "random.uniform" not in source
    assert "Service Status: ACTIVE" not in source


def test_gui_model_uses_ipc_client_only() -> None:
    source = Path("src/elliot/gui/model.py").read_text(encoding="utf-8")
    assert "IpcClient" in source
    assert "socket.socket" not in source
    assert "localhost" not in source
    assert "65432" not in source
