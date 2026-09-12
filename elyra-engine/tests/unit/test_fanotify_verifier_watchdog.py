"""Stage 8.1 liveness tests for the external execution broker."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import pytest

@pytest.fixture(scope="module")
def verifier_module():
    path = Path(__file__).resolve().parents[2] / "scripts" / "verify_fanotify_pardus.py"
    spec = importlib.util.spec_from_file_location("elyra_stage81_verifier", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

@pytest.fixture
def broker(verifier_module):
    instance = verifier_module.ExecBroker()
    try:
        yield instance
    finally:
        instance.close()

def test_external_broker_allows_harmless_true(broker) -> None:
    result = broker.execute(Path("/bin/true"), timeout=2.0)
    assert result["returncode"] == 0
    assert result["timed_out"] is False
    assert result["watchdog_action"] == "NONE"

def test_external_watchdog_terminates_blocked_launcher(broker) -> None:
    sleep = Path("/bin/sleep")
    if not sleep.exists():
        pytest.skip("/bin/sleep is unavailable")
    result = broker.execute(sleep, argv=(str(sleep), "10"), timeout=0.15)
    assert result["returncode"] == 124
    assert result["timed_out"] is True
    assert result["watchdog_action"] == "TERMINATE_THEN_KILL"

def test_atomic_progress_evidence_is_always_valid_json(tmp_path, verifier_module) -> None:
    output = tmp_path / "evidence.json"
    verifier_module._persist_progress(output, [{"scenario": "fixture", "status": "OK"}], status="IN_PROGRESS")
    payload = __import__("json").loads(output.read_text(encoding="utf-8"))
    assert payload["overall_status"] == "IN_PROGRESS"
    assert payload["verifier_revision"] == "STAGE_8_1_FORK_WATCHDOG"
