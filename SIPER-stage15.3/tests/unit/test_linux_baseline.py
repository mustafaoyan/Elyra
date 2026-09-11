from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "linux_baseline.py"
_SPEC = importlib.util.spec_from_file_location("elliot_linux_baseline", _SCRIPT)
assert _SPEC and _SPEC.loader
linux_baseline = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = linux_baseline
_SPEC.loader.exec_module(linux_baseline)


def test_baseline_is_read_only_and_explicit_on_non_linux(monkeypatch) -> None:
    monkeypatch.setattr(linux_baseline.platform, "system", lambda: "Windows")
    payload = linux_baseline.collect_baseline()
    assert payload["overall_status"] == "UNAVAILABLE_NON_LINUX_HOST"
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["packages_changed"] is False
    assert payload["safety"]["probes_attached"] is False
    assert payload["fanotify"]["status"] == "UNAVAILABLE"
    assert payload["ebpf"]["status"] == "UNAVAILABLE"


def test_baseline_json_output_is_machine_readable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(linux_baseline.platform, "system", lambda: "Windows")
    output = tmp_path / "evidence" / "baseline.json"
    assert linux_baseline.main(["--json-out", str(output)]) == 2
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["tool"] == "elliot-linux-baseline"
    assert payload["schema_version"] == 1
    assert payload["safety"]["fanotify_group_opened"] is False
