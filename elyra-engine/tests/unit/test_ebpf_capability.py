from __future__ import annotations

from pathlib import Path

from elyra.monitor.ebpf.capability import assess_ebpf_capability


def test_ebpf_capability_is_explicit_on_non_linux() -> None:
    result = assess_ebpf_capability(system_name="Windows")
    assert result.status == "UNAVAILABLE"
    assert result.ready is False
    assert "LINUX_EBPF_REQUIRES_LINUX_HOST" in result.issues


def test_ebpf_capability_fixture_reports_all_prerequisites(tmp_path: Path, monkeypatch) -> None:
    tracefs = tmp_path / "events"
    tracefs.mkdir()
    monkeypatch.setattr(
        "elyra.monitor.ebpf.capability.assess_kernel_headers",
        lambda **_: type("Assessment", (), {"status": "READY"})(),
    )
    result = assess_ebpf_capability(
        system_name="Linux",
        tracefs_paths=(tracefs,),
        bcc_importable=True,
        privileged=True,
    )
    assert result.ready is True
    assert result.to_dict()["status"] == "READY"
