from __future__ import annotations

import socket
from pathlib import Path
from types import SimpleNamespace

from elyra.monitor.ebpf.collector import EBPFCollector, EbpfFilterConfig
from elyra.monitor.ebpf.events import EbpfEvent


class FakeMap(dict):
    def open_perf_buffer(self, callback, lost_cb=None):
        self.callback = callback
        self.lost_cb = lost_cb

    def event(self, data):
        return data


class FakeBPF:
    def __init__(self, *, text):
        assert "EVENT_PROCESS_EXEC" in text
        self.maps = {"events": FakeMap(), "ignored_tgids": FakeMap(),
                     "monitored_uids": FakeMap(), "filter_flags": FakeMap()}
        self.kprobes = []

    def __getitem__(self, name):
        return self.maps[name]

    def attach_kprobe(self, **kwargs):
        self.kprobes.append(kwargs)

    def perf_buffer_poll(self, timeout=100):
        return None


def test_load_attach_and_status(tmp_path: Path):
    source = tmp_path / "probes.c"
    source.write_text("#define EVENT_PROCESS_EXEC 1", encoding="utf-8")
    collector = EBPFCollector(
        str(source),
        bpf_factory=FakeBPF,
        rename_tracepoint_detector=lambda: ["rename", "renameat", "renameat2"],
    )
    assert collector.load() is True
    assert collector.attach_probes() is True
    status = collector.status()
    assert status["available"] is True
    assert "vfs_write" in status["attached_probes"]
    assert status["path_capability"] == "IDENTIFIER_ONLY_FOR_FILE_EVENTS"


def test_missing_bcc_is_safe_degraded(tmp_path: Path):
    source = tmp_path / "probes.c"
    source.write_text("x", encoding="utf-8")
    collector = EBPFCollector(str(source), bpf_factory=None)
    # Force the module-level optional dependency path.
    import elyra.monitor.ebpf.collector as module
    original = module.BPF
    module.BPF = None
    try:
        assert collector.load() is False
        assert collector.status()["degraded_reason"] == "BCC_PYTHON_BINDINGS_UNAVAILABLE"
    finally:
        module.BPF = original


def test_decode_network_event():
    raw = SimpleNamespace(event_type=5, timestamp_ns=10, pid=1, tgid=1, ppid=0,
                          uid=1000, comm=b"curl", filename=b"",
                          daddr=socket.htonl(0x7F000001), dport=socket.htons(443))
    event = EBPFCollector.decode_event(raw)
    assert event is not None
    assert event.destination_address == "127.0.0.1"
    assert event.destination_port == 443


def test_process_filter_accepts_descendants():
    config = EbpfFilterConfig(monitored_tgids={10}, include_descendants=True)
    event = EbpfEvent("FILE_WRITE", 1, 30, 30, 20, 1000, "child", device=1, inode=2)
    assert config.accepts(event, {20: 10}) is True
    assert EbpfFilterConfig(monitored_tgids={10}, include_descendants=False).accepts(event, {20: 10}) is False


def test_unique_file_identifier_is_published(tmp_path: Path):
    source = tmp_path / "probes.c"
    source.write_text("x", encoding="utf-8")
    collector = EBPFCollector(str(source), bpf_factory=FakeBPF)
    event = EbpfEvent("FILE_WRITE", 1, 7, 7, 1, 1000, "writer", device=8, inode=99)
    assert collector.publish_event(event) is True
    assert collector.get_event()["distinct_file_key"] == "8:99"


def test_exec_tracepoint_field_detection_uses_pardus_member(monkeypatch):
    monkeypatch.delenv("ELYRA_EXEC_FILENAME_FIELD", raising=False)
    monkeypatch.setattr(EBPFCollector, "_tracepoint_format_paths", classmethod(
        lambda cls, category, name: [Path("/nonexistent")]
    ))
    assert EBPFCollector._detect_exec_filename_field() == "data_loc_filename"


def test_exec_tracepoint_field_override(monkeypatch):
    monkeypatch.setenv("ELYRA_EXEC_FILENAME_FIELD", "__data_loc_filename")
    assert EBPFCollector._detect_exec_filename_field() == "__data_loc_filename"


def test_rename_tracepoint_detection_and_source_generation(monkeypatch):
    monkeypatch.setenv("ELYRA_RENAME_TRACEPOINTS", "rename,renameat,renameat2")
    names = EBPFCollector._detect_rename_tracepoints()
    assert names == ["rename", "renameat", "renameat2"]
    source = EBPFCollector._build_rename_probe_source(names)
    assert "sys_enter_rename)" in source
    assert "sys_enter_renameat)" in source
    assert "sys_enter_renameat2)" in source


def test_duplicate_rename_events_are_deduplicated(tmp_path: Path):
    source = tmp_path / "probes.c"
    source.write_text("x", encoding="utf-8")
    collector = EBPFCollector(str(source), bpf_factory=FakeBPF)
    first = EbpfEvent("FILE_RENAME", 1_000_000_000, 7, 7, 1, 1000, "mv",
                      executable_identifier="old.txt", device=0, inode=0)
    duplicate = EbpfEvent("FILE_RENAME", 1_005_000_000, 7, 7, 1, 1000, "mv",
                          executable_identifier="old.txt", device=0, inode=0)
    later = EbpfEvent("FILE_RENAME", 1_020_000_000, 7, 7, 1, 1000, "mv",
                      executable_identifier="old.txt", device=0, inode=0)
    assert collector.publish_event(first) is True
    assert collector.publish_event(duplicate) is False
    assert collector.publish_event(later) is True


def test_tracepoint_permission_error_is_a_capability_result(monkeypatch):
    class UnreadableFormat:
        def open(self, *args, **kwargs):
            raise PermissionError(13, "permission denied")

    monkeypatch.setattr(
        EBPFCollector,
        "_tracepoint_format_paths",
        classmethod(lambda cls, category, name: [UnreadableFormat()]),
    )
    assert EBPFCollector._tracepoint_exists("syscalls", "sys_enter_rename") is False


def test_rename_detection_does_not_guess_when_tracefs_is_unreadable(monkeypatch):
    monkeypatch.delenv("ELYRA_RENAME_TRACEPOINTS", raising=False)
    monkeypatch.setattr(
        EBPFCollector,
        "_tracepoint_exists",
        classmethod(lambda cls, category, name: False),
    )
    assert EBPFCollector._detect_rename_tracepoints() == []


def test_load_uses_injected_tracepoint_detector_without_host_tracefs(tmp_path: Path, monkeypatch):
    source = tmp_path / "probes.c"
    source.write_text("#define EVENT_PROCESS_EXEC 1\nELYRA_RENAME_PROBES", encoding="utf-8")

    def forbidden_host_detection():
        raise AssertionError("unit test attempted host tracefs discovery")

    monkeypatch.setattr(EBPFCollector, "_detect_rename_tracepoints", forbidden_host_detection)
    collector = EBPFCollector(
        str(source),
        bpf_factory=FakeBPF,
        rename_tracepoint_detector=lambda: ["renameat2", "rename", "rename"],
    )
    assert collector.load() is True
    assert collector.status()["tracepoint_compatibility"]["rename.tracepoints"] == "rename,renameat2"


def test_lost_event_callback_accepts_pardus_bcc_one_argument(tmp_path: Path):
    source = tmp_path / "probes.c"
    source.write_text("x", encoding="utf-8")
    collector = EBPFCollector(str(source), bpf_factory=FakeBPF)

    collector._on_lost_events(7)

    assert collector.status()["dropped_events"] == 7


def test_lost_event_callback_accepts_two_argument_bcc_variant(tmp_path: Path):
    source = tmp_path / "probes.c"
    source.write_text("x", encoding="utf-8")
    collector = EBPFCollector(str(source), bpf_factory=FakeBPF)

    collector._on_lost_events(3, 11)

    assert collector.status()["dropped_events"] == 11


def test_registered_lost_callback_matches_pardus_bcc_invocation(tmp_path: Path):
    source = tmp_path / "probes.c"
    source.write_text("#define EVENT_PROCESS_EXEC 1\nELYRA_RENAME_PROBES", encoding="utf-8")
    collector = EBPFCollector(
        str(source),
        bpf_factory=FakeBPF,
        rename_tracepoint_detector=lambda: ["renameat2"],
    )
    assert collector.load() is True
    assert collector.start() is True
    try:
        lost_callback = collector.bpf["events"].lost_cb
        lost_callback(5)
        assert collector.status()["dropped_events"] == 5
    finally:
        collector.stop()
