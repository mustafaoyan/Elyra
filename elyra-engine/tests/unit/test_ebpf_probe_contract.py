from pathlib import Path


def test_probe_source_has_required_event_set_and_no_complex_response_logic():
    source = Path("src/elyra/monitor/ebpf/probes.c").read_text(encoding="utf-8")
    for token in ["EVENT_PROCESS_EXEC", "EVENT_PROCESS_EXIT", "EVENT_FILE_WRITE",
                  "EVENT_FILE_RENAME", "EVENT_NETWORK_CONNECT"]:
        assert token in source
    assert "SIGKILL" not in source
    assert "quarantine" not in source.lower()
    assert "risk" not in source.lower()


def test_file_events_do_not_claim_verified_full_paths():
    source = Path("src/elyra/monitor/ebpf/probes.c").read_text(encoding="utf-8")
    assert "IDENTIFIER_ONLY" not in source  # capability is stated in user space
    assert "user-supplied identifier" in source


def test_probe_uses_supported_ppid_read_and_portable_exit_event():
    source = Path("src/elyra/monitor/ebpf/probes.c").read_text(encoding="utf-8")
    assert "bpf_get_current_ppid" not in source
    assert "task->real_parent" in source
    assert "args->exit_code" not in source
    assert "ELYRA_EXEC_FILENAME_FIELD" in source


def test_rename_probes_are_injected_dynamically():
    source = Path("src/elyra/monitor/ebpf/probes.c").read_text(encoding="utf-8")
    assert "ELYRA_RENAME_PROBES" in source
    assert "sys_enter_renameat2" not in source
