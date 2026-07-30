from elliot.monitor.ebpf.aggregator import RuntimeTelemetryAggregator


def test_distinct_file_count_counts_unique_files_not_writes():
    agg = RuntimeTelemetryAggregator()
    base = {"tgid": 10, "pid": 10, "ppid": 1, "uid": 1000, "event_type": "FILE_WRITE"}
    assert agg.ingest({**base, "distinct_file_key": "1:2"})["distinct_files_modified"] == 1
    assert agg.ingest({**base, "distinct_file_key": "1:2"})["distinct_files_modified"] == 1
    assert agg.ingest({**base, "distinct_file_key": "1:3"})["distinct_files_modified"] == 2


def test_exit_removes_state_without_threads():
    agg = RuntimeTelemetryAggregator()
    agg.ingest({"tgid": 20, "pid": 20, "ppid": 1, "uid": 1000,
                "event_type": "PROCESS_EXEC", "executable_identifier": "/bin/true"})
    assert 20 in agg.states
    agg.ingest({"tgid": 20, "pid": 20, "ppid": 1, "uid": 1000, "event_type": "PROCESS_EXIT"})
    assert 20 not in agg.states


def test_bounded_state_eviction():
    agg = RuntimeTelemetryAggregator(max_states=2)
    for pid in (1, 2, 3):
        agg.ingest({"tgid": pid, "pid": pid, "ppid": 0, "uid": 1000, "event_type": "PROCESS_EXEC"})
    assert len(agg.states) == 2
