from __future__ import annotations

from elliot.monitor.ebpf.collector import EBPFCollector
from elliot.monitor.ebpf.events import EbpfEvent


def test_bounded_event_queue_reports_drops() -> None:
    collector = EBPFCollector("unused", queue_size=1)
    event = EbpfEvent("PROCESS_EXEC", 1, 1, 1, 0, 0, "fixture")
    assert collector.publish_event(event) is True
    assert collector.publish_event(event) is False
    assert collector.status()["dropped_events"] == 1
