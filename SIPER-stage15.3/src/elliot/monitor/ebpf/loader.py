"""Safe eBPF loader with explicit degraded-mode reporting."""
from __future__ import annotations

import os
from pathlib import Path

from .collector import EBPFCollector, EbpfFilterConfig


class EBPFLoader:
    def __init__(self, probes_path: str | None = None, *, filter_config: EbpfFilterConfig | None = None, **_legacy) -> None:
        self.probes_path = str(Path(probes_path) if probes_path else Path(__file__).with_name("probes.c"))
        config = filter_config or EbpfFilterConfig(ignored_tgids={os.getpid()})
        self.collector = EBPFCollector(self.probes_path, filter_config=config)

    def initialize(self) -> bool:
        if not self.collector.load():
            return False
        if not self.collector.attach_probes():
            self.collector.stop()
            return False
        if not self.collector.start():
            self.collector.stop()
            return False
        return True

    def shutdown(self) -> None:
        self.collector.stop()

    def fetch_event(self, timeout: float = 0.5):
        return self.collector.get_event(timeout)

    def status(self):
        return self.collector.status()

    def self_test(self) -> bool:
        ok = self.collector.load() and self.collector.attach_probes()
        self.collector.stop()
        return bool(ok)
