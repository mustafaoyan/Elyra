"""Typed user-space representation of ELYRA eBPF telemetry."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum
from typing import Any


class EventType(IntEnum):
    PROCESS_EXEC = 1
    PROCESS_EXIT = 2
    FILE_WRITE = 3
    FILE_RENAME = 4
    NETWORK_CONNECT = 5


@dataclass(frozen=True)
class EbpfEvent:
    event_type: str
    timestamp_ns: int
    pid: int
    tgid: int
    ppid: int
    uid: int
    comm: str
    executable_identifier: str | None = None
    exit_code: int | None = None
    device: int | None = None
    inode: int | None = None
    destination_address: str | None = None
    destination_port: int | None = None
    probe_path_capability: str = "IDENTIFIER_ONLY"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
