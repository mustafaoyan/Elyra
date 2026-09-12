"""Filtered BCC collector for ELYRA runtime telemetry.

No response action or complex scoring occurs inside eBPF. This module only
loads probes, decodes events, filters them and publishes structured records.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import queue
import socket
import struct
import threading
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

try:
    from bcc import BPF  # type: ignore
except ImportError:  # Pardus system dependency, intentionally not from PyPI.
    BPF = None

from .events import EbpfEvent, EventType
from .kernel_headers import KernelHeaderAssessment, assess_kernel_headers

logger = logging.getLogger("elyra.monitor.ebpf.collector")


@dataclass
class EbpfFilterConfig:
    monitored_uids: set[int] = field(default_factory=set)
    monitored_tgids: set[int] = field(default_factory=set)
    ignored_tgids: set[int] = field(default_factory=set)
    include_descendants: bool = True
    max_tracked_processes: int = 4096

    def accepts(self, event: EbpfEvent, ancestry: dict[int, int]) -> bool:
        if event.tgid in self.ignored_tgids or event.pid in self.ignored_tgids:
            return False
        uid_ok = not self.monitored_uids or event.uid in self.monitored_uids
        if not uid_ok:
            return False
        if not self.monitored_tgids:
            return True
        if event.tgid in self.monitored_tgids or event.pid in self.monitored_tgids:
            return True
        if not self.include_descendants:
            return False
        current = event.ppid
        visited: set[int] = set()
        while current > 0 and current not in visited:
            if current in self.monitored_tgids:
                return True
            visited.add(current)
            current = ancestry.get(current, 0)
        return False


class EBPFCollector:
    def __init__(
        self,
        bpf_program_path: str,
        *,
        filter_config: EbpfFilterConfig | None = None,
        bpf_factory: Callable[..., Any] | None = None,
        rename_tracepoint_detector: Callable[[], list[str]] | None = None,
        kernel_header_assessor: Callable[[], KernelHeaderAssessment] | None = None,
        queue_size: int = 4096,
    ) -> None:
        self.bpf_program_path = str(Path(bpf_program_path))
        self.filter_config = filter_config or EbpfFilterConfig(ignored_tgids={os.getpid()})
        self._bpf_factory = bpf_factory
        self._rename_tracepoint_detector = rename_tracepoint_detector
        self._kernel_header_assessor = kernel_header_assessor
        self._kernel_header_assessment: KernelHeaderAssessment | None = None
        self.bpf: Any | None = None
        self.event_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=queue_size)
        self.stop_event = threading.Event()
        self.degraded_reason: str | None = None
        self._poll_thread: threading.Thread | None = None
        self._ancestry: OrderedDict[int, int] = OrderedDict()
        self._dropped_events = 0
        self._attached_probes: list[str] = []
        self._tracepoint_compatibility: dict[str, str] = {}
        self._rename_tracepoints: list[str] = []
        self._recent_rename_events: OrderedDict[tuple[int, int, str], int] = OrderedDict()
        self._rename_dedup_window_ns = 10_000_000

    @property
    def available(self) -> bool:
        return self.bpf is not None and self.degraded_reason is None

    def load(self) -> bool:
        factory = self._bpf_factory or BPF
        if factory is None:
            self.degraded_reason = "BCC_PYTHON_BINDINGS_UNAVAILABLE"
            logger.warning("eBPF degraded: %s", self.degraded_reason)
            return False
        # Unit-test or externally injected BPF factories are intentionally not
        # gated on the host's /lib/modules tree. Real BCC compilation is.
        if self._bpf_factory is None:
            assessor = self._kernel_header_assessor or assess_kernel_headers
            self._kernel_header_assessment = assessor()
            if not self._kernel_header_assessment.ready:
                self.degraded_reason = (
                    f"KERNEL_HEADERS_{self._kernel_header_assessment.status}"
                )
                logger.warning(
                    "eBPF degraded: %s; run scripts/resolve_kernel_headers.py "
                    "for a dry-run repair plan",
                    self.degraded_reason,
                )
                return False
        path = Path(self.bpf_program_path)
        if not path.is_file():
            self.degraded_reason = "PROBE_SOURCE_MISSING"
            return False
        try:
            source = path.read_text(encoding="utf-8")
            if "ELYRA_EXEC_FILENAME_FIELD" in source:
                exec_field = self._detect_exec_filename_field()
                if exec_field is None:
                    self.degraded_reason = "TRACEPOINT_FORMAT_UNSUPPORTED:sched_process_exec filename field missing"
                    logger.warning("eBPF degraded: %s", self.degraded_reason)
                    return False
                source = source.replace("ELYRA_EXEC_FILENAME_FIELD", exec_field)
                self._tracepoint_compatibility["sched_process_exec.filename_field"] = exec_field
            else:
                # Tiny injected test probes and externally supplied probes can
                # omit this project-specific template token entirely.  Their
                # BCC source must not be gated on tracefs discovery they do
                # not use.
                self._tracepoint_compatibility["sched_process_exec.filename_field"] = "NOT_REQUIRED"
            detector = self._rename_tracepoint_detector or self._detect_rename_tracepoints
            self._rename_tracepoints = self._normalise_rename_tracepoints(detector())
            if "ELYRA_RENAME_PROBES" in source and not self._rename_tracepoints:
                self.degraded_reason = "TRACEPOINT_FORMAT_UNSUPPORTED:no rename syscall tracepoint available"
                logger.warning("eBPF degraded: %s", self.degraded_reason)
                return False
            source = source.replace("ELYRA_RENAME_PROBES", self._build_rename_probe_source(self._rename_tracepoints))
            self._tracepoint_compatibility["rename.tracepoints"] = ",".join(self._rename_tracepoints)
            self.bpf = factory(text=source)
            self._configure_maps()
            return True
        except Exception as exc:
            self.bpf = None
            self.degraded_reason = f"BCC_LOAD_FAILED:{type(exc).__name__}:{exc}"
            logger.warning("eBPF degraded: %s", self.degraded_reason)
            return False


    @staticmethod
    def _tracepoint_format_paths(category: str, name: str) -> list[Path]:
        relative = Path("events") / category / name / "format"
        return [Path("/sys/kernel/tracing") / relative, Path("/sys/kernel/debug/tracing") / relative]

    @classmethod
    def _detect_exec_filename_field(cls) -> str | None:
        """Return the BCC-generated member for sched_process_exec filename.

        Modern kernels expose ``__data_loc char[] filename`` in tracefs, while
        BCC may generate either ``data_loc_filename`` or the legacy
        ``__data_loc_filename`` member. Pardus 25 uses the former. The optional
        environment override exists only for reproducible compatibility tests.
        """
        override = os.environ.get("ELYRA_EXEC_FILENAME_FIELD")
        if override in {"data_loc_filename", "__data_loc_filename"}:
            return override
        for path in cls._tracepoint_format_paths("sched", "sched_process_exec"):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if re.search(r"field:__data_loc\s+char\[\]\s+filename;", text):
                return "data_loc_filename"
        # The generated BCC field on supported Pardus/Debian kernels.  When
        # tracefs is intentionally hidden (containers, restricted virtual
        # machines, or source-only tests), let BCC perform the final ABI check
        # instead of treating unavailable metadata as proof of incompatibility.
        return "data_loc_filename"


    @classmethod
    def _tracepoint_exists(cls, category: str, name: str) -> bool:
        """Return True only when the tracepoint format is readable.

        Tracefs may be mounted while its event metadata is restricted to root.
        Permission errors are therefore a normal capability result, not an
        exception that should escape into unit tests or generic status checks.
        """
        for path in cls._tracepoint_format_paths(category, name):
            try:
                with path.open("rb") as stream:
                    stream.read(1)
                return True
            except OSError:
                continue
        return False

    @staticmethod
    def _normalise_rename_tracepoints(names: list[str]) -> list[str]:
        """Validate, order and deduplicate rename-family tracepoint names."""
        allowed = ("rename", "renameat", "renameat2")
        requested = set(names)
        return [name for name in allowed if name in requested]

    @classmethod
    def _detect_rename_tracepoints(cls) -> list[str]:
        """Return supported rename-family syscall tracepoints.

        The environment override is intended for deterministic tests only.
        On systems where tracefs cannot be read, the common Linux syscall set
        is used and BCC compilation remains the final compatibility check.
        """
        override = os.environ.get("ELYRA_RENAME_TRACEPOINTS")
        allowed = ("rename", "renameat", "renameat2")
        if override is not None:
            requested = [item.strip() for item in override.split(",") if item.strip()]
            return [item for item in requested if item in allowed]
        return [name for name in allowed if cls._tracepoint_exists("syscalls", f"sys_enter_{name}")]

    @staticmethod
    def _build_rename_probe_source(names: list[str]) -> str:
        templates = {
            "rename": """TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
    struct event_t event = {};
    fill_common(&event, EVENT_FILE_RENAME);
    if (!should_emit(event.tgid, event.uid)) return 0;
    /* User-supplied identifier only; not a verified canonical path. */
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), args->oldname);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}""",
            "renameat": """TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
    struct event_t event = {};
    fill_common(&event, EVENT_FILE_RENAME);
    if (!should_emit(event.tgid, event.uid)) return 0;
    /* User-supplied identifier only; not a verified canonical path. */
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), args->oldname);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}""",
            "renameat2": """TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
    struct event_t event = {};
    fill_common(&event, EVENT_FILE_RENAME);
    if (!should_emit(event.tgid, event.uid)) return 0;
    /* User-supplied identifier only; not a verified canonical path. */
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), args->oldname);
    events.perf_submit(args, &event, sizeof(event));
    return 0;
}""",
        }
        return "\n\n".join(templates[name] for name in names if name in templates)

    def _configure_maps(self) -> None:
        if self.bpf is None:
            return
        try:
            ignored = self.bpf["ignored_tgids"]
            for tgid in self.filter_config.ignored_tgids:
                ignored[struct.pack("I", int(tgid))] = struct.pack("B", 1)
            uids = self.bpf["monitored_uids"]
            for uid in self.filter_config.monitored_uids:
                uids[struct.pack("I", int(uid))] = struct.pack("B", 1)
            cfg = self.bpf["filter_flags"]
            cfg[struct.pack("I", 0)] = struct.pack("I", 1 if self.filter_config.monitored_uids else 0)
        except Exception as exc:
            logger.debug("Map preconfiguration unavailable in mock/older BCC: %s", exc)

    def attach_probes(self) -> bool:
        if self.bpf is None:
            return False
        # TRACEPOINT_PROBE sections are auto-attached by BCC during load.
        attachments = [
            ("kprobe", {"event":"vfs_write", "fn_name":"on_vfs_write"}),
            ("kprobe", {"event":"tcp_v4_connect", "fn_name":"on_tcp_v4_connect"}),
        ]
        attached: list[str] = [
            "sched:sched_process_exec",
            "sched:sched_process_exit",
            *[f"syscalls:sys_enter_{name}" for name in self._rename_tracepoints],
        ]
        try:
            for kind, kwargs in attachments:
                if kind == "tracepoint":
                    self.bpf.attach_tracepoint(**kwargs)
                    attached.append(kwargs["tp"])
                else:
                    self.bpf.attach_kprobe(**kwargs)
                    attached.append(kwargs["event"])
            self._attached_probes = attached
            return True
        except Exception as exc:
            self.degraded_reason = f"PROBE_ATTACH_FAILED:{type(exc).__name__}:{exc}"
            logger.warning("eBPF degraded: %s", self.degraded_reason)
            return False

    def start(self) -> bool:
        if self.bpf is None:
            return False
        try:
            self.bpf["events"].open_perf_buffer(self._on_raw_event, lost_cb=self._on_lost_events)
        except Exception as exc:
            self.degraded_reason = f"PERF_BUFFER_OPEN_FAILED:{type(exc).__name__}:{exc}"
            return False
        self.stop_event.clear()
        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True, name="elyra-ebpf-poll")
        self._poll_thread.start()
        return True

    def _poll_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                break
            except Exception as exc:
                if not self.stop_event.is_set():
                    self.degraded_reason = f"PERF_POLL_FAILED:{type(exc).__name__}:{exc}"
                    logger.warning("eBPF polling stopped: %s", self.degraded_reason)
                break

    def _on_lost_events(self, *callback_args: int) -> None:
        """Handle BCC perf-buffer loss callbacks across supported API variants.

        Pardus 25's packaged BCC calls ``lost_cb(lost_count)`` while some BCC
        releases call ``lost_cb(cpu, lost_count)``.  Accept both signatures so
        the callback never raises inside ctypes and floods the system journal.
        """
        if len(callback_args) == 1:
            count = callback_args[0]
        elif len(callback_args) == 2:
            _cpu, count = callback_args
        else:
            logger.error(
                "Unexpected BCC lost-event callback signature: %d arguments",
                len(callback_args),
            )
            return

        try:
            lost_count = int(count)
        except (TypeError, ValueError):
            logger.error("Invalid BCC lost-event count ignored: %r", count)
            return
        if lost_count < 0:
            logger.error("Negative BCC lost-event count ignored: %s", lost_count)
            return

        self._dropped_events += lost_count
        logger.warning("eBPF perf events lost: %s", lost_count)

    def _on_raw_event(self, _cpu: int, data: Any, _size: int) -> None:
        try:
            raw = self.bpf["events"].event(data)
            event = self.decode_event(raw)
            if event is not None:
                self.publish_event(event)
        except Exception as exc:
            logger.debug("Invalid eBPF event ignored: %s", exc)

    @staticmethod
    def _decode_c_string(value: Any) -> str:
        if isinstance(value, bytes):
            return value.split(b"\0", 1)[0].decode("utf-8", "replace")
        return str(value or "")

    @classmethod
    def decode_event(cls, raw: Any) -> EbpfEvent | None:
        try:
            kind = EventType(int(raw.event_type))
        except (ValueError, TypeError, AttributeError):
            return None
        names = {
            EventType.PROCESS_EXEC: "PROCESS_EXEC",
            EventType.PROCESS_EXIT: "PROCESS_EXIT",
            EventType.FILE_WRITE: "FILE_WRITE",
            EventType.FILE_RENAME: "FILE_RENAME",
            EventType.NETWORK_CONNECT: "NETWORK_CONNECT",
        }
        daddr = None
        dport = None
        if kind == EventType.NETWORK_CONNECT:
            packed = struct.pack("!I", socket.ntohl(int(getattr(raw, "daddr", 0))))
            daddr = str(ipaddress.ip_address(packed))
            dport = socket.ntohs(int(getattr(raw, "dport", 0)))
        executable = cls._decode_c_string(getattr(raw, "filename", b"")) or None
        return EbpfEvent(
            event_type=names[kind], timestamp_ns=int(getattr(raw, "timestamp_ns", 0)),
            pid=int(getattr(raw, "pid", 0)), tgid=int(getattr(raw, "tgid", 0)),
            ppid=int(getattr(raw, "ppid", 0)), uid=int(getattr(raw, "uid", 0)),
            comm=cls._decode_c_string(getattr(raw, "comm", b"")),
            executable_identifier=executable,
            exit_code=int(getattr(raw, "exit_code", 0)) if kind == EventType.PROCESS_EXIT else None,
            device=int(getattr(raw, "device", 0)) if kind in {EventType.FILE_WRITE, EventType.FILE_RENAME} else None,
            inode=int(getattr(raw, "inode", 0)) if kind in {EventType.FILE_WRITE, EventType.FILE_RENAME} else None,
            destination_address=daddr, destination_port=dport,
        )

    def publish_event(self, event: EbpfEvent) -> bool:
        if event.event_type == "FILE_RENAME":
            fingerprint = (event.tgid, event.uid, event.executable_identifier or "")
            previous = self._recent_rename_events.get(fingerprint)
            if previous is not None and event.timestamp_ns - previous <= self._rename_dedup_window_ns:
                return False
            self._recent_rename_events[fingerprint] = event.timestamp_ns
            self._recent_rename_events.move_to_end(fingerprint)
            cutoff = event.timestamp_ns - self._rename_dedup_window_ns
            while self._recent_rename_events:
                _, oldest = next(iter(self._recent_rename_events.items()))
                if oldest >= cutoff:
                    break
                self._recent_rename_events.popitem(last=False)
        if event.event_type == "PROCESS_EXEC":
            self._ancestry[event.tgid] = event.ppid
            self._ancestry.move_to_end(event.tgid)
            while len(self._ancestry) > self.filter_config.max_tracked_processes:
                self._ancestry.popitem(last=False)
        accepted = self.filter_config.accepts(event, self._ancestry)
        if event.event_type == "PROCESS_EXIT":
            self._ancestry.pop(event.tgid, None)
        if not accepted:
            return False
        record = event.to_dict()
        record["distinct_file_key"] = (
            f"{event.device}:{event.inode}" if event.device is not None and event.inode is not None else None
        )
        try:
            self.event_queue.put_nowait(record)
            return True
        except queue.Full:
            self._dropped_events += 1
            logger.warning("eBPF user-space queue full; event dropped")
            return False

    def get_event(self, timeout: float = 0.5) -> dict[str, Any] | None:
        try:
            return self.event_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def status(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "degraded_reason": self.degraded_reason,
            "attached_probes": list(self._attached_probes),
            "dropped_events": self._dropped_events,
            "queued_events": self.event_queue.qsize(),
            "path_capability": "IDENTIFIER_ONLY_FOR_FILE_EVENTS",
            "tracepoint_compatibility": dict(self._tracepoint_compatibility),
            "rename_tracepoints": list(self._rename_tracepoints),
            "rename_dedup_window_ns": self._rename_dedup_window_ns,
            "exit_code_capability": "NOT_EXPOSED_BY_PORTABLE_SCHED_PROCESS_EXIT",
            "kernel_header_compatibility": (
                self._kernel_header_assessment.to_dict()
                if self._kernel_header_assessment is not None
                else None
            ),
        }

    def stop(self) -> None:
        self.stop_event.set()
        if self._poll_thread and self._poll_thread.is_alive():
            self._poll_thread.join(timeout=2.0)
        self._poll_thread = None
