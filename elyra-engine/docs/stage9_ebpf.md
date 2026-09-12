# Stage 9.2 — eBPF Runtime Telemetry

Stage 9.2 collects only selected runtime telemetry:

- process execution and exit;
- PID, TGID, PPID, UID, command name, timestamp and executable identifier;
- selected file writes using device/inode identifiers;
- rename attempts using a user-supplied identifier, not a canonical-path claim;
- IPv4 outbound connection attempts.

No entropy calculation, complex scoring, process termination, quarantine or restoration occurs inside eBPF or the collector. Those functions remain in user space and later response stages.

The collector has an explicit degraded mode for missing BCC bindings, compile failures, unsupported probes, perf-buffer failures and polling failures.


## Stage 9.2 rename compatibility

The loader detects and injects probes for every supported rename-family syscall tracepoint (`rename`, `renameat`, and `renameat2`). User space deduplicates equivalent rename records within a 10 ms window. The real verifier exercises both libc `rename(2)` and Python `os.rename` using harmless temporary files.
