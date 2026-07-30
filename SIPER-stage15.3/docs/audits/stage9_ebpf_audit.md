# Stage 9 eBPF Audit

| Issue | Previous location | Severity | Effect | Stage 9 fix |
|---|---|---:|---|---|
| Probe event structures were incompatible but shared one perf buffer | `probes.c`, `collector.py` | Critical | User space could decode fields using the wrong layout | One tagged event structure and explicit event type |
| Collector used a nonexistent blocking `event_reader()` API | `collector.py` | Critical | Runtime collection could not operate | BCC perf-buffer callback and polling loop |
| Kernel hooks were attached to unstable or incorrect symbols | `collector.py` | High | Load/attach failures across kernels | sched/syscall tracepoints plus limited kprobes, with explicit degraded mode |
| No file-write or rename telemetry | `probes.c` | High | Required event set incomplete | Selected VFS write and rename syscall telemetry |
| File writes were implicitly treated as paths | previous schema | High | Unsupported full-path claims | Device/inode identifiers; rename is labelled a user-supplied identifier |
| Every TCP connection could add a large risk score | old collector/runtime engine | High | Uncalibrated automatic termination risk | Collector emits telemetry only; no killing, quarantine or scoring in eBPF |
| Collector could terminate and quarantine processes directly | `collector.py` | Critical | Unsafe PID-reuse/path-replacement exposure | Removed all response actions from Stage 9 collector |
| Distinct files were not counted correctly | old runtime scoring | Medium | Write calls could be confused with unique files | Bounded user-space set keyed by device/inode |
| Process cleanup lacked bounded state | collector/runtime engine | Medium | Long-running daemon could grow indefinitely | TTL and maximum-state eviction without per-process threads |
| BCC failures raised into startup | loader | High | Daemon could fail instead of degrading | Boolean initialization and explicit reason/status |
| Collection was effectively system-wide | old probes | High | Excessive volume and privacy/resource risk | UID and ignored-TGID maps plus user-space TGID/ancestry filtering |

## Verification boundary

Automated tests verify decoding, filtering, aggregation, bounded state, source contracts and degraded mode. Actual kernel attachment and event delivery remain unverified until the controlled Pardus root verifier succeeds.
