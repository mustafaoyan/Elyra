# Stage 8 fanotify audit

Scope: `src/elyra/monitor/fanotify/`, its static-analysis adapter, and the daemon ownership boundary. No eBPF, response-engine, systemd, or production installation claim is made here.

| Classification | Confirmed issue in Stage 7 | Previous file and line | Severity | Effect | Stage 8 correction |
|---|---|---:|---|---|---|
| Confirmed defect | Only the first metadata record from each `read(2)` buffer was processed | `syscalls.py:47-68` | Critical | Concurrent execution events in the same kernel buffer could be ignored and their descriptors left unanswered | Parse every complete metadata record and expose queue-overflow records explicitly |
| Confirmed defect | Permission-response write failures and close failures were silently swallowed | `syscalls.py:70-82` | Critical | The daemon could claim a decision even when no valid response reached the kernel | Return response success, log critical failure, and always close the event descriptor exactly once |
| Confirmed defect | Event metadata version, event length, permission mask, truncation, and overflow were not validated | `syscalls.py:47-68` | High | Invalid or unexpected kernel data could be treated as a normal execution request | Validate metadata version 3, lengths, mask, truncation, and `FAN_Q_OVERFLOW` |
| Confirmed defect | `startswith` was used for monitored/excluded paths | `policy.py:45-57` | High | `/tmp/a` could incorrectly match `/tmp/ab`; exclusion boundaries were unreliable | Use normalized `commonpath` containment checks |
| Architectural inconsistency | Enforcement and selected high-risk `FAIL_CLOSED` behaviour were enabled by default | `policy.py:6-7,59-71` | Critical | A development build could deny execution before Pardus laboratory validation | Default to `MONITOR_ONLY` and `FAIL_OPEN`; fail-closed paths must be configured explicitly |
| Incomplete feature | Mount marks were repeated for paths on the same filesystem | `controller.py:27-30`, `syscalls.py:38-45` | Medium | Duplicate mark operations and misleading path-level assumptions | De-duplicate production mount marks by device identifier and continue filtering every event in user space |
| Confirmed defect | Event submissions used an unbounded executor queue | `controller.py:17,42-47` | High | A burst of execution requests could accumulate indefinitely and delay permission responses | Add a bounded pending-event semaphore; saturation gets an immediate critical fail-open response |
| Confirmed defect | There was no final response guard around the complete event-handling function | `controller.py:49-98` | Critical | Exceptions outside the inner analysis block could leave an execution request waiting | Add a `finally` response guard and explicit response-result recording |
| Incomplete feature | Queue wait time was not included in the response deadline | `controller.py:58-80` | High | A valid analysis result could arrive after the permission deadline | Use event receipt time, remaining deadline, and a post-analysis deadline check |
| Architectural inconsistency | Path-based analysis was used after fanotify supplied an open descriptor | `controller.py:58-59` | High | The pathname could be replaced between interception and analysis | Analyse bytes and metadata through the open event descriptor; use the resolved pathname only for extension/location context |
| Incomplete feature | ELYRA excluded only its exact daemon PID | `controller.py:50-52` | Medium | Helper descendants could recursively trigger monitoring | Add bounded `/proc` ancestry exclusion and installation/data/log path exclusion |
| Incomplete feature | Large-file behaviour was undefined | — | Medium | Long analysis could hold permission events beyond a safe deadline | Add a configurable pre-execution size limit with visible `LARGE_FILE_DEFERRED_FAIL_OPEN` degradation |
| Incomplete feature | Script/interpreter execution was not classified or evidenced | — | Medium | GUI/audit records could not distinguish ELF from shebang scripts | Classify the open event descriptor as `ELF`, `SCRIPT`, `OTHER`, or `UNREADABLE`; actual kernel behaviour remains a Pardus/root verification item |
| Incomplete feature | Decisions were queued but not guaranteed to enter the audit log | `controller.py:90-98` | High | Acceptance criterion “all decisions are logged” was not supported | Record each decision through `AuditLogger` and also publish it to the daemon event queue |

## Exact event and mark model

- Permission event: `FAN_OPEN_EXEC_PERM`.
- Production interface class: `FAN_CLASS_PRE_CONTENT` with nonblocking and close-on-exec flags.
- Production mark scope: mount marks, de-duplicated by device. This is not described as path-recursive marking; user-space policy filters the mount events to the configured monitored paths.
- Laboratory verifier mark scope: one inode directory mark with `FAN_EVENT_ON_CHILD`, limited to direct harmless fixtures in one temporary directory.

## Verified before Pardus/root testing

- Source compilation on generic Linux.
- 105 automated tests.
- Whole-buffer metadata parsing.
- Deterministic monitor/enforcement policy projection.
- High-level allow/deny response paths through a fake syscall boundary.
- Deadline and queue-saturation fail-open paths.
- Separate event and analysis execution resources.
- Open-descriptor static and entropy analysis.
- Self/path exclusion, large-file degradation, concurrency, and audit recording.

## Not yet verified

- `fanotify_init(2)` privileges and `FAN_OPEN_EXEC_PERM` support on the target Pardus kernel.
- Real harmless ELF allow, real safe suspicious ELF denial, and real shebang-script event behaviour.
- Production mount-mark volume and resource use.
- Behaviour across all filesystems, removable media, overlays, and network filesystems.
- systemd restart and root-owned production directories.
- eBPF runtime correlation.
