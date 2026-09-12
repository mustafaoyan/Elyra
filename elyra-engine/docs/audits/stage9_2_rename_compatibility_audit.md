# Stage 9.2 rename compatibility audit

| Defect | Severity | Effect | Correction |
|---|---|---|---|
| Only `sys_enter_renameat2` was observed | High | Pardus/Python could use another rename syscall, so no event matched | Detect and inject `rename`, `renameat`, and `renameat2` probes supported by the running kernel |
| Verifier used only one rename wrapper | Medium | Test did not prove syscall-family compatibility | Exercise libc `rename(2)` and Python `os.rename` |
| Multiple compatible probes could duplicate records | Medium | Runtime counters could over-count | Deduplicate matching rename records in user space within 10 ms |

No malware, external network, termination, quarantine, or persistence action is used.
