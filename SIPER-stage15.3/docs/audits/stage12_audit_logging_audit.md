# Stage 12 Audit-Logging Audit

| Confirmed issue | Previous file/behaviour | Severity | Stage 12 correction |
|---|---|---:|---|
| Startup trusted only the final line | `audit_logger.py::_load_last_hash` | Critical | Verify every retained record and segment before accepting the chain |
| Exceptions during startup were silently ignored | broad `except Exception: pass` | Critical | Raise `AuditIntegrityError` or preserve corrupt logs under an explicit recovery policy |
| Appends were not crash-synchronised | text-mode append without `fsync` | High | `O_APPEND`, complete encoded line, file `fsync`, and directory `fsync` |
| Log path could be a symbolic link | ordinary `open()` | High | Reject symlinks and use `O_NOFOLLOW` where supported |
| File mode was not enforced | ordinary text file creation | High | Directory `0750`, audit file `0640`, lock file `0600` |
| No rotation or retention model | one indefinitely growing file | High | Atomic numbered rotation with bounded retention and cross-segment chaining |
| Retention could lead to false full-chain claims | not implemented | High | Report `RETAINED_WINDOW` when genesis segments are no longer retained |
| Multi-process writers could race | thread lock only | High | Add protected `flock` inter-process serialisation and refresh the tail state |
| Final partial write had no recovery path | invalid JSON stopped manual parsing | High | Preserve partial bytes, truncate to the last complete record, then verify the chain |
| Payload conversion was shallow | top-level values only | Medium | Recursively preserve mappings, sequences, paths, bytes and dataclasses as structured JSON |
| Hash-chain limitations were not stated | no threat-model statement | Medium | Explicitly state that a privileged attacker can replace and recompute the full log set |
| Daemon status did not expose audit integrity | `get_status` omitted audit state | Medium | Include protected audit status and startup integrity report in the official IPC status |

## Verification boundary

Stage 12 verifies the audit subsystem on temporary generic-Linux/Pardus paths.
Production ownership and group behaviour under `/var/log/elliot` remain part of
the installed root-daemon verification in Stage 13.
