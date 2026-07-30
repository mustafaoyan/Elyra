# Stage 9.1 Pardus kernel compatibility audit

## Confirmed Stage 9 failures on Pardus 25

| Defect | Severity | Effect | Stage 9.1 correction |
|---|---|---|---|
| `bpf_get_current_ppid()` was called although no such BPF helper exists | Critical | BCC compilation failed | Read `task_struct.real_parent->tgid` with `bpf_probe_read_kernel` |
| Probe assumed BCC member `__data_loc_filename` | Critical | `sched_process_exec` failed to compile on Linux 6.12 | Detect the tracepoint format and substitute `data_loc_filename` on Pardus 25 |
| Probe assumed `sched_process_exit.exit_code` exists | Critical | Exit probe failed to compile | Emit a portable exit event without claiming an exit code |
| Compatibility detail was not exposed in status | Medium | Degraded behaviour was hard to diagnose | Report selected filename member and exit-code capability |

The user-space event model remains unchanged. An exit event's `exit_code` is now
explicitly unavailable rather than fabricated. Full file paths are still not claimed for
write and rename activity.
