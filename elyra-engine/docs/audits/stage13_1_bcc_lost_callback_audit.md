# Stage 13.1 — Pardus BCC lost-event callback compatibility audit

## Confirmed production defect

| Issue | File and line before repair | Severity | Effect | Repair |
|---|---|---:|---|---|
| The eBPF perf-buffer lost-event callback required `(cpu, count)`, but Pardus 25 BCC invokes `lost_cb(count)` | `src/elyra/monitor/ebpf/collector.py`, `_on_lost_events` | High | Every lost-event notification raised `TypeError` inside the ctypes callback and flooded `journalctl`, while dropped-event accounting was unavailable | Accept and validate both the one-argument Pardus signature and the two-argument BCC variant |

## Scope

This repair changes only callback compatibility and regression coverage. It does not alter eBPF probes, fanotify policy, scoring, response actions, IPC, installation paths, or systemd safe defaults.

## Verification

- One-argument callback updates the dropped-event counter.
- Two-argument callback remains compatible.
- The callback registered through `open_perf_buffer` can be invoked exactly as Pardus BCC invokes it.
- Invalid callback shapes are rejected without throwing into ctypes.
- The complete automated suite must pass as an unprivileged user before reinstallation.
- After reinstallation, the service journal from the new activation must not contain the prior `missing 1 required positional argument: 'count'` traceback.
