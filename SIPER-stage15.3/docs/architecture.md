# Architecture

## Privilege separation

`elliot-daemon` runs as root because fanotify, BCC/eBPF and protected response
operations require privileges. `elliot-gui` runs as the desktop user. The only
supported transport is `/run/elliot/elliot.sock`, owned by root and the
`elliot` group with mode `0660`. Linux `SO_PEERCRED` identifies the connecting
PID, UID and GID.

## Static analysis

The analyser reads the kernel-provided descriptor when available and extracts:
whole-file entropy, block entropy, MIME evidence, extension consistency, ELF
sections/segments, permissions and path context. It returns evidence rather than
a malware verdict.

## Pre-execution control

fanotify uses `FAN_OPEN_EXEC_PERM`. Event handling and static analysis use
separate bounded execution resources. Every event receives a response. Timeout
or queue saturation follows the configured fail-open policy and is audited.

## Runtime telemetry

BCC/eBPF probes emit process execution/exit, selected file writes, rename-family
operations and outbound IPv4 connection attempts. Kernel probes collect minimal
data; filtering, deduplication, correlation and scoring occur in user space.

## Correlation and response

The correlation engine links the analysed executable, fanotify PID, eBPF
identity and child processes. Pre-execution and runtime scores remain separate
and produce a bounded combined score. The response engine performs only actions
permitted by policy and authorisation, using pidfds and file identity checks to
reduce PID reuse and path replacement risk.

## Audit and GUI

All decisions and actions produce structured audit records. The GUI consumes
only official IPC responses and displays unavailable data as unavailable.
