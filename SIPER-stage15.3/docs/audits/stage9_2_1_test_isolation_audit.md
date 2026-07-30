# Stage 9.2.1 Test-Isolation Audit

## Confirmed defect

`tests/unit/test_ebpf_collector.py::test_load_attach_and_status` instantiated the
collector with a fake BCC factory but still allowed rename tracepoint discovery
to inspect the host `/sys/kernel/tracing` tree. On Pardus, the normal user could
not read the syscall tracepoint format file, causing a host-permission-dependent
unit-test failure.

## Correction

- Added an injectable rename-tracepoint detector to `EBPFCollector`.
- The affected unit test supplies a deterministic synthetic capability set.
- Tracepoint existence now requires readable format metadata and catches
  `OSError`, including `PermissionError`.
- Runtime discovery no longer guesses that all rename tracepoints exist when
  tracefs cannot be read.
- Added regression tests proving that permission errors are treated as a
  capability result and that unit tests do not access host tracefs.

## Scope

No eBPF event schema, probe body, filtering rule, aggregation rule or verifier
scenario was changed. The real root verifier remains the authority for Pardus
kernel support.
