# Changelog

## 1.0.0 — Final controlled competition release

- Completed canonical entropy, MIME, ELF and permission analysis.
- Added deterministic explainable scoring with configurable provisional rules.
- Added protected quarantine/restore transactions and SHA-256 verification.
- Replaced TCP/mock IPC with versioned protected Unix-domain-socket IPC.
- Connected the unprivileged GUI to real daemon data.
- Verified real Pardus fanotify pre-execution allow/deny behaviour.
- Verified filtered BCC/eBPF process, file, rename and network telemetry.
- Added fanotify/eBPF runtime correlation and reachable response transitions.
- Added authorised pidfd terminate, quarantine and restore operations.
- Added structured, rotating, tamper-evident audit logging.
- Added versioned systemd installation and production verification.
- Added complete integrated Pardus workflow verification.
- Added final evidence manifest, release archives, wheel and Pardus Debian
  package builder.

Compatibility fixes included Pardus fanotify verifier watchdog handling, Pardus
6.12 tracepoint layouts, rename-family probes, tracefs test isolation, BCC lost
event callback signatures and runtime-state IPC authorisation.

## Stage 15.2

- derive Stage 4 scoring evidence `overall_status` from explicit scenario checks;
- reject entropy-only denial, missing/duplicate scenarios and unstructured results;
- add regression tests and document the evidence-schema compatibility repair.

- Siper public branding added while preserving the verified internal `elliot` namespace for backward compatibility.
- Added `python3-pil.imagetk` to Pardus packaging dependencies so the installed GUI opens on a clean system.
