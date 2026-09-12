# Final Verification Matrix

| Capability | Source/tests | Pardus/kernel evidence | Final status |
|---|---|---|---|
| Entropy and static analysis | Unit tests | Stage 3 benchmark | Verified |
| Explainable scoring | Unit tests | Stage 4 demo | Verified, thresholds provisional |
| Quarantine/restore | Unit tests | Stage 5 demo | Verified |
| Secure IPC | Unit/integration tests | Stage 6 demo | Verified |
| GUI official API | Tests | Stage 7 GUI evidence | Verified |
| fanotify | Unit tests | Stage 8.1 root verifier | Verified on Pardus |
| eBPF telemetry | Unit tests | Stage 9.2.1 root verifier | Verified on Pardus |
| Runtime correlation | Unit tests | Stage 10 demo | Verified |
| Response engine | Unit tests | Stage 11 demo | Verified with harmless child |
| Audit logging | Unit tests | Stage 12 demo | Verified within threat model |
| systemd/install | Contract tests | Stage 13.1 installed check | Verified |
| Full workflow | 223 Stage 14.1 tests / coverage | Stage 14.1 installed workflow | Verified in monitor-only mode |
| Final release controls | 254 Stage 15.2 tests | Manifest/archive/package contracts | Verified generically; rerun on Pardus |
| Controlled live malware | Not part of normal tests | Separate authorised lab only | Not completed/not claimed |
