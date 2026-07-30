# ELLIOT Stage 1 Repository Audit

Audit basis: `Siper-main3(2).zip` and the supplied ELLIOT Çalışma Planı.
This audit separates source-confirmed defects from incomplete or kernel-dependent work.

## Confirmed defects in the uploaded repository

| Issue | Original file and line | Severity | Effect | Stage 1 fix |
|---|---:|---|---|---|
| Invalid placeholder import | `src/daemon/loader.py:1` | Critical | `compileall` fails; loader cannot be imported | Replaced with explicit package-relative imports and a concrete `EBPFLoader` |
| Daemon imports packages that do not exist | `src/daemon/daemon.py:10-19` | Critical | Daemon cannot be imported or started | Created `src/elliot/` package tree and corrected imports |
| Daemon expects fanotify APIs absent from the included controller | `src/daemon/daemon.py:60-80`; `src/daemon/controller.py:11-35` | High | Constructor/startup contract is inconsistent | Reworked only the daemon ownership layer to call the existing `baslat/durdur` API; internal fanotify logic unchanged |
| Daemon expects eBPF classes and callbacks absent from the included collector | `src/daemon/daemon.py:64,82-85,120-140`; `src/daemon/collector.py:13-15,71-128` | High | eBPF integration cannot start as written | Added a concrete loader boundary and basic event-queue ownership; Stage 9 behaviour remains unverified |
| BCC is imported unconditionally | `src/daemon/collector.py:8` | High | Any module import fails on systems without BCC Python bindings | Made BCC an optional system dependency at import time; loading fails explicitly in degraded mode |
| Python package imports rely on `sys.path` mutation and top-level package names | `src/gui/main.py:4-13`; `src/gui/controllers/pardus_controllers.py:5-6` | High | GUI import depends on current working directory | Replaced with package-relative imports and a module entry point |
| Three incompatible GUI/daemon communication paths coexist | `src/gui/controllers/pardus_controllers.py:18-23`; `src/gui/models/pardus_models.py:8-23`; `src/gui/socked_server.py:10,30-35`; `src/daemon/collector.py:15,47-54` | High | GUI and daemon do not share one authoritative API; `/tmp` listener is world writable | Preserved for later controlled Stage 6-7 repair but isolated under one package and explicitly marked unverified |
| systemd `ExecStart` targets a nonexistent source path | `src/daemon/daemon.service:9` | High | Service cannot start | Pointed service to `python -m elliot.service.daemon` with the installed `src` path |
| Installer copies a service and launches a GUI file that do not exist at the stated paths | `kurulum.sh:34-48,57-62` | High | Installation completes incorrectly or fails | Updated installation paths, service name and GUI launcher to the Stage 1 structure |
| README is empty | `README.md` (0 bytes) | Medium | No project identity, status or safe-use warning | Added a Stage 1 status README without completion claims |
| GUI settings file is empty JSON | `src/gui/ayarlar.json` (0 bytes) | Medium | JSON parsing fails and is silently discarded | Removed the invalid source-tree settings file; GUI settings storage is deferred to Stage 7 |
| File named as a test is not a pytest test and performs online threat-feed loading/full-system scanning | `test_scanner.py:11-35,91-120` | Medium | Unsafe/non-reproducible test discovery and scope drift | Removed from the active repository; no malware or hash-feed download test is retained |
| Duplicate entropy/static/scoring implementations | `src/daemon/analyzer.py:71-145`; `src/daemon/scanner.py:28-85,97-193,213-284`; `src/daemon/scoring.py:7-76` | Medium | Conflicting thresholds, result schemas and ownership | Mapped into explicit modules without claiming canonicalisation; Stage 3-4 must select and test the canonical implementations |
| GUI generates random entropy values presented as live values | `src/gui/views/pardus_views.py:91-100` | High | Misrepresents synthetic values as measured telemetry | Not changed in Stage 1; must be removed or clearly labelled in Stage 7 |
| Placeholder repository URL in systemd metadata | `src/daemon/daemon.service:3` | Low | Invalid documentation reference | Removed |
| No `pyproject.toml` and no import-structure tests | repository root | Medium | Package cannot be installed/import-checked coherently | Added minimal package metadata and structural tests |

## Incomplete features, not Stage 1 completion claims

- Canonical entropy/static-analysis implementation and error model.
- Explainable configurable scoring engine.
- Secure quarantine transaction and restoration semantics.
- One secure, versioned daemon-GUI IPC schema.
- Real GUI values and functional callbacks.
- fanotify timeout/concurrency/permission-response guarantees.
- eBPF probe correctness, filtering and event correlation.
- Pre-execution/runtime state model and response actions.
- Audit rotation, startup verification and crash safety.
- Final dependency, systemd, installer and Pardus evidence validation.

## Unverified Pardus/kernel-dependent behaviour

- `FAN_OPEN_EXEC_PERM` availability and mark semantics on the target Pardus kernel.
- Root/capability requirements and fail-open/fail-closed behaviour.
- BCC/BPFCC package naming and probe attachment on the target kernel.
- eBPF event decoding, path claims, process filtering and performance.
- systemd service startup and runtime-directory ownership.
- GUI display operation under the target Pardus desktop session.

## Existing-file to Stage 1 architecture mapping

| Uploaded path | Stage 1 path | Status |
|---|---|---|
| `src/daemon/analyzer.py` | `src/elliot/analyzer/pre_execution.py` | Preserved; canonicalisation deferred |
| `src/daemon/scanner.py` | `src/elliot/analyzer/static_analyzer.py` | Preserved; entropy/static/scoring split deferred |
| `src/daemon/scoring.py` | `src/elliot/scoring/runtime_engine.py` | Preserved; redesign deferred |
| `src/daemon/controller.py` | `src/elliot/monitor/fanotify/controller.py` | Imports/name fixed |
| `src/daemon/policy.py` | `src/elliot/monitor/fanotify/policy.py` | Moved; policy review deferred |
| `src/daemon/fanotify_syscalls.py` | `src/elliot/monitor/fanotify/syscalls.py` | Moved; kernel verification deferred |
| `src/daemon/loader.py` | `src/elliot/monitor/ebpf/loader.py` | Syntax/import defect repaired |
| `src/daemon/collector.py` | `src/elliot/monitor/ebpf/collector.py` | Optional BCC import; behaviour deferred |
| `src/daemon/probes.c` | `src/elliot/monitor/ebpf/probes.c` | Naming fixed; probe review deferred |
| `src/daemon/quarantine_manager.py` | `src/elliot/response/quarantine_manager.py` | Moved; security review deferred |
| `src/daemon/daemon.py` | `src/elliot/service/daemon.py` | Entry/import ownership repaired |
| `src/daemon/ipc_server.py` | `src/elliot/service/ipc_server.py` | Moved; schema/security review deferred |
| `src/daemon/authorization.py` | `src/elliot/service/authorization.py` | Moved; group model review deferred |
| `src/daemon/audit_logger.py` | `src/elliot/audit/audit_logger.py` | Moved; integrity/rotation review deferred |
| `src/gui/**` | `src/elliot/gui/**` | Package imports/naming repaired; integration deferred |
| `src/daemon/daemon.service` | `packaging/systemd/elliot.service` | Path/name repaired; not run on Pardus |
| `kurulum.sh` | `scripts/install.sh` | Path/name repaired; not run on Pardus |
| `test_scanner.py` | removed | Not an assertion-based test; outside agreed ELLIOT workflow |

## Stage 1 verification

| Check | Result | Classification |
|---|---|---|
| `python3 -m compileall -q src` | Passed | Verified by automated test on generic Linux |
| Import every `elliot.*` Python module | Passed | Verified by automated test on generic Linux |
| Active source filenames contain no `Siper` naming | Passed | Verified by automated test |
| `bash -n scripts/install.sh scripts/launch_gui.sh` | Passed | Verified by syntax inspection only |
| fanotify runtime | Not run | Requires Pardus/root/kernel verification |
| eBPF runtime | Not run | Requires Pardus/root/kernel verification |
| GUI runtime | Not run | Requires Pardus/desktop/dependency verification |
| systemd installation | Not run | Requires Pardus/root verification |
