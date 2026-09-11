# ELLIOT AI Context Blueprint

<!-- ELLIOT_AI_CONTEXT:v11 | local-first | repository-root | windows:PAUSED | linux:L7_READY_NATIVE_EVIDENCE_PENDING -->

```json
{
  "project": "ELLIOT – Siper Antivirus",
  "purpose": "Local-first, explainable zero-day signal detection and controlled endpoint response.",
  "repository_root": ".",
  "primary_source_root": "SIPER-stage15.3",
  "public_name": "Siper",
  "engineering_name": "ELLIOT",
  "security_invariants": [
    "No cloud management, remote event logging, analytics, or endpoint telemetry in this release.",
    "High entropy is evidence, not proof of malware and cannot alone cause a deny decision.",
    "Linux enforcement and Windows user-space monitoring must be labelled accurately; never claim an unavailable kernel capability.",
    "Automatic destructive responses require explicit policy and authorization."
  ],
  "status_contract": {
    "linux_live_capacity": "Run scripts/test_linux_capacity.py --live as root on a compatible Linux host.",
    "windows_runtime": "Default ReadDirectoryChangesW notifications feed shared static analysis. ETW is an explicitly injected adapter only. No signed minifilter is shipped; MONITOR_ONLY.",
    "phase_1": "COMPLETE. Shared static-analysis foundation; see ELLIOT_ROADMAP.md and SIPER-stage15.3/docs/phase1-verification.md for acceptance evidence.",
    "phase_2": "NOT_STARTED; Windows work paused at W1 and requires separate user approval.",
    "windows_status": "PAUSED_AT_W1_HANDOFF",
    "linux_status": "L7_RELEASE_GATE_READY_NATIVE_EVIDENCE_PENDING",
    "linux_roadmap": "ELLIOT_LINUX_ROADMAP.md; L0 baseline is prepared but not Linux-native verified",
    "ai_handoff_index": "AI.md",
    "landing": "Static site in landing/; GitHub Pages workflow publishes it after a successful main-branch run.",
    "release_assets": "Do not represent placeholder URLs as published installers. Build, sign, checksum, upload, then configure landing/assets/js/download-config.js."
  }
}
```

## Architectural tree

```text
Siper-Antivirus/
├── README.md                         # Public project and deployment entry point
├── ELLIOT_AI_CONTEXT.md              # This machine-readable/human-readable blueprint
├── AI.md                              # GitHub-visible continuation index
├── ELLIOT_ROADMAP.md                 # Eight milestones; only M1 authorized for implementation
├── ELLIOT_LINUX_ROADMAP.md            # Linux-only plan; gated by “başla”
├── landing/                          # Dependency-free static download site
│   ├── index.html
│   ├── assets/css/styles.css
│   ├── assets/js/app.js
│   └── assets/js/download-config.js  # Release asset URL configuration only
├── .github/workflows/
│   ├── deploy-landing.yml             # Static GitHub Pages deployment
│   └── verify.yml                     # Ubuntu + Windows platform-aware test matrix
├── kurulum/                          # Existing Debian package and installation notes
└── SIPER-stage15.3/
    ├── src/elliot/
    │   ├── analyzer/
    │   │   ├── entropy.py             # Canonical Shannon entropy engine
    │   │   ├── static_analyzer.py     # MIME, ELF/PE, permissions, path and entropy evidence
    │   │   ├── pe.py                  # Bounded PE32/PE32+ headers/sections; not signature trust
    │   │   └── pre_execution.py
    │   ├── scoring/engine.py          # Deterministic, explainable scoring
    │   ├── monitor/
    │   │   ├── fanotify/              # Linux pre-execution monitor/enforcement path
    │   │   ├── ebpf/                  # Linux BCC/eBPF telemetry and header resolver
    │   │   └── windows/               # Local notifications; no execution enforcement
    │   │       ├── analysis.py        # Shared static scan + heuristic score + assessment
    │   │       ├── entropy.py         # Backward-compatible entropy-only adapter
    │   │       ├── policy.py          # Queue/size/retry limits and local-path policy
    │   │       ├── backends.py        # Injected ETW boundary / native directory notifications
    │   │       └── controller.py      # Bounded work admission and local event records
    │   ├── correlation/engine.py      # Linux pre-execution/runtime state correlation
    │   ├── response/                  # Authorized Linux response and quarantine controls
    │   ├── audit/                     # Local tamper-evident JSONL audit chain
    │   ├── service/
    │   │   ├── daemon.py              # Linux privileged daemon and Unix-socket API
    │   │   └── windows_local.py       # Windows in-process, local-only GUI service facade
    │   └── gui/                       # CustomTkinter local desktop dashboard
    ├── scripts/
    │   ├── linux_baseline.py          # L0 read-only host capability snapshot
    │   ├── resolve_kernel_headers.py  # Dry-run by default; --apply requires root
    │   ├── test_linux_capacity.py     # Portable + optional harmless live-capacity assertions
    │   └── build_windows_release.py   # PyInstaller + Inno Setup local release builder
    ├── packaging/windows/             # Windows executable and installer definitions
    ├── tests/unit/                    # Platform-safe contract tests
    └── docs/                          # Architecture, operations and verified evidence
```

## Tech stack

```json
{
  "language": "Python >= 3.10",
  "desktop_gui": "CustomTkinter + Matplotlib",
  "linux_monitoring": ["fanotify", "BCC/eBPF", "tracefs", "Linux kernel headers"],
  "windows_monitoring": ["ETW adapter boundary", "signed-minifilter adapter boundary", "ReadDirectoryChangesW fallback", "optional PyWin32"],
  "analysis": ["Shannon entropy", "libmagic/signature MIME fallback", "ELF parsing", "bounded PE header/section parsing", "provisional explainable rules"],
  "not_implemented": ["malware signature database", "YARA integration", "Authenticode trust verification", "trained ML classifier", "LLM analyst", "dynamic sandbox", "Windows execution blocking"],
  "local_interface": ["protected Unix-domain socket on Linux", "in-process local service on Windows"],
  "web": "Static HTML/CSS/JavaScript; GitHub Pages, Netlify, or Vercel compatible",
  "cloud": "intentionally absent"
}
```

## Entropy and scoring logic

`src/elliot/analyzer/entropy.py` is the single canonical entropy implementation.
It calculates whole-file and configurable block-level Shannon entropy from file
bytes. `StaticFileScanner` combines that result with MIME/extension consistency,
ELF/PE structure, permissions, and path context. `PreExecutionScoringEngine` turns
these explainable indicators into a deterministic score and decision.

The Windows default is `WindowsStaticAnalyzer`: automatic monitoring and manual
GUI scans share its `StaticFileScanner` and `PreExecutionScoringEngine` instances.
The legacy `entropy` envelope is derived from the same scan, not a second file
pass. `WindowsEntropyAnalyzer` remains available for explicit legacy injection;
entropy-only output must not be represented as a complete risk assessment.
Do not fork or alter the entropy formula per operating system.

PE evidence does not introduce new heuristic weights. The supported inspection
scope is headers and section metadata only; a structurally valid PE can still be
malicious. Certificate-table presence does not verify an Authenticode signature.

## Completed work — chronological handoff

The following list is the authoritative completed history. A future AI should
not repeat these items unless a regression is found:

1. **Repository baseline and local-only boundary:** mapped the Python engine,
   Linux fanotify/eBPF paths, Windows boundary, GUI, landing page and CI. Kept
   cloud management, remote logging and endpoint file upload out of scope.
2. **Linux operational groundwork:** added dry-run kernel-header resolution for
   running-kernel/VM mismatch diagnostics and a harmless portable/live capacity
   test command. Live Linux capacity remains host-dependent and unverified here.
3. **Cross-platform service and GUI:** added the Windows local facade and
   monitor-only dashboard capability reporting. The UI does not claim kernel
   enforcement when only a user-space sensor is present.
4. **Windows local monitoring:** added injected ETW boundary and native
   `ReadDirectoryChangesW` fallback with bounded queues, retries, event records,
   local-path policy, size limits and no destructive action.
5. **Shared static analysis:** automatic Windows notifications and manual scans
   now share one scanner, canonical entropy engine and provisional scoring
   engine. Entropy is not read a second time for the Windows result envelope.
6. **Bounded PE evidence:** added standard-library PE32/PE32+ DOS/COFF/optional
   header and section parsing. It never loads code, extracts archives, reads
   imports/disassembly, or verifies Authenticode trust.
7. **Honest result/UI contract:** incomplete/locked/changed/unsupported scans
   become `INCONCLUSIVE` with nullable score; the GUI uses `N/A`. Assessment,
   recommendation and enforcement are separate. A score is explicitly not a
   probability and Windows remains `MONITOR_ONLY`/`NONE`.
8. **Verification and handoff docs:** native Windows smoke and notification
   integration passed; the complete result is recorded in
   `SIPER-stage15.3/docs/phase1-verification.md`. The public README and this
   context file link to the roadmap and acceptance evidence.

9. **Linux L0 baseline tool:** added `scripts/linux_baseline.py`, a read-only
   JSON capability snapshot for kernel headers, virtualization, fanotify,
   tracefs, BCC, Clang and package-manager availability. It performs no package
   installation, link repair, probe attach or fanotify group operation. Its
   non-Linux result is intentionally `UNAVAILABLE_NON_LINUX_HOST`.

10. **Linux L1 header compatibility:** the existing resolver now labels a
    virtual-machine header mismatch as `VIRTUALIZED_HEADER_CONFLICT` and rejects
    unsafe kernel-release values before constructing package commands. Exact
    headers are still repaired only through explicit root `--apply`; dry-run is
   the default and real build directories are never overwritten.

11. **Linux L2 fanotify capability:** added a descriptor-free
   `assess_fanotify_capability()` report for Linux/filesystem/permission/root
   prerequisites. It returns explicit `READY`, `DEGRADED` or `UNAVAILABLE`
   states and never hides missing privileges behind a simulated pass.

12. **Linux L3 eBPF capability:** added `assess_ebpf_capability()` and exposed
   it through `EBPFLoader.capability()`. BCC, tracefs, matching headers and
   privilege state are reported before any probe attach; missing capability is
   explicit and local-only.

13. **Linux L4 shared pre-execution analysis:** static scan results now carry
   descriptor/path identity metadata, and partial scans are explicitly marked
   `INCONCLUSIVE` with `ALLOW_MONITOR` rather than being treated as malware proof.

14. **Linux L5 local response:** quarantine actions now expose audit health via
   `audit_status`; a committed quarantine with failed audit recording is marked
   `DEGRADED_AUDIT_WRITE_FAILED` instead of appearing fully protected.

15. **Linux L6 resilience benchmark:** added a harmless deterministic benchmark
   that reports scanner mean/p50/p95 latency, malformed-parser safety and bounded
   eBPF queue drops. It does not attach probes, open fanotify or execute files.

16. **Linux L7 release gate:** added `scripts/release_gate.py` to validate local
   Debian/Pardus artifacts and SHA-256 sidecars. Missing or unsigned artifacts
   block publication; landing links must not point at placeholders.

## Planned work — do not start without the next milestone approval

The next approved-by-user milestone is **M2 — local signatures and richer
static evidence**, described in `ELLIOT_ROADMAP.md`. Its queue is:

- [ ] Provenance-aware local hash/signature rule format and versioning.
- [ ] Evaluate and, only after review, integrate a bounded local YARA-X rule
      engine with positive/negative synthetic rule tests.
- [ ] Add bounded PE import/export, section-permission and packer evidence;
      keep evidence separate from uncalibrated decision weights until M3.
- [ ] Add Authenticode trust-chain reporting while distinguishing certificate
      presence from verified trust and offline revocation limitations.
- [ ] Add signed offline rule bundles, downgrade protection and rollback.
- [ ] Add parser resource budgets/fuzz tests for this new evidence.

Later milestones remain planned in order: M3 measurement/calibration, M4 local
ML, M5 constrained local AI evidence analyst, M6 isolated behavior lab, M7
controlled enforcement, and M8 release hardening. Do not implement a later
milestone as a shortcut for M2. Do not claim any detection percentage until M3
has a versioned, leakage-resistant evaluation set.

## Continuation protocol for another AI

1. Read this file, `ELLIOT_ROADMAP.md`, and the linked phase verification file.
2. Run `git status` and inspect the current branch before touching files. Existing
   uncommitted work may belong to the user; never discard it.
3. Confirm the latest milestone in the JSON blocks and the roadmap status. Work
   only on the first unchecked item in the current milestone.
4. Read relevant tests before editing. Use harmless synthetic fixtures; never
   download or execute malware on the development host.
5. Keep results local and preserve the distinction between evidence, assessment,
   recommendation and enforcement. Add tests and update the verification file.
6. At a natural stop, mark only verified items complete, append new work to the
   planned queue, commit, push, and report the commit plus test totals. If a
   test is platform-specific, record it as skipped/unverified rather than
   converting it into a success claim.

The authoritative “done” state is code + tests + verification evidence + the
status JSON, not a conversational claim. If the session ends mid-step, leave
the item unchecked and write the blocker under the current milestone.

## Phase 1 result contract

```json
{
  "schema": "elliot.phase1.result-contract.v1",
  "assessment_values": ["NO_HIGH_RISK_INDICATORS", "SUSPICIOUS", "INCONCLUSIVE"],
  "risk_score": "0..100 provisional heuristic; null when incomplete or unavailable",
  "score_is_probability": false,
  "recommended_decision": "policy recommendation, not an applied action",
  "enforced_action": "NONE on Windows",
  "monitor_mode": "MONITOR_ONLY on Windows",
  "pe_status_values": ["NOT_PE", "COMPLETE", "INCOMPLETE", "UNSUPPORTED", "ERROR"],
  "pe_scope": "headers_and_sections",
  "signature_verification": "NOT_PERFORMED",
  "pe_max_header_bytes_read": 8024,
  "pe_max_sections": 96,
  "pe_max_optional_header_bytes": 4096,
  "pe_max_header_offset_bytes": 1048576,
  "default_windows_max_file_bytes": 134217728,
  "default_analysis_workers": 4,
  "default_pending_jobs": 128,
  "default_retained_records": 512,
  "default_retry_attempts_after_initial": 2
}
```

`NO_HIGH_RISK_INDICATORS` means the available rules did not cross the high-risk
decision threshold, not a clean certificate. Read failures, unsupported or
incomplete PE inspection, partial entropy reads, changing files, and skipped
paths are `INCONCLUSIVE`, never a measured zero risk. The GUI shows unavailable
scores as `N/A`, cancels stale score animations, and separates PE evidence,
recommended decisions, and enforcement. Scoring remains uncalibrated.

## OS-specific operating model

### Linux

- `fanotify` receives pre-execution permission events and may enforce only per
  configured policy.
- `eBPF` collects filtered process, write, rename, and network telemetry.
- `kernel_headers.py` validates the **running** kernel's header tree, detects
  stale VirtualBox/VM links, and emits a transparent repair plan. It never
  modifies the system without `--apply`, root privileges, and an exact plan.
- `scripts/test_linux_capacity.py --live` invokes the existing harmless eBPF
  and fanotify verifiers after portable assertions pass.

### Windows

- `EtwBackend` is an explicitly injected local ETW or signed-minifilter bridge;
  no remote provider is configured by default.
- `ReadDirectoryChangesBackend` is a local NTFS change-notification fallback.
- `WindowsMonitorController` has bounded analysis work, explicit backpressure,
  local-only records, and monitor-only policy.
- `WindowsStaticAnalyzer` adds file-size and stream byte bounds, finite retries,
  local-volume checks, and native read guards. A file with an active writer can
  be temporarily unscannable and must remain inconclusive.
- UNC/device paths, alternate data streams, mapped remote volumes, and reparse
  paths are rejected by the Windows adapter. This is not a sandbox or protection
  against an administrator/kernel-level adversary.
- User-space monitoring does **not** block execution. A signed minifilter is
  required before Windows enforcement can be claimed or enabled.
- `WindowsLocalService` lets the GUI run locally without a Linux socket,
  fanotify, or cloud service.

## Test states and commands

```json
{
  "unit_tests": {
    "command": "PYTHONPATH=src python -m pytest -q",
    "scope": ["entropy", "bounded PE parsing", "kernel-header resolver", "Windows shared scanner and monitor", "GUI projection/render logic", "existing Linux contracts"]
  },
  "continuous_integration": {
    "workflow": ".github/workflows/verify.yml",
    "platforms": ["ubuntu-latest", "windows-latest"],
    "live_kernel_tests": "not run in shared CI; run the explicit Linux live-capacity command on an authorized host"
  },
  "portable_linux_capacity": {
    "command": "PYTHONPATH=src python scripts/test_linux_capacity.py --output evidence/capacity/linux_capacity.json",
    "success_status": "PORTABLE_CONTRACT_READY"
  },
  "linux_l0_baseline": {
    "command": "PYTHONPATH=src python scripts/linux_baseline.py --json-out evidence/linux/baseline.json",
    "status_on_windows": "UNAVAILABLE_NON_LINUX_HOST",
    "safety": "READ_ONLY_NO_PACKAGE_INSTALL_NO_KERNEL_ATTACH"
  },
  "live_linux_capacity": {
    "command": "sudo PYTHONPATH=src python scripts/test_linux_capacity.py --live --output evidence/capacity/linux_capacity.json",
    "success_status": "FULL_CAPACITY_READY",
    "host_requirements": ["Linux", "root/CAP_SYS_ADMIN", "matching kernel headers", "BCC", "fanotify capability"]
  },
  "windows_package": {
    "command": "py scripts/build_windows_release.py --version <version> --clean",
    "host_requirements": ["64-bit Windows", "PyInstaller", "Inno Setup", "code-signing step before publication"]
  },
  "phase_1_verification": {
    "evidence_file": "SIPER-stage15.3/docs/phase1-verification.md",
    "native_windows_pipeline_test": "tests/integration/test_windows_static_pipeline_native.py",
    "linux_only_modules_ignored_on_windows": 17,
    "linux_live_kernel_capacity": "NOT_VERIFIED_ON_WINDOWS",
    "malware_execution": "NOT_PERFORMED"
  }
}
```

## Guidance for future AI work

- Preserve local-only scope unless a user expressly approves a cloud design and
  privacy/security review.
- Keep optional OS dependencies import-safe so Linux and Windows test suites can
  run on the other platform.
- Prefer capability reports (`READY`, `DEGRADED`, `UNAVAILABLE`) over simulated
  telemetry or guessed protection state.
- Never label ETW, directory notifications, or a user-space process as a kernel
  execution blocker; that claim belongs only to a deployed, signed minifilter.
- Build and test first; do not update release asset URLs until signed artifacts
  and checksums are truly published.
