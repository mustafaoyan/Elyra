# ELLIOT AI Context Blueprint

<!-- ELLIOT_AI_CONTEXT:v1 | local-first | repository-root -->

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
    "windows_runtime": "Local ETW/minifilter adapter or ReadDirectoryChangesW monitor; monitor-only unless a separately signed minifilter is deployed.",
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
    │   │   ├── static_analyzer.py     # MIME, ELF, permissions, path and entropy evidence
    │   │   └── pre_execution.py
    │   ├── scoring/engine.py          # Deterministic, explainable scoring
    │   ├── monitor/
    │   │   ├── fanotify/              # Linux pre-execution monitor/enforcement path
    │   │   ├── ebpf/                  # Linux BCC/eBPF telemetry and header resolver
    │   │   └── windows/               # Windows local ETW/minifilter boundary + NTFS fallback
    │   ├── correlation/engine.py      # Linux pre-execution/runtime state correlation
    │   ├── response/                  # Authorized Linux response and quarantine controls
    │   ├── audit/                     # Local tamper-evident JSONL audit chain
    │   ├── service/
    │   │   ├── daemon.py              # Linux privileged daemon and Unix-socket API
    │   │   └── windows_local.py       # Windows in-process, local-only GUI service facade
    │   └── gui/                       # CustomTkinter local desktop dashboard
    ├── scripts/
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
  "analysis": ["Shannon entropy", "libmagic/signature MIME fallback", "ELF parsing", "explainable rules"],
  "local_interface": ["protected Unix-domain socket on Linux", "in-process local service on Windows"],
  "web": "Static HTML/CSS/JavaScript; GitHub Pages, Netlify, or Vercel compatible",
  "cloud": "intentionally absent"
}
```

## Entropy and scoring logic

`src/elliot/analyzer/entropy.py` is the single canonical entropy implementation.
It calculates whole-file and configurable block-level Shannon entropy from file
bytes. `StaticFileScanner` combines that result with MIME/extension consistency,
ELF structure, permissions, and path context. `PreExecutionScoringEngine` turns
these explainable indicators into a deterministic score and decision.

Windows uses `WindowsEntropyAnalyzer`, which delegates to the same canonical
`EntropyEngine`; it only adds NTFS-volume reporting, size bounds, and bounded
retry behavior for transient locked-file conditions. Do not fork or alter the
entropy formula per operating system.

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
- User-space monitoring does **not** block execution. A signed minifilter is
  required before Windows enforcement can be claimed or enabled.
- `WindowsLocalService` lets the GUI run locally without a Linux socket,
  fanotify, or cloud service.

## Test states and commands

```json
{
  "unit_tests": {
    "command": "PYTHONPATH=src python -m pytest -q",
    "scope": ["entropy", "kernel-header resolver", "Windows monitor", "GUI projection", "existing Linux contracts"]
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
  "live_linux_capacity": {
    "command": "sudo PYTHONPATH=src python scripts/test_linux_capacity.py --live --output evidence/capacity/linux_capacity.json",
    "success_status": "FULL_CAPACITY_READY",
    "host_requirements": ["Linux", "root/CAP_SYS_ADMIN", "matching kernel headers", "BCC", "fanotify capability"]
  },
  "windows_package": {
    "command": "py scripts/build_windows_release.py --version <version> --clean",
    "host_requirements": ["64-bit Windows", "PyInstaller", "Inno Setup", "code-signing step before publication"]
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
