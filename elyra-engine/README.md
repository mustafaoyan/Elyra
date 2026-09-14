# Elyra

## 🌐 Live Deployment & Download

The public ELYRA landing page is published from this repository at
[https://mustafaoyan.github.io/Elyra/](https://mustafaoyan.github.io/Elyra/)
after the GitHub Pages workflow completes. It detects Windows and Linux and
selects the matching release asset. Before public release, build, sign and
checksum the Windows installer and Linux package, then replace the versioned
placeholder links in [`../landing/assets/js/download-config.js`](../landing/assets/js/download-config.js).

The current scope is strictly local-first: no cloud management or remote event
logging is enabled. Windows user-space monitoring is monitor-only until a
separately signed minifilter is deployed; see the repository-root
[`AI.md`](../AI.md) for the cross-platform model.

**Elyra — the Pardus security application developed within the ELYRA project**

Official TEKNOFEST project title: **ELYRA: Pardus İçin Entropi Tabanlı Otonom Zafiyet Tespit ve Sıfırcı Gün Savunma Motoru**

Elyra is a Pardus-oriented Linux defence engine that combines explainable
static file analysis, fanotify pre-execution decisions, filtered BCC/eBPF
runtime telemetry, secure response operations, an unprivileged GUI and
structured tamper-evident auditing.

> **Current controlled release:** `1.0.2`  
> **Verified target:** Pardus GNU/Linux 25.1, x86_64, Linux 6.12-series kernel  
> **Default production policy:** `MONITOR_ONLY`  
> **Automatic terminate/quarantine:** disabled unless explicitly authorised

## Türkçe özet

Elyra; dosya entropisi, MIME/uzantı uyumu, ELF yapısı, izinler ve dosya
bağlamını açıklanabilir kurallarla değerlendirir. Çalıştırma öncesinde fanotify,
çalışma zamanında ise eBPF/BCC telemetrisi kullanır. GUI root yetkisi olmadan
çalışır ve ayrıcalıklı daemon ile korumalı Unix soketi üzerinden haberleşir.
Yüksek entropi tek başına zararlı yazılım kanıtı değildir ve otomatik `DENY`
kararı oluşturmaz.

## Verified capabilities

- whole-file and configurable block-level Shannon entropy;
- MIME detection and extension/MIME consistency checks;
- ELF sections, segments, entry point and writable-executable indicators;
- SUID, SGID, world-writable, hidden-file and suspicious-location evidence;
- deterministic, configurable and fully explainable rule-based scoring;
- real `FAN_OPEN_EXEC_PERM` monitor/enforcement support with guaranteed response;
- filtered process, file-write, rename and IPv4-connect BCC/eBPF telemetry;
- fanotify-to-process-to-eBPF correlation with evolving runtime score;
- authorised allow, monitor, warn, deny, terminate, quarantine and restore;
- pidfd-based termination and path/inode/hash replacement protections;
- protected Unix-domain-socket IPC with `SO_PEERCRED` and schema validation;
- unprivileged GUI using only the official daemon API;
- structured JSONL audit records with rotation and SHA-256 hash chaining;
- versioned `/opt/elyra/releases` installation (legacy-compatible internal path) and systemd integration;
- safe synthetic and harmless-executable test workflows.


## Naming and backward compatibility

**Elyra** is the public application name. **ELYRA** remains the official TEKNOFEST project name.
To preserve the already verified integration evidence and upgrade compatibility, the internal Python namespace, protected runtime groups, socket path and primary systemd unit keep the legacy `elyra` identifier in this release. Public commands use `elyra-*`, and `elyra.service` is provided as a systemd alias.

## Architecture

```text
Execution request
      │
      ▼
fanotify FAN_OPEN_EXEC_PERM
      │
      ▼
Entropy + MIME + ELF + permission analysis
      │
      ▼
Explainable pre-execution score ──► allow / monitor / warn / deny
      │
      ▼
Process identity and eBPF runtime events
      │
      ▼
Correlation engine and evolving score
      │
      ▼
Authorised response engine
      │
      ├── alert / terminate / quarantine / restore
      ▼
Unix IPC ──► unprivileged GUI
      │
      ▼
Tamper-evident audit log
```

Detailed design: [`docs/architecture.md`](docs/architecture.md).

## Safety boundary

Normal development and verification use only harmless executables, synthetic
byte files, legitimate compressed/encrypted files, temporary fixtures and EICAR
when appropriate. The repository does not download malware.

Controlled live-malware validation is **not part of the normal workflow** and
must not begin until written authorisation, VM isolation, network restrictions,
snapshots, disabled shared integrations, sample hashes, recovery procedures and
sanitised-evidence rules are documented. See
[`docs/controlled_live_malware_lab.md`](docs/controlled_live_malware_lab.md).

## Requirements

Verified Pardus system packages:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip python3-tk \
  python3-bpfcc bpfcc-tools clang libmagic1 python3-pil.imagetk linux-headers-amd64
```

The running kernel must have matching headers:

```bash
uname -r
ls -ld /lib/modules/$(uname -r)/build
```

## Source verification

```bash
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
python scripts/check_environment.py
python -m compileall -q src scripts tests
PYTHONPATH=src python -m pytest -q
PYTHONPATH=src python -m pytest --cov=src --cov-report=term-missing
```

The test suite is platform-aware: native Windows runs the local monitor and
portable-analysis contracts, while Linux CI additionally runs the POSIX IPC,
fanotify, eBPF, audit and package-layout contracts. Privileged kernel and GUI
paths are verified through real Pardus integration evidence rather than a
fabricated coverage claim.

## Installation option A — verified installer

```bash
deactivate 2>/dev/null || true
sudo ./scripts/install.sh --user "$USER"
```

The installer creates groups, protected directories, a versioned release under
`/opt/elyra/releases`, `/opt/elyra/current`, the systemd unit, GUI launcher and
desktop entry. It starts safely in monitor-only mode.

Log out and back in after group membership changes, then launch:

```bash
elyra-gui
```

The legacy `elyra-gui` command remains available for backward compatibility.

Service management:

```bash
sudo systemctl status elyra.service --no-pager
sudo journalctl -u elyra.service -n 100 --no-pager
sudo systemctl restart elyra.service
sudo systemctl stop elyra.service
```

## Installation option B — Debian package

Build on the target Pardus system so compatible Python wheels are downloaded
and embedded into the package:

```bash
./scripts/build_pardus_deb.sh
sudo apt install ./dist/debian/elyra-pardus_1.0.2-1_amd64.deb
sudo usermod -aG elyra "$USER"
```

The generated Elyra `.deb` installs dependencies offline from its embedded wheelhouse
but still relies on declared Pardus system packages for BCC, Clang, Tkinter,
libmagic and kernel headers. Rebuild the package for materially different
Pardus/Python architectures.

## Configuration

Canonical configuration files are installed from:

```text
src/elyra/config/scoring.default.json
src/elyra/config/runtime_correlation.default.json
src/elyra/config/response.default.json
```

All scoring weights and thresholds are labelled provisional and not clinically
or statistically calibrated. High entropy alone cannot produce a deny decision.

## Runtime directories and permissions

| Path | Purpose | Expected protection |
|---|---|---|
| `/run/elyra/elyra.sock` | daemon/GUI IPC | root:`elyra`, `0660` |
| `/var/lib/elyra` | state and quarantine | root-only, `0700` |
| `/var/log/elyra` | audit logs | protected directory, `0750` |
| `/opt/elyra/current` | active release symlink | root-owned |

Members of `elyra` may use ordinary read-only GUI actions. Membership of
`elyra-admin` authorises sensitive restore, deletion and policy operations and
must be granted explicitly.

## Degraded mode

ELYRA remains explicit when a component is unavailable:

- fanotify failure: monitor/enforcement availability is reported and permission
  events use the configured fail-open/fail-closed policy;
- BCC/eBPF failure: static and fanotify protection continue while runtime
  telemetry is marked degraded;
- GUI IPC failure: the GUI displays `DISCONNECTED` and never invents data;
- audit integrity failure: startup reports the failure and preserves corrupted
  material for investigation.

## Known limitations

- The ML and local AI components are recommendation-only and are not production
  malware verdicts.
- Synthetic training data cannot establish real-world zero-day detection rates.
- Windows monitoring remains monitor-only until a separately signed native
  minifilter is available.
- Native fanotify, eBPF and disposable-VM evidence depends on the target Linux
  kernel, permissions and virtualization capabilities.

## Final evidence and submission

Copy the verified Pardus evidence from the previous stage, then run:

```bash
PYTHONPATH=src python scripts/finalize_submission.py --project-root . --strict
```

Required result:

```text
overall_status: COMPLETE
```

Build final archives and wheel:

```bash
PYTHONPATH=src python scripts/build_release_artifacts.py \
  --project-root . --output-dir dist/final
(cd dist/final && sha256sum -c SHA256SUMS)
```

The final manifest, inventory and checksums are written under
`evidence/submission/`. Detailed instructions are in
[`docs/evidence_guide.md`](docs/evidence_guide.md) and the final hand-in list is
in [`docs/submission_checklist.md`](docs/submission_checklist.md).


## License

Apache License 2.0. See [`LICENSE`](LICENSE).
