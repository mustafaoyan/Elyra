# Siper

**Siper — the Pardus security application developed within the ELLIOT project**

Official TEKNOFEST project title: **ELLIOT: Pardus İçin Entropi Tabanlı Otonom Zafiyet Tespit ve Sıfırcı Gün Savunma Motoru**

Siper is a Pardus-oriented Linux defence engine that combines explainable
static file analysis, fanotify pre-execution decisions, filtered BCC/eBPF
runtime telemetry, secure response operations, an unprivileged GUI and
structured tamper-evident auditing.

> **Final controlled release:** `1.0.0`  
> **Verified target:** Pardus GNU/Linux 25.1, x86_64, Linux 6.12-series kernel  
> **Default production policy:** `MONITOR_ONLY`  
> **Automatic terminate/quarantine:** disabled unless explicitly authorised

## Türkçe özet

Siper; dosya entropisi, MIME/uzantı uyumu, ELF yapısı, izinler ve dosya
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
- versioned `/opt/elliot/releases` installation (legacy-compatible internal path) and systemd integration;
- safe synthetic and harmless-executable test workflows.


## Naming and backward compatibility

**Siper** is the public application name. **ELLIOT** remains the official TEKNOFEST project name.
To preserve the already verified integration evidence and upgrade compatibility, the internal Python namespace, protected runtime groups, socket path and primary systemd unit keep the legacy `elliot` identifier in this release. Public commands use `siper-*`, and `siper.service` is provided as a systemd alias.

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

The final Stage 15.2 source package contains **254 automated tests**. The Stage
14.1 installed-workflow baseline was **223 passed** with approximately **70%**
source-line coverage; Stage 15 adds release, evidence and packaging-contract
tests. Privileged kernel and GUI paths are additionally verified through real
Pardus integration evidence rather than fabricated unit coverage.

## Installation option A — verified installer

```bash
deactivate 2>/dev/null || true
sudo ./scripts/install.sh --user "$USER"
```

The installer creates groups, protected directories, a versioned release under
`/opt/elliot/releases`, `/opt/elliot/current`, the systemd unit, GUI launcher and
desktop entry. It starts safely in monitor-only mode.

Log out and back in after group membership changes, then launch:

```bash
siper-gui
```

The legacy `elliot-gui` command remains available for backward compatibility.

Service management:

```bash
sudo systemctl status siper.service --no-pager
sudo journalctl -u siper.service -n 100 --no-pager
sudo systemctl restart siper.service
sudo systemctl stop siper.service
```

## Installation option B — Debian package

Build on the target Pardus system so compatible Python wheels are downloaded
and embedded into the package:

```bash
./scripts/build_pardus_deb.sh
sudo apt install ./dist/debian/siper-pardus_1.0.0-1_amd64.deb
sudo usermod -aG elliot "$USER"
```

The generated Siper `.deb` installs dependencies offline from its embedded wheelhouse
but still relies on declared Pardus system packages for BCC, Clang, Tkinter,
libmagic and kernel headers. Rebuild the package for materially different
Pardus/Python architectures.

## Configuration

Canonical configuration files are installed from:

```text
src/elliot/config/scoring.default.json
src/elliot/config/runtime_correlation.default.json
src/elliot/config/response.default.json
```

All scoring weights and thresholds are labelled provisional and not clinically
or statistically calibrated. High entropy alone cannot produce a deny decision.

## Runtime directories and permissions

| Path | Purpose | Expected protection |
|---|---|---|
| `/run/elliot/elliot.sock` | daemon/GUI IPC | root:`elliot`, `0660` |
| `/var/lib/elliot` | state and quarantine | root-only, `0700` |
| `/var/log/elliot` | audit logs | protected directory, `0750` |
| `/opt/elliot/current` | active release symlink | root-owned |

Members of `elliot` may use ordinary read-only GUI actions. Membership of
`elliot-admin` authorises sensitive restore, deletion and policy operations and
must be granted explicitly.

## Degraded mode

ELLIOT remains explicit when a component is unavailable:

- fanotify failure: monitor/enforcement availability is reported and permission
  events use the configured fail-open/fail-closed policy;
- BCC/eBPF failure: static and fanotify protection continue while runtime
  telemetry is marked degraded;
- GUI IPC failure: the GUI displays `DISCONNECTED` and never invents data;
- audit integrity failure: startup reports the failure and preserves corrupted
  material for investigation.

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

## Known limitations

- Rules and thresholds are provisional and require broader benign/malicious
  validation before high-risk deployment.
- File-write eBPF events identify device/inode and user-supplied identifiers;
  they do not claim a verified canonical full path.
- The portable process-exit tracepoint does not expose every exit code.
- The audit hash chain is tamper-evident within its threat model; a privileged
  attacker able to replace all logs and manifests could recompute the chain.
- Real-malware validation and large-scale production performance testing remain
  separate authorised laboratory activities.
- Automatic terminate/quarantine is intentionally disabled by default.

## Documentation

- [Architecture](docs/architecture.md)
- [Operations and recovery](docs/operations.md)
- [Evidence guide](docs/evidence_guide.md)
- [Final verification matrix](docs/final_verification_matrix.md)
- [Submission checklist](docs/submission_checklist.md)
- [Controlled live-malware laboratory gate](docs/controlled_live_malware_lab.md)
- [Security policy](SECURITY.md)
- [Release notes](RELEASE_NOTES.md)
- [Changelog](CHANGELOG.md)

## License

Apache License 2.0. See [`LICENSE`](LICENSE).

### Stage 15.1 verifier note

The final installed-workflow verifier accounts for the daemon's intentionally
bounded 200-event dashboard buffer. When a verified fixture event ages out
between polling and the final dashboard refresh, GUI projection is checked
against the exact event records previously returned through `PardusModel`'s
official Unix-socket API. This does not use mock telemetry and does not weaken
IPC-error checks.

### Stage 15.2 scoring-evidence note

The Stage 4 evidence generator now emits schema version `1.1`, explicit derived
validation checks and a top-level `overall_status`. The status is `OK` only when
ordinary text is allowed, entropy-only evidence is not denied, the labelled
combined synthetic fixture reaches the denial path, and all results retain
structured explainability fields. Existing Stage 4 evidence must be regenerated
with `scripts/demonstrate_pre_execution_scoring.py`; the finalizer never inserts
an unconditional success value.
