# ELLIOT – Siper Antivirus

## 🌐 Live Deployment & Download

**AI devam noktası:** [AI.md](AI.md) — başka bir AI’ın projeyi aynı yerden
devam ettirmesi için güncel durum, Windows handoff ve Linux başlangıç noktası.

**Landing page:** [https://mustafaoyan.github.io/Elyra/](https://mustafaoyan.github.io/Elyra/)

The landing page detects Windows or Linux and selects the matching installer
or package. It is published by the repository's GitHub Pages workflow after a
successful `main`-branch deployment. Before promoting it publicly, publish the
signed Windows installer and Linux package with SHA-256 checksums, then update
[`landing/assets/js/download-config.js`](landing/assets/js/download-config.js)
with the actual GitHub Release asset names. The committed links are deliberately
versioned placeholders until those assets exist.

> The engine and its telemetry remain local to the endpoint in this release.
> There is no central cloud console or remote event logging.

## What ELLIOT does

ELLIOT – Siper Antivirus is an explainable, entropy-based security engine for
unknown-file analysis and host-native monitoring. It combines byte-level
Shannon entropy, file structure, MIME/extension consistency, permission/path
evidence, and deterministic scoring. A high entropy value is an investigative
signal, never proof of malware by itself.

| Platform | Local monitoring | Enforcement status |
| --- | --- | --- |
| Linux / Pardus | fanotify + filtered BCC/eBPF runtime telemetry | Policy-controlled fanotify path; privileged and explicitly configured |
| Windows | ETW/minifilter adapter boundary + `ReadDirectoryChangesW` NTFS fallback | Monitor-only until a separately signed minifilter is deployed |

## Repository layout

The complete development plan and current gates are tracked in [AI.md](AI.md).
Windows work is paused; Linux implementation starts only after the user says
“başla”.

```text
SIPER-stage15.3/     Core Python engine, desktop GUI, tests, packaging and docs
landing/              Static deployment site with OS-aware download routing
kurulum/              Existing Debian package and installation material
AI.md                 Complete AI handoff, standards, history and continuation instructions
```

## Phase 1: shared local static analysis

Windows automatic monitoring and manual scans now use the same static scanner
and provisional scoring engine. EXE/DLL analysis includes bounded PE32/PE32+
headers and section metadata, alongside MIME, path and canonical entropy
evidence. PE anomalies are advisory; they do not add uncalibrated scoring weights.

Incomplete, unreadable, unsupported, changing or skipped files are reported as
`INCONCLUSIVE`, with no numeric risk score. The GUI displays `N/A` for missing
scores and distinguishes a policy recommendation from an applied action.
`NO_HIGH_RISK_INDICATORS` is **not** proof that a file is clean, and a 0–100
heuristic score is **not** a malware probability.

This milestone does not include Authenticode verification, malware signatures,
a trained AI model, sandbox execution or Windows execution blocking. Windows
remains `MONITOR_ONLY`, with `enforced_action=NONE`; nothing is uploaded.
See [Phase 1 verification and limitations](SIPER-stage15.3/docs/phase1-verification.md).

## Quick start

### Linux / Pardus

```bash
cd SIPER-stage15.3
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
PYTHONPATH=src python -m pytest -q
PYTHONPATH=src python scripts/resolve_kernel_headers.py --json
PYTHONPATH=src python scripts/test_linux_capacity.py
```

For the isolated, harmless live fanotify/eBPF verification on a compatible
Linux host, run the capacity command with root privileges:

```bash
sudo PYTHONPATH=src python scripts/test_linux_capacity.py --live \
  --output evidence/capacity/linux_capacity.json
```

The header resolver is a dry run by default. Its `--apply` option requires
root and refuses to overwrite a real kernel build directory.

### Windows

```powershell
cd SIPER-stage15.3
py -m pip install -r requirements.txt -r requirements-dev.txt
$env:PYTHONPATH = "src"
py -m pytest -q
py -m elliot.gui.main
```

The desktop dashboard uses the Windows local service facade instead of the
Linux Unix-socket daemon. Windows monitoring stays local and reports precisely
when an ETW/minifilter adapter or directory watcher is unavailable.

Build a release only on 64-bit Windows after installing PyInstaller and Inno
Setup:

```powershell
py scripts/build_windows_release.py --version 1.0.0 --clean
```

Sign the resulting installer and publish its checksum before adding it to a
GitHub Release.

## Desktop GUI

The CustomTkinter dashboard is redesigned as a dark, neon-accented security
command center. It shows only local daemon/service data: sensor state, recent
events, risk distribution, quarantine records, and genuine block-level entropy
results. UI animations interpolate already received values; they never invent
threat telemetry.

## Landing page deployment

The dependency-free site in [`landing/`](landing/) can deploy without a custom
domain to GitHub Pages, Netlify, or Vercel. The repository includes
[GitHub Pages workflow](.github/workflows/deploy-landing.yml),
[`netlify.toml`](landing/netlify.toml), and
[`vercel.json`](landing/vercel.json). See
[`landing/README.md`](landing/README.md) for exact deployment steps.

## Safety boundary

Normal development and verification use harmless synthetic data, temporary
fixtures, benign executables, and loopback traffic only. The project does not
download or execute malware. Automatic destructive response actions remain
disabled unless a local policy and authorization explicitly permit them.

## Documentation

- [AI architecture context](AI.md)
- [Core architecture](SIPER-stage15.3/docs/architecture.md)
- [Linux operations](SIPER-stage15.3/docs/operations.md)
- [Landing-page deployment](landing/README.md)

## License

Apache License 2.0. See [`SIPER-stage15.3/LICENSE`](SIPER-stage15.3/LICENSE).
