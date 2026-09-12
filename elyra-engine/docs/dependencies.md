# ELYRA dependency contract

This document records the dependencies directly supported by the current source tree.
It does not claim that fanotify or eBPF has been verified on Pardus merely because the
packages are installed.

## Direct Python runtime dependencies

| Package | Why it is currently required | Import location |
|---|---|---|
| `numpy` | Byte histograms and Shannon entropy calculations | `elyra.analyzer.static_analyzer` |
| `customtkinter` | Desktop GUI widgets | `elyra.gui.view` |
| `matplotlib` | Block-entropy graph rendering | `elyra.gui.view` |
| `python-magic` | MIME detection through libmagic | `elyra.analyzer.static_analyzer` |
| `pyelftools` | ELF header, section and segment parsing | `elyra.analyzer.static_analyzer`, `elyra.analyzer.pre_execution` |

These are the only direct packages in `requirements.txt`. Transitive packages must not be
copied from a developer computer into the file.

## Direct development dependencies

| Package | Purpose |
|---|---|
| `pytest` | Automated tests |
| `pytest-cov` | Coverage measurement |

`pytest-mock`, Hypothesis, tox, nose and XML test runners were removed because the current
test suite does not import or use them. They may be added later only when a committed test
or workflow directly requires them.

## Pardus system dependencies

Minimum user-space dependencies for Stage 2 and the GUI:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip python3-tk libmagic1
```

Additional eBPF/BCC development and verification dependencies:

```bash
sudo apt install python3-bpfcc bpfcc-tools \
  "linux-headers-$(uname -r)" clang llvm libelf-dev build-essential
```

The BCC Python module is intentionally **not** installed from PyPI. ELYRA expects the
Pardus/Debian `python3-bpfcc` package because it is coupled to the system BCC libraries.
A normal isolated virtual environment cannot necessarily see distribution-installed BCC
bindings. The final installer must therefore use a reviewed integration strategy, such as a
service virtual environment created with `--system-site-packages`, or a system-Python
packaging design. That choice remains unverified until the daemon and eBPF stages.

Kernel headers must match the running kernel. Package installation alone does not prove
that the selected probes are supported or attach successfully.

## Clean virtual environment

Run from the repository root:

```bash
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r requirements-dev.txt
python scripts/check_environment.py
python -m compileall -q src
PYTHONPATH=src python -m pytest -q
```

The environment checker treats BCC and kernel headers as degraded/optional unless
`--require-ebpf` is supplied. This allows the static-analysis and GUI dependency layer to be
validated without falsely claiming eBPF readiness.

## Stage 9 Pardus system packages

The real eBPF verifier requires Pardus packages equivalent to:

```bash
sudo apt install python3-bpfcc bpfcc-tools clang "linux-headers-$(uname -r)"
```

Create the Stage 9 virtual environment with `--system-site-packages` so the apt-managed `bcc` Python module is visible without installing unofficial PyPI substitutes.

## Stage 13 installer dependencies

The production installer uses the Pardus/Debian build backend and system BCC
bindings through a virtual environment created with `--system-site-packages`.
The direct system package set is:

```bash
sudo apt install python3 python3-venv python3-pip python3-setuptools python3-wheel \
  python3-tk python3-bpfcc bpfcc-tools clang libmagic1 linux-headers-amd64
```

If the running kernel has no matching `/lib/modules/$(uname -r)/build`, the
installer obtains the current kernel/header meta-packages and exits with a
reboot-required message rather than starting eBPF against mismatched headers.
