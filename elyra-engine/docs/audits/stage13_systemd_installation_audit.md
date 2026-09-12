# Stage 13 systemd and installation audit

| Issue | Original file and line area | Severity | Effect | Stage 13 correction |
|---|---|---:|---|---|
| Service relied on `PYTHONPATH` instead of an installed Python package | `packaging/systemd/elyra.service` | High | Entry point could differ from the package actually installed | Added PEP 621 console scripts and points systemd to `/opt/elyra/current/.venv/bin/elyra-daemon` |
| Installer created a normal isolated venv | `scripts/install.sh` | Critical for eBPF | Apt-installed `bcc` bindings were invisible to the daemon | Uses `python3 -m venv --system-site-packages` |
| Exact running-kernel headers were installed unconditionally | `scripts/install.sh` | High | Installation failed when the old exact header package left the repository | Installs header meta-package, checks `/lib/modules/$(uname -r)/build`, and exits with an explicit reboot-required code when necessary |
| IPC and admin groups were not created | Installer/service contract | Critical | Protected socket startup failed and sensitive-action policy could not work | Adds `elyra` and `elyra-admin` sysusers definitions; admin membership remains explicit |
| Installer copied over one mutable `/opt/elyra` tree | `scripts/install.sh` | High | Partial upgrades could leave a mixed installation | Uses immutable timestamped releases and an atomic `/opt/elyra/current` symlink switch with rollback |
| eBPF C source was absent from package data | `pyproject.toml` | Critical | Installed collector could not find `probes.c` | Packages `elyra.monitor.ebpf/probes.c` and verifies it during installation |
| Production paths had no single manifest | Installation layout | Medium | Service, GUI and support evidence could drift | Adds canonical constants and `INSTALLATION.json` per release |
| GUI launcher depended on `PYTHONPATH` | `scripts/launch_gui.sh` | High | GUI could run source code different from the daemon release | Launcher executes the installed `elyra-gui` console script under the current release |
| Runtime/state/log permissions were incomplete | systemd/installer | High | Socket, quarantine and audit paths could be unsafe or unavailable | Creates `/run/elyra` 0750, `/var/lib/elyra` 0700 and `/var/log/elyra` 0750; systemd manages them on service start |
| Automatic enforcement/action flags were not explicitly excluded from the unit | systemd unit | High | A packaging edit could silently enable destructive behaviour | Unit contains neither `--enforce` nor `--execute-responses`; manifest records safe defaults |
| No installed-system verifier existed | Repository | Medium | A running service could be claimed without checking paths, groups, socket or IPC | Adds read-only `elyra-install-check` with JSON evidence |
| Uninstall behaviour could remove evidence unintentionally | Repository | Medium | Quarantine and logs could be lost | Uninstaller preserves `/var/lib/elyra` and `/var/log/elyra` unless `--purge-data` is explicit |

## Verification boundary

Source-contract tests and the safe layout demonstration do not install packages or
start systemd. Real Pardus acceptance still requires root installation, service
status, journal, socket and IPC verification on the target computer.
