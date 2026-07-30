# Stage 13 — systemd and reproducible Pardus installation

## Production layout

```text
/opt/elliot/
├── current -> releases/<version>-<UTC timestamp>
└── releases/
    └── <version>-<UTC timestamp>/
        ├── .venv/
        ├── src/
        ├── INSTALLATION.json
        └── ...

/etc/systemd/system/elliot.service
/usr/local/bin/elliot-gui
/usr/share/applications/elliot.desktop
/usr/lib/sysusers.d/elliot.conf
/run/elliot/elliot.sock
/var/lib/elliot/
/var/log/elliot/
```

The privileged daemon runs as root because fanotify permission events, BCC/eBPF
loading, authorised process termination and protected quarantine require it. The
GUI remains unprivileged and communicates only through the `0660` Unix socket
owned by the `elliot` group.

## Safe defaults

The installed unit starts without `--enforce` and without
`--execute-responses`. Therefore fanotify starts in monitor-only mode and Stage
11 destructive runtime actions remain disabled. Membership in `elliot-admin` is
never assigned implicitly.

## Installation

```bash
sudo ./scripts/install.sh --user "$USER"
```

Use `--admin-user USER` only for a deliberately authorised administrator. If the
installer reports exit code 20, reboot into the newly installed kernel and rerun
it so the running kernel and headers match.

After adding a user to `elliot`, log out and log back in before launching the GUI.

## Service operations

```bash
sudo systemctl daemon-reload
sudo systemctl enable elliot.service
sudo systemctl start elliot.service
sudo systemctl status elliot.service --no-pager
sudo journalctl -u elliot.service -n 80 --no-pager
```

## Installed-system evidence

```bash
sudo /opt/elliot/current/.venv/bin/elliot-install-check \
  --expected-user "$USER" \
  --output "$PWD/evidence/installation/stage13_installation_pardus.json"
sudo chown "$USER:$USER" evidence/installation/stage13_installation_pardus.json
```

The verifier is read-only. It checks the current release, manifest, entry points,
groups, service state, safe ExecStart flags, directory modes, socket mode/group,
IPC status, audit startup integrity, GUI launcher and journal access.

## Removal

```bash
sudo /opt/elliot/current/scripts/uninstall.sh
```

The default removal preserves quarantine metadata and audit logs. Data removal
requires the explicit `--purge-data` option.
