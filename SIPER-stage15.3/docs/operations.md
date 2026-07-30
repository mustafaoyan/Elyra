# Operations and Recovery

## Normal operation

```bash
sudo systemctl status elliot.service --no-pager
sudo journalctl -u elliot.service -f
elliot-gui
```

## Health checks

```bash
sudo /opt/elliot/current/.venv/bin/elliot-install-check \
  --expected-user "$USER" --output /tmp/elliot-install-check.json
```

The service must remain in `MONITOR_ONLY` during ordinary demonstrations unless
a written enforcement test plan has been approved.

## Safe rollback

The installer preserves versioned releases. Stop the service, point
`/opt/elliot/current` to the previously verified release, reload systemd and
restart. Record the old and new targets in the evidence log.

## Uninstallation

```bash
sudo ./scripts/uninstall.sh
```

State and audit data are preserved by default. Use purge options only after
quarantine recovery and evidence-retention decisions are documented.

## Failure handling

- IPC unavailable: verify socket ownership, group membership and service state.
- fanotify unavailable: inspect kernel privileges and mounts; retain fail-open
  logs.
- eBPF degraded: verify BCC, Clang and matching running-kernel headers.
- audit integrity failure: stop destructive operations and preserve the corrupt
  log and startup report.
