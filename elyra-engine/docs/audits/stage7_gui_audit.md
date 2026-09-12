# Stage 7 GUI integration audit

| Issue | Previous file and line | Severity | Effect | Stage 7 correction |
|---|---:|---|---|---|
| Random entropy values were plotted | `gui/view.py:108-112` | Critical | Simulated telemetry was presented as real | Removed all random generation; graph consumes only daemon `block_entropies` |
| Service status was hard-coded as active | `gui/view.py:51` | High | GUI could claim protection while daemon was absent | Status is derived from `get_status`; disconnected and degraded states are explicit |
| Buttons had no callbacks | `gui/view.py:54-60` | High | Quarantine and restore controls were non-functional | Controller binds refresh, scan, quarantine refresh, and authorised restore callbacks |
| Controller only opened the window | `gui/controller.py:10-16` | High | No IPC integration or error handling existed | Added asynchronous official-API calls, periodic refresh, and safe error display |
| Event/quarantine API errors were silently converted to empty lists | `gui/model.py:33-43` | High | Connection failures looked like legitimate empty data | Model preserves section-specific errors and supports partial dashboard results |
| GUI settings were stored in the current directory | `gui/view.py:145-166` | Medium | Installed GUI could write unpredictable files | Settings use `$XDG_CONFIG_HOME/elyra/gui.json`, mode `0600`, atomic replacement |
| Runtime score was not available but could be implied by the dashboard | old dashboard | High | Unavailable telemetry could be misunderstood | Runtime score is shown as `N/A` unless the API actually supplies it |
| No reproducible GUI/IPC evidence path existed | repository | Medium | Integration could not be demonstrated safely | Added headless official-IPC proof and visibly labelled graphical demo |

## Deferred verification

The Stage 7 graphical demonstration uses a temporary unprivileged Unix socket and
is explicitly labelled as a safe demonstration. It does not prove that the
root-owned production daemon, fanotify, eBPF, system groups, or systemd service
work. Those remain separate root/kernel/installation verification tasks.
