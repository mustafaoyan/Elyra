# Stage 7 — GUI integration

The GUI is an unprivileged client. It imports no fanotify, eBPF, quarantine, or
privileged service implementation and communicates only through `IpcClient`.

Displayed values are sourced from the official API:

- service and degraded-component state: `get_status`;
- current policy: `get_policy`;
- recent events: `list_events`;
- quarantine records: `list_quarantine`;
- file entropy, MIME/ELF evidence and pre-execution score: `scan_file`;
- authorised restoration: `restore_file`.

The entropy chart never synthesizes data. Runtime score is displayed as `N/A`
until a real runtime score is supplied by the daemon API. The GUI remains usable
when the daemon is absent and reports the IPC failure rather than claiming an
active service.
