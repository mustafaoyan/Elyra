# Stage 14 — Full automated and integrated workflow testing

Stage 14 validates two complementary workflows.

## 1. Safe in-process integration

`demonstrate_integrated_workflow.py` connects the real static analyser, scoring
engine, correlation engine, response engine, quarantine/restore manager,
structured audit logger, official Unix-domain-socket server/client, and GUI
presentation model. It uses a temporary copy of `/bin/sleep`. Runtime-risk
records are synthetic and explicitly labelled. The response engine terminates
only the child created by the demonstration, quarantines only its temporary
copied executable, and restores that file.

## 2. Installed Pardus MONITOR_ONLY workflow

`elliot-integration-check` exercises the installed systemd service without
changing policy. It verifies:

1. the service is active;
2. the daemon reports fanotify and eBPF available;
3. policy remains `MONITOR_ONLY`;
4. a private copied `/bin/sleep` file is scanned over the official IPC API;
5. fanotify observes and allows the execution;
6. eBPF observes process execution and exit;
7. the correlation state contains pre-execution, runtime and combined scores;
8. the unprivileged GUI model projects the live daemon events;
9. the audit chain remains valid and gains records;
10. the current systemd invocation journal contains no traceback.

The installed verifier requires root only to read the protected audit log and
system journal. It does not enable enforcement or automatic terminate/quarantine
actions.

## Coverage

The final test command is:

```bash
PYTHONPATH=src python -m pytest --cov=src --cov-report=term-missing
```

Coverage is evidence of executed code paths, not proof that every kernel,
security, or race condition is absent. Root/kernel verifiers remain separate
because unit tests must not require privileged host resources.
