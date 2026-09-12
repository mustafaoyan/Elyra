# Stage 8.1 Pardus fanotify verifier

Stage 8.1 is a narrow repair for the Stage 8 root verifier. It does not redesign the fanotify controller.

Run only after the non-root test suite and controller demonstration pass:

```bash
sudo -E env PYTHONPATH=src .venv/bin/python scripts/verify_fanotify_pardus.py \
  --output evidence/fanotify/stage8_1_fanotify_root_pardus.json
```

The command prints each scenario immediately after completion. The evidence file is updated atomically after every scenario. If a child execution stalls, the watchdog terminates it and the verifier continues or records a failure rather than hanging indefinitely.

Expected successful scenarios:

- `harmless_elf_allowed_monitor_only`
- `interpreter_script_execution_observed`
- `safe_suspicious_elf_denied_enforcement`
- `analyser_failure_no_hang_fail_open`
- `concurrent_exec_events_all_responded`
- `reproducible_after_controller_restart`
- `all_decision_sessions_audited`

No malware, downloads, network listeners, systemd changes, or persistent test fixtures are used.
