# Stage 14 integration evidence

This directory stores the final automated and integrated workflow evidence.

Expected Pardus files:

- `stage14_coverage_pardus.txt` — full pytest coverage report.
- `stage14_safe_integrated_workflow_pardus.json` — non-root in-process chain using a harmless copied `/bin/sleep` executable and synthetic runtime-risk records.
- `stage14_safe_integrated_workflow_pardus.png` — terminal screenshot of the safe workflow result.
- `stage14_installed_workflow_pardus.json` — root/read-only production service verification using real fanotify, eBPF, official IPC, GUI projection and audit-chain checks.
- `stage14_installed_workflow_pardus.png` — terminal screenshot of the installed workflow result.
- `stage14_current_journal_pardus.txt` — current systemd invocation journal used to verify that no traceback occurred.

No test in this stage downloads, creates or executes malware. The live installed
workflow uses only a private temporary copy of `/bin/sleep` and keeps the daemon
in `MONITOR_ONLY` mode with automatic destructive responses disabled. The safe
response workflow uses synthetic risk records that are explicitly labelled as
test fixtures.

No malware is used in any Stage 14 verification.
