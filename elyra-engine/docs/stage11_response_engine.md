# Stage 11 — Authorised Response Engine

## Response flow

1. Stage 10 produces a correlation ID, process ID, executable path, score,
   triggered rules and recommendation.
2. Stage 11 binds the live process and file identities to that exact correlation
   generation.
3. Non-destructive actions are recorded immediately.
4. Destructive actions require `automatic_runtime_actions=true`, which the
   production daemon enables only with `--execute-responses`.
5. Termination opens a pidfd, revalidates process start time and executable
   device/inode, sends SIGTERM, and optionally escalates to SIGKILL.
6. Quarantine validates the previously bound file identity and SHA-256 before
   moving the file into protected storage.
7. Every action produces a structured audit result and a GUI/IPC event.

## Action meanings

- `ALLOW`: permit the pre-execution request.
- `ALLOW_MONITOR`: permit and continue runtime telemetry.
- `WARN`: emit a visible warning without destructive action.
- `DENY`: acknowledge a denial already applied by fanotify; it cannot be used
  retroactively.
- `TERMINATE`: stop the exact correlation-bound process through a pidfd.
- `QUARANTINE`: terminate the bound process when present, then quarantine the
  exact bound file.
- `RESTORE`: restore an authorised quarantine record without overwriting.

## Safety properties

- no arbitrary PID/path action is exposed through IPC;
- PID reuse is mitigated with pidfds plus start-time and executable identity;
- a held file descriptor prevents inode reuse while a response is pending;
- replacement paths, symlinks and changed hashes are refused;
- destructive actions are off by default;
- equal or weaker duplicate responses are suppressed;
- ELYRA protected paths and processes are refused.

## Remaining limitations

- Stage 11 tests the response engine separately from the installed systemd
  daemon; installed end-to-end execution remains unverified.
- fanotify file descriptors are not yet passed directly into quarantine; the
  held response-engine descriptor plus quarantine identity checks provide a
  strong path-race defence, but descriptor hand-off would further reduce the
  remaining pathname dependency.
- response thresholds are provisional and require representative-corpus
  calibration.
