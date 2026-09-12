# Stage 8 — fanotify pre-execution monitoring

## Safety defaults

The Stage 8 default is `MONITOR_ONLY` plus `FAIL_OPEN`. `ENFORCEMENT` is available but must be selected explicitly. `FAIL_CLOSED` is supported only for explicitly configured paths and is not enabled by the default policy.

## Execution workflow

1. `FanotifyInterface` receives `FAN_OPEN_EXEC_PERM` metadata.
2. Every metadata record in the kernel buffer is parsed.
3. Queue overflow, unsupported metadata, non-permission records, and invalid descriptors are handled explicitly.
4. The controller filters ELYRA processes, ELYRA/system paths, and paths outside policy.
5. Static analysis reads through the event descriptor rather than reopening the pathname.
6. The Stage 4 scoring engine returns the explainable requested decision.
7. `MONITOR_ONLY` always sends `FAN_ALLOW`; enforcement sends `FAN_DENY` only for a valid `DENY` result.
8. A response guard attempts a permission response for every valid permission event.
9. The complete record is written to the audit log and daemon event queue.

## Time and load safeguards

- Event-handler and static-analysis executors are separate.
- Pending event work is bounded.
- Queue saturation receives immediate fail-open handling.
- The response deadline starts when the event is received, not when analysis starts.
- Files over the configurable pre-execution size limit are allowed and marked for deferred monitoring.
- A kernel queue overflow is logged as a critical degraded state.

## Safe tests

The non-root demonstration uses a fake syscall boundary and proves controller semantics only:

```bash
PYTHONPATH=src python scripts/demonstrate_fanotify_controller.py \
  --output evidence/fanotify/stage8_controller_pardus.json
```

The real root/kernel verifier uses only temporary copies of `/bin/true` and a harmless shell script. It marks only one temporary directory and does not start systemd or eBPF:

```bash
sudo -E env PYTHONPATH=src .venv/bin/python \
  scripts/verify_fanotify_pardus.py \
  --output evidence/fanotify/stage8_fanotify_root_pardus.json
```

The root test must be run only after the ordinary 105-test suite and non-root demonstration pass. Its JSON result is the evidence for actual Pardus/kernel behaviour.

## Honest limitations

Mount marks observe a whole mount and are filtered in user space; they are not recursive path marks. Script/interpreter behaviour is recorded by the real verifier and must not be claimed before that result exists. Closing the fanotify listener during catastrophic failure is a final kernel-level release mechanism, but the implementation does not claim that user-space code can guarantee a response after process death or kernel failure.
