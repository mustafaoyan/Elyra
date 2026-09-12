# Stage 10 — Pre-execution/runtime correlation

Stage 10 joins the static fanotify decision to subsequent eBPF process, file,
rename and network events. The correlation engine is intentionally a state and
recommendation layer. It does **not** terminate a process or quarantine a file;
those side effects are deferred to Stage 11.

## State path

```text
fanotify analysis
→ pending execution state
→ eBPF PROCESS_EXEC binding
→ runtime event indicators
→ runtime score
→ combined score
→ recommended action
→ PROCESS_EXIT / expiration
```

The canonical formula is explicit and reachable:

```text
combined_score = min(100, pre_execution_score + runtime_score)
```

The development thresholds are provisional:

| Combined score | Recommended action |
|---:|---|
| 0–39 | CONTINUE_MONITORING |
| 40–69 | ALERT |
| 70–89 | TERMINATE |
| 90–100 | QUARANTINE |

A fanotify kernel denial remains `DENY` and is recorded as a terminal
pre-execution state.

## Runtime evidence

Runtime scoring uses capped, visible contributions for unique file identifiers,
rename operations, unique network endpoints, runtime-only child execution and
fanotify/eBPF executable-identifier mismatch. Repeated writes to the same
`device:inode` identifier do not repeatedly increase the score.

All weights and thresholds are labelled `PROVISIONAL_NOT_CALIBRATED` and are
stored in `src/elyra/config/runtime_correlation.default.json`.

## Process identity and lifecycle

- fanotify PID/TGID is bound to the eBPF `PROCESS_EXEC` event;
- eBPF-first races can be late-bound to the later fanotify record;
- runtime-only children retain a parent correlation identifier but do not
  silently inherit the parent's pre-execution score;
- a second exec on the same PID creates a new generation;
- exited and inactive states expire using bounded time-to-live settings;
- Stage 10 outputs `NOT_EXECUTED_STAGE10` for all recommended side effects.

## Safe verification

```bash
python -m compileall -q src scripts tests
PYTHONPATH=src python -m pytest -q
PYTHONPATH=src python scripts/demonstrate_runtime_correlation.py \
  --output evidence/correlation/stage10_correlation_pardus.json
```

The demonstration uses synthetic records only and performs no privileged or
harmful action.
