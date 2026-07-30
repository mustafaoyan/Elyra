# Stage 10 correlation audit

| Issue | Previous file/behaviour | Severity | Effect | Stage 10 correction |
|---|---|---:|---|---|
| Runtime scoring was disconnected from fanotify state | `scoring/runtime_engine.py` | Critical | No reliable pre-execution → runtime chain | Replaced by one canonical bounded correlation engine |
| Runtime score could only inspect command strings and one network field | old runtime engine | High | Required file/rename/network telemetry was not correlated | Uses typed Stage 9 event records and visible capped rules |
| Score formula and reachability were not validated | old runtime engine | High | Configured actions could be unreachable | Direct bounded sum and configuration-time reachability validation |
| Process-to-executable mapping was absent | daemon consumers | Critical | eBPF events could not be attributed to the analysed executable | Same-PID binding plus eBPF-first late binding |
| Parent-child handling was absent | daemon/runtime aggregator | High | Runtime-only children lost context | Parent correlation link without silently inheriting static score |
| PID reuse and repeated exec were not modelled | old PID dictionary | High | New processes could inherit stale risk | Explicit generations and archival on repeated exec |
| Process state had no terminal retention/expiration model | old runtime engine | Medium | Unbounded or prematurely lost state | Active and exited TTLs with bounded state eviction |
| Runtime score could grow from duplicate writes | old ad hoc updates | High | One file could inflate risk repeatedly | Unique `device:inode` keys and capped occurrences |
| Runtime scorer directly returned terminate/quarantine actions without integration boundary | old runtime engine | High | Side-effect ownership was unclear | Stage 10 emits recommendations only; Stage 11 owns execution |
| GUI/API had no structured runtime-state access | IPC API | Medium | Evolving score could not be inspected | Added bounded `list_runtime_states` action and status summary |

## Verification classification

- **Verified by source inspection:** state model, bounded score formula, no Stage 10 side effects.
- **Verified by automated test:** mapping, late binding, all four transitions, deduplication, parent-child links, PID generations and expiration.
- **Verified on generic Linux:** full suite and synthetic demonstration.
- **Requires Pardus verification:** full test suite and synthetic demonstration on the target system.
- **Requires integrated root/kernel verification later:** simultaneous production fanotify and eBPF daemon workflow.
