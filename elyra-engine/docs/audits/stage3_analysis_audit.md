# Stage 3 entropy and static-analysis audit

## Confirmed Stage 2 defects

| Issue | Original file and line | Severity | Effect | Stage 3 repair |
|---|---:|---|---|---|
| Two independent Shannon-entropy implementations | `pre_execution.py:71-113`, `static_analyzer.py:28-82` | High | Different block sizes, thresholds and file-size behaviour | Added one canonical streaming engine in `entropy.py`; fanotify wrapper now delegates to it |
| Whole-file entropy loaded the complete file into memory | `static_analyzer.py:47-50` | High | Unbounded memory use for large files | Bounded streaming histogram and bounded block reporting |
| Pre-execution analysis silently truncated files at 5 MiB | `pre_execution.py:35-43` | High | Reported “whole-file” entropy was not whole-file entropy | Removed truncation; complete file is streamed |
| Block-count calculation ignored a final partial block | `pre_execution.py:99-108` | Medium | Incorrect high-entropy ratio | Canonical block counter includes the final partial block |
| ELF parse failures were silently swallowed | `pre_execution.py:121-131` | High | Malformed ELF and parser failures were invisible | Structured warnings/errors and explicit ELF-validity field |
| Static analyser mixed extraction, runtime simulation and scoring | `static_analyzer.py:196-347` | High | Unclear component boundaries and executable demo side effects | Removed demo/runtime code; retained only a documented temporary scoring adapter for daemon compatibility |
| MIME/extension consistency was checked only for a few suffixes | both analyser files | Medium | Inconsistent content could be missed or misrepresented | Explicit MIME source, expected types and `CONSISTENT/INCONSISTENT/UNKNOWN` result |
| Permission analysis detected only SUID/SGID and combined world-write/execute | `static_analyzer.py:165-178` | Medium | World-writable state was not independently exposed | Structured mode details and independent indicators |
| Symlinks were followed implicitly | analyser file opens | High | Potential path substitution and misleading scan target | Stage 3 default rejects symlinks; stronger descriptor-based TOCTOU control remains Stage 5 work |

## Threshold statement

The block threshold in `EntropyConfig` is explicitly named
`provisional_high_entropy_threshold`. It is descriptive, configurable and marked
`PROVISIONAL_NOT_CALIBRATED`. It is not proof of malware and cannot alone produce a
deny decision in the temporary compatibility adapter.

## Verification boundary

Source extraction, deterministic entropy calculations, MIME analysis, ELF metadata,
permission flags, path context and controlled errors are covered by unit tests.
fanotify timing, root-only permissions, real kernel interception and eBPF behaviour are
not part of Stage 3 and remain unverified.
