# Stage 4 scoring audit

| Classification | Issue | Original file and lines | Severity | Effect | Stage 4 correction |
|---|---|---:|---|---|---|
| Confirmed defect | A temporary score class was embedded in the static evidence extractor. | `src/elliot/analyzer/static_analyzer.py:437-459` | High | Analysis and policy responsibilities were mixed. | Removed it and introduced `elliot.scoring.engine.PreExecutionScoringEngine`. |
| Confirmed defect | The pre-execution adapter duplicated thresholds and decision logic. | `src/elliot/analyzer/pre_execution.py:64-87` | High | Two locations could produce inconsistent decisions and explanations. | The adapter now delegates all scoring to the canonical engine. |
| Confirmed defect | The old result exposed only a formatted score and a flat rule-name list. | `src/elliot/analyzer/pre_execution.py:84-88` | High | The weight, category, evidence and description of each contribution were unavailable. | Added a versioned structured result with full indicator objects and category scores. |
| Incomplete feature | Weights and thresholds were hard-coded and not validated. | Static analyser and pre-execution adapter | High | Policy changes required source edits and invalid threshold combinations were possible. | Added packaged UTF-8 JSON policy loading and strict configuration validation. |
| Architectural inconsistency | Entropy, ELF, permission and path evidence were combined without category separation. | Temporary Stage 3 score adapter | Medium | It was difficult to explain which evidence family caused a decision. | Added separate entropy, static and context category scores with explicit caps. |
| Safety concern | A high total score had no explicit denial gate requiring non-entropy/static evidence. | Temporary Stage 3 decision logic | High | Future threshold changes could accidentally make entropy sufficient for denial. | DENY now requires both the total threshold and a configurable minimum static score. |
| Incomplete feature | Error and timeout outputs used a different result schema. | `src/elliot/analyzer/pre_execution.py:34-61` | Medium | GUI/daemon consumers would need special-case parsing. | Added structured degraded results with score 0, `ALLOW_MONITOR`, evidence and audit notes. |
| Unverified behaviour | The scoring result is not yet connected to real fanotify permission responses. | Kernel integration | Kernel-dependent | Passing unit tests cannot demonstrate actual prevention. | Explicitly deferred to Stage 8 and labelled unverified. |

All Stage 4 weights and thresholds remain `PROVISIONAL_NOT_CALIBRATED`. They are
development policy values, not validated malware-detection parameters.
