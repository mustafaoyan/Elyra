# Stage 4 — Explainable pre-execution scoring

## Purpose

The Stage 4 engine converts the structured Stage 3 scan result into a deterministic,
explainable pre-execution score. It does not label a file as malware. The packaged
policy is explicitly marked `PROVISIONAL_NOT_CALIBRATED`.

## Output contract

The engine returns:

- integer `score` in the range 0–100;
- `decision`: `ALLOW`, `ALLOW_MONITOR`, `WARN`, or `DENY`;
- separate `entropy`, `static`, and `context` category scores;
- each triggered rule with its category, configured weight, observed evidence and
  human-readable description;
- policy version, thresholds, category caps and explanatory notes;
- compatibility fields `risk_score` and `contributing_indicators` for the current
  fanotify adapter.

## Default provisional thresholds

- `ALLOW`: score below 20;
- `ALLOW_MONITOR`: 20–39;
- `WARN`: 40–69;
- `DENY`: at least 70 **and** at least 25 points of static evidence.

The denial gate prevents entropy-only evidence from denying execution, even if a
future local configuration lowers the total denial threshold. Category caps also
prevent repeated indicators from growing without bound.

## Configuration

The canonical packaged development policy is:

`src/elliot/config/scoring.default.json`

A separate policy may be loaded with:

```python
from elliot.scoring import PreExecutionScoringEngine

engine = PreExecutionScoringEngine.from_config_file("/etc/elliot/scoring.json")
```

Invalid JSON, missing fields, unsupported categories, invalid weights or
non-monotonic decision thresholds are rejected explicitly.

## Safety and limitations

- High entropy is descriptive evidence, not proof of malware.
- The default weights have not been calibrated against a representative corpus.
- A score is only as reliable as the static evidence available to it.
- `PARTIAL` scans are disclosed in the result.
- Failed scans use the documented provisional fail-open result:
  `ALLOW_MONITOR`, score 0, critical audit requirement.
- fanotify enforcement, daemon authorisation, GUI display and eBPF correlation are
  not verified by Stage 4.
