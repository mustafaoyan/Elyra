# Stage 15.2 — Stage 4 scoring evidence-schema audit

## Confirmed defect

`evidence/scoring/stage4_scoring_pardus.json` was produced by the original Stage 4
demonstration before the final submission schema existed. Its three scenario
results were present, but the document had no top-level `overall_status` field.
The strict finalizer therefore correctly reported:

```text
explainable_scoring: FAIL — overall_status is None, expected 'OK'
```

This was an evidence-schema incompatibility. It was not a Pardus permission
problem, a scoring-engine failure, or a request to execute malware.

## Controlled correction

The Stage 4 demonstration now derives an explicit status from validated scenario
outcomes. It reports `overall_status: OK` only when all of the following are true:

1. the three required scenarios are present exactly once;
2. harmless ordinary text receives `ALLOW`;
3. entropy-only evidence does not receive `DENY`, has no static/context score,
   and carries the entropy-only limitation note;
4. the explicitly labelled combined synthetic fixture reaches `DENY`;
5. every result exposes a structured score, decision, category breakdown and
   indicator list.

The generator exits non-zero and writes `overall_status: FAIL` when any derived
check fails. No unconditional success marker is inserted, and old evidence is
not silently rewritten by the finalizer.

## Safety boundary

The command scans one harmless text file and one deterministic synthetic-byte
file. The denial-path fixture is a manually constructed scoring object. No file
is executed, no malware is downloaded, and no root/kernel privilege is needed.
