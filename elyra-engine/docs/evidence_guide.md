# Evidence Guide

Each result should record date/time, project version or Git commit, Pardus
version, kernel, architecture, Python, command, expected result, actual result
and a log or screenshot.

## Required machine-readable evidence

The finalizer checks the critical Pardus JSON/text records from Stages 3–14.1.
It validates `overall_status: OK` for workflow JSON files and rejects empty or
symbolic-link evidence.

## Finalization

```bash
PYTHONPATH=src python scripts/finalize_submission.py --project-root . --strict
```

Outputs:

```text
evidence/environment/final_environment_pardus.json
evidence/submission/final_manifest.json
evidence/submission/final_checksums.sha256
evidence/submission/final_inventory.txt
evidence/submission/FINAL_STATUS.md
```

A result of `INCOMPLETE` must not be renamed or edited to appear complete.
Restore the missing evidence or rerun the failed verification.

## Screenshot rules

- Capture the command and result in the same image when practical.
- Do not expose passwords, malware binaries, personal addresses or unrelated
  personal data.
- Use descriptive filenames under the matching evidence directory.
- Retain original JSON/text output; screenshots are supporting evidence, not a
  substitute for machine-readable records.
