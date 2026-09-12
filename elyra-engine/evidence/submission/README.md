# Submission evidence

The finalization command creates:

- `final_manifest.json` — required-evidence status and complete file inventory;
- `final_checksums.sha256` — SHA-256 hashes for retained evidence;
- `final_inventory.txt` — file sizes and modes;
- `FINAL_STATUS.md` — human-readable completion report.

Never edit generated evidence to hide a failure. Correct the underlying problem,
rerun the relevant verification and regenerate the manifest.
