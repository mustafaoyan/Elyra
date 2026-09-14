# Elyra submission checklist

Use this checklist before creating a release archive.

- [ ] Run the complete test suite on the target Linux/Pardus environment.
- [ ] Record kernel, headers, fanotify and eBPF capability evidence.
- [ ] Run `scripts/finalize_submission.py --strict` and confirm `COMPLETE`.
- [ ] Build the Debian package and reproducible release archives.
- [ ] Generate SHA-256 checksums and verify them on a clean checkout.
- [ ] Review `SECURITY.md`, `RELEASE_NOTES.md` and known limitations.
- [ ] Confirm monitor-only defaults and that no cloud telemetry is enabled.
- [ ] Publish only signed artifacts with their checksums.
