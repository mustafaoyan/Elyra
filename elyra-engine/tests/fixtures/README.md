# Safe Stage 3 fixtures

Stage 3 tests generate harmless temporary files through `tmp_path`. Permanent binary
fixtures are intentionally not stored here. Future fixtures must be demonstrably safe,
small and documented.
