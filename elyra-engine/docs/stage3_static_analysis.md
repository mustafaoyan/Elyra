# Stage 3 static-analysis contract

`EntropyEngine` is the only Shannon-entropy implementation. It computes exact
whole-file entropy with a streaming byte histogram and computes block entropy using a
configurable block size. Large files are fully scanned, while the detailed block list is
deterministically sampled when it would exceed `max_reported_blocks`; aggregate values
still include every block.

`StaticFileScanner` returns a `StaticScanResult` containing:

- scan status and structured errors/warnings;
- MIME type and detection source;
- extension/MIME consistency;
- ELF validity, entry point, sections, segments and writable-executable indicators;
- SUID, SGID, world-writable and execute permission states;
- hidden-path and selected high-risk-location context;
- whole-file and block-level entropy;
- analysis duration.

The scanner extracts evidence only. High entropy is common in legitimate compressed,
encrypted and packed content and is not treated as a malware verdict.

## Benchmark

From an activated virtual environment:

```bash
PYTHONPATH=src python scripts/benchmark_static_analysis.py \
  --output evidence/entropy/stage3_benchmark.json
```

The benchmark creates only temporary deterministic byte-pattern files and deletes them
automatically.
