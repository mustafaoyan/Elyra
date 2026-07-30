from __future__ import annotations

import gzip
import random
from pathlib import Path

import pytest

from elliot.analyzer.entropy import (
    EntropyConfig,
    EntropyEngine,
    FileAccessError,
    InvalidEntropyConfiguration,
)


def test_shannon_entropy_known_inputs() -> None:
    engine = EntropyEngine()
    assert engine.shannon_entropy(b"") == 0.0
    assert engine.shannon_entropy(b"A" * 4096) == 0.0
    assert engine.shannon_entropy(bytes(range(256)) * 16) == pytest.approx(8.0)


def test_empty_and_repeated_files(tmp_path: Path) -> None:
    empty = tmp_path / "empty.bin"
    repeated = tmp_path / "repeated.bin"
    empty.write_bytes(b"")
    repeated.write_bytes(b"\x00" * 8192)

    empty_report = EntropyEngine().analyze(empty)
    repeated_report = EntropyEngine().analyze(repeated)

    assert empty_report.file_size == 0
    assert empty_report.block_count == 0
    assert empty_report.whole_file_entropy == 0.0
    assert repeated_report.block_count == 2
    assert repeated_report.whole_file_entropy == 0.0


def test_text_random_and_compressed_are_measured_not_classified(tmp_path: Path) -> None:
    text_path = tmp_path / "ordinary.txt"
    random_path = tmp_path / "random.bin"
    compressed_path = tmp_path / "ordinary.txt.gz"
    text = ("ELLIOT Pardus güvenli analiz testi\n" * 1000).encode("utf-8")
    text_path.write_bytes(text)
    random_path.write_bytes(random.Random(2026).randbytes(len(text)))
    with gzip.open(compressed_path, "wb") as stream:
        stream.write(text)

    engine = EntropyEngine()
    text_report = engine.analyze(text_path)
    random_report = engine.analyze(random_path)
    compressed_report = engine.analyze(compressed_path)

    assert random_report.whole_file_entropy > text_report.whole_file_entropy
    assert 0.0 <= compressed_report.whole_file_entropy <= 8.0
    assert random_report.threshold_status == "PROVISIONAL_NOT_CALIBRATED"


def test_large_file_is_streamed_and_block_report_is_bounded(tmp_path: Path) -> None:
    large = tmp_path / "large.bin"
    large.write_bytes(bytes(range(256)) * (5 * 1024 * 1024 // 256))
    config = EntropyConfig(
        block_size=4096,
        read_chunk_size=1024 * 1024,
        max_reported_blocks=10,
    )
    report = EntropyEngine(config).analyze(large)

    assert report.bytes_analyzed == large.stat().st_size
    assert report.block_count == 1280
    assert len(report.reported_blocks) <= 10
    assert report.blocks_truncated is True
    assert report.report_sample_stride > 1
    assert report.whole_file_entropy == pytest.approx(8.0)


def test_missing_file_has_controlled_error(tmp_path: Path) -> None:
    with pytest.raises(FileAccessError, match="does not exist"):
        EntropyEngine().analyze(tmp_path / "missing.bin")


def test_unreadable_file_has_controlled_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "unreadable.bin"
    target.write_bytes(b"safe")

    def deny_open(path: Path):
        raise FileAccessError(f"permission denied while opening file: {path}")

    monkeypatch.setattr(EntropyEngine, "_open_binary", staticmethod(deny_open))
    with pytest.raises(FileAccessError, match="permission denied"):
        EntropyEngine().analyze(target)


def test_invalid_entropy_configuration_is_rejected() -> None:
    with pytest.raises(InvalidEntropyConfiguration):
        EntropyConfig(block_size=0)
    with pytest.raises(InvalidEntropyConfiguration):
        EntropyConfig(block_size=4096, read_chunk_size=5000)
    with pytest.raises(InvalidEntropyConfiguration):
        EntropyConfig(provisional_high_entropy_threshold=9.0)


def test_final_partial_block_is_included(tmp_path: Path) -> None:
    target = tmp_path / "partial.bin"
    target.write_bytes(b"A" * 4097)
    report = EntropyEngine().analyze(target)
    assert report.block_count == 2
    assert report.reported_blocks[-1].offset == 4096
    assert report.reported_blocks[-1].size == 1
