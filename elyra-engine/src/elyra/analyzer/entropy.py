"""Canonical Shannon-entropy implementation for ELYRA.

The implementation scans files in bounded chunks.  It does not classify a file as
malicious.  The configurable high-entropy threshold is provisional and exists only
for descriptive reporting until controlled calibration is completed.
"""

from __future__ import annotations

import math
import os
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import BinaryIO

import numpy as np


class EntropyAnalysisError(RuntimeError):
    """Base class for controlled entropy-analysis failures."""


class InvalidEntropyConfiguration(ValueError):
    """Raised when an entropy configuration is internally invalid."""


class FileAccessError(EntropyAnalysisError):
    """Raised when a target file cannot be safely opened or read."""


class UnsupportedFileTypeError(EntropyAnalysisError):
    """Raised when the target is not a regular file."""


@dataclass(frozen=True, slots=True)
class EntropyConfig:
    block_size: int = 4096
    read_chunk_size: int = 1024 * 1024
    provisional_high_entropy_threshold: float = 7.5
    max_reported_blocks: int = 4096

    def __post_init__(self) -> None:
        if self.block_size <= 0:
            raise InvalidEntropyConfiguration("block_size must be greater than zero")
        if self.read_chunk_size < self.block_size:
            raise InvalidEntropyConfiguration(
                "read_chunk_size must be greater than or equal to block_size"
            )
        if self.read_chunk_size % self.block_size != 0:
            raise InvalidEntropyConfiguration(
                "read_chunk_size must be an exact multiple of block_size"
            )
        if not 0.0 <= self.provisional_high_entropy_threshold <= 8.0:
            raise InvalidEntropyConfiguration(
                "provisional_high_entropy_threshold must be between 0 and 8"
            )
        if self.max_reported_blocks <= 0:
            raise InvalidEntropyConfiguration(
                "max_reported_blocks must be greater than zero"
            )


@dataclass(frozen=True, slots=True)
class BlockEntropy:
    index: int
    offset: int
    size: int
    entropy: float
    above_provisional_threshold: bool


@dataclass(slots=True)
class EntropyReport:
    file_size: int
    bytes_analyzed: int
    whole_file_entropy: float
    block_size: int
    block_count: int
    high_entropy_block_count: int
    high_entropy_block_ratio: float
    min_block_entropy: float
    max_block_entropy: float
    mean_block_entropy: float
    provisional_high_entropy_threshold: float
    threshold_status: str = "PROVISIONAL_NOT_CALIBRATED"
    reported_blocks: list[BlockEntropy] = field(default_factory=list)
    blocks_truncated: bool = False
    report_sample_stride: int = 1

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class EntropyEngine:
    """Memory-bounded whole-file and block-level Shannon entropy analyser."""

    def __init__(self, config: EntropyConfig | None = None) -> None:
        self.config = config or EntropyConfig()

    @staticmethod
    def shannon_entropy(data: bytes | bytearray | memoryview) -> float:
        """Return byte-wise Shannon entropy in the range 0..8 bits/byte."""
        if not data:
            return 0.0
        view = memoryview(data)
        counts = np.bincount(np.frombuffer(view, dtype=np.uint8), minlength=256)
        probabilities = counts[counts > 0] / len(view)
        return float(-np.sum(probabilities * np.log2(probabilities)))

    @staticmethod
    def _validate_target(path: Path) -> os.stat_result:
        try:
            metadata = path.lstat()
        except FileNotFoundError as exc:
            raise FileAccessError(f"file does not exist: {path}") from exc
        except PermissionError as exc:
            raise FileAccessError(f"permission denied while stating file: {path}") from exc
        except OSError as exc:
            raise FileAccessError(f"cannot stat file {path}: {exc}") from exc

        if stat.S_ISLNK(metadata.st_mode):
            raise UnsupportedFileTypeError(
                f"symbolic links are not scanned by the Stage 3 analyser: {path}"
            )
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsupportedFileTypeError(f"target is not a regular file: {path}")
        return metadata

    @staticmethod
    def _open_binary(path: Path) -> BinaryIO:
        try:
            return path.open("rb", buffering=0)
        except PermissionError as exc:
            raise FileAccessError(f"permission denied while opening file: {path}") from exc
        except OSError as exc:
            raise FileAccessError(f"cannot open file {path}: {exc}") from exc

    def analyze(self, filepath: str | os.PathLike[str]) -> EntropyReport:
        path = Path(filepath)
        metadata = self._validate_target(path)
        stream = self._open_binary(path)
        return self._analyze_stream(stream, metadata.st_size, str(path))

    def analyze_open_fd(self, fd: int, label: str | None = None) -> EntropyReport:
        """Analyse an already-open regular-file descriptor without closing it."""

        if fd < 0:
            raise ValueError("file descriptor must be non-negative")
        try:
            metadata = os.fstat(fd)
        except OSError as exc:
            raise FileAccessError(f"cannot stat open file descriptor {fd}: {exc}") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise UnsupportedFileTypeError(
                f"open descriptor is not a regular file: {label or fd}"
            )
        try:
            duplicate = os.dup(fd)
            os.lseek(duplicate, 0, os.SEEK_SET)
            stream = os.fdopen(duplicate, "rb", buffering=0)
        except OSError as exc:
            raise FileAccessError(
                f"cannot duplicate open file descriptor {fd}: {exc}"
            ) from exc
        return self._analyze_stream(stream, metadata.st_size, label or f"fd:{fd}")

    def _analyze_stream(
        self,
        stream: BinaryIO,
        file_size: int,
        label: str,
    ) -> EntropyReport:
        expected_blocks = math.ceil(file_size / self.config.block_size) if file_size else 0
        sample_stride = max(
            1,
            math.ceil(expected_blocks / self.config.max_reported_blocks),
        )

        whole_histogram = np.zeros(256, dtype=np.int64)
        block_entropies: list[float] = []
        reported_blocks: list[BlockEntropy] = []
        bytes_analyzed = 0
        high_count = 0
        block_index = 0
        carry = b""

        try:
            with stream:
                while True:
                    try:
                        chunk = stream.read(self.config.read_chunk_size)
                    except PermissionError as exc:
                        raise FileAccessError(
                            f"permission denied while reading file: {label}"
                        ) from exc
                    except OSError as exc:
                        raise FileAccessError(f"cannot read file {label}: {exc}") from exc
                    if not chunk:
                        break

                    bytes_analyzed += len(chunk)
                    whole_histogram += np.bincount(
                        np.frombuffer(chunk, dtype=np.uint8), minlength=256
                    )
                    buffer = carry + chunk
                    complete_size = (
                        len(buffer) // self.config.block_size
                    ) * self.config.block_size

                    for start in range(0, complete_size, self.config.block_size):
                        block = buffer[start : start + self.config.block_size]
                        entropy = self.shannon_entropy(block)
                        block_entropies.append(entropy)
                        above = (
                            entropy
                            >= self.config.provisional_high_entropy_threshold
                        )
                        high_count += int(above)
                        if block_index % sample_stride == 0:
                            reported_blocks.append(
                                BlockEntropy(
                                    index=block_index,
                                    offset=block_index * self.config.block_size,
                                    size=len(block),
                                    entropy=round(entropy, 6),
                                    above_provisional_threshold=above,
                                )
                            )
                        block_index += 1
                    carry = buffer[complete_size:]

                if carry:
                    entropy = self.shannon_entropy(carry)
                    block_entropies.append(entropy)
                    above = entropy >= self.config.provisional_high_entropy_threshold
                    high_count += int(above)
                    if block_index % sample_stride == 0:
                        reported_blocks.append(
                            BlockEntropy(
                                index=block_index,
                                offset=block_index * self.config.block_size,
                                size=len(carry),
                                entropy=round(entropy, 6),
                                above_provisional_threshold=above,
                            )
                        )
                    block_index += 1
        except FileAccessError:
            raise

        if bytes_analyzed != file_size:
            raise FileAccessError(
                f"file changed or was incompletely read: expected {file_size} bytes, "
                f"read {bytes_analyzed}"
            )

        nonzero = whole_histogram[whole_histogram > 0]
        if bytes_analyzed:
            probabilities = nonzero / bytes_analyzed
            whole_entropy = float(-np.sum(probabilities * np.log2(probabilities)))
        else:
            whole_entropy = 0.0

        block_count = len(block_entropies)
        return EntropyReport(
            file_size=file_size,
            bytes_analyzed=bytes_analyzed,
            whole_file_entropy=round(whole_entropy, 6),
            block_size=self.config.block_size,
            block_count=block_count,
            high_entropy_block_count=high_count,
            high_entropy_block_ratio=round(
                high_count / block_count if block_count else 0.0, 6
            ),
            min_block_entropy=round(min(block_entropies, default=0.0), 6),
            max_block_entropy=round(max(block_entropies, default=0.0), 6),
            mean_block_entropy=round(
                sum(block_entropies) / block_count if block_count else 0.0, 6
            ),
            provisional_high_entropy_threshold=(
                self.config.provisional_high_entropy_threshold
            ),
            reported_blocks=reported_blocks,
            blocks_truncated=len(reported_blocks) < block_count,
            report_sample_stride=sample_stride,
        )

    def whole_file_entropy(self, filepath: str | os.PathLike[str]) -> float:
        return self.analyze(filepath).whole_file_entropy

    def block_level_entropy(
        self, filepath: str | os.PathLike[str]
    ) -> list[BlockEntropy]:
        return self.analyze(filepath).reported_blocks
