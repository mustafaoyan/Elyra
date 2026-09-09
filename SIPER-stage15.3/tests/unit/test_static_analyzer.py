from __future__ import annotations

import gzip
import os
import shutil
import sys
from pathlib import Path

import pytest

from elliot.analyzer.entropy import EntropyConfig, FileAccessError
from elliot.analyzer.static_analyzer import StaticAnalyzerConfig, StaticFileScanner


def _scanner() -> StaticFileScanner:
    return StaticFileScanner(
        StaticAnalyzerConfig(
            entropy=EntropyConfig(block_size=1024, read_chunk_size=1024 * 1024)
        )
    )


def _harmless_elf() -> Path:
    candidates = [Path("/bin/true"), Path(sys.executable)]
    return next(path for path in candidates if path.exists())


def test_ordinary_text_and_compressed_file(tmp_path: Path) -> None:
    text = tmp_path / "example.txt"
    compressed = tmp_path / "example.txt.gz"
    content = ("Pardus ELLIOT test data\n" * 100).encode()
    text.write_bytes(content)
    with gzip.open(compressed, "wb") as stream:
        stream.write(content)

    text_scan = _scanner().scan(text)
    compressed_scan = _scanner().scan(compressed)

    assert text_scan.status == "OK"
    assert text_scan.is_elf is False
    assert text_scan.mime_extension_consistency in {"CONSISTENT", "UNKNOWN"}
    assert compressed_scan.status == "OK"
    assert compressed_scan.mime_type in {"application/gzip", "application/x-gzip"}


@pytest.mark.skipif(os.name == "nt", reason="ELF metadata is a Linux/POSIX parser contract")
def test_harmless_elf_metadata_and_disguised_extension(tmp_path: Path) -> None:
    source = _harmless_elf()
    normal = tmp_path / "harmless.elf"
    disguised = tmp_path / "harmless.txt"
    shutil.copy2(source, normal)
    shutil.copy2(source, disguised)

    normal_scan = _scanner().scan(normal)
    disguised_scan = _scanner().scan(disguised)

    assert normal_scan.is_elf is True
    assert normal_scan.elf_valid in {True, None}
    assert disguised_scan.mime_extension_consistency == "INCONSISTENT"
    assert "MIME_EXTENSION_INCONSISTENT" in disguised_scan.path_indicators
    if normal_scan.elf_valid is True:
        assert normal_scan.elf_segments
        assert normal_scan.elf_sections


def test_malformed_elf_is_reported_without_crash(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.elf"
    malformed.write_bytes(b"\x7fELF" + b"not-a-valid-elf-header")

    scan = _scanner().scan(malformed)

    assert scan.is_elf is True
    assert scan.status in {"PARTIAL", "OK"}
    if scan.elf_valid is False:
        assert any(error["code"] == "MALFORMED_ELF" for error in scan.errors)


@pytest.mark.skipif(os.name == "nt", reason="NTFS ACLs are not POSIX mode bits")
def test_permission_indicators(tmp_path: Path) -> None:
    target = tmp_path / "permissions.bin"
    target.write_bytes(b"safe")
    target.chmod(0o6777)

    scan = _scanner().scan(target)

    assert scan.permission_details["suid"] is True
    assert scan.permission_details["sgid"] is True
    assert scan.permission_details["world_writable"] is True
    assert "SUID_BIT_SET" in scan.permission_anomalies
    assert "SGID_BIT_SET" in scan.permission_anomalies
    assert "WORLD_WRITABLE" in scan.permission_anomalies


def test_hidden_and_temporary_path_context(tmp_path: Path) -> None:
    hidden_dir = tmp_path / ".hidden"
    hidden_dir.mkdir()
    target = hidden_dir / "sample.bin"
    target.write_bytes(b"safe")

    scan = _scanner().scan(target)

    assert scan.path_context["hidden"] is True
    assert "HIDDEN_PATH_COMPONENT" in scan.path_indicators


def test_missing_file_returns_structured_error(tmp_path: Path) -> None:
    scan = _scanner().scan(tmp_path / "missing.bin")
    assert scan.status == "ERROR"
    assert scan.errors == [
        {
            "code": "FILE_NOT_FOUND",
            "message": f"file does not exist: {tmp_path / 'missing.bin'}",
        }
    ]


def test_unreadable_file_returns_structured_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "unreadable.bin"
    target.write_bytes(b"safe")

    def deny_read(path: Path, size: int = 64) -> bytes:
        raise FileAccessError(f"permission denied while reading file: {path}")

    monkeypatch.setattr(StaticFileScanner, "_read_head", staticmethod(deny_read))
    scan = _scanner().scan(target)
    assert scan.status == "ERROR"
    assert scan.errors[0]["code"] == "FILE_READ_FAILED"


def test_large_file_records_analysis_time(tmp_path: Path) -> None:
    target = tmp_path / "large.bin"
    target.write_bytes(b"ABCD" * (2 * 1024 * 1024 // 4))

    scan = _scanner().scan(target)

    assert scan.status == "OK"
    assert scan.file_size == 2 * 1024 * 1024
    assert scan.duration_ms >= 0.0
    assert scan.entropy_summary["bytes_analyzed"] == target.stat().st_size


@pytest.mark.skipif(os.name == "nt", reason="symbolic-link creation requires a Windows privilege")
def test_symlink_is_not_followed_by_default(tmp_path: Path) -> None:
    target = tmp_path / "target.bin"
    link = tmp_path / "link.bin"
    target.write_bytes(b"safe")
    os.symlink(target, link)

    scan = _scanner().scan(link)

    assert scan.status == "ERROR"
    assert scan.errors[0]["code"] == "SYMLINK_NOT_SCANNED"
