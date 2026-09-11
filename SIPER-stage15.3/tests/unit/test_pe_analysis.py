"""Synthetic PE headers only: fixtures contain no executable instructions."""

from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest

from elliot.analyzer.pe import (
    MAX_INSPECTION_BYTES,
    MAX_OPTIONAL_HEADER_SIZE,
    MAX_PE_HEADER_OFFSET,
    MAX_SECTIONS,
    analyze_pe,
)
from elliot.analyzer.static_analyzer import StaticFileScanner


def _pe_bytes(*, plus: bool = False, dll: bool = False, sections: int = 1) -> bytearray:
    """Build harmless, structurally complete headers followed by zero bytes."""
    pe_offset = 0x80
    optional_size = 240 if plus else 224
    table_offset = pe_offset + 24 + optional_size
    headers_size = ((table_offset + sections * 40 + 511) // 512) * 512
    data = bytearray(headers_size + sections * 512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe_offset)
    data[pe_offset:pe_offset + 4] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH", data, pe_offset + 4,
        0x8664 if plus else 0x14C, sections, 0, 0, 0, optional_size,
        0x0002 | (0x2000 if dll else 0),
    )
    optional_offset = pe_offset + 24
    struct.pack_into("<H", data, optional_offset, 0x20B if plus else 0x10B)
    struct.pack_into("<I", data, optional_offset + 16, 0 if dll else 0x1000)
    struct.pack_into("<Q" if plus else "<I", data, optional_offset + (24 if plus else 28), 0x140000000 if plus else 0x400000)
    struct.pack_into("<II", data, optional_offset + 32, 0x1000, 512)
    struct.pack_into("<II", data, optional_offset + 56, (sections + 1) * 0x1000, headers_size)
    struct.pack_into("<HH", data, optional_offset + 68, 3, 0x140)
    struct.pack_into("<I", data, optional_offset + (108 if plus else 92), 16)
    for index in range(sections):
        offset = table_offset + index * 40
        data[offset:offset + 8] = f".s{index}".encode().ljust(8, b"\x00")
        struct.pack_into("<IIII", data, offset + 8, 512, (index + 1) * 0x1000, 512, headers_size + index * 512)
        struct.pack_into("<I", data, offset + 36, 0x60000020)
    return data


def _write(tmp_path: Path, data: bytes | bytearray, name: str = "fixture.exe") -> Path:
    target = tmp_path / name
    target.write_bytes(data)
    return target


@pytest.mark.parametrize("plus,architecture,format_name", [(False, "x86", "PE32"), (True, "x64", "PE32+")])
def test_pe32_and_pe32_plus_headers(tmp_path: Path, plus: bool, architecture: str, format_name: str) -> None:
    result = analyze_pe(_write(tmp_path, _pe_bytes(plus=plus)))

    assert result.is_pe is True
    assert result.valid is True
    assert result.summary["status"] == "COMPLETE"
    assert result.summary["format"] == format_name
    assert result.summary["architecture"] == architecture
    assert result.summary["section_count"] == 1
    assert result.summary["entry_point_rva"] == 0x1000
    assert result.summary["certificate_table_present"] is False
    assert result.summary["signature_verification"] == "NOT_PERFORMED"
    assert result.sections[0]["raw_offset"] == 512
    assert result.sections[0]["flags"] == {"readable": True, "writable": False, "executable": True}
    assert result.anomalies == []


def test_dll_zero_entry_point_is_not_an_anomaly(tmp_path: Path) -> None:
    result = analyze_pe(_write(tmp_path, _pe_bytes(plus=True, dll=True), "fixture.dll"))
    assert result.valid is True
    assert result.summary["is_dll"] is True
    assert result.summary["entry_point_rva"] == 0
    assert not result.anomalies


@pytest.mark.parametrize("data", [b"", b"plain text", b"\x7fELF\x00", b"PK\x03\x04archive bytes"])
def test_non_pe_files_remain_not_applicable(tmp_path: Path, data: bytes) -> None:
    result = analyze_pe(_write(tmp_path, data))
    assert result.is_pe is False
    assert result.valid is None
    assert result.summary["status"] == "NOT_PE"
    assert not result.warnings
    assert not result.sections


@pytest.mark.parametrize("length", [2, 63, 64, 140, 153, 220, 400, 600])
def test_truncation_is_incomplete_evidence(tmp_path: Path, length: int) -> None:
    result = analyze_pe(_write(tmp_path, _pe_bytes()[:length]))
    assert result.valid is False
    assert result.summary["status"] == "INCOMPLETE"
    assert result.warnings
    assert result.summary["bytes_read"] <= MAX_INSPECTION_BYTES


@pytest.mark.parametrize("offset", [0, 32, 63, 0xFFFFFFFF])
def test_untrusted_e_lfanew_cannot_escape_file(tmp_path: Path, offset: int) -> None:
    data = _pe_bytes()
    struct.pack_into("<I", data, 0x3C, offset)
    result = analyze_pe(_write(tmp_path, data))
    assert result.is_pe is False
    assert result.valid is False
    assert result.anomalies == ["PE_HEADER_OUT_OF_BOUNDS"]
    assert result.summary["bytes_read"] == 64


def test_header_offset_limit_does_not_read_gap(tmp_path: Path) -> None:
    data = _pe_bytes()
    offset = MAX_PE_HEADER_OFFSET + 1
    struct.pack_into("<I", data, 0x3C, offset)
    target = _write(tmp_path, data)
    with target.open("r+b") as stream:
        stream.seek(offset + 24)
        stream.write(b"\x00")
    result = analyze_pe(target)
    assert result.valid is None
    assert result.summary["status"] == "UNSUPPORTED"
    assert result.anomalies == ["PE_HEADER_OFFSET_LIMIT"]
    assert result.summary["bytes_read"] == 64


def test_mz_without_pe_signature_is_not_confirmed_pe(tmp_path: Path) -> None:
    data = _pe_bytes()
    data[0x80:0x84] = b"NOPE"
    result = analyze_pe(_write(tmp_path, data))
    assert result.is_pe is False
    assert result.valid is False
    assert result.summary["candidate"] is True
    assert result.anomalies == ["PE_SIGNATURE_MISSING"]


@pytest.mark.parametrize("offset,fmt,value,code", [
    (0x86, "H", MAX_SECTIONS + 1, "PE_SECTION_COUNT_LIMIT"),
    (0x86, "H", 0xFFFF, "PE_SECTION_COUNT_LIMIT"),
    (0x94, "H", MAX_OPTIONAL_HEADER_SIZE + 1, "PE_OPTIONAL_HEADER_LIMIT"),
    (0x94, "H", 0xFFFF, "PE_OPTIONAL_HEADER_LIMIT"),
    (0x98, "H", 0x107, "PE_OPTIONAL_HEADER_UNSUPPORTED"),
])
def test_unsupported_counts_sizes_and_format_are_bounded(tmp_path: Path, offset: int, fmt: str, value: int, code: str) -> None:
    data = _pe_bytes()
    struct.pack_into("<" + fmt, data, offset, value)
    result = analyze_pe(_write(tmp_path, data))
    assert result.is_pe is True
    assert result.valid is None
    assert result.summary["status"] == "UNSUPPORTED"
    assert result.anomalies == [code]
    assert not result.sections
    assert result.summary["bytes_read"] <= MAX_INSPECTION_BYTES


@pytest.mark.parametrize("plus", [False, True])
def test_directory_count_must_fit_optional_header(tmp_path: Path, plus: bool) -> None:
    data = _pe_bytes(plus=plus)
    struct.pack_into("<I", data, 0x98 + (108 if plus else 92), 0xFFFFFFFF)
    result = analyze_pe(_write(tmp_path, data))
    assert result.valid is False
    assert result.anomalies == ["PE_DATA_DIRECTORIES_TRUNCATED"]


@pytest.mark.parametrize("offset,value,code", [
    (0x86, 0, "PE_NO_SECTIONS"),
    (0x94, 0, "PE_OPTIONAL_HEADER_TRUNCATED"),
    (0x94, 1, "PE_OPTIONAL_HEADER_TRUNCATED"),
    (0x94, 95, "PE_OPTIONAL_HEADER_TRUNCATED"),
])
def test_missing_required_header_fields_are_incomplete(tmp_path: Path, offset: int, value: int, code: str) -> None:
    data = _pe_bytes()
    struct.pack_into("<H", data, offset, value)
    result = analyze_pe(_write(tmp_path, data))
    assert result.valid is False
    assert result.summary["status"] == "INCOMPLETE"
    assert result.anomalies == [code]


def test_truncated_section_table_is_reported(tmp_path: Path) -> None:
    result = analyze_pe(_write(tmp_path, _pe_bytes()[:400]))
    assert result.valid is False
    assert result.anomalies == ["PE_SECTION_TABLE_TRUNCATED"]


def test_unreadable_pe_is_unknown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _write(tmp_path, _pe_bytes())

    def deny_open(*args, **kwargs):
        raise PermissionError("simulated unreadable PE")

    monkeypatch.setattr(Path, "open", deny_open)
    result = analyze_pe(target, b"MZ")
    assert result.valid is None
    assert result.summary["status"] == "ERROR"
    assert result.warnings[0]["code"] == "PE_READ_ERROR"


@pytest.mark.parametrize("raw_offset,raw_size", [(0, 512), (400, 512), (512, 0xFFFFFFFF), (0xFFFFFFFF, 512), (1024, 1)])
def test_raw_section_ranges_are_validated_without_payload_read(tmp_path: Path, raw_offset: int, raw_size: int) -> None:
    data = _pe_bytes()
    table = 0x98 + 224
    struct.pack_into("<II", data, table + 16, raw_size, raw_offset)
    result = analyze_pe(_write(tmp_path, data))
    assert result.valid is False
    assert result.anomalies == ["PE_SECTION_RAW_RANGE_INVALID"]
    assert result.summary["bytes_read"] == 64 + 4 + 20 + 224 + 40


def test_raw_section_overlap_is_incomplete(tmp_path: Path) -> None:
    data = _pe_bytes(sections=2)
    struct.pack_into("<I", data, 0x98 + 224 + 40 + 20, 512)
    result = analyze_pe(_write(tmp_path, data))
    assert result.valid is False
    assert result.anomalies == ["PE_SECTION_RAW_OVERLAP"]


def test_uninitialized_section_needs_no_raw_data(tmp_path: Path) -> None:
    data = _pe_bytes()
    struct.pack_into("<II", data, 0x98 + 224 + 16, 0, 0)
    result = analyze_pe(_write(tmp_path, data))
    assert result.valid is True
    assert result.sections[0]["raw_size"] == 0


def test_writable_executable_section_is_advisory(tmp_path: Path) -> None:
    data = _pe_bytes()
    struct.pack_into("<I", data, 0x98 + 224 + 36, 0xE0000020)
    result = analyze_pe(_write(tmp_path, data))
    assert result.valid is True
    assert result.summary["status"] == "COMPLETE"
    assert result.anomalies == ["PE_WRITABLE_EXECUTABLE_SECTION:0"]


@pytest.mark.parametrize("plus", [False, True])
def test_certificate_presence_never_means_verified_signature(tmp_path: Path, plus: bool) -> None:
    data = _pe_bytes(plus=plus)
    directory_base = 112 if plus else 96
    struct.pack_into("<II", data, 0x98 + directory_base + 4 * 8, len(data), 16)
    data.extend(b"not a signature!")
    result = analyze_pe(_write(tmp_path, data))
    assert result.valid is True
    assert result.summary["certificate_table_present"] is True
    assert result.summary["signature_verification"] == "NOT_PERFORMED"
    assert "signature_valid" not in result.summary
    assert "trusted" not in result.summary


@pytest.mark.parametrize("offset,size,code", [(0, 10, "PE_CERTIFICATE_RANGE_INVALID"), (1024, 0xFFFFFFFF, "PE_CERTIFICATE_RANGE_INVALID"), (512, 16, "PE_CERTIFICATE_SECTION_OVERLAP")])
def test_certificate_directory_bounds(tmp_path: Path, offset: int, size: int, code: str) -> None:
    data = _pe_bytes()
    struct.pack_into("<II", data, 0x98 + 96 + 4 * 8, offset, size)
    result = analyze_pe(_write(tmp_path, data))
    assert result.valid is False
    assert result.anomalies == [code]
    assert result.summary["signature_verification"] == "NOT_PERFORMED"


def test_actual_reads_are_bounded_at_maximum_section_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _write(tmp_path, _pe_bytes(sections=MAX_SECTIONS))
    original_open = Path.open
    reads: list[int] = []

    class TrackedFile:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

        def fileno(self):
            return self.stream.fileno()

        def seek(self, offset):
            return self.stream.seek(offset)

        def read(self, size=-1):
            assert 0 <= size <= MAX_OPTIONAL_HEADER_SIZE
            reads.append(size)
            return self.stream.read(size)

    def tracked_open(path, *args, **kwargs):
        assert kwargs.get("buffering") == 0
        return TrackedFile(original_open(path, *args, **kwargs))

    monkeypatch.setattr(Path, "open", tracked_open)
    result = analyze_pe(target)
    assert result.valid is True
    assert len(result.sections) == MAX_SECTIONS
    assert reads == [64, 4, 20, 224, MAX_SECTIONS * 40]
    assert sum(reads) <= MAX_INSPECTION_BYTES
    assert sum(reads) == result.summary["bytes_read"]


@pytest.mark.parametrize("name", ["file.exe", "file.dll", "file.EXE"])
def test_scanner_integrates_pe_and_expected_mime_types(tmp_path: Path, name: str) -> None:
    scanner = StaticFileScanner()
    scanner._magic = None
    result = scanner.scan(_write(tmp_path, _pe_bytes(), name))
    assert result.status == "OK"
    assert result.is_pe is True
    assert result.pe_valid is True
    assert result.is_elf is False
    assert result.mime_extension_consistency == "CONSISTENT"
    assert "application/vnd.microsoft.portable-executable" in result.expected_mime_types
    assert result.to_dict()["pe_sections"][0]["name"] == ".s0"


@pytest.mark.parametrize("name", ["report.txt", "report.pdf", "photo.png", "report.docx"])
def test_pe_disguise_uses_file_content_even_if_mime_is_wrong(tmp_path: Path, name: str) -> None:
    scanner = StaticFileScanner()

    class FakeMagic:
        def from_file(self, path):
            return "text/plain"

    scanner._magic = FakeMagic()
    result = scanner.scan(_write(tmp_path, _pe_bytes(), name))
    assert result.is_pe is True
    assert result.mime_extension_consistency == "INCONSISTENT"
    assert "MIME_EXTENSION_INCONSISTENT" in result.path_indicators


def test_malformed_mz_is_partial_without_a_malware_error(tmp_path: Path) -> None:
    result = StaticFileScanner().scan(_write(tmp_path, b"MZtruncated"))
    assert result.status == "PARTIAL"
    assert result.is_pe is False
    assert result.pe_valid is False
    assert result.pe_summary["status"] == "INCOMPLETE"
    assert not result.errors
    assert any(item["code"] == "PE_DOS_HEADER_TRUNCATED" for item in result.warnings)


@pytest.mark.skipif(os.name == "nt", reason="fanotify descriptor paths use /proc on Linux")
def test_open_descriptor_keeps_pe_bytes_and_original_context(tmp_path: Path) -> None:
    candidate = _write(tmp_path, _pe_bytes(), "descriptor.exe")
    context = tmp_path / ".hidden" / "Downloads" / "report.pdf"
    fd = os.open(candidate, os.O_RDONLY)
    try:
        os.unlink(candidate)
        result = StaticFileScanner().scan_open_fd(fd, str(context))
    finally:
        os.close(fd)
    assert result.filepath == str(context)
    assert result.is_pe is True
    assert result.pe_valid is True
    assert result.extension == ".pdf"
    assert result.mime_extension_consistency == "INCONSISTENT"
    assert result.path_context["hidden"] is True
    assert "DOWNLOAD_DIRECTORY" in result.path_indicators


def test_mime_fallback_uses_original_descriptor_filename(tmp_path: Path) -> None:
    scanner = StaticFileScanner()
    scanner._magic = None
    mime, source, _ = scanner.detect_mime(Path("/proc/self/fd/17"), b"plain text", tmp_path / "data.json")
    assert mime == "application/json"
    assert source == "extension-fallback"
