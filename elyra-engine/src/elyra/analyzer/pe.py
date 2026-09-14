"""Bounded, read-only PE header evidence; never a loader or trust verifier.

Offsets and field sizes follow the Microsoft PE Format specification:
https://learn.microsoft.com/en-us/windows/win32/debug/pe-format

Only the DOS/COFF/optional headers and section table are read. Section contents,
imports, certificate contents, archives and executable code are never loaded.
``valid`` means the supported structural checks passed, not that Windows can
load the image or that the file is safe. All anomalies are advisory evidence.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO

MAX_PE_HEADER_OFFSET = 1024 * 1024
MAX_OPTIONAL_HEADER_SIZE = 4096
MAX_SECTIONS = 96
SECTION_HEADER_SIZE = 40
MAX_INSPECTION_BYTES = 64 + 4 + 20 + MAX_OPTIONAL_HEADER_SIZE + MAX_SECTIONS * 40

_MACHINES = {0x014C: "x86", 0x8664: "x64", 0x01C4: "ARM", 0xAA64: "ARM64"}


@dataclass(slots=True)
class PEAnalysis:
    is_pe: bool = False
    valid: bool | None = None
    summary: dict[str, Any] = field(default_factory=lambda: {
        "status": "NOT_PE",
        "candidate": False,
        "scope": "headers_and_sections",
        "signature_verification": "NOT_PERFORMED",
        "bytes_read": 0,
    })
    sections: list[dict[str, Any]] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    warnings: list[dict[str, str]] = field(default_factory=list)


class _InspectionIssue(Exception):
    def __init__(self, code: str, message: str, *, unsupported: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.unsupported = unsupported


class _Reader:
    def __init__(self, stream: BinaryIO, file_size: int, result: PEAnalysis) -> None:
        self.stream = stream
        self.file_size = file_size
        self.result = result

    def read(self, offset: int, size: int, code: str) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.file_size:
            raise _InspectionIssue(code, "Declared PE structure exceeds the file bounds")
        if self.result.summary["bytes_read"] + size > MAX_INSPECTION_BYTES:
            raise _InspectionIssue("PE_READ_LIMIT", "PE inspection read limit reached", unsupported=True)
        self.stream.seek(offset)
        data = self.stream.read(size)
        self.result.summary["bytes_read"] += len(data)
        if len(data) != size:
            raise _InspectionIssue(code, "PE structure was truncated while reading")
        return data


def _inspect(reader: _Reader, result: PEAnalysis) -> None:
    dos = reader.read(0, min(64, reader.file_size), "PE_DOS_HEADER_TRUNCATED")
    if not dos.startswith(b"MZ"):
        return
    result.summary.update(status="INCOMPLETE", candidate=True)
    if len(dos) < 64:
        raise _InspectionIssue("PE_DOS_HEADER_TRUNCATED", "MZ header does not contain e_lfanew")
    pe_offset = struct.unpack_from("<I", dos, 0x3C)[0]
    result.summary["pe_header_offset"] = pe_offset
    if pe_offset < 64 or pe_offset + 24 > reader.file_size:
        raise _InspectionIssue("PE_HEADER_OUT_OF_BOUNDS", "e_lfanew does not identify an in-file PE header")
    if pe_offset > MAX_PE_HEADER_OFFSET:
        raise _InspectionIssue("PE_HEADER_OFFSET_LIMIT", "PE header offset exceeds the inspection limit", unsupported=True)
    if reader.read(pe_offset, 4, "PE_SIGNATURE_TRUNCATED") != b"PE\x00\x00":
        raise _InspectionIssue("PE_SIGNATURE_MISSING", "MZ candidate does not have the PE signature")
    result.is_pe = True
    coff = reader.read(pe_offset + 4, 20, "PE_COFF_HEADER_TRUNCATED")
    machine, count, timestamp, _, _, optional_size, characteristics = struct.unpack("<HHIIIHH", coff)
    result.summary.update(
        machine=machine,
        architecture=_MACHINES.get(machine, f"machine-0x{machine:04x}"),
        section_count=count,
        coff_timestamp=timestamp,
        characteristics=characteristics,
        is_dll=bool(characteristics & 0x2000),
        optional_header_size=optional_size,
    )
    if count == 0:
        raise _InspectionIssue("PE_NO_SECTIONS", "PE image declares no sections")
    if count > MAX_SECTIONS:
        raise _InspectionIssue("PE_SECTION_COUNT_LIMIT", "Section count exceeds the supported limit of 96", unsupported=True)
    if optional_size < 2:
        raise _InspectionIssue("PE_OPTIONAL_HEADER_TRUNCATED", "PE image has no complete optional-header magic")
    if optional_size > MAX_OPTIONAL_HEADER_SIZE:
        raise _InspectionIssue("PE_OPTIONAL_HEADER_LIMIT", "Optional header exceeds the inspection limit", unsupported=True)
    optional_offset = pe_offset + 24
    optional = reader.read(optional_offset, optional_size, "PE_OPTIONAL_HEADER_TRUNCATED")
    magic = struct.unpack_from("<H", optional)[0]
    result.summary["optional_header_magic"] = magic
    if magic not in {0x10B, 0x20B}:
        raise _InspectionIssue("PE_OPTIONAL_HEADER_UNSUPPORTED", "Only PE32 and PE32+ optional headers are supported", unsupported=True)
    is_plus = magic == 0x20B
    directory_base = 112 if is_plus else 96
    result.summary["format"] = "PE32+" if is_plus else "PE32"
    if len(optional) < directory_base:
        raise _InspectionIssue("PE_OPTIONAL_HEADER_TRUNCATED", "Optional header lacks required Windows fields")
    entry_point = struct.unpack_from("<I", optional, 16)[0]
    image_base = struct.unpack_from("<Q" if is_plus else "<I", optional, 24 if is_plus else 28)[0]
    section_alignment, file_alignment = struct.unpack_from("<II", optional, 32)
    image_size, headers_size = struct.unpack_from("<II", optional, 56)
    subsystem, dll_characteristics = struct.unpack_from("<HH", optional, 68)
    directories = struct.unpack_from("<I", optional, directory_base - 4)[0]
    result.summary.update(
        entry_point_rva=entry_point,
        image_base=image_base,
        section_alignment=section_alignment,
        file_alignment=file_alignment,
        size_of_image=image_size,
        size_of_headers=headers_size,
        subsystem=subsystem,
        dll_characteristics=dll_characteristics,
        data_directory_count=directories,
    )
    if directories > (optional_size - directory_base) // 8:
        raise _InspectionIssue("PE_DATA_DIRECTORIES_TRUNCATED", "Directory count exceeds the declared optional header")
    directory_values: dict[int, tuple[int, int]] = {}
    for directory_index in range(min(directories, 16)):
        directory_offset = directory_base + directory_index * 8
        directory_values[directory_index] = struct.unpack_from("<II", optional, directory_offset)
    # Directory presence is structural evidence only. Names, imports and
    # certificate trust are intentionally not resolved in this bounded pass.
    result.summary.update(
        import_directory_present=bool(directory_values.get(1, (0, 0))[1]),
        export_directory_present=bool(directory_values.get(0, (0, 0))[1]),
        debug_directory_present=bool(directory_values.get(6, (0, 0))[1]),
        certificate_table_present=bool(directory_values.get(4, (0, 0))[0] and directory_values.get(4, (0, 0))[1]),
        packer_indicators=[],
    )
    table_offset = optional_offset + optional_size
    table_end = table_offset + count * SECTION_HEADER_SIZE
    if table_end > reader.file_size:
        raise _InspectionIssue("PE_SECTION_TABLE_TRUNCATED", "Section table exceeds the file bounds")
    if headers_size < table_end or headers_size > reader.file_size:
        raise _InspectionIssue("PE_HEADERS_SIZE_INVALID", "SizeOfHeaders does not contain the section table within the file")
    table = reader.read(table_offset, count * SECTION_HEADER_SIZE, "PE_SECTION_TABLE_TRUNCATED")
    raw_ranges: list[tuple[int, int, int]] = []
    for index in range(count):
        row = table[index * SECTION_HEADER_SIZE:(index + 1) * SECTION_HEADER_SIZE]
        name = row[:8].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        # Section names are untrusted display text, with a maximum of 8 bytes.
        name = "".join(char if char.isprintable() else "?" for char in name)
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", row, 8)
        flags = struct.unpack_from("<I", row, 36)[0]
        section = {
            "index": index,
            "name": name,
            "virtual_address": virtual_address,
            "virtual_size": virtual_size,
            "raw_offset": raw_offset,
            "raw_size": raw_size,
            "characteristics": flags,
            "flags": {
                "readable": bool(flags & 0x40000000),
                "writable": bool(flags & 0x80000000),
                "executable": bool(flags & 0x20000000),
            },
        }
        result.sections.append(section)
        lowered_name = name.lower()
        if lowered_name in {"upx0", "upx1", "upx2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1"}:
            result.summary["packer_indicators"].append(f"SUSPICIOUS_SECTION_NAME:{name}")
        if raw_size and virtual_size > raw_size * 8:
            result.summary["packer_indicators"].append(f"HIGH_VIRTUAL_RAW_RATIO:{index}")
        if raw_size:
            if raw_offset < headers_size or raw_offset + raw_size > reader.file_size:
                raise _InspectionIssue("PE_SECTION_RAW_RANGE_INVALID", f"Section {index} raw data is outside the file or overlaps headers")
            raw_ranges.append((raw_offset, raw_offset + raw_size, index))
        if section["flags"]["writable"] and section["flags"]["executable"]:
            result.anomalies.append(f"PE_WRITABLE_EXECUTABLE_SECTION:{index}")
    raw_ranges.sort()
    for previous, current in zip(raw_ranges, raw_ranges[1:]):
        if current[0] < previous[1]:
            raise _InspectionIssue("PE_SECTION_RAW_OVERLAP", "Raw data ranges of PE sections overlap")
    # This is a file offset, not an RVA. Presence does not authenticate anything.
    certificate_offset, certificate_size = directory_values.get(4, (0, 0))
    result.summary.update(
        certificate_table_present=bool(certificate_offset and certificate_size),
        certificate_table_offset=certificate_offset,
        certificate_table_size=certificate_size,
    )
    if certificate_offset or certificate_size:
        if not certificate_offset or not certificate_size or certificate_offset < headers_size or certificate_offset + certificate_size > reader.file_size:
            raise _InspectionIssue("PE_CERTIFICATE_RANGE_INVALID", "Certificate directory has an incomplete or out-of-file range")
        if any(certificate_offset < end and start < certificate_offset + certificate_size for start, end, _ in raw_ranges):
            raise _InspectionIssue("PE_CERTIFICATE_SECTION_OVERLAP", "Certificate directory overlaps raw section data")
    result.valid = True
    result.summary["status"] = "COMPLETE"


def analyze_pe(path: str | os.PathLike[str], head: bytes | None = None) -> PEAnalysis:
    """Inspect a regular file or trusted /proc descriptor path without executing it.

    A caller-supplied head only avoids opening files that clearly are not MZ
    candidates. Every PE field is re-read from the inspected file itself.
    """
    result = PEAnalysis()
    if head is not None and not head.startswith(b"MZ"):
        return result
    try:
        # Unbuffered IO avoids hidden read-ahead beyond our explicit byte budget.
        with Path(path).open("rb", buffering=0) as stream:
            reader = _Reader(stream, os.fstat(stream.fileno()).st_size, result)
            _inspect(reader, result)
    except _InspectionIssue as exc:
        result.valid = None if exc.unsupported else False
        result.summary["status"] = "UNSUPPORTED" if exc.unsupported else "INCOMPLETE"
        result.anomalies.append(exc.code)
        result.warnings.append({"code": exc.code, "message": str(exc)})
    except (OSError, ValueError, struct.error) as exc:
        result.valid = None
        result.summary["status"] = "ERROR"
        result.warnings.append({"code": "PE_READ_ERROR", "message": str(exc)})
    return result
