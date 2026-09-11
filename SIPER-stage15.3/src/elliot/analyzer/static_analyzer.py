"""Canonical static file analyser used by ELLIOT.

This module extracts evidence.  It does not declare that a file is malware.  Risk
It deliberately extracts evidence without making a malware determination.  The
Stage 4 scoring engine consumes this structured result.
"""

from __future__ import annotations

import mimetypes
import os
import stat
import struct
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .entropy import (
    EntropyConfig,
    EntropyEngine,
    FileAccessError,
    UnsupportedFileTypeError,
)
from .pe import analyze_pe

try:
    import magic  # type: ignore[import-untyped]
except ImportError:  # Explicit degraded mode; checked in Stage 2.
    magic = None

try:
    from elftools.common.exceptions import ELFError
    from elftools.elf.elffile import ELFFile
except ImportError:  # Explicit degraded mode; checked in Stage 2.
    ELFError = None
    ELFFile = None


@dataclass(frozen=True, slots=True)
class StaticAnalyzerConfig:
    entropy: EntropyConfig = field(default_factory=EntropyConfig)


@dataclass(slots=True)
class StaticScanResult:
    filepath: str
    status: str = "ERROR"
    file_size: int | None = None
    mime_type: str = "unknown"
    mime_source: str = "unavailable"
    extension: str = ""
    mime_extension_consistency: str = "UNKNOWN"
    expected_mime_types: list[str] = field(default_factory=list)
    is_elf: bool = False
    elf_valid: bool | None = None
    elf_entry_point: int | None = None
    elf_sections: list[dict[str, Any]] = field(default_factory=list)
    elf_segments: list[dict[str, Any]] = field(default_factory=list)
    elf_anomalies: list[str] = field(default_factory=list)
    permission_details: dict[str, Any] = field(default_factory=dict)
    permission_anomalies: list[str] = field(default_factory=list)
    path_context: dict[str, Any] = field(default_factory=dict)
    path_indicators: list[str] = field(default_factory=list)
    entropy_summary: dict[str, Any] = field(default_factory=dict)
    block_entropies: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[dict[str, str]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    duration_ms: float = 0.0
    is_pe: bool = False
    pe_valid: bool | None = None
    pe_summary: dict[str, Any] = field(default_factory=dict)
    pe_sections: list[dict[str, Any]] = field(default_factory=list)
    pe_anomalies: list[str] = field(default_factory=list)
    file_identity: dict[str, int | str] = field(default_factory=dict)
    identity_source: str = "UNVERIFIED_PATH"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class StaticFileScanner:
    ELF_MAGIC = b"\x7fELF"
    _PE_MIME_TYPES = (
        "application/vnd.microsoft.portable-executable",
        "application/x-dosexec",
        "application/x-msdownload",
        "application/x-ms-dos-executable",
    )

    _EXTENSION_MIME_RULES: dict[str, tuple[str, ...]] = {
        ".txt": ("text/plain",),
        ".csv": ("text/csv", "text/plain"),
        ".json": ("application/json", "text/plain"),
        ".xml": ("application/xml", "text/xml", "text/plain"),
        ".pdf": ("application/pdf",),
        ".png": ("image/png",),
        ".jpg": ("image/jpeg",),
        ".jpeg": ("image/jpeg",),
        ".gif": ("image/gif",),
        ".zip": ("application/zip", "application/x-zip"),
        ".gz": ("application/gzip", "application/x-gzip"),
        ".py": ("text/x-python", "text/plain"),
        ".sh": ("text/x-shellscript", "text/plain", "application/x-shellscript"),
        ".so": ("application/x-sharedlib", "application/x-pie-executable"),
        ".exe": _PE_MIME_TYPES,
        ".dll": _PE_MIME_TYPES,
        ".elf": (
            "application/x-executable",
            "application/x-pie-executable",
            "application/x-sharedlib",
        ),
    }
    _OBVIOUS_CONTENT_EXTENSIONS = {
        ".txt", ".csv", ".json", ".xml", ".pdf", ".png", ".jpg", ".jpeg",
        ".gif", ".zip", ".gz", ".py", ".sh",
    }
    _PE_DISGUISE_EXTENSIONS = _OBVIOUS_CONTENT_EXTENSIONS | {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf",
        ".mp3", ".mp4", ".wav", ".html", ".htm",
    }

    def __init__(self, config: StaticAnalyzerConfig | None = None) -> None:
        self.config = config or StaticAnalyzerConfig()
        self.entropy_engine = EntropyEngine(self.config.entropy)
        self._magic = None
        if magic is not None:
            try:
                self._magic = magic.Magic(mime=True)
            except Exception:
                # The scan method records an explicit degraded-mode warning.
                self._magic = None

    @staticmethod
    def _error(code: str, message: str) -> dict[str, str]:
        return {"code": code, "message": message}

    @staticmethod
    def _read_head(path: Path, size: int = 64) -> bytes:
        try:
            with path.open("rb") as stream:
                return stream.read(size)
        except PermissionError as exc:
            raise FileAccessError(f"permission denied while reading file: {path}") from exc
        except OSError as exc:
            raise FileAccessError(f"cannot read file {path}: {exc}") from exc

    @classmethod
    def _fallback_mime(cls, path: Path, head: bytes) -> tuple[str, str]:
        signatures = (
            (cls.ELF_MAGIC, "application/x-executable"),
            (b"MZ", "application/x-dosexec"),
            (b"%PDF", "application/pdf"),
            (b"\x89PNG\r\n\x1a\n", "image/png"),
            (b"\xff\xd8\xff", "image/jpeg"),
            (b"PK\x03\x04", "application/zip"),
            (b"\x1f\x8b", "application/gzip"),
        )
        for signature, mime_type in signatures:
            if head.startswith(signature):
                return mime_type, "signature-fallback"
        guessed, _ = mimetypes.guess_type(path.name, strict=False)
        if guessed:
            return guessed, "extension-fallback"
        if head and b"\x00" not in head:
            try:
                head.decode("utf-8")
                return "text/plain", "utf8-fallback"
            except UnicodeDecodeError:
                pass
        return "application/octet-stream", "generic-fallback"

    def detect_mime(
        self, path: Path, head: bytes, context_path: Path | None = None
    ) -> tuple[str, str, list[dict[str, str]]]:
        warnings: list[dict[str, str]] = []
        if self._magic is not None:
            try:
                detected = str(self._magic.from_file(str(path)))
                if detected:
                    return detected, "libmagic", warnings
            except Exception as exc:
                warnings.append(
                    self._error("LIBMAGIC_FAILED", f"libmagic failed: {exc}")
                )
        else:
            warnings.append(
                self._error(
                    "LIBMAGIC_UNAVAILABLE",
                    "python-magic/libmagic unavailable; signature fallback used",
                )
            )
        detected, source = self._fallback_mime(context_path or path, head)
        return detected, source, warnings

    @classmethod
    def evaluate_mime_extension(
        cls, path: Path, mime_type: str, is_elf: bool, is_pe: bool = False
    ) -> tuple[str, list[str]]:
        extension = path.suffix.lower()
        if not extension:
            return "NO_EXTENSION", []

        if is_pe and extension in cls._PE_DISGUISE_EXTENSIONS:
            return "INCONSISTENT", list(cls._PE_MIME_TYPES)

        if is_elf and extension in cls._OBVIOUS_CONTENT_EXTENSIONS:
            return "INCONSISTENT", [
                "application/x-executable",
                "application/x-pie-executable",
                "application/x-sharedlib",
            ]

        expected = list(cls._EXTENSION_MIME_RULES.get(extension, ()))
        if not expected:
            return "UNKNOWN", expected
        if mime_type in expected:
            return "CONSISTENT", expected
        return "INCONSISTENT", expected

    @staticmethod
    def analyze_permissions(path: Path, metadata: os.stat_result) -> tuple[dict[str, Any], list[str]]:
        mode = metadata.st_mode
        posix_mode_semantics = os.name != "nt"
        details = {
            "mode_octal": f"{stat.S_IMODE(mode):04o}",
            "posix_mode_semantics": posix_mode_semantics,
            "owner_uid": metadata.st_uid,
            "owner_gid": metadata.st_gid,
            "suid": bool(mode & stat.S_ISUID) if posix_mode_semantics else False,
            "sgid": bool(mode & stat.S_ISGID) if posix_mode_semantics else False,
            "owner_executable": bool(mode & stat.S_IXUSR),
            "group_executable": bool(mode & stat.S_IXGRP),
            "world_executable": bool(mode & stat.S_IXOTH),
            # NTFS ACLs are not faithfully represented by Python's POSIX-like
            # stat mode bits.  Treating every writable local file as
            # world-writable would create a false static-risk signal on
            # Windows, so ACL evaluation is intentionally outside this
            # cross-platform byte-analysis layer.
            "world_writable": bool(mode & stat.S_IWOTH) if posix_mode_semantics else False,
        }
        indicators: list[str] = []
        if details["suid"]:
            indicators.append("SUID_BIT_SET")
        if details["sgid"]:
            indicators.append("SGID_BIT_SET")
        if details["world_writable"]:
            indicators.append("WORLD_WRITABLE")
        if details["world_writable"] and details["world_executable"]:
            indicators.append("WORLD_WRITABLE_AND_EXECUTABLE")
        return details, indicators

    @staticmethod
    def analyze_path_context(path: Path) -> tuple[dict[str, Any], list[str]]:
        absolute = path.absolute()
        parts = absolute.parts
        lowered = [part.casefold() for part in parts]
        hidden_components = [
            part for part in parts if part.startswith(".") and part not in {".", ".."}
        ]
        categories: list[str] = []
        as_string = str(absolute)
        if as_string == "/tmp" or as_string.startswith("/tmp/"):
            categories.append("TEMPORARY_DIRECTORY")
        if as_string == "/var/tmp" or as_string.startswith("/var/tmp/"):
            categories.append("TEMPORARY_DIRECTORY")
        if any(part in {"downloads", "indirilenler"} for part in lowered):
            categories.append("DOWNLOAD_DIRECTORY")
        if (
            as_string == "/media"
            or as_string.startswith("/media/")
            or as_string == "/run/media"
            or as_string.startswith("/run/media/")
            or as_string == "/mnt"
            or as_string.startswith("/mnt/")
        ):
            categories.append("REMOVABLE_OR_MOUNTED_MEDIA")
        indicators = list(categories)
        if hidden_components:
            indicators.append("HIDDEN_PATH_COMPONENT")
        return {
            "absolute_path": as_string,
            "hidden": bool(hidden_components),
            "hidden_components": hidden_components,
            "location_categories": categories,
        }, indicators

    @staticmethod
    def _segment_flags(flags: int) -> dict[str, bool]:
        return {
            "readable": bool(flags & 4),
            "writable": bool(flags & 2),
            "executable": bool(flags & 1),
        }

    @staticmethod
    def _section_flags(flags: int) -> dict[str, bool]:
        return {
            "writable": bool(flags & 0x1),
            "allocated": bool(flags & 0x2),
            "executable": bool(flags & 0x4),
        }

    def analyze_elf(
        self, path: Path, head: bytes
    ) -> tuple[dict[str, Any], list[dict[str, str]], list[dict[str, str]]]:
        result: dict[str, Any] = {
            "is_elf": head.startswith(self.ELF_MAGIC),
            "valid": None,
            "entry_point": None,
            "sections": [],
            "segments": [],
            "indicators": [],
        }
        warnings: list[dict[str, str]] = []
        errors: list[dict[str, str]] = []
        if not result["is_elf"]:
            return result, warnings, errors

        if ELFFile is None:
            warnings.append(
                self._error(
                    "PYELFTOOLS_UNAVAILABLE",
                    "pyelftools unavailable; only ELF magic was verified",
                )
            )
            return result, warnings, errors

        try:
            with path.open("rb") as stream:
                elf = ELFFile(stream)
                result["valid"] = True
                result["entry_point"] = int(elf.header["e_entry"])
                if result["entry_point"] == 0:
                    result["indicators"].append("ELF_ENTRY_POINT_ZERO")

                for index, section in enumerate(elf.iter_sections()):
                    raw_flags = int(section.header["sh_flags"])
                    flags = self._section_flags(raw_flags)
                    section_data = {
                        "index": index,
                        "name": section.name,
                        "type": str(section.header["sh_type"]),
                        "offset": int(section.header["sh_offset"]),
                        "size": int(section.header["sh_size"]),
                        "flags": flags,
                    }
                    result["sections"].append(section_data)
                    if flags["writable"] and flags["executable"]:
                        result["indicators"].append(
                            f"WRITABLE_EXECUTABLE_SECTION:{section.name or index}"
                        )

                for index, segment in enumerate(elf.iter_segments()):
                    raw_flags = int(segment.header["p_flags"])
                    flags = self._segment_flags(raw_flags)
                    segment_data = {
                        "index": index,
                        "type": str(segment.header["p_type"]),
                        "offset": int(segment.header["p_offset"]),
                        "file_size": int(segment.header["p_filesz"]),
                        "memory_size": int(segment.header["p_memsz"]),
                        "flags": flags,
                    }
                    result["segments"].append(segment_data)
                    if flags["writable"] and flags["executable"]:
                        result["indicators"].append(
                            f"WRITABLE_EXECUTABLE_SEGMENT:{index}"
                        )

                if not result["sections"]:
                    result["indicators"].append("ELF_NO_SECTION_HEADERS")
        except (OSError, PermissionError) as exc:
            result["valid"] = False
            errors.append(self._error("ELF_READ_ERROR", str(exc)))
        except (struct.error, ValueError) as exc:
            result["valid"] = False
            errors.append(self._error("MALFORMED_ELF", str(exc)))
        except Exception as exc:
            # pyelftools raises several parser-specific exception subclasses.
            if ELFError is not None and isinstance(exc, ELFError):
                result["valid"] = False
                errors.append(self._error("MALFORMED_ELF", str(exc)))
            else:
                result["valid"] = False
                errors.append(
                    self._error("ELF_ANALYSIS_FAILED", f"{type(exc).__name__}: {exc}")
                )
        return result, warnings, errors

    def scan(self, filepath: str | os.PathLike[str]) -> StaticScanResult:
        """Analyse a path supplied by an IPC/manual-scan caller."""

        path = Path(filepath)
        return self._scan(read_path=path, context_path=path, trusted_open_fd=False)

    def scan_open_fd(
        self,
        fd: int,
        original_path: str | os.PathLike[str] | None = None,
    ) -> StaticScanResult:
        """Analyse an already-open fanotify event descriptor.

        Reading through ``/proc/self/fd/<fd>`` keeps the analysed object tied to
        the descriptor supplied by the kernel.  ``original_path`` is used only
        for extension and location context; file bytes and metadata come from
        the open descriptor.
        """

        if fd < 0:
            raise ValueError("fanotify event fd must be non-negative")
        read_path = Path(f"/proc/self/fd/{fd}")
        context_path = Path(original_path) if original_path else read_path
        return self._scan(
            read_path=read_path,
            context_path=context_path,
            trusted_open_fd=True,
        )

    def _scan(
        self,
        *,
        read_path: Path,
        context_path: Path,
        trusted_open_fd: bool,
    ) -> StaticScanResult:
        started = time.perf_counter()
        result = StaticScanResult(filepath=str(context_path))
        result.extension = context_path.suffix.lower()

        try:
            metadata = read_path.stat() if trusted_open_fd else read_path.lstat()
        except FileNotFoundError:
            result.errors.append(
                self._error("FILE_NOT_FOUND", f"file does not exist: {context_path}")
            )
            result.duration_ms = round((time.perf_counter() - started) * 1000, 3)
            return result
        except PermissionError:
            result.errors.append(
                self._error("STAT_PERMISSION_DENIED", f"cannot stat: {context_path}")
            )
            result.duration_ms = round((time.perf_counter() - started) * 1000, 3)
            return result
        except OSError as exc:
            result.errors.append(self._error("STAT_FAILED", str(exc)))
            result.duration_ms = round((time.perf_counter() - started) * 1000, 3)
            return result

        if not trusted_open_fd and stat.S_ISLNK(metadata.st_mode):
            result.errors.append(
                self._error(
                    "SYMLINK_NOT_SCANNED", "symbolic-link targets are not followed"
                )
            )
            result.duration_ms = round((time.perf_counter() - started) * 1000, 3)
            return result
        if not stat.S_ISREG(metadata.st_mode):
            result.errors.append(
                self._error("NOT_REGULAR_FILE", "target is not a regular file")
            )
            result.duration_ms = round((time.perf_counter() - started) * 1000, 3)
            return result

        result.file_size = metadata.st_size
        result.file_identity = {
            "device": int(metadata.st_dev),
            "inode": int(metadata.st_ino),
            "size": int(metadata.st_size),
            "mtime_ns": int(metadata.st_mtime_ns),
        }
        result.identity_source = "OPEN_DESCRIPTOR" if trusted_open_fd else "PATH_LSTAT"
        result.permission_details, result.permission_anomalies = self.analyze_permissions(
            context_path, metadata
        )
        result.path_context, result.path_indicators = self.analyze_path_context(
            context_path
        )

        try:
            head = self._read_head(read_path)
        except FileAccessError as exc:
            result.errors.append(self._error("FILE_READ_FAILED", str(exc)))
            result.duration_ms = round((time.perf_counter() - started) * 1000, 3)
            return result

        result.mime_type, result.mime_source, mime_warnings = self.detect_mime(
            read_path, head, context_path
        )
        result.warnings.extend(mime_warnings)

        elf_data, elf_warnings, elf_errors = self.analyze_elf(read_path, head)
        result.is_elf = bool(elf_data["is_elf"])
        result.elf_valid = elf_data["valid"]
        result.elf_entry_point = elf_data["entry_point"]
        result.elf_sections = elf_data["sections"]
        result.elf_segments = elf_data["segments"]
        result.elf_anomalies = elf_data["indicators"]
        result.warnings.extend(elf_warnings)
        result.errors.extend(elf_errors)

        pe_data = analyze_pe(read_path, head)
        result.is_pe = pe_data.is_pe
        result.pe_valid = pe_data.valid
        result.pe_summary = pe_data.summary
        result.pe_sections = pe_data.sections
        result.pe_anomalies = pe_data.anomalies
        result.warnings.extend(pe_data.warnings)

        (
            result.mime_extension_consistency,
            result.expected_mime_types,
        ) = self.evaluate_mime_extension(
            context_path, result.mime_type, result.is_elf, result.is_pe
        )
        if result.mime_extension_consistency == "INCONSISTENT":
            result.path_indicators.append("MIME_EXTENSION_INCONSISTENT")

        try:
            if trusted_open_fd:
                entropy = self.entropy_engine.analyze_open_fd(
                    int(read_path.name), str(context_path)
                )
            else:
                entropy = self.entropy_engine.analyze(read_path)
            entropy_dict = entropy.to_dict()
            result.block_entropies = list(entropy_dict.pop("reported_blocks"))
            result.entropy_summary = entropy_dict
        except (FileAccessError, UnsupportedFileTypeError) as exc:
            result.errors.append(self._error("ENTROPY_ANALYSIS_FAILED", str(exc)))

        result.status = "OK" if not result.errors else "PARTIAL"
        if result.pe_summary.get("status") in {"INCOMPLETE", "UNSUPPORTED", "ERROR"}:
            result.status = "PARTIAL"
        result.duration_ms = round((time.perf_counter() - started) * 1000, 3)
        return result
