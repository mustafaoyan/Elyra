"""Versioned dataset manifest validation for leakage-resistant evaluation."""

from __future__ import annotations

import hashlib
from typing import Any, Iterable, Mapping


class DatasetManifestError(ValueError):
    pass


def validate_manifest(records: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Validate required provenance and reject hash/family split leakage."""

    items = [dict(record) for record in records]
    seen_hashes: dict[str, str] = {}
    seen_families: dict[str, str] = {}
    for record in items:
        for key in ("sample_id", "sha256", "split", "label"):
            if key not in record:
                raise DatasetManifestError(f"missing field: {key}")
        digest = record["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise DatasetManifestError("sha256 must be lowercase hexadecimal")
        split = record["split"]
        if split not in {"train", "validation", "test"}:
            raise DatasetManifestError("split must be train, validation or test")
        family = record.get("family")
        if digest in seen_hashes and seen_hashes[digest] != split:
            raise DatasetManifestError("identical sample hash appears in multiple splits")
        seen_hashes[digest] = split
        if isinstance(family, str) and family:
            if family in seen_families and seen_families[family] != split:
                raise DatasetManifestError("sample family appears in multiple splits")
            seen_families[family] = split
        if record["label"] not in {True, False, None}:
            raise DatasetManifestError("label must be true, false or null")
    return items


def manifest_digest(records: Iterable[Mapping[str, Any]]) -> str:
    """Return a stable digest for a validated manifest."""

    items = validate_manifest(records)
    canonical = "\n".join(sorted(str(sorted(item.items())) for item in items)).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
