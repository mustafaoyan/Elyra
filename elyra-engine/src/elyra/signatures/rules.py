"""Versioned local signature-rule bundles with provenance and tamper checks.

This module deliberately performs no network access and does not treat an
unknown rule source as trusted. Matching engines (for example YARA-X) can use
the validated rule records later; this first M2 increment defines the safe
portable bundle contract only.
"""

from __future__ import annotations

import hashlib
import json
import re
import os
from pathlib import Path
from typing import Any, Mapping

SCHEMA_VERSION = "elyra.rules.v1"
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
_RULE_ID = re.compile(r"^[A-Z][A-Z0-9_.-]{2,127}$")


def _version_key(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", value)
    if not match:
        raise RuleBundleError("invalid semantic version")
    return tuple(int(part) for part in match.groups())


class RuleBundleError(ValueError):
    """Raised when a local rule bundle is malformed or tampered with."""


def _canonical_payload(bundle: Mapping[str, Any]) -> bytes:
    payload = dict(bundle)
    payload.pop("content_sha256", None)
    return (json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def content_sha256(bundle: Mapping[str, Any]) -> str:
    """Return the canonical SHA-256 digest of a bundle without its digest field."""

    return hashlib.sha256(_canonical_payload(bundle)).hexdigest()


def validate_bundle(bundle: Mapping[str, Any], *, trusted_sources: set[str] | None = None) -> None:
    """Validate schema, provenance, rule identity and content integrity."""

    if not isinstance(bundle, Mapping):
        raise RuleBundleError("bundle must be a JSON object")
    if bundle.get("schema_version") != SCHEMA_VERSION:
        raise RuleBundleError("unsupported rule bundle schema")
    for key in ("bundle_id", "bundle_version", "provenance", "rules", "content_sha256"):
        if key not in bundle:
            raise RuleBundleError(f"missing required field: {key}")
    if not isinstance(bundle["bundle_id"], str) or not bundle["bundle_id"].strip():
        raise RuleBundleError("bundle_id must be a non-empty string")
    if not isinstance(bundle["bundle_version"], str) or not _SEMVER.fullmatch(bundle["bundle_version"]):
        raise RuleBundleError("bundle_version must use semantic versioning")
    provenance = bundle["provenance"]
    if not isinstance(provenance, Mapping):
        raise RuleBundleError("provenance must be an object")
    source = provenance.get("source")
    if not isinstance(source, str) or not source.strip():
        raise RuleBundleError("provenance.source must be a non-empty string")
    if trusted_sources is not None and source not in trusted_sources:
        raise RuleBundleError(f"untrusted rule source: {source}")
    if not isinstance(bundle["rules"], list) or not bundle["rules"]:
        raise RuleBundleError("rules must be a non-empty array")
    seen: set[str] = set()
    for rule in bundle["rules"]:
        if not isinstance(rule, Mapping):
            raise RuleBundleError("each rule must be an object")
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id):
            raise RuleBundleError("rule id has invalid format")
        if rule_id in seen:
            raise RuleBundleError(f"duplicate rule id: {rule_id}")
        seen.add(rule_id)
        if not isinstance(rule.get("description"), str) or not rule["description"].strip():
            raise RuleBundleError(f"rule description missing: {rule_id}")
        if rule.get("match_type") not in {"sha256", "literal", "yara"}:
            raise RuleBundleError(f"unsupported match_type: {rule_id}")
        if not isinstance(rule.get("value"), str) or not rule["value"]:
            raise RuleBundleError(f"rule value missing: {rule_id}")
    digest = bundle["content_sha256"]
    if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
        raise RuleBundleError("content_sha256 must be a lowercase SHA-256 digest")
    if digest != content_sha256(bundle):
        raise RuleBundleError("rule bundle content hash mismatch")


def create_bundle(
    bundle_id: str,
    bundle_version: str,
    provenance: Mapping[str, Any],
    rules: list[Mapping[str, Any]],
) -> dict[str, Any]:
    """Create and validate a canonical local rule bundle."""

    bundle: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "bundle_id": bundle_id,
        "bundle_version": bundle_version,
        "provenance": dict(provenance),
        "rules": [dict(rule) for rule in rules],
    }
    bundle["content_sha256"] = content_sha256(bundle)
    validate_bundle(bundle)
    return bundle


def load_bundle(path: str | Path, *, trusted_sources: set[str] | None = None) -> dict[str, Any]:
    """Load one local JSON bundle and verify it before returning it."""

    try:
        bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuleBundleError(f"unable to read rule bundle: {exc}") from exc
    validate_bundle(bundle, trusted_sources=trusted_sources)
    return dict(bundle)


class RuleBundleStore:
    """Install verified offline bundles with downgrade protection and rollback."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def current(self) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        return load_bundle(self.path)

    def install(self, bundle: Mapping[str, Any], *, allow_rollback: bool = False) -> dict[str, Any]:
        validate_bundle(bundle)
        existing = self.current()
        if existing and _version_key(str(bundle["bundle_version"])) < _version_key(str(existing["bundle_version"])) and not allow_rollback:
            raise RuleBundleError("bundle downgrade rejected")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_name(f".{self.path.name}.new-{os.getpid()}")
        temporary.write_text(json.dumps(bundle, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        if existing:
            self.path.with_suffix(self.path.suffix + ".bak").write_bytes(self.path.read_bytes())
        os.replace(temporary, self.path)
        return dict(bundle)

    def rollback(self) -> dict[str, Any]:
        backup = self.path.with_suffix(self.path.suffix + ".bak")
        if not backup.exists():
            raise RuleBundleError("no verified bundle backup available")
        previous = load_bundle(backup)
        os.replace(backup, self.path)
        return previous
