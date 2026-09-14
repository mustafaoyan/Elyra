"""Honest Authenticode evidence reporting boundary.

Certificate-table presence is structural evidence, not signature validation.
Full chain/revocation verification is intentionally delegated to a future,
platform-specific trusted verifier and never guessed by this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


@dataclass(frozen=True)
class AuthenticodeReport:
    status: str
    certificate_table_present: bool
    trust: str
    verification: str
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "certificate_table_present": self.certificate_table_present,
            "trust": self.trust,
            "verification": self.verification,
            "limitations": list(self.limitations),
        }


def report_authenticode(pe_summary: Mapping[str, Any], path: str | Path | None = None) -> AuthenticodeReport:
    """Report certificate evidence without claiming cryptographic trust."""

    present = bool(pe_summary.get("certificate_table_present", False))
    limitations = (
        "certificate contents are not parsed",
        "certificate chain and revocation are not verified",
        "a present certificate is not a trusted signature",
    )
    if not present:
        return AuthenticodeReport("NO_CERTIFICATE_TABLE", False, "UNKNOWN", "NOT_PERFORMED", limitations)
    return AuthenticodeReport("CERTIFICATE_TABLE_PRESENT", True, "UNKNOWN", "NOT_PERFORMED", limitations)
