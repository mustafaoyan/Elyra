"""Backend-neutral disposable behavior lab boundary.

The runner accepts fixture identifiers and metadata only. A hypervisor adapter
must be supplied by a separately reviewed integration; there is intentionally
no local process, shell, network, or file execution fallback.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

from .policy import LabPolicy

_FIXTURE_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class LabUnavailable(RuntimeError):
    """Raised when no approved disposable-lab backend is configured."""


class LabBackend(Protocol):
    def prepare(self, policy: LabPolicy) -> None: ...
    def run_fixture(self, fixture_id: str, *, timeout_seconds: int) -> None: ...
    def collect_evidence(self) -> dict[str, Any]: ...
    def revert_snapshot(self) -> None: ...
    def destroy(self) -> None: ...


class BehaviorLab:
    def __init__(self, backend: LabBackend | None = None, *, policy: LabPolicy | None = None) -> None:
        self.policy = policy or LabPolicy()
        self.policy.validate()
        self.backend = backend

    def run_fixture(self, fixture_id: str) -> dict[str, Any]:
        if not isinstance(fixture_id, str) or not _FIXTURE_ID.fullmatch(fixture_id):
            raise ValueError("fixture_id must be a bounded identifier, not a path")
        if self.backend is None:
            return {"schema_version": "elyra.behavior.v1", "status": "UNAVAILABLE", "reason": "NO_APPROVED_DISPOSABLE_BACKEND", "authoritative": False, "actions_allowed": []}
        prepared = False
        try:
            self.backend.prepare(self.policy)
            prepared = True
            self.backend.run_fixture(fixture_id, timeout_seconds=self.policy.max_duration_seconds)
            evidence = self.backend.collect_evidence()
            if not isinstance(evidence, dict):
                raise TypeError("backend evidence must be an object")
            return {"schema_version": "elyra.behavior.v1", "status": "OK", "fixture_id": fixture_id, "evidence": evidence, "authoritative": False, "actions_allowed": []}
        finally:
            if prepared:
                try:
                    self.backend.revert_snapshot()
                finally:
                    self.backend.destroy()
