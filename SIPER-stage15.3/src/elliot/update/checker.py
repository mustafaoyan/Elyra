"""Safe update notification policy for the local Linux application."""

from __future__ import annotations

import json
import urllib.request
from dataclasses import dataclass
from typing import Any

from elliot import __version__


@dataclass(frozen=True, slots=True)
class UpdateDecision:
    status: str
    current_version: str
    latest_version: str | None = None
    can_defer: bool = True
    reason: str = ""
    release_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "current_version": self.current_version,
            "latest_version": self.latest_version,
            "can_defer": self.can_defer,
            "reason": self.reason,
            "release_url": self.release_url,
        }


def _version_tuple(value: str) -> tuple[int, ...]:
    numbers: list[int] = []
    for part in value.lstrip("v").split("."):
        digits = "".join(character for character in part if character.isdigit())
        numbers.append(int(digits or 0))
    return tuple(numbers[:4])


def decide_update(manifest: dict[str, Any], *, current_version: str = __version__) -> UpdateDecision:
    latest = str(manifest.get("version", "")).lstrip("v") or None
    if latest is None or _version_tuple(latest) <= _version_tuple(current_version):
        return UpdateDecision("UP_TO_DATE", current_version, latest, True, "no newer release")
    minimum = str(manifest.get("min_supported_version", current_version))
    mandatory = bool(manifest.get("mandatory", False)) or _version_tuple(current_version) < _version_tuple(minimum)
    return UpdateDecision(
        "UPDATE_REQUIRED" if mandatory else "UPDATE_AVAILABLE",
        current_version,
        latest,
        not mandatory,
        "installed version is below the supported minimum" if mandatory else "new release available",
        str(manifest.get("url")) if manifest.get("url") else None,
    )


def check_latest(url: str, *, timeout: float = 2.0, current_version: str = __version__) -> UpdateDecision:
    """Fetch a small release manifest; failures remain local and non-blocking."""
    try:
        request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "ELLIOT-update-check"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            manifest = json.loads(response.read(64 * 1024).decode("utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("update manifest must be an object")
        return decide_update(manifest, current_version=current_version)
    except Exception as exc:
        return UpdateDecision("CHECK_UNAVAILABLE", current_version, reason=type(exc).__name__)
