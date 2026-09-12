from __future__ import annotations

from elyra.update.checker import decide_update


def test_compatible_update_can_be_deferred() -> None:
    result = decide_update({"version": "1.1.0", "url": "https://example.invalid/v1.1.0"}, current_version="1.0.0")
    assert result.status == "UPDATE_AVAILABLE"
    assert result.can_defer is True


def test_update_below_minimum_cannot_be_deferred() -> None:
    result = decide_update({"version": "2.0.0", "min_supported_version": "1.5.0"}, current_version="1.0.0")
    assert result.status == "UPDATE_REQUIRED"
    assert result.can_defer is False


def test_current_version_is_up_to_date() -> None:
    assert decide_update({"version": "1.0.0"}, current_version="1.0.0").status == "UP_TO_DATE"
