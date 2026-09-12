from __future__ import annotations

from elyra.monitor.fanotify.policy import FanotifyPolicy


def test_path_containment_does_not_use_unsafe_prefix_matching(tmp_path):
    monitored = tmp_path / "watch"
    sibling = tmp_path / "watch-other"
    monitored.mkdir()
    sibling.mkdir()
    policy = FanotifyPolicy(
        monitored_paths=[str(monitored)],
        excluded_paths=[],
        fail_closed_paths=[],
    )

    assert policy.should_monitor(str(monitored / "file")) is True
    assert policy.should_monitor(str(sibling / "file")) is False


def test_monitor_only_never_returns_kernel_deny(tmp_path):
    policy = FanotifyPolicy(
        mode="MONITOR_ONLY",
        monitored_paths=[str(tmp_path)],
        excluded_paths=[],
    )
    assert policy.get_final_action("DENY") == "ALLOW"


def test_fail_closed_requires_explicit_path_and_enforcement(tmp_path):
    strict = tmp_path / "strict"
    strict.mkdir()
    policy = FanotifyPolicy(
        mode="ENFORCEMENT",
        default_fail_policy="FAIL_OPEN",
        monitored_paths=[str(tmp_path)],
        excluded_paths=[],
        fail_closed_paths=[str(strict)],
    )
    assert policy.get_fail_policy(str(tmp_path / "ordinary")) == "FAIL_OPEN"
    assert policy.get_fail_policy(str(strict / "candidate")) == "FAIL_CLOSED"
