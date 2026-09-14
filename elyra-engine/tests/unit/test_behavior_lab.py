import pytest

from elyra.behavior_lab import BehaviorLab, LabPolicy, LabUnavailable, UnsafeLabConfiguration


def test_default_lab_is_explicitly_unavailable():
    result = BehaviorLab().run_fixture("benign-fixture-1")
    assert result["status"] == "UNAVAILABLE"
    assert result["authoritative"] is False
    assert result["actions_allowed"] == []


def test_policy_rejects_host_exposure():
    with pytest.raises(UnsafeLabConfiguration):
        BehaviorLab(policy=LabPolicy(host_shares=True))


def test_fixture_id_cannot_be_a_path():
    with pytest.raises(ValueError):
        BehaviorLab().run_fixture("../../etc/passwd")


class FakeBackend:
    def __init__(self):
        self.calls = []

    def prepare(self, policy): self.calls.append("prepare")
    def run_fixture(self, fixture_id, *, timeout_seconds): self.calls.append(("run", fixture_id, timeout_seconds))
    def collect_evidence(self): self.calls.append("collect"); return {"process_count": 0}
    def revert_snapshot(self): self.calls.append("revert")
    def destroy(self): self.calls.append("destroy")


def test_backend_is_cleaned_up_and_result_is_non_authoritative():
    backend = FakeBackend()
    result = BehaviorLab(backend).run_fixture("safe-fixture")
    assert result["status"] == "OK"
    assert result["authoritative"] is False
    assert backend.calls[-2:] == ["revert", "destroy"]


class FailingBackend(FakeBackend):
    def run_fixture(self, fixture_id, *, timeout_seconds):
        self.calls.append("run")
        raise RuntimeError("controlled fixture failure")


def test_backend_failure_still_reverts_and_destroys():
    backend = FailingBackend()
    with pytest.raises(RuntimeError):
        BehaviorLab(backend).run_fixture("safe-fixture")
    assert backend.calls[-2:] == ["revert", "destroy"]
