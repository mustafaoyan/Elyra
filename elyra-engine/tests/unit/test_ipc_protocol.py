from __future__ import annotations

import json

import pytest

from elyra.service.ipc_protocol import (
    MAX_REQUEST_BYTES,
    PROTOCOL_VERSION,
    ProtocolError,
    build_request,
    decode_request_line,
    validate_request_object,
)


def test_valid_versioned_request_round_trip() -> None:
    request = build_request("list_events", {"limit": 25})
    decoded = decode_request_line(json.dumps(request).encode())
    assert decoded.version == PROTOCOL_VERSION
    assert decoded.action == "list_events"
    assert decoded.params == {"limit": 25}


def test_protocol_rejects_wrong_version() -> None:
    request = build_request("get_status")
    request["version"] = 99
    with pytest.raises(ProtocolError, match="version") as captured:
        validate_request_object(request)
    assert captured.value.code == "UNSUPPORTED_VERSION"


def test_protocol_rejects_unknown_action_and_extra_parameter() -> None:
    request = build_request("get_status")
    request["action"] = "run_shell"
    with pytest.raises(ProtocolError) as unknown:
        validate_request_object(request)
    assert unknown.value.code == "UNKNOWN_ACTION"

    request = build_request("get_status")
    request["params"] = {"unexpected": True}
    with pytest.raises(ProtocolError) as extra:
        validate_request_object(request)
    assert extra.value.code == "INVALID_PARAMETERS"


def test_protocol_validates_action_specific_parameters() -> None:
    with pytest.raises(ProtocolError):
        build_request("list_events", {"limit": 0})
    with pytest.raises(ProtocolError):
        build_request("scan_file", {"path": ""})
    with pytest.raises(ProtocolError):
        build_request("scan_file", {"path": "relative.bin"})
    with pytest.raises(ProtocolError):
        build_request("restore_file", {"quarantine_id": "not-a-uuid", "destination": None})
    with pytest.raises(ProtocolError):
        build_request("update_enforcement_policy", {"mode": "DISABLE_ALL"})


def test_protocol_rejects_oversized_line() -> None:
    with pytest.raises(ProtocolError) as captured:
        decode_request_line(b"x" * (MAX_REQUEST_BYTES + 1))
    assert captured.value.code == "MESSAGE_TOO_LARGE"
