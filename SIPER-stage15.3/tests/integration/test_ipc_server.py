from __future__ import annotations

import json
import os
import socket
import stat
import threading
import time
from pathlib import Path

import pytest

from elliot.service.ipc_client import IpcClient, IpcRemoteError
from elliot.service.ipc_protocol import MAX_REQUEST_BYTES, PROTOCOL_VERSION, build_request
from elliot.service.ipc_server import IpcConfigurationError, IpcServer


pytestmark = pytest.mark.integration


@pytest.fixture
def running_server(tmp_path: Path):
    socket_path = tmp_path / "run" / "elliot.sock"

    def handler(action, params, requester):
        if action == "get_status":
            return {"pid": requester.pid, "uid": requester.uid, "api_version": PROTOCOL_VERSION}
        if action == "list_events":
            return {"events": [], "limit": params["limit"]}
        raise ValueError("unsupported in test handler")

    server = IpcServer(handler, socket_path, socket_group=None, connection_timeout=0.5)
    server.start()
    thread = threading.Thread(target=server.run_forever, daemon=True)
    thread.start()
    try:
        yield socket_path
    finally:
        server.stop()
        thread.join(timeout=2)


def _raw_exchange(socket_path: Path, payload: bytes) -> dict:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(socket_path))
        client.sendall(payload)
        if not payload.endswith(b"\n"):
            client.shutdown(socket.SHUT_WR)
        data = bytearray()
        while b"\n" not in data:
            chunk = client.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
    return json.loads(bytes(data).split(b"\n", 1)[0].decode())


def test_client_round_trip_peer_credentials_and_reconnect(running_server: Path) -> None:
    client = IpcClient(running_server)
    result = client.request("get_status")
    assert result["uid"] == os.getuid()
    assert result["pid"] == os.getpid()
    assert result["api_version"] == PROTOCOL_VERSION

    second = client.request("list_events", {"limit": 7})
    assert second == {"events": [], "limit": 7}


def test_socket_mode_is_0660(running_server: Path) -> None:
    assert stat.S_IMODE(running_server.stat().st_mode) == 0o660


def test_malformed_wrong_version_and_incomplete_messages(running_server: Path) -> None:
    malformed = _raw_exchange(running_server, b"not-json\n")
    assert malformed["error"]["code"] == "INVALID_JSON"

    request = build_request("get_status")
    request["version"] = 99
    wrong = _raw_exchange(running_server, json.dumps(request).encode() + b"\n")
    assert wrong["error"]["code"] == "UNSUPPORTED_VERSION"

    incomplete = _raw_exchange(running_server, b'{"version":1')
    assert incomplete["error"]["code"] == "INCOMPLETE_MESSAGE"


def test_oversized_message_is_rejected(running_server: Path) -> None:
    response = _raw_exchange(running_server, b"x" * (MAX_REQUEST_BYTES + 1))
    assert response["error"]["code"] == "MESSAGE_TOO_LARGE"


def test_remote_authorization_error_is_structured(tmp_path: Path) -> None:
    socket_path = tmp_path / "elliot.sock"

    def deny(_requester, _action):
        from elliot.service.authorization import AuthorizationError
        raise AuthorizationError("denied for test")

    server = IpcServer(lambda *_: {}, socket_path, socket_group=None, authorizer=deny)
    server.start()
    thread = threading.Thread(target=server.run_forever, daemon=True)
    thread.start()
    try:
        with pytest.raises(IpcRemoteError) as captured:
            IpcClient(socket_path).request("get_status")
        assert captured.value.code == "AUTHORIZATION_DENIED"
    finally:
        server.stop()
        thread.join(timeout=2)


def test_server_refuses_to_unlink_non_socket_path(tmp_path: Path) -> None:
    socket_path = tmp_path / "elliot.sock"
    socket_path.write_text("do not replace", encoding="utf-8")
    server = IpcServer(lambda *_: {}, socket_path, socket_group=None)
    with pytest.raises(IpcConfigurationError, match="non-socket"):
        server.start()
    assert socket_path.read_text(encoding="utf-8") == "do not replace"
