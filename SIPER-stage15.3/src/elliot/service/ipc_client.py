"""Official unprivileged client for ELLIOT's Unix-domain-socket API."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any, Mapping

from .ipc_protocol import (
    MAX_RESPONSE_BYTES,
    PROTOCOL_VERSION,
    ProtocolError,
    build_request,
    encode_json_line,
)
from .ipc_server import DEFAULT_SOCKET_PATH


class IpcClientError(RuntimeError):
    """Connection, framing, or daemon-response failure."""


class IpcRemoteError(IpcClientError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class IpcClient:
    def __init__(
        self,
        socket_path: str | Path = DEFAULT_SOCKET_PATH,
        *,
        timeout: float = 3.0,
    ) -> None:
        self.socket_path = str(socket_path)
        self.timeout = timeout

    def request(self, action: str, params: Mapping[str, Any] | None = None) -> Any:
        request = build_request(action, params)
        encoded = encode_json_line(request, maximum=64 * 1024)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(self.timeout)
                client.connect(self.socket_path)
                client.sendall(encoded)
                response = self._receive_line(client)
        except FileNotFoundError as exc:
            raise IpcClientError("ELLIOT daemon socket was not found") from exc
        except PermissionError as exc:
            raise IpcClientError("Permission denied while connecting to ELLIOT IPC") from exc
        except (ConnectionRefusedError, ConnectionResetError, socket.timeout, OSError) as exc:
            raise IpcClientError(f"ELLIOT IPC connection failed: {exc}") from exc

        if not isinstance(response, dict):
            raise IpcClientError("Daemon response is not a JSON object")
        if response.get("version") != PROTOCOL_VERSION:
            raise IpcClientError("Daemon returned an unsupported protocol version")
        if response.get("request_id") != request["request_id"]:
            raise IpcClientError("Daemon response request_id does not match")
        if response.get("ok") is True:
            return response.get("result")
        error = response.get("error")
        if not isinstance(error, dict):
            raise IpcClientError("Daemon returned a malformed error response")
        raise IpcRemoteError(
            str(error.get("code", "REMOTE_ERROR")),
            str(error.get("message", "The daemon rejected the request")),
        )

    @staticmethod
    def _receive_line(client: socket.socket) -> Any:
        buffer = bytearray()
        while b"\n" not in buffer:
            chunk = client.recv(4096)
            if not chunk:
                raise IpcClientError("Daemon closed the connection before a response")
            buffer.extend(chunk)
            if len(buffer) > MAX_RESPONSE_BYTES:
                raise IpcClientError("Daemon response exceeds the size limit")
        line, remainder = bytes(buffer).split(b"\n", 1)
        if remainder:
            raise IpcClientError("Daemon sent unexpected data after the response")
        try:
            return json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IpcClientError("Daemon response is not valid UTF-8 JSON") from exc
