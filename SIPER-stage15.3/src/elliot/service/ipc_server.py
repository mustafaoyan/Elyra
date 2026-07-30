"""Protected Unix-domain-socket server for the privileged ELLIOT daemon."""

from __future__ import annotations

import grp
import logging
import os
import socket
import stat
import struct
import threading
from pathlib import Path
from typing import Callable

from .authorization import AuthorizationError, IPC_GROUP, Requester, authorize
from .ipc_protocol import (
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    ProtocolError,
    decode_request_line,
    encode_json_line,
    error_response,
    success_response,
)

logger = logging.getLogger("elliot.ipc")

DEFAULT_SOCKET_PATH = "/run/elliot/elliot.sock"
SOCKET_MODE = 0o660
RUNTIME_DIRECTORY_MODE = 0o750
SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)


class IpcConfigurationError(RuntimeError):
    """Raised when secure socket ownership or path setup cannot be guaranteed."""


class IpcServer:
    def __init__(
        self,
        handler: Callable[[str, dict, Requester], dict],
        socket_path: str | os.PathLike[str] = DEFAULT_SOCKET_PATH,
        *,
        socket_group: str | None = IPC_GROUP,
        connection_timeout: float = 5.0,
        maximum_clients: int = 32,
        authorizer: Callable[[Requester, str], None] = authorize,
    ) -> None:
        self.handler = handler
        self.socket_path = Path(socket_path)
        self.socket_group = socket_group
        self.connection_timeout = connection_timeout
        self.authorizer = authorizer
        self._server: socket.socket | None = None
        self._stop = threading.Event()
        self._client_slots = threading.BoundedSemaphore(maximum_clients)
        self._client_threads: set[threading.Thread] = set()
        self._thread_lock = threading.Lock()

    def start(self) -> None:
        if self._server is not None:
            raise IpcConfigurationError("IPC server is already started")
        if not hasattr(socket, "AF_UNIX"):
            raise IpcConfigurationError("Unix-domain sockets are unavailable")

        group_id = self._resolve_group_id()
        self._prepare_runtime_directory(group_id)
        self._remove_stale_socket_safely()

        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            server.bind(str(self.socket_path))
            os.chmod(self.socket_path, SOCKET_MODE)
            if group_id is not None:
                os.chown(self.socket_path, -1, group_id)
            server.listen(16)
            server.settimeout(0.5)
        except Exception:
            server.close()
            self._unlink_owned_socket()
            raise
        self._server = server
        logger.info("IPC server listening on %s", self.socket_path)

    def run_forever(self) -> None:
        if self._server is None:
            raise IpcConfigurationError("IPC server has not been started")
        while not self._stop.is_set():
            try:
                connection, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    break
                raise
            if not self._client_slots.acquire(blocking=False):
                self._send_response(
                    connection,
                    error_response(None, "SERVER_BUSY", "Too many concurrent IPC clients"),
                )
                connection.close()
                continue
            thread = threading.Thread(
                target=self._client_worker,
                args=(connection,),
                name="elliot-ipc-client",
                daemon=True,
            )
            with self._thread_lock:
                self._client_threads.add(thread)
            thread.start()

    def stop(self) -> None:
        self._stop.set()
        server = self._server
        self._server = None
        if server is not None:
            server.close()
        with self._thread_lock:
            threads = list(self._client_threads)
        for thread in threads:
            thread.join(timeout=1.0)
        self._unlink_owned_socket()

    def _client_worker(self, connection: socket.socket) -> None:
        try:
            self._handle_client(connection)
        finally:
            connection.close()
            self._client_slots.release()
            current = threading.current_thread()
            with self._thread_lock:
                self._client_threads.discard(current)

    def _handle_client(self, connection: socket.socket) -> None:
        try:
            requester = self._peer_identity(connection)
        except OSError as exc:
            logger.warning("SO_PEERCRED failed: %s", exc)
            self._send_response(
                connection,
                error_response(None, "PEER_CREDENTIALS_UNAVAILABLE", "Peer identity is unavailable"),
            )
            return

        connection.settimeout(self.connection_timeout)
        buffer = bytearray()
        while not self._stop.is_set():
            try:
                chunk = connection.recv(4096)
            except socket.timeout:
                self._send_response(
                    connection,
                    error_response(None, "REQUEST_TIMEOUT", "IPC request timed out"),
                )
                return
            except ConnectionResetError:
                return
            if not chunk:
                if buffer:
                    self._send_response(
                        connection,
                        error_response(None, "INCOMPLETE_MESSAGE", "Request was not newline terminated"),
                    )
                return
            buffer.extend(chunk)
            if len(buffer) > MAX_REQUEST_BYTES and b"\n" not in buffer:
                self._send_response(
                    connection,
                    error_response(None, "MESSAGE_TOO_LARGE", "Request exceeds the size limit"),
                )
                return

            while b"\n" in buffer:
                raw_line, remainder = bytes(buffer).split(b"\n", 1)
                buffer = bytearray(remainder)
                response = self._process_line(raw_line, requester)
                if not self._send_response(connection, response):
                    return
                if len(buffer) > MAX_REQUEST_BYTES:
                    self._send_response(
                        connection,
                        error_response(None, "MESSAGE_TOO_LARGE", "Request exceeds the size limit"),
                    )
                    return

    def _process_line(self, line: bytes, requester: Requester) -> dict:
        try:
            request = decode_request_line(line)
        except ProtocolError as exc:
            return error_response(exc.request_id, exc.code, exc.message)

        try:
            self.authorizer(requester, request.action)
        except AuthorizationError as exc:
            logger.warning(
                "IPC authorization denied: pid=%s uid=%s action=%s",
                requester.pid,
                requester.uid,
                request.action,
            )
            return error_response(request.request_id, "AUTHORIZATION_DENIED", str(exc))

        try:
            result = self.handler(request.action, request.params, requester)
        except AuthorizationError as exc:
            logger.warning(
                "IPC path/action policy denied: pid=%s uid=%s action=%s",
                requester.pid,
                requester.uid,
                request.action,
            )
            return error_response(request.request_id, "AUTHORIZATION_DENIED", str(exc))
        except (FileNotFoundError, KeyError) as exc:
            logger.info("IPC resource not found for action %s: %s", request.action, exc)
            return error_response(request.request_id, "NOT_FOUND", "Requested resource was not found")
        except ValueError as exc:
            logger.info("IPC invalid operation parameters for %s: %s", request.action, exc)
            return error_response(request.request_id, "INVALID_PARAMETERS", str(exc))
        except Exception:
            logger.exception("IPC handler failed: action=%s", request.action)
            return error_response(
                request.request_id,
                "OPERATION_FAILED",
                "The requested operation failed; see the daemon audit log",
            )
        return success_response(request.request_id, result)

    def _send_response(self, connection: socket.socket, response: dict) -> bool:
        try:
            encoded = encode_json_line(response, maximum=MAX_RESPONSE_BYTES)
        except ProtocolError:
            encoded = encode_json_line(
                error_response(
                    response.get("request_id"),
                    "RESPONSE_TOO_LARGE",
                    "The daemon result exceeds the IPC response limit",
                ),
                maximum=MAX_RESPONSE_BYTES,
            )
        try:
            connection.sendall(encoded)
            return True
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            return False

    def _resolve_group_id(self) -> int | None:
        if self.socket_group is None:
            return None
        try:
            return grp.getgrnam(self.socket_group).gr_gid
        except KeyError as exc:
            raise IpcConfigurationError(
                f"Required IPC group does not exist: {self.socket_group}"
            ) from exc

    def _prepare_runtime_directory(self, group_id: int | None) -> None:
        directory = self.socket_path.parent
        directory.mkdir(parents=True, exist_ok=True, mode=RUNTIME_DIRECTORY_MODE)
        metadata = directory.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise IpcConfigurationError("IPC runtime path is not a real directory")
        os.chmod(directory, RUNTIME_DIRECTORY_MODE)
        if group_id is not None:
            if os.geteuid() != 0 and metadata.st_gid != group_id:
                raise IpcConfigurationError(
                    "Changing the IPC runtime-directory group requires root"
                )
            os.chown(directory, -1, group_id)

    def _remove_stale_socket_safely(self) -> None:
        try:
            metadata = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(metadata.st_mode):
            raise IpcConfigurationError(
                f"Refusing to replace non-socket IPC path: {self.socket_path}"
            )
        if metadata.st_uid not in {0, os.geteuid()}:
            raise IpcConfigurationError("Refusing to remove a socket owned by another user")
        self.socket_path.unlink()

    def _unlink_owned_socket(self) -> None:
        try:
            metadata = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid in {0, os.geteuid()}:
            self.socket_path.unlink()

    @staticmethod
    def _peer_identity(connection: socket.socket) -> Requester:
        credentials = connection.getsockopt(
            socket.SOL_SOCKET,
            SO_PEERCRED,
            struct.calcsize("3i"),
        )
        pid, uid, gid = struct.unpack("3i", credentials)
        return Requester(pid=pid, uid=uid, gid=gid)
