#!/usr/bin/env python3
"""Safe Stage 6 Unix-socket demonstration using only a temporary directory."""

from __future__ import annotations

import argparse
import json
import os
import socket
import stat
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from elliot.service.authorization import AuthorizationError, Requester, authorize
from elliot.service.ipc_client import IpcClient
from elliot.service.ipc_protocol import MAX_REQUEST_BYTES, PROTOCOL_VERSION
from elliot.service.ipc_server import IpcServer


def raw_error(socket_path: Path, payload: bytes) -> str:
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
    response = json.loads(bytes(data).split(b"\n", 1)[0].decode("utf-8"))
    return str(response["error"]["code"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    records: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="elliot-stage6-") as directory:
        socket_path = Path(directory) / "run" / "elliot.sock"

        def handler(action, params, requester):
            return {
                "action": action,
                "params": params,
                "peer_pid": requester.pid,
                "peer_uid": requester.uid,
                "peer_gid": requester.gid,
                "api_version": PROTOCOL_VERSION,
            }

        server = IpcServer(handler, socket_path, socket_group=None)
        server.start()
        thread = threading.Thread(target=server.run_forever, daemon=True)
        thread.start()
        try:
            result = IpcClient(socket_path).request("get_status")
            records.append(
                {
                    "scenario": "versioned_round_trip_and_peer_credentials",
                    "status": "OK" if (
                        result["api_version"] == PROTOCOL_VERSION
                        and result["peer_uid"] == os.getuid()
                        and result["peer_pid"] == os.getpid()
                    ) else "FAIL",
                    "peer_pid": result["peer_pid"],
                    "peer_uid": result["peer_uid"],
                }
            )
            mode = stat.S_IMODE(socket_path.stat().st_mode)
            records.append(
                {
                    "scenario": "protected_socket_mode",
                    "status": "OK" if mode == 0o660 else "FAIL",
                    "mode": f"0{mode:o}",
                }
            )
            malformed_code = raw_error(socket_path, b"not-json\n")
            records.append(
                {
                    "scenario": "malformed_json_rejection",
                    "status": "OK" if malformed_code == "INVALID_JSON" else "FAIL",
                    "error_code": malformed_code,
                }
            )
            oversized_code = raw_error(socket_path, b"x" * (MAX_REQUEST_BYTES + 1))
            records.append(
                {
                    "scenario": "oversized_request_rejection",
                    "status": "OK" if oversized_code == "MESSAGE_TOO_LARGE" else "FAIL",
                    "error_code": oversized_code,
                }
            )
        finally:
            server.stop()
            thread.join(timeout=2)

    synthetic_requester = Requester(pid=4242, uid=65534, gid=65534)
    try:
        authorize(synthetic_requester, "restore_file")
    except AuthorizationError:
        denied = True
    else:
        denied = False
    records.append(
        {
            "scenario": "synthetic_unprivileged_sensitive_action_denial",
            "status": "OK" if denied else "FAIL",
            "note": "policy evaluation only; no file was restored",
        }
    )

    overall = "OK" if all(item["status"] == "OK" for item in records) else "FAIL"
    payload = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "method": "temporary Unix socket; no root, kernel hooks, network listener, or malware",
        "protocol_version": PROTOCOL_VERSION,
        "results": records,
        "overall_status": overall,
    }
    output = json.dumps(payload, ensure_ascii=False, indent=2)
    for item in records:
        print(f"{item['scenario']}: {item['status']}")
    print(f"overall_status: {overall}")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output + "\n", encoding="utf-8")
        print(f"Evidence written to: {args.output}")
    return 0 if overall == "OK" else 1


if __name__ == "__main__":
    raise SystemExit(main())
