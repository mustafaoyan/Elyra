#!/usr/bin/env python3
"""Single-threaded execution broker used by the Stage 8.1 root verifier.

The broker is started before fanotify controller threads. It receives newline-delimited
JSON commands, forks the requested harmless fixture, applies a watchdog, and returns
one JSON result. It never performs fanotify operations or scoring.
"""
from __future__ import annotations

import json
import os
import signal
import sys
import time
from typing import Any

EXEC_DENIED_EXIT_CODE = 126
EXEC_FAILED_EXIT_CODE = 125
WATCHDOG_TERMINATED_EXIT_CODE = 124


def _exec_child(path: str, argv: tuple[str, ...]) -> None:
    try:
        os.execv(path, list(argv))
    except PermissionError:
        os._exit(EXEC_DENIED_EXIT_CODE)
    except OSError:
        os._exit(EXEC_FAILED_EXIT_CODE)


def _decode_wait_status(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return EXEC_FAILED_EXIT_CODE


def _kill_and_reap(pid: int, grace_seconds: float = 0.75) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        waited, _status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return
        time.sleep(0.02)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def _fork_exec(path: str, argv: tuple[str, ...]) -> int:
    pid = os.fork()
    if pid == 0:
        _exec_child(path, argv)
        os._exit(EXEC_FAILED_EXIT_CODE)
    return pid


def _wait_many(pids: list[int], timeout: float) -> list[dict[str, Any]]:
    started = time.monotonic()
    deadline = started + timeout
    pending = set(pids)
    statuses: dict[int, int] = {}
    while pending and time.monotonic() < deadline:
        for pid in tuple(pending):
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited == pid:
                statuses[pid] = _decode_wait_status(status)
                pending.remove(pid)
        if pending:
            time.sleep(0.01)
    timed_out = set(pending)
    for pid in tuple(pending):
        _kill_and_reap(pid)
        statuses[pid] = WATCHDOG_TERMINATED_EXIT_CODE
        pending.remove(pid)
    elapsed = round((time.monotonic() - started) * 1000, 3)
    return [
        {
            "started": True,
            "launcher_pid": pid,
            "returncode": statuses[pid],
            "denied_by_exec": statuses[pid] == EXEC_DENIED_EXIT_CODE,
            "timed_out": pid in timed_out,
            "watchdog_action": "TERMINATE_THEN_KILL" if pid in timed_out else "NONE",
            "elapsed_ms": elapsed,
        }
        for pid in pids
    ]


def handle(command: dict[str, Any]) -> dict[str, Any]:
    action = command.get("action")
    if action == "shutdown":
        return {"shutdown": True}
    if action not in {"execute", "execute_many"}:
        raise ValueError("unsupported broker action")
    path = command.get("path")
    timeout = command.get("timeout", 5.0)
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("path must be absolute")
    if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 30:
        raise ValueError("timeout must be in (0, 30]")
    if action == "execute":
        argv_value = command.get("argv", [path])
        if not isinstance(argv_value, list) or not all(isinstance(v, str) for v in argv_value):
            raise ValueError("argv must be a string list")
        argv = tuple(argv_value)
        if not argv or argv[0] != path:
            argv = (path, *argv)
        return {"results": _wait_many([_fork_exec(path, argv)], float(timeout))}
    count = command.get("count")
    if not isinstance(count, int) or count < 1 or count > 32:
        raise ValueError("count must be in [1, 32]")
    return {
        "results": _wait_many(
            [_fork_exec(path, (path,)) for _ in range(count)],
            float(timeout),
        )
    }


def main() -> int:
    for line in sys.stdin:
        try:
            command = json.loads(line)
            response = handle(command)
            print(json.dumps({"ok": True, **response}), flush=True)
            if response.get("shutdown"):
                return 0
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            print(
                json.dumps(
                    {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                ),
                flush=True,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
