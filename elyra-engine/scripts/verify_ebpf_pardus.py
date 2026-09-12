#!/usr/bin/env python3
"""Controlled real-kernel Stage 9 verifier using harmless local activity only."""
from __future__ import annotations
import argparse, json, os, platform, socket, subprocess, sys, tempfile, threading, time
from datetime import datetime, timezone
from pathlib import Path

from elyra.monitor.ebpf.collector import EbpfFilterConfig
from elyra.monitor.ebpf.loader import EBPFLoader


def write_evidence(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--timeout", type=float, default=12.0)
    args = parser.parse_args()
    output = Path(args.output)
    payload = {"timestamp_utc": datetime.now(timezone.utc).isoformat(),
               "method": "real BCC/eBPF telemetry with Pardus 25 kernel compatibility; harmless temporary files and loopback TCP only",
               "verifier_revision": "STAGE_9_2_RENAME_COMPAT",
               "environment": {"platform": platform.platform(), "kernel": platform.release(),
                               "python": platform.python_version(), "euid": os.geteuid()},
               "results": [], "overall_status": "UNAVAILABLE"}
    if os.geteuid() != 0:
        payload["reason"] = "ROOT_REQUIRED"
        write_evidence(output, payload)
        print("overall_status: UNAVAILABLE (ROOT_REQUIRED)")
        return 2
    config = EbpfFilterConfig(monitored_uids={0}, ignored_tgids={os.getpid()})
    loader = EBPFLoader(filter_config=config)
    if not loader.initialize():
        payload["reason"] = loader.status().get("degraded_reason")
        payload["collector_status"] = loader.status()
        write_evidence(output, payload)
        print(f"overall_status: UNAVAILABLE ({payload['reason']})")
        return 2
    try:
        with tempfile.TemporaryDirectory(prefix="elyra-stage9-") as temp:
            root = Path(temp)
            source = root / "write_source.txt"
            renamed = root / "write_renamed.txt"
            renamed_again = root / "write_renamed_again.txt"
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind(("127.0.0.1", 0)); server.listen(1)
            port = server.getsockname()[1]
            accept_thread = threading.Thread(target=lambda: server.accept()[0].close(), daemon=True)
            accept_thread.start()
            code = ("from pathlib import Path; import ctypes,os,socket; "
                    f"p=Path({str(source)!r}); p.write_text('safe stage9.2'); "
                    f"libc=ctypes.CDLL(None,use_errno=True); "
                    f"rc=libc.rename({os.fsencode(str(source))!r},{os.fsencode(str(renamed))!r}); "
                    f"assert rc==0, ctypes.get_errno(); os.rename({str(renamed)!r},{str(renamed_again)!r}); "
                    f"s=socket.socket(); s.connect(('127.0.0.1',{port})); s.close()")
            child = subprocess.run([sys.executable, "-c", code], check=False, timeout=5)
            deadline = time.monotonic() + args.timeout
            records = []
            while time.monotonic() < deadline:
                event = loader.fetch_event(timeout=0.25)
                if event:
                    records.append(event)
                types = {item["event_type"] for item in records}
                if {"PROCESS_EXEC", "PROCESS_EXIT", "FILE_WRITE", "FILE_RENAME", "NETWORK_CONNECT"}.issubset(types):
                    break
            server.close()
            types = {item["event_type"] for item in records}
            checks = [
                ("process_execution_observed", "PROCESS_EXEC" in types),
                ("process_exit_observed", "PROCESS_EXIT" in types),
                ("selected_file_write_observed", "FILE_WRITE" in types),
                ("selected_rename_observed", "FILE_RENAME" in types),
                ("loopback_outbound_connect_observed", "NETWORK_CONNECT" in types),
                ("child_completed_without_hang", child.returncode == 0),
                ("file_events_use_identifier_not_unverified_full_path",
                 all(item.get("probe_path_capability") == "IDENTIFIER_ONLY" for item in records
                     if item["event_type"] in {"FILE_WRITE", "FILE_RENAME"})),
            ]
            payload["results"] = [{"scenario": name, "status": "OK" if ok else "FAIL"} for name, ok in checks]
            payload["observed_event_types"] = sorted(types)
            payload["sample_records"] = records[:30]
            payload["collector_status"] = loader.status()
            payload["overall_status"] = "OK" if all(ok for _, ok in checks) else "FAIL"
    except Exception as exc:
        payload["overall_status"] = "FAIL"
        payload["reason"] = f"{type(exc).__name__}: {exc}"
    finally:
        loader.shutdown()
        write_evidence(output, payload)
    for result in payload.get("results", []):
        print(f"{result['scenario']}: {result['status']}")
    print(f"overall_status: {payload['overall_status']}")
    print(f"Evidence written to: {output}")
    return 0 if payload["overall_status"] == "OK" else 1

if __name__ == "__main__":
    raise SystemExit(main())
