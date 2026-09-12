#!/usr/bin/env python3
"""Inspect and optionally repair eBPF kernel-header compatibility.

The default invocation is a dry run.  It prints the exact running-kernel
package and/or safe build-link operation that would be used, but makes no
system changes.  ``--apply`` is intentionally explicit because installing
headers and changing ``/lib/modules/<release>/build`` require administrator
approval.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from elyra.monitor.ebpf.kernel_headers import resolve_kernel_headers


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "explicitly install exact headers and/or repair a build symlink; "
            "requires root and never replaces a real directory"
        ),
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    result = resolve_kernel_headers(apply=args.apply)
    payload = result.to_dict()
    final = result.final_assessment
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        mode = "APPLY" if args.apply else "DRY RUN"
        print(f"mode: {mode}")
        print(f"kernel: {final.kernel_release}")
        print(f"virtualization: {final.virtualization.kind}")
        for action in result.initial_plan.actions:
            if action.command:
                print(f"planned {action.kind}: {' '.join(action.command)}")
            elif action.source_path and action.target_path:
                print(f"planned {action.kind}: {action.target_path} -> {action.source_path}")
            else:
                print(f"planned {action.kind}: {action.summary}")
        for step in result.steps:
            print(f"{step.status}: {step.action.kind}: {step.detail}")
        print(f"final_status: {final.status}")

    if final.ready:
        return 0
    if not args.apply:
        # A dry run found an actionable (or manual) compatibility issue.
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
