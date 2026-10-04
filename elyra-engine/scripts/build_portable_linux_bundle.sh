#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT_DIR=${1:-$PROJECT_ROOT/dist/portable}
VERSION=$(python3 - "$PROJECT_ROOT/pyproject.toml" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as stream:
    print(tomllib.load(stream)["project"]["version"])
PY
)
BUNDLE="elyra-linux-${VERSION}-x86_64"
WORK=$(mktemp -d -t elyra-portable-XXXXXX)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/$BUNDLE"
tar -C "$PROJECT_ROOT" --exclude='.venv' --exclude='.pytest_cache' --exclude='.pytest-temp' --exclude='__pycache__' -cf - . | tar -C "$WORK/$BUNDLE" -xf -
cat > "$WORK/$BUNDLE/PORTABLE-LINUX.md" <<'EOF'
# Elyra portable Linux bundle

This bundle is distribution-neutral source packaging for Linux x86_64. It
requires Python 3.10+ and the native libraries listed in `requirements.txt`.
Run `sudo ./scripts/install.sh --user "$USER"` from this directory. For Debian
and Ubuntu, prefer the `.deb` asset when available. Kernel-specific fanotify
and eBPF capabilities remain dependent on the host kernel and permissions.
EOF
mkdir -p "$OUTPUT_DIR"
tar -C "$WORK" -czf "$OUTPUT_DIR/${BUNDLE}.tar.gz" "$BUNDLE"
sha256sum "$OUTPUT_DIR/${BUNDLE}.tar.gz" > "$OUTPUT_DIR/${BUNDLE}.tar.gz.sha256"
echo "Portable Linux bundle: $OUTPUT_DIR/${BUNDLE}.tar.gz"
