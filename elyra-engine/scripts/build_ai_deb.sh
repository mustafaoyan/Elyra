#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT_DIR=${1:-$PROJECT_ROOT/dist/ai-debian}
PYTHON=${PYTHON:-python3}
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 1; }
command -v "$PYTHON" >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 1; }

VERSION=$($PYTHON - "$PROJECT_ROOT/pyproject.toml" <<'PY'
import sys, tomllib
with open(sys.argv[1], 'rb') as stream:
    print(tomllib.load(stream)['project']['version'])
PY
)
DEBIAN_VERSION="${VERSION}-1"
PACKAGE_NAME="elyra-ai-linux_${DEBIAN_VERSION}_amd64"
WORK=$(mktemp -d -t elyra-ai-deb-XXXXXX)
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/$PACKAGE_NAME"
PAYLOAD="$ROOT/usr/share/elyra-ai"
WHEELHOUSE="$PAYLOAD/wheelhouse"
mkdir -p "$ROOT/DEBIAN" "$PAYLOAD" "$WHEELHOUSE" "$ROOT/usr/local/bin" "$ROOT/usr/share/applications"

cat > "$ROOT/DEBIAN/control" <<EOF
Package: elyra-ai
Version: $DEBIAN_VERSION
Section: utils
Priority: optional
Architecture: amd64
Depends: python3, python3-venv
Maintainer: Elyra Team
Description: Elyra local evidence analysis assistant
 A safe, local-only assistant for explaining Elyra scanner evidence.
EOF
cat > "$ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
python3 -m venv --system-site-packages /usr/share/elyra-ai/.venv
/usr/share/elyra-ai/.venv/bin/python -m pip install --no-index --no-deps /usr/share/elyra-ai/wheelhouse/*.whl
ln -sf /usr/share/elyra-ai/.venv/bin/elyra-ai /usr/local/bin/elyra-ai
exit 0
EOF
chmod 0755 "$ROOT/DEBIAN/postinst"
cp "$PROJECT_ROOT/packaging/desktop/elyra-ai.desktop" "$ROOT/usr/share/applications/elyra-ai.desktop"
"$PYTHON" -m pip wheel --no-deps --no-build-isolation --wheel-dir "$WHEELHOUSE" "$PROJECT_ROOT"
mkdir -p "$OUTPUT_DIR"
dpkg-deb --root-owner-group --build "$ROOT" "$OUTPUT_DIR/${PACKAGE_NAME}.deb"
sha256sum "$OUTPUT_DIR/${PACKAGE_NAME}.deb" > "$OUTPUT_DIR/${PACKAGE_NAME}.deb.sha256"
echo "AI package: $OUTPUT_DIR/${PACKAGE_NAME}.deb"
