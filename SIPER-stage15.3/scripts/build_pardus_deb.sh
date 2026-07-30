#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT_DIR=${1:-$PROJECT_ROOT/dist/debian}
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
PACKAGE_NAME="siper-pardus_${DEBIAN_VERSION}_amd64"
WORK=$(mktemp -d -t siper-deb-XXXXXX)
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/$PACKAGE_NAME"
PAYLOAD="$ROOT/usr/share/siper"
WHEELHOUSE="$PAYLOAD/wheelhouse"

mkdir -p "$ROOT/DEBIAN" "$PAYLOAD/release" "$WHEELHOUSE" \
    "$ROOT/etc/systemd/system" "$ROOT/usr/local/bin" \
    "$ROOT/usr/share/applications" "$ROOT/usr/lib/sysusers.d"

sed "s/@DEBIAN_VERSION@/$DEBIAN_VERSION/g" "$PROJECT_ROOT/packaging/debian/control.in" > "$ROOT/DEBIAN/control"
for script in postinst prerm postrm; do
    sed "s/@PROJECT_VERSION@/$VERSION/g" "$PROJECT_ROOT/packaging/debian/${script}.in" > "$ROOT/DEBIAN/$script"
    chmod 0755 "$ROOT/DEBIAN/$script"
done

cp "$PROJECT_ROOT/requirements.txt" "$PAYLOAD/requirements.txt"
cp -a "$PROJECT_ROOT/README.md" "$PROJECT_ROOT/LICENSE" "$PROJECT_ROOT/SECURITY.md" \
    "$PROJECT_ROOT/RELEASE_NOTES.md" "$PROJECT_ROOT/docs" "$PAYLOAD/release/"
cp "$PROJECT_ROOT/packaging/systemd/elliot.service" "$ROOT/etc/systemd/system/elliot.service"
cp "$PROJECT_ROOT/scripts/launch_gui.sh" "$ROOT/usr/local/bin/siper-gui"
ln -s siper-gui "$ROOT/usr/local/bin/elliot-gui"
cp "$PROJECT_ROOT/packaging/desktop/siper.desktop" "$ROOT/usr/share/applications/siper.desktop"
cp "$PROJECT_ROOT/packaging/sysusers/elliot.conf" "$ROOT/usr/lib/sysusers.d/elliot.conf"
chmod 0755 "$ROOT/usr/local/bin/siper-gui"

"$PYTHON" -m pip download --only-binary=:all: --dest "$WHEELHOUSE" -r "$PROJECT_ROOT/requirements.txt"
"$PYTHON" -m pip wheel --no-deps --no-build-isolation --wheel-dir "$WHEELHOUSE" "$PROJECT_ROOT"
"$PYTHON" -m pip download --only-binary=:all: --dest "$WHEELHOUSE" pip setuptools wheel

mkdir -p "$OUTPUT_DIR"
dpkg-deb --root-owner-group --build "$ROOT" "$OUTPUT_DIR/${PACKAGE_NAME}.deb"
sha256sum "$OUTPUT_DIR/${PACKAGE_NAME}.deb" > "$OUTPUT_DIR/${PACKAGE_NAME}.deb.sha256"
echo "Debian package: $OUTPUT_DIR/${PACKAGE_NAME}.deb"
echo "Install with: sudo apt install ./$PACKAGE_NAME.deb"
