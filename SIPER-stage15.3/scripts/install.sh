#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_ROOT=/opt/elliot
RELEASES_DIR="$INSTALL_ROOT/releases"
CURRENT_LINK="$INSTALL_ROOT/current"
SERVICE_FILE=/etc/systemd/system/elliot.service
GUI_LAUNCHER=/usr/local/bin/siper-gui
LEGACY_GUI_LAUNCHER=/usr/local/bin/elliot-gui
DESKTOP_ENTRY=/usr/share/applications/siper.desktop
SYSUSERS_FILE=/usr/lib/sysusers.d/elliot.conf
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

INSTALL_SYSTEM_DEPS=1
ENABLE_SERVICE=1
START_SERVICE=1
GUI_USER=${SUDO_USER:-}
ADMIN_USER=""
PREVIOUS_TARGET=""
NEW_RELEASE=""
SWITCHED=0

usage() {
    cat <<'EOF'
Usage: sudo ./scripts/install.sh [options]

Options:
  --user USER              Add USER to the unprivileged 'elliot' IPC group.
  --admin-user USER        Explicitly add USER to the sensitive 'elliot-admin' group.
  --skip-system-deps       Do not run apt; require dependencies to be preinstalled.
  --no-enable              Install the unit without enabling it at boot.
  --no-start               Install without starting/restarting the daemon.
  -h, --help               Show this help.

Safe defaults:
  * fanotify starts in MONITOR_ONLY mode;
  * automatic runtime terminate/quarantine actions remain disabled;
  * no user is added to elliot-admin unless --admin-user is supplied.
EOF
}

while (($#)); do
    case "$1" in
        --user)
            [[ $# -ge 2 ]] || { echo "--user requires a value" >&2; exit 2; }
            GUI_USER=$2
            shift 2
            ;;
        --admin-user)
            [[ $# -ge 2 ]] || { echo "--admin-user requires a value" >&2; exit 2; }
            ADMIN_USER=$2
            shift 2
            ;;
        --skip-system-deps)
            INSTALL_SYSTEM_DEPS=0
            shift
            ;;
        --no-enable)
            ENABLE_SERVICE=0
            shift
            ;;
        --no-start)
            START_SERVICE=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ${EUID} -ne 0 ]]; then
    echo "Siper installation requires root: sudo ./scripts/install.sh" >&2
    exit 1
fi

validate_user() {
    local username=$1
    [[ -z "$username" ]] && return 0
    if ! id "$username" >/dev/null 2>&1; then
        echo "Requested user does not exist: $username" >&2
        exit 2
    fi
}
validate_user "$GUI_USER"
validate_user "$ADMIN_USER"

install_system_dependencies() {
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        python3 python3-venv python3-pip python3-setuptools python3-wheel python3-tk \
        python3-bpfcc bpfcc-tools clang libmagic1 python3-pil.imagetk \
        linux-headers-amd64

    if [[ ! -e "/lib/modules/$(uname -r)/build" ]]; then
        echo "Matching headers for the running kernel are unavailable." >&2
        echo "Installing the current Pardus kernel/header meta-packages; reboot is required." >&2
        DEBIAN_FRONTEND=noninteractive apt-get install -y linux-image-amd64 linux-headers-amd64
        echo "Reboot Pardus, verify /lib/modules/\$(uname -r)/build, then rerun this installer." >&2
        exit 20
    fi
}

create_groups() {
    install -d -m 0755 "$(dirname "$SYSUSERS_FILE")"
    install -m 0644 "$SOURCE_DIR/packaging/sysusers/elliot.conf" "$SYSUSERS_FILE"
    if command -v systemd-sysusers >/dev/null 2>&1; then
        systemd-sysusers "$SYSUSERS_FILE"
    else
        getent group elliot >/dev/null || groupadd --system elliot
        getent group elliot-admin >/dev/null || groupadd --system elliot-admin
    fi
    getent group elliot >/dev/null || { echo "Failed to create elliot group" >&2; exit 1; }
    getent group elliot-admin >/dev/null || { echo "Failed to create elliot-admin group" >&2; exit 1; }
}

copy_release_source() {
    local destination=$1
    install -d -o root -g root -m 0755 "$destination"
    tar \
        --exclude='./.git' \
        --exclude='./.venv' \
        --exclude='./.pytest_cache' \
        --exclude='*/__pycache__' \
        --exclude='*.pyc' \
        -C "$SOURCE_DIR" -cf - . | tar -C "$destination" -xf -
    find "$destination" -xdev -type d -exec chmod go-w {} +
    find "$destination" -xdev -type f -exec chmod go-w {} +
}

atomic_switch_current() {
    local target=$1
    local temporary="$INSTALL_ROOT/.current.$$.tmp"
    rm -f "$temporary"
    ln -s "releases/$(basename "$target")" "$temporary"
    mv -Tf "$temporary" "$CURRENT_LINK"
    SWITCHED=1
}

rollback() {
    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        return
    fi
    echo "Siper installation failed; attempting rollback." >&2
    if [[ $SWITCHED -eq 1 ]]; then
        if [[ -n "$PREVIOUS_TARGET" ]]; then
            local temporary="$INSTALL_ROOT/.rollback.$$.tmp"
            rm -f "$temporary"
            ln -s "$PREVIOUS_TARGET" "$temporary"
            mv -Tf "$temporary" "$CURRENT_LINK"
        else
            rm -f "$CURRENT_LINK"
        fi
    fi
    if [[ -n "$NEW_RELEASE" && -d "$NEW_RELEASE" ]]; then
        rm -rf "$NEW_RELEASE"
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        if [[ -n "$PREVIOUS_TARGET" && $START_SERVICE -eq 1 ]]; then
            systemctl restart elliot.service >/dev/null 2>&1 || true
        fi
    fi
    exit "$exit_code"
}
trap rollback ERR

if [[ $INSTALL_SYSTEM_DEPS -eq 1 ]]; then
    install_system_dependencies
fi

create_groups

if [[ -n "$GUI_USER" ]]; then
    usermod -a -G elliot "$GUI_USER"
fi
if [[ -n "$ADMIN_USER" ]]; then
    usermod -a -G elliot-admin "$ADMIN_USER"
fi

install -d -o root -g root -m 0755 "$INSTALL_ROOT" "$RELEASES_DIR"
install -d -o root -g root -m 0700 /var/lib/elliot /var/lib/elliot/quarantine /var/lib/elliot/metadata
install -d -o root -g root -m 0750 /var/log/elliot
install -d -o root -g elliot -m 0750 /run/elliot

VERSION=$(python3 - "$SOURCE_DIR/pyproject.toml" <<'PY'
import sys, tomllib
with open(sys.argv[1], 'rb') as stream:
    print(tomllib.load(stream)['project']['version'])
PY
)
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)
RELEASE_NAME="${VERSION}-${TIMESTAMP}"
NEW_RELEASE="$RELEASES_DIR/$RELEASE_NAME"
if [[ -e "$NEW_RELEASE" ]]; then
    echo "Release path already exists: $NEW_RELEASE" >&2
    exit 1
fi

if [[ -L "$CURRENT_LINK" ]]; then
    PREVIOUS_TARGET=$(readlink "$CURRENT_LINK")
elif [[ -e "$CURRENT_LINK" ]]; then
    echo "Refusing to replace non-symlink current path: $CURRENT_LINK" >&2
    exit 1
fi

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet elliot.service; then
    systemctl stop elliot.service
fi

copy_release_source "$NEW_RELEASE"
python3 -m venv --system-site-packages "$NEW_RELEASE/.venv"
"$NEW_RELEASE/.venv/bin/python" -m pip install --upgrade pip
"$NEW_RELEASE/.venv/bin/pip" install -r "$NEW_RELEASE/requirements.txt"
"$NEW_RELEASE/.venv/bin/pip" install --no-build-isolation --no-deps "$NEW_RELEASE"

"$NEW_RELEASE/.venv/bin/python" - "$NEW_RELEASE" "$VERSION" "$RELEASE_NAME" "$SOURCE_DIR" <<'PY'
import json, sys
from datetime import datetime, timezone
from pathlib import Path
from elliot.service.install_layout import INSTALLATION_MANIFEST, installation_manifest
release = Path(sys.argv[1])
payload = installation_manifest(
    version=sys.argv[2],
    release_name=sys.argv[3],
    source_directory=sys.argv[4],
    installed_at_utc=datetime.now(timezone.utc).isoformat(),
)
path = release / INSTALLATION_MANIFEST
path.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o644)
PY

for entry in siper-daemon siper-gui siper-preflight siper-install-check elliot-daemon elliot-gui; do
    [[ -x "$NEW_RELEASE/.venv/bin/$entry" ]] || {
        echo "Installed entry point is missing: $entry" >&2
        exit 1
    }
done
if ! find "$NEW_RELEASE/.venv/lib" -type f \
    -path '*/site-packages/elliot/monitor/ebpf/probes.c' -print -quit | grep -q .; then
    # A source-tree fallback remains available for editable/build-backend differences.
    [[ -f "$NEW_RELEASE/src/elliot/monitor/ebpf/probes.c" ]] || {
        echo "Packaged eBPF source is missing" >&2
        exit 1
    }
fi

atomic_switch_current "$NEW_RELEASE"

install -m 0644 "$NEW_RELEASE/packaging/systemd/elliot.service" "$SERVICE_FILE"
install -m 0755 "$NEW_RELEASE/scripts/launch_gui.sh" "$GUI_LAUNCHER"
install -m 0644 "$NEW_RELEASE/packaging/desktop/siper.desktop" "$DESKTOP_ENTRY"
ln -sfn "$GUI_LAUNCHER" "$LEGACY_GUI_LAUNCHER"

systemctl daemon-reload
if [[ $ENABLE_SERVICE -eq 1 ]]; then
    systemctl enable elliot.service
fi
if [[ $START_SERVICE -eq 1 ]]; then
    systemctl restart elliot.service
    if ! systemctl is-active --quiet elliot.service; then
        systemctl status elliot.service --no-pager >&2 || true
        journalctl -u elliot.service -n 80 --no-pager >&2 || true
        false
    fi
fi

SWITCHED=0
trap - ERR

echo "Siper installed release: $RELEASE_NAME"
echo "Current release: $(readlink -f "$CURRENT_LINK")"
echo "Service status: sudo systemctl status elliot.service"
echo "Service logs: sudo journalctl -u elliot.service"
echo "GUI launcher: siper-gui (legacy alias: elliot-gui)"
if [[ -n "$GUI_USER" ]]; then
    echo "User '$GUI_USER' was added to group 'elliot'. Log out and back in before launching the GUI."
fi
if [[ -n "$ADMIN_USER" ]]; then
    echo "WARNING: '$ADMIN_USER' was explicitly added to the sensitive 'elliot-admin' group."
fi
