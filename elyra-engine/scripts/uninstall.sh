#!/usr/bin/env bash
set -Eeuo pipefail

PURGE_DATA=0
PURGE_GROUPS=0

usage() {
    cat <<'EOF'
Usage: sudo ./scripts/uninstall.sh [--purge-data] [--purge-groups]

By default, Elyra application files and systemd integration are removed while
/var/lib/elyra and /var/log/elyra are preserved for recovery and evidence.
EOF
}

while (($#)); do
    case "$1" in
        --purge-data) PURGE_DATA=1 ;;
        --purge-groups) PURGE_GROUPS=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

if [[ ${EUID} -ne 0 ]]; then
    echo "Elyra removal requires root" >&2
    exit 1
fi

systemctl disable --now elyra.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/elyra.service
rm -f /usr/local/bin/elyra-gui /usr/local/bin/elyra-gui
rm -f /usr/share/applications/elyra.desktop /usr/share/applications/elyra.desktop
rm -f /usr/lib/sysusers.d/elyra.conf
rm -rf /opt/elyra
rm -rf /run/elyra
systemctl daemon-reload
systemctl reset-failed elyra.service >/dev/null 2>&1 || true

if [[ $PURGE_DATA -eq 1 ]]; then
    rm -rf /var/lib/elyra /var/log/elyra
else
    echo "Preserved /var/lib/elyra and /var/log/elyra"
fi

if [[ $PURGE_GROUPS -eq 1 ]]; then
    getent group elyra-admin >/dev/null && groupdel elyra-admin || true
    getent group elyra >/dev/null && groupdel elyra || true
fi

echo "Elyra application and systemd integration removed."
