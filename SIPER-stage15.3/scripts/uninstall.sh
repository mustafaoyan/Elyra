#!/usr/bin/env bash
set -Eeuo pipefail

PURGE_DATA=0
PURGE_GROUPS=0

usage() {
    cat <<'EOF'
Usage: sudo ./scripts/uninstall.sh [--purge-data] [--purge-groups]

By default, Siper application files and systemd integration are removed while
/var/lib/elliot and /var/log/elliot are preserved for recovery and evidence.
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
    echo "Siper removal requires root" >&2
    exit 1
fi

systemctl disable --now elliot.service >/dev/null 2>&1 || true
rm -f /etc/systemd/system/elliot.service
rm -f /usr/local/bin/siper-gui /usr/local/bin/elliot-gui
rm -f /usr/share/applications/siper.desktop /usr/share/applications/elliot.desktop
rm -f /usr/lib/sysusers.d/elliot.conf
rm -rf /opt/elliot
rm -rf /run/elliot
systemctl daemon-reload
systemctl reset-failed elliot.service >/dev/null 2>&1 || true

if [[ $PURGE_DATA -eq 1 ]]; then
    rm -rf /var/lib/elliot /var/log/elliot
else
    echo "Preserved /var/lib/elliot and /var/log/elliot"
fi

if [[ $PURGE_GROUPS -eq 1 ]]; then
    getent group elliot-admin >/dev/null && groupdel elliot-admin || true
    getent group elliot >/dev/null && groupdel elliot || true
fi

echo "Siper application and systemd integration removed."
