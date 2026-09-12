#!/bin/sh
set -eu

ENTRY=/opt/elyra/current/.venv/bin/elyra-gui
if [ ! -x "$ENTRY" ]; then
    echo "Elyra GUI is not installed correctly: $ENTRY" >&2
    exit 1
fi

if [ "$(id -u)" -ne 0 ] && ! id -nG | tr ' ' '\n' | grep -Fxq elyra; then
    echo "This login session is not yet a member of the 'elyra' IPC group." >&2
    echo "Log out and log in again after installation, then retry." >&2
fi

exec "$ENTRY" "$@"
