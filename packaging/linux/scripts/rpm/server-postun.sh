#!/bin/sh
# packaging/linux/scripts/rpm/server-postun.sh — RPM %postun scriptlet for
# vapourwault-server (TASK-150). RPM's %postun receives $1 as an
# install-count, NOT an action string like DEB's postrm: $1 == 0 means
# this was the final removal (no versions of the package remain), $1 >= 1
# means an upgrade is in progress (a newer version is being installed) —
# the exact opposite kind of signal from DEB's "remove"/"purge" strings,
# so this cannot share a script verbatim with
# packaging/linux/scripts/server/postrm (TASK-149); it interprets its own
# convention and keeps its own copy of the same delete logic (RPM has no
# "purge" concept distinct from final removal at all — see TASK-150's
# docs/RELEASE.md note, `dnf remove` behaves like DEB's `apt purge`, not
# `apt remove`).

set -e

if [ "$1" -eq 0 ]; then
    SERVICE_USER="vapourwault"
    DATA_DIR="/var/lib/vapourwault"
    CONF_DIR="/etc/vapourwault"
    RUN_DIR="/run/vapourwault"

    rm -rf "${DATA_DIR}"
    rm -rf "${CONF_DIR}"
    rm -rf "${RUN_DIR}"

    if id "${SERVICE_USER}" >/dev/null 2>&1; then
        userdel "${SERVICE_USER}" || true
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

exit 0
