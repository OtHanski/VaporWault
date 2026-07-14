#!/usr/bin/env bash
# client_install.sh — install the VaporWault client daemon (no root required).
#
# Usage:
#   packaging/linux/client_install.sh [--build-dir DIR]
#
# Installs to $HOME/.local/bin and registers a systemd user service.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="build/bin"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done

DAEMON_BIN="${BUILD_DIR}/vapourwault-daemon"
CLI_BIN="${BUILD_DIR}/vapourwault-cli"

if [ ! -f "$DAEMON_BIN" ]; then
    echo "error: vapourwault-daemon not found at '$DAEMON_BIN'" >&2
    echo "Build the project first:  cmake --build build" >&2
    exit 1
fi
if [ ! -f "$CLI_BIN" ]; then
    echo "error: vapourwault-cli not found at '$CLI_BIN'" >&2
    exit 1
fi

# ── Directories ───────────────────────────────────────────────────────────────

BIN_DIR="$HOME/.local/bin"
STATE_DIR="$HOME/.local/share/vapourwault"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"

mkdir -p "$BIN_DIR" "$STATE_DIR" "$SYSTEMD_USER_DIR"

# ── Binaries ──────────────────────────────────────────────────────────────────

install -m 0755 "$DAEMON_BIN" "$BIN_DIR/vapourwault-daemon"
install -m 0755 "$CLI_BIN"    "$BIN_DIR/vapourwault-cli"
echo "Installed:  $BIN_DIR/vapourwault-daemon"
echo "Installed:  $BIN_DIR/vapourwault-cli"

# ── systemd user service ──────────────────────────────────────────────────────

install -m 0644 \
    "$SCRIPT_DIR/vapourwault-daemon.service" \
    "$SYSTEMD_USER_DIR/vapourwault-daemon.service"
echo "Installed:  $SYSTEMD_USER_DIR/vapourwault-daemon.service"

systemctl --user daemon-reload
echo "Reloaded:   systemctl --user daemon-reload"

# ── Default config (do not overwrite existing) ────────────────────────────────

CONF_FILE="$STATE_DIR/daemon.conf"
if [ ! -f "$CONF_FILE" ]; then
    install -m 0600 "$SCRIPT_DIR/client.conf.example" "$CONF_FILE"
    echo "Created:    $CONF_FILE (template — edit before starting the daemon)"
else
    echo "Skipped:    $CONF_FILE already exists"
fi

# ── Next steps ────────────────────────────────────────────────────────────────

cat <<EOF

Next steps:

  1. Edit the daemon configuration:
       \$EDITOR $CONF_FILE

  2. Enable and start the daemon (auto-starts on login):
       systemctl --user enable --now vapourwault-daemon

  3. Check the daemon status:
       systemctl --user status vapourwault-daemon

  4. Log in to your VaporWault account:
       vapourwault-cli login <password>

EOF
