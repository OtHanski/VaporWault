#!/usr/bin/env bash
# install.sh — install VaporWault server on Linux
#
# Run as root after building the project:
#   sudo packaging/linux/install.sh [--prefix /usr/local] [--build-dir build]
#
# The script is idempotent: safe to run on an existing installation.

set -euo pipefail

PREFIX="/usr/local"
BUILD_DIR="build"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)  PREFIX="$2";    shift 2 ;;
        --build-dir) BUILD_DIR="$2"; shift 2 ;;
        *)         echo "Unknown option: $1"; exit 1 ;;
    esac
done

BIN_DIR="${PREFIX}/bin"
SYSTEMD_DIR="/lib/systemd/system"
CONF_DIR="/etc/vapourwault"
DATA_DIR="/var/lib/vapourwault"
RUN_DIR="/run/vapourwault"
SERVICE_USER="vapourwault"

# ── Locate binaries ───────────────────────────────────────────────────────────

SERVER_BIN="${BUILD_DIR}/bin/vapourwaultd"
ADMIN_BIN="${BUILD_DIR}/bin/vapourwault-server-cli"
GUI_BIN="${BUILD_DIR}/bin/vapourwault-server-gui"

if [[ ! -f "${SERVER_BIN}" ]]; then
    echo "ERROR: server binary not found at ${SERVER_BIN}" >&2
    echo "Build the project first: cmake --build ${BUILD_DIR}" >&2
    exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
    echo "ERROR: this script must be run as root (use sudo)" >&2
    exit 1
fi

echo "Installing VaporWault to ${PREFIX}..."

# ── Create system user ────────────────────────────────────────────────────────

if ! id "${SERVICE_USER}" &>/dev/null; then
    echo "Creating system user: ${SERVICE_USER}"
    useradd --system \
            --no-create-home \
            --home-dir "${DATA_DIR}" \
            --shell /usr/sbin/nologin \
            --comment "VaporWault server" \
            "${SERVICE_USER}"
fi

# ── Install binaries ──────────────────────────────────────────────────────────

install -d "${BIN_DIR}"
install -m 755 "${SERVER_BIN}" "${BIN_DIR}/vapourwaultd"
install -m 755 "${ADMIN_BIN}"  "${BIN_DIR}/vapourwault-server-cli"
if [[ -f "${GUI_BIN}" ]]; then
    install -m 755 "${GUI_BIN}" "${BIN_DIR}/vapourwault-server-gui"
fi
echo "Installed binaries to ${BIN_DIR}"

# ── Create directories ────────────────────────────────────────────────────────

install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 750 "${DATA_DIR}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 750 "${CONF_DIR}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 750 "${RUN_DIR}"

# ── Install config template (do not overwrite existing config) ─────────────────

CONF_FILE="${CONF_DIR}/server.conf"
if [[ ! -f "${CONF_FILE}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    install -m 640 -o "${SERVICE_USER}" -g "${SERVICE_USER}" \
        "${SCRIPT_DIR}/server.conf.example" "${CONF_FILE}"
    echo "Installed default config to ${CONF_FILE}"
    echo "  --> Edit ${CONF_FILE} before starting the service."
else
    echo "Config already exists at ${CONF_FILE} — not overwritten."
fi

# ── Install systemd unit ──────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install -m 644 "${SCRIPT_DIR}/vapourwaultd.service" \
    "${SYSTEMD_DIR}/vapourwaultd.service"
systemctl daemon-reload
echo "Installed systemd unit: vapourwaultd.service"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "Installation complete. Next steps:"
echo "  1. Edit ${CONF_FILE}"
echo "  2. Add at least one admin user:"
echo "       ${BIN_DIR}/vapourwault-server-cli --admin-socket ${RUN_DIR}/admin.sock \\"
echo "           user-create admin 'YourStrongPassword' --admin"
echo "     (run after starting the service for the first time)"
echo "  3. Enable and start the service:"
echo "       systemctl enable --now vapourwaultd"
echo "  4. Check status:"
echo "       systemctl status vapourwaultd"
echo "       journalctl -u vapourwaultd -f"
