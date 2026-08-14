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
# TASK-165/167: the gateway's own state (remember.db, when --state-dir is
# used) - separate directory from the server's DATA_DIR above, since the
# gateway and server are frequently on different hosts and are always
# separate services even when colocated (vapourwault-web-gateway.service's
# own comment: "Deliberately NOT After=/Wants=vapourwaultd.service").
GATEWAY_DATA_DIR="/var/lib/vapourwault-gateway"

# ── Locate binaries ───────────────────────────────────────────────────────────

SERVER_BIN="${BUILD_DIR}/bin/vapourwaultd"
ADMIN_BIN="${BUILD_DIR}/bin/vapourwault-server-cli"
GUI_BIN="${BUILD_DIR}/bin/vapourwault-server-gui"
# Optional, like GUI_BIN above - VW_BUILD_WEB_GATEWAY defaults OFF
# (docs/DEPLOYMENT.md §11.2), so most server-only builds won't have this.
GATEWAY_BIN="${BUILD_DIR}/bin/vapourwault-web-gateway"

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
if [[ -f "${GATEWAY_BIN}" ]]; then
    install -m 755 "${GATEWAY_BIN}" "${BIN_DIR}/vapourwault-web-gateway"
fi
echo "Installed binaries to ${BIN_DIR}"

# ── Create directories ────────────────────────────────────────────────────────

install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 750 "${DATA_DIR}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 750 "${CONF_DIR}"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 750 "${RUN_DIR}"

# TASK-165/167: only created when the gateway is actually being installed -
# an unused directory for a feature/binary this install doesn't ship would
# just be clutter. 0700 (not the server DATA_DIR's 0750): the gateway's own
# remember.db file inside it is a bearer-credential store as sensitive as a
# password (see vw_gateway_remember.h's own doc), so even group-read on the
# containing directory is one more thing that could go wrong - narrower than
# strictly required (the file itself is already 0600) but cheap insurance,
# and there's no legitimate reason for anyone but SERVICE_USER to read this
# directory's contents at all.
if [[ -f "${GATEWAY_BIN}" ]]; then
    install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 700 "${GATEWAY_DATA_DIR}"
fi

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
if [[ -f "${GATEWAY_BIN}" ]]; then
    install -m 644 "${SCRIPT_DIR}/vapourwault-web-gateway.service" \
        "${SYSTEMD_DIR}/vapourwault-web-gateway.service"
    echo "Installed systemd unit: vapourwault-web-gateway.service"
    echo "  --> Edit its ExecStart line for your --server-host/--server-port/--ca-cert"
    echo "      before starting it (it has no separate config file - see"
    echo "      docs/DEPLOYMENT.md §11.3)."
fi
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
