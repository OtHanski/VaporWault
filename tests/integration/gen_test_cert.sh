#!/usr/bin/env bash
# gen_test_cert.sh — generate a self-signed TLS certificate and key for local
# integration test runs.  Not for production use.
#
# Usage:
#   tests/integration/gen_test_cert.sh [output-dir]
#
# Outputs:
#   <output-dir>/test.crt  — self-signed X.509 certificate (PEM)
#   <output-dir>/test.key  — private key (PEM, RSA-2048)
#
# The output directory defaults to the directory containing this script.
# If test.crt and test.key already exist the script exits without regenerating.

set -euo pipefail

OUT_DIR="${1:-$(dirname "$0")}"
CERT="${OUT_DIR}/test.crt"
KEY="${OUT_DIR}/test.key"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    echo "gen_test_cert: $CERT and $KEY already exist — skipping." >&2
    exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
    echo "gen_test_cert: 'openssl' not found in PATH." >&2
    echo "Install it (e.g. 'sudo apt install openssl' or 'brew install openssl')," >&2
    echo "or provide pre-generated test.crt and test.key files." >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" \
    -out    "$CERT" \
    -days   3650 \
    -subj   "/CN=vapourwault-test-ca" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    2>/dev/null

echo "gen_test_cert: wrote $CERT and $KEY" >&2
