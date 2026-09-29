#!/usr/bin/env bash
# gen_update_keypair.sh — generate the VaporWault update-manifest signing
# keypair (TASK-00293).
#
# Run this OFFLINE, by hand, once. Never run from CI — the private key must
# never touch a CI runner except as the short-lived, already-provisioned
# GitHub Actions secret UPDATE_SIGNING_KEY that release.yml materializes
# and immediately deletes per signing run (same custody pattern as the
# existing GPG_SIGNING_PRIVATE_KEY secret — see docs/RELEASE.md).
#
# This is a DISTINCT keypair from the GPG packaging-signing key
# (packaging/signing/vaporwault-releases-pubkey.asc): that one signs
# .deb/.rpm/tar.gz/zip/apk for human `gpg --verify` use; this one signs
# only the small update-manifest.json the client's own code verifies
# automatically, using a lightweight scheme (raw ECDSA-over-bytes) the
# client can implement without an OpenPGP dependency.
#
# Usage:
#   ./gen_update_keypair.sh
#
# Produces (in the current directory, NOT committed to the repo):
#   update_signing_key.pem       — PRIVATE key. Paste its contents into the
#                                   UPDATE_SIGNING_KEY GitHub Actions secret,
#                                   then delete this file. Never commit it.
#   update-manifest-pubkey.pem   — PUBLIC key. This one IS committed, at
#                                   packaging/signing/update-manifest-pubkey.pem
#                                   (this script's own directory) — copy it
#                                   there and `git add` it.
#
# After generating, run tools/gen_update_pubkey_header.sh (or the manual
# steps in its header comment) to regenerate src/core/vw_update_pubkey.h's
# compiled-in constant from the new public key, and confirm
# test_vw_update_pubkey_matches_pem (tests/unit/test_vw_crypto.c) passes —
# it fails loudly if the two committed representations (this .pem and the
# compiled header) ever drift apart.

set -euo pipefail

if [ -e update_signing_key.pem ] || [ -e update-manifest-pubkey.pem ]; then
    echo "error: update_signing_key.pem or update-manifest-pubkey.pem already exists in $(pwd)" >&2
    echo "       refusing to overwrite — remove it first if you really mean to rotate the key." >&2
    exit 1
fi

openssl ecparam -name prime256v1 -genkey -noout -out update_signing_key.pem
openssl ec -in update_signing_key.pem -pubout -out update-manifest-pubkey.pem

echo
echo "Generated update_signing_key.pem (PRIVATE — do not commit) and"
echo "update-manifest-pubkey.pem (public — commit this one) in $(pwd)."
echo
echo "Next steps:"
echo "  1. Paste update_signing_key.pem's contents into the UPDATE_SIGNING_KEY"
echo "     GitHub Actions secret, then delete update_signing_key.pem from disk."
echo "  2. Copy update-manifest-pubkey.pem to packaging/signing/ in the repo"
echo "     and commit it."
echo "  3. Regenerate src/core/vw_update_pubkey.h's raw point bytes from the"
echo "     new public key and confirm the drift-check unit test passes."
