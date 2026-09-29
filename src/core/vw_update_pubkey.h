#ifndef VW_UPDATE_PUBKEY_H
#define VW_UPDATE_PUBKEY_H

/*
 * vw_update_pubkey — the compiled-in VaporWault update-manifest signing
 * public key (TASK-00293).
 *
 * GENERATED FILE — do not hand-edit. Regenerate from the committed
 * packaging/signing/update-manifest-pubkey.pem (public key only; the
 * matching private key lives ONLY in the UPDATE_SIGNING_KEY GitHub Actions
 * secret, never in this repo) via:
 *
 *   openssl ec -in packaging/signing/update-manifest-pubkey.pem -pubin \
 *     -outform DER | tail -c 65 | xxd -i
 *
 * and reformat the resulting byte list into VW_UPDATE_MANIFEST_PUBKEY
 * below. tests/unit/test_vw_crypto.c's
 * "vw_update_pubkey: compiled-in constant matches committed .pem" case
 * parses the .pem itself at test time and fails loudly if the two
 * committed representations (this header and the .pem) ever drift apart —
 * always run it after regenerating this file.
 *
 * This key is compiled directly into every client binary (not loaded from
 * a sidecar file) specifically so it cannot be swapped by tampering with
 * files next to the binary — see ARCHITECTURE.md's "Client auto-update:
 * manifest signing key" row for the full rationale.
 */

#include "vw_crypto.h"  /* VW_ECDSA_P256_PUBKEY_BYTES */

#ifdef __cplusplus
extern "C" {
#endif

static const uint8_t VW_UPDATE_MANIFEST_PUBKEY[VW_ECDSA_P256_PUBKEY_BYTES] = {
    0x04, 0xf9, 0x92, 0x08, 0x91, 0xdd, 0x95, 0x59, 0x92, 0x46,
    0x2c, 0x37, 0x52, 0x3e, 0x7d, 0x3e, 0x7c, 0xfb, 0x08, 0xec,
    0xc6, 0x4b, 0x30, 0x31, 0x0d, 0x5f, 0x1f, 0xc7, 0x14, 0x64,
    0x8b, 0x6d, 0xdf, 0xcc, 0xb6, 0x9f, 0xa3, 0xa5, 0x28, 0x8c,
    0x72, 0xce, 0xda, 0xd6, 0x18, 0x13, 0xc2, 0x90, 0xd9, 0xcb,
    0x36, 0xcd, 0xed, 0x11, 0x22, 0xa8, 0x58, 0xfc, 0x1b, 0x2f,
    0x2f, 0x9c, 0xf7, 0x30, 0xe3
};

#ifdef __cplusplus
}
#endif

#endif /* VW_UPDATE_PUBKEY_H */
