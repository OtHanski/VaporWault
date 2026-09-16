#ifndef VW_UPDATE_MANIFEST_H
#define VW_UPDATE_MANIFEST_H

/*
 * vw_update_manifest — fetch, cryptographically verify, and parse the
 * client auto-update feature's `update-manifest.json` (TASK-00297,
 * ARCHITECTURE.md Phase 23).
 *
 * The manifest is the actual, cryptographically-verified source of truth
 * for what release exists and what to install — the server's version
 * advertisement (docs/PROTOCOL.md §6.4) is only ever a trigger hint, never
 * trusted directly (see vw_update.c, TASK-00298). This module never acts
 * on manifest bytes it hasn't already verified: signature check happens
 * over the exact raw bytes fetched, BEFORE any JSON parsing.
 */

#include "../core/vw_proto.h"   /* vw_err_t */
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define VW_UPDATE_MANIFEST_MAX_ASSETS       8u
#define VW_UPDATE_MANIFEST_VERSION_MAXLEN   31u
#define VW_UPDATE_MANIFEST_PLATFORM_MAXLEN  15u
#define VW_UPDATE_MANIFEST_ARCH_MAXLEN      15u
#define VW_UPDATE_MANIFEST_DISTKIND_MAXLEN  15u
#define VW_UPDATE_MANIFEST_FILENAME_MAXLEN  255u

typedef struct {
    char    platform[VW_UPDATE_MANIFEST_PLATFORM_MAXLEN + 1];
    char    arch[VW_UPDATE_MANIFEST_ARCH_MAXLEN + 1];
    char    dist_kind[VW_UPDATE_MANIFEST_DISTKIND_MAXLEN + 1];
    char    filename[VW_UPDATE_MANIFEST_FILENAME_MAXLEN + 1];
    uint8_t sha256[32];
} vw_update_manifest_asset_t;

typedef struct {
    uint32_t schema_version;
    uint64_t sequence;
    char     release_version[VW_UPDATE_MANIFEST_VERSION_MAXLEN + 1];
    uint16_t min_client_protocol_version;
    int64_t  published_at; /* informational only — never used in a trust
                               or rollback decision; see vw_update_manifest.c */
    vw_update_manifest_asset_t assets[VW_UPDATE_MANIFEST_MAX_ASSETS];
    uint32_t asset_count;
} vw_update_manifest_t;

/*
 * Fetch, verify, and parse the update manifest. Mandatory internal order,
 * never reversed: fetch manifest bytes -> fetch detached signature bytes
 * -> ECDSA-verify the signature over SHA-256(manifest bytes) against the
 * compiled-in VW_UPDATE_MANIFEST_PUBKEY -> only then parse the bytes as
 * JSON -> rollback check against the ratchet persisted in
 * {state_dir}/daemon.conf.
 *
 * state_dir: the daemon's state directory (same one vw_daemon_cfg_load
 * uses) — needed to read/persist the sequence-number rollback ratchet.
 * Not part of the original design sketch's signature (which omitted any
 * way to locate daemon.conf); added because the function cannot do its
 * rollback-ratchet job without it.
 *
 * Returns VW_OK with *out populated on success.
 * Returns VW_ERR_UPDATE_NET on any fetch failure.
 * Returns VW_ERR_UPDATE_MANIFEST_INVALID if the signature doesn't verify,
 * or the (already-verified) bytes don't match the fixed schema.
 * Returns VW_ERR_UPDATE_MANIFEST_ROLLBACK if the manifest is validly
 * signed but its sequence number is below the locally persisted ratchet —
 * a replay/downgrade attempt. The ratchet is NOT advanced in this case.
 */
vw_err_t vw_update_manifest_fetch_and_verify(const char *state_dir,
                                              vw_update_manifest_t *out);

/*
 * Parses already-verified manifest bytes against the fixed schema (see
 * vw_update_manifest.c's header comment for why this is a hand-rolled
 * parser, not a general JSON library). Exposed publicly — separate from
 * vw_update_manifest_fetch_and_verify() — so tests/fuzz/fuzz_update_manifest.c
 * can exercise the parser in isolation from the network fetch it's
 * normally paired with; it performs NO signature verification itself and
 * must never be called on bytes that haven't already been verified by the
 * real pipeline above. Returns VW_ERR_UPDATE_MANIFEST_INVALID on any
 * malformed or schema-mismatched input; never crashes on arbitrary bytes.
 */
vw_err_t vw_update_manifest_parse(const char *data, size_t len,
                                   vw_update_manifest_t *out);

#ifdef __cplusplus
}
#endif

#endif /* VW_UPDATE_MANIFEST_H */
