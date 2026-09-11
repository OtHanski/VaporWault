#ifndef VW_VAULT_H
#define VW_VAULT_H

/*
 * vw_vault — E2EE vault storage (TASK-098; design in docs/PROTOCOL.md §7.11).
 *
 * The server's role is deliberately narrow: store opaque key-wrapping blobs
 * and treat encrypted chunk content exactly like any other chunk. No content
 * decryption or key material ever exists server-side — every variable-length
 * field this module stores (wrapped_vk, kdf_params) is client-chosen opaque
 * bytes; the server never parses or validates their content, only their
 * size against a generous ceiling.
 *
 * Storage: {data_dir}/vaults/vaults.db (fixed-size vw_vault_record_t, 96
 * bytes/slot, slot 0 = guard) + {data_dir}/vaults/vaults.blob (wrapped_vk
 * bytes immediately followed by kdf_params bytes per vault, referenced by
 * blob_offset/wrapped_vk_len/kdf_params_len) — same fixed-record +
 * append-only-blob pattern as vw_store_files.c's versions.db/versions.blob.
 *
 * In-memory index rebuilt by scanning on open: vault_id -> slot (direct
 * array, like vw_store_files.c's fid_to_slot). No owner_id index —
 * VAULT_LIST goes through vw_vault_scan(), a full O(total vaults) scan per
 * call, same tradeoff already made for vw_share_scan() at this project's
 * scale.
 */

#include "../core/vw_proto.h"
#include "vw_oplog.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Record ──────────────────────────────────────────────────────────────── */

typedef struct {
    uint64_t vault_id;         /* monotonic, 1-based; 0 = free slot            */
    uint64_t owner_id;
    uint64_t folder_file_id;   /* the folder or file opted into encryption     */
    int64_t  created_at;
    uint64_t blob_offset;      /* vaults.blob: wrapped_vk bytes then kdf_params */
    uint32_t wrapped_vk_len;
    uint32_t kdf_params_len;
    uint8_t  kdf_salt[16];     /* Argon2id salt; fixed size per §7.11.4         */
    uint8_t  deleted;          /* TASK-00277: soft-delete flag, same convention
                                 * as vw_share_record_t.revoked — a record whose
                                 * trailing bytes were always zero (every prior
                                 * write path memset the old _pad[32] to 0) reads
                                 * back deleted==0 for free, no migration needed */
    uint8_t  _pad[31];
} vw_vault_record_t;

_Static_assert(sizeof(vw_vault_record_t) == 96,
               "vw_vault_record_t must be exactly 96 bytes");

/* Generous ceilings — opaque client-chosen bytes, never parsed server-side;
 * these bound storage abuse, not content validity. */
#define VW_VAULT_MAX_WRAPPED_VK_BYTES  4096u
#define VW_VAULT_MAX_KDF_PARAMS_BYTES  256u

/* ── Opaque context ──────────────────────────────────────────────────────── */

typedef struct vw_vault_store vw_vault_store_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

vw_err_t vw_vault_store_open(const char *data_dir, vw_oplog_t *oplog,
                              vw_vault_store_t **out);
void vw_vault_store_close(vw_vault_store_t *vs);

/*
 * TASK-172 (replica hot-standby data replication, docs/PROTOCOL.md §7.7):
 * atomically replace `live`'s in-memory vaults.db contents (vid_to_slot and
 * every derived field) with a freshly-parsed read of data_dir's current
 * on-disk vaults.db/vaults.blob, without invalidating any pointer already
 * held by other threads. Builds a scratch vw_vault_store_t via
 * vw_vault_store_open, steals its fields under live->lock, then discards
 * the gutted scratch.
 */
vw_err_t vw_vault_store_reload(vw_vault_store_t *live, const char *data_dir);

/* ── CRUD ────────────────────────────────────────────────────────────────── */

/*
 * Register a new vault. wrapped_vk/kdf_params are stored as fully opaque
 * bytes — no parsing, no validation beyond the size ceilings above. Returns
 * VW_ERR_INVALID_ARG if either exceeds its ceiling or is empty, or if
 * owner_id/folder_file_id is 0.
 */
vw_err_t vw_vault_create(vw_vault_store_t *vs,
                          uint64_t owner_id, uint64_t folder_file_id,
                          const uint8_t *wrapped_vk, uint32_t wrapped_vk_len,
                          const uint8_t kdf_salt[16],
                          const uint8_t *kdf_params, uint32_t kdf_params_len,
                          uint64_t *out_vault_id);

/*
 * Fetch a vault record plus its blob contents. *out_wrapped_vk and
 * *out_kdf_params are malloc'd by this call; caller frees both that are
 * non-NULL. Returns VW_ERR_NOT_FOUND if vault_id doesn't exist.
 */
vw_err_t vw_vault_get_by_id(vw_vault_store_t *vs, uint64_t vault_id,
                             vw_vault_record_t *out_rec,
                             uint8_t **out_wrapped_vk, uint8_t **out_kdf_params);

/*
 * Scan every allocated vault record, including soft-deleted ones —
 * matching vw_share_scan's convention of returning everything and
 * letting the caller filter (CQR.08 API-consistency finding, TASK-00275
 * review pass), rather than vw_vault_scan silently deciding what counts
 * as "gone" on every caller's behalf. Check rec->deleted in the callback
 * if a caller wants live vaults only (handle_vault_list's vault_list_cb
 * does exactly this). callback returning non-zero stops the scan. Holds
 * a read lock for the entire scan; the callback must NOT call any other
 * vw_vault_store_t function. Does not fetch blob contents — call
 * vw_vault_get_by_id for those if the scan's caller needs them.
 */
vw_err_t vw_vault_scan(vw_vault_store_t *vs,
                        int (*callback)(const vw_vault_record_t *rec, void *ud),
                        void *userdata);

/*
 * Soft-delete a vault registration (TASK-00277). Only the vault's
 * owner_id may delete it: returns VW_ERR_PERMISSION otherwise, and
 * VW_ERR_NOT_FOUND if the vault doesn't exist or was already deleted.
 *
 * Does NOT check whether any file version still references this
 * vault_id — the caller (handle_vault_delete) must confirm the vault is
 * empty first via vw_store_version_vault_in_use(), the same cross-module
 * ordering handle_file_commit already uses to validate a vault_id against
 * a real vault before accepting a commit (vw_vault.c is deliberately kept
 * free of any vw_store_files.h dependency).
 *
 * Once deleted, vw_vault_get_by_id() returns VW_ERR_NOT_FOUND for this
 * vault_id and vw_vault_scan() no longer visits it — matching
 * vw_share_revoke's "revoked reads as gone" convention (vw_share.c).
 */
vw_err_t vw_vault_delete(vw_vault_store_t *vs, uint64_t vault_id,
                          uint64_t caller_user_id);

#ifdef __cplusplus
}
#endif

#endif /* VW_VAULT_H */
