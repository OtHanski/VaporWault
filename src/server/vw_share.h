#ifndef VW_SHARE_H
#define VW_SHARE_H

/*
 * vw_share — file/folder sharing store (TASK-094; design in docs/PROTOCOL.md §7.5).
 *
 * Two independent sharing mechanisms share one on-disk table:
 *   - User-to-user grants (share_type == VW_SHARE_TYPE_GRANT): target_user_id
 *     is the grantee; link_token is all-zero.
 *   - Public links (share_type == VW_SHARE_TYPE_LINK): target_user_id is 0;
 *     link_token is a 256-bit CSPRNG token, disclosed exactly once at
 *     creation (LINK_CREATE_ACK) and never re-displayed.
 *
 * Storage: {data_dir}/shares/shares.db — flat array of vw_share_record_t
 * (128 bytes/slot). Slot 0 is a guard (share_id == 0 == free). Rows are
 * never hard-deleted on revoke (revoked=1 instead), matching this
 * codebase's soft-delete convention (TASK-090) — kept for audit trail.
 *
 * In-memory indexes rebuilt by scanning on open:
 *   share_id -> slot        (direct array, like vw_store_files.c's fid_to_slot)
 *   link_token -> share_id  (open-addressed hash, like vw_invite.c's code index —
 *                            this is the hot O(1) path LINK_ACCESS needs)
 * There is deliberately no file_id-> or user_id-> index: permission
 * resolution (walking a file's ancestor chain) and SHARE_LIST/LINK_LIST
 * both go through vw_share_scan(), a full O(total shares) scan per call —
 * acceptable at Phase-8 scale, same tradeoff already made and flagged in
 * vw_file_handlers.c's check_chunk_ownership(). A real file_id index is a
 * candidate follow-up if this becomes a hot path at scale.
 */

#include "../core/vw_proto.h"
#include "vw_store.h"
#include "vw_oplog.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── share_type values ───────────────────────────────────────────────────── */

#define VW_SHARE_TYPE_GRANT ((uint8_t)0)
#define VW_SHARE_TYPE_LINK  ((uint8_t)1)

/* ── Record ──────────────────────────────────────────────────────────────── */

typedef struct {
    uint64_t share_id;         /* monotonic, 1-based; 0 = free slot            */
    uint64_t file_id;          /* the shared file or folder                    */
    uint64_t owner_id;         /* copied from file.owner_id at grant/link time */
    uint64_t target_user_id;   /* user grants only; 0 for public links         */
    uint8_t  link_token[32];   /* public links only; all-zero for user grants  */
    uint8_t  share_type;       /* VW_SHARE_TYPE_GRANT or VW_SHARE_TYPE_LINK     */
    uint8_t  permission;       /* vw_perm_t: VW_PERM_VIEW or VW_PERM_EDIT only  */
    uint8_t  revoked;          /* 1 = revoked; rows are never hard-deleted      */
    uint8_t  _pad1;
    uint8_t  _pad_align[4];    /* reserved; aligns created_at to an 8-byte offset */
    int64_t  created_at;
    int64_t  expires_at;       /* 0 = never expires                            */
    /* TASK-186: public links only. has_link_password==0 means
     * link_password_hash is meaningless (and, per this codebase's
     * reserved-bytes convention, actually all-zero — every record starts
     * from a memset(0) and this field is only ever written together with
     * has_link_password). No salt is stored — see docs/PROTOCOL.md §7.5's
     * share-record note for why (derived from link_token via HMAC-SHA256,
     * which already carries enough entropy/uniqueness that a stored salt
     * would add nothing but 16 bytes this record doesn't have to spare). */
    uint8_t  link_password_hash[32];
    uint8_t  has_link_password;
    uint8_t  _reserved[7];
} vw_share_record_t;

_Static_assert(sizeof(vw_share_record_t) == 128,
               "vw_share_record_t must be exactly 128 bytes");

/* ── Opaque context ──────────────────────────────────────────────────────── */

typedef struct vw_share_store vw_share_store_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

vw_err_t vw_share_store_open(const char *data_dir, vw_oplog_t *oplog,
                              vw_share_store_t **out);
void vw_share_store_close(vw_share_store_t *ss);

/*
 * TASK-172 (replica hot-standby data replication, docs/PROTOCOL.md §7.7):
 * atomically replace `live`'s in-memory shares.db contents (token_ht and
 * every derived field) with a freshly-parsed read of data_dir's current
 * on-disk shares.db, without invalidating any pointer already held by other
 * threads. Builds a scratch vw_share_store_t via vw_share_store_open, steals
 * its fields under live->lock, then discards the gutted scratch. Does not
 * touch live->rate_lock-guarded runtime rate-limit state (not persisted, not
 * part of the on-disk file being synced).
 */
vw_err_t vw_share_store_reload(vw_share_store_t *live, const char *data_dir);

/* ── CRUD ────────────────────────────────────────────────────────────────── */

/*
 * Create a user-to-user grant. Returns VW_ERR_INVALID_ARG if permission is
 * not VW_PERM_VIEW/VW_PERM_EDIT.
 */
vw_err_t vw_share_grant_create(vw_share_store_t *ss,
                                uint64_t file_id, uint64_t owner_id,
                                uint64_t target_user_id, vw_perm_t permission,
                                int64_t expires_at, uint64_t *out_share_id);

/*
 * Create a public link. out_link_token[32] receives the raw token — the
 * only time it is ever available in plaintext; the caller must relay it to
 * the client immediately (LINK_CREATE_ACK) and never persist or log it.
 *
 * password/password_len (TASK-186): optional — pass NULL/0 for no
 * password. When non-empty, hashed (Argon2id, salt derived from the
 * freshly-generated link_token) and stored; the raw password is never
 * persisted or logged, matching every other password-handling path in
 * this codebase.
 */
vw_err_t vw_share_link_create(vw_share_store_t *ss,
                               uint64_t file_id, uint64_t owner_id,
                               vw_perm_t permission, int64_t expires_at,
                               const void *password, size_t password_len,
                               uint8_t out_link_token[32],
                               uint64_t *out_share_id);

/*
 * Verify a candidate password against share's stored link password
 * (derives the Argon2id salt from share->link_token — see the record's
 * own doc comment). Returns:
 *   VW_OK                          — no password set, or a correct one given
 *   VW_ERR_LINK_PASSWORD_REQUIRED  — a password is set, none given
 *   VW_ERR_LINK_PASSWORD_WRONG     — a password is set, given one is wrong
 * password/password_len may be NULL/0 (treated as "none given").
 */
vw_err_t vw_share_link_verify_password(const vw_share_record_t *share,
                                        const void *password, size_t password_len);

/* Fetch by share_id. Returns VW_ERR_NOT_FOUND if absent (including a
 * revoked or expired row is still "found" — callers check revoked/expires_at
 * themselves; this mirrors vw_store_file_get_by_id, not vw_invite_claim). */
vw_err_t vw_share_get_by_id(vw_share_store_t *ss, uint64_t share_id,
                             vw_share_record_t *out);

/*
 * Fetch by link_token. Unlike vw_share_get_by_id, this DOES apply the
 * revoked/expired check internally (matching vw_invite_claim's convention
 * for the unauthenticated LINK_ACCESS path) — returns VW_ERR_NOT_FOUND for an
 * unknown, revoked, or expired token, indistinguishably (anti-enumeration).
 */
vw_err_t vw_share_get_by_token(vw_share_store_t *ss, const uint8_t token[32],
                                vw_share_record_t *out);

/*
 * Revoke a share/link. caller_user_id must equal the share's owner_id (the
 * file's owner at grant/link time) — returns VW_ERR_PERMISSION otherwise,
 * per the "only the creator can revoke" rule (§7.5). VW_ERR_NOT_FOUND if
 * share_id doesn't exist or is already revoked.
 */
vw_err_t vw_share_revoke(vw_share_store_t *ss, uint64_t share_id,
                          uint64_t caller_user_id);

/*
 * Scan every non-free slot (revoked or not — callers filter). callback
 * returning non-zero stops the scan. Holds a read lock for the entire scan;
 * the callback must NOT call any other vw_share_store_t function.
 */
vw_err_t vw_share_scan(vw_share_store_t *ss,
                        int (*callback)(const vw_share_record_t *rec, void *ud),
                        void *userdata);

/* ── Permission resolution ───────────────────────────────────────────────── */

/*
 * Resolve the caller's effective permission on file_id, per §7.5's ordered
 * rule (owner check is the caller's responsibility — this function only
 * covers rule 2 and 3: grants and scoped-session access):
 *
 *   2. An active grant whose target_user_id == caller_user_id and whose
 *      file_id is file_id itself or an ancestor of it (walking
 *      parent_dir_id up to the root via fs).
 *   3. If scope_share_id != 0: the scoped share/link itself, if its
 *      file_id is file_id itself or an ancestor of it — re-checked against
 *      the LIVE share record (revoked/expires_at), never cached, so a
 *      revoked share immediately stops granting access on the very next
 *      call. caller_user_id must be 0 when scope_share_id != 0 (anonymous
 *      scoped session) — callers must not pass both a real caller_user_id
 *      and a scope_share_id.
 *
 * Returns VW_PERM_NONE if neither applies (or on any lookup failure) —
 * callers combine this with their own owner_id == caller_user_id check.
 */
vw_perm_t vw_share_resolve_permission(vw_share_store_t *ss, vw_file_store_t *fs,
                                       uint64_t file_id,
                                       uint64_t caller_user_id,
                                       uint64_t scope_share_id);

/* ── Scoped-session write-count rate limit ──────────────────────────────── */

/*
 * TASK-094 (SEC.07 finding): per-scoped-session limit on write operations
 * (FILE_COMMIT, CHUNK_UPLOAD, FILE_DELETE, FILE_MOVE), independent of and in
 * addition to the byte-quota check — bounds the number of writes an
 * anonymous public-edit-link holder can perform, not just their bytes.
 * Call once per write attempt; returns VW_ERR_RATE_LIMITED once the
 * threshold is exceeded within the current window, VW_OK otherwise (and
 * records the attempt). Keyed by session token, not share_id, so distinct
 * holders of the same link get independent limits — token[32] uniquely
 * identifies the session with cryptographic-strength collision resistance
 * (vw_crypto_random), same trust assumption as every other session-token
 * use in this codebase.
 */
vw_err_t vw_share_scoped_write_ratelimit_check(vw_share_store_t *ss,
                                                const uint8_t token[32]);

/*
 * TASK-094 (SEC.07 finding): IP-based rate limit on failed LINK_ACCESS
 * attempts (unknown/revoked/expired token), mirroring the existing
 * NODE_HELLO pattern in vw_cluster.c (5 failures/60s -> silent drop).
 * Call vw_share_link_access_is_blocked before attempting to resolve the
 * token; call vw_share_link_access_record_failure after a failed lookup;
 * call vw_share_link_access_reset_on_success after a successful redemption.
 */
int vw_share_link_access_is_blocked(vw_share_store_t *ss, const char *ip);
void vw_share_link_access_record_failure(vw_share_store_t *ss, const char *ip);
void vw_share_link_access_reset_on_success(vw_share_store_t *ss, const char *ip);

#ifdef __cplusplus
}
#endif

#endif /* VW_SHARE_H */
