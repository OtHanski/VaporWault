#ifndef VW_STORE_H
#define VW_STORE_H

/*
 * vw_store — flat-file storage engine for users and sessions (Phase 1).
 *
 * Storage files live under {data_dir}/store/:
 *   users.dat    — array of vw_user_record_t (256 bytes/slot)
 *   sessions.dat — array of vw_session_record_t (128 bytes/slot)
 *
 * A slot with user_id == 0 is free in users.dat.
 * A slot with is_active == 0 is free in sessions.dat.
 * In-memory hash indexes are rebuilt by scanning the .dat files on open.
 *
 * All functions are thread-safe. Users and sessions each have a separate
 * rwlock; readers hold shared, writers hold exclusive.
 */

#include "../core/vw_proto.h"
#include "vw_oplog.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Record types ────────────────────────────────────────────────────────── */

/*
 * On-disk user record. Exactly 256 bytes; _Static_assert enforced.
 * All fields are little-endian on disk (identical to native on x86-64/ARM64).
 * user_id == 0 marks a free slot.
 *
 * SECURITY: password_hash and password_salt are sensitive. Every
 * vw_store_user_get_* function zeroes both fields in the returned copy
 * before returning. vw_auth must read the raw file bytes directly (via its
 * own pread, not via this public API) for credential verification.
 */
typedef struct {
    uint64_t user_id;           /* monotonic, 1-based; 0 = free slot          */
    uint8_t  username[64];      /* UTF-8, NUL-padded; max VW_MAX_USERNAME_BYTES */
    uint8_t  email[128];        /* UTF-8, NUL-padded; max 128 bytes on disk   */
    uint8_t  password_hash[32]; /* Argon2id output — NEVER log or return      */
    uint8_t  password_salt[16]; /* Argon2id salt   — NEVER log or return      */
    uint8_t  is_admin;
    uint8_t  is_active;
    uint8_t  otp_enabled;
    uint8_t  _pad1;             /* reserved; must be zero on write             */
    uint32_t admin_caps;        /* vw_admin_cap_t bitmask (TASK-092); only
                                  * meaningful when is_admin == 1. Was
                                  * _pad[5] — offset 252 is still 4-byte
                                  * aligned after splitting off _pad1, so this
                                  * is layout-compatible with any record
                                  * already on disk (reads back as 0, which
                                  * vw_admin_has_cap() below treats as "full
                                  * capabilities" for backward compatibility —
                                  * see vw_admin_cap_t's comment in vw_proto.h). */
} vw_user_record_t;

_Static_assert(sizeof(vw_user_record_t) == 256,
               "vw_user_record_t must be exactly 256 bytes");

/*
 * Returns non-zero if this user record has the given admin capability.
 * Always false if is_admin == 0. admin_caps == 0 on an admin record is
 * treated as VW_CAP_ALL (see the field comment above and vw_admin_cap_t in
 * vw_proto.h) — callers must use this helper rather than testing
 * `rec->admin_caps & cap` directly, or they will incorrectly deny every
 * pre-TASK-092 admin account every capability.
 */
static inline int vw_admin_has_cap(const vw_user_record_t *rec, vw_admin_cap_t cap)
{
    if (!rec || !rec->is_admin) return 0;
    uint32_t caps = rec->admin_caps ? rec->admin_caps : (uint32_t)VW_CAP_ALL;
    return (caps & (uint32_t)cap) != 0;
}

/*
 * On-disk session record. Exactly 128 bytes; _Static_assert enforced.
 * is_active == 0 marks a free slot.
 * token is sensitive — NEVER log it.
 */
typedef struct {
    uint8_t  token[32];       /* random session token — NEVER log             */
    uint64_t user_id;
    uint64_t created_at;      /* Unix timestamp                               */
    uint64_t expires_at;      /* Unix timestamp; 0 = never                    */
    uint8_t  is_active;       /* 0 = free / logged-out                        */
    uint8_t  awaiting_otp;    /* 1 = password OK, OTP not yet verified        */
    uint8_t  _pad_align[6];   /* reserved; must be zero on write — was part of
                                * the original _pad[70]; kept here (rather
                                * than eliminated) so scope_share_id below
                                * lands on an 8-byte-aligned offset without
                                * relying on struct packing, and so every
                                * field at/before this point keeps its
                                * original byte offset unchanged. */
    uint64_t scope_share_id;  /* TASK-094: 0 = normal session; non-zero = a
                                * scoped session created via LINK_ACCESS,
                                * bound to this vw_share_record_t. user_id
                                * == 0 for every scoped session (anonymous).
                                * Deliberately the share_id, not a denormalized
                                * copy of its file_id/permission — every
                                * scoped-session check re-reads the live share
                                * record via this id, which is what makes
                                * live revocation (a revoked/expired share
                                * immediately blocking an already-issued
                                * session) automatic rather than a separate
                                * mechanism to keep in sync. Was part of
                                * _pad[70] — reusing always-zero reserved
                                * bytes, same precedent as TASK-090's
                                * deleted_at reuse in vw_file_record_t. A
                                * pre-existing session record predating this
                                * field reads back scope_share_id == 0,
                                * correctly behaving as a normal session. */
    uint8_t  _pad[56];        /* reserved; must be zero on write              */
} vw_session_record_t;

_Static_assert(sizeof(vw_session_record_t) == 128,
               "vw_session_record_t must be exactly 128 bytes");

/* ── File entry type constants ───────────────────────────────────────────── */

#define VW_ENTRY_FILE ((uint8_t)0)
#define VW_ENTRY_DIR  ((uint8_t)1)

/*
 * On-disk file metadata record. Exactly 128 bytes; _Static_assert enforced.
 * file_id == 0 marks a free slot. deleted == 1 marks soft-deleted (GC pending).
 * name is the leaf filename component only (not full path), NUL-padded.
 */
typedef struct {
    uint64_t file_id;             /* monotonic, 1-based; 0 = free slot           */
    uint64_t owner_id;            /* user_id from vw_user_record_t               */
    uint64_t parent_dir_id;       /* 0 = root; non-zero = parent directory       */
    uint64_t current_version_id;  /* version_id of HEAD; 0 = no version yet      */
    uint64_t size_bytes;          /* size of HEAD version in bytes               */
    int64_t  mtime_unix;          /* Unix timestamp of HEAD version creation      */
    uint8_t  entry_type;          /* VW_ENTRY_FILE or VW_ENTRY_DIR               */
    uint8_t  deleted;             /* 1 = soft-deleted (GC pending)               */
    uint8_t  _pad[6];
    char     name[64];            /* leaf filename, UTF-8, NUL-padded            */
    int64_t  deleted_at;          /* Unix timestamp of soft-delete; 0 = unset.
                                    * Was _reserved[8] — same size, layout-compatible
                                    * with records written before this field existed
                                    * (deleted_at reads back as 0 for those; GC treats
                                    * 0 as "immediately eligible", matching the old
                                    * no-retention-window behavior for them). */
} vw_file_record_t;

_Static_assert(sizeof(vw_file_record_t) == 128,
               "vw_file_record_t must be exactly 128 bytes");

/*
 * On-disk version record. Exactly 80 bytes; _Static_assert enforced.
 * version_id == 0 marks a free slot.
 * chunk_count * VW_HASH_BYTES of SHA-256 hashes live in versions.blob at blob_offset.
 *
 * TASK-098 (E2EE, docs/PROTOCOL.md §7.11): the former `_reserved[32]` is
 * repurposed below to carry a vault-encrypted version's vault_id and a
 * reference to its wrapped DEK, stored in the same versions.blob area used
 * for chunk hashes (mirroring that existing pattern rather than growing the
 * fixed-size record). A version record written before this field existed —
 * or any version of a file never opted into a vault — reads back with
 * vault_id == 0 for free, since old records' trailing bytes were always
 * written as zero (see handle_file_commit/vw_store_version_create) and
 * memset(w._reserved, 0, ...) already zeroed this exact byte range on every
 * write; no migration needed. wrapped_dek_offset/_len are meaningless
 * (and always 0) whenever vault_id == 0.
 */
typedef struct {
    uint64_t version_id;     /* monotonic, 1-based; 0 = free slot               */
    uint64_t file_id;        /* owning file                                     */
    uint64_t created_at;     /* Unix timestamp                                  */
    uint64_t size_bytes;     /* total file size (sum of chunk sizes)            */
    uint32_t chunk_count;    /* number of 4 MiB chunks                          */
    uint32_t _pad;
    uint64_t blob_offset;    /* byte offset in versions.blob where hashes start */
    uint64_t vault_id;           /* 0 = not encrypted (was _reserved[0:8])      */
    uint64_t wrapped_dek_offset; /* versions.blob offset of the wrapped DEK bytes,
                                   * placed immediately after this version's chunk
                                   * hashes (was _reserved[8:16])                */
    uint32_t wrapped_dek_len;    /* byte length; 0 if vault_id == 0 (was _reserved[16:20]) */
    uint8_t  _reserved[12];      /* still reserved (was _reserved[20:32])       */
} vw_version_record_t;

_Static_assert(sizeof(vw_version_record_t) == 80,
               "vw_version_record_t must be exactly 80 bytes");

/*
 * On-disk quota record. Exactly 32 bytes; _Static_assert enforced.
 * user_id == 0 marks a free slot. quota_bytes == 0 means unlimited.
 * Lives in {data_dir}/store/quotas.db.
 */
typedef struct {
    uint64_t user_id;      /* 0 = free slot                            */
    uint64_t quota_bytes;  /* hard limit in bytes; 0 = unlimited       */
    uint64_t used_bytes;   /* currently consumed (sum of chunk sizes)  */
    uint8_t  _reserved[8];
} vw_quota_record_t;

_Static_assert(sizeof(vw_quota_record_t) == 32,
               "vw_quota_record_t must be 32 bytes");

/*
 * On-disk notification-preferences record (TASK-205/206/207). Exactly 16
 * bytes; _Static_assert enforced. user_id == 0 marks a free slot.
 * prefs_bitmask == 0 (every category off) is both the default and what a
 * user who never called NOTIFY_PREFS_SET reads back as.
 * Lives in {data_dir}/store/notify_prefs.db.
 *
 * A separate side table rather than a vw_user_record_t field for the same
 * reason quota accounting already lives in quotas.db rather than in
 * vw_user_record_t: that record is exactly 256 bytes with zero spare
 * padding (see admin_caps's own field comment above).
 *
 * Not part of TASK-172's hot-standby replication file-tag list
 * (docs/PROTOCOL.md §7.7) — a replica's copy of this file is always its
 * own fresh, empty-defaults instance. A `NOTIFY_PREFS_GET` served from a
 * fallback-connected replica therefore always reads back 0 (every
 * category off) regardless of the real value on the primary; filed as a
 * follow-up (see TASK-207's notes) rather than silently folded into this
 * task, since fixing it means extending the fixed, wire-documented 8-tag
 * table — a protocol change, PRT.04's call, not SRV.01's to make
 * unilaterally.
 */
typedef struct {
    uint64_t user_id;
    uint32_t prefs_bitmask;   /* VW_NOTIFY_* bits, src/core/vw_proto.h */
    uint8_t  _reserved[4];
} vw_notify_prefs_record_t;

_Static_assert(sizeof(vw_notify_prefs_record_t) == 16,
               "vw_notify_prefs_record_t must be 16 bytes");

/* ── Opaque context ──────────────────────────────────────────────────────── */

typedef struct vw_store vw_store_t;

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/*
 * Open or create the store under {data_dir}/store/.
 * Creates the directory and both .dat files if they do not exist.
 * Scans existing files and builds in-memory hash indexes.
 *
 * oplog must be an already-open context; vw_store does not take ownership
 * (caller closes it after vw_store_close).
 *
 * Returns VW_OK and sets *out_ctx on success.
 * Returns VW_ERR_IO on I/O failure; VW_ERR_OOM on allocation failure.
 */
vw_err_t vw_store_open(const char *data_dir, vw_oplog_t *oplog,
                        vw_store_t **out_ctx);

/*
 * Close and free the store. Safe to call with NULL.
 */
void vw_store_close(vw_store_t *ctx);

/*
 * TASK-172 (replica hot-standby data replication, docs/PROTOCOL.md §7.7):
 * rebuild `live`'s users/quotas/notify_prefs (TASK-220) in-memory
 * indexes from the CURRENT on-disk users.dat/quotas.db/notify_prefs.db
 * under data_dir, in place — for when a replica's sync pass has just
 * atomically replaced those files out from under an already-open,
 * already-in-use store context (never close/reopen `live` itself for
 * this: other threads already hold that exact pointer). sessions.dat is
 * never touched by this call (per §7.7's own "deliberately never synced
 * this way" — this store's session table is always this node's own
 * local sessions). On failure, `live` is left completely unchanged.
 */
vw_err_t vw_store_reload_users_and_quotas(vw_store_t *live, const char *data_dir);

/* ── Users ───────────────────────────────────────────────────────────────── */

/*
 * Create a new user. Assigns a monotonic user_id; record->user_id is ignored
 * on input. *out_user_id receives the assigned ID.
 *
 * Returns VW_ERR_ALREADY_EXISTS if record->username or record->email
 * already belongs to an existing user.
 * Uses oplog two-phase commit: append → pwrite → sync → confirm.
 */
vw_err_t vw_store_user_create(vw_store_t *ctx,
                               const vw_user_record_t *record,
                               uint64_t *out_user_id);

/*
 * Look up a user by ID. *out_record is populated on success.
 * password_hash and password_salt are zeroed in the returned copy.
 * Returns VW_ERR_NOT_FOUND if no active user has that ID.
 */
vw_err_t vw_store_user_get_by_id(vw_store_t *ctx,
                                  uint64_t user_id,
                                  vw_user_record_t *out_record);

/*
 * Look up a user by NUL-terminated username.
 * password_hash and password_salt are zeroed in the returned copy.
 * Returns VW_ERR_NOT_FOUND if not found.
 */
vw_err_t vw_store_user_get_by_username(vw_store_t *ctx,
                                        const char *username,
                                        vw_user_record_t *out_record);

/*
 * Look up a user by NUL-terminated email.
 * password_hash and password_salt are zeroed in the returned copy.
 * Returns VW_ERR_NOT_FOUND if not found.
 */
vw_err_t vw_store_user_get_by_email(vw_store_t *ctx,
                                     const char *email,
                                     vw_user_record_t *out_record);

/*
 * Update a single field within an existing user record via in-place pwrite.
 * field_offset is the byte offset of the field within vw_user_record_t.
 *
 * Do NOT use for the username or email fields — those require index
 * updates this raw pwrite does not perform. Use only for is_active,
 * otp_enabled, etc. Email now has its own dedicated setter, below
 * (TASK-222) — username still has no post-creation setter of any kind.
 *
 * Returns VW_ERR_INVALID_ARG if field_offset + len > 256.
 * Returns VW_ERR_NOT_FOUND if user_id does not exist.
 * Uses oplog two-phase commit.
 */
vw_err_t vw_store_user_update_field(vw_store_t *ctx,
                                     uint64_t user_id,
                                     uint32_t field_offset,
                                     const void *data, size_t len);

/*
 * Conservative allow-list check for an address before it is ever persisted
 * into vw_user_record_t.email (TASK-222). This is the sole gate on what
 * can reach vw_smtp.c's "RCPT TO:<%s>"/"MAIL FROM:<%s>" interpolation
 * (vw_smtp_send) — that call site does no escaping of its own, so an
 * email containing CR/LF or other SMTP-command-meaningful bytes would be
 * command injection into the outbound relay session. Deliberately
 * stricter than full RFC 5322: exactly one '@', a non-empty local part
 * and a non-empty domain part containing at least one '.', and every
 * byte restricted to a safe allow-list — no whitespace, no control
 * characters, nothing that could confuse SMTP command parsing.
 *
 * email need not be NUL-terminated; len is the exact byte count to check
 * (as read off the wire, before any local NUL-terminated copy is made).
 * Returns VW_OK if safe to store, VW_ERR_INVALID_ARG otherwise.
 */
vw_err_t vw_email_validate(const char *email, size_t len);

/*
 * Set (or change) a user's email address — the first, and as of TASK-222
 * the only, real path that can put a non-empty email on an account
 * (neither USER_CREATE_REQ nor INVITE_REDEEM carry one). Unlike
 * vw_store_user_update_field, this correctly maintains the email_ht
 * uniqueness index: the old address (if any) is evicted before the new
 * one is inserted, so a stale mapping never lingers and shadows a later
 * vw_store_user_get_by_email lookup.
 *
 * Does NOT itself call vw_email_validate — callers (the ACCOUNT_EMAIL_SET
 * handler) must validate before calling this, so this function stays a
 * generic "persist this byte string as the email field + fix up the
 * index" primitive, consistent with every other vw_store_* setter never
 * re-deriving policy its caller already enforced.
 *
 * email may be "" (empty) to clear a user's email back to unset.
 * Returns VW_ERR_INVALID_ARG if len > 128. Returns VW_ERR_ALREADY_EXISTS
 * if a *different* user already owns this exact non-empty email.
 * Returns VW_OK (a no-op) if email already matches the caller's current
 * value. Returns VW_ERR_NOT_FOUND if user_id does not exist.
 * Uses oplog two-phase commit.
 */
vw_err_t vw_store_user_set_email(vw_store_t *ctx,
                                  uint64_t user_id,
                                  const char *email);

/*
 * Invoke callback for every active user slot, in user_id order.
 * callback return value: 0 = continue, non-zero = stop iteration.
 * password_hash and password_salt are zeroed in the record passed to callback.
 * Returns VW_OK or VW_ERR_IO (disk read error).
 */
vw_err_t vw_store_user_scan(vw_store_t *ctx,
                              int (*callback)(const vw_user_record_t *rec, void *ud),
                              void *userdata);

/* ── Sessions ────────────────────────────────────────────────────────────── */

/*
 * Create a new session. A random 32-byte token is generated internally;
 * record->token is ignored on input. out_token[32] receives the token.
 *
 * Uses oplog two-phase commit.
 */
vw_err_t vw_store_session_create(vw_store_t *ctx,
                                  const vw_session_record_t *record,
                                  uint8_t out_token[32]);

/*
 * Look up a session by token[32]. Checks is_active and expires_at against
 * the current time. *out_record is populated on success.
 *
 * Returns VW_ERR_NOT_FOUND if no matching active, unexpired session exists.
 */
vw_err_t vw_store_session_get(vw_store_t *ctx,
                               const uint8_t token[32],
                               vw_session_record_t *out_record);

/*
 * Deactivate a session (logout / expiry). Sets is_active=0 on disk and
 * removes the token from the in-memory index.
 *
 * Returns VW_ERR_NOT_FOUND if no matching active session exists.
 */
vw_err_t vw_store_session_delete(vw_store_t *ctx, const uint8_t token[32]);

/* ── File metadata store (Phase 2) ──────────────────────────────────────── */

/*
 * Opaque file/version table context. Separate from the user/session store.
 * Data files live under {data_dir}/files/:
 *   meta.dat       — array of vw_file_record_t (128 bytes/slot)
 *   versions.dat   — array of vw_version_record_t (80 bytes/slot)
 *   versions.blob  — chunk hash arrays (variable length, addressed by blob_offset)
 *
 * Thread safety: files and versions each have a separate rwlock.
 */
typedef struct vw_file_store vw_file_store_t;

/*
 * Open or create the file metadata store under {data_dir}/files/.
 * Creates the directory and all data files if they do not exist.
 * Scans existing records and builds in-memory indexes.
 * oplog is borrowed — caller closes it after vw_file_store_close.
 */
vw_err_t vw_file_store_open(const char *data_dir, vw_oplog_t *oplog,
                             vw_file_store_t **out);

/* Close and free the file store. Safe to call with NULL. */
void vw_file_store_close(vw_file_store_t *fs);

/*
 * TASK-172 (replica hot-standby data replication, docs/PROTOCOL.md §7.7):
 * rebuild `live`'s in-memory indexes (path_ht/fid_to_slot from meta.dat;
 * vid_to_slot/blob_size from versions.dat) from the CURRENT on-disk files
 * under data_dir, in place — never close/reopen `live` itself (other
 * threads already hold that exact pointer). Always covers both meta.dat
 * and versions.dat together since a sync pass always fetches/applies
 * versions.dat and versions.blob as a pair. On failure, `live` is left
 * completely unchanged.
 */
vw_err_t vw_file_store_reload_meta_and_versions(vw_file_store_t *live,
                                                 const char *data_dir);

/* ── File CRUD ───────────────────────────────────────────────────────────── */

/*
 * Create a new file or directory record.
 * rec->file_id is ignored; *out_file_id receives the assigned monotonic ID.
 * Returns VW_ERR_ALREADY_EXISTS if a non-deleted record with the same
 * owner_id, parent_dir_id, and name already exists.
 */
vw_err_t vw_store_file_create(vw_file_store_t *fs,
                               const vw_file_record_t *rec,
                               uint64_t *out_file_id);

/*
 * Fetch a record by file_id.
 * Returns VW_ERR_NOT_FOUND if the slot is free or deleted.
 */
vw_err_t vw_store_file_get_by_id(vw_file_store_t *fs,
                                  uint64_t file_id,
                                  vw_file_record_t *out);

/*
 * Look up a file by its full virtual path under the given owner.
 * path must be NUL-terminated and absolute (starts with '/').
 * Walks path components via the in-memory name index.
 * Returns VW_ERR_NOT_FOUND if path does not exist for this owner.
 * SECURITY: does not enforce cross-user access beyond owner_id match;
 * callers must check the returned record's owner_id before sending on wire.
 */
vw_err_t vw_store_file_get_by_path(vw_file_store_t *fs,
                                    uint64_t owner_id,
                                    const char *path,
                                    vw_file_record_t *out);

/*
 * Replace an existing record in-place (write new data over the same slot,
 * under oplog two-phase commit). Returns VW_ERR_NOT_FOUND if absent.
 */
vw_err_t vw_store_file_update(vw_file_store_t *fs,
                               uint64_t file_id,
                               const vw_file_record_t *new_rec);

/*
 * Soft-delete: sets deleted=1 and deleted_at=now on the record. The file
 * stays recoverable via vw_store_file_restore until the GC trash-retention
 * window elapses (vw_gc_cfg_t.trash_retention_secs), after which pass 3
 * hard-deletes it and decrements chunk refs.
 * Returns VW_ERR_NOT_FOUND if absent or already deleted.
 */
vw_err_t vw_store_file_soft_delete(vw_file_store_t *fs, uint64_t file_id);

/*
 * Restore a soft-deleted file: clears deleted/deleted_at, making it visible
 * again via the normal lookup/list functions. Must be called before the GC
 * retention window elapses and the file is hard-deleted.
 * Returns VW_ERR_NOT_FOUND if file_id doesn't exist at all; VW_ERR_INVALID_ARG
 * if it exists but isn't currently deleted.
 */
vw_err_t vw_store_file_restore(vw_file_store_t *fs, uint64_t file_id);

/*
 * List all non-deleted records under a directory (shallow, one level).
 * parent_dir_id == 0 lists the root. Returns a malloc'd array; caller frees.
 * *out_count may be 0. Returns VW_ERR_OOM on allocation failure.
 */
vw_err_t vw_store_file_list(vw_file_store_t *fs,
                             uint64_t owner_id,
                             uint64_t parent_dir_id,
                             vw_file_record_t **out_records,
                             uint32_t *out_count);

/* ── Version CRUD ────────────────────────────────────────────────────────── */

/*
 * Create a version record and append its chunk hashes to versions.blob.
 * rec->version_id, rec->blob_offset, rec->wrapped_dek_offset are ignored on
 * input (server-computed). chunk_hashes: rec->chunk_count * VW_HASH_BYTES of
 * ordered SHA-256 hashes. Caller must have incremented ref-counts (via
 * vw_storage_chunk_put) for every hash before calling this — ref-count must
 * be >= 1 before commit.
 *
 * wrapped_dek/wrapped_dek_len (TASK-098): opaque bytes appended to
 * versions.blob immediately after this version's chunk hashes; this
 * function sets rec->wrapped_dek_offset itself. Pass NULL/0 for an
 * unencrypted version (rec->vault_id must then also be 0 — this function
 * does not cross-check that; the caller, handle_file_commit, already
 * validated vault_id against a real vault before calling here).
 */
vw_err_t vw_store_version_create(vw_file_store_t *fs,
                                  const vw_version_record_t *rec,
                                  const uint8_t *chunk_hashes,
                                  const uint8_t *wrapped_dek, uint32_t wrapped_dek_len,
                                  uint64_t *out_version_id);

/* Fetch a version record by version_id. Returns VW_ERR_NOT_FOUND if absent. */
vw_err_t vw_store_version_get(vw_file_store_t *fs,
                               uint64_t version_id,
                               vw_version_record_t *out);

/*
 * Read the ordered chunk SHA-256 hashes for a version.
 * *out_hashes receives a malloc'd buffer of ver->chunk_count * VW_HASH_BYTES.
 * Caller frees *out_hashes.
 */
vw_err_t vw_store_version_get_chunks(vw_file_store_t *fs,
                                      const vw_version_record_t *ver,
                                      uint8_t **out_hashes);

/*
 * TASK-098 (E2EE): read a version's wrapped DEK. *out_wrapped_dek receives
 * a malloc'd buffer of ver->wrapped_dek_len bytes, or NULL if
 * ver->vault_id == 0 (unencrypted — not an error). Caller frees a non-NULL
 * result.
 */
vw_err_t vw_store_version_get_wrapped_dek(vw_file_store_t *fs,
                                           const vw_version_record_t *ver,
                                           uint8_t **out_wrapped_dek);

/*
 * List all versions for a file, sorted by version_id ascending.
 * Returns a malloc'd array; caller frees. *out_count may be 0.
 */
vw_err_t vw_store_version_list(vw_file_store_t *fs,
                                uint64_t file_id,
                                vw_version_record_t **out_records,
                                uint32_t *out_count);

/*
 * TASK-00277 (VAULT_DELETE safety check): does any version record — across
 * every file, current or superseded — still reference vault_id? Full-table
 * scan of versions.db, same accepted O(n) tradeoff already on record for
 * vw_share_scan/vw_vault_scan at this project's scale. Used by
 * handle_vault_delete to refuse deleting a vault that would strand a
 * still-referenced wrapped DEK.
 */
vw_err_t vw_store_version_vault_in_use(vw_file_store_t *fs, uint64_t vault_id,
                                        int *out_in_use);

/* ── Quota management (Phase 3) ──────────────────────────────────────────── */

/*
 * Get the quota record for user_id. Returns VW_ERR_NOT_FOUND if no quota
 * record exists (meaning: quota = unlimited, used_bytes = 0).
 */
vw_err_t vw_store_quota_get(vw_store_t *ctx, uint64_t user_id,
                              vw_quota_record_t *out);

/*
 * Set or replace the quota for a user. Creates a new record if absent;
 * updates in-place if present. Flushes to disk before returning.
 */
vw_err_t vw_store_quota_set(vw_store_t *ctx, uint64_t user_id,
                              uint64_t quota_bytes);

/*
 * Atomically add delta to used_bytes (exclusive quota_lock held throughout).
 *
 *   delta > 0 (upload): checks used_bytes + delta <= quota_bytes when
 *   quota_bytes != 0. Returns VW_ERR_QUOTA_EXCEEDED if the limit would be
 *   exceeded. On success increments used_bytes and persists the record.
 *
 *   delta < 0 (GC/delete): decrements used_bytes, clamping to 0.
 *
 * Creates a free-unlimited record if no quota record exists yet.
 */
vw_err_t vw_store_quota_add(vw_store_t *ctx, uint64_t user_id, int64_t delta);

/*
 * Callback invoked after every successful vw_store_quota_add (both
 * directions — increase and decrease), reporting the user's current
 * used_bytes/quota_bytes (quota_bytes == 0 means unlimited). Invoked
 * outside vw_store's own lock.
 *
 * TASK-207: lets vw_notify.c detect a quota_warning threshold
 * crossing (and re-arm once usage drops back under it) without vw_store
 * depending on vw_notify/vw_smtp at link time — same opaque-callback
 * idiom vw_store_user_scan already uses elsewhere in this header. The
 * edge-trigger/debounce decision itself lives entirely in the hook's own
 * implementation; vw_store only ever reports the raw current numbers.
 */
typedef void (*vw_store_quota_hook_fn)(void *userdata, uint64_t user_id,
                                        uint64_t used_bytes, uint64_t quota_bytes);

/*
 * Register (or, passing hook=NULL, clear) the quota hook. Only one hook
 * may be registered at a time; a second call replaces the first.
 */
void vw_store_set_quota_hook(vw_store_t *ctx, vw_store_quota_hook_fn hook,
                              void *userdata);

/* ── Notification preferences (TASK-205/206/207) ─────────────────────────── */

/*
 * Fetch user_id's notification preference bitmask. Unlike
 * vw_store_quota_get, never returns VW_ERR_NOT_FOUND for "no record yet" —
 * an account that has never called vw_store_notify_prefs_set reads back
 * VW_OK with *out_prefs == 0 (every category off), matching TASK-205's
 * "default off everywhere" requirement without every caller needing its
 * own NOT_FOUND-means-default special case.
 */
vw_err_t vw_store_notify_prefs_get(vw_store_t *ctx, uint64_t user_id,
                                     uint32_t *out_prefs);

/*
 * Replace user_id's complete notification preference bitmask. Creates a
 * new record if absent; updates in place if present. Flushes to disk
 * before returning. Does not validate individual bits — the
 * NOTIFY_PREFS_SET wire handler (vw_server_core.c) rejects any reserved
 * bit with VW_ERR_INVALID_ARG before ever calling this.
 */
vw_err_t vw_store_notify_prefs_set(vw_store_t *ctx, uint64_t user_id,
                                     uint32_t prefs);

/* ── File GC helpers (used by vw_gc) ─────────────────────────────────────── */

/*
 * Iterate all file slots where deleted == 1. Holds a read lock for the entire
 * scan; the callback must NOT acquire any vw_file_store lock.
 * callback return value: 0 = continue, non-zero = stop iteration.
 * Individual slot pread failures are skipped silently (best-effort).
 * Always returns VW_OK.
 */
vw_err_t vw_store_file_scan_deleted(vw_file_store_t *fs,
                                     int (*cb)(const vw_file_record_t *, void *),
                                     void *userdata);

/*
 * TASK-198: iterate all live (non-deleted) file slots — the counterpart scan
 * to vw_store_file_scan_deleted, used by SEARCH (docs/PROTOCOL.md §7.12)
 * since there is no owner_id-indexed enumeration to walk instead. Same
 * locking/callback contract as vw_store_file_scan_deleted above.
 */
vw_err_t vw_store_file_scan_all(vw_file_store_t *fs,
                                 int (*cb)(const vw_file_record_t *, void *),
                                 void *userdata);

/*
 * Permanently remove a file record: zeroes the slot in meta.dat and clears
 * the entry in fid_to_slot. Does NOT remove the path_ht entry — soft-deleted
 * files are already invisible to path lookups (path_ht skips deleted records).
 * Blob space is not compacted. Caller must have already deref'd all chunks
 * and hard-deleted all version records for this file.
 * Returns VW_ERR_NOT_FOUND if file_id is absent from the in-memory index.
 */
vw_err_t vw_store_file_hard_delete(vw_file_store_t *fs, uint64_t file_id);

/*
 * Permanently remove a version record: zeroes the slot in versions.dat and
 * clears the entry in vid_to_slot. Blob space is NOT reclaimed (append-only).
 * Returns VW_ERR_NOT_FOUND if version_id is absent from the in-memory index.
 */
vw_err_t vw_store_version_hard_delete(vw_file_store_t *fs, uint64_t version_id);

/* ── Session GC helpers ───────────────────────────────────────────────────── */

/*
 * Scan all session slots and deactivate those where:
 *   is_active == 1  &&  expires_at != 0  &&  expires_at <= now_unix
 *
 * For each expired slot: writes is_active=0 via pwrite, removes the token from
 * the in-memory index, pushes the slot onto the session free list.  A single
 * fdatasync is issued after all per-slot pwrite calls.
 *
 * *out_count (may be NULL) receives the number of sessions expired.
 * Holds the sessions write lock for the entire scan.
 * Returns VW_OK or VW_ERR_IO (disk read error; no partial changes on error).
 */
vw_err_t vw_store_session_gc(vw_store_t *ctx, uint64_t now_unix,
                              uint32_t *out_count);

/*
 * Invalidate all active sessions belonging to user_id.
 * Used after a successful password reset to force re-authentication.
 * Writes is_active=0 for each matching session, syncs once, removes tokens
 * from the in-memory index, and pushes slots onto the free list.
 *
 * *out_count (may be NULL) receives the number of sessions revoked.
 * Holds the sessions write lock for the entire scan.
 * Returns VW_OK or VW_ERR_IO.
 */
vw_err_t vw_store_sessions_revoke_by_user(vw_store_t *ctx, uint64_t user_id,
                                           uint32_t *out_count);

/* ── Auth-only credential access ─────────────────────────────────────────── */

/*
 * Retrieve the raw password_hash and password_salt for a user by ID.
 *
 * SECURITY: This is the sole vw_store function that returns sensitive
 * credential fields. It exists exclusively for vw_auth password verification.
 * All other user-fetch functions zero these fields before returning.
 *
 * Returns VW_ERR_NOT_FOUND if the user does not exist or the slot is free.
 */
vw_err_t vw_store_user_get_credentials(vw_store_t *ctx, uint64_t user_id,
                                        uint8_t out_hash[32],
                                        uint8_t out_salt[16]);

#ifdef __cplusplus
}
#endif

#endif /* VW_STORE_H */
