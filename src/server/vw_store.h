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
    uint8_t  _pad[5];           /* reserved; must be zero on write             */
} vw_user_record_t;

_Static_assert(sizeof(vw_user_record_t) == 256,
               "vw_user_record_t must be exactly 256 bytes");

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
    uint8_t  _pad[70];        /* reserved; must be zero on write              */
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
    uint8_t  _reserved[8];
} vw_file_record_t;

_Static_assert(sizeof(vw_file_record_t) == 128,
               "vw_file_record_t must be exactly 128 bytes");

/*
 * On-disk version record. Exactly 80 bytes; _Static_assert enforced.
 * version_id == 0 marks a free slot.
 * chunk_count * VW_HASH_BYTES of SHA-256 hashes live in versions.blob at blob_offset.
 */
typedef struct {
    uint64_t version_id;     /* monotonic, 1-based; 0 = free slot               */
    uint64_t file_id;        /* owning file                                     */
    uint64_t created_at;     /* Unix timestamp                                  */
    uint64_t size_bytes;     /* total file size (sum of chunk sizes)            */
    uint32_t chunk_count;    /* number of 4 MiB chunks                          */
    uint32_t _pad;
    uint64_t blob_offset;    /* byte offset in versions.blob where hashes start */
    uint8_t  _reserved[32];
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
 * Do NOT use for username or email fields — those require index updates and
 * are not supported in Phase 1. Use only for is_active, otp_enabled, etc.
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
 * Soft-delete: sets deleted=1 on the record. GC decrement chunk refs later.
 * Returns VW_ERR_NOT_FOUND if absent or already deleted.
 */
vw_err_t vw_store_file_soft_delete(vw_file_store_t *fs, uint64_t file_id);

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
 * rec->version_id and rec->blob_offset are ignored on input.
 * chunk_hashes: rec->chunk_count * VW_HASH_BYTES of ordered SHA-256 hashes.
 * Caller must have incremented ref-counts (via vw_storage_chunk_put) for every
 * hash before calling this — ref-count must be >= 1 before commit.
 */
vw_err_t vw_store_version_create(vw_file_store_t *fs,
                                  const vw_version_record_t *rec,
                                  const uint8_t *chunk_hashes,
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
 * List all versions for a file, sorted by version_id ascending.
 * Returns a malloc'd array; caller frees. *out_count may be 0.
 */
vw_err_t vw_store_version_list(vw_file_store_t *fs,
                                uint64_t file_id,
                                vw_version_record_t **out_records,
                                uint32_t *out_count);

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
