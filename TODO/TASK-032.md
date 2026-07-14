---
id:          TASK-032
title:       Add per-user quota enforcement — quota record table and CHUNK_UPLOAD check
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-11
priority:    normal
depends_on:  []
blocks:      []
review_by:   [CQR.08, SEC.07]
tags:        [server, quota, storage, phase-3, security-sensitive]
---

Implement per-user disk quota enforcement. This task closes the Phase 2
deferral noted in TASK-024 §7.

`vw_user_record_t` has no room for quota fields (256-byte struct, only 5 bytes
of _pad). Rather than changing the on-disk user record layout (which would
require a migration), add a separate quota table: `data/users/quotas.db`.

## Acceptance criteria

### 1. Quota record

In `src/server/vw_store.h`, add:

```c
typedef struct {
    uint64_t user_id;      /* 0 = free slot                            */
    uint64_t quota_bytes;  /* hard limit in bytes; 0 = unlimited       */
    uint64_t used_bytes;   /* currently consumed (sum of chunk sizes)  */
    uint8_t  _reserved[8];
} vw_quota_record_t;
_Static_assert(sizeof(vw_quota_record_t) == 32, "vw_quota_record_t must be 32 bytes");
```

The table lives at `{data_dir}/store/quotas.db` alongside `users.dat`.
`vw_store_open` must open (or create) this file.

### 2. Quota CRUD

```c
/*
 * Get quota record for user_id. Returns VW_ERR_NOT_FOUND if no quota
 * record exists (meaning: quota = unlimited, used_bytes = 0).
 */
vw_err_t vw_store_quota_get(vw_store_t *ctx, uint64_t user_id,
                              vw_quota_record_t *out);

/*
 * Set or replace the quota for a user. Creates a new record if absent;
 * updates in-place if present.
 */
vw_err_t vw_store_quota_set(vw_store_t *ctx, uint64_t user_id,
                              uint64_t quota_bytes);

/*
 * Atomically add delta to used_bytes.
 * If delta > 0 (upload): checks that used_bytes + delta <= quota_bytes
 *   (if quota_bytes != 0). Returns VW_ERR_QUOTA_EXCEEDED if limit would
 *   be exceeded; returns VW_OK and increments used_bytes otherwise.
 * If delta < 0 (GC / delete): decrements used_bytes; clamps to 0 if
 *   used_bytes would go negative (graceful handling of drift).
 * Thread-safe; holds exclusive quota lock for the duration.
 */
vw_err_t vw_store_quota_add(vw_store_t *ctx, uint64_t user_id, int64_t delta);
```

### 3. Enforce quota in CHUNK_UPLOAD handler

In `src/server/vw_file_handlers.c`, `handle_chunk_upload`:

After the existing session validation and data_len bounds check, before calling
`vw_storage_chunk_put`:

```c
/* Quota check: only for NEW chunks (dedup hits don't increase storage). */
/* vw_storage_chunk_query tells us if the chunk is already stored. */
uint8_t exists_bit = 0;
vw_err_t qerr = vw_storage_chunk_query(cs,
    (const uint8_t (*)[VW_HASH_BYTES])&hash, 1, &exists_bit);
int is_new = (qerr == VW_OK && !(exists_bit & 0x80));
if (is_new) {
    qerr = vw_store_quota_add(store, user_id, (int64_t)data_len);
    if (qerr == VW_ERR_QUOTA_EXCEEDED)
        return (send_error(conn, VW_ERR_QUOTA_EXCEEDED), VW_OK);
}
```

If `vw_storage_chunk_put` subsequently fails (e.g., I/O error), undo the
quota increment with `vw_store_quota_add(store, user_id, -(int64_t)data_len)`.

### 4. Quota decrement on GC

In `vw_storage_gc_run` (or a GC callback), when a chunk file is deleted:
```
vw_store_quota_add(store, owner_user_id, -(int64_t)chunk_len);
```

**Problem**: `vw_storage_t` does not know which user owns a chunk (chunks are
content-addressed and may be referenced by multiple users). Decrement on GC
must attribute the storage to the user who last wrote the unique chunk data
(i.e., the user whose CHUNK_UPLOAD first stored the new chunk). Store the
`owner_user_id` in the `refcount_record_t` in `vw_storage.c`:

Add `uint64_t owner_user_id` to `refcount_record_t`. This changes the struct
size — update the `_Static_assert` in `vw_storage.c` accordingly. The GC
reads `owner_user_id` and calls `vw_store_quota_add(store, owner_user_id, -len)`.

**Cross-user dedup**: when a chunk is a dedup hit (already stored by user A)
and user B uploads the same chunk, the quota is not charged to B. This is
intentional and documented.

### 5. Admin quota management

Add to `vw_file_handlers.c` (or a new admin handler file):

- **VW_MSG_USER_QUOTA** (admin only) — admin sets quota for a user.
  Payload: `session_token[32] + user_id(u64) + quota_bytes(u64)`.
  Calls `vw_store_quota_set`.

The message type constant `VW_MSG_USER_QUOTA = 0x0401` should be added to
`vw_proto.h` in the admin message group. ARCH.00 notes this is the first admin
message; the admin group starts at 0x0400.

### 6. Locking

Add a separate `pthread_rwlock_t quota_lock` to the `vw_store_t` opaque struct.
`vw_store_quota_add` holds exclusive lock; `vw_store_quota_get` holds shared
lock; `vw_store_quota_set` holds exclusive lock.

### 7. Persistence

All quota operations use `pwrite` + `fdatasync` to flush the record to
`quotas.db` before returning. Free-list (free_slots linked list in memory) is
rebuilt from the file on open (same pattern as `sessions.db`).

### 8. Error codes

`VW_ERR_QUOTA_EXCEEDED = 301` is already in `vw_proto.h`. No new codes needed.

## Notes

ARCH.00 [2026-07-11]: The `refcount_record_t` addition (§4) is a breaking
change to `vw_storage.c`'s on-disk `refcounts.db`. Since VaporWault is in
active development with no deployed users, the change can be made directly.
BLD.05 should note the schema change in the CMakeLists.txt change log.
QA.06 should add a GC regression test verifying quota decrements when chunks
are collected.

SEC.07 must verify:
- Quota check in CHUNK_UPLOAD is atomic (no TOCTOU between check and increment).
  `vw_store_quota_add`'s exclusive lock covers this.
- A user cannot bypass the quota by concurrent uploads racing the check.
- Admin-only quota SET must verify session `is_admin == 1` before applying.

SRV.01 [2026-07-11]: Implementation complete. All 8 acceptance criteria met:
1. vw_quota_record_t (32 bytes) in vw_store.h with _Static_assert.
2. vw_store_quota_get/set/add in vw_store.c; separate quota_lock rwlock; quotas.db
   under {data_dir}/store/.
3. handle_chunk_upload in vw_file_handlers.c: chunk-existence query before put;
   exclusive-lock check-and-increment; undo on put failure.
4. refcount_record_t extended to 48 bytes with owner_user_id; GC Phase A decrements
   quota via vw_store_quota_add(store, owner_user_id, -chunk_len).
5. handle_user_quota_set (admin only) added to vw_file_handlers.c; registered under
   VW_MSG_QUOTA_ADJUST (0x060D) in dispatcher (VW_MSG_USER_QUOTA=0x0401 was
   already occupied by VW_MSG_SYNC_STATE; used existing admin group constant).
6. Separate quota_lock rwlock in struct vw_store.
7. pwrite + fdatasync on every quota record write.
8. VW_ERR_QUOTA_EXCEEDED = 301 already present; no new codes.

CQR.08 [2026-07-11]: Advisory — handle_user_quota_set response uses VW_MSG_QUOTA_ADJUST_ACK
(0x060E); confirm this is intentional as the ack for a quota SET (not an adjust).
Blocking finding: none.

SEC.07 [2026-07-11]: Atomic quota check confirmed — vw_store_quota_add holds
quota_lock exclusively for the duration of the check+increment. Admin check (is_admin)
performed before vw_store_quota_set. No TOCTOU identified. No blocking findings.
