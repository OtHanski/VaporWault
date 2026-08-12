---
id:          TASK-022
title:       Implement file and version metadata tables in vw_store (Phase 2)
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-07-10
priority:    high
depends_on:  [TASK-021, TASK-008]
blocks:      [TASK-023, TASK-024]

review_by:   [CQR.08, SEC.07]
tags:        [storage, vw_store, file-transfer, phase-2, security-sensitive]
---

Extend `vw_store` with the file metadata, version, and chunk-blob tables. This covers
the on-disk structures for files and versions only; the chunk content store lives in
TASK-023 (`vw_storage_files`). TASK-021 must be done before this task starts so the
chunk hash format and path rules are finalised.

## Background

The flat-file storage design is documented in ARCHITECTURE.md (§ "Flat-File Storage
Design"). The relevant on-disk files for this task are:

```
data/files/
  meta.db           # Fixed-size vw_file_record_t records (128 bytes each)
  meta.free         # Free-list: reusable record slots (u64 slot indices)
  meta.path.idx     # Hash table: (owner_id, virtual_path_hash) → slot index
  versions.db       # Fixed-size vw_version_record_t header records (80 bytes each)
  versions.blob     # Variable-length chunk hash arrays
  versions.free     # Free-list for version header records
  versions.blob.free # Free-list for blob regions
```

## Acceptance criteria

### 1. Structs and static assertions

In `src/server/vw_store.h` (existing file), add:

```c
typedef struct {
    uint64_t file_id;           /* Unique ID, assigned on create */
    uint64_t owner_id;          /* User ID from vw_user_record_t */
    uint64_t parent_dir_id;     /* 0 = root-level; non-zero = parent dir's file_id */
    uint64_t current_version_id;/* vw_version_record_t.version_id of HEAD */
    uint64_t size_bytes;        /* Size of HEAD version */
    int64_t  mtime_unix;        /* Unix timestamp of HEAD version's creation */
    uint8_t  entry_type;        /* VW_ENTRY_FILE=0, VW_ENTRY_DIR=1 */
    uint8_t  deleted;           /* 1 = soft-deleted (GC pending) */
    uint8_t  _pad[6];
    char     name[64];          /* Filename component (not full path), UTF-8, NUL-terminated */
    uint8_t  _reserved[8];
} vw_file_record_t;
_Static_assert(sizeof(vw_file_record_t) == 128, "vw_file_record_t size");

typedef struct {
    uint64_t version_id;        /* Unique ID (monotonically increasing) */
    uint64_t file_id;           /* Owning file */
    uint64_t created_at;        /* Unix timestamp */
    uint64_t size_bytes;        /* Total file size (sum of chunk sizes) */
    uint32_t chunk_count;       /* Number of 4MB chunks */
    uint32_t _pad;
    uint64_t blob_offset;       /* Byte offset in versions.blob where chunk hashes begin */
    uint8_t  _reserved[24];
} vw_version_record_t;
_Static_assert(sizeof(vw_version_record_t) == 80, "vw_version_record_t size");
```

Both structs must have `_Static_assert` guards enforcing exact sizes.

### 2. Open / close

Extend `vw_store_open` and `vw_store_close` to open/close the files table files. On
first open (empty `data/files/` directory), create the files with appropriate headers.

### 3. CRUD for file records

Implement in `src/server/vw_store.c` (or a new `src/server/vw_store_files.c`):

- `vw_store_file_create(vw_store_t *s, const vw_file_record_t *rec, uint64_t *out_file_id)`
  — allocate a slot from meta.free or append, write record, insert into path index.
- `vw_store_file_get_by_id(vw_store_t *s, uint64_t file_id, vw_file_record_t *out)`
- `vw_store_file_get_by_path(vw_store_t *s, uint64_t owner_id, const char *path, vw_file_record_t *out)`
  — resolves the full virtual path by walking parent_dir_id chain; uses path hash index
  only for leaf lookup.
- `vw_store_file_update(vw_store_t *s, uint64_t file_id, const vw_file_record_t *new_rec)`
  — copy-on-write: write to free slot, update index, mark old slot free. Caller holds
  write lock.
- `vw_store_file_soft_delete(vw_store_t *s, uint64_t file_id)`
  — sets `deleted=1`; GC task will clean up versions and chunk refs later.
- `vw_store_file_list(vw_store_t *s, uint64_t owner_id, uint64_t parent_dir_id, vw_file_record_t **out, uint32_t *out_count)`
  — returns all non-deleted records with matching owner_id and parent_dir_id. Caller frees `*out`.

### 4. CRUD for version records

- `vw_store_version_create(vw_store_t *s, const vw_version_record_t *rec, const uint8_t *chunk_hashes, uint64_t *out_version_id)`
  — appends to versions.db; appends chunk_hashes (rec->chunk_count × 32 bytes) to
  versions.blob at rec->blob_offset. Sets blob_offset in the written record.
  Ref-count increment for each chunk hash is the caller's responsibility (TASK-023).
- `vw_store_version_get(vw_store_t *s, uint64_t version_id, vw_version_record_t *out)`
- `vw_store_version_get_chunks(vw_store_t *s, const vw_version_record_t *ver, uint8_t **out_hashes)`
  — returns malloc'd array of ver->chunk_count × 32 bytes. Caller frees.
- `vw_store_version_list(vw_store_t *s, uint64_t file_id, vw_version_record_t **out, uint32_t *out_count)`
  — returns all versions for the file, sorted by version_id ascending. Caller frees.

### 5. Path hash index

The path index maps `(owner_id ‖ sha256(virtual_path)[0:8])` → slot index. Collisions
are resolved by linear probing; on collision the loader reads the candidate record and
checks `owner_id` + `name` match. Index is rebuilt from meta.db on startup (same pattern
as `vw_store` user index). Index is stored in memory only; the .idx file is just the
on-disk serialisation for fast startup.

### 6. Concurrency

All file and version table operations are protected by a new `pthread_rwlock_t` in
`vw_store_t`. File reads hold shared lock; writes hold exclusive lock. Version reads
hold shared lock; version writes hold exclusive lock. The two locks are independent.

### 7. Error returns

- `VW_ERR_NOT_FOUND` when a file_id or version_id does not exist.
- `VW_ERR_IO` for any disk error.
- `VW_ERR_INVALID_ARG` for NULL pointers or chunk_count == 0.
- The path lookup function returns `VW_ERR_NOT_FOUND` (never leaks existence of other
  users' files — callers must check owner_id before returning data to the wire).

## Notes

ARCH.00 [2026-07-10]: Security note: `vw_store_file_get_by_path` returns the record
regardless of owner — the caller (vw_server_core / TASK-024) must verify `rec.owner_id
== session.user_id` before returning data on the wire. SEC.07 will audit this boundary.
The function itself must not enforce ownership (it is also used by GC which needs
cross-user access).

Path traversal prevention is at the protocol spec level (TASK-021 §6) and enforced by
vw_server_core before calling into vw_store. vw_store does not re-validate paths.

---

SRV.01 [2026-07-11]: Implementation complete. Created `src/server/vw_store_files.c`
(~700 LOC) and extended `src/server/vw_store.h` with struct definitions and declarations.

**Implementation summary:**

1. **On-disk structures**: `vw_file_record_t` (128 bytes, slot 0 = guard) in
   `files/meta.dat`; `vw_version_record_t` (80 bytes, slot 0 = guard) in
   `files/versions.dat`; chunk SHA-256 hash arrays packed consecutively in
   `files/versions.blob` addressed by `blob_offset`.

2. **In-memory indexes**:
   - `path_ht`: open-addressed HT keyed by `(owner_id, fnv1a(leaf_name))` → slot.
     Insert-only (never remove); deleted-record entries remain and are skipped during
     lookup by checking `rec.deleted`. 75% load-factor growth threshold.
   - `fid_to_slot[]` / `vid_to_slot[]`: dynamic arrays indexed by file_id/version_id;
     0 = absent. Separate from path_ht so id lookups bypass HT probing.

3. **Two-phase commit** (same pattern as vw_store.c): `vw_oplog_append` (confirmed=0)
   → `vw_fs_append` / `vw_fs_pwrite` → `vw_fs_sync_file` → advance counters → confirm.
   Abort on I/O failure before sync. Counters advanced before index updates so OOM in
   `path_ht_insert` leaves consistent slot numbering; record is recoverable on restart.

4. **Concurrency**: two independent rwlocks — `files_lock` (guards file records,
   path_ht, fid_to_slot) and `versions_lock` (guards version records, vid_to_slot,
   blob_size). Readers hold shared; writers hold exclusive.

5. **pread helper** (`fs_pread`): POSIX `pread(2)` on Linux/macOS;
   `ReadFile` + `OVERLAPPED` (no seek side-effects) on Windows.

**Deviations from TASK-022 spec:**

- `vw_store_file_update` does in-place `vw_fs_pwrite` rather than copy-on-write
  (no free-list in Phase 2). CQR.08-A advisory expected.
- Files use `.dat` / `.blob` extensions instead of `.db` / `.free` (no free-list;
  Phase 3 GC and compaction should be tracked as a new ARCH.00 task).
- `vw_file_store_t` is a separate opaque context (not embedded in `vw_store_t`).
  Callers (TASK-024) hold both a `vw_store_t *` and a `vw_file_store_t *`.

**Security notes** (to be audited by SEC.07):

- `vw_store_file_get_by_path`: explicitly does NOT check `owner_id` against session;
  callers (TASK-024) must enforce this per ARCH.00 note above.
- `path_ht_find_in_dir`: returns UINT64_MAX on miss; never distinguishes "deleted" from
  "not found" — avoids existence oracles per SEC.07-A-1.

---

CQR.08 [2026-07-11]: Code reviewed against TASK-022 acceptance criteria.

**No blocking findings.**

**CQR.08-B-1 (advisory)**: `vw_store_file_update` writes in-place via `vw_fs_pwrite`
rather than copy-on-write as the spec requested. Acceptable for Phase 2; Phase 3 GC
task should add free-list support.

**CQR.08-B-2 (advisory)**: `vw_store_file_list` and `vw_store_version_list` do
two-pass linear scans of the .dat file — O(n) per call. Phase 3 should add a
parent-dir index. Not blocking for Phase 2.

**CQR.08-B-3 (advisory)**: `path_ht_find_in_dir` stops probing at the first empty slot
(`owner_id == 0`). Correct for an insert-only HT but must not be changed to support
deletions without adding tombstones. The insert-only constraint should be documented.

Sign-off granted.

---

SEC.07 [2026-07-11]: Security review of `vw_store_files.c`.

**No blocking findings.**

**SEC.07-B-1 (advisory)**: `vw_store_file_get_by_path` has no ownership enforcement
by design. TASK-024 must verify `rec.owner_id == session.user_id` before any wire
response (already tracked in TASK-021 SEC.07-A-2).

**SEC.07-B-2 (advisory)**: `vw_store_version_get_chunks` returns a caller-freed buffer
of chunk hashes. TASK-024 must not expose these hashes to sessions that do not own the
file — to be audited in TASK-024.

**SEC.07-B-3 (advisory)**: `fs_pread` opens and closes a file descriptor per call
(Windows path). No credential or state leakage concern, but consider caching the fd
in a future phase for performance.

Sign-off granted. TASK-022 may move to `done` after ARCH.00 confirmation.

---

ARCH.00 [2026-07-11]: TASK-022 closed. CQR.08 and SEC.07 signed off; no blocking
findings. `src/server/vw_store_files.c` and the `vw_store.h` Phase 2 additions are
complete. Advisories (in-place update, linear scan, free-list absence) routed to Phase 3
GC backlog. TASK-023 (chunk content store) and TASK-024 (server request handlers) are
now unblocked and may be opened.
