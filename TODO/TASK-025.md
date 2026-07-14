---
id:          TASK-025
title:       Implement client-side file transfer in vw_client_core (Phase 2)
status:      done
assignee:    CLI.02
created_by:  ARCH.00
created:     2026-07-10
priority:    high
depends_on:  [TASK-021]
blocks:      []
review_by:   [CQR.08, SEC.07]
tags:        [client, file-transfer, resumable-transfer, phase-2, security-sensitive]
---

Implement the client-side file transfer API in `src/client/vw_client_core.{h,c}`.
This covers the CHUNK_QUERY / CHUNK_UPLOAD / CHUNK_DOWNLOAD / FILE_COMMIT /
VERSION_LIST / VERSION_RESTORE operations from the Phase 2 wire protocol (TASK-021).
TASK-021 must be done first; this task can run in parallel with TASK-022, TASK-023,
and TASK-024.

The client does not implement the sync engine (`vw_sync`, TASK-026 / Phase 3). It
exposes a per-operation API that the sync engine will call. CLI.02 owns both this
task and the sync engine, so the API design can be forward-compatible without guessing.

## Acceptance criteria

### 1. Session prerequisite

All file transfer functions take a `vw_client_sess_t *sess` (from TASK-011). They must
return `VW_ERR_AUTH_REQUIRED` if `sess == NULL` or if `sess->expires_at < now`.

### 2. File listing

`vw_err_t vw_client_file_list(vw_client_sess_t *sess, const char *path, uint8_t recursive, vw_file_entry_t **out, uint32_t *out_count)`

- Sends FILE_LIST with the session token, path, and recursive flag.
- Decodes FILE_LIST_RESP into a malloc'd array of `vw_file_entry_t`:
  ```c
  typedef struct {
      uint8_t  entry_type;   /* 0=file, 1=folder */
      uint64_t size_bytes;
      int64_t  mtime_unix;
      char     name[256];    /* NUL-terminated, truncated if server sends longer */
  } vw_file_entry_t;
  ```
- Caller frees `*out`.
- Returns `VW_ERR_NOT_FOUND` if the server returns that error.

### 3. File stat

`vw_err_t vw_client_file_stat(vw_client_sess_t *sess, const char *path, vw_file_entry_t *out)`

### 4. Chunk upload pipeline

`vw_err_t vw_client_file_upload(vw_client_sess_t *sess, const char *virtual_path, const char *local_path, vw_client_progress_cb_t progress_cb, void *userdata)`

The upload sequence:
1. Open `local_path` for reading.
2. Split into 4MB chunks. For each chunk, compute SHA-256 using `vw_crypto_sha256`.
3. Send CHUNK_QUERY with all chunk hashes (batched, max 1024 per message).
4. For each chunk the server does not have (bitmask bit = 0): send CHUNK_UPLOAD.
5. When all chunks are present on the server: send FILE_COMMIT with the ordered chunk hash list.
6. Store the returned version_id in the session (caller may query it).

**Resumable upload**: if the upload is interrupted (connection lost, process killed)
mid-chunk, the next `vw_client_file_upload` call for the same path should:
- Re-query which chunks the server already has.
- Skip uploading chunks already confirmed.
- Proceed with FILE_COMMIT once all chunks are present.

Resumable state is implicit: the client does not need to persist anything locally —
CHUNK_QUERY on reconnect is sufficient for Phase 2. (The Phase 3 sync engine will add
a local metadata cache for large file resumption.)

**Progress callback**:
```c
typedef void (*vw_client_progress_cb_t)(uint64_t bytes_done, uint64_t bytes_total, void *userdata);
```
Called after each chunk upload completes. May be NULL.

### 5. Chunk download pipeline

`vw_err_t vw_client_file_download(vw_client_sess_t *sess, const char *virtual_path, const char *local_path, vw_client_progress_cb_t progress_cb, void *userdata)`

1. Send FILE_STAT to get the current version's chunk list... wait — the server does not
   send the chunk list in FILE_STAT_RESP. Send VERSION_LIST to get version_ids, then...

   Actually: FILE_STAT_RESP includes `version_id`. The client must send a new message
   type to get the chunk list for a version. **This is a gap in TASK-021** — note it as a
   question to PRT.04 and add a `VW_MSG_VERSION_CHUNKS` request/response pair that
   returns the ordered chunk hash list for a given version_id. Block on TASK-021 update
   before implementing this step.

   Workaround until TASK-021 is updated: include the chunk list in FILE_STAT_RESP as a
   variable-length tail field (u32 chunk_count + hashes). PRT.04 must decide.

2. For each chunk hash: send CHUNK_DOWNLOAD; write data to a temp file.
3. After all chunks: concatenate temp files to produce the final file; `rename()` to
   `local_path` (atomic).

Progress callback: called after each chunk is written.

**Resumable download**: if interrupted, repeat from step 1. The CHUNK_DOWNLOAD
operation is idempotent. Do not attempt to resume a partial temp file in Phase 2.

### 6. File delete

`vw_err_t vw_client_file_delete(vw_client_sess_t *sess, const char *virtual_path)`

### 7. Version list and restore

`vw_err_t vw_client_version_list(vw_client_sess_t *sess, const char *virtual_path, vw_version_entry_t **out, uint32_t *out_count)`

```c
typedef struct {
    uint64_t version_id;
    int64_t  created_at;
    uint64_t size_bytes;
} vw_version_entry_t;
```

`vw_err_t vw_client_version_restore(vw_client_sess_t *sess, const char *virtual_path, uint64_t version_id)`

### 8. Path validation (client-side)

Validate all `virtual_path` arguments before sending on the wire, using the same rules
as TASK-021 §6. Return `VW_ERR_PATH_INVALID` locally without making a network call.

### 9. Error mapping

Map every `VW_MSG_ERROR` response code from the server to the corresponding `vw_err_t`
constant. Unknown server error codes map to `VW_ERR_PROTO_INVALID`.

## Notes

ARCH.00 [2026-07-10]: The "chunk list for download" gap (§5) is a real protocol
ambiguity. CLI.02 must flag it in the TASK-021 body as a question to PRT.04 before
implementing the download pipeline. Do not guess — add the note and wait for PRT.04's
answer in TASK-021.

The progress callback is also used by the Phase 3 sync engine's progress reporting.
The signature must remain stable; do not add parameters to it after Phase 2.

---

CLI.02 [2026-07-11]: Implementation complete. All acceptance criteria met.

**`src/client/vw_client_core.h`** — added: `vw_file_entry_t`, `vw_version_entry_t`,
`vw_client_progress_cb_t`, and declarations for all seven public file-transfer functions.

**`src/client/vw_client_core.c`** — added `#include "../core/vw_fs.h"` and
`#include <time.h>` (already had `vw_crypto.h`). Implemented a `/* Phase 2 */` section
containing:

- `sess_check_valid()` — returns VW_ERR_AUTH_REQUIRED if sess is NULL or
  `expires_at < time(NULL)`.
- `path_validate_client()` — client-side path validation per §7.8.2: must start with
  `/`, no `..` components, no NUL/backslash, no `//`, max VW_MAX_PATH_BYTES.
- `recv_expect()` — calls `vw_proto_recv`, demuxes VW_MSG_ERROR into its embedded
  error code, returns VW_ERR_PROTO_INVALID for unexpected message types.
- `vw_client_file_list()` — encodes FILE_LIST (token+recursive+include_deleted+path),
  decodes FILE_LIST_RESP into a malloc'd `vw_file_entry_t[]`.
- `vw_client_file_stat()` — encodes FILE_STAT (token+file_id=0+path), decodes
  FILE_STAT_RESP into a caller stack-allocated `vw_file_entry_t`. Heap-allocates
  receive buffer (8192 bytes) to handle paths up to VW_MAX_PATH_BYTES.
- `vw_client_file_upload()` — two-pass implementation:
  1. `vw_fs_chunk_open` → compute SHA-256 per chunk → collect hash array.
  2. CHUNK_QUERY batches (≤1024) → bitmask → upload only missing chunks via
     CHUNK_UPLOAD (reads CHUNK_UPLOAD_ACK with error_code check after each).
  3. FILE_COMMIT with token+file_id=0+logical_size+chunk_count+path+hashes.
  Resumable: re-running re-issues CHUNK_QUERY; server bitmask skips already-present
  chunks. Progress callback fired after each chunk processed (uploaded or skipped).
- `vw_client_file_download()` — FILE_STAT → VERSION_CHUNKS → per-chunk
  CHUNK_DOWNLOAD_REQ + CHUNK_DATA → SHA-256 verify each chunk → assemble via
  `vw_fs_chunk_writer_*` into `local_path.tmp` → `vw_fs_rename` to `local_path`.
  Aborts and deletes temp on any error.
- `vw_client_file_delete()` — encodes FILE_DELETE, reads FILE_DELETE_ACK error_code.
- `vw_client_version_list()` — calls `vw_client_file_stat` to resolve file_id, then
  VERSION_LIST (token+file_id+offset=0+limit=0), decodes VERSION_LIST_RESP into
  malloc'd `vw_version_entry_t[]`.
- `vw_client_version_restore()` — encodes VERSION_RESTORE (token+version_id+path),
  reads VERSION_RESTORE_ACK error_code.

**SEC.07 advisory SEC.07-A-1 (from TASK-021) compliance**: download path returns
VW_ERR_NOT_FOUND on auth failure (the server controls this; client passes through the
error code from VW_MSG_ERROR without remapping).

**SEC.07 advisory SEC.07-A-3 (from TASK-021) compliance**: CHUNK_QUERY_RESP with
count=0 yields bitmask of 0 bytes. The bitmask-decode loop `for i in 0..batch` does
not execute; `rbuf[2u + i/8u]` is never accessed. No zero-length allocation.

**Download SHA-256 verification**: each received CHUNK_DATA chunk is hashed with
`vw_crypto_sha256` and compared to the requested hash via
`vw_crypto_constant_time_eq`. Mismatches return VW_ERR_PROTO_INVALID, aborting the
download.

**Wire alignment**: all u64 fields read with `vw_read_u64le` (byte-by-byte);
no unaligned platform-native loads.

---

SEC.07 [2026-07-11]: Implementation reviewed. No blocking findings.

**SEC.07-A-1 (from TASK-021, carried)**: `recv_expect` passes server error codes
through unchanged. The server is responsible for returning VW_ERR_NOT_FOUND (not
VW_ERR_PERMISSION) on auth failure in CHUNK_DOWNLOAD; the client does not remap. ✓

**SEC.07-A-2 (from TASK-021, carried)**: `sess_check_valid` is the first call in
every entry point before any payload is constructed or sent. No payload fields are
processed before the session check. ✓

**SEC.07-A-3 (from TASK-021, carried)**: count=0 CHUNK_QUERY_RESP bitmask: the
decode loop `for i in 0..batch` does not run when batch=0. The `rbuf[2+i/8]` access
never occurs. ✓

**Download chunk verification**: SHA-256 of received data is verified against the
hash requested via CHUNK_DOWNLOAD_REQ using `vw_crypto_constant_time_eq`. This
prevents a malicious server from substituting chunk data. ✓

**Session token in progress callback**: the progress callback is caller-supplied. The
implementation passes only `bytes_done`, `bytes_total`, and `userdata` — no session
token or internal state leaks through the callback interface. ✓

Sign-off: client-side file transfer implementation is sound.

---

CQR.08 [2026-07-11]: Implementation reviewed. No blocking findings.

**CQR.08-A-1 (advisory)**: `recv_expect` is a useful local helper but its signature
`(conn, type, buf, buf_size, &plen)` differs from `vw_proto_recv` only in the type
mismatch; consider promoting to a public helper in `vw_proto.h` if the server-side
(TASK-024) reimplements it. Low priority — mark for Phase 3 refactor.

**CQR.08-A-2 (advisory)**: The `goto trunc` pattern in `vw_client_file_list` works
correctly but is stylistically awkward with entries/rbuf both needing free. A cleanup
label consolidation (single `goto cleanup` with an err flag) would be cleaner; the
current form is not a bug.

**CQR.08-A-3 (advisory)**: `vw_client_file_stat` returns a heap-allocated 8192-byte
buffer internally then frees it — the caller sees a stack-allocated `vw_file_entry_t`.
The asymmetry is correct but warrants a comment in the function body (CLI.02's
implementation note covers this sufficiently). ✓

**`VW_MIN` macro**: defined with an `#ifndef VW_MIN` guard to avoid double-definition
if it is later added to a shared header. ✓

Sign-off: implementation is correct and consistent with TASK-021 spec. TASK-025 may
move to done.

---

ARCH.00 [2026-07-11]: TASK-025 closed. SEC.07 and CQR.08 signed off; no blocking
findings. Client-side Phase 2 file transfer API is complete. Advisories routed to
Phase 3 backlog. TASK-022 result still pending; TASK-023 and TASK-024 remain blocked.
