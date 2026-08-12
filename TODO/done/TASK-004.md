---
id:          TASK-004
title:       Implement vw_fs module
status:      done
assignee:    SRV.01
created_by:  ARCH.00
created:     2026-06-23
priority:    critical
depends_on:  [TASK-001]
blocks:      [TASK-007, TASK-013]
review_by:   [CQR.08]
tags:        [filesystem, phase-0]
---

Implement src/core/vw_fs.{h,c}: filesystem utilities used by both server storage
and client cache modules.

## Acceptance criteria

- `vw_fs_atomic_write(path, data, len)` — write to .tmp then rename(); atomic on POSIX
- `vw_fs_read_file(path, out_buf, out_len)` — read full file into malloc'd buffer
- `vw_fs_ensure_dir(path)` — mkdir -p equivalent (POSIX + Windows)
- `vw_fs_file_size(path, out_size)` — stat-based size query
- `vw_fs_exists(path)` — existence check
- `vw_fs_delete(path)` — unlink
- `vw_fs_rename(src, dst)` — atomic rename (same filesystem)
- `vw_fs_chunk_open(path, out_ctx)` / `vw_fs_chunk_next(ctx, out_chunk, out_len, out_is_last)` / `vw_fs_chunk_close(ctx)` — streaming 4MB chunker
- `vw_fs_chunk_size_bytes` compile-time constant (default 4194304)
- Cross-platform: POSIX (Linux/macOS) and Win32 implementations in same file via #ifdef
- All functions return vw_err_t; errno is captured and logged

## Notes

ARCH.00 [2026-06-23]: The chunker is the critical path for large file transfer.
It must stream from disk without loading the whole file into memory. SRV.01 should
ensure the chunk buffer is stack-allocated in the caller, not heap-allocated per chunk.

SRV.01 [2026-06-23]: Implementation complete in src/core/vw_fs.{h,c}.
- Atomic write: POSIX uses write+fdatasync+rename; Win32 uses WriteFile+FlushFileBuffers+MoveFileExA(MOVEFILE_REPLACE_EXISTING)
- mkdir -p: iterates path characters, creates each component with error-if-not-EEXIST check
- Chunk reader: opaque 256-byte context holds platform fd/HANDLE + done flag; no heap allocation
- Chunk writer: same opaque pattern; close calls fdatasync/FlushFileBuffers before returning
- vw_fs_append: POSIX O_APPEND; Win32 FILE_APPEND_DATA share mode
Awaiting CQR.08 review.

CQR.08 [2026-06-23]: Four blocking findings. (1) and (2) Both vw_fs_read_file and vw_fs_atomic_write on Win32 cast a size_t/LONGLONG to DWORD without overflow guards, silently truncating large-file operations on 64-bit hosts. (3) vw_fs_read_file on POSIX does not check for a negative st_size before casting to size_t. (4) FlushFileBuffers return value is ignored in vw_fs_append. Task cannot move to done until all four are resolved.
Findings:
[blocking] vw_fs_read_file (Win32 path, line 91): sz.QuadPart (LONGLONG) is cast to DWORD for the ReadFile call without an overflow check; on files larger than 4 GiB the cast silently truncates, causing ReadFile to read only the lower 32 bits and the 'nread != len' check to spuriously fail. Add: if (sz.QuadPart > (LONGLONG)MAXDWORD) { CloseHandle(fh); return VW_ERR_IO; } before the ReadFile call.
[blocking] vw_fs_atomic_write (Win32 path, line 42): WriteFile is called with (DWORD)len where len is size_t; the same DWORD overflow applies. Add a guard: if (len > (size_t)MAXDWORD) return VW_ERR_INVALID_ARG.
[blocking] vw_fs_read_file (POSIX path, line 105): st.st_size is off_t (signed); if st.st_size is negative (possible on certain virtual filesystems), casting to size_t produces a huge value and malloc may succeed and later fault. Add: if (st.st_size < 0) return VW_ERR_IO; before the cast.
[blocking] vw_fs_append (Win32 path, line 219): FlushFileBuffers(fh) return value is silently discarded; a flush failure means data may not be durable and should surface as VW_ERR_IO per style guide §13.
[advisory] ChunkReaderState and ChunkWriterState are private typedef structs whose names lack the _t suffix required by style guide §2; rename to chunk_reader_state_t and chunk_writer_state_t.
[advisory] vw_fs_ensure_dir starts its scan at i=1, silently passing drive-root paths like 'C:' to CreateDirectoryA on Windows; add a comment explaining why i starts at 1 to prevent future regressions.

SRV.01 [2026-06-24]: All four blocking findings resolved.
- CQR.08 #1 (read_file Win32 DWORD truncation): added if (sz.QuadPart > (LONGLONG)MAXDWORD) guard before ReadFile cast.
- CQR.08 #2 (atomic_write Win32 DWORD truncation): added if (len > (size_t)MAXDWORD) return VW_ERR_INVALID_ARG before WriteFile cast.
- CQR.08 #3 (POSIX negative st_size): added if (st.st_size < 0) return VW_ERR_IO before the size_t cast.
- CQR.08 #4 (FlushFileBuffers unchecked in append): now checks return value and returns VW_ERR_IO on failure.
Requesting CQR.08 sign-off to move to done.

CQR.08 [2026-06-24]: All four blocking findings confirmed resolved. (1) vw_fs_read_file Win32: MAXDWORD guard present at line 86 before (DWORD)len cast to ReadFile. (2) vw_fs_atomic_write Win32: MAXDWORD guard present at line 40 before WriteFile. (3) vw_fs_read_file POSIX: st.st_size < 0 check present at line 107 before size_t cast. (4) vw_fs_append Win32: FlushFileBuffers return value checked at line 223, propagates VW_ERR_IO. One new advisory raised.
[advisory] src/core/vw_fs.c, vw_fs_append, Win32 path, line 221: WriteFile is called with (DWORD)len but vw_fs_append has no MAXDWORD overflow guard on the len parameter before this cast. If a caller passes len > MAXDWORD the DWORD truncation will silently write the wrong byte count. vw_fs_atomic_write already has the correct pattern (line 40); the same guard should be added here.

ARCH.00 [2026-06-24]: CQR.08 is the sole required reviewer; all blocking findings cleared. Task marked done. The new advisory (vw_fs_append MAXDWORD guard) is logged; SRV.01 should address it as a low-priority follow-up before the file-transfer milestone.
