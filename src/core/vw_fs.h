#ifndef VW_FS_H
#define VW_FS_H

/*
 * vw_fs — filesystem utilities for VaporWault.
 *
 * Cross-platform (POSIX + Win32). All path arguments use the platform's
 * native separator. Callers are responsible for path construction.
 */

#include "vw_proto.h"   /* vw_err_t */
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Default chunk size: 4 MiB. Change at build time with -DVW_CHUNK_SIZE=N */
#ifndef VW_CHUNK_SIZE
#define VW_CHUNK_SIZE 4194304u
#endif

/* ── Basic file operations ───────────────────────────────────────────────── */

/*
 * Write data atomically: writes to path+".tmp", then renames to path.
 * On POSIX, rename() is atomic on the same filesystem (POSIX.1-2008).
 * On Windows, uses MoveFileExW with MOVEFILE_REPLACE_EXISTING.
 *
 * Suitable for updating metadata files. NOT suitable for files larger than
 * available RAM; use the chunk API for those.
 */
vw_err_t vw_fs_atomic_write(const char *path, const void *data, size_t len);

/*
 * Read the entire file at path into a malloc'd buffer.
 * *out_buf is set to the buffer (caller must free()); *out_len to its size.
 * Returns VW_ERR_NOT_FOUND if the file does not exist.
 * Returns VW_ERR_OOM if malloc fails.
 */
vw_err_t vw_fs_read_file(const char *path, void **out_buf, size_t *out_len);

/*
 * Create directories recursively (mkdir -p equivalent).
 * Returns VW_OK if the directory already exists or was created.
 */
vw_err_t vw_fs_ensure_dir(const char *path);

/*
 * Return the file size in bytes via *out_size.
 * Returns VW_ERR_NOT_FOUND if the file does not exist.
 */
vw_err_t vw_fs_file_size(const char *path, uint64_t *out_size);

/*
 * Return 1 if path exists (file or directory), 0 otherwise.
 */
int vw_fs_exists(const char *path);

/*
 * Unlink (delete) a file. Returns VW_ERR_NOT_FOUND if it does not exist
 * (treated as success — idempotent delete).
 */
vw_err_t vw_fs_delete(const char *path);

/*
 * Rename src to dst, replacing dst if it exists.
 * src and dst must be on the same filesystem for atomicity.
 */
vw_err_t vw_fs_rename(const char *src, const char *dst);

/*
 * Append data to a file, creating it if it does not exist.
 * Not atomic; suitable only for append-only logs.
 */
vw_err_t vw_fs_append(const char *path, const void *data, size_t len);

/*
 * Build a path string: writes base + "/" + name into out (size out_size).
 * Returns VW_ERR_INVALID_ARG if the result would exceed out_size.
 */
vw_err_t vw_fs_path_join(char *out, size_t out_size,
                          const char *base, const char *name);

/*
 * Write `len` bytes from `data` into the existing file at `path`, starting at
 * byte offset `offset`. The file must already exist and be large enough.
 *
 * Does NOT sync to disk — caller must call vw_fs_sync_file after all pwrite
 * calls for a record to guarantee durability.
 *
 * A naturally-aligned write of 1, 2, 4, or 8 bytes is atomic on x86-64 and
 * ARM64. Larger or unaligned writes are not atomic; use vw_fs_atomic_write for
 * those.
 *
 * Returns VW_OK on success; VW_ERR_IO on any failure.
 */
vw_err_t vw_fs_pwrite(const char *path, uint64_t offset,
                       const void *data, size_t len);

/*
 * Flush all pending writes to the file at `path` to durable storage
 * (fsync / FlushFileBuffers). Call after one or more vw_fs_pwrite calls on the
 * same file.
 *
 * Returns VW_OK on success; VW_ERR_IO on failure.
 */
vw_err_t vw_fs_sync_file(const char *path);

/*
 * Enumerate all entries in directory `dir`, calling `cb(name, userdata)` for
 * each entry excluding "." and "..". The `name` pointer is only valid for the
 * duration of the callback invocation.
 *
 * `cb` return value: 0 = continue enumeration, non-zero = stop.
 *
 * Returns VW_OK when all entries are delivered (or iteration stopped by cb);
 * VW_ERR_IO if the directory cannot be opened.
 */
vw_err_t vw_fs_list_dir(const char *dir,
                         int (*cb)(const char *name, void *userdata),
                         void *userdata);

/* ── Chunk streaming API ─────────────────────────────────────────────────── */

/*
 * Opaque chunk reader context. Stack-allocate; initialise with vw_fs_chunk_open.
 */
typedef struct vw_fs_chunk_ctx {
    uint8_t  _opaque[256];  /* platform-specific state; do not access directly */
} vw_fs_chunk_ctx_t;

/*
 * Open a file for chunk-streaming. Seeks to the beginning of the file.
 *
 *   path     : file to open
 *   ctx      : caller-allocated context (stack or static)
 *
 * Returns VW_ERR_NOT_FOUND if the file does not exist.
 */
vw_err_t vw_fs_chunk_open(const char *path, vw_fs_chunk_ctx_t *ctx);

/*
 * Read the next chunk into out_buf (must be at least VW_CHUNK_SIZE bytes).
 * *out_len receives the number of bytes written (may be < VW_CHUNK_SIZE for
 * the final chunk). *out_is_last is set to 1 when this is the final chunk.
 *
 * Returns VW_OK on success. Returns VW_ERR_IO on read error.
 * Returns VW_ERR_NOT_FOUND if called after the last chunk (programming error).
 */
vw_err_t vw_fs_chunk_next(vw_fs_chunk_ctx_t *ctx,
                           uint8_t *out_buf, size_t *out_len,
                           int *out_is_last);

/*
 * Close the chunk reader and release resources.
 */
void vw_fs_chunk_close(vw_fs_chunk_ctx_t *ctx);

/* ── Chunk writer API ────────────────────────────────────────────────────── */

/*
 * Opaque chunk writer context. Used to assemble an uploaded file from
 * content-addressed chunks.
 *
 * Workflow:
 *   1. vw_fs_chunk_writer_open(tmp_path, &ctx)
 *   2. For each chunk in order: vw_fs_chunk_writer_append(&ctx, data, len)
 *   3. vw_fs_chunk_writer_close(&ctx)
 *   4. vw_fs_rename(tmp_path, final_path)
 *
 * If any step fails, call vw_fs_chunk_writer_abort(&ctx) to clean up.
 */
typedef struct vw_fs_chunk_writer_ctx {
    uint8_t _opaque[256];
} vw_fs_chunk_writer_ctx_t;

vw_err_t vw_fs_chunk_writer_open(const char *path,
                                  vw_fs_chunk_writer_ctx_t *ctx);
vw_err_t vw_fs_chunk_writer_append(vw_fs_chunk_writer_ctx_t *ctx,
                                    const void *data, size_t len);
vw_err_t vw_fs_chunk_writer_close(vw_fs_chunk_writer_ctx_t *ctx);
void     vw_fs_chunk_writer_abort(vw_fs_chunk_writer_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* VW_FS_H */
