#include "vw_fs.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef _WIN32
#   include <windows.h>
#   include <io.h>
#   include <direct.h>
#   define VW_PATH_SEP '\\'
#else
#   include <dirent.h>
#   include <unistd.h>
#   include <sys/stat.h>
#   include <sys/types.h>
#   include <fcntl.h>
#   define VW_PATH_SEP '/'
#endif

/* ── Internal helpers ────────────────────────────────────────────────────── */

static vw_err_t build_tmp_path(char *out, size_t out_size, const char *path) {
    int n = snprintf(out, out_size, "%s.tmp", path);
    if (n < 0 || (size_t)n >= out_size) return VW_ERR_INVALID_ARG;
    return VW_OK;
}

/* ── Basic file operations ───────────────────────────────────────────────── */

vw_err_t vw_fs_atomic_write(const char *path, const void *data, size_t len) {
    char tmp[4096];
    vw_err_t err = build_tmp_path(tmp, sizeof(tmp), path);
    if (err != VW_OK) return err;

#ifdef _WIN32
    HANDLE fh = INVALID_HANDLE_VALUE;
    DWORD written = 0;
    vw_err_t win_err = VW_OK;

    if (len > (size_t)MAXDWORD) return VW_ERR_INVALID_ARG;

    fh = CreateFileA(tmp, GENERIC_WRITE, 0, NULL,
                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return VW_ERR_IO;

    if (!WriteFile(fh, data, (DWORD)len, &written, NULL) || (size_t)written != len) {
        win_err = VW_ERR_IO; goto cleanup_win;
    }
    if (!FlushFileBuffers(fh)) { win_err = VW_ERR_IO; goto cleanup_win; }
    CloseHandle(fh);
    fh = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING)) {
        DeleteFileA(tmp);
        return VW_ERR_IO;
    }
    return VW_OK;

cleanup_win:
    if (fh != INVALID_HANDLE_VALUE) CloseHandle(fh);
    DeleteFileA(tmp);
    return win_err;
#else
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return VW_ERR_IO;

    size_t pos = 0;
    while (pos < len) {
        ssize_t n = write(fd, (const char *)data + pos, len - pos);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            unlink(tmp);
            return VW_ERR_IO;
        }
        pos += (size_t)n;
    }

    if (fdatasync(fd) != 0) { close(fd); unlink(tmp); return VW_ERR_IO; }
    close(fd);

    if (rename(tmp, path) != 0) { unlink(tmp); return VW_ERR_IO; }
    return VW_OK;
#endif
}

vw_err_t vw_fs_read_file(const char *path, void **out_buf, size_t *out_len) {
#ifdef _WIN32
    HANDLE fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) {
        return (GetLastError() == ERROR_FILE_NOT_FOUND)
               ? VW_ERR_NOT_FOUND : VW_ERR_IO;
    }

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(fh, &sz)) { CloseHandle(fh); return VW_ERR_IO; }
    if (sz.QuadPart > (LONGLONG)SIZE_MAX)  { CloseHandle(fh); return VW_ERR_OOM; }
    if (sz.QuadPart > (LONGLONG)MAXDWORD) { CloseHandle(fh); return VW_ERR_IO; }

    size_t len = (size_t)sz.QuadPart;
    void *buf = malloc(len + 1);
    if (!buf) { CloseHandle(fh); return VW_ERR_OOM; }

    DWORD nread;
    if (!ReadFile(fh, buf, (DWORD)len, &nread, NULL) || nread != len) {
        free(buf); CloseHandle(fh); return VW_ERR_IO;
    }
    CloseHandle(fh);
    ((char *)buf)[len] = '\0';
    *out_buf = buf;
    *out_len = len;
    return VW_OK;
#else
    struct stat st;
    if (stat(path, &st) != 0) {
        return (errno == ENOENT) ? VW_ERR_NOT_FOUND : VW_ERR_IO;
    }

    if (st.st_size < 0) return VW_ERR_IO;
    size_t len = (size_t)st.st_size;
    void *buf = malloc(len + 1);
    if (!buf) return VW_ERR_OOM;

    int fd = open(path, O_RDONLY);
    if (fd < 0) { free(buf); return VW_ERR_IO; }

    size_t pos = 0;
    while (pos < len) {
        ssize_t n = read(fd, (char *)buf + pos, len - pos);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd); free(buf); return VW_ERR_IO;
        }
        if (n == 0) break;
        pos += (size_t)n;
    }
    close(fd);
    ((char *)buf)[pos] = '\0';
    *out_buf = buf;
    *out_len = pos;
    return VW_OK;
#endif
}

vw_err_t vw_fs_ensure_dir(const char *path) {
    char tmp[4096];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(tmp)) return VW_ERR_INVALID_ARG;
    memcpy(tmp, path, len + 1);

    /* On Windows, skip the bare drive letter ("X:") to avoid calling
     * CreateDirectoryA("X:", NULL), which returns ERROR_ACCESS_DENIED
     * rather than ERROR_ALREADY_EXISTS and would be treated as an error. */
#ifdef _WIN32
    size_t start = (len >= 2 && tmp[1] == ':') ? 3 : 1;
#else
    size_t start = 1;
#endif
    for (size_t i = start; i <= len; i++) {
        if (i == len || tmp[i] == '/' || tmp[i] == '\\') {
            char saved = tmp[i];
            tmp[i] = '\0';
#ifdef _WIN32
            if (!CreateDirectoryA(tmp, NULL)) {
                DWORD e = GetLastError();
                if (e != ERROR_ALREADY_EXISTS) return VW_ERR_IO;
            }
#else
            if (mkdir(tmp, 0700) != 0 && errno != EEXIST) return VW_ERR_IO;
#endif
            tmp[i] = saved;
        }
    }
    return VW_OK;
}

vw_err_t vw_fs_file_size(const char *path, uint64_t *out_size) {
#ifdef _WIN32
    HANDLE fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) {
        return (GetLastError() == ERROR_FILE_NOT_FOUND)
               ? VW_ERR_NOT_FOUND : VW_ERR_IO;
    }
    LARGE_INTEGER sz;
    BOOL ok = GetFileSizeEx(fh, &sz);
    CloseHandle(fh);
    if (!ok) return VW_ERR_IO;
    *out_size = (uint64_t)sz.QuadPart;
    return VW_OK;
#else
    struct stat st;
    if (stat(path, &st) != 0) {
        return (errno == ENOENT) ? VW_ERR_NOT_FOUND : VW_ERR_IO;
    }
    *out_size = (uint64_t)st.st_size;
    return VW_OK;
#endif
}

int vw_fs_exists(const char *path) {
#ifdef _WIN32
    return (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
#else
    struct stat st;
    return (stat(path, &st) == 0) ? 1 : 0;
#endif
}

vw_err_t vw_fs_delete(const char *path) {
#ifdef _WIN32
    if (!DeleteFileA(path)) {
        DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND) return VW_OK;
        return VW_ERR_IO;
    }
#else
    if (unlink(path) != 0) {
        if (errno == ENOENT) return VW_OK;
        return VW_ERR_IO;
    }
#endif
    return VW_OK;
}

vw_err_t vw_fs_rename(const char *src, const char *dst) {
#ifdef _WIN32
    if (!MoveFileExA(src, dst, MOVEFILE_REPLACE_EXISTING)) return VW_ERR_IO;
#else
    if (rename(src, dst) != 0) return VW_ERR_IO;
#endif
    return VW_OK;
}

vw_err_t vw_fs_append(const char *path, const void *data, size_t len) {
#ifdef _WIN32
    if (len > (size_t)MAXDWORD) return VW_ERR_INVALID_ARG;
    HANDLE fh = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ,
                            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return VW_ERR_IO;
    DWORD written;
    BOOL ok = WriteFile(fh, data, (DWORD)len, &written, NULL);
    if (!ok || written != len) { CloseHandle(fh); return VW_ERR_IO; }
    if (!FlushFileBuffers(fh)) { CloseHandle(fh); return VW_ERR_IO; }
    CloseHandle(fh);
    return VW_OK;
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return VW_ERR_IO;
    size_t pos = 0;
    while (pos < len) {
        ssize_t n = write(fd, (const char *)data + pos, len - pos);
        if (n < 0) { if (errno == EINTR) continue; close(fd); return VW_ERR_IO; }
        pos += (size_t)n;
    }
    close(fd);
    return VW_OK;
#endif
}

vw_err_t vw_fs_path_join(char *out, size_t out_size,
                          const char *base, const char *name) {
    int n = snprintf(out, out_size, "%s%c%s", base, VW_PATH_SEP, name);
    if (n < 0 || (size_t)n >= out_size) return VW_ERR_INVALID_ARG;
    return VW_OK;
}

/* ── In-place write and sync ─────────────────────────────────────────────── */

vw_err_t vw_fs_pwrite(const char *path, uint64_t offset,
                       const void *data, size_t len) {
    if (!path || !data) return VW_ERR_INVALID_ARG;
#ifdef _WIN32
    if (len > (size_t)MAXDWORD) return VW_ERR_INVALID_ARG;

    /* FILE_SHARE_WRITE required: vw_store may have the file open concurrently. */
    HANDLE fh = CreateFileA(path, GENERIC_WRITE | GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return VW_ERR_IO;

    /* Use SetFilePointerEx + non-overlapped WriteFile. Passing an OVERLAPPED
     * struct to WriteFile on a synchronous handle has ambiguous MSDN semantics
     * and is avoided here. */
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(fh, li, NULL, FILE_BEGIN)) {
        CloseHandle(fh);
        return VW_ERR_IO;
    }

    DWORD written = 0;
    if (!WriteFile(fh, data, (DWORD)len, &written, NULL) || written != (DWORD)len) {
        CloseHandle(fh);
        return VW_ERR_IO;
    }
    CloseHandle(fh);
    return VW_OK;
#else
    size_t pos = 0;
    int fd = open(path, O_RDWR);
    if (fd < 0) return VW_ERR_IO;

    while (pos < len) {
        ssize_t n = pwrite(fd, (const char *)data + pos, len - pos,
                           (off_t)(offset + pos));
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return VW_ERR_IO;
        }
        pos += (size_t)n;
    }
    close(fd);
    return VW_OK;
#endif
}

vw_err_t vw_fs_sync_file(const char *path) {
    if (!path) return VW_ERR_INVALID_ARG;
#ifdef _WIN32
    HANDLE fh = CreateFileA(path, GENERIC_WRITE | GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fh == INVALID_HANDLE_VALUE) return VW_ERR_IO;
    BOOL ok = FlushFileBuffers(fh);
    CloseHandle(fh);
    return ok ? VW_OK : VW_ERR_IO;
#else
    int fd = open(path, O_RDWR);
    if (fd < 0) return VW_ERR_IO;
    int rc = fsync(fd);
    close(fd);
    return (rc == 0) ? VW_OK : VW_ERR_IO;
#endif
}

/* ── Directory listing ───────────────────────────────────────────────────── */

vw_err_t vw_fs_list_dir(const char *dir,
                         int (*cb)(const char *name, void *userdata),
                         void *userdata) {
    if (!dir || !cb) return VW_ERR_INVALID_ARG;
#ifdef _WIN32
    char pattern[4096];
    int n = snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    if (n < 0 || (size_t)n >= sizeof(pattern)) return VW_ERR_INVALID_ARG;

    WIN32_FIND_DATAA ffd;
    HANDLE h = FindFirstFileA(pattern, &ffd);
    if (h == INVALID_HANDLE_VALUE) return VW_ERR_IO;

    do {
        if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0)
            continue;
        if (cb(ffd.cFileName, userdata) != 0) break;
    } while (FindNextFileA(h, &ffd));
    FindClose(h);
    return VW_OK;
#else
    DIR *d = opendir(dir);
    if (!d) return VW_ERR_IO;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        if (cb(ent->d_name, userdata) != 0) break;
    }
    closedir(d);
    return VW_OK;
#endif
}

/* ── Chunk reader ────────────────────────────────────────────────────────── */

/* We store the platform file handle at the start of the opaque array */

#ifdef _WIN32
typedef struct { HANDLE fh; int done; } ChunkReaderState;
#else
typedef struct { int fd; int done; } ChunkReaderState;
#endif

vw_err_t vw_fs_chunk_open(const char *path, vw_fs_chunk_ctx_t *ctx) {
    ChunkReaderState *s = (ChunkReaderState *)(void *)ctx->_opaque;
#ifdef _WIN32
    s->fh = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (s->fh == INVALID_HANDLE_VALUE) {
        return (GetLastError() == ERROR_FILE_NOT_FOUND)
               ? VW_ERR_NOT_FOUND : VW_ERR_IO;
    }
#else
    s->fd = open(path, O_RDONLY);
    if (s->fd < 0) return (errno == ENOENT) ? VW_ERR_NOT_FOUND : VW_ERR_IO;
#endif
    s->done = 0;
    return VW_OK;
}

vw_err_t vw_fs_chunk_next(vw_fs_chunk_ctx_t *ctx,
                           uint8_t *out_buf, size_t *out_len,
                           int *out_is_last) {
    ChunkReaderState *s = (ChunkReaderState *)(void *)ctx->_opaque;
    if (s->done) return VW_ERR_NOT_FOUND;

#ifdef _WIN32
    DWORD nread = 0;
    if (!ReadFile(s->fh, out_buf, (DWORD)VW_CHUNK_SIZE, &nread, NULL))
        return VW_ERR_IO;
    *out_len = (size_t)nread;
#else
    size_t pos = 0;
    while (pos < VW_CHUNK_SIZE) {
        ssize_t n = read(s->fd, out_buf + pos, VW_CHUNK_SIZE - pos);
        if (n < 0) { if (errno == EINTR) continue; return VW_ERR_IO; }
        if (n == 0) break;
        pos += (size_t)n;
    }
    *out_len = pos;
#endif

    if (*out_len < VW_CHUNK_SIZE) {
        *out_is_last = 1;
        s->done = 1;
    } else {
        *out_is_last = 0;
    }
    return VW_OK;
}

void vw_fs_chunk_close(vw_fs_chunk_ctx_t *ctx) {
    ChunkReaderState *s = (ChunkReaderState *)(void *)ctx->_opaque;
#ifdef _WIN32
    if (s->fh != INVALID_HANDLE_VALUE) { CloseHandle(s->fh); s->fh = INVALID_HANDLE_VALUE; }
#else
    if (s->fd >= 0) { close(s->fd); s->fd = -1; }
#endif
}

/* ── Chunk writer ────────────────────────────────────────────────────────── */

#ifdef _WIN32
typedef struct { HANDLE fh; } ChunkWriterState;
#else
typedef struct { int fd; } ChunkWriterState;
#endif

vw_err_t vw_fs_chunk_writer_open(const char *path,
                                  vw_fs_chunk_writer_ctx_t *ctx) {
    ChunkWriterState *s = (ChunkWriterState *)(void *)ctx->_opaque;
#ifdef _WIN32
    s->fh = CreateFileA(path, GENERIC_WRITE, 0, NULL,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (s->fh == INVALID_HANDLE_VALUE) return VW_ERR_IO;
#else
    s->fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (s->fd < 0) return VW_ERR_IO;
#endif
    return VW_OK;
}

vw_err_t vw_fs_chunk_writer_append(vw_fs_chunk_writer_ctx_t *ctx,
                                    const void *data, size_t len) {
    ChunkWriterState *s = (ChunkWriterState *)(void *)ctx->_opaque;
#ifdef _WIN32
    DWORD written;
    if (!WriteFile(s->fh, data, (DWORD)len, &written, NULL) || written != len)
        return VW_ERR_IO;
#else
    size_t pos = 0;
    while (pos < len) {
        ssize_t n = write(s->fd, (const char *)data + pos, len - pos);
        if (n < 0) { if (errno == EINTR) continue; return VW_ERR_IO; }
        pos += (size_t)n;
    }
#endif
    return VW_OK;
}

vw_err_t vw_fs_chunk_writer_close(vw_fs_chunk_writer_ctx_t *ctx) {
    ChunkWriterState *s = (ChunkWriterState *)(void *)ctx->_opaque;
#ifdef _WIN32
    if (!FlushFileBuffers(s->fh)) { CloseHandle(s->fh); return VW_ERR_IO; }
    CloseHandle(s->fh);
    s->fh = INVALID_HANDLE_VALUE;
#else
    if (fdatasync(s->fd) != 0) { close(s->fd); s->fd = -1; return VW_ERR_IO; }
    close(s->fd);
    s->fd = -1;
#endif
    return VW_OK;
}

void vw_fs_chunk_writer_abort(vw_fs_chunk_writer_ctx_t *ctx) {
    ChunkWriterState *s = (ChunkWriterState *)(void *)ctx->_opaque;
#ifdef _WIN32
    if (s->fh != INVALID_HANDLE_VALUE) { CloseHandle(s->fh); s->fh = INVALID_HANDLE_VALUE; }
#else
    if (s->fd >= 0) { close(s->fd); s->fd = -1; }
#endif
}
