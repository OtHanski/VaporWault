/*
 * vw_oplog.c — append-only, segmented, crash-safe operation log.
 *
 * See vw_oplog.h for the full design description.
 *
 * On-disk entry layout (little-endian, packed):
 *   Offset  Size  Field
 *   0       4     crc32         (covers bytes 4..end of entry)
 *   4       4     payload_len   (= 1 + caller's payload_len: includes op_type byte)
 *   8       8     entry_id
 *   16      1     confirmed     (NOT CRC-covered; 0 = pending, 1 = committed)
 *   17      1     op_type
 *   18      N     op_payload    (N = payload_len - 1)
 *
 *   Total entry size on disk = 4 + 4 + 8 + 1 + payload_len = 17 + payload_len bytes.
 *
 *   crc32 covers bytes 4..15 (payload_len + entry_id) plus all payload bytes.
 *   The confirmed byte at offset 16 is excluded from the CRC so it can be
 *   updated in-place by vw_oplog_confirm() without recomputing the CRC.
 *
 * CRC-32 uses the ISO 3309 / Ethernet polynomial 0xEDB88320 (reflected).
 */

#include "vw_oplog.h"
#include "../core/vw_fs.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
#else
#   include <pthread.h>
#   include <dirent.h>
#   include <fcntl.h>
#   include <unistd.h>
#   include <sys/stat.h>
#endif

/* ── Fixed sizes ─────────────────────────────────────────────────────────── */

/*
 * Full fixed header = crc32(4) + payload_len(4) + entry_id(8) + confirmed(1) = 17 bytes.
 * Then payload_len bytes follow (op_type + op_payload).
 *
 * CRC covers bytes 4..15 (payload_len + entry_id = 12 bytes) plus the entire
 * payload (op_type byte + op_payload bytes = payload_len bytes total).
 * The confirmed byte at offset 16 is intentionally excluded.
 */
#define ENTRY_HDR_SIZE        17u  /* crc32(4) + payload_len(4) + entry_id(8) + confirmed(1) */
#define ENTRY_CONFIRMED_OFF   16u  /* byte offset of the confirmed field within each entry    */
#define CRC_HEADER_BYTES      12u  /* CRC-covered header bytes: payload_len(4) + entry_id(8) */

/* Maximum number of entries awaiting vw_oplog_confirm() at any one time. */
#define VW_OPLOG_MAX_PENDING  64u

/* ── CRC-32 (ISO 3309, polynomial 0xEDB88320) ───────────────────────────── */

static uint32_t s_crc32_table[256];

#ifdef _WIN32
static INIT_ONCE s_crc32_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK crc32_init_once_win(PINIT_ONCE o, PVOID p, PVOID *c)
{
    (void)o; (void)p; (void)c;
    uint32_t i, j, cv;
    for (i = 0; i < 256; i++) {
        cv = i;
        for (j = 0; j < 8; j++) {
            if (cv & 1u) cv = 0xEDB88320u ^ (cv >> 1);
            else         cv >>= 1;
        }
        s_crc32_table[i] = cv;
    }
    return TRUE;
}
static void crc32_init_table(void) {
    InitOnceExecuteOnce(&s_crc32_once, crc32_init_once_win, NULL, NULL);
}
#else
static pthread_once_t s_crc32_once = PTHREAD_ONCE_INIT;
static void crc32_fill_table(void)
{
    uint32_t i, j, c;
    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++) {
            if (c & 1u) c = 0xEDB88320u ^ (c >> 1);
            else        c >>= 1;
        }
        s_crc32_table[i] = c;
    }
}
static void crc32_init_table(void) { pthread_once(&s_crc32_once, crc32_fill_table); }
#endif

static uint32_t crc32_update(uint32_t crc, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    crc = ~crc;
    while (len--) crc = s_crc32_table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

/* ── Platform mutex ─────────────────────────────────────────────────────── */

#ifdef _WIN32
typedef CRITICAL_SECTION vw_mutex_t;
static void mutex_init(vw_mutex_t *m)    { InitializeCriticalSection(m); }
static void mutex_destroy(vw_mutex_t *m) { DeleteCriticalSection(m); }
static void mutex_lock(vw_mutex_t *m)    { EnterCriticalSection(m); }
static void mutex_unlock(vw_mutex_t *m)  { LeaveCriticalSection(m); }
#else
typedef pthread_mutex_t vw_mutex_t;
static void mutex_init(vw_mutex_t *m)    { pthread_mutex_init(m, NULL); }
static void mutex_destroy(vw_mutex_t *m) { pthread_mutex_destroy(m); }
static void mutex_lock(vw_mutex_t *m)    { pthread_mutex_lock(m); }
static void mutex_unlock(vw_mutex_t *m)  { pthread_mutex_unlock(m); }
#endif

/* ── Platform file I/O ──────────────────────────────────────────────────── */

#ifdef _WIN32
typedef HANDLE vw_fd_t;
#define VW_FD_INVALID  INVALID_HANDLE_VALUE

static vw_fd_t fd_open_append(const char *path)
{
    /* GENERIC_READ is required so that GetFileSizeEx (used in fd_size) succeeds
     * on this handle.  FILE_APPEND_DATA alone does not include FILE_READ_ATTRIBUTES,
     * causing GetFileSizeEx to return ERROR_ACCESS_DENIED and fd_size to return -1,
     * which breaks the fd_write failure path in vw_oplog_append. */
    HANDLE h = CreateFileA(path,
                           GENERIC_READ | FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL,
                           OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    return h;
}

static vw_fd_t fd_open_read(const char *path)
{
    HANDLE h = CreateFileA(path,
                           GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    return h;
}

/* GENERIC_WRITE needed for SetEndOfFile (fd_truncate) and in-place pwrite. */
static vw_fd_t fd_open_readwrite(const char *path)
{
    HANDLE h = CreateFileA(path,
                           GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL,
                           OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    return h;
}

static void fd_close(vw_fd_t fd)
{
    if (fd != INVALID_HANDLE_VALUE) CloseHandle(fd);
}

static int fd_write(vw_fd_t fd, const void *buf, uint32_t len)
{
    DWORD written = 0;
    return WriteFile(fd, buf, (DWORD)len, &written, NULL) && written == (DWORD)len ? 0 : -1;
}

static int fd_sync(vw_fd_t fd)
{
    return FlushFileBuffers(fd) ? 0 : -1;
}

/* Returns bytes read, -1 on error, 0 on EOF. */
static int fd_read(vw_fd_t fd, void *buf, uint32_t len)
{
    DWORD got = 0;
    if (!ReadFile(fd, buf, (DWORD)len, &got, NULL)) return -1;
    return (int)got;
}

static int64_t fd_seek(vw_fd_t fd, int64_t offset, int whence)
{
    LARGE_INTEGER li, out;
    li.QuadPart = offset;
    DWORD method = (whence == SEEK_SET) ? FILE_BEGIN :
                   (whence == SEEK_CUR) ? FILE_CURRENT : FILE_END;
    if (!SetFilePointerEx(fd, li, &out, method)) return -1;
    return (int64_t)out.QuadPart;
}

static int64_t fd_tell(vw_fd_t fd)
{
    return fd_seek(fd, 0, SEEK_CUR);
}

static int64_t fd_size(vw_fd_t fd)
{
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(fd, &sz)) return -1;
    return (int64_t)sz.QuadPart;
}

static int fd_truncate(vw_fd_t fd, int64_t new_size)
{
    if (fd_seek(fd, new_size, SEEK_SET) < 0) return -1;
    return SetEndOfFile(fd) ? 0 : -1;
}

#else /* POSIX */

typedef int vw_fd_t;
#define VW_FD_INVALID  (-1)

static vw_fd_t fd_open_append(const char *path)
{
    return open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
}

static vw_fd_t fd_open_read(const char *path)
{
    return open(path, O_RDONLY);
}

static vw_fd_t fd_open_readwrite(const char *path)
{
    return open(path, O_RDWR);
}

static void fd_close(vw_fd_t fd)
{
    if (fd >= 0) close(fd);
}

static int fd_write(vw_fd_t fd, const void *buf, uint32_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint32_t rem = len;
    while (rem > 0) {
        ssize_t n = write(fd, p, rem);
        if (n <= 0) return -1;
        p += n; rem -= (uint32_t)n;
    }
    return 0;
}

static int fd_sync(vw_fd_t fd)
{
    return fdatasync(fd);
}

static int fd_read(vw_fd_t fd, void *buf, uint32_t len)
{
    ssize_t n = read(fd, buf, len);
    return (int)n;
}

static int64_t fd_seek(vw_fd_t fd, int64_t offset, int whence)
{
    return (int64_t)lseek(fd, (off_t)offset, whence);
}

static int64_t fd_tell(vw_fd_t fd)
{
    return fd_seek(fd, 0, SEEK_CUR);
}

static int64_t fd_size(vw_fd_t fd)
{
    off_t cur = lseek(fd, 0, SEEK_CUR);
    if (cur < 0) return -1;
    off_t end = lseek(fd, 0, SEEK_END);
    lseek(fd, cur, SEEK_SET);
    return (int64_t)end;
}

static int fd_truncate(vw_fd_t fd, int64_t new_size)
{
    return ftruncate(fd, (off_t)new_size);
}

#endif /* _WIN32 / POSIX */

/* ── Segment list ───────────────────────────────────────────────────────── */

/*
 * Each known segment is described by its first entry_id.
 * We keep a sorted (ascending) array; the last element is always the active
 * (write) segment.
 */
typedef struct {
    uint64_t first_id;   /* first entry_id in this segment  */
} vw_seg_info_t;

/*
 * An entry appended but not yet confirmed.  Stored until vw_oplog_confirm()
 * is called for the matching entry_id.
 */
typedef struct {
    uint64_t entry_id;
    uint64_t seg_first_id;   /* which segment contains the entry        */
    int64_t  confirmed_off;  /* byte offset of confirmed byte in segment */
} vw_pending_entry_t;

/* ── Internal context ───────────────────────────────────────────────────── */

struct vw_oplog {
    char          oplog_dir[4096];  /* path to the oplog/ directory  */
    uint64_t      next_entry_id;    /* next ID to assign (1-based)   */
    uint64_t      last_entry_id;    /* last successfully written ID   */

    /* Active write segment */
    vw_fd_t       seg_fd;           /* write descriptor              */
    uint64_t      seg_first_id;     /* first entry_id in active seg  */
    uint64_t      seg_bytes;        /* bytes written so far          */

    /* Segment index (all segments, sorted ascending by first_id) */
    vw_seg_info_t *segs;
    size_t         segs_len;
    size_t         segs_cap;

    /* Pending confirms: appended but not yet committed entries */
    vw_pending_entry_t pending[VW_OPLOG_MAX_PENDING];
    size_t             pending_len;

    vw_mutex_t     mu;
};

/* ── Helpers ────────────────────────────────────────────────────────────── */

static void seg_path(const vw_oplog_t *ctx, uint64_t first_id,
                     char *out, size_t out_size)
{
    snprintf(out, out_size, "%s/%016llx.log",
             ctx->oplog_dir, (unsigned long long)first_id);
}

/* Insert a segment entry (sorted ascending). */
static vw_err_t segs_insert(vw_oplog_t *ctx, uint64_t first_id)
{
    /* Grow if needed */
    if (ctx->segs_len == ctx->segs_cap) {
        size_t new_cap = ctx->segs_cap ? ctx->segs_cap * 2 : 8;
        vw_seg_info_t *p = (vw_seg_info_t *)realloc(ctx->segs,
                                new_cap * sizeof(vw_seg_info_t));
        if (!p) return VW_ERR_OOM;
        ctx->segs     = p;
        ctx->segs_cap = new_cap;
    }

    /* Find insertion point */
    size_t i = ctx->segs_len;
    while (i > 0 && ctx->segs[i-1].first_id > first_id) i--;

    /* Shift right */
    memmove(&ctx->segs[i+1], &ctx->segs[i],
            (ctx->segs_len - i) * sizeof(vw_seg_info_t));
    ctx->segs[i].first_id = first_id;
    ctx->segs_len++;
    return VW_OK;
}

/* ── Segment scanning (crash recovery) ─────────────────────────────────── */

/*
 * Read the given segment file from the beginning.  Find the last contiguous
 * run of entries that have a valid CRC.  If a partial or corrupt entry is
 * found at the tail, truncate the file there.
 *
 * Sets *out_last_id to the last valid entry_id (0 if the segment is empty).
 * Sets *out_end_offset to the file offset just after the last valid entry.
 */
static vw_err_t seg_scan(const char *path,
                          uint64_t *out_last_id,
                          int64_t  *out_end_offset)
{
    *out_last_id   = 0;
    *out_end_offset = 0;

    vw_fd_t fd = fd_open_read(path);
    if (fd == VW_FD_INVALID) return VW_ERR_IO;

    int64_t last_good_offset = 0;
    uint64_t last_good_id    = 0;
    uint8_t  hdr[ENTRY_HDR_SIZE];

    for (;;) {
        /* Read fixed header (17 bytes: crc32+payload_len+entry_id+confirmed) */
        int n = fd_read(fd, hdr, ENTRY_HDR_SIZE);
        if (n == 0) break;                   /* clean EOF          */
        if (n < (int)ENTRY_HDR_SIZE) break;  /* partial header — corrupt tail */

        uint32_t stored_crc  = vw_read_u32le(hdr + 0);
        uint32_t payload_len = vw_read_u32le(hdr + 4);
        uint64_t entry_id    = vw_read_u64le(hdr + 8);
        uint8_t  confirmed   = hdr[ENTRY_CONFIRMED_OFF]; /* offset 16 */

        if (payload_len == 0) break;   /* malformed */
        if (payload_len > VW_OPLOG_SEGMENT_MAX) break; /* malformed — exceeds segment cap */

        /* Read payload (op_type byte + op_payload) */
        uint8_t *payload = (uint8_t *)malloc(payload_len);
        if (!payload) {
            fd_close(fd);
            return VW_ERR_OOM;
        }

        uint32_t got = 0;
        while (got < payload_len) {
            int r = fd_read(fd, payload + got, payload_len - got);
            if (r <= 0) { got = 0; break; }
            got += (uint32_t)r;
        }
        if (got < payload_len) {
            /* Incomplete payload — corrupt tail */
            free(payload);
            break;
        }

        /* Verify CRC: covers hdr[4..15] (payload_len+entry_id) + payload.
         * The confirmed byte (hdr[16]) is intentionally excluded from CRC. */
        uint32_t crc = 0;
        crc = crc32_update(crc, hdr + 4, CRC_HEADER_BYTES);
        crc = crc32_update(crc, payload, payload_len);

        free(payload);

        if (crc != stored_crc) {
            /* Bad CRC — corrupt tail */
            break;
        }

        if (confirmed == 0) {
            /* Unconfirmed entry: server crashed before vw_oplog_confirm().
             * Skip it (continue scanning) so that confirmed==1 entries later
             * in the segment (from other concurrent transactions) are preserved.
             * The file is truncated only after the LAST confirmed==1 entry, so
             * trailing unconfirmed entries are removed but interior holes remain
             * (they are skipped by vw_oplog_replay_from). */
            continue;
        }

        last_good_id = entry_id;
        int64_t tell = fd_tell(fd);
        if (tell >= 0) last_good_offset = tell;
    }

    fd_close(fd);

    /* Truncate any corrupt tail */
    {
        int64_t sz = 0;
        vw_err_t vw_rc = vw_fs_file_size(path, (uint64_t *)&sz);
        if (vw_rc != VW_OK) return vw_rc;
        if (last_good_offset < sz) {
            /* fd_open_readwrite: GENERIC_WRITE needed for SetEndOfFile on Win32 */
            vw_fd_t wfd = fd_open_readwrite(path);
            if (wfd == VW_FD_INVALID || fd_truncate(wfd, last_good_offset) != 0) {
                fd_close(wfd);
                return VW_ERR_IO;
            }
            fd_close(wfd);
        }
    }

    *out_last_id   = last_good_id;
    *out_end_offset = last_good_offset;
    return VW_OK;
}

/* ── Directory enumeration ─────────────────────────────────────────────── */

#ifdef _WIN32

static vw_err_t enumerate_segments(vw_oplog_t *ctx)
{
    char pattern[4096 + 8];
    snprintf(pattern, sizeof(pattern), "%s\\*.log", ctx->oplog_dir);

    WIN32_FIND_DATAA fd_data;
    HANDLE h = FindFirstFileA(pattern, &fd_data);
    if (h == INVALID_HANDLE_VALUE) return VW_OK; /* no segments yet */

    do {
        const char *name = fd_data.cFileName;
        size_t nlen = strlen(name);
        if (nlen < 20) continue;          /* too short: not %016llx.log */
        /* Parse first 16 hex characters */
        uint64_t first_id = 0;
        int ok = 1;
        for (int i = 0; i < 16; i++) {
            char c = name[i];
            uint64_t nibble;
            if (c >= '0' && c <= '9')      nibble = (uint64_t)(c - '0');
            else if (c >= 'a' && c <= 'f') nibble = (uint64_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') nibble = (uint64_t)(c - 'A' + 10);
            else { ok = 0; break; }
            first_id = (first_id << 4) | nibble;
        }
        if (!ok) continue;
        vw_err_t si_rc = segs_insert(ctx, first_id);
        if (si_rc != VW_OK) { FindClose(h); return si_rc; }
    } while (FindNextFileA(h, &fd_data));

    FindClose(h);
    return VW_OK;
}

#else /* POSIX */

static vw_err_t enumerate_segments(vw_oplog_t *ctx)
{
    DIR *d = opendir(ctx->oplog_dir);
    if (!d) return VW_OK; /* not created yet */

    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        const char *name = de->d_name;
        size_t nlen = strlen(name);
        if (nlen < 20) continue;    /* %016llx.log == 20 chars */
        uint64_t first_id = 0;
        int ok = 1;
        for (int i = 0; i < 16; i++) {
            char c = name[i];
            uint64_t nibble;
            if (c >= '0' && c <= '9')      nibble = (uint64_t)(c - '0');
            else if (c >= 'a' && c <= 'f') nibble = (uint64_t)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') nibble = (uint64_t)(c - 'A' + 10);
            else { ok = 0; break; }
            first_id = (first_id << 4) | nibble;
        }
        if (!ok) continue;
        vw_err_t si_rc = segs_insert(ctx, first_id);
        if (si_rc != VW_OK) { closedir(d); return si_rc; }
    }
    closedir(d);
    return VW_OK;
}

#endif /* _WIN32 / POSIX */

/* ── Segment rotation ───────────────────────────────────────────────────── */

/*
 * Close current write segment and open a new one starting at next_entry_id.
 * Must be called with mutex held.
 */
static vw_err_t rotate_segment(vw_oplog_t *ctx)
{
    fd_close(ctx->seg_fd);
    ctx->seg_fd = VW_FD_INVALID;

    uint64_t new_first = ctx->next_entry_id;
    char path[4096 + 32];
    seg_path(ctx, new_first, path, sizeof(path));

    vw_fd_t fd = fd_open_append(path);
    if (fd == VW_FD_INVALID) return VW_ERR_IO;

    vw_err_t rc = segs_insert(ctx, new_first);
    if (rc != VW_OK) {
        fd_close(fd);
        return rc;
    }

    ctx->seg_fd       = fd;
    ctx->seg_first_id = new_first;
    ctx->seg_bytes    = 0;
    return VW_OK;
}

/* ── vw_oplog_open ──────────────────────────────────────────────────────── */

vw_err_t vw_oplog_open(const char *data_dir, vw_oplog_t **out_ctx)
{
    if (!data_dir || !out_ctx) return VW_ERR_INVALID_ARG;

    crc32_init_table();

    vw_oplog_t *ctx = (vw_oplog_t *)calloc(1, sizeof(vw_oplog_t));
    if (!ctx) return VW_ERR_OOM;

    mutex_init(&ctx->mu);
    ctx->seg_fd = VW_FD_INVALID;

    /* Build oplog dir path */
    {
        int n = snprintf(ctx->oplog_dir, sizeof(ctx->oplog_dir),
                         "%s/oplog", data_dir);
        if (n < 0 || (size_t)n >= sizeof(ctx->oplog_dir)) {
            free(ctx);
            return VW_ERR_INVALID_ARG;
        }
    }

    /* Create the directory if it doesn't exist */
    vw_err_t rc = vw_fs_ensure_dir(ctx->oplog_dir);
    if (rc != VW_OK) { mutex_destroy(&ctx->mu); free(ctx); return rc; }

    /* Enumerate existing segment files */
    rc = enumerate_segments(ctx);
    if (rc != VW_OK) { mutex_destroy(&ctx->mu); free(ctx->segs); free(ctx); return rc; }

    if (ctx->segs_len == 0) {
        /* No existing segments — brand new log.  Active segment starts at 1. */
        ctx->next_entry_id = 1;
        ctx->last_entry_id = 0;
        ctx->seg_first_id  = 1;

        char path[4096 + 32];
        seg_path(ctx, 1, path, sizeof(path));
        ctx->seg_fd = fd_open_append(path);
        if (ctx->seg_fd == VW_FD_INVALID) {
            mutex_destroy(&ctx->mu); free(ctx->segs); free(ctx); return VW_ERR_IO;
        }
        rc = segs_insert(ctx, 1);
        if (rc != VW_OK) {
            fd_close(ctx->seg_fd); mutex_destroy(&ctx->mu); free(ctx->segs); free(ctx); return rc;
        }
        ctx->seg_bytes = 0;
    } else {
        /* Recover: scan the latest segment for the last valid entry */
        uint64_t active_first = ctx->segs[ctx->segs_len - 1].first_id;
        char path[4096 + 32];
        seg_path(ctx, active_first, path, sizeof(path));

        uint64_t last_id       = 0;
        int64_t  end_offset    = 0;
        rc = seg_scan(path, &last_id, &end_offset);
        if (rc != VW_OK) {
            mutex_destroy(&ctx->mu); free(ctx->segs); free(ctx); return rc;
        }

        ctx->last_entry_id = last_id;
        ctx->next_entry_id = last_id + 1;
        ctx->seg_first_id  = active_first;

        /* Open for appending (positioned at EOF by O_APPEND / FILE_APPEND_DATA) */
        ctx->seg_fd = fd_open_append(path);
        if (ctx->seg_fd == VW_FD_INVALID) {
            mutex_destroy(&ctx->mu); free(ctx->segs); free(ctx); return VW_ERR_IO;
        }
        ctx->seg_bytes = (uint64_t)end_offset;
    }

    *out_ctx = ctx;
    return VW_OK;
}

/* ── vw_oplog_close ─────────────────────────────────────────────────────── */

void vw_oplog_close(vw_oplog_t *ctx)
{
    if (!ctx) return;
    fd_close(ctx->seg_fd);
    mutex_destroy(&ctx->mu);
    free(ctx->segs);
    free(ctx);
}

/* ── vw_oplog_append ────────────────────────────────────────────────────── */

vw_err_t vw_oplog_append(vw_oplog_t *ctx,
                          vw_oplog_op_t op_type,
                          const void *payload, uint32_t payload_len,
                          uint64_t *out_entry_id)
{
    if (!ctx) return VW_ERR_INVALID_ARG;
    /* payload may be NULL only when payload_len == 0 */
    if (payload_len > 0 && !payload) return VW_ERR_INVALID_ARG;
    /* Guard: payload_len + 1u must not wrap to 0 */
    if (payload_len > UINT32_MAX - 1u) return VW_ERR_INVALID_ARG;

    /*
     * On-disk payload_len field = 1 (op_type byte) + caller's payload_len.
     * So the minimum stored payload_len is 1.
     */
    uint32_t stored_plen = payload_len + 1u;

    mutex_lock(&ctx->mu);

    /* Reject early if pending-confirm array is full: checking before any I/O
     * (including segment rotation) prevents creating an empty orphaned segment
     * that would confuse crash recovery. */
    if (ctx->pending_len >= VW_OPLOG_MAX_PENDING) {
        mutex_unlock(&ctx->mu);
        return VW_ERR_INVALID_ARG;
    }

    /* Rotate segment if needed */
    if (ctx->seg_bytes >= VW_OPLOG_SEGMENT_MAX) {
        vw_err_t rc = rotate_segment(ctx);
        if (rc != VW_OK) { mutex_unlock(&ctx->mu); return rc; }
    }

    uint64_t eid = ctx->next_entry_id;

    /* Build CRC-covered header bytes: [payload_len(4)][entry_id(8)] = 12 bytes.
     * The confirmed byte (offset 16) is NOT included in the CRC. */
    uint8_t crc_hdr[CRC_HEADER_BYTES];
    vw_write_u32le(crc_hdr + 0, stored_plen);
    vw_write_u64le(crc_hdr + 4, eid);

    /* CRC covers: crc_hdr(12) + op_type(1) + payload(payload_len) */
    uint32_t crc = 0;
    crc = crc32_update(crc, crc_hdr, CRC_HEADER_BYTES);
    uint8_t op_byte = (uint8_t)op_type;
    crc = crc32_update(crc, &op_byte, 1);
    if (payload_len > 0)
        crc = crc32_update(crc, payload, payload_len);

    /* Serialise full entry into one buffer for a single write syscall.
     * Layout: [crc32(4)][payload_len(4)][entry_id(8)][confirmed(1)][op_type(1)][op_payload(N)]
     * Total  = ENTRY_HDR_SIZE(17) + stored_plen bytes. */
    size_t total = ENTRY_HDR_SIZE + stored_plen;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (!buf) { mutex_unlock(&ctx->mu); return VW_ERR_OOM; }

    vw_write_u32le(buf + 0, crc);
    vw_write_u32le(buf + 4, stored_plen);
    vw_write_u64le(buf + 8, eid);
    buf[ENTRY_CONFIRMED_OFF] = 0;   /* confirmed = 0 (pending) */
    buf[17]                  = op_byte;
    if (payload_len > 0)
        memcpy(buf + 18, payload, payload_len);

    /* Record the byte offset of the confirmed field before incrementing seg_bytes.
     * O_APPEND / FILE_APPEND_DATA writes start at file offset ctx->seg_bytes. */
    int64_t confirmed_off = (int64_t)ctx->seg_bytes + ENTRY_CONFIRMED_OFF;

    int wrc = fd_write(ctx->seg_fd, buf, (uint32_t)total);
    free(buf);

    if (wrc != 0) {
        /* Partial write may have occurred (EINTR, POSIX); re-sync seg_bytes from the
         * real file size so the next append's confirmed_off is not based on stale state.
         * fd_size calls GetFileSizeEx on Windows, which requires FILE_READ_ATTRIBUTES —
         * included via GENERIC_READ in fd_open_append (see TASK-019). */
        int64_t real_sz = fd_size(ctx->seg_fd);
        if (real_sz >= 0) ctx->seg_bytes = (uint64_t)real_sz;
        mutex_unlock(&ctx->mu);
        return VW_ERR_IO;
    }

    /* Flush for durability */
    if (fd_sync(ctx->seg_fd) != 0) {
        /* Write is in the kernel buffer; advance seg_bytes so the next append
         * is positioned correctly even though this entry is not yet durable. */
        ctx->seg_bytes += total;
        mutex_unlock(&ctx->mu);
        return VW_ERR_IO;
    }

    ctx->seg_bytes     += total;
    ctx->last_entry_id  = eid;
    ctx->next_entry_id  = eid + 1;

    /* Register in the pending-confirm set */
    ctx->pending[ctx->pending_len].entry_id      = eid;
    ctx->pending[ctx->pending_len].seg_first_id  = ctx->seg_first_id;
    ctx->pending[ctx->pending_len].confirmed_off = confirmed_off;
    ctx->pending_len++;

    if (out_entry_id) *out_entry_id = eid;

    mutex_unlock(&ctx->mu);
    return VW_OK;
}

/* ── vw_oplog_confirm ───────────────────────────────────────────────────── */

vw_err_t vw_oplog_confirm(vw_oplog_t *ctx, uint64_t entry_id)
{
    if (!ctx) return VW_ERR_INVALID_ARG;

    mutex_lock(&ctx->mu);

    /* Find in pending array */
    size_t idx;
    for (idx = 0; idx < ctx->pending_len; idx++) {
        if (ctx->pending[idx].entry_id == entry_id) break;
    }
    if (idx >= ctx->pending_len) {
        mutex_unlock(&ctx->mu);
        return VW_ERR_NOT_FOUND;
    }

    int64_t  confirmed_off = ctx->pending[idx].confirmed_off;
    uint64_t seg_fid       = ctx->pending[idx].seg_first_id;

    /* Build segment file path while still holding the lock. */
    char path[4096 + 32];
    seg_path(ctx, seg_fid, path, sizeof(path));

    /* Open the segment for in-place write.  The append handle (ctx->seg_fd)
     * uses FILE_SHARE_WRITE on Windows, so this open succeeds concurrently. */
    vw_fd_t wfd = fd_open_readwrite(path);
    if (wfd == VW_FD_INVALID) {
        mutex_unlock(&ctx->mu);
        return VW_ERR_IO;
    }

    vw_err_t rc = VW_OK;

    if (fd_seek(wfd, confirmed_off, SEEK_SET) < 0) {
        rc = VW_ERR_IO;
        goto done;
    }

    {
        uint8_t one = 1;
        if (fd_write(wfd, &one, 1) != 0) { rc = VW_ERR_IO; goto done; }
    }

    if (fd_sync(wfd) != 0) { rc = VW_ERR_IO; goto done; }

    /* Remove from pending array only after the write has been durably synced. */
    memmove(&ctx->pending[idx], &ctx->pending[idx + 1],
            (ctx->pending_len - idx - 1) * sizeof(vw_pending_entry_t));
    ctx->pending_len--;

done:
    fd_close(wfd);
    mutex_unlock(&ctx->mu);
    return rc;
}

/* ── vw_oplog_abort ─────────────────────────────────────────────────────── */

vw_err_t vw_oplog_abort(vw_oplog_t *ctx, uint64_t entry_id)
{
    if (!ctx) return VW_ERR_INVALID_ARG;

    mutex_lock(&ctx->mu);

    size_t idx;
    for (idx = 0; idx < ctx->pending_len; idx++) {
        if (ctx->pending[idx].entry_id == entry_id) break;
    }
    if (idx >= ctx->pending_len) {
        mutex_unlock(&ctx->mu);
        return VW_ERR_NOT_FOUND;
    }

    /* Drop from pending without touching the file.  The confirmed=0 entry is
     * treated as an unconfirmed hole by seg_scan on next open, so no data
     * action is needed here.  Callers must ensure the corresponding data-table
     * write has already been rolled back before calling vw_oplog_abort. */
    ctx->pending_len--;
    if (idx < ctx->pending_len)
        memmove(&ctx->pending[idx], &ctx->pending[idx + 1],
                (ctx->pending_len - idx) * sizeof(vw_pending_entry_t));

    mutex_unlock(&ctx->mu);
    return VW_OK;
}

/* ── vw_oplog_replay_from ───────────────────────────────────────────────── */

vw_err_t vw_oplog_replay_from(vw_oplog_t *ctx,
                               uint64_t from_entry_id,
                               int (*callback)(uint64_t, vw_oplog_op_t,
                                               const void *, uint32_t, void *),
                               void *userdata)
{
    if (!ctx || !callback) return VW_ERR_INVALID_ARG;

    /*
     * We need to read segments.  We take the lock only to snapshot the segment
     * list and last_entry_id, then release it while doing file I/O.  The active
     * segment may grow during iteration; we will simply stop at the end of each
     * segment file naturally (EOF).
     */
    mutex_lock(&ctx->mu);
    size_t n_segs = ctx->segs_len;
    vw_seg_info_t *segs_copy = NULL;
    if (n_segs > 0) {
        segs_copy = (vw_seg_info_t *)malloc(n_segs * sizeof(vw_seg_info_t));
        if (!segs_copy) { mutex_unlock(&ctx->mu); return VW_ERR_OOM; }
        memcpy(segs_copy, ctx->segs, n_segs * sizeof(vw_seg_info_t));
    }
    char oplog_dir[4096];
    strncpy(oplog_dir, ctx->oplog_dir, sizeof(oplog_dir) - 1);
    oplog_dir[sizeof(oplog_dir)-1] = '\0';
    mutex_unlock(&ctx->mu);

    vw_err_t rc = VW_OK;
    int stop    = 0;

    for (size_t si = 0; si < n_segs && !stop; si++) {
        uint64_t seg_first = segs_copy[si].first_id;

        /*
         * Determine the last entry_id of this segment.
         * For all segments except the last, the next segment's first_id - 1
         * is an upper bound on the last entry_id.  For the last segment we
         * don't know a priori; we just read until EOF.
         *
         * Skip this segment entirely if its last possible entry_id is below
         * from_entry_id.  For segments that are not the last, we can use the
         * next segment's first_id as a strict upper bound.
         */
        if (si + 1 < n_segs) {
            uint64_t next_first = segs_copy[si + 1].first_id;
            /* The segment's last entry_id is at most next_first - 1. */
            if (next_first > 0 && (next_first - 1) < from_entry_id) continue;
        }
        /* (For the last segment we can't skip — we must read to find entry IDs.) */

        char path[4096 + 32];
        snprintf(path, sizeof(path), "%s/%016llx.log",
                 oplog_dir, (unsigned long long)seg_first);

        vw_fd_t fd = fd_open_read(path);
        if (fd == VW_FD_INVALID) {
            /* Segment may have been GC'd; skip. */
            continue;
        }

        uint8_t hdr[ENTRY_HDR_SIZE]; /* 17 bytes */
        for (;;) {
            int n = fd_read(fd, hdr, ENTRY_HDR_SIZE);
            if (n <= 0) break;                  /* EOF or error */
            if (n < (int)ENTRY_HDR_SIZE) break; /* partial header */

            uint32_t stored_crc  = vw_read_u32le(hdr + 0);
            uint32_t stored_plen = vw_read_u32le(hdr + 4);
            uint64_t entry_id    = vw_read_u64le(hdr + 8);
            uint8_t  confirmed   = hdr[ENTRY_CONFIRMED_OFF]; /* offset 16 */

            if (stored_plen == 0) break; /* malformed */
            if (stored_plen > VW_OPLOG_SEGMENT_MAX) break; /* malformed — exceeds segment cap */

            uint8_t *payload = (uint8_t *)malloc(stored_plen);
            if (!payload) { rc = VW_ERR_OOM; stop = 1; break; }

            uint32_t got = 0;
            while (got < stored_plen) {
                int r = fd_read(fd, payload + got, stored_plen - got);
                if (r <= 0) { got = 0; break; }
                got += (uint32_t)r;
            }
            if (got < stored_plen) { free(payload); break; } /* partial payload */

            /* Verify CRC: hdr[4..15] + payload (confirmed byte excluded) */
            uint32_t crc = 0;
            crc = crc32_update(crc, hdr + 4, CRC_HEADER_BYTES);
            crc = crc32_update(crc, payload, stored_plen);

            if (crc != stored_crc) { free(payload); break; } /* corrupt */

            /* Skip unconfirmed entries (not yet committed via vw_oplog_confirm).
             * These should not exist in a recovered log, but be defensive. */
            if (confirmed == 0) { free(payload); continue; }

            /* Dispatch if entry_id >= from_entry_id */
            if (entry_id >= from_entry_id) {
                vw_oplog_op_t op_type = (vw_oplog_op_t)payload[0];
                uint32_t      op_len  = stored_plen - 1;
                /* Pass NULL when op_len==0 to prevent one-past-end pointer */
                const void   *op_data = (op_len > 0) ? (payload + 1) : NULL;

                int cbrc = callback(entry_id, op_type, op_data, op_len, userdata);
                if (cbrc != 0) stop = 1;
            }

            free(payload);
            if (stop) break;
        }

        fd_close(fd);
    }

    free(segs_copy);
    return rc;
}

/* ── vw_oplog_truncate_before ───────────────────────────────────────────── */

vw_err_t vw_oplog_truncate_before(vw_oplog_t *ctx, uint64_t min_entry_id)
{
    if (!ctx) return VW_ERR_INVALID_ARG;

    mutex_lock(&ctx->mu);

    /*
     * A segment may be deleted only if ALL its entries precede min_entry_id.
     * A segment's entries span [seg[i].first_id, seg[i+1].first_id - 1].
     * For the active (last) segment we never delete.
     */
    size_t del_count = 0;
    for (size_t i = 0; i + 1 < ctx->segs_len; i++) {
        uint64_t next_first = ctx->segs[i + 1].first_id;
        /* The segment ends just before the next one starts. */
        if (next_first <= min_entry_id) {
            del_count = i + 1; /* we can delete up to and including index i */
        } else {
            break; /* sorted — no point looking further */
        }
    }

    if (del_count == 0) { mutex_unlock(&ctx->mu); return VW_OK; }

    /* Delete files and remove from the in-memory index. */
    vw_err_t first_err = VW_OK;
    for (size_t i = 0; i < del_count; i++) {
        char path[4096 + 32];
        seg_path(ctx, ctx->segs[i].first_id, path, sizeof(path));
        vw_err_t rc = vw_fs_delete(path);
        if (rc != VW_OK && first_err == VW_OK) first_err = rc;
    }

    /* Compact the array */
    memmove(&ctx->segs[0], &ctx->segs[del_count],
            (ctx->segs_len - del_count) * sizeof(vw_seg_info_t));
    ctx->segs_len -= del_count;

    mutex_unlock(&ctx->mu);
    return first_err;
}

/* ── vw_oplog_last_entry_id ─────────────────────────────────────────────── */

uint64_t vw_oplog_last_entry_id(const vw_oplog_t *ctx)
{
    if (!ctx) return 0;
    /*
     * last_entry_id is written only under the mutex and is a naturally-aligned
     * 64-bit value.  On all supported architectures a single 64-bit load is
     * atomic enough for a plain informational read, but we take the mutex for
     * strict correctness.
     */
    mutex_lock((vw_mutex_t *)&ctx->mu);
    uint64_t id = ctx->last_entry_id;
    mutex_unlock((vw_mutex_t *)&ctx->mu);
    return id;
}

/* ── vw_oplog_read_range ────────────────────────────────────────────────── */

typedef struct {
    uint8_t  *buf;
    uint32_t  buf_cap;
    uint32_t  buf_len;
    uint32_t  count;
    uint64_t  last_entry_id;
    uint32_t  max_entries;
    int       oom;
} read_range_ctx_t;

static int read_range_cb(uint64_t entry_id, vw_oplog_op_t op_type,
                         const void *payload, uint32_t payload_len,
                         void *userdata)
{
    read_range_ctx_t *rctx = (read_range_ctx_t *)userdata;
    if (rctx->count >= rctx->max_entries) return 1;  /* stop */

    uint32_t stored_plen = payload_len + 1u;
    uint32_t entry_total = ENTRY_HDR_SIZE + stored_plen;

    /* Build CRC-covered header bytes: [payload_len(4)][entry_id(8)] */
    uint8_t crc_hdr[CRC_HEADER_BYTES];
    vw_write_u32le(crc_hdr + 0, stored_plen);
    vw_write_u64le(crc_hdr + 4, entry_id);
    uint8_t op_byte = (uint8_t)op_type;
    uint32_t crc = 0;
    crc = crc32_update(crc, crc_hdr, CRC_HEADER_BYTES);
    crc = crc32_update(crc, &op_byte, 1);
    if (payload_len > 0)
        crc = crc32_update(crc, payload, payload_len);

    /* Grow output buffer if needed */
    if (rctx->buf_len + entry_total > rctx->buf_cap) {
        uint32_t new_cap = rctx->buf_cap ? rctx->buf_cap * 2 : 65536;
        while (new_cap < rctx->buf_len + entry_total) new_cap *= 2;
        uint8_t *p = (uint8_t *)realloc(rctx->buf, new_cap);
        if (!p) { rctx->oom = 1; return 1; }
        rctx->buf     = p;
        rctx->buf_cap = new_cap;
    }

    uint8_t *dst = rctx->buf + rctx->buf_len;
    vw_write_u32le(dst + 0,  crc);
    vw_write_u32le(dst + 4,  stored_plen);
    vw_write_u64le(dst + 8,  entry_id);
    dst[ENTRY_CONFIRMED_OFF] = 1;  /* confirmed — safe for replica to apply */
    dst[17]                  = op_byte;
    if (payload_len > 0)
        memcpy(dst + 18, payload, payload_len);

    rctx->buf_len       += entry_total;
    rctx->count++;
    rctx->last_entry_id  = entry_id;

    return (rctx->count >= rctx->max_entries) ? 1 : 0;
}

vw_err_t vw_oplog_read_range(vw_oplog_t *oplog,
                              uint64_t    from_entry_id,
                              uint32_t    max_entries,
                              uint8_t   **out_buf,
                              uint32_t   *out_count,
                              uint64_t   *out_last_entry_id)
{
    if (!oplog || !out_buf || !out_count || !out_last_entry_id)
        return VW_ERR_INVALID_ARG;

    *out_buf           = NULL;
    *out_count         = 0;
    *out_last_entry_id = 0;

    if (max_entries == 0) return VW_OK;

    read_range_ctx_t rctx;
    memset(&rctx, 0, sizeof(rctx));
    rctx.max_entries = max_entries;

    /* Pass from_entry_id + 1 to replay_from so we get entries strictly after it. */
    uint64_t start = (from_entry_id < UINT64_MAX) ? from_entry_id + 1 : UINT64_MAX;
    vw_err_t rc = vw_oplog_replay_from(oplog, start, read_range_cb, &rctx);

    if (rctx.oom) { free(rctx.buf); return VW_ERR_OOM; }
    if (rc != VW_OK) { free(rctx.buf); return rc; }

    *out_buf           = rctx.buf;   /* NULL when count == 0 */
    *out_count         = rctx.count;
    *out_last_entry_id = rctx.last_entry_id;
    return VW_OK;
}

/* ── vw_oplog_append_raw ────────────────────────────────────────────────── */

vw_err_t vw_oplog_append_raw(vw_oplog_t    *oplog,
                              const uint8_t *entry_bytes,
                              uint32_t       entry_len,
                              uint64_t       expected_entry_id)
{
    if (!oplog || !entry_bytes) return VW_ERR_INVALID_ARG;

    /* Minimum: ENTRY_HDR_SIZE + 1 byte payload (op_type only) */
    if (entry_len < ENTRY_HDR_SIZE + 1u) return VW_ERR_PROTO_INVALID;

    uint32_t stored_crc  = vw_read_u32le(entry_bytes + 0);
    uint32_t stored_plen = vw_read_u32le(entry_bytes + 4);
    uint64_t entry_id    = vw_read_u64le(entry_bytes + 8);

    /* Validate that stored sizes are internally consistent with entry_len */
    if (stored_plen == 0 || stored_plen > entry_len - ENTRY_HDR_SIZE)
        return VW_ERR_PROTO_INVALID;
    if (ENTRY_HDR_SIZE + stored_plen != entry_len)
        return VW_ERR_PROTO_INVALID;
    if (entry_id != expected_entry_id)
        return VW_ERR_PROTO_INVALID;

    /* Verify CRC: covers entry_bytes[4..15] (payload_len + entry_id)
     * plus entry_bytes[17..end] (op_type + op_payload).
     * The confirmed byte at offset 16 is intentionally excluded. */
    uint32_t crc = 0;
    crc = crc32_update(crc, entry_bytes + 4,  CRC_HEADER_BYTES); /* [4..15] */
    crc = crc32_update(crc, entry_bytes + 17, stored_plen);      /* [17..end] */
    if (crc != stored_crc) return VW_ERR_PROTO_INVALID;

    mutex_lock(&oplog->mu);

    /* Idempotent: entry already applied on this replica (re-delivery after reconnect). */
    if (expected_entry_id <= oplog->last_entry_id) {
        mutex_unlock(&oplog->mu);
        return VW_OK;
    }

    /* Gap check: must be exactly the next expected sequence number. */
    if (expected_entry_id != oplog->next_entry_id) {
        mutex_unlock(&oplog->mu);
        return VW_ERR_PROTO_INVALID;
    }

    /* Rotate segment if the current one is full. */
    if (oplog->seg_bytes >= VW_OPLOG_SEGMENT_MAX) {
        vw_err_t rc = rotate_segment(oplog);
        if (rc != VW_OK) { mutex_unlock(&oplog->mu); return rc; }
    }

    /* Write with confirmed=1 — entries from the primary are pre-committed. */
    uint8_t *write_buf = (uint8_t *)malloc(entry_len);
    if (!write_buf) { mutex_unlock(&oplog->mu); return VW_ERR_OOM; }
    memcpy(write_buf, entry_bytes, entry_len);
    write_buf[ENTRY_CONFIRMED_OFF] = 1;

    int wrc = fd_write(oplog->seg_fd, write_buf, entry_len);
    free(write_buf);

    if (wrc != 0) {
        int64_t real_sz = fd_size(oplog->seg_fd);
        if (real_sz >= 0) oplog->seg_bytes = (uint64_t)real_sz;
        mutex_unlock(&oplog->mu);
        return VW_ERR_IO;
    }

    if (fd_sync(oplog->seg_fd) != 0) {
        oplog->seg_bytes += entry_len;
        mutex_unlock(&oplog->mu);
        return VW_ERR_IO;
    }

    oplog->seg_bytes    += entry_len;
    oplog->last_entry_id = entry_id;
    oplog->next_entry_id = entry_id + 1;

    mutex_unlock(&oplog->mu);
    return VW_OK;
}
