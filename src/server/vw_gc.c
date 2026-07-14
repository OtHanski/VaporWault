/*
 * vw_gc.c — Background garbage-collection thread.
 *
 * See vw_gc.h for the design description.
 *
 * GC passes run every cfg.interval_secs seconds (default 1800):
 *   1. Session expiry   — vw_store_session_gc
 *   2. Oplog truncation — vw_oplog_truncate_before (single-node mode)
 *   3. File/chunk GC    — vw_store_file_scan_deleted → deref → hard-delete → vw_storage_gc_run
 *
 * POSIX: uses pthread + sleep(1) polling loop.
 * Windows: uses CreateThread + Sleep(1000) polling loop.
 * Shutdown latency: at most 1 second.
 */

#include "vw_gc.h"
#include "vw_cluster.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

/* ── Logging ─────────────────────────────────────────────────────────────── */

#define GC_LOG_TAG "GC"

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
static void gc_log(const char *level, const char *fmt, ...);
static void gc_log(const char *level, const char *fmt, ...)
{
    fprintf(stderr, "[%s] %s  ", level, GC_LOG_TAG);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif
#define GC_INFO(fmt, ...)  gc_log("INFO",  fmt, ##__VA_ARGS__)
#define GC_WARN(fmt, ...)  gc_log("WARN",  fmt, ##__VA_ARGS__)
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

/* ── Platform thread abstraction ─────────────────────────────────────────── */

#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
typedef HANDLE vw_gc_thread_t;
#else
#   include <pthread.h>
#   include <unistd.h>
typedef pthread_t vw_gc_thread_t;
#endif

/* ── Internal context ────────────────────────────────────────────────────── */

struct vw_gc_ctx {
    vw_gc_cfg_t      cfg;
    vw_store_t      *store;       /* borrowed */
    vw_file_store_t *file_store;  /* borrowed; NULL = skip file/chunk GC */
    vw_storage_t    *chunk_store; /* borrowed; NULL = skip file/chunk GC */
    vw_oplog_t      *oplog;       /* borrowed */
    vw_cluster_t    *cluster;     /* borrowed; NULL = single-node mode */

    volatile int    shutdown; /* set to 1 to signal thread exit */
    int             running;  /* 1 after vw_gc_start */
    vw_gc_thread_t  thread;
};

/* ── Deleted-file collector (for pass 3) ─────────────────────────────────── */

typedef struct {
    uint64_t *ids;
    uint32_t  count;
    uint32_t  cap;
} del_collect_t;

static int collect_deleted_cb(const vw_file_record_t *rec, void *ud)
{
    del_collect_t *dc = (del_collect_t *)ud;
    if (dc->count >= dc->cap) {
        if (dc->cap > UINT32_MAX / 2) return -1; /* cap at ~2 billion files */
        uint32_t new_cap = dc->cap ? dc->cap * 2 : 16;
        uint64_t *p = (uint64_t *)realloc(dc->ids,
                                          (size_t)new_cap * sizeof(uint64_t));
        if (!p) return -1; /* OOM — stop scan */
        dc->ids = p;
        dc->cap = new_cap;
    }
    dc->ids[dc->count++] = rec->file_id;
    return 0;
}

/* ── GC pass ─────────────────────────────────────────────────────────────── */

vw_err_t vw_gc_run_once(vw_gc_ctx_t *ctx)
{
    uint64_t now    = (uint64_t)time(NULL);
    uint32_t expired = 0;
    vw_err_t rc;

    /* 1. Expire stale sessions. */
    rc = vw_store_session_gc(ctx->store, now, &expired);
    if (rc != VW_OK)
        GC_WARN("session GC failed: %d", (int)rc);
    else if (expired > 0)
        GC_INFO("expired %u stale session(s)", expired);

    /* 2. Truncate completed oplog segments.
     *    vw_oplog_truncate_before(oplog, N) deletes every segment whose LAST
     *    entry_id is strictly less than N.
     *    In cluster mode: truncate only up to the minimum replica sync watermark
     *    so lagging replicas can still pull the entries they need.
     *    In single-node mode: truncate up to last_entry_id (all complete segments
     *    except the currently active one). */
    {
        uint64_t safe_eid;
        if (ctx->cluster && vw_cluster_has_active_replicas(ctx->cluster)) {
            safe_eid = vw_cluster_min_sync_watermark(ctx->cluster);
        } else {
            safe_eid = vw_oplog_last_entry_id(ctx->oplog);
        }
        if (safe_eid > 0) {
            rc = vw_oplog_truncate_before(ctx->oplog, safe_eid);
            if (rc != VW_OK)
                GC_WARN("oplog truncation failed: %d", (int)rc);
        }
    }

    /* 3. File/version/chunk GC.
     *
     * Safety invariants (TASK-043 §3):
     *   a. Ref counts are decremented within the oplog two-phase commit window
     *      so crash recovery can detect incomplete GC and retry on next cycle.
     *   b. A chunk is only eligible for deletion when ref_count == 0.
     *      vw_storage_chunk_decref clamps to 0 on underflow and logs WARN,
     *      preventing double-free of chunk data on GC retry after a crash.
     *   c. Only files with deleted == 1 are collected, which guarantees we
     *      never decrement ref-counts for the current_version_id of a live file.
     */
    if (ctx->file_store && ctx->chunk_store) {
        del_collect_t dc;
        memset(&dc, 0, sizeof(dc));

        rc = vw_store_file_scan_deleted(ctx->file_store, collect_deleted_cb, &dc);
        if (rc != VW_OK)
            GC_WARN("scan_deleted failed: %d", (int)rc);

        uint32_t i;
        uint32_t files_collected = 0;
        for (i = 0; i < dc.count; i++) {
            uint64_t file_id = dc.ids[i];
            uint64_t eid;

            /* Begin two-phase commit for this file's deletion. */
            rc = vw_oplog_append(ctx->oplog, VW_OPLOG_FILE_DELETE,
                                 &file_id, (uint32_t)sizeof(file_id), &eid);
            if (rc != VW_OK) {
                GC_WARN("oplog_append for file %llu: %d",
                        (unsigned long long)file_id, (int)rc);
                continue;
            }

            /* Load all version records for this file. */
            vw_version_record_t *vers = NULL;
            uint32_t ver_count = 0;
            rc = vw_store_version_list(ctx->file_store, file_id,
                                       &vers, &ver_count);
            if (rc != VW_OK) {
                GC_WARN("version_list for file %llu: %d",
                        (unsigned long long)file_id, (int)rc);
                (void)vw_oplog_abort(ctx->oplog, eid);
                continue;
            }

            int file_ok = 1;
            uint32_t j;
            for (j = 0; j < ver_count; j++) {
                /* Load chunk hashes for this version. */
                uint8_t *hashes = NULL;
                rc = vw_store_version_get_chunks(ctx->file_store,
                                                 &vers[j], &hashes);
                if (rc != VW_OK) {
                    GC_WARN("get_chunks ver %llu: %d",
                            (unsigned long long)vers[j].version_id, (int)rc);
                    file_ok = 0;
                    break;
                }

                /* Decref each chunk. Clamped to 0 on underflow (invariant b). */
                uint32_t k;
                for (k = 0; k < vers[j].chunk_count; k++) {
                    vw_err_t drc = vw_storage_chunk_decref(
                        ctx->chunk_store,
                        hashes + (size_t)k * VW_HASH_BYTES);
                    if (drc != VW_OK && drc != VW_ERR_NOT_FOUND)
                        GC_WARN("chunk_decref ver %llu chunk %u: %d",
                                (unsigned long long)vers[j].version_id,
                                k, (int)drc);
                }
                free(hashes);

                /* Hard-delete this version record. */
                rc = vw_store_version_hard_delete(ctx->file_store,
                                                  vers[j].version_id);
                if (rc != VW_OK) {
                    GC_WARN("version_hard_delete %llu: %d",
                            (unsigned long long)vers[j].version_id, (int)rc);
                    file_ok = 0;
                    break;
                }
            }
            free(vers);

            if (!file_ok) {
                (void)vw_oplog_abort(ctx->oplog, eid);
                continue;
            }

            /* Hard-delete the file record (last step before confirm). */
            rc = vw_store_file_hard_delete(ctx->file_store, file_id);
            if (rc != VW_OK) {
                GC_WARN("file_hard_delete %llu: %d",
                        (unsigned long long)file_id, (int)rc);
                (void)vw_oplog_abort(ctx->oplog, eid);
                continue;
            }

            rc = vw_oplog_confirm(ctx->oplog, eid);
            if (rc != VW_OK)
                GC_WARN("oplog_confirm file %llu: %d",
                        (unsigned long long)file_id, (int)rc);
            else
                files_collected++;
        }

        if (files_collected > 0)
            GC_INFO("collected %u soft-deleted file(s)", files_collected);

        free(dc.ids);

        /* Phase B: delete zero-ref chunks and decrement owner quota. */
        rc = vw_storage_gc_run(ctx->chunk_store);
        if (rc != VW_OK)
            GC_WARN("chunk GC failed: %d", (int)rc);
    }

    return VW_OK;
}

/* ── Thread entry point ──────────────────────────────────────────────────── */

#ifdef _WIN32

static DWORD WINAPI gc_thread_entry(LPVOID arg)
{
    vw_gc_ctx_t *ctx = (vw_gc_ctx_t *)arg;
    uint32_t elapsed = 0;

    while (!ctx->shutdown) {
        Sleep(1000);
        if (ctx->shutdown) break;
        elapsed++;
        if (elapsed >= ctx->cfg.interval_secs) {
            vw_gc_run_once(ctx);
            elapsed = 0;
        }
    }
    return 0;
}

#else /* POSIX */

static void *gc_thread_entry(void *arg)
{
    vw_gc_ctx_t *ctx = (vw_gc_ctx_t *)arg;
    uint32_t elapsed = 0;

    while (!ctx->shutdown) {
        sleep(1);
        if (ctx->shutdown) break;
        elapsed++;
        if (elapsed >= ctx->cfg.interval_secs) {
            vw_gc_run_once(ctx);
            elapsed = 0;
        }
    }
    return NULL;
}

#endif /* _WIN32 */

/* ── Public API ──────────────────────────────────────────────────────────── */

vw_err_t vw_gc_create(const vw_gc_cfg_t *cfg,
                       vw_store_t       *store,
                       vw_file_store_t  *file_store,
                       vw_storage_t     *chunk_store,
                       vw_oplog_t       *oplog,
                       vw_cluster_t     *cluster,
                       vw_gc_ctx_t     **out)
{
    vw_gc_ctx_t *ctx;

    if (!cfg || !store || !oplog || !out) return VW_ERR_INVALID_ARG;

    ctx = (vw_gc_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return VW_ERR_OOM;

    ctx->cfg         = *cfg;
    ctx->store       = store;
    ctx->file_store  = file_store;
    ctx->chunk_store = chunk_store;
    ctx->oplog       = oplog;
    ctx->cluster     = cluster; /* NULL = single-node mode */

    *out = ctx;
    return VW_OK;
}

void vw_gc_destroy(vw_gc_ctx_t *ctx)
{
    if (!ctx) return;
    free(ctx);
}

vw_err_t vw_gc_start(vw_gc_ctx_t *ctx)
{
    if (!ctx) return VW_ERR_INVALID_ARG;

    /* Disabled when interval is zero. */
    if (ctx->cfg.interval_secs == 0) return VW_OK;

    ctx->shutdown = 0;

#ifdef _WIN32
    ctx->thread = CreateThread(NULL, 0, gc_thread_entry, ctx, 0, NULL);
    if (!ctx->thread) return VW_ERR_IO;
#else
    {
        int err = pthread_create(&ctx->thread, NULL, gc_thread_entry, ctx);
        if (err != 0) return VW_ERR_IO;
    }
#endif

    ctx->running = 1;
    return VW_OK;
}

void vw_gc_stop(vw_gc_ctx_t *ctx)
{
    if (!ctx || !ctx->running) return;

    ctx->shutdown = 1;

#ifdef _WIN32
    WaitForSingleObject(ctx->thread, INFINITE);
    CloseHandle(ctx->thread);
#else
    pthread_join(ctx->thread, NULL);
#endif

    ctx->running = 0;
}
