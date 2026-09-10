/*
 * vw_scrub.c — Background chunk-store integrity scan thread.
 *
 * See vw_scrub.h for the design description.
 *
 * POSIX: uses pthread + sleep(1) polling loop.
 * Windows: uses CreateThread + Sleep(1000) polling loop.
 * Shutdown latency: at most 1 second. Both the polling loop and the
 * last-stats mutex mirror vw_gc.c/vw_notify.c's existing patterns exactly
 * rather than introducing a third shared-state convention.
 */

#include "vw_scrub.h"
#include "vw_repair.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

/* TASK-264: generous cap on how many stuck parity groups one scrub pass
 * retries — a pathological case this project doesn't expect to actually
 * hit at scale; silently truncated if ever exceeded (next pass picks up
 * where this one left off, since a still-stuck group stays stuck). */
#define VW_SCRUB_MAX_STUCK_GROUPS_PER_PASS 256u

/* ── Logging ─────────────────────────────────────────────────────────────── */

#define SCRUB_LOG_TAG "SCRUB"

#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 2, 3)))
#endif
static void scrub_log(const char *level, const char *fmt, ...);
static void scrub_log(const char *level, const char *fmt, ...)
{
    fprintf(stderr, "[%s] %s  ", level, SCRUB_LOG_TAG);
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
#define SCRUB_INFO(fmt, ...)  scrub_log("INFO", fmt, ##__VA_ARGS__)
#define SCRUB_WARN(fmt, ...)  scrub_log("WARN", fmt, ##__VA_ARGS__)
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

/* ── Platform thread + mutex abstraction ──────────────────────────────────── */

#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
typedef HANDLE vw_scrub_thread_t;
typedef CRITICAL_SECTION vw_scrub_mutex_t;
#   define scrub_mutex_init(m)    InitializeCriticalSection(m)
#   define scrub_mutex_destroy(m) DeleteCriticalSection(m)
#   define scrub_mutex_lock(m)    EnterCriticalSection(m)
#   define scrub_mutex_unlock(m)  LeaveCriticalSection(m)
#else
#   include <pthread.h>
#   include <unistd.h>
typedef pthread_t vw_scrub_thread_t;
typedef pthread_mutex_t vw_scrub_mutex_t;
#   define scrub_mutex_init(m)    pthread_mutex_init((m), NULL)
#   define scrub_mutex_destroy(m) pthread_mutex_destroy(m)
#   define scrub_mutex_lock(m)    pthread_mutex_lock(m)
#   define scrub_mutex_unlock(m)  pthread_mutex_unlock(m)
#endif

/* ── Internal context ────────────────────────────────────────────────────── */

struct vw_scrub_ctx {
    vw_scrub_cfg_t  cfg;
    vw_storage_t   *chunk_store; /* borrowed */
    vw_cluster_t   *cluster;     /* borrowed; NULL = no replica-fetch fallback (TASK-260) */
    vw_notify_ctx_t *notify;     /* borrowed; NULL = no admin alert on unrepairable (TASK-261) */

    vw_scrub_mutex_t          stats_lock; /* guards the two fields below */
    vw_storage_scrub_stats_t  last_stats;
    int64_t                   last_run_unix; /* 0 = never run */

    volatile int    shutdown;
    int             running;
    vw_scrub_thread_t thread;
};

/* ── Corrupt-chunk callback: drive repair, log the outcome ────────────────── */

static void hash_to_hex_str(const uint8_t hash[VW_HASH_BYTES], char out[VW_HASH_BYTES * 2 + 1])
{
    static const char hexch[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < VW_HASH_BYTES; i++) {
        out[i * 2]     = hexch[hash[i] >> 4];
        out[i * 2 + 1] = hexch[hash[i] & 0xF];
    }
    out[VW_HASH_BYTES * 2] = '\0';
}

static void repair_corrupt_chunk(const uint8_t hash[VW_HASH_BYTES], void *ud)
{
    vw_scrub_ctx_t *ctx = (vw_scrub_ctx_t *)ud;
    char hex[VW_HASH_BYTES * 2 + 1];
    hash_to_hex_str(hash, hex);

    SCRUB_WARN("corrupt chunk detected, still referenced: %s", hex);

    /* TASK-260: local Reed-Solomon reconstruction first, cluster
     * replica-fetch fallback second (vw_repair_chunk handles the
     * ordering — see vw_repair.h). A failure here is logged, not
     * treated as a scrub-pass failure; TASK-261 additionally raises a
     * debounced admin alert for the still-corrupt case. */
    vw_err_t rc = vw_repair_chunk(ctx->chunk_store, ctx->cluster, hash);
    if (rc == VW_OK) {
        SCRUB_INFO("repaired chunk %s", hex);
    } else {
        SCRUB_WARN("could not repair chunk %s (rc=%d) — still corrupt on disk", hex, (int)rc);
        if (ctx->notify) vw_notify_chunk_unrepairable(ctx->notify, hash);
    }
}

/* ── Scrub pass ──────────────────────────────────────────────────────────── */

vw_err_t vw_scrub_run_once(vw_scrub_ctx_t *ctx)
{
    if (!ctx) return VW_ERR_INVALID_ARG;

    vw_storage_scrub_stats_t stats;
    vw_err_t rc = vw_storage_scrub_run(ctx->chunk_store, repair_corrupt_chunk, ctx, &stats);
    if (rc != VW_OK) {
        SCRUB_WARN("scrub pass failed: %d", (int)rc);
        return VW_OK;
    }

    if (stats.corrupt > 0) {
        SCRUB_WARN("scrub pass complete: scanned=%llu corrupt=%llu tombstoned=%llu",
                    (unsigned long long)stats.scanned,
                    (unsigned long long)stats.corrupt,
                    (unsigned long long)stats.tombstoned);
    } else {
        SCRUB_INFO("scrub pass complete: scanned=%llu corrupt=0 tombstoned=%llu",
                   (unsigned long long)stats.scanned,
                   (unsigned long long)stats.tombstoned);
    }

    /* TASK-264: detect and retry-seal any parity group left stuck at
     * exactly VW_ECC_MAX_DATA_SHARDS members with no parity file — see
     * vw_storage_parity_stuck_groups's own doc comment for how this
     * happens. Same cadence as the corruption scan above, no second
     * background thread. A transient original cause heals silently on a
     * successful retry; a permanent one (the disclosed TASK-263 residual
     * race) is logged every pass instead of staying invisible forever. */
    {
        uint64_t stuck_ids[VW_SCRUB_MAX_STUCK_GROUPS_PER_PASS];
        uint32_t stuck_count = 0;
        if (vw_storage_parity_stuck_groups(ctx->chunk_store, stuck_ids,
                                            VW_SCRUB_MAX_STUCK_GROUPS_PER_PASS,
                                            &stuck_count) == VW_OK) {
            uint32_t i;
            for (i = 0; i < stuck_count; i++) {
                SCRUB_WARN("stuck parity group detected (full, unsealed): group_id=%llu — retrying seal",
                           (unsigned long long)stuck_ids[i]);
                vw_err_t seal_rc = vw_storage_parity_group_reseal(ctx->chunk_store, stuck_ids[i]);
                if (seal_rc == VW_OK) {
                    SCRUB_INFO("stuck parity group healed: group_id=%llu",
                               (unsigned long long)stuck_ids[i]);
                } else {
                    SCRUB_WARN("stuck parity group still unsealed after retry: group_id=%llu (rc=%d)",
                               (unsigned long long)stuck_ids[i], (int)seal_rc);
                }
            }
        }
    }

    scrub_mutex_lock(&ctx->stats_lock);
    ctx->last_stats     = stats;
    ctx->last_run_unix  = (int64_t)time(NULL);
    scrub_mutex_unlock(&ctx->stats_lock);

    return VW_OK;
}

void vw_scrub_get_last_stats(vw_scrub_ctx_t *ctx,
                              vw_storage_scrub_stats_t *out_stats,
                              int64_t *out_last_run_unix)
{
    if (!ctx) {
        if (out_stats) memset(out_stats, 0, sizeof(*out_stats));
        if (out_last_run_unix) *out_last_run_unix = 0;
        return;
    }

    scrub_mutex_lock(&ctx->stats_lock);
    if (out_stats) *out_stats = ctx->last_stats;
    if (out_last_run_unix) *out_last_run_unix = ctx->last_run_unix;
    scrub_mutex_unlock(&ctx->stats_lock);
}

/* ── Thread entry point ──────────────────────────────────────────────────── */

#ifdef _WIN32

static DWORD WINAPI scrub_thread_entry(LPVOID arg)
{
    vw_scrub_ctx_t *ctx = (vw_scrub_ctx_t *)arg;
    uint32_t elapsed = 0;

    while (!ctx->shutdown) {
        Sleep(1000);
        if (ctx->shutdown) break;
        elapsed++;
        if (elapsed >= ctx->cfg.interval_secs) {
            vw_scrub_run_once(ctx);
            elapsed = 0;
        }
    }
    return 0;
}

#else /* POSIX */

static void *scrub_thread_entry(void *arg)
{
    vw_scrub_ctx_t *ctx = (vw_scrub_ctx_t *)arg;
    uint32_t elapsed = 0;

    while (!ctx->shutdown) {
        sleep(1);
        if (ctx->shutdown) break;
        elapsed++;
        if (elapsed >= ctx->cfg.interval_secs) {
            vw_scrub_run_once(ctx);
            elapsed = 0;
        }
    }
    return NULL;
}

#endif /* _WIN32 */

/* ── Public API ──────────────────────────────────────────────────────────── */

vw_err_t vw_scrub_create(const vw_scrub_cfg_t *cfg,
                          vw_storage_t *chunk_store,
                          vw_cluster_t *cluster,
                          vw_notify_ctx_t *notify,
                          vw_scrub_ctx_t **out)
{
    if (!cfg || !chunk_store || !out) return VW_ERR_INVALID_ARG;

    vw_scrub_ctx_t *ctx = (vw_scrub_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return VW_ERR_OOM;

    ctx->cfg         = *cfg;
    ctx->chunk_store = chunk_store;
    ctx->cluster     = cluster; /* NULL = no replica-fetch fallback */
    ctx->notify      = notify;  /* NULL = no admin alert on unrepairable */
    scrub_mutex_init(&ctx->stats_lock);

    *out = ctx;
    return VW_OK;
}

void vw_scrub_destroy(vw_scrub_ctx_t *ctx)
{
    if (!ctx) return;
    scrub_mutex_destroy(&ctx->stats_lock);
    free(ctx);
}

vw_err_t vw_scrub_start(vw_scrub_ctx_t *ctx)
{
    if (!ctx) return VW_ERR_INVALID_ARG;

    if (ctx->cfg.interval_secs == 0) return VW_OK;

    ctx->shutdown = 0;

#ifdef _WIN32
    ctx->thread = CreateThread(NULL, 0, scrub_thread_entry, ctx, 0, NULL);
    if (!ctx->thread) return VW_ERR_IO;
#else
    {
        int err = pthread_create(&ctx->thread, NULL, scrub_thread_entry, ctx);
        if (err != 0) return VW_ERR_IO;
    }
#endif

    ctx->running = 1;
    return VW_OK;
}

void vw_scrub_stop(vw_scrub_ctx_t *ctx)
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
