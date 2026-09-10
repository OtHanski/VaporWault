#include "vw_notify.h"
#include "../core/vw_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#   define WIN32_LEAN_AND_MEAN
#   include <windows.h>
typedef CRITICAL_SECTION vw_notify_mutex_t;
#   define notify_mutex_init(m)    InitializeCriticalSection(m)
#   define notify_mutex_destroy(m) DeleteCriticalSection(m)
#   define notify_mutex_lock(m)    EnterCriticalSection(m)
#   define notify_mutex_unlock(m)  LeaveCriticalSection(m)
#else
#   include <pthread.h>
typedef pthread_mutex_t vw_notify_mutex_t;
#   define notify_mutex_init(m)    pthread_mutex_init((m), NULL)
#   define notify_mutex_destroy(m) pthread_mutex_destroy(m)
#   define notify_mutex_lock(m)    pthread_mutex_lock(m)
#   define notify_mutex_unlock(m)  pthread_mutex_unlock(m)
#endif

/* quota_warning threshold — 90% of quota_bytes, per TASK-205's design. */
#define VW_NOTIFY_QUOTA_THRESHOLD_NUM 9
#define VW_NOTIFY_QUOTA_THRESHOLD_DEN 10

typedef struct {
    uint64_t user_id;
    uint8_t  armed;   /* 1 = already warned; waiting to drop back under threshold */
} quota_debounce_entry_t;

/* Rolling window for lockout_spike (TASK-208) — fixed-cap ring buffer of
 * recent lockout timestamps, mirroring this project's existing
 * fixed-size-table-with-eviction convention (e.g. vw_auth.c's own
 * per-account lockout table, TASK-078) rather than an unbounded list. */
#define VW_NOTIFY_LOCKOUT_RING_CAP 256u

/* Same fixed-cap-ring convention, for chunk_unrepairable's per-hash
 * debounce (Phase 22, TASK-261) — "already alerted for this hash since
 * the last restart" state, not a timestamp window. */
#define VW_NOTIFY_CHUNK_UNREPAIRABLE_RING_CAP 256u

struct vw_notify_ctx {
    vw_store_t           *store;    /* borrowed */
    const vw_smtp_cfg_t   *smtp_cfg; /* borrowed; NULL = email disabled */

    vw_notify_mutex_t        debounce_lock;
    quota_debounce_entry_t  *debounce;
    size_t                   debounce_len;
    size_t                   debounce_cap;

    /* Admin-category config + debounce state (TASK-208) — guarded by the
     * same debounce_lock as the user-category quota table above; the two
     * are never on the hot path together, no benefit to separate locks. */
    vw_notify_admin_cfg_t admin_cfg;
    uint8_t               replica_lag_armed;
    uint8_t               disk_capacity_armed;
    uint8_t               lockout_spike_armed;
    time_t                lockout_ring[VW_NOTIFY_LOCKOUT_RING_CAP];
    size_t                lockout_ring_len;   /* next write position, wraps */

    /* chunk_unrepairable (TASK-261) per-hash debounce ring. */
    uint8_t               chunk_unrepairable_hashes[VW_NOTIFY_CHUNK_UNREPAIRABLE_RING_CAP][VW_HASH_BYTES];
    size_t                chunk_unrepairable_ring_len; /* next write position, wraps */
};

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

vw_err_t vw_notify_ctx_open(vw_store_t *store, const vw_smtp_cfg_t *smtp_cfg,
                             vw_notify_ctx_t **out_ctx)
{
    if (!store || !out_ctx) return VW_ERR_INVALID_ARG;

    vw_notify_ctx_t *ctx = (vw_notify_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return VW_ERR_OOM;

    ctx->store    = store;
    ctx->smtp_cfg = smtp_cfg;
    notify_mutex_init(&ctx->debounce_lock);

    *out_ctx = ctx;
    return VW_OK;
}

void vw_notify_ctx_close(vw_notify_ctx_t *ctx)
{
    if (!ctx) return;
    notify_mutex_destroy(&ctx->debounce_lock);
    free(ctx->debounce);
    free(ctx);
}

/* ── Shared send helper ──────────────────────────────────────────────────── */

/*
 * Test-only seam — same volatile-function-pointer idiom vw_auth.c already
 * uses for vw_auth_test_set_time_fn (its own comment: "declared here but
 * not in vw_auth.h — internal test hook only"). Defaults to the real
 * vw_smtp_send; tests/unit/test_vw_notify.c substitutes a fake that
 * records (to_addr, subject, body) instead of doing real network I/O, so
 * this module's opt-in/debounce logic can be verified without standing up
 * a real SMTP server.
 */
static vw_err_t (* volatile g_smtp_send_fn)(const vw_smtp_cfg_t *, const char *,
                                             const char *, const char *,
                                             char *, size_t) = vw_smtp_send;

void vw_notify_test_set_smtp_send_fn(
    vw_err_t (*fn)(const vw_smtp_cfg_t *, const char *, const char *,
                   const char *, char *, size_t))
{
    g_smtp_send_fn = fn ? fn : vw_smtp_send;
}

/*
 * Returns non-zero if an email was actually attempted (opted in, SMTP
 * configured, user found) — purely informational for callers that don't
 * need it; every caller here ignores the return value today.
 */
static int notify_send_if_enabled(vw_notify_ctx_t *ctx, uint64_t user_id,
                                   uint32_t category_bit,
                                   const char *subject, const char *body)
{
    if (!ctx || !ctx->smtp_cfg || ctx->smtp_cfg->host[0] == '\0') return 0;

    uint32_t prefs = 0;
    if (vw_store_notify_prefs_get(ctx->store, user_id, &prefs) != VW_OK) return 0;
    if ((prefs & category_bit) == 0) return 0;

    vw_user_record_t rec;
    if (vw_store_user_get_by_id(ctx->store, user_id, &rec) != VW_OK) return 0;
    if (rec.email[0] == '\0') return 0;

    char email[129];
    memcpy(email, rec.email, 128);
    email[128] = '\0';

    /* Best-effort — a notification is a courtesy, never a reason to fail
     * or block the operation that triggered it (same posture as this
     * project's existing OTP/recovery emails). */
    (void)g_smtp_send_fn(ctx->smtp_cfg, email, subject, body, NULL, 0);
    return 1;
}

/* ── share_received ──────────────────────────────────────────────────────── */

void vw_notify_share_received(vw_notify_ctx_t *ctx, uint64_t target_user_id,
                               const char *sharer_username,
                               const char *item_name)
{
    if (!ctx || !target_user_id) return;

    char body[512];
    snprintf(body, sizeof(body),
              "%s shared \"%s\" with you on VaporWault.\r\n\r\n"
              "Open your VaporWault client to view it.",
              sharer_username ? sharer_username : "Someone",
              item_name ? item_name : "an item");

    (void)notify_send_if_enabled(ctx, target_user_id, VW_NOTIFY_SHARE_RECEIVED,
                                  "VaporWault: something was shared with you",
                                  body);
}

/* ── new_login ────────────────────────────────────────────────────────────── */

void vw_notify_new_login(vw_notify_ctx_t *ctx, uint64_t user_id,
                          const char *peer_ip)
{
    if (!ctx || !user_id) return;

    /* UTC, human-readable, no locale/timezone ambiguity in an email a
     * user might read from anywhere. */
    time_t now = time(NULL);
    char when[32] = "";
    struct tm tmv;
#ifdef _WIN32
    if (gmtime_s(&tmv, &now) == 0)
        strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S UTC", &tmv);
#else
    if (gmtime_r(&now, &tmv) != NULL)
        strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S UTC", &tmv);
#endif

    char body[512];
    snprintf(body, sizeof(body),
              "A new login to your VaporWault account succeeded"
              "%s%s, at %s.\r\n\r\n"
              "If this wasn't you, change your password and revoke your "
              "other sessions as soon as possible.",
              (peer_ip && peer_ip[0]) ? " from " : "",
              (peer_ip && peer_ip[0]) ? peer_ip : "",
              when[0] ? when : "an unknown time");

    (void)notify_send_if_enabled(ctx, user_id, VW_NOTIFY_NEW_LOGIN,
                                  "VaporWault: new login to your account",
                                  body);
}

/* ── account_security_change ─────────────────────────────────────────────── */

void vw_notify_account_security_change(vw_notify_ctx_t *ctx, uint64_t user_id,
                                        const char *what_changed)
{
    if (!ctx || !user_id || !what_changed) return;

    char body[512];
    snprintf(body, sizeof(body),
              "A security-relevant change to your VaporWault account just "
              "happened: %s.\r\n\r\n"
              "If this wasn't you, change your password and revoke your "
              "other sessions as soon as possible.",
              what_changed);

    (void)notify_send_if_enabled(ctx, user_id, VW_NOTIFY_ACCOUNT_SECURITY_CHANGE,
                                  "VaporWault: account security change",
                                  body);
}

/* ── quota_warning (vw_store_quota_hook_fn) ──────────────────────────────── */

static quota_debounce_entry_t *debounce_find(vw_notify_ctx_t *ctx, uint64_t user_id)
{
    size_t i;
    for (i = 0; i < ctx->debounce_len; i++)
        if (ctx->debounce[i].user_id == user_id) return &ctx->debounce[i];
    return NULL;
}

static quota_debounce_entry_t *debounce_find_or_add(vw_notify_ctx_t *ctx, uint64_t user_id)
{
    quota_debounce_entry_t *e = debounce_find(ctx, user_id);
    if (e) return e;

    if (ctx->debounce_len >= ctx->debounce_cap) {
        size_t nc = ctx->debounce_cap ? ctx->debounce_cap * 2 : 16;
        quota_debounce_entry_t *p = (quota_debounce_entry_t *)realloc(
            ctx->debounce, nc * sizeof(*p));
        if (!p) return NULL; /* OOM: caller treats as "not previously armed" */
        ctx->debounce = p;
        ctx->debounce_cap = nc;
    }
    e = &ctx->debounce[ctx->debounce_len++];
    e->user_id = user_id;
    e->armed = 0;
    return e;
}

void vw_notify_quota_hook(void *userdata, uint64_t user_id,
                           uint64_t used_bytes, uint64_t quota_bytes)
{
    vw_notify_ctx_t *ctx = (vw_notify_ctx_t *)userdata;
    if (!ctx || !user_id || quota_bytes == 0) return; /* unlimited: never fires */

    int now_over = (used_bytes * (uint64_t)VW_NOTIFY_QUOTA_THRESHOLD_DEN) >=
                   (quota_bytes * (uint64_t)VW_NOTIFY_QUOTA_THRESHOLD_NUM);
    int should_fire = 0;

    notify_mutex_lock(&ctx->debounce_lock);
    quota_debounce_entry_t *e = debounce_find_or_add(ctx, user_id);
    if (e) {
        if (now_over && !e->armed) {
            e->armed = 1;
            should_fire = 1;
        } else if (!now_over && e->armed) {
            e->armed = 0; /* re-armed silently — no email on the way back down */
        }
    }
    notify_mutex_unlock(&ctx->debounce_lock);

    if (!should_fire) return;

    char body[512];
    snprintf(body, sizeof(body),
              "Your VaporWault storage usage has crossed %d%% of your quota."
              "\r\n\r\nConsider freeing up space or asking your administrator "
              "for a higher limit.",
              (int)(VW_NOTIFY_QUOTA_THRESHOLD_NUM * 100 / VW_NOTIFY_QUOTA_THRESHOLD_DEN));

    (void)notify_send_if_enabled(ctx, user_id, VW_NOTIFY_QUOTA_WARNING,
                                  "VaporWault: storage quota warning",
                                  body);
}

/* ── Admin operational alerts (TASK-208) ─────────────────────────────────── */

void vw_notify_ctx_set_admin_cfg(vw_notify_ctx_t *ctx, const vw_notify_admin_cfg_t *cfg)
{
    if (!ctx) return;
    if (cfg) {
        ctx->admin_cfg = *cfg;
    } else {
        memset(&ctx->admin_cfg, 0, sizeof(ctx->admin_cfg));
    }
}

/* Same shape as notify_send_if_enabled, but the recipient is the fixed
 * admin_email from config rather than a per-user store lookup — admin
 * categories have no per-user preference concept at all (TASK-205). */
static void notify_send_admin_if_enabled(vw_notify_ctx_t *ctx, int category_enabled,
                                          const char *subject, const char *body)
{
    if (!ctx || !category_enabled) return;
    if (!ctx->smtp_cfg || ctx->smtp_cfg->host[0] == '\0') return;
    if (ctx->admin_cfg.admin_email[0] == '\0') return; /* fail-loud check already
                                                          * happened at startup; this
                                                          * is just defensive */
    (void)g_smtp_send_fn(ctx->smtp_cfg, ctx->admin_cfg.admin_email, subject, body, NULL, 0);
}

/* ── replica_lag ──────────────────────────────────────────────────────────── */

void vw_notify_replica_lag(vw_notify_ctx_t *ctx, uint64_t lag_entries)
{
    if (!ctx) return;
    uint32_t threshold = ctx->admin_cfg.replica_lag_threshold_entries
                          ? ctx->admin_cfg.replica_lag_threshold_entries
                          : VW_NOTIFY_REPLICA_LAG_THRESHOLD_ENTRIES_DEFAULT;
    int now_over = lag_entries >= (uint64_t)threshold;
    int should_fire = 0;

    notify_mutex_lock(&ctx->debounce_lock);
    if (now_over && !ctx->replica_lag_armed) {
        ctx->replica_lag_armed = 1;
        should_fire = 1;
    } else if (!now_over && ctx->replica_lag_armed) {
        ctx->replica_lag_armed = 0;
    }
    notify_mutex_unlock(&ctx->debounce_lock);

    if (!should_fire) return;

    char body[512];
    snprintf(body, sizeof(body),
              "A paired replica is falling behind — it has not acknowledged "
              "the last %llu oplog entries.\r\n\r\n"
              "This means the replica is not yet a safe fallback target and "
              "is worth investigating (network issue, replica down, or "
              "under heavy load).",
              (unsigned long long)lag_entries);

    notify_send_admin_if_enabled(ctx, ctx->admin_cfg.replica_lag_enabled,
                                  "VaporWault: replica falling behind", body);
}

/* ── acme_renewal_failure ─────────────────────────────────────────────────── */

void vw_notify_acme_renewal_failure(vw_notify_ctx_t *ctx, const char *reason)
{
    if (!ctx) return;

    char body[512];
    snprintf(body, sizeof(body),
              "An automatic TLS certificate renewal attempt failed%s%s.\r\n\r\n"
              "The current certificate is still in use; if this keeps "
              "failing until it expires, clients will start rejecting TLS "
              "connections to this server.",
              (reason && reason[0]) ? ": " : "",
              (reason && reason[0]) ? reason : "");

    notify_send_admin_if_enabled(ctx, ctx->admin_cfg.acme_renewal_failure_enabled,
                                  "VaporWault: certificate renewal failed", body);
}

/* ── disk_capacity ────────────────────────────────────────────────────────── */

void vw_notify_disk_capacity(vw_notify_ctx_t *ctx, uint32_t used_pct)
{
    if (!ctx) return;
    uint32_t threshold = ctx->admin_cfg.disk_capacity_threshold_pct
                          ? ctx->admin_cfg.disk_capacity_threshold_pct
                          : VW_NOTIFY_DISK_CAPACITY_THRESHOLD_PCT_DEFAULT;
    int now_over = used_pct >= threshold;
    int should_fire = 0;

    notify_mutex_lock(&ctx->debounce_lock);
    if (now_over && !ctx->disk_capacity_armed) {
        ctx->disk_capacity_armed = 1;
        should_fire = 1;
    } else if (!now_over && ctx->disk_capacity_armed) {
        ctx->disk_capacity_armed = 0;
    }
    notify_mutex_unlock(&ctx->debounce_lock);

    if (!should_fire) return;

    char body[512];
    snprintf(body, sizeof(body),
              "This server's storage disk is at %u%% capacity.\r\n\r\n"
              "Free up space or provision more storage soon — running out "
              "of disk will start failing uploads for every user.",
              (unsigned)used_pct);

    notify_send_admin_if_enabled(ctx, ctx->admin_cfg.disk_capacity_enabled,
                                  "VaporWault: disk nearing capacity", body);
}

/* ── lockout_spike ────────────────────────────────────────────────────────── */

void vw_notify_lockout_spike(vw_notify_ctx_t *ctx)
{
    if (!ctx) return;
    uint32_t threshold = ctx->admin_cfg.lockout_spike_threshold_count
                          ? ctx->admin_cfg.lockout_spike_threshold_count
                          : VW_NOTIFY_LOCKOUT_SPIKE_THRESHOLD_COUNT_DEFAULT;
    uint32_t window = ctx->admin_cfg.lockout_spike_window_secs
                       ? ctx->admin_cfg.lockout_spike_window_secs
                       : VW_NOTIFY_LOCKOUT_SPIKE_WINDOW_SECS_DEFAULT;
    time_t now = time(NULL);
    int should_fire = 0;
    uint32_t count_in_window = 0;

    notify_mutex_lock(&ctx->debounce_lock);

    /* Record this lockout. */
    ctx->lockout_ring[ctx->lockout_ring_len % VW_NOTIFY_LOCKOUT_RING_CAP] = now;
    ctx->lockout_ring_len++;

    /* Count how many recorded lockouts fall within the rolling window —
     * bounded by VW_NOTIFY_LOCKOUT_RING_CAP regardless of how many total
     * lockouts have ever occurred (fixed-cap ring, same convention as
     * vw_auth.c's own lockout table). */
    size_t scan_n = (ctx->lockout_ring_len < VW_NOTIFY_LOCKOUT_RING_CAP)
                    ? ctx->lockout_ring_len : VW_NOTIFY_LOCKOUT_RING_CAP;
    for (size_t i = 0; i < scan_n; i++) {
        if ((double)(now - ctx->lockout_ring[i]) <= (double)window)
            count_in_window++;
    }

    if (count_in_window >= threshold && !ctx->lockout_spike_armed) {
        ctx->lockout_spike_armed = 1;
        should_fire = 1;
    } else if (count_in_window < threshold && ctx->lockout_spike_armed) {
        ctx->lockout_spike_armed = 0;
    }

    notify_mutex_unlock(&ctx->debounce_lock);

    if (!should_fire) return;

    char body[512];
    snprintf(body, sizeof(body),
              "%u account lockouts occurred within the last %u seconds — an "
              "unusually high rate, possibly a brute-force attempt.\r\n\r\n"
              "Check the audit log for the accounts and source addresses "
              "involved.",
              (unsigned)count_in_window, (unsigned)window);

    notify_send_admin_if_enabled(ctx, ctx->admin_cfg.lockout_spike_enabled,
                                  "VaporWault: unusual rate of account lockouts", body);
}

/* ── crash_recovery ───────────────────────────────────────────────────────── */

void vw_notify_crash_recovery(vw_notify_ctx_t *ctx)
{
    if (!ctx) return;

    static const char body[] =
        "This server's oplog crash-recovery replay ran at startup, meaning "
        "it did not shut down cleanly last time (a crash, a kill -9, a "
        "power loss, etc.).\r\n\r\n"
        "No data was lost — only unconfirmed, in-flight entries from the "
        "moment of the unclean shutdown were discarded, the same guarantee "
        "the oplog's two-phase commit design always provides. Worth "
        "checking why the process stopped uncleanly.";

    notify_send_admin_if_enabled(ctx, ctx->admin_cfg.crash_recovery_enabled,
                                  "VaporWault: server recovered from an unclean shutdown",
                                  body);
}

/* ── chunk_unrepairable (Phase 22, TASK-261) ──────────────────────────────── */

void vw_notify_chunk_unrepairable(vw_notify_ctx_t *ctx,
                                   const uint8_t hash[VW_HASH_BYTES])
{
    if (!ctx || !hash) return;

    int already_alerted = 0;

    notify_mutex_lock(&ctx->debounce_lock);
    {
        size_t scan_n = (ctx->chunk_unrepairable_ring_len < VW_NOTIFY_CHUNK_UNREPAIRABLE_RING_CAP)
                        ? ctx->chunk_unrepairable_ring_len
                        : VW_NOTIFY_CHUNK_UNREPAIRABLE_RING_CAP;
        for (size_t i = 0; i < scan_n; i++) {
            if (memcmp(ctx->chunk_unrepairable_hashes[i], hash, VW_HASH_BYTES) == 0) {
                already_alerted = 1;
                break;
            }
        }
        if (!already_alerted) {
            size_t slot = ctx->chunk_unrepairable_ring_len % VW_NOTIFY_CHUNK_UNREPAIRABLE_RING_CAP;
            memcpy(ctx->chunk_unrepairable_hashes[slot], hash, VW_HASH_BYTES);
            ctx->chunk_unrepairable_ring_len++;
        }
    }
    notify_mutex_unlock(&ctx->debounce_lock);

    if (already_alerted) return;

    static const char hexch[] = "0123456789abcdef";
    char hex[VW_HASH_BYTES * 2 + 1];
    for (size_t i = 0; i < VW_HASH_BYTES; i++) {
        hex[i * 2]     = hexch[hash[i] >> 4];
        hex[i * 2 + 1] = hexch[hash[i] & 0xF];
    }
    hex[VW_HASH_BYTES * 2] = '\0';

    char body[512];
    snprintf(body, sizeof(body),
              "A chunk could not be repaired: local Reed-Solomon "
              "reconstruction and every reachable replica were both "
              "tried and failed.\r\n\r\n"
              "Chunk hash: %s\r\n\r\n"
              "This chunk will keep failing to download until it is "
              "restored manually (e.g. from an offline backup) or "
              "becomes reachable from a replica again. Check the server "
              "log around this hash for the corresponding scrub/"
              "CHUNK_DOWNLOAD entry.",
              hex);

    notify_send_admin_if_enabled(ctx, ctx->admin_cfg.chunk_unrepairable_enabled,
                                  "VaporWault: chunk could not be repaired", body);
}
