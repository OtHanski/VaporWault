#ifndef VW_NOTIFY_H
#define VW_NOTIFY_H

/*
 * vw_notify — opt-in email alert dispatch for the four user-facing
 * categories (TASK-205/206/207): share_received, quota_warning,
 * new_login, account_security_change.
 *
 * Every public function here is a no-op (no email, no side effect other
 * than the debounce bookkeeping quota_warning needs) whenever:
 *   - outbound SMTP is not configured (smtp_cfg is NULL or has an empty
 *     host, same "disabled" convention vw_server_core.c's recovery-email
 *     path already uses), or
 *   - the target user has not opted in to that specific category
 *     (vw_store_notify_prefs_get's bitmask), which is the default for
 *     every account per TASK-205's "default off everywhere" requirement.
 *
 * A send failure (SMTP unreachable, auth failure, etc.) is swallowed —
 * same best-effort posture this project already uses for the OTP/
 * recovery emails in vw_server_core.c: a notification is a courtesy, not
 * a step the triggering operation (a share grant, a login, a password
 * change) should ever fail or block on.
 */

#include "vw_store.h"
#include "vw_smtp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vw_notify_ctx vw_notify_ctx_t;

/*
 * Create a notification dispatch context. Borrows store and smtp_cfg —
 * caller keeps both alive until vw_notify_ctx_close (same borrowing
 * convention as every other vw_server_ctx_set_* attachment). smtp_cfg
 * may be NULL.
 */
vw_err_t vw_notify_ctx_open(vw_store_t *store, const vw_smtp_cfg_t *smtp_cfg,
                             vw_notify_ctx_t **out_ctx);

void vw_notify_ctx_close(vw_notify_ctx_t *ctx);

/*
 * share_received: call when a SHARE_GRANT targeting another user is
 * created (never for an anonymous LINK_ACCESS redemption — there is no
 * "you" to notify there). sharer_username and item_name are plain,
 * display-only text (already validated elsewhere as a real username /
 * file leaf name) — never attacker-controlled free-form content.
 */
void vw_notify_share_received(vw_notify_ctx_t *ctx, uint64_t target_user_id,
                               const char *sharer_username,
                               const char *item_name);

/*
 * new_login: call on a successful, FRESH AUTH_REQUEST only. Never call
 * this for SESSION_RESUME — that is the daemon's ordinary reconnect path
 * and would otherwise fire on every flaky network blip (docs/PROTOCOL.md
 * §7.13 / TASK-205's design). peer_ip is display-only context, never a
 * secret and never used for any decision here.
 */
void vw_notify_new_login(vw_notify_ctx_t *ctx, uint64_t user_id,
                          const char *peer_ip);

/*
 * account_security_change: call on a real change to password or 2FA
 * enrollment. `what_changed` must be one of this module's own
 * pre-approved phrases (see vw_notify.c) — never caller-supplied free
 * text, so this can never become a vector for injecting attacker content
 * into an email a user is likely to trust.
 */
void vw_notify_account_security_change(vw_notify_ctx_t *ctx, uint64_t user_id,
                                        const char *what_changed);

/*
 * quota_warning trigger, shaped to match vw_store_quota_hook_fn exactly
 * (vw_store.h) — register with:
 *   vw_store_set_quota_hook(store, vw_notify_quota_hook, notify_ctx);
 * `userdata` must be the vw_notify_ctx_t* returned by vw_notify_ctx_open.
 *
 * Edge-triggered at 90% of quota_bytes: fires once on crossing into the
 * warning zone, and re-arms (silently, no email) once usage drops back
 * under it — never a repeat reminder while it stays bad (TASK-205's
 * debounce requirement). An unlimited account (quota_bytes == 0) never
 * fires. The debounce state lives here, in-memory, per notify_ctx — it is
 * NOT persisted, so a server restart re-arms every account (the next
 * upload that's still over threshold will re-fire once); accepted as a
 * harmless, bounded-impact simplification for a personal-self-hosted-
 * scale project, not a hidden correctness gap.
 */
void vw_notify_quota_hook(void *userdata, uint64_t user_id,
                           uint64_t used_bytes, uint64_t quota_bytes);

/* ── Admin operational alerts (TASK-208) ─────────────────────────────────── */

/*
 * Admin-category configuration, sourced entirely from vapourwaultd.conf
 * (never the wire — TASK-205's design deliberately keeps these
 * operator-set-once knobs, not per-session user state). All *_enabled
 * fields default OFF; admin_email is required if any is on — enforced by
 * vw_server_main.c's startup validation (fail loud, never a silent
 * no-op), not by this module.
 */
typedef struct {
    char     admin_email[256];             /* recipient for every admin category */
    int      replica_lag_enabled;
    int      acme_renewal_failure_enabled;
    int      disk_capacity_enabled;
    int      lockout_spike_enabled;
    int      crash_recovery_enabled;
    uint32_t replica_lag_threshold_entries; /* oplog entries a replica may lag by */
    uint32_t disk_capacity_threshold_pct;   /* 0-100 */
    uint32_t lockout_spike_threshold_count; /* lockouts within the window below */
    uint32_t lockout_spike_window_secs;
} vw_notify_admin_cfg_t;

#define VW_NOTIFY_REPLICA_LAG_THRESHOLD_ENTRIES_DEFAULT 1000u
#define VW_NOTIFY_DISK_CAPACITY_THRESHOLD_PCT_DEFAULT   90u
#define VW_NOTIFY_LOCKOUT_SPIKE_THRESHOLD_COUNT_DEFAULT 10u
#define VW_NOTIFY_LOCKOUT_SPIKE_WINDOW_SECS_DEFAULT      300u

/*
 * Attach (or replace) the admin-category configuration. Copies cfg by
 * value — the caller's own copy need not outlive this call. Safe to call
 * again later (e.g. after a config reload).
 */
void vw_notify_ctx_set_admin_cfg(vw_notify_ctx_t *ctx, const vw_notify_admin_cfg_t *cfg);

/*
 * replica_lag: call once per GC cycle (or any periodic health check) with
 * the current lag in oplog entries (current tail - slowest replica's
 * acknowledged watermark) for the whole server — this is a per-server
 * signal, not per-user, so there is no target user_id. Edge-triggers at
 * replica_lag_threshold_entries; re-arms once lag drops back under it.
 */
void vw_notify_replica_lag(vw_notify_ctx_t *ctx, uint64_t lag_entries);

/*
 * acme_renewal_failure: call on every failed renewal attempt. One-shot —
 * ACME renewal already only runs on its own slow schedule (default:
 * checked once a day, renewing days before expiry), so every failure is
 * itself a discrete, actionable event, not a continuous bad state to
 * debounce.
 */
void vw_notify_acme_renewal_failure(vw_notify_ctx_t *ctx, const char *reason);

/*
 * disk_capacity: call periodically (same cadence as replica_lag above)
 * with the storage root's current disk usage percentage (0-100).
 * Edge-triggers at disk_capacity_threshold_pct; re-arms once usage drops
 * back under it.
 */
void vw_notify_disk_capacity(vw_notify_ctx_t *ctx, uint32_t used_pct);

/*
 * lockout_spike: call whenever an account lockout occurs (vw_auth.c).
 * Maintains its own rolling-window count internally; edge-triggers when
 * the count of lockouts within lockout_spike_window_secs reaches
 * lockout_spike_threshold_count, re-arms once the rate drops back under
 * it (the window quiets down).
 */
void vw_notify_lockout_spike(vw_notify_ctx_t *ctx);

/*
 * crash_recovery: call once at startup if vw_oplog_did_recover_from_crash
 * returned true. One-shot — tied to this single startup event.
 */
void vw_notify_crash_recovery(vw_notify_ctx_t *ctx);

#ifdef __cplusplus
}
#endif
#endif /* VW_NOTIFY_H */
