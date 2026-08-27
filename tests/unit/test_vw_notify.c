/*
 * test_vw_notify.c — unit tests for vw_notify (TASK-207/208).
 *
 * Covers: default-off (no send with prefs unset), opt-in gating per
 * user category, quota_warning's edge-trigger/re-arm debounce, that no
 * email body ever contains a password/session-token-shaped secret, and
 * (TASK-208) the five admin categories' own enable-gating and
 * edge-trigger/re-arm/one-shot behavior. Uses
 * vw_notify_test_set_smtp_send_fn to record calls instead of doing real
 * network I/O — see vw_notify.c's own comment on that seam.
 *
 * Full end-to-end (real wire messages, real SMTP-shaped server,
 * fail-loud config validation) coverage is TASK-213's job; this file
 * exercises vw_notify.c's own dispatch/debounce logic directly.
 */

#include "vw_test.h"
#include "vw_notify.h"
#include "vw_store.h"
#include "vw_oplog.h"
#include "../../src/core/vw_proto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#  include <windows.h>
#  include <process.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  include <dirent.h>
#  define VW_PID() ((unsigned)getpid())
#endif

/* Declared in vw_notify.c but not vw_notify.h — internal test hook only. */
void vw_notify_test_set_smtp_send_fn(
    vw_err_t (*fn)(const vw_smtp_cfg_t *, const char *, const char *,
                   const char *, char *, size_t));

/* ── Temp-dir helpers (same pattern as test_vw_share.c) ──────────────────── */

static void make_tmpdir(char *out, size_t sz, const char *label)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_notifytest_%u_%s", tmp, VW_PID(), label);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_notifytest_%u_%s", VW_PID(), label);
    mkdir(out, 0700);
#endif
}

static void rm_rf(const char *dir)
{
#ifdef _WIN32
    char pat[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            char child[MAX_PATH];
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
                continue;
            snprintf(child, sizeof(child), "%s\\%s", dir, fd.cFileName);
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                rm_rf(child);
            else
                DeleteFileA(child);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryA(dir);
#else
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char child[512];
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        snprintf(child, sizeof(child), "%s/%s", dir, e->d_name);
        if (stat(child, &st) == 0 && S_ISDIR(st.st_mode))
            rm_rf(child);
        else
            remove(child);
    }
    closedir(d);
    rmdir(dir);
#endif
}

/* ── Fake SMTP send: records every call instead of touching the network ─── */

#define MAX_RECORDED 16

typedef struct {
    char to_addr[256];
    char subject[256];
    char body[1024];
} recorded_send_t;

static recorded_send_t g_recorded[MAX_RECORDED];
static int              g_recorded_count = 0;

static void reset_recorder(void) { g_recorded_count = 0; }

static vw_err_t fake_smtp_send(const vw_smtp_cfg_t *cfg, const char *to_addr,
                                const char *subject, const char *body,
                                char *out_err_msg, size_t err_msg_size)
{
    (void)cfg; (void)out_err_msg; (void)err_msg_size;
    if (g_recorded_count < MAX_RECORDED) {
        recorded_send_t *r = &g_recorded[g_recorded_count++];
        snprintf(r->to_addr, sizeof(r->to_addr), "%s", to_addr ? to_addr : "");
        snprintf(r->subject, sizeof(r->subject), "%s", subject ? subject : "");
        snprintf(r->body, sizeof(r->body), "%s", body ? body : "");
    }
    return VW_OK;
}

/* ── Stack helper ─────────────────────────────────────────────────────────── */

typedef struct {
    char         tmpdir[512];
    vw_oplog_t  *oplog;
    vw_store_t  *store;
} notify_stack_t;

static void stack_open(notify_stack_t *s, const char *label)
{
    make_tmpdir(s->tmpdir, sizeof(s->tmpdir), label);
    VW_ASSERT_OK(vw_oplog_open(s->tmpdir, &s->oplog));
    VW_ASSERT_OK(vw_store_open(s->tmpdir, s->oplog, &s->store));
}

static void stack_close(notify_stack_t *s)
{
    vw_store_close(s->store);
    vw_oplog_close(s->oplog);
    rm_rf(s->tmpdir);
}

static uint64_t make_user(notify_stack_t *s, const char *username, const char *email)
{
    vw_user_record_t rec;
    uint64_t uid = 0;
    memset(&rec, 0, sizeof(rec));
    snprintf((char *)rec.username, sizeof(rec.username), "%s", username);
    snprintf((char *)rec.email, sizeof(rec.email), "%s", email);
    rec.is_active = 1;
    VW_ASSERT_OK(vw_store_user_create(s->store, &rec, &uid));
    return uid;
}

/* A real-looking SMTP config so notify_send_if_enabled's "is SMTP
 * configured" check passes; fake_smtp_send never actually connects. */
static vw_smtp_cfg_t make_smtp_cfg(void)
{
    vw_smtp_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.host, sizeof(cfg.host), "smtp.example.invalid");
    cfg.port = 587;
    snprintf(cfg.from_addr, sizeof(cfg.from_addr), "vaporwault@example.invalid");
    cfg.tls_mode = VW_SMTP_TLS_STARTTLS;
    return cfg;
}

VW_TEST_SUITE("vw_notify") {
    vw_notify_test_set_smtp_send_fn(fake_smtp_send);

    VW_TEST_CASE("default off: no send for any category when prefs is never set") {
        notify_stack_t s = {0};
        stack_open(&s, "default_off");
        {
            vw_smtp_cfg_t smtp = make_smtp_cfg();
            uint64_t uid = make_user(&s, "alice", "alice@example.invalid");

            vw_notify_ctx_t *ctx = NULL;
            VW_ASSERT_OK(vw_notify_ctx_open(s.store, &smtp, &ctx));

            reset_recorder();
            vw_notify_share_received(ctx, uid, "bob", "notes.txt");
            vw_notify_new_login(ctx, uid, "10.0.0.1");
            vw_notify_account_security_change(ctx, uid, "your password was changed");
            VW_ASSERT_EQ(0, g_recorded_count);

            vw_notify_ctx_close(ctx);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("share_received: fires only when that bit is set") {
        notify_stack_t s = {0};
        stack_open(&s, "share_received");
        {
            vw_smtp_cfg_t smtp = make_smtp_cfg();
            uint64_t uid = make_user(&s, "alice", "alice@example.invalid");

            vw_notify_ctx_t *ctx = NULL;
            VW_ASSERT_OK(vw_notify_ctx_open(s.store, &smtp, &ctx));

            reset_recorder();
            vw_notify_share_received(ctx, uid, "bob", "notes.txt");
            VW_ASSERT_EQ(0, g_recorded_count); /* not opted in yet */

            VW_ASSERT_OK(vw_store_notify_prefs_set(s.store, uid, VW_NOTIFY_SHARE_RECEIVED));
            vw_notify_share_received(ctx, uid, "bob", "notes.txt");
            VW_ASSERT_EQ(1, g_recorded_count);
            VW_ASSERT(strcmp(g_recorded[0].to_addr, "alice@example.invalid") == 0);
            VW_ASSERT(strstr(g_recorded[0].body, "bob") != NULL);
            VW_ASSERT(strstr(g_recorded[0].body, "notes.txt") != NULL);

            /* Other categories still off. */
            reset_recorder();
            vw_notify_new_login(ctx, uid, "10.0.0.1");
            vw_notify_account_security_change(ctx, uid, "your password was changed");
            VW_ASSERT_EQ(0, g_recorded_count);

            vw_notify_ctx_close(ctx);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("no email body ever contains a password/token-shaped secret") {
        notify_stack_t s = {0};
        stack_open(&s, "no_secrets");
        {
            vw_smtp_cfg_t smtp = make_smtp_cfg();
            uint64_t uid = make_user(&s, "alice", "alice@example.invalid");
            VW_ASSERT_OK(vw_store_notify_prefs_set(s.store, uid, VW_NOTIFY_ALL_KNOWN));

            vw_notify_ctx_t *ctx = NULL;
            VW_ASSERT_OK(vw_notify_ctx_open(s.store, &smtp, &ctx));

            const char *secret = "SuperSecretPassword123";
            reset_recorder();
            vw_notify_share_received(ctx, uid, "bob", "notes.txt");
            vw_notify_new_login(ctx, uid, "10.0.0.1");
            vw_notify_account_security_change(ctx, uid, "your password was changed");
            VW_ASSERT_EQ(3, g_recorded_count);
            for (int i = 0; i < g_recorded_count; i++) {
                VW_ASSERT(strstr(g_recorded[i].body, secret) == NULL);
                VW_ASSERT(strstr(g_recorded[i].subject, secret) == NULL);
            }

            vw_notify_ctx_close(ctx);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("quota_warning: edge-triggers once, re-arms, fires again on a second crossing") {
        notify_stack_t s = {0};
        stack_open(&s, "quota_warning");
        {
            vw_smtp_cfg_t smtp = make_smtp_cfg();
            uint64_t uid = make_user(&s, "alice", "alice@example.invalid");
            VW_ASSERT_OK(vw_store_notify_prefs_set(s.store, uid, VW_NOTIFY_QUOTA_WARNING));

            vw_notify_ctx_t *ctx = NULL;
            VW_ASSERT_OK(vw_notify_ctx_open(s.store, &smtp, &ctx));

            uint64_t quota = 1000;
            reset_recorder();

            /* Under threshold (50%) — no fire. */
            vw_notify_quota_hook(ctx, uid, 500, quota);
            VW_ASSERT_EQ(0, g_recorded_count);

            /* Cross into the 90% zone — fires exactly once. */
            vw_notify_quota_hook(ctx, uid, 950, quota);
            VW_ASSERT_EQ(1, g_recorded_count);

            /* Still over — no repeat while it stays bad. */
            vw_notify_quota_hook(ctx, uid, 980, quota);
            vw_notify_quota_hook(ctx, uid, 999, quota);
            VW_ASSERT_EQ(1, g_recorded_count);

            /* Drops back under — silently re-arms, no email. */
            vw_notify_quota_hook(ctx, uid, 400, quota);
            VW_ASSERT_EQ(1, g_recorded_count);

            /* Crosses again — fires a second time. */
            vw_notify_quota_hook(ctx, uid, 960, quota);
            VW_ASSERT_EQ(2, g_recorded_count);

            /* Unlimited (quota_bytes == 0) never fires regardless of used_bytes. */
            reset_recorder();
            vw_notify_quota_hook(ctx, uid, 999999, 0);
            VW_ASSERT_EQ(0, g_recorded_count);

            vw_notify_ctx_close(ctx);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("SMTP not configured: every category is a silent no-op") {
        notify_stack_t s = {0};
        stack_open(&s, "smtp_disabled");
        {
            uint64_t uid = make_user(&s, "alice", "alice@example.invalid");
            VW_ASSERT_OK(vw_store_notify_prefs_set(s.store, uid, VW_NOTIFY_ALL_KNOWN));

            vw_notify_ctx_t *ctx = NULL;
            VW_ASSERT_OK(vw_notify_ctx_open(s.store, NULL /* smtp disabled */, &ctx));

            reset_recorder();
            vw_notify_share_received(ctx, uid, "bob", "notes.txt");
            vw_notify_new_login(ctx, uid, "10.0.0.1");
            vw_notify_account_security_change(ctx, uid, "your password was changed");
            vw_notify_quota_hook(ctx, uid, 999, 1000);
            VW_ASSERT_EQ(0, g_recorded_count);

            vw_notify_ctx_close(ctx);
        }
        stack_close(&s);
    }

    /* ── Admin categories (TASK-208) ─────────────────────────────────────── */

    VW_TEST_CASE("admin: disabled category never fires even when its condition is true") {
        notify_stack_t s = {0};
        stack_open(&s, "admin_disabled");
        {
            vw_smtp_cfg_t smtp = make_smtp_cfg();
            vw_notify_ctx_t *ctx = NULL;
            VW_ASSERT_OK(vw_notify_ctx_open(s.store, &smtp, &ctx));
            /* admin_cfg never set — every *_enabled defaults to 0/false via calloc. */

            reset_recorder();
            vw_notify_replica_lag(ctx, 999999);
            vw_notify_acme_renewal_failure(ctx, "timeout");
            vw_notify_disk_capacity(ctx, 99);
            vw_notify_lockout_spike(ctx);
            vw_notify_crash_recovery(ctx);
            VW_ASSERT_EQ(0, g_recorded_count);

            vw_notify_ctx_close(ctx);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("admin: enabled category with no admin_email configured is a no-op") {
        notify_stack_t s = {0};
        stack_open(&s, "admin_no_email");
        {
            vw_smtp_cfg_t smtp = make_smtp_cfg();
            vw_notify_ctx_t *ctx = NULL;
            VW_ASSERT_OK(vw_notify_ctx_open(s.store, &smtp, &ctx));

            vw_notify_admin_cfg_t acfg;
            memset(&acfg, 0, sizeof(acfg));
            acfg.crash_recovery_enabled = 1; /* admin_email left empty */
            vw_notify_ctx_set_admin_cfg(ctx, &acfg);

            reset_recorder();
            vw_notify_crash_recovery(ctx);
            VW_ASSERT_EQ(0, g_recorded_count);

            vw_notify_ctx_close(ctx);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("admin: replica_lag edge-triggers, re-arms, fires again — recipient is admin_email") {
        notify_stack_t s = {0};
        stack_open(&s, "admin_replica_lag");
        {
            vw_smtp_cfg_t smtp = make_smtp_cfg();
            vw_notify_ctx_t *ctx = NULL;
            VW_ASSERT_OK(vw_notify_ctx_open(s.store, &smtp, &ctx));

            vw_notify_admin_cfg_t acfg;
            memset(&acfg, 0, sizeof(acfg));
            snprintf(acfg.admin_email, sizeof(acfg.admin_email), "admin@example.invalid");
            acfg.replica_lag_enabled = 1;
            acfg.replica_lag_threshold_entries = 100;
            vw_notify_ctx_set_admin_cfg(ctx, &acfg);

            reset_recorder();
            vw_notify_replica_lag(ctx, 10);   /* under threshold */
            VW_ASSERT_EQ(0, g_recorded_count);

            vw_notify_replica_lag(ctx, 150);  /* crosses */
            VW_ASSERT_EQ(1, g_recorded_count);
            VW_ASSERT(strcmp(g_recorded[0].to_addr, "admin@example.invalid") == 0);

            vw_notify_replica_lag(ctx, 200);  /* still over — no repeat */
            VW_ASSERT_EQ(1, g_recorded_count);

            vw_notify_replica_lag(ctx, 5);    /* drops back under — re-arms silently */
            VW_ASSERT_EQ(1, g_recorded_count);

            vw_notify_replica_lag(ctx, 150);  /* crosses again */
            VW_ASSERT_EQ(2, g_recorded_count);

            vw_notify_ctx_close(ctx);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("admin: disk_capacity edge-triggers and re-arms") {
        notify_stack_t s = {0};
        stack_open(&s, "admin_disk_capacity");
        {
            vw_smtp_cfg_t smtp = make_smtp_cfg();
            vw_notify_ctx_t *ctx = NULL;
            VW_ASSERT_OK(vw_notify_ctx_open(s.store, &smtp, &ctx));

            vw_notify_admin_cfg_t acfg;
            memset(&acfg, 0, sizeof(acfg));
            snprintf(acfg.admin_email, sizeof(acfg.admin_email), "admin@example.invalid");
            acfg.disk_capacity_enabled = 1;
            acfg.disk_capacity_threshold_pct = 90;
            vw_notify_ctx_set_admin_cfg(ctx, &acfg);

            reset_recorder();
            vw_notify_disk_capacity(ctx, 50);
            VW_ASSERT_EQ(0, g_recorded_count);
            vw_notify_disk_capacity(ctx, 95);
            VW_ASSERT_EQ(1, g_recorded_count);
            vw_notify_disk_capacity(ctx, 96);
            VW_ASSERT_EQ(1, g_recorded_count);
            vw_notify_disk_capacity(ctx, 10);
            vw_notify_disk_capacity(ctx, 91);
            VW_ASSERT_EQ(2, g_recorded_count);

            vw_notify_ctx_close(ctx);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("admin: lockout_spike fires once at the threshold, re-arms after the window quiets") {
        notify_stack_t s = {0};
        stack_open(&s, "admin_lockout_spike");
        {
            vw_smtp_cfg_t smtp = make_smtp_cfg();
            vw_notify_ctx_t *ctx = NULL;
            VW_ASSERT_OK(vw_notify_ctx_open(s.store, &smtp, &ctx));

            vw_notify_admin_cfg_t acfg;
            memset(&acfg, 0, sizeof(acfg));
            snprintf(acfg.admin_email, sizeof(acfg.admin_email), "admin@example.invalid");
            acfg.lockout_spike_enabled = 1;
            acfg.lockout_spike_threshold_count = 3;
            acfg.lockout_spike_window_secs = 300;
            vw_notify_ctx_set_admin_cfg(ctx, &acfg);

            reset_recorder();
            vw_notify_lockout_spike(ctx); /* 1 */
            vw_notify_lockout_spike(ctx); /* 2 */
            VW_ASSERT_EQ(0, g_recorded_count);
            vw_notify_lockout_spike(ctx); /* 3 — crosses */
            VW_ASSERT_EQ(1, g_recorded_count);
            vw_notify_lockout_spike(ctx); /* still >= 3 — no repeat */
            VW_ASSERT_EQ(1, g_recorded_count);

            vw_notify_ctx_close(ctx);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("admin: acme_renewal_failure and crash_recovery are one-shot, no debounce state") {
        notify_stack_t s = {0};
        stack_open(&s, "admin_oneshot");
        {
            vw_smtp_cfg_t smtp = make_smtp_cfg();
            vw_notify_ctx_t *ctx = NULL;
            VW_ASSERT_OK(vw_notify_ctx_open(s.store, &smtp, &ctx));

            vw_notify_admin_cfg_t acfg;
            memset(&acfg, 0, sizeof(acfg));
            snprintf(acfg.admin_email, sizeof(acfg.admin_email), "admin@example.invalid");
            acfg.acme_renewal_failure_enabled = 1;
            acfg.crash_recovery_enabled = 1;
            vw_notify_ctx_set_admin_cfg(ctx, &acfg);

            reset_recorder();
            vw_notify_acme_renewal_failure(ctx, "authorization fetch failed (status 403)");
            vw_notify_acme_renewal_failure(ctx, "authorization fetch failed (status 403)");
            VW_ASSERT_EQ(2, g_recorded_count); /* every call fires — no edge-trigger for one-shot categories */
            VW_ASSERT(strstr(g_recorded[0].body, "403") != NULL);

            vw_notify_crash_recovery(ctx);
            VW_ASSERT_EQ(3, g_recorded_count);

            vw_notify_ctx_close(ctx);
        }
        stack_close(&s);
    }
}
VW_TEST_SUITE_END()
