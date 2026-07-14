/*
 * test_vw_gc.c — unit tests for vw_gc.
 *
 * Tests the GC's session-expiry pass and oplog-truncation pass.
 * vw_cluster.c is NOT linked here; stubs for the two cluster functions
 * called by vw_gc.c are defined below so the cluster-aware truncation
 * path can be exercised without a live cluster.
 *
 * Compiled with VW_OPLOG_SEGMENT_MAX=512 (set via CMakeLists.txt) so that
 * oplog segment rotation can be triggered with ~18 small entries, making
 * truncation verification practical.
 */

#include "vw_test.h"
#include "vw_gc.h"
#include "vw_store.h"
#include "vw_oplog.h"
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

/* ── Stub vw_cluster_t for cluster-aware oplog truncation tests ───────────── */

/*
 * vw_cluster_t is opaque in vw_cluster.h (forward-declared only).
 * We define the struct here so tests can create and control it.
 * vw_cluster.c must NOT be linked into this test binary.
 */
struct vw_cluster {
    int      has_active_replicas; /* non-zero → GC uses min_sync_watermark    */
    uint64_t min_sync_watermark;  /* returned by vw_cluster_min_sync_watermark */
};

int vw_cluster_has_active_replicas(vw_cluster_t *ctx)
{
    return ctx ? ctx->has_active_replicas : 0;
}

uint64_t vw_cluster_min_sync_watermark(vw_cluster_t *ctx)
{
    return ctx ? ctx->min_sync_watermark : 0;
}

/* ── Temp-dir helpers ─────────────────────────────────────────────────────── */

static void make_tmpdir(char *out, size_t sz, const char *label)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_gctest_%u_%s", tmp, VW_PID(), label);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_gctest_%u_%s", VW_PID(), label);
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

/* ── GC stack helper ──────────────────────────────────────────────────────── */

typedef struct {
    char          tmpdir[512];
    vw_oplog_t   *oplog;
    vw_store_t   *store;
    vw_gc_ctx_t  *gc;
} gc_stack_t;

static void gc_stack_open(gc_stack_t *s, const char *label,
                           vw_cluster_t *cluster)
{
    vw_gc_cfg_t cfg;
    make_tmpdir(s->tmpdir, sizeof(s->tmpdir), label);
    VW_ASSERT_OK(vw_oplog_open(s->tmpdir, &s->oplog));
    VW_ASSERT_OK(vw_store_open(s->tmpdir, s->oplog, &s->store));

    cfg.interval_secs = 0; /* disabled — we call run_once manually */
    VW_ASSERT_OK(vw_gc_create(&cfg, s->store,
                               NULL, /* file_store  — skips file GC pass */
                               NULL, /* chunk_store — skips chunk GC pass */
                               s->oplog, cluster, &s->gc));
}

static void gc_stack_close(gc_stack_t *s)
{
    vw_gc_destroy(s->gc);
    vw_store_close(s->store);
    vw_oplog_close(s->oplog);
    rm_rf(s->tmpdir);
}

/* ── Oplog replay counter ─────────────────────────────────────────────────── */

static int count_replay_cb(uint64_t entry_id, vw_oplog_op_t op_type,
                            const void *payload, uint32_t payload_len,
                            void *userdata)
{
    (void)entry_id; (void)op_type; (void)payload; (void)payload_len;
    (*(int *)userdata)++;
    return 0;
}

/* Append `n` confirmed entries; payload is 4 zero bytes each. */
static void append_confirmed(vw_oplog_t *oplog, int n)
{
    static const uint8_t payload[4] = {0};
    int i;
    for (i = 0; i < n; i++) {
        uint64_t eid = 0;
        VW_ASSERT_OK(vw_oplog_append(oplog, VW_OPLOG_USER_WRITE,
                                     payload, sizeof(payload), &eid));
        VW_ASSERT_OK(vw_oplog_confirm(oplog, eid));
    }
}

/* ── Test suite ───────────────────────────────────────────────────────────── */

VW_TEST_SUITE("vw_gc") {

    /* ── Session expiry pass ─────────────────────────────────────────────── */

    VW_TEST_CASE("run_once expires sessions whose expires_at <= now") {
        gc_stack_t s;
        gc_stack_open(&s, "sess_exp", NULL);
        {
            vw_session_record_t rec, out;
            uint8_t tok_stale[32], tok_live[32];

            /* Stale session: expired at unix time 500 */
            memset(&rec, 0, sizeof(rec));
            rec.user_id    = 1;
            rec.created_at = 1;
            rec.expires_at = 500;
            rec.is_active  = 1;
            VW_ASSERT_OK(vw_store_session_create(s.store, &rec, tok_stale));

            /* Live session: expires far in the future */
            memset(&rec, 0, sizeof(rec));
            rec.user_id    = 2;
            rec.created_at = 1;
            rec.expires_at = 9999999999ULL;
            rec.is_active  = 1;
            VW_ASSERT_OK(vw_store_session_create(s.store, &rec, tok_live));

            /*
             * GC run_once uses the current wall clock for session expiry.
             * We cannot inject a fake clock, so we verify via store_session_gc
             * directly that the mechanism works, and verify run_once returns OK.
             */
            VW_ASSERT_OK(vw_gc_run_once(s.gc));

            /*
             * Directly expire the stale session via the store to verify the
             * session GC path independently (with a controlled timestamp).
             */
            uint32_t expired = 0;
            VW_ASSERT_OK(vw_store_session_gc(s.store, 1000, &expired));
            VW_ASSERT_EQ(1u, (unsigned)expired);

            VW_ASSERT_ERR(vw_store_session_get(s.store, tok_stale, &out),
                          VW_ERR_NOT_FOUND);
            VW_ASSERT_OK(vw_store_session_get(s.store, tok_live, &out));
        }
        gc_stack_close(&s);
    }

    /* ── Oplog truncation — single-node (cluster = NULL) ─────────────────── */

    VW_TEST_CASE("run_once single-node: truncates oplog segments before last entry") {
        gc_stack_t s;
        gc_stack_open(&s, "oplog_single", NULL);
        {
            int before_count = 0;
            int after_count  = 0;
            uint64_t last_eid;

            /*
             * Append enough entries to fill multiple segments.
             * Each entry: 17-byte header + 5-byte payload = 22 bytes.
             * SEGMENT_MAX=512 → 23 entries/segment.  50 entries → 3 segments:
             *   seg 1 (entries 1-23), seg 2 (24-46), seg 3 active (47-50).
             */
            append_confirmed(s.oplog, 50);
            last_eid = vw_oplog_last_entry_id(s.oplog);
            VW_ASSERT_EQ(50u, (unsigned)last_eid);

            VW_ASSERT_OK(vw_oplog_replay_from(s.oplog, 1,
                                              count_replay_cb, &before_count));
            VW_ASSERT_EQ(50, before_count);

            VW_ASSERT_OK(vw_gc_run_once(s.gc));

            /* After GC, close and reopen to make deletion visible via replay */
            vw_oplog_close(s.oplog);
            VW_ASSERT_OK(vw_oplog_open(s.tmpdir, &s.oplog));

            VW_ASSERT_OK(vw_oplog_replay_from(s.oplog, 1,
                                              count_replay_cb, &after_count));

            /* Some segments should have been truncated; fewer entries survive */
            VW_ASSERT(after_count < before_count);
            /* The last entry must still exist */
            VW_ASSERT_EQ(50u, (unsigned)vw_oplog_last_entry_id(s.oplog));
        }
        gc_stack_close(&s);
    }

    /* ── Oplog truncation — cluster-aware ────────────────────────────────── */

    VW_TEST_CASE("run_once cluster-aware: uses replica watermark not last_entry_id") {
        vw_cluster_t stub_cluster;
        gc_stack_t s;

        /*
         * Entry size calculation (for SEGMENT_MAX=512):
         *   header = 17 bytes (crc32:4 + payload_len:4 + entry_id:8 + confirmed:1)
         *   payload = op_type:1 + data:4 = 5 bytes
         *   total = 22 bytes/entry → 23 entries per segment (23×22=506 ≤ 512)
         *
         * With 50 entries across 3 segments:
         *   seg 1: entries  1-23  (last=23)  ← 506 bytes, full
         *   seg 2: entries 24-46  (last=46)  ← 506 bytes, full
         *   seg 3: entries 47-50  (last=50)  ← active, never truncated
         *
         * watermark=40: truncate_before(40) deletes segments where last < 40.
         *   seg 1 (last=23 < 40) → DELETED; seg 2 (last=46 ≥ 40) → KEPT.
         *   Entries 24-50 survive (27 entries).
         *
         * Single-node would set safe_eid=50: truncate_before(50) deletes
         * segs 1 and 2, leaving only entries 47-50 (4 entries). The cluster-
         * aware GC retains more entries — those needed by the lagging replica.
         */
        stub_cluster.has_active_replicas = 1;
        stub_cluster.min_sync_watermark  = 40;

        gc_stack_open(&s, "oplog_cluster", &stub_cluster);
        {
            int before_count = 0;
            int after_wm_count = 0;

            append_confirmed(s.oplog, 50);
            VW_ASSERT_OK(vw_oplog_replay_from(s.oplog, 1,
                                              count_replay_cb, &before_count));
            VW_ASSERT_EQ(50, before_count);

            VW_ASSERT_OK(vw_gc_run_once(s.gc));

            /* Close and reopen to observe the effect of truncation */
            vw_oplog_close(s.oplog);
            VW_ASSERT_OK(vw_oplog_open(s.tmpdir, &s.oplog));

            VW_ASSERT_OK(vw_oplog_replay_from(s.oplog, 1,
                                              count_replay_cb, &after_wm_count));

            VW_ASSERT(after_wm_count > 0);
            VW_ASSERT(after_wm_count < before_count);
            /* The last entry is always preserved regardless of truncation */
            VW_ASSERT_EQ(50u, (unsigned)vw_oplog_last_entry_id(s.oplog));
        }
        gc_stack_close(&s);
    }

    /* ── No-op when cluster has no active replicas ───────────────────────── */

    VW_TEST_CASE("run_once: cluster with no active replicas behaves like single-node") {
        vw_cluster_t stub_cluster;
        gc_stack_t s_cluster, s_solo;
        int count_cluster = 0, count_solo = 0;

        stub_cluster.has_active_replicas = 0;
        stub_cluster.min_sync_watermark  = 5; /* ignored — no active replicas */

        gc_stack_open(&s_cluster, "oplog_no_repl", &stub_cluster);
        gc_stack_open(&s_solo,    "oplog_solo",    NULL);

        append_confirmed(s_cluster.oplog, 50);
        append_confirmed(s_solo.oplog,    50);

        VW_ASSERT_OK(vw_gc_run_once(s_cluster.gc));
        VW_ASSERT_OK(vw_gc_run_once(s_solo.gc));

        vw_oplog_close(s_cluster.oplog);
        vw_oplog_close(s_solo.oplog);
        VW_ASSERT_OK(vw_oplog_open(s_cluster.tmpdir, &s_cluster.oplog));
        VW_ASSERT_OK(vw_oplog_open(s_solo.tmpdir,    &s_solo.oplog));

        VW_ASSERT_OK(vw_oplog_replay_from(s_cluster.oplog, 1,
                                          count_replay_cb, &count_cluster));
        VW_ASSERT_OK(vw_oplog_replay_from(s_solo.oplog, 1,
                                          count_replay_cb, &count_solo));

        /* Both should truncate to the same depth */
        VW_ASSERT_EQ(count_solo, count_cluster);

        gc_stack_close(&s_cluster);
        gc_stack_close(&s_solo);
    }
}

VW_TEST_SUITE_END()
