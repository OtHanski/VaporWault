/*
 * test_vw_storage_gc.c — regression tests for TASK-00266.
 *
 * Two related bugs found while root-causing a flaky integration test
 * (test_notify_alerts.py::test_user_category_quota_warning_edge_triggers_and_rearms
 * intermittently observed 2 quota_warning emails instead of 1):
 *
 *   1. chunk_put_impl's "entry && ref_count == 0" branch (vw_storage.c)
 *      unconditionally charged quota again, under the mistaken belief it
 *      could only be reached by a genuinely GC'd-and-reused hash. It
 *      cannot: vw_storage_gc_run's Phase A fully erases a collected
 *      hash from the in-memory table (ht_find returns NULL for it
 *      afterwards), so the only way to reach that branch is a second
 *      chunk_put call for a hash whose first call already inserted a
 *      ref_count == 0 entry and already charged its quota — i.e. a
 *      retry or a race against the SAME in-flight, not-yet-committed
 *      upload. Charging again there double-charged a single logical
 *      upload.
 *
 *   2. Even with (1) fixed, vw_storage_gc_run's Phase A was free to
 *      collect a chunk sitting at ref_count == 0 between CHUNK_UPLOAD
 *      and its FILE_COMMIT (intentional per TASK-180) the moment GC next
 *      ran — safe only so long as gc_interval_secs comfortably exceeds
 *      every real upload-to-commit round trip. Under load (or a
 *      deliberately short gc_interval_secs, which several integration
 *      tests need for unrelated reasons) that assumption can fail: GC
 *      collects a chunk still genuinely in flight, decrementing quota
 *      out from under it and failing the pending FILE_COMMIT's addref
 *      with NOT_FOUND — which a client then retries, re-uploading and
 *      re-charging quota, crossing a debounced threshold a second time.
 *
 * Fixed with an explicit, in-memory-only grace period (gc_grace_entry_t
 * in vw_storage.c) independent of gc_interval_secs, and by making the
 * "entry && ref_count == 0" branch behave like the sibling
 * "entry && ref_count > 0" race branch (a no-op presence-check for a
 * real upload, never a second quota charge).
 */

#include "vw_test.h"
#include "vw_storage.h"
#include "vw_store.h"
#include "vw_oplog.h"
#include "vw_crypto.h"
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#  define VW_SLEEP_SECS(n) Sleep((n) * 1000)
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  define VW_PID() ((unsigned)getpid())
#  define VW_SLEEP_SECS(n) sleep(n)
#endif

/* ── Temp-dir helper (same pattern as test_vw_storage_parity.c) ──────────── */

static void make_tmpdir(char *out, size_t sz, const char *label)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_storagegctest_%u_%s", tmp, VW_PID(), label);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_storagegctest_%u_%s", VW_PID(), label);
    mkdir(out, 0700);
#endif
}

static uint32_t g_rng_state = 0x2545F491u;
static uint32_t next_rand(void)
{
    g_rng_state ^= g_rng_state << 13;
    g_rng_state ^= g_rng_state >> 17;
    g_rng_state ^= g_rng_state << 5;
    return g_rng_state;
}

static void fill_random(uint8_t *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) buf[i] = (uint8_t)(next_rand() & 0xFF);
}

#define TEST_USER_ID 1u
#define TEST_CHUNK_LEN 4096u

VW_TEST_SUITE("vw_storage_gc") {
    VW_ASSERT_OK(vw_crypto_init());

    VW_TEST_CASE("a second chunk_put for the same not-yet-committed hash does not double-charge quota") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "dup");

        vw_oplog_t *oplog = NULL;
        vw_store_t *store = NULL;
        vw_storage_t *st = NULL;
        VW_ASSERT_OK(vw_oplog_open(tmpdir, &oplog));
        VW_ASSERT_OK(vw_store_open(tmpdir, oplog, &store));
        VW_ASSERT_OK(vw_storage_open(tmpdir, &st));
        vw_storage_set_store(st, store);
        VW_ASSERT_OK(vw_store_quota_set(store, TEST_USER_ID, 1000000));

        uint8_t data[TEST_CHUNK_LEN];
        fill_random(data, sizeof(data));
        uint8_t hash[VW_HASH_BYTES];
        VW_ASSERT_OK(vw_crypto_sha256(data, sizeof(data), hash));

        /* First upload: establishes presence at ref_count == 0 (TASK-180 —
         * a real upload leaves ref-counting to the FILE_COMMIT addref that
         * hasn't happened yet), charges quota once. */
        VW_ASSERT_OK(vw_storage_chunk_put(st, hash, data, sizeof(data), TEST_USER_ID));

        vw_quota_record_t q;
        VW_ASSERT_OK(vw_store_quota_get(store, TEST_USER_ID, &q));
        VW_ASSERT_EQ(q.used_bytes, (uint64_t)TEST_CHUNK_LEN);

        /* Second call for the identical hash, before any addref — exactly
         * what a client retry (or a race between two uploaders of the
         * same brand-new content) looks like from chunk_put_impl's side.
         * Must be a pure no-op: same content already present, already
         * charged. */
        VW_ASSERT_OK(vw_storage_chunk_put(st, hash, data, sizeof(data), TEST_USER_ID));

        VW_ASSERT_OK(vw_store_quota_get(store, TEST_USER_ID, &q));
        VW_ASSERT_EQ(q.used_bytes, (uint64_t)TEST_CHUNK_LEN);

        /* The eventual FILE_COMMIT's addref must still succeed once. */
        VW_ASSERT_OK(vw_storage_chunk_addref(st, hash));

        uint8_t *out_data = NULL; uint32_t out_len = 0;
        VW_ASSERT_OK(vw_storage_chunk_get(st, hash, &out_data, &out_len));
        VW_ASSERT_EQ(out_len, (uint32_t)TEST_CHUNK_LEN);
        free(out_data);

        vw_storage_close(st);
        vw_store_close(store);
        vw_oplog_close(oplog);
    }

    VW_TEST_CASE("GC does not collect a not-yet-committed chunk within its grace period") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "grace_hold");

        vw_oplog_t *oplog = NULL;
        vw_store_t *store = NULL;
        vw_storage_t *st = NULL;
        VW_ASSERT_OK(vw_oplog_open(tmpdir, &oplog));
        VW_ASSERT_OK(vw_store_open(tmpdir, oplog, &store));
        VW_ASSERT_OK(vw_storage_open(tmpdir, &st));
        vw_storage_set_store(st, store);
        VW_ASSERT_OK(vw_store_quota_set(store, TEST_USER_ID, 1000000));
        /* Comfortably longer than this test can possibly take. */
        vw_storage_set_gc_grace_secs_for_test(st, 60);

        uint8_t data[TEST_CHUNK_LEN];
        fill_random(data, sizeof(data));
        uint8_t hash[VW_HASH_BYTES];
        VW_ASSERT_OK(vw_crypto_sha256(data, sizeof(data), hash));

        VW_ASSERT_OK(vw_storage_chunk_put(st, hash, data, sizeof(data), TEST_USER_ID));

        /* Simulate GC racing a slow-but-legitimate FILE_COMMIT: run it
         * immediately, well within the grace window. */
        VW_ASSERT_OK(vw_storage_gc_run(st));

        /* The chunk must have survived... */
        uint8_t *out_data = NULL; uint32_t out_len = 0;
        VW_ASSERT_OK(vw_storage_chunk_get(st, hash, &out_data, &out_len));
        free(out_data);

        /* ...and quota must still reflect the one real upload, not have
         * been silently decremented by a GC collection that shouldn't
         * have happened. */
        vw_quota_record_t q;
        VW_ASSERT_OK(vw_store_quota_get(store, TEST_USER_ID, &q));
        VW_ASSERT_EQ(q.used_bytes, (uint64_t)TEST_CHUNK_LEN);

        /* The delayed FILE_COMMIT's addref must still succeed — this is
         * the exact call that returned VW_ERR_NOT_FOUND in the pre-fix
         * race, forcing the client to retry the whole upload. */
        VW_ASSERT_OK(vw_storage_chunk_addref(st, hash));

        vw_storage_close(st);
        vw_store_close(store);
        vw_oplog_close(oplog);
    }

    VW_TEST_CASE("GC collects a genuinely abandoned chunk once its grace period expires") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "grace_expire");

        vw_oplog_t *oplog = NULL;
        vw_store_t *store = NULL;
        vw_storage_t *st = NULL;
        VW_ASSERT_OK(vw_oplog_open(tmpdir, &oplog));
        VW_ASSERT_OK(vw_store_open(tmpdir, oplog, &store));
        VW_ASSERT_OK(vw_storage_open(tmpdir, &st));
        vw_storage_set_store(st, store);
        VW_ASSERT_OK(vw_store_quota_set(store, TEST_USER_ID, 1000000));
        vw_storage_set_gc_grace_secs_for_test(st, 1);

        uint8_t data[TEST_CHUNK_LEN];
        fill_random(data, sizeof(data));
        uint8_t hash[VW_HASH_BYTES];
        VW_ASSERT_OK(vw_crypto_sha256(data, sizeof(data), hash));

        /* Uploaded, never committed — a genuinely abandoned upload. */
        VW_ASSERT_OK(vw_storage_chunk_put(st, hash, data, sizeof(data), TEST_USER_ID));

        /* A GC pass immediately after must still hold it (grace not yet
         * expired) — otherwise this test would prove nothing about the
         * grace period actually gating anything. */
        VW_ASSERT_OK(vw_storage_gc_run(st));
        uint8_t *out_data = NULL; uint32_t out_len = 0;
        VW_ASSERT_OK(vw_storage_chunk_get(st, hash, &out_data, &out_len));
        free(out_data);

        /* Let real wall-clock time pass the 1-second grace window (same
         * pattern as test_vw_gc.c's trash_retention_secs tests). */
        VW_SLEEP_SECS(2);

        VW_ASSERT_OK(vw_storage_gc_run(st));

        /* Now genuinely gone... */
        VW_ASSERT_ERR(vw_storage_chunk_get(st, hash, &out_data, &out_len), VW_ERR_NOT_FOUND);

        /* ...and its quota was reclaimed, not leaked forever. */
        vw_quota_record_t q;
        VW_ASSERT_OK(vw_store_quota_get(store, TEST_USER_ID, &q));
        VW_ASSERT_EQ(q.used_bytes, (uint64_t)0);

        vw_storage_close(st);
        vw_store_close(store);
        vw_oplog_close(oplog);
    }

    VW_TEST_CASE("a real delete is immediately GC-eligible even under a long upload grace period") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "delete_promptly");

        vw_oplog_t *oplog = NULL;
        vw_store_t *store = NULL;
        vw_storage_t *st = NULL;
        VW_ASSERT_OK(vw_oplog_open(tmpdir, &oplog));
        VW_ASSERT_OK(vw_store_open(tmpdir, oplog, &store));
        VW_ASSERT_OK(vw_storage_open(tmpdir, &st));
        vw_storage_set_store(st, store);
        VW_ASSERT_OK(vw_store_quota_set(store, TEST_USER_ID, 1000000));
        /* A long grace period must not delay reclaiming space for a
         * chunk that was actually committed and then explicitly deleted
         * (the quota_warning integration test's delete-then-recross
         * scenario depends on this happening promptly). */
        vw_storage_set_gc_grace_secs_for_test(st, 60);

        uint8_t data[TEST_CHUNK_LEN];
        fill_random(data, sizeof(data));
        uint8_t hash[VW_HASH_BYTES];
        VW_ASSERT_OK(vw_crypto_sha256(data, sizeof(data), hash));

        VW_ASSERT_OK(vw_storage_chunk_put(st, hash, data, sizeof(data), TEST_USER_ID));
        VW_ASSERT_OK(vw_storage_chunk_addref(st, hash));   /* FILE_COMMIT */
        VW_ASSERT_OK(vw_storage_chunk_decref(st, hash));   /* FILE_DELETE, back to ref_count 0 */

        /* GC's very next pass — no sleep — must collect it despite the
         * 60s upload grace period configured above, because addref
         * already cleared it. */
        VW_ASSERT_OK(vw_storage_gc_run(st));

        uint8_t *out_data = NULL; uint32_t out_len = 0;
        VW_ASSERT_ERR(vw_storage_chunk_get(st, hash, &out_data, &out_len), VW_ERR_NOT_FOUND);

        vw_quota_record_t q;
        VW_ASSERT_OK(vw_store_quota_get(store, TEST_USER_ID, &q));
        VW_ASSERT_EQ(q.used_bytes, (uint64_t)0);

        vw_storage_close(st);
        vw_store_close(store);
        vw_oplog_close(oplog);
    }
}
VW_TEST_SUITE_END()
