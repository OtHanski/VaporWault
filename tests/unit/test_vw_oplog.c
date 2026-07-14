/*
 * test_vw_oplog.c — crash-injection tests for vw_oplog (CJ-1 through CJ-5).
 *
 * These tests are the QA.06 sign-off gate for TASK-007 (vw_oplog).
 * A "crash" is simulated by closing the oplog context without calling
 * vw_oplog_confirm/abort for pending entries, then reopening — identical
 * to what happens when the server process is killed mid-operation.
 *
 * Compiled with VW_OPLOG_SEGMENT_MAX=512 so CJ-5 can trigger segment
 * rotation with a small number of appends (see CMakeLists.txt).
 *
 * CJ-1: Basic append + confirm survives close/reopen (happy path).
 * CJ-2: Unconfirmed entry is truncated on reopen (no data delivered).
 * CJ-3: Multi-entry: only confirmed entries survive an unconfirmed tail.
 * CJ-4: Out-of-order confirm: confirmed entry AFTER an unconfirmed hole
 *        is preserved (validates the break→continue fix in seg_scan).
 * CJ-5: Segment boundary: confirmed entries in the full segment survive;
 *        unconfirmed entry in the new segment is truncated.
 */

#include "vw_test.h"
#include "vw_oplog.h"
#include "vw_fs.h"
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

/* ── Temp-dir helpers ────────────────────────────────────────────────────── */

static void make_base_tmpdir(char *out, size_t sz)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_optest_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_optest_%u", VW_PID());
    mkdir(out, 0700);
#endif
}

static void rm_rf(const char *dir)
{
#ifdef _WIN32
    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) goto rmdir_only;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        char child[MAX_PATH];
        snprintf(child, sizeof(child), "%s\\%s", dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            rm_rf(child);
        else
            DeleteFileA(child);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
rmdir_only:
    RemoveDirectoryA(dir);
#else
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char child[512];
        snprintf(child, sizeof(child), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(child, &st) == 0 && S_ISDIR(st.st_mode))
            rm_rf(child);
        else
            remove(child);
    }
    closedir(d);
    rmdir(dir);
#endif
}

static void path_join(char *out, size_t sz, const char *dir, const char *name)
{
#ifdef _WIN32
    snprintf(out, sz, "%s\\%s", dir, name);
#else
    snprintf(out, sz, "%s/%s", dir, name);
#endif
}

static void make_testdir(char *out, size_t sz,
                          const char *base, const char *label)
{
    path_join(out, sz, base, label);
    vw_fs_ensure_dir(out);
}

/* ── Replay callback ─────────────────────────────────────────────────────── */

typedef struct {
    uint64_t      ids[128];
    vw_oplog_op_t ops[128];
    int           count;
} replay_ctx_t;

static int replay_collect(uint64_t entry_id, vw_oplog_op_t op_type,
                           const void *payload, uint32_t payload_len,
                           void *userdata)
{
    (void)payload; (void)payload_len;
    replay_ctx_t *r = (replay_ctx_t *)userdata;
    if (r->count < 128) {
        r->ids[r->count] = entry_id;
        r->ops[r->count] = op_type;
        r->count++;
    }
    return 0;
}

/* ── Common payload ──────────────────────────────────────────────────────── */

static const uint8_t PAYLOAD[4] = {0xAA, 0xBB, 0xCC, 0xDD};

/* ── Test suite ──────────────────────────────────────────────────────────── */

VW_TEST_SUITE("vw_oplog crash-injection") {

    char base[512];
    make_base_tmpdir(base, sizeof(base));

    /* ------------------------------------------------------------------ */
    VW_TEST_CASE("CJ-1: confirmed entry survives close/reopen") {
    /* ------------------------------------------------------------------ */
        char d[512]; make_testdir(d, sizeof(d), base, "cj1");
        vw_oplog_t *log = NULL;

        VW_ASSERT_OK(vw_oplog_open(d, &log));
        uint64_t id_a;
        VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_USER_WRITE,
                                     PAYLOAD, sizeof(PAYLOAD), &id_a));
        VW_ASSERT_OK(vw_oplog_confirm(log, id_a));
        vw_oplog_close(log);
        log = NULL;

        /* Reopen: recovery */
        VW_ASSERT_OK(vw_oplog_open(d, &log));
        replay_ctx_t r = {{0},{0},0};
        VW_ASSERT_OK(vw_oplog_replay_from(log, 0, replay_collect, &r));
        VW_ASSERT_EQ(r.count, 1);
        VW_ASSERT_EQ((int)r.ids[0], (int)id_a);
        VW_ASSERT_EQ((int)r.ops[0], (int)VW_OPLOG_USER_WRITE);
        vw_oplog_close(log);
    }

    /* ------------------------------------------------------------------ */
    VW_TEST_CASE("CJ-2: unconfirmed entry is truncated; replay delivers 0 entries") {
    /* ------------------------------------------------------------------ */
        char d[512]; make_testdir(d, sizeof(d), base, "cj2");
        vw_oplog_t *log = NULL;

        VW_ASSERT_OK(vw_oplog_open(d, &log));
        uint64_t id_a;
        VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_FILE_WRITE,
                                     PAYLOAD, sizeof(PAYLOAD), &id_a));
        /* Simulate crash: close without confirming id_a */
        vw_oplog_close(log);
        log = NULL;

        /* Reopen: recovery should truncate id_a */
        VW_ASSERT_OK(vw_oplog_open(d, &log));
        replay_ctx_t r = {{0},{0},0};
        VW_ASSERT_OK(vw_oplog_replay_from(log, 0, replay_collect, &r));
        VW_ASSERT_EQ(r.count, 0);
        vw_oplog_close(log);
    }

    /* ------------------------------------------------------------------ */
    VW_TEST_CASE("CJ-3: confirmed entries survive; unconfirmed tail is truncated") {
    /* ------------------------------------------------------------------ */
        char d[512]; make_testdir(d, sizeof(d), base, "cj3");
        vw_oplog_t *log = NULL;

        VW_ASSERT_OK(vw_oplog_open(d, &log));

        uint64_t id_a, id_b, id_c;
        VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_USER_WRITE,
                                     PAYLOAD, sizeof(PAYLOAD), &id_a));
        VW_ASSERT_OK(vw_oplog_confirm(log, id_a));

        VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_FILE_WRITE,
                                     PAYLOAD, sizeof(PAYLOAD), &id_b));
        VW_ASSERT_OK(vw_oplog_confirm(log, id_b));

        /* id_c: appended but not confirmed — simulate crash */
        VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_FILE_DELETE,
                                     PAYLOAD, sizeof(PAYLOAD), &id_c));
        vw_oplog_close(log);
        log = NULL;

        /* Reopen: id_c must be truncated; id_a and id_b survive */
        VW_ASSERT_OK(vw_oplog_open(d, &log));
        replay_ctx_t r = {{0},{0},0};
        VW_ASSERT_OK(vw_oplog_replay_from(log, 0, replay_collect, &r));
        VW_ASSERT_EQ(r.count, 2);
        VW_ASSERT_EQ((int)r.ids[0], (int)id_a);
        VW_ASSERT_EQ((int)r.ids[1], (int)id_b);
        vw_oplog_close(log);
    }

    /* ------------------------------------------------------------------ */
    VW_TEST_CASE("CJ-4: confirmed entry AFTER unconfirmed hole is preserved") {
    /* ------------------------------------------------------------------ */
        /*
         * This is the primary regression test for the break→continue fix in
         * seg_scan. File layout after crash:
         *   [entry A: confirmed=0][entry B: confirmed=1]
         *
         * With the old break: seg_scan stops at A, truncates both A and B.
         * With the fix (continue): seg_scan skips A (hole), sees B (confirmed=1),
         *   records last_good_offset = after B, then truncates only the tail.
         *   Both A and B remain on disk; replay skips A (confirmed=0) and delivers B.
         */
        char d[512]; make_testdir(d, sizeof(d), base, "cj4");
        vw_oplog_t *log = NULL;

        VW_ASSERT_OK(vw_oplog_open(d, &log));

        uint64_t id_a, id_b;
        /* Thread-A analogue: append A, table write will fail → no confirm */
        VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_USER_WRITE,
                                     PAYLOAD, sizeof(PAYLOAD), &id_a));
        /* Thread-B analogue: append B, table write succeeds → confirm */
        VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_FILE_WRITE,
                                     PAYLOAD, sizeof(PAYLOAD), &id_b));
        VW_ASSERT_OK(vw_oplog_confirm(log, id_b));

        /* Crash: close without confirming id_a */
        vw_oplog_close(log);
        log = NULL;

        /* Recovery */
        VW_ASSERT_OK(vw_oplog_open(d, &log));
        replay_ctx_t r = {{0},{0},0};
        VW_ASSERT_OK(vw_oplog_replay_from(log, 0, replay_collect, &r));

        /* Must deliver exactly B (not A, not zero entries) */
        VW_ASSERT_EQ(r.count, 1);
        VW_ASSERT_EQ((int)r.ids[0], (int)id_b);
        VW_ASSERT_EQ((int)r.ops[0], (int)VW_OPLOG_FILE_WRITE);
        vw_oplog_close(log);
    }

    /* ------------------------------------------------------------------ */
    VW_TEST_CASE("CJ-5: unconfirmed entry in new segment is truncated; "
                 "prior confirmed segment replays intact") {
    /* ------------------------------------------------------------------ */
        /*
         * VW_OPLOG_SEGMENT_MAX is overridden to 512 bytes at compile time.
         * Each append writes 18 + 4 = 22 bytes (header + 4-byte payload).
         * 24 entries = 528 bytes > 512 → the 25th entry triggers segment rotation.
         *
         * Scenario:
         *   1. Write + confirm entries 1-24 (fills segment 1 to 528 bytes).
         *   2. Append entry 25 (not confirmed) → written to segment 2.
         *   3. Close without confirming entry 25 (simulate crash).
         *   4. Reopen: seg_scan(seg 1) sees 24 confirmed entries; seg_scan(seg 2)
         *      sees entry 25 (confirmed=0, tail) → truncates it.
         *   5. Replay: delivers exactly 24 entries.
         */
        char d[512]; make_testdir(d, sizeof(d), base, "cj5");
        vw_oplog_t *log = NULL;

        VW_ASSERT_OK(vw_oplog_open(d, &log));

        /* Write and confirm 24 entries to fill segment 1 */
        uint64_t ids[24];
        for (int i = 0; i < 24; i++) {
            VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_USER_WRITE,
                                         PAYLOAD, sizeof(PAYLOAD), &ids[i]));
            VW_ASSERT_OK(vw_oplog_confirm(log, ids[i]));
        }

        /* Entry 25: triggers segment rotation (seg_bytes 528 >= 512);
         * goes to segment 2; simulate crash — do NOT confirm */
        uint64_t id_25;
        VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_FILE_WRITE,
                                     PAYLOAD, sizeof(PAYLOAD), &id_25));
        vw_oplog_close(log);
        log = NULL;

        /* Recovery */
        VW_ASSERT_OK(vw_oplog_open(d, &log));
        replay_ctx_t r = {{0},{0},0};
        VW_ASSERT_OK(vw_oplog_replay_from(log, 0, replay_collect, &r));

        /* All 24 confirmed entries from segment 1 must be present;
         * entry 25 (unconfirmed, segment 2) must be absent */
        VW_ASSERT_EQ(r.count, 24);

        /* Verify entry IDs are contiguous starting from ids[0] */
        int ids_ok = 1;
        for (int i = 0; i < r.count; i++) {
            if (r.ids[i] != ids[0] + (uint64_t)i) { ids_ok = 0; break; }
        }
        VW_ASSERT(ids_ok);
        vw_oplog_close(log);
    }

    /* ── Additional API contract tests ─────────────────────────────────── */

    VW_TEST_CASE("abort releases pending slot without delivering entry on replay") {
        char d[512]; make_testdir(d, sizeof(d), base, "abort");
        vw_oplog_t *log = NULL;

        VW_ASSERT_OK(vw_oplog_open(d, &log));
        uint64_t id_a, id_b;
        VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_USER_WRITE,
                                     PAYLOAD, sizeof(PAYLOAD), &id_a));
        VW_ASSERT_OK(vw_oplog_confirm(log, id_a));

        VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_FILE_DELETE,
                                     PAYLOAD, sizeof(PAYLOAD), &id_b));
        VW_ASSERT_OK(vw_oplog_abort(log, id_b));

        /* id_b was aborted; replay should only see id_a */
        replay_ctx_t r = {{0},{0},0};
        VW_ASSERT_OK(vw_oplog_replay_from(log, 0, replay_collect, &r));
        VW_ASSERT_EQ(r.count, 1);
        VW_ASSERT_EQ((int)r.ids[0], (int)id_a);
        vw_oplog_close(log);
    }

    VW_TEST_CASE("confirm unknown entry_id returns VW_ERR_NOT_FOUND") {
        char d[512]; make_testdir(d, sizeof(d), base, "badconf");
        vw_oplog_t *log = NULL;
        VW_ASSERT_OK(vw_oplog_open(d, &log));
        VW_ASSERT_ERR(vw_oplog_confirm(log, 99999), VW_ERR_NOT_FOUND);
        vw_oplog_close(log);
    }

    VW_TEST_CASE("abort unknown entry_id returns VW_ERR_NOT_FOUND") {
        char d[512]; make_testdir(d, sizeof(d), base, "badabort");
        vw_oplog_t *log = NULL;
        VW_ASSERT_OK(vw_oplog_open(d, &log));
        VW_ASSERT_ERR(vw_oplog_abort(log, 99999), VW_ERR_NOT_FOUND);
        vw_oplog_close(log);
    }

    VW_TEST_CASE("payload_len overflow guard returns VW_ERR_INVALID_ARG") {
        char d[512]; make_testdir(d, sizeof(d), base, "overflow");
        vw_oplog_t *log = NULL;
        VW_ASSERT_OK(vw_oplog_open(d, &log));
        VW_ASSERT_ERR(vw_oplog_append(log, VW_OPLOG_USER_WRITE,
                                      NULL, 0xFFFFFFFFu, NULL),
                      VW_ERR_INVALID_ARG);
        vw_oplog_close(log);
    }

    VW_TEST_CASE("replay_from with non-zero from_entry_id skips earlier entries") {
        char d[512]; make_testdir(d, sizeof(d), base, "replay_from");
        vw_oplog_t *log = NULL;
        VW_ASSERT_OK(vw_oplog_open(d, &log));

        uint64_t ids[4];
        for (int i = 0; i < 4; i++) {
            VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_USER_WRITE,
                                         PAYLOAD, sizeof(PAYLOAD), &ids[i]));
            VW_ASSERT_OK(vw_oplog_confirm(log, ids[i]));
        }

        /* Replay starting from the 3rd entry */
        replay_ctx_t r = {{0},{0},0};
        VW_ASSERT_OK(vw_oplog_replay_from(log, ids[2], replay_collect, &r));
        VW_ASSERT_EQ(r.count, 2);
        VW_ASSERT_EQ((int)r.ids[0], (int)ids[2]);
        VW_ASSERT_EQ((int)r.ids[1], (int)ids[3]);
        vw_oplog_close(log);
    }

    VW_TEST_CASE("last_entry_id returns 0 on empty log") {
        char d[512]; make_testdir(d, sizeof(d), base, "lastid");
        vw_oplog_t *log = NULL;
        VW_ASSERT_OK(vw_oplog_open(d, &log));
        VW_ASSERT_EQ((int)vw_oplog_last_entry_id(log), 0);
        vw_oplog_close(log);
    }

    VW_TEST_CASE("last_entry_id tracks most-recent confirmed entry") {
        char d[512]; make_testdir(d, sizeof(d), base, "lastid2");
        vw_oplog_t *log = NULL;
        VW_ASSERT_OK(vw_oplog_open(d, &log));

        uint64_t id_a, id_b;
        VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_USER_WRITE,
                                     PAYLOAD, sizeof(PAYLOAD), &id_a));
        VW_ASSERT_OK(vw_oplog_confirm(log, id_a));
        VW_ASSERT_OK(vw_oplog_append(log, VW_OPLOG_USER_WRITE,
                                     PAYLOAD, sizeof(PAYLOAD), &id_b));
        VW_ASSERT_OK(vw_oplog_confirm(log, id_b));

        VW_ASSERT_EQ((int)vw_oplog_last_entry_id(log), (int)id_b);
        vw_oplog_close(log);
    }

    /* cleanup */
    rm_rf(base);
}
VW_TEST_SUITE_END()
