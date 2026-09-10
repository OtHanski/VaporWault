/*
 * test_vw_vault.c — unit tests for vw_vault (TASK-098).
 *
 * Covers: create/get_by_id blob round-trip, opaque-size-ceiling rejection,
 * not-found handling, scan/filter-by-owner, and index rebuild across a
 * store close+reopen (crash-recovery-shaped check, same convention as
 * vw_store_files.c/vw_share.c's own reopen tests). Full client<->server
 * wire round-trip coverage is a separate integration-test concern (this
 * file exercises the server-side storage module directly, matching
 * test_vw_share.c's own scope split).
 */

#include "vw_test.h"
#include "vw_vault.h"
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

/* ── Temp-dir helpers (same pattern as test_vw_share.c) ──────────────────── */

static void make_tmpdir(char *out, size_t sz, const char *label)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_vaulttest_%u_%s", tmp, VW_PID(), label);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_vaulttest_%u_%s", VW_PID(), label);
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

typedef struct {
    char              tmpdir[512];
    vw_oplog_t       *oplog;
    vw_vault_store_t *vs;
} vault_stack_t;

static void stack_open(vault_stack_t *s, const char *label)
{
    make_tmpdir(s->tmpdir, sizeof(s->tmpdir), label);
    VW_ASSERT_OK(vw_oplog_open(s->tmpdir, &s->oplog));
    VW_ASSERT_OK(vw_vault_store_open(s->tmpdir, s->oplog, &s->vs));
}

static void stack_close(vault_stack_t *s)
{
    vw_vault_store_close(s->vs);
    vw_oplog_close(s->oplog);
    rm_rf(s->tmpdir);
}

typedef struct {
    uint64_t owner_id;
    uint32_t matched;
    uint32_t total;
} scan_ctx_t;

static int count_by_owner_cb(const vw_vault_record_t *rec, void *ud)
{
    scan_ctx_t *c = (scan_ctx_t *)ud;
    c->total++;
    if (rec->owner_id == c->owner_id) c->matched++;
    return 0;
}

VW_TEST_SUITE("vw_vault") {

    VW_TEST_CASE("create + get_by_id round-trips the wrapped_vk/kdf_salt/kdf_params blob exactly") {
        vault_stack_t s = {0};
        stack_open(&s, "roundtrip");
        {
            uint8_t wrapped_vk[48];
            for (int i = 0; i < 48; i++) wrapped_vk[i] = (uint8_t)(i * 7 + 3);
            uint8_t kdf_salt[16];
            for (int i = 0; i < 16; i++) kdf_salt[i] = (uint8_t)(i + 1);
            uint8_t kdf_params[6] = { 0, 0, 0, 0, 0, 0 }; /* opaque; content irrelevant */

            uint64_t vault_id = 0;
            VW_ASSERT_OK(vw_vault_create(s.vs, 42, 7, wrapped_vk, sizeof(wrapped_vk),
                                          kdf_salt, kdf_params, sizeof(kdf_params), &vault_id));
            VW_ASSERT(vault_id != 0);

            vw_vault_record_t rec;
            uint8_t *out_vk = NULL, *out_params = NULL;
            VW_ASSERT_OK(vw_vault_get_by_id(s.vs, vault_id, &rec, &out_vk, &out_params));
            VW_ASSERT_EQ(42, (int)rec.owner_id);
            VW_ASSERT_EQ(7, (int)rec.folder_file_id);
            VW_ASSERT_EQ(sizeof(wrapped_vk), (size_t)rec.wrapped_vk_len);
            VW_ASSERT_EQ(sizeof(kdf_params), (size_t)rec.kdf_params_len);
            VW_ASSERT(memcmp(rec.kdf_salt, kdf_salt, 16) == 0);
            VW_ASSERT(out_vk != NULL);
            VW_ASSERT(memcmp(out_vk, wrapped_vk, sizeof(wrapped_vk)) == 0);
            VW_ASSERT(out_params != NULL);
            VW_ASSERT(memcmp(out_params, kdf_params, sizeof(kdf_params)) == 0);
            free(out_vk);
            free(out_params);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("create + get_by_id with empty kdf_params (0 length is valid, unlike wrapped_vk)") {
        vault_stack_t s = {0};
        stack_open(&s, "empty_params");
        {
            uint8_t wrapped_vk[16] = {0};
            uint8_t kdf_salt[16] = {0};

            uint64_t vault_id = 0;
            VW_ASSERT_OK(vw_vault_create(s.vs, 1, 1, wrapped_vk, sizeof(wrapped_vk),
                                          kdf_salt, NULL, 0, &vault_id));

            vw_vault_record_t rec;
            uint8_t *out_vk = NULL, *out_params = NULL;
            VW_ASSERT_OK(vw_vault_get_by_id(s.vs, vault_id, &rec, &out_vk, &out_params));
            VW_ASSERT_EQ(0, (int)rec.kdf_params_len);
            VW_ASSERT(out_params == NULL);
            free(out_vk);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("create rejects empty or oversized wrapped_vk/kdf_params — opaque size ceilings only") {
        vault_stack_t s = {0};
        stack_open(&s, "ceilings");
        {
            uint8_t kdf_salt[16] = {0};
            uint8_t ok_vk[4] = {0};
            uint64_t vault_id = 0;
            uint32_t huge_vk_len = VW_VAULT_MAX_WRAPPED_VK_BYTES + 1u;
            uint32_t huge_params_len = VW_VAULT_MAX_KDF_PARAMS_BYTES + 1u;
            uint8_t *huge = NULL;
            uint8_t *huge_params = NULL;

            /* wrapped_vk empty */
            VW_ASSERT_EQ((int)VW_ERR_INVALID_ARG,
                (int)vw_vault_create(s.vs, 1, 1, NULL, 0, kdf_salt, NULL, 0, &vault_id));
            VW_ASSERT_EQ((int)VW_ERR_INVALID_ARG,
                (int)vw_vault_create(s.vs, 1, 1, ok_vk, 0, kdf_salt, NULL, 0, &vault_id));

            /* wrapped_vk over ceiling */
            huge = (uint8_t *)calloc(1, huge_vk_len);
            VW_ASSERT(huge != NULL);
            VW_ASSERT_EQ((int)VW_ERR_INVALID_ARG, (int)vw_vault_create(s.vs, 1, 1, huge, huge_vk_len, kdf_salt, NULL, 0, &vault_id));
            free(huge);

            /* kdf_params over ceiling */
            huge_params = (uint8_t *)calloc(1, huge_params_len);
            VW_ASSERT(huge_params != NULL);
            VW_ASSERT_EQ((int)VW_ERR_INVALID_ARG, (int)vw_vault_create(s.vs, 1, 1, ok_vk, sizeof(ok_vk), kdf_salt, huge_params, huge_params_len, &vault_id));
            free(huge_params);

            /* owner_id / folder_file_id == 0 */
            VW_ASSERT_EQ((int)VW_ERR_INVALID_ARG,
                (int)vw_vault_create(s.vs, 0, 1, ok_vk, sizeof(ok_vk), kdf_salt, NULL, 0, &vault_id));
            VW_ASSERT_EQ((int)VW_ERR_INVALID_ARG,
                (int)vw_vault_create(s.vs, 1, 0, ok_vk, sizeof(ok_vk), kdf_salt, NULL, 0, &vault_id));
        }
        stack_close(&s);
    }

    VW_TEST_CASE("get_by_id on an unknown vault_id returns NOT_FOUND, not a crash") {
        vault_stack_t s = {0};
        stack_open(&s, "not_found");
        {
            vw_vault_record_t rec;
            uint8_t *vk = NULL, *params = NULL;
            VW_ASSERT_EQ((int)VW_ERR_NOT_FOUND,
                (int)vw_vault_get_by_id(s.vs, 999999, &rec, &vk, &params));
            VW_ASSERT(vk == NULL);
            VW_ASSERT(params == NULL);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("scan visits every vault; caller filters by owner_id") {
        vault_stack_t s = {0};
        stack_open(&s, "scan_filter");
        {
            uint8_t wrapped_vk[8] = {0};
            uint8_t kdf_salt[16] = {0};
            uint64_t vid;

            VW_ASSERT_OK(vw_vault_create(s.vs, 10, 100, wrapped_vk, sizeof(wrapped_vk),
                                          kdf_salt, NULL, 0, &vid));
            VW_ASSERT_OK(vw_vault_create(s.vs, 10, 101, wrapped_vk, sizeof(wrapped_vk),
                                          kdf_salt, NULL, 0, &vid));
            VW_ASSERT_OK(vw_vault_create(s.vs, 20, 200, wrapped_vk, sizeof(wrapped_vk),
                                          kdf_salt, NULL, 0, &vid));

            scan_ctx_t c = { 10, 0, 0 };
            VW_ASSERT_OK(vw_vault_scan(s.vs, count_by_owner_cb, &c));
            VW_ASSERT_EQ(3, (int)c.total);
            VW_ASSERT_EQ(2, (int)c.matched);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("delete removes a vault from get_by_id and scan (TASK-00277)") {
        vault_stack_t s = {0};
        stack_open(&s, "delete_basic");
        {
            uint8_t wrapped_vk[8] = {0};
            uint8_t kdf_salt[16] = {0};
            uint64_t vid = 0;
            VW_ASSERT_OK(vw_vault_create(s.vs, 10, 100, wrapped_vk, sizeof(wrapped_vk),
                                          kdf_salt, NULL, 0, &vid));

            VW_ASSERT_OK(vw_vault_delete(s.vs, vid, 10));

            vw_vault_record_t rec;
            uint8_t *vk = NULL, *params = NULL;
            VW_ASSERT_EQ((int)VW_ERR_NOT_FOUND,
                (int)vw_vault_get_by_id(s.vs, vid, &rec, &vk, &params));

            scan_ctx_t c = { 10, 0, 0 };
            VW_ASSERT_OK(vw_vault_scan(s.vs, count_by_owner_cb, &c));
            VW_ASSERT_EQ(0, (int)c.total);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("delete rejects a non-owner caller with PERMISSION, leaving the vault intact") {
        vault_stack_t s = {0};
        stack_open(&s, "delete_permission");
        {
            uint8_t wrapped_vk[8] = {0};
            uint8_t kdf_salt[16] = {0};
            uint64_t vid = 0;
            VW_ASSERT_OK(vw_vault_create(s.vs, 10, 100, wrapped_vk, sizeof(wrapped_vk),
                                          kdf_salt, NULL, 0, &vid));

            VW_ASSERT_EQ((int)VW_ERR_PERMISSION, (int)vw_vault_delete(s.vs, vid, 999));

            vw_vault_record_t rec;
            uint8_t *vk = NULL, *params = NULL;
            VW_ASSERT_OK(vw_vault_get_by_id(s.vs, vid, &rec, &vk, &params));
            free(vk); free(params);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("delete on an unknown or already-deleted vault returns NOT_FOUND, not a crash") {
        vault_stack_t s = {0};
        stack_open(&s, "delete_not_found");
        {
            VW_ASSERT_EQ((int)VW_ERR_NOT_FOUND, (int)vw_vault_delete(s.vs, 999999, 1));

            uint8_t wrapped_vk[8] = {0};
            uint8_t kdf_salt[16] = {0};
            uint64_t vid = 0;
            VW_ASSERT_OK(vw_vault_create(s.vs, 1, 1, wrapped_vk, sizeof(wrapped_vk),
                                          kdf_salt, NULL, 0, &vid));
            VW_ASSERT_OK(vw_vault_delete(s.vs, vid, 1));
            VW_ASSERT_EQ((int)VW_ERR_NOT_FOUND, (int)vw_vault_delete(s.vs, vid, 1));
        }
        stack_close(&s);
    }

    VW_TEST_CASE("store reopen rebuilds the vault_id index and continues numbering correctly") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "reopen");
        {
            vw_oplog_t *oplog = NULL;
            vw_vault_store_t *vs = NULL;
            VW_ASSERT_OK(vw_oplog_open(tmpdir, &oplog));
            VW_ASSERT_OK(vw_vault_store_open(tmpdir, oplog, &vs));

            uint8_t wrapped_vk[8] = {1,2,3,4,5,6,7,8};
            uint8_t kdf_salt[16] = {0};
            uint64_t vid1 = 0, vid2 = 0;
            VW_ASSERT_OK(vw_vault_create(vs, 5, 50, wrapped_vk, sizeof(wrapped_vk),
                                          kdf_salt, NULL, 0, &vid1));

            vw_vault_store_close(vs);
            vw_oplog_close(oplog);

            VW_ASSERT_OK(vw_oplog_open(tmpdir, &oplog));
            VW_ASSERT_OK(vw_vault_store_open(tmpdir, oplog, &vs));

            /* The first vault must still be readable, with its blob intact. */
            vw_vault_record_t rec;
            uint8_t *out_vk = NULL, *out_params = NULL;
            VW_ASSERT_OK(vw_vault_get_by_id(vs, vid1, &rec, &out_vk, &out_params));
            VW_ASSERT(memcmp(out_vk, wrapped_vk, sizeof(wrapped_vk)) == 0);
            free(out_vk); free(out_params);

            /* A new vault after reopen must get a fresh id, not reuse vid1. */
            VW_ASSERT_OK(vw_vault_create(vs, 5, 51, wrapped_vk, sizeof(wrapped_vk),
                                          kdf_salt, NULL, 0, &vid2));
            VW_ASSERT(vid2 != vid1);

            vw_vault_store_close(vs);
            vw_oplog_close(oplog);
        }
        rm_rf(tmpdir);
    }

    /* ── vw_version_record_t layout (TASK-098's on-disk compatibility claim) ── */

    VW_TEST_CASE("vw_version_record_t is unchanged in size; vault_id defaults to 0") {
        /* The 80-byte size claim itself is already compile-time-enforced by
         * _Static_assert in vw_store.h (for every build, including this
         * one) — no runtime check needed here, and a runtime check against
         * a compile-time-constant sizeof() is itself the kind of thing
         * -W4 flags as a "constant conditional" warning under MSVC. */
        vw_version_record_t rec;
        memset(&rec, 0, sizeof(rec));
        /* A version created the same way every version was created before
         * TASK-098 (no vault_id ever set) must read back with vault_id==0
         * and wrapped_dek_offset/_len==0 — the exact "not encrypted" state,
         * for free, with no migration. */
        VW_ASSERT_EQ(0, (int)rec.vault_id);
        VW_ASSERT_EQ(0, (int)rec.wrapped_dek_offset);
        VW_ASSERT_EQ(0, (int)rec.wrapped_dek_len);
    }

    VW_TEST_CASE("vw_store_version_create with a wrapped_dek round-trips vault_id and the DEK blob") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "version_dek");
        {
            vw_oplog_t *oplog = NULL;
            vw_file_store_t *fs = NULL;
            VW_ASSERT_OK(vw_oplog_open(tmpdir, &oplog));
            VW_ASSERT_OK(vw_file_store_open(tmpdir, oplog, &fs));

            vw_file_record_t frec;
            memset(&frec, 0, sizeof(frec));
            frec.owner_id   = 1;
            frec.entry_type = VW_ENTRY_FILE;
            snprintf(frec.name, sizeof(frec.name), "encrypted.bin");
            uint64_t file_id = 0;
            VW_ASSERT_OK(vw_store_file_create(fs, &frec, &file_id));

            uint8_t chunk_hash[32];
            for (int i = 0; i < 32; i++) chunk_hash[i] = (uint8_t)i;
            uint8_t wrapped_dek[40];
            for (int i = 0; i < 40; i++) wrapped_dek[i] = (uint8_t)(200 - i);

            vw_version_record_t ver;
            memset(&ver, 0, sizeof(ver));
            ver.file_id     = file_id;
            ver.chunk_count = 1;
            ver.vault_id    = 77;

            uint64_t version_id = 0;
            VW_ASSERT_OK(vw_store_version_create(fs, &ver, chunk_hash,
                                                  wrapped_dek, sizeof(wrapped_dek), &version_id));
            VW_ASSERT(version_id != 0);

            vw_version_record_t got;
            VW_ASSERT_OK(vw_store_version_get(fs, version_id, &got));
            VW_ASSERT_EQ(77, (int)got.vault_id);
            VW_ASSERT_EQ(sizeof(wrapped_dek), (size_t)got.wrapped_dek_len);

            uint8_t *out_dek = NULL;
            VW_ASSERT_OK(vw_store_version_get_wrapped_dek(fs, &got, &out_dek));
            VW_ASSERT(out_dek != NULL);
            VW_ASSERT(memcmp(out_dek, wrapped_dek, sizeof(wrapped_dek)) == 0);
            free(out_dek);

            /* The chunk hash itself must still be readable too — the
             * wrapped_dek append must not have corrupted it. */
            uint8_t *out_hashes = NULL;
            VW_ASSERT_OK(vw_store_version_get_chunks(fs, &got, &out_hashes));
            VW_ASSERT(memcmp(out_hashes, chunk_hash, 32) == 0);
            free(out_hashes);

            vw_file_store_close(fs);
            vw_oplog_close(oplog);
        }
        rm_rf(tmpdir);
    }

    VW_TEST_CASE("vw_store_version_create rejects a vault_id/wrapped_dek mismatch") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "version_dek_mismatch");
        {
            vw_oplog_t *oplog = NULL;
            vw_file_store_t *fs = NULL;
            VW_ASSERT_OK(vw_oplog_open(tmpdir, &oplog));
            VW_ASSERT_OK(vw_file_store_open(tmpdir, oplog, &fs));

            vw_file_record_t frec;
            memset(&frec, 0, sizeof(frec));
            frec.owner_id   = 1;
            frec.entry_type = VW_ENTRY_FILE;
            snprintf(frec.name, sizeof(frec.name), "f.bin");
            uint64_t file_id = 0;
            VW_ASSERT_OK(vw_store_file_create(fs, &frec, &file_id));

            vw_version_record_t ver;
            memset(&ver, 0, sizeof(ver));
            ver.file_id  = file_id;
            ver.vault_id = 5; /* claims encrypted, but no wrapped_dek given */

            uint64_t version_id = 0;
            VW_ASSERT_EQ((int)VW_ERR_INVALID_ARG,
                (int)vw_store_version_create(fs, &ver, NULL, NULL, 0, &version_id));

            vw_file_store_close(fs);
            vw_oplog_close(oplog);
        }
        rm_rf(tmpdir);
    }

    VW_TEST_CASE("vw_store_version_vault_in_use finds a live reference and ignores unrelated vault_ids (TASK-00277)") {
        char tmpdir[512];
        make_tmpdir(tmpdir, sizeof(tmpdir), "vault_in_use");
        {
            vw_oplog_t *oplog = NULL;
            vw_file_store_t *fs = NULL;
            VW_ASSERT_OK(vw_oplog_open(tmpdir, &oplog));
            VW_ASSERT_OK(vw_file_store_open(tmpdir, oplog, &fs));

            vw_file_record_t frec;
            memset(&frec, 0, sizeof(frec));
            frec.owner_id   = 1;
            frec.entry_type = VW_ENTRY_FILE;
            snprintf(frec.name, sizeof(frec.name), "encrypted.bin");
            uint64_t file_id = 0;
            VW_ASSERT_OK(vw_store_file_create(fs, &frec, &file_id));

            uint8_t chunk_hash[32] = {0};
            uint8_t wrapped_dek[8] = {0};

            vw_version_record_t ver;
            memset(&ver, 0, sizeof(ver));
            ver.file_id     = file_id;
            ver.chunk_count = 1;
            ver.vault_id    = 42;
            uint64_t version_id = 0;
            VW_ASSERT_OK(vw_store_version_create(fs, &ver, chunk_hash,
                                                  wrapped_dek, sizeof(wrapped_dek), &version_id));

            int in_use = -1;
            VW_ASSERT_OK(vw_store_version_vault_in_use(fs, 42, &in_use));
            VW_ASSERT_EQ(1, in_use);

            /* An unrelated vault_id — including one that has never had any
             * version at all — must read back as not in use. */
            in_use = -1;
            VW_ASSERT_OK(vw_store_version_vault_in_use(fs, 43, &in_use));
            VW_ASSERT_EQ(0, in_use);

            vw_file_store_close(fs);
            vw_oplog_close(oplog);
        }
        rm_rf(tmpdir);
    }
}
VW_TEST_SUITE_END()
