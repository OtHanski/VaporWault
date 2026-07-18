/*
 * test_vw_store.c — unit tests for vw_store: user CRUD, sessions, and session GC.
 *
 * Tests the user and session table APIs directly against a real store+oplog
 * backed by a temporary directory. Does not exercise file/version records
 * (those require vw_file_store_t, a separate context).
 */

#include "vw_test.h"
#include "vw_store.h"
#include "vw_oplog.h"
#include "vw_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h> /* offsetof */

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

/* ── Temp-dir helpers ─────────────────────────────────────────────────────── */

static void make_tmpdir(char *out, size_t sz, const char *label)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_storetest_%u_%s", tmp, VW_PID(), label);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_storetest_%u_%s", VW_PID(), label);
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

/* ── Store stack helper ───────────────────────────────────────────────────── */

typedef struct {
    char        tmpdir[512];
    vw_oplog_t *oplog;
    vw_store_t *store;
} store_stack_t;

static void store_stack_open(store_stack_t *s, const char *label)
{
    make_tmpdir(s->tmpdir, sizeof(s->tmpdir), label);
    VW_ASSERT_OK(vw_oplog_open(s->tmpdir, &s->oplog));
    VW_ASSERT_OK(vw_store_open(s->tmpdir, s->oplog, &s->store));
}

static void store_stack_close(store_stack_t *s)
{
    vw_store_close(s->store);
    vw_oplog_close(s->oplog);
    rm_rf(s->tmpdir);
}

/* Build a minimal populated vw_user_record_t (password fields zeroed — tests
 * don't need valid credentials for most user-CRUD scenarios). */
static void fill_user_rec(vw_user_record_t *rec, const char *username,
                           const char *email, int is_admin)
{
    memset(rec, 0, sizeof(*rec));
    snprintf((char *)rec->username, sizeof(rec->username), "%s", username);
    snprintf((char *)rec->email,    sizeof(rec->email),    "%s", email);
    rec->is_admin  = (uint8_t)(is_admin ? 1 : 0);
    rec->is_active = 1;
}

/* ── File-scope callbacks (C11 does not allow nested functions) ───────────── */

static int scan_count_cb(const vw_user_record_t *r, void *ud)
{
    (void)r;
    (*(int *)ud)++;
    return 0;
}

/* ── Test suite ───────────────────────────────────────────────────────────── */

VW_TEST_SUITE("vw_store") {
    VW_ASSERT_OK(vw_crypto_init());

    /* ── User CRUD ──────────────────────────────────────────────────────────── */

    VW_TEST_CASE("user_create + user_get_by_id returns matching record") {
        store_stack_t s = {0};
        store_stack_open(&s, "usr_id");
        {
            vw_user_record_t rec, out;
            uint64_t uid = 0;
            fill_user_rec(&rec, "alice", "alice@example.com", 0);
            VW_ASSERT_OK(vw_store_user_create(s.store, &rec, &uid));
            VW_ASSERT_NE(0u, (unsigned)uid);
            VW_ASSERT_OK(vw_store_user_get_by_id(s.store, uid, &out));
            VW_ASSERT_EQ(uid, out.user_id);
            VW_ASSERT_STR_EQ("alice", (const char *)out.username);
        }
        store_stack_close(&s);
    }

    VW_TEST_CASE("user_get_by_id returns VW_ERR_NOT_FOUND for unknown id") {
        store_stack_t s = {0};
        store_stack_open(&s, "usr_id_nf");
        {
            vw_user_record_t out;
            VW_ASSERT_ERR(vw_store_user_get_by_id(s.store, 9999, &out),
                          VW_ERR_NOT_FOUND);
        }
        store_stack_close(&s);
    }

    VW_TEST_CASE("user_get_by_username finds the correct record") {
        store_stack_t s = {0};
        store_stack_open(&s, "usr_name");
        {
            vw_user_record_t rec, out;
            uint64_t uid = 0;
            fill_user_rec(&rec, "bob", "bob@example.com", 0);
            VW_ASSERT_OK(vw_store_user_create(s.store, &rec, &uid));
            VW_ASSERT_OK(vw_store_user_get_by_username(s.store, "bob", &out));
            VW_ASSERT_EQ(uid, out.user_id);
            VW_ASSERT_STR_EQ("bob@example.com", (const char *)out.email);
        }
        store_stack_close(&s);
    }

    VW_TEST_CASE("user_get_by_username returns VW_ERR_NOT_FOUND for unknown name") {
        store_stack_t s = {0};
        store_stack_open(&s, "usr_name_nf");
        {
            vw_user_record_t out;
            VW_ASSERT_ERR(vw_store_user_get_by_username(s.store, "nobody", &out),
                          VW_ERR_NOT_FOUND);
        }
        store_stack_close(&s);
    }

    VW_TEST_CASE("user_get_by_email finds the correct record") {
        store_stack_t s = {0};
        store_stack_open(&s, "usr_email");
        {
            vw_user_record_t rec, out;
            uint64_t uid = 0;
            fill_user_rec(&rec, "carol", "carol@corp.com", 0);
            VW_ASSERT_OK(vw_store_user_create(s.store, &rec, &uid));
            VW_ASSERT_OK(vw_store_user_get_by_email(s.store, "carol@corp.com", &out));
            VW_ASSERT_EQ(uid, out.user_id);
        }
        store_stack_close(&s);
    }

    VW_TEST_CASE("user_create duplicate username returns VW_ERR_ALREADY_EXISTS") {
        store_stack_t s = {0};
        store_stack_open(&s, "usr_dup");
        {
            vw_user_record_t rec;
            uint64_t uid = 0;
            fill_user_rec(&rec, "dave", "dave@x.com", 0);
            VW_ASSERT_OK(vw_store_user_create(s.store, &rec, &uid));

            fill_user_rec(&rec, "dave", "dave2@x.com", 0);
            VW_ASSERT_ERR(vw_store_user_create(s.store, &rec, &uid),
                          VW_ERR_ALREADY_EXISTS);
        }
        store_stack_close(&s);
    }

    VW_TEST_CASE("user_update_field changes is_active in place") {
        store_stack_t s = {0};
        store_stack_open(&s, "usr_upd");
        {
            vw_user_record_t rec, out;
            uint64_t uid = 0;
            uint8_t inactive = 0;

            fill_user_rec(&rec, "eve", "eve@x.com", 0);
            VW_ASSERT_OK(vw_store_user_create(s.store, &rec, &uid));

            VW_ASSERT_OK(vw_store_user_update_field(
                s.store, uid,
                (uint32_t)offsetof(vw_user_record_t, is_active),
                &inactive, 1));

            VW_ASSERT_OK(vw_store_user_get_by_id(s.store, uid, &out));
            VW_ASSERT_EQ(0, (int)out.is_active);
        }
        store_stack_close(&s);
    }

    VW_TEST_CASE("user_scan visits all active users") {
        store_stack_t s = {0};
        store_stack_open(&s, "usr_scan");
        {
            vw_user_record_t rec;
            uint64_t uid = 0;
            int count = 0;

            fill_user_rec(&rec, "f1", "f1@x.com", 0);
            VW_ASSERT_OK(vw_store_user_create(s.store, &rec, &uid));
            fill_user_rec(&rec, "f2", "f2@x.com", 0);
            VW_ASSERT_OK(vw_store_user_create(s.store, &rec, &uid));
            fill_user_rec(&rec, "f3", "f3@x.com", 0);
            VW_ASSERT_OK(vw_store_user_create(s.store, &rec, &uid));

            VW_ASSERT_OK(vw_store_user_scan(s.store, scan_count_cb, &count));
            VW_ASSERT_EQ(3, count);
        }
        store_stack_close(&s);
    }

    VW_TEST_CASE("get_by_id zeroes password_hash and password_salt") {
        store_stack_t s = {0};
        store_stack_open(&s, "usr_cred_zero");
        {
            vw_user_record_t rec, out;
            uint64_t uid = 0;
            uint8_t zero32[32], zero16[16];
            memset(zero32, 0, 32);
            memset(zero16, 0, 16);

            fill_user_rec(&rec, "frank", "frank@x.com", 0);
            /* Set non-zero credential fields */
            memset(rec.password_hash, 0xAB, 32);
            memset(rec.password_salt, 0xCD, 16);
            VW_ASSERT_OK(vw_store_user_create(s.store, &rec, &uid));

            VW_ASSERT_OK(vw_store_user_get_by_id(s.store, uid, &out));
            /* Public API must zero sensitive fields */
            VW_ASSERT_MEM_EQ(zero32, out.password_hash, 32);
            VW_ASSERT_MEM_EQ(zero16, out.password_salt, 16);
        }
        store_stack_close(&s);
    }

    /* ── Session CRUD ────────────────────────────────────────────────────── */

    VW_TEST_CASE("session_create + session_get returns active session") {
        store_stack_t s = {0};
        store_stack_open(&s, "sess_get");
        {
            vw_session_record_t rec, out;
            uint8_t tok[32];

            memset(&rec, 0, sizeof(rec));
            rec.user_id    = 42;
            rec.created_at = 1000;
            rec.expires_at = 9999999999ULL;
            rec.is_active  = 1;

            VW_ASSERT_OK(vw_store_session_create(s.store, &rec, tok));
            VW_ASSERT_OK(vw_store_session_get(s.store, tok, &out));
            VW_ASSERT_EQ(42u, (unsigned)out.user_id);
            VW_ASSERT_EQ(1, (int)out.is_active);
        }
        store_stack_close(&s);
    }

    VW_TEST_CASE("session_delete then session_get returns VW_ERR_NOT_FOUND") {
        store_stack_t s = {0};
        store_stack_open(&s, "sess_del");
        {
            vw_session_record_t rec, out;
            uint8_t tok[32];

            memset(&rec, 0, sizeof(rec));
            rec.user_id    = 7;
            rec.created_at = 1;
            rec.expires_at = 9999999999ULL;
            rec.is_active  = 1;

            VW_ASSERT_OK(vw_store_session_create(s.store, &rec, tok));
            VW_ASSERT_OK(vw_store_session_delete(s.store, tok));
            VW_ASSERT_ERR(vw_store_session_get(s.store, tok, &out),
                          VW_ERR_NOT_FOUND);
        }
        store_stack_close(&s);
    }

    /* ── Session GC ──────────────────────────────────────────────────────── */

    VW_TEST_CASE("session_gc expires sessions whose expires_at <= now_unix") {
        store_stack_t s = {0};
        store_stack_open(&s, "sess_gc");
        {
            vw_session_record_t rec, out;
            uint8_t tok_exp[32], tok_live[32];
            uint32_t expired_count = 0;

            /* Session that has already expired (expires_at = 100) */
            memset(&rec, 0, sizeof(rec));
            rec.user_id    = 1;
            rec.created_at = 1;
            rec.expires_at = 100;
            rec.is_active  = 1;
            VW_ASSERT_OK(vw_store_session_create(s.store, &rec, tok_exp));

            /* Session that is still live (expires_at = far future) */
            memset(&rec, 0, sizeof(rec));
            rec.user_id    = 2;
            rec.created_at = 1;
            rec.expires_at = 9999999999ULL;
            rec.is_active  = 1;
            VW_ASSERT_OK(vw_store_session_create(s.store, &rec, tok_live));

            /* Advance time past the first session's expiry */
            VW_ASSERT_OK(vw_store_session_gc(s.store, 1000, &expired_count));
            VW_ASSERT_EQ(1u, (unsigned)expired_count);

            /* Expired session is gone */
            VW_ASSERT_ERR(vw_store_session_get(s.store, tok_exp, &out),
                          VW_ERR_NOT_FOUND);

            /* Live session is untouched */
            VW_ASSERT_OK(vw_store_session_get(s.store, tok_live, &out));
        }
        store_stack_close(&s);
    }

    VW_TEST_CASE("sessions_revoke_by_user invalidates all sessions for a user") {
        store_stack_t s = {0};
        store_stack_open(&s, "sess_revoke_uid");
        {
            vw_session_record_t rec, out;
            uint8_t tok1[32], tok2[32];
            uint32_t count = 0;

            /* Two sessions for user_id=5 */
            memset(&rec, 0, sizeof(rec));
            rec.user_id    = 5;
            rec.created_at = 1;
            rec.expires_at = 9999999999ULL;
            rec.is_active  = 1;
            VW_ASSERT_OK(vw_store_session_create(s.store, &rec, tok1));
            VW_ASSERT_OK(vw_store_session_create(s.store, &rec, tok2));

            VW_ASSERT_OK(vw_store_sessions_revoke_by_user(s.store, 5, &count));
            VW_ASSERT_EQ(2u, (unsigned)count);

            VW_ASSERT_ERR(vw_store_session_get(s.store, tok1, &out),
                          VW_ERR_NOT_FOUND);
            VW_ASSERT_ERR(vw_store_session_get(s.store, tok2, &out),
                          VW_ERR_NOT_FOUND);
        }
        store_stack_close(&s);
    }
}

VW_TEST_SUITE_END()
