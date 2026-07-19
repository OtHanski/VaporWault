/*
 * test_vw_auth.c — unit tests for vw_auth (password hashing, sessions, login flow).
 *
 * Tests the vw_auth API against a real (in-memory) store and oplog.
 * smtp_cfg is passed as NULL so no email is sent during tests.
 */

#include "vw_test.h"
#include "vw_auth.h"
#include "vw_store.h"
#include "vw_oplog.h"
#include "vw_crypto.h"
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

/* ── Temp-dir helpers ─────────────────────────────────────────────────────── */

static void make_tmpdir(char *out, size_t sz, const char *label)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_authtest_%u_%s", tmp, VW_PID(), label);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_authtest_%u_%s", VW_PID(), label);
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

/* ── Auth stack helper ────────────────────────────────────────────────────── */

typedef struct {
    char           tmpdir[512];
    vw_oplog_t    *oplog;
    vw_store_t    *store;
    vw_auth_ctx_t *auth;
} auth_stack_t;

static void auth_stack_open(auth_stack_t *s, const char *label)
{
    make_tmpdir(s->tmpdir, sizeof(s->tmpdir), label);
    VW_ASSERT_OK(vw_oplog_open(s->tmpdir, &s->oplog));
    VW_ASSERT_OK(vw_store_open(s->tmpdir, s->oplog, &s->store));
    VW_ASSERT_OK(vw_auth_open(s->store, NULL, NULL, &s->auth));
}

static void auth_stack_close(auth_stack_t *s)
{
    vw_auth_close(s->auth);
    vw_store_close(s->store);
    vw_oplog_close(s->oplog);
    rm_rf(s->tmpdir);
}

/* Create a test user; returns the assigned user_id. */
static uint64_t make_user(auth_stack_t *s, const char *username,
                           const char *password, int is_admin)
{
    uint8_t hash[32], salt[16];
    vw_user_record_t rec;
    uint64_t uid = 0;

    VW_ASSERT_OK(vw_auth_hash_password(password, strlen(password), hash, salt));

    memset(&rec, 0, sizeof(rec));
    snprintf((char *)rec.username, sizeof(rec.username), "%s", username);
    snprintf((char *)rec.email,    sizeof(rec.email),    "%s@test.local", username);
    memcpy(rec.password_hash, hash, 32);
    memcpy(rec.password_salt, salt, 16);
    rec.is_admin  = (uint8_t)(is_admin ? 1 : 0);
    rec.is_active = 1;

    VW_ASSERT_OK(vw_store_user_create(s->store, &rec, &uid));
    return uid;
}

/* ── Test suite ───────────────────────────────────────────────────────────── */

VW_TEST_SUITE("vw_auth") {
    VW_ASSERT_OK(vw_crypto_init());

    /* ── Password hashing ─────────────────────────────────────────────────── */

    VW_TEST_CASE("hash_password: correct password matches stored hash") {
        uint8_t hash[32], salt[16];
        VW_ASSERT_OK(vw_auth_hash_password("hunter2", 7, hash, salt));
        VW_ASSERT_OK(vw_auth_verify_password("hunter2", 7, hash, salt));
    }

    VW_TEST_CASE("hash_password: wrong password returns VW_ERR_AUTH_BAD_CREDS") {
        uint8_t hash[32], salt[16];
        VW_ASSERT_OK(vw_auth_hash_password("correct", 7, hash, salt));
        VW_ASSERT_ERR(vw_auth_verify_password("wrong!!", 7, hash, salt),
                      VW_ERR_AUTH_BAD_CREDS);
    }

    VW_TEST_CASE("hash_password: two hashes of the same password use different salts") {
        uint8_t hash1[32], salt1[16];
        uint8_t hash2[32], salt2[16];
        VW_ASSERT_OK(vw_auth_hash_password("samepass", 8, hash1, salt1));
        VW_ASSERT_OK(vw_auth_hash_password("samepass", 8, hash2, salt2));
        /* CSPRNG salts must differ */
        VW_ASSERT_NE(0, memcmp(salt1, salt2, 16));
        /* Different salts produce different hashes */
        VW_ASSERT_NE(0, memcmp(hash1, hash2, 32));
    }

    /* ── Session lifecycle ────────────────────────────────────────────────── */

    VW_TEST_CASE("create_session + validate_session returns correct user_id") {
        auth_stack_t s = {0};
        auth_stack_open(&s, "sess_val");
        {
            uint64_t uid = make_user(&s, "alice", "alicepw", 0);
            uint8_t  token[32];
            uint64_t got = 0;
            VW_ASSERT_OK(vw_auth_create_session(s.auth, uid, "127.0.0.1", token));
            VW_ASSERT_OK(vw_auth_validate_session(s.auth, token, &got));
            VW_ASSERT_EQ(uid, got);
        }
        auth_stack_close(&s);
    }

    VW_TEST_CASE("revoke_session then validate returns an error") {
        auth_stack_t s = {0};
        auth_stack_open(&s, "sess_rev");
        {
            uint64_t uid = make_user(&s, "bob", "bobpw", 0);
            uint8_t  token[32];
            uint64_t got = 0;
            VW_ASSERT_OK(vw_auth_create_session(s.auth, uid, "127.0.0.1", token));
            VW_ASSERT_OK(vw_auth_revoke_session(s.auth, token));
            VW_ASSERT_NE(VW_OK, (int)vw_auth_validate_session(s.auth, token, &got));
        }
        auth_stack_close(&s);
    }

    VW_TEST_CASE("validate with zeroed token returns an error") {
        auth_stack_t s = {0};
        auth_stack_open(&s, "sess_zero");
        {
            uint8_t zero[32];
            uint64_t uid = 0;
            memset(zero, 0, 32);
            VW_ASSERT_NE(VW_OK, (int)vw_auth_validate_session(s.auth, zero, &uid));
        }
        auth_stack_close(&s);
    }

    VW_TEST_CASE("two sessions for the same user are independent") {
        auth_stack_t s = {0};
        auth_stack_open(&s, "sess_two");
        {
            uint64_t uid = make_user(&s, "carol", "carolpw", 0);
            uint8_t tok1[32], tok2[32];
            uint64_t got = 0;
            VW_ASSERT_OK(vw_auth_create_session(s.auth, uid, "1.1.1.1", tok1));
            VW_ASSERT_OK(vw_auth_create_session(s.auth, uid, "2.2.2.2", tok2));
            /* tokens differ */
            VW_ASSERT_NE(0, memcmp(tok1, tok2, 32));
            /* both validate */
            VW_ASSERT_OK(vw_auth_validate_session(s.auth, tok1, &got));
            VW_ASSERT_OK(vw_auth_validate_session(s.auth, tok2, &got));
            /* revoking one does not affect the other */
            VW_ASSERT_OK(vw_auth_revoke_session(s.auth, tok1));
            VW_ASSERT_NE(VW_OK, (int)vw_auth_validate_session(s.auth, tok1, &got));
            VW_ASSERT_OK(vw_auth_validate_session(s.auth, tok2, &got));
        }
        auth_stack_close(&s);
    }

    /* ── Login flow ───────────────────────────────────────────────────────── */

    VW_TEST_CASE("begin_login: correct credentials succeed (no 2FA)") {
        auth_stack_t s = {0};
        auth_stack_open(&s, "login_ok");
        {
            uint64_t uid = make_user(&s, "dave", "davepw123", 0);
            vw_auth_state_t state;
            uint16_t lockout_secs = 0;
            VW_ASSERT_OK(vw_auth_begin_login(s.auth, "dave", "davepw123", 9, &state, &lockout_secs));
            VW_ASSERT_EQ(uid, state.user_id);
        }
        auth_stack_close(&s);
    }

    VW_TEST_CASE("begin_login: wrong password returns VW_ERR_AUTH_BAD_CREDS") {
        auth_stack_t s = {0};
        auth_stack_open(&s, "login_badpw");
        {
            (void)make_user(&s, "eve", "correctpw", 0);
            vw_auth_state_t state;
            uint16_t lockout_secs = 0;
            VW_ASSERT_ERR(vw_auth_begin_login(s.auth, "eve", "wrongpw!!", 9, &state, &lockout_secs),
                          VW_ERR_AUTH_BAD_CREDS);
            VW_ASSERT_EQ(0, (int)lockout_secs);
        }
        auth_stack_close(&s);
    }

    VW_TEST_CASE("begin_login: unknown user returns same error as wrong password") {
        auth_stack_t s = {0};
        auth_stack_open(&s, "login_nouser");
        {
            vw_auth_state_t state;
            uint16_t lockout_secs = 0;
            /* Must run dummy Argon2id hash — we only check the error code here */
            VW_ASSERT_ERR(vw_auth_begin_login(s.auth, "nobody", "anything", 8, &state, &lockout_secs),
                          VW_ERR_AUTH_BAD_CREDS);
            VW_ASSERT_EQ(0, (int)lockout_secs);
        }
        auth_stack_close(&s);
    }

    VW_TEST_CASE("begin_login: brute-force lockout after 5 failed attempts (TASK-075)") {
        auth_stack_t s = {0};
        auth_stack_open(&s, "login_lockout");
        {
            (void)make_user(&s, "frank", "correctpw", 0);
            vw_auth_state_t state;
            uint16_t lockout_secs;

            for (int i = 0; i < 5; i++) {
                lockout_secs = 0;
                VW_ASSERT_ERR(vw_auth_begin_login(s.auth, "frank", "wrongpw!!", 9,
                                                   &state, &lockout_secs),
                              VW_ERR_AUTH_BAD_CREDS);
                VW_ASSERT_EQ(0, (int)lockout_secs);
            }

            /* 6th attempt: locked, even though credentials would fail anyway. */
            lockout_secs = 0;
            VW_ASSERT_ERR(vw_auth_begin_login(s.auth, "frank", "wrongpw!!", 9,
                                               &state, &lockout_secs),
                          VW_ERR_AUTH_LOCKED);
            VW_ASSERT(lockout_secs > 0);

            /* Still locked even with the CORRECT password. */
            lockout_secs = 0;
            VW_ASSERT_ERR(vw_auth_begin_login(s.auth, "frank", "correctpw", 9,
                                               &state, &lockout_secs),
                          VW_ERR_AUTH_LOCKED);
            VW_ASSERT(lockout_secs > 0);
        }
        auth_stack_close(&s);
    }

    VW_TEST_CASE("begin_login: unknown username never locks regardless of attempt count (anti-enumeration)") {
        auth_stack_t s = {0};
        auth_stack_open(&s, "login_nouser_lockout");
        {
            vw_auth_state_t state;
            uint16_t lockout_secs;

            for (int i = 0; i < 10; i++) {
                lockout_secs = 0;
                VW_ASSERT_ERR(vw_auth_begin_login(s.auth, "ghost", "anything", 8,
                                                   &state, &lockout_secs),
                              VW_ERR_AUTH_BAD_CREDS);
                VW_ASSERT_EQ(0, (int)lockout_secs);
            }
        }
        auth_stack_close(&s);
    }
}

VW_TEST_SUITE_END()
