/*
 * test_vw_gateway_remember.c — unit tests for vw_gateway_remember
 * (TASK-165's on-disk "remember me" store).
 *
 * Tests:
 *   open (fresh) -> put -> get round-trip, including the file permission
 *   hardening SEC.07 required be verified by a real test, not just code
 *   inspection (vw_gateway_remember_verify_perms, on both POSIX and
 *   Windows depending which tree this runs in)
 *   get on an unknown cookie -> VW_ERR_NOT_FOUND
 *   put with the same cookie again rotates the token in place (mirrors
 *   vw_client_resume's single-use-per-resume rotation)
 *   remove -> subsequent get fails; idempotent second remove
 *   persistence across close+reopen (simulates a gateway restart)
 *   the store's own hard cap (VW_GATEWAY_REMEMBER_MAX_ENTRIES)
 */

#include "vw_test.h"
#include "vw_gateway_remember.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#  include <windows.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <unistd.h>
#  include <sys/stat.h>
#  include <dirent.h>
#  define VW_PID() ((unsigned)getpid())
#endif

/* ── Temp-dir helpers (mirrors test_vw_fs.c's own convention) ────────────── */

static void make_tmpdir(char *out, size_t sz)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_gwremembertest_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_gwremembertest_%u", VW_PID());
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
            ; /* no nested dirs used by this test */
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
        remove(child);
    }
    closedir(d);
    rmdir(dir);
#endif
}

/*
 * Deterministic, genuinely distinct 64-hex-char cookie values
 * (VW_GATEWAY_COOKIE_HEX_LEN). Encodes n directly into the first 8 hex
 * digits (32 bits, so every n up to and including
 * VW_GATEWAY_REMEMBER_MAX_ENTRIES produces a unique string) rather than
 * a rotating single-character pattern, which would alias for n and
 * n+16 if it only ever cycled through 16 hex digits — exactly the kind
 * of bug that would silently turn "put N distinct cookies" into "update
 * the same handful of cookies N/16 times each," making the hard-cap
 * test below pass or fail for the wrong reason.
 */
static void make_cookie(char *out, unsigned n)
{
    static const char hexits[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++) out[i] = hexits[(n >> (28 - i * 4)) & 0xFu];
    for (int i = 8; i < 64; i++) out[i] = hexits[i % 16];
    out[64] = '\0';
}

VW_TEST_SUITE("vw_gateway_remember")

VW_TEST_CASE("open creates a hardened store; put/get round-trip") {
    char dir[512];
    make_tmpdir(dir, sizeof(dir));

    vw_gateway_remember_store_t *store = NULL;
    VW_ASSERT_OK(vw_gateway_remember_open(dir, &store));
    VW_ASSERT(store != NULL);

    /* SEC.07's own required check: a real OS-level permission check, not
     * just "the code that sets permissions exists." */
    VW_ASSERT_OK(vw_gateway_remember_verify_perms(store));

    char cookie[65];
    make_cookie(cookie, 1);
    uint8_t token[32];
    for (int i = 0; i < 32; i++) token[i] = (uint8_t)i;

    VW_ASSERT_OK(vw_gateway_remember_put(store, cookie, token, "alice"));

    uint8_t got_token[32];
    char got_username[65];
    VW_ASSERT_OK(vw_gateway_remember_get(store, cookie, got_token, got_username, sizeof(got_username)));
    VW_ASSERT_MEM_EQ(got_token, token, sizeof(token));
    VW_ASSERT_STR_EQ(got_username, "alice");

    vw_gateway_remember_close(store);
    rm_rf(dir);
}

VW_TEST_CASE("get on an unknown cookie fails cleanly") {
    char dir[512];
    make_tmpdir(dir, sizeof(dir));
    vw_gateway_remember_store_t *store = NULL;
    VW_ASSERT_OK(vw_gateway_remember_open(dir, &store));

    char unknown[65];
    make_cookie(unknown, 99);
    uint8_t token[32];
    char username[65];
    VW_ASSERT_ERR(vw_gateway_remember_get(store, unknown, token, username, sizeof(username)),
                  VW_ERR_NOT_FOUND);

    vw_gateway_remember_close(store);
    rm_rf(dir);
}

VW_TEST_CASE("put on an existing cookie rotates the token in place") {
    char dir[512];
    make_tmpdir(dir, sizeof(dir));
    vw_gateway_remember_store_t *store = NULL;
    VW_ASSERT_OK(vw_gateway_remember_open(dir, &store));

    char cookie[65];
    make_cookie(cookie, 2);
    uint8_t token_a[32], token_b[32];
    memset(token_a, 0xAA, sizeof(token_a));
    memset(token_b, 0xBB, sizeof(token_b));

    VW_ASSERT_OK(vw_gateway_remember_put(store, cookie, token_a, "bob"));
    VW_ASSERT_OK(vw_gateway_remember_put(store, cookie, token_b, "bob"));

    uint8_t got[32];
    char got_username[65];
    VW_ASSERT_OK(vw_gateway_remember_get(store, cookie, got, got_username, sizeof(got_username)));
    VW_ASSERT_MEM_EQ(got, token_b, sizeof(token_b));

    vw_gateway_remember_close(store);
    rm_rf(dir);
}

VW_TEST_CASE("remove deletes the entry and is idempotent") {
    char dir[512];
    make_tmpdir(dir, sizeof(dir));
    vw_gateway_remember_store_t *store = NULL;
    VW_ASSERT_OK(vw_gateway_remember_open(dir, &store));

    char cookie[65];
    make_cookie(cookie, 3);
    uint8_t token[32] = {0};
    VW_ASSERT_OK(vw_gateway_remember_put(store, cookie, token, "carol"));

    vw_gateway_remember_remove(store, cookie);

    uint8_t got[32];
    char got_username[65];
    VW_ASSERT_ERR(vw_gateway_remember_get(store, cookie, got, got_username, sizeof(got_username)),
                  VW_ERR_NOT_FOUND);

    /* Idempotent - must not crash on a second remove of an already-gone
     * (or never-existed) cookie. */
    vw_gateway_remember_remove(store, cookie);

    vw_gateway_remember_close(store);
    rm_rf(dir);
}

VW_TEST_CASE("survives close + reopen (simulated gateway restart)") {
    char dir[512];
    make_tmpdir(dir, sizeof(dir));

    char cookie[65];
    make_cookie(cookie, 4);
    uint8_t token[32];
    memset(token, 0xCC, sizeof(token));

    {
        vw_gateway_remember_store_t *store = NULL;
        VW_ASSERT_OK(vw_gateway_remember_open(dir, &store));
        VW_ASSERT_OK(vw_gateway_remember_put(store, cookie, token, "dave"));
        vw_gateway_remember_close(store);
    }

    {
        vw_gateway_remember_store_t *store = NULL;
        VW_ASSERT_OK(vw_gateway_remember_open(dir, &store));
        uint8_t got[32];
        char got_username[65];
        VW_ASSERT_OK(vw_gateway_remember_get(store, cookie, got, got_username, sizeof(got_username)));
        VW_ASSERT_MEM_EQ(got, token, sizeof(token));
        VW_ASSERT_STR_EQ(got_username, "dave");
        vw_gateway_remember_close(store);
    }

    rm_rf(dir);
}

VW_TEST_CASE("link session (NULL username) round-trips as an empty string") {
    char dir[512];
    make_tmpdir(dir, sizeof(dir));
    vw_gateway_remember_store_t *store = NULL;
    VW_ASSERT_OK(vw_gateway_remember_open(dir, &store));

    char cookie[65];
    make_cookie(cookie, 5);
    uint8_t token[32] = {0};
    VW_ASSERT_OK(vw_gateway_remember_put(store, cookie, token, NULL));

    uint8_t got[32];
    char got_username[65];
    VW_ASSERT_OK(vw_gateway_remember_get(store, cookie, got, got_username, sizeof(got_username)));
    VW_ASSERT_STR_EQ(got_username, "");

    vw_gateway_remember_close(store);
    rm_rf(dir);
}

VW_TEST_CASE("hard cap: the store rejects a new cookie once full") {
    char dir[512];
    make_tmpdir(dir, sizeof(dir));
    vw_gateway_remember_store_t *store = NULL;
    VW_ASSERT_OK(vw_gateway_remember_open(dir, &store));

    uint8_t token[32] = {0};
    char cookie[65];
    for (unsigned i = 0; i < VW_GATEWAY_REMEMBER_MAX_ENTRIES; i++) {
        make_cookie(cookie, i);
        VW_ASSERT_OK(vw_gateway_remember_put(store, cookie, token, "user"));
    }

    /* One more, distinct cookie -> the store is full. */
    make_cookie(cookie, VW_GATEWAY_REMEMBER_MAX_ENTRIES);
    VW_ASSERT_ERR(vw_gateway_remember_put(store, cookie, token, "overflow"),
                  VW_ERR_QUOTA_EXCEEDED);

    /* But re-putting an ALREADY-known cookie (rotation) must still work
     * even at capacity - this is an update, not a new entry. */
    make_cookie(cookie, 0);
    VW_ASSERT_OK(vw_gateway_remember_put(store, cookie, token, "user"));

    vw_gateway_remember_close(store);
    rm_rf(dir);
}

VW_TEST_SUITE_END()
