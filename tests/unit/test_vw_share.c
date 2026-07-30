/*
 * test_vw_share.c — unit tests for vw_share (TASK-094).
 *
 * Covers: grant/link CRUD, ownership-gated revoke, permission resolution
 * (owner / user-to-user grant walk-up / scoped-session walk-up / live
 * revocation), and the scoped-session write-count + LINK_ACCESS IP rate
 * limits. Full client<->server round-trip coverage of the wire messages
 * themselves is TASK-097's job (needs TASK-095's client support to exist);
 * this file exercises the server-side module directly.
 */

#include "vw_test.h"
#include "vw_share.h"
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

/* ── Temp-dir helpers (same pattern as test_vw_gc.c) ─────────────────────── */

static void make_tmpdir(char *out, size_t sz, const char *label)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_sharetest_%u_%s", tmp, VW_PID(), label);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_sharetest_%u_%s", VW_PID(), label);
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

/* ── Stack helper: oplog + file_store + share_store together ────────────── */

typedef struct {
    char              tmpdir[512];
    vw_oplog_t       *oplog;
    vw_file_store_t  *fs;
    vw_share_store_t *ss;
} share_stack_t;

static void stack_open(share_stack_t *s, const char *label)
{
    make_tmpdir(s->tmpdir, sizeof(s->tmpdir), label);
    VW_ASSERT_OK(vw_oplog_open(s->tmpdir, &s->oplog));
    VW_ASSERT_OK(vw_file_store_open(s->tmpdir, s->oplog, &s->fs));
    VW_ASSERT_OK(vw_share_store_open(s->tmpdir, s->oplog, &s->ss));
}

static void stack_close(share_stack_t *s)
{
    vw_share_store_close(s->ss);
    vw_file_store_close(s->fs);
    vw_oplog_close(s->oplog);
    rm_rf(s->tmpdir);
}

/* Create a file/dir record owned by owner_id under parent_dir_id. */
static uint64_t make_entry(share_stack_t *s, uint64_t owner_id,
                            uint64_t parent_dir_id, const char *name, uint8_t entry_type)
{
    vw_file_record_t rec;
    uint64_t file_id = 0;
    memset(&rec, 0, sizeof(rec));
    rec.owner_id      = owner_id;
    rec.parent_dir_id = parent_dir_id;
    rec.entry_type    = entry_type;
    snprintf(rec.name, sizeof(rec.name), "%s", name);
    VW_ASSERT_OK(vw_store_file_create(s->fs, &rec, &file_id));
    return file_id;
}

VW_TEST_SUITE("vw_share") {
    VW_ASSERT_OK(vw_crypto_init()); /* needed for vw_crypto_random (link tokens) */

    VW_TEST_CASE("grant: create, get_by_id, and permission resolves for the target user") {
        share_stack_t s = {0};
        stack_open(&s, "grant_basic");
        {
            uint64_t owner = 100, grantee = 200;
            uint64_t folder = make_entry(&s, owner, 0, "shared", VW_ENTRY_DIR);
            uint64_t file   = make_entry(&s, owner, folder, "notes.txt", VW_ENTRY_FILE);

            uint64_t share_id = 0;
            VW_ASSERT_OK(vw_share_grant_create(s.ss, folder, owner, grantee,
                                                VW_PERM_EDIT, 0, &share_id));
            VW_ASSERT(share_id != 0);

            vw_share_record_t rec;
            VW_ASSERT_OK(vw_share_get_by_id(s.ss, share_id, &rec));
            VW_ASSERT_EQ(folder, rec.file_id);
            VW_ASSERT_EQ(grantee, rec.target_user_id);
            VW_ASSERT_EQ((int)VW_PERM_EDIT, (int)rec.permission);
            VW_ASSERT_EQ(0, rec.revoked);

            /* Grant is on the FOLDER; the file underneath must inherit it
             * via the ancestor walk-up. */
            vw_perm_t p = vw_share_resolve_permission(s.ss, s.fs, file, grantee, 0);
            VW_ASSERT_EQ((int)VW_PERM_EDIT, (int)p);

            /* A different user gets nothing. */
            p = vw_share_resolve_permission(s.ss, s.fs, file, 999, 0);
            VW_ASSERT_EQ((int)VW_PERM_NONE, (int)p);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("grant: revoke requires the share's owner_id, not merely EDIT access") {
        share_stack_t s = {0};
        stack_open(&s, "grant_revoke_owner_only");
        {
            uint64_t owner = 100, grantee = 200, other = 300;
            uint64_t file = make_entry(&s, owner, 0, "doc.txt", VW_ENTRY_FILE);

            uint64_t share_id = 0;
            VW_ASSERT_OK(vw_share_grant_create(s.ss, file, owner, grantee,
                                                VW_PERM_EDIT, 0, &share_id));

            /* The grantee (has EDIT on the file) cannot revoke it. */
            VW_ASSERT_ERR(vw_share_revoke(s.ss, share_id, grantee), VW_ERR_PERMISSION);
            /* Some unrelated user cannot either. */
            VW_ASSERT_ERR(vw_share_revoke(s.ss, share_id, other), VW_ERR_PERMISSION);
            /* The owner can. */
            VW_ASSERT_OK(vw_share_revoke(s.ss, share_id, owner));

            vw_perm_t p = vw_share_resolve_permission(s.ss, s.fs, file, grantee, 0);
            VW_ASSERT_EQ((int)VW_PERM_NONE, (int)p);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("grant: expired grant no longer grants access") {
        share_stack_t s = {0};
        stack_open(&s, "grant_expired");
        {
            uint64_t owner = 100, grantee = 200;
            uint64_t file = make_entry(&s, owner, 0, "doc.txt", VW_ENTRY_FILE);

            uint64_t share_id = 0;
            /* expires_at in the past. */
            VW_ASSERT_OK(vw_share_grant_create(s.ss, file, owner, grantee,
                                                VW_PERM_VIEW, 1, &share_id));

            vw_perm_t p = vw_share_resolve_permission(s.ss, s.fs, file, grantee, 0);
            VW_ASSERT_EQ((int)VW_PERM_NONE, (int)p);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("link: create, get_by_token, and live revocation blocks the next check") {
        share_stack_t s = {0};
        stack_open(&s, "link_basic");
        {
            uint64_t owner = 100;
            uint64_t folder = make_entry(&s, owner, 0, "public", VW_ENTRY_DIR);
            uint64_t file   = make_entry(&s, owner, folder, "readme.txt", VW_ENTRY_FILE);

            uint8_t  token[32];
            uint64_t share_id = 0;
            VW_ASSERT_OK(vw_share_link_create(s.ss, folder, owner, VW_PERM_VIEW, 0,
                                               token, &share_id));

            vw_share_record_t rec;
            VW_ASSERT_OK(vw_share_get_by_token(s.ss, token, &rec));
            VW_ASSERT_EQ(share_id, rec.share_id);

            /* Scoped-session resolution: file inherits the folder link's
             * permission via ancestor walk-up. */
            vw_perm_t p = vw_share_resolve_permission(s.ss, s.fs, file, 0, share_id);
            VW_ASSERT_EQ((int)VW_PERM_VIEW, (int)p);

            /* Live revocation: the very next check must reflect it —
             * nothing about the earlier successful resolution is cached. */
            VW_ASSERT_OK(vw_share_revoke(s.ss, share_id, owner));
            p = vw_share_resolve_permission(s.ss, s.fs, file, 0, share_id);
            VW_ASSERT_EQ((int)VW_PERM_NONE, (int)p);

            /* get_by_token also stops finding a revoked link (anti-
             * enumeration: same VW_ERR_NOT_FOUND as an unknown token). */
            VW_ASSERT_ERR(vw_share_get_by_token(s.ss, token, &rec), VW_ERR_NOT_FOUND);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("link: unknown token returns NOT_FOUND, not a crash") {
        share_stack_t s = {0};
        stack_open(&s, "link_unknown_token");
        {
            uint8_t bogus[32];
            memset(bogus, 0xAB, sizeof(bogus));
            vw_share_record_t rec;
            VW_ASSERT_ERR(vw_share_get_by_token(s.ss, bogus, &rec), VW_ERR_NOT_FOUND);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("permission: owner is not resolved via vw_share_resolve_permission (caller's job)") {
        share_stack_t s = {0};
        stack_open(&s, "perm_owner_not_share");
        {
            /* vw_share_resolve_permission only covers rules 2/3 (grants and
             * scope) — the owner check is effective_permission's job in
             * vw_file_handlers.c, not this function's. With no grant and no
             * scope, even the owner gets VW_PERM_NONE from this call. */
            uint64_t owner = 100;
            uint64_t file = make_entry(&s, owner, 0, "mine.txt", VW_ENTRY_FILE);
            vw_perm_t p = vw_share_resolve_permission(s.ss, s.fs, file, owner, 0);
            VW_ASSERT_EQ((int)VW_PERM_NONE, (int)p);
        }
        stack_close(&s);
    }

    VW_TEST_CASE("rate limit: scoped-session write count blocks past the threshold") {
        share_stack_t s = {0};
        stack_open(&s, "ratelimit_write");
        {
            uint8_t token[32];
            memset(token, 0x11, sizeof(token));

            int allowed = 0, blocked = 0;
            for (int i = 0; i < 40; i++) {
                if (vw_share_scoped_write_ratelimit_check(s.ss, token) == VW_OK)
                    allowed++;
                else
                    blocked++;
            }
            VW_ASSERT(allowed > 0);
            VW_ASSERT(blocked > 0);
            VW_ASSERT_EQ(40, allowed + blocked);

            /* A different token's budget is independent. */
            uint8_t token2[32];
            memset(token2, 0x22, sizeof(token2));
            VW_ASSERT_OK(vw_share_scoped_write_ratelimit_check(s.ss, token2));
        }
        stack_close(&s);
    }

    VW_TEST_CASE("rate limit: LINK_ACCESS failures block the source IP after the threshold") {
        share_stack_t s = {0};
        stack_open(&s, "ratelimit_link_access");
        {
            const char *ip = "203.0.113.7";
            VW_ASSERT(!vw_share_link_access_is_blocked(s.ss, ip));

            for (int i = 0; i < 5; i++)
                vw_share_link_access_record_failure(s.ss, ip);
            VW_ASSERT(vw_share_link_access_is_blocked(s.ss, ip));

            /* A different source IP is unaffected. */
            VW_ASSERT(!vw_share_link_access_is_blocked(s.ss, "203.0.113.8"));

            /* A success resets it. */
            vw_share_link_access_reset_on_success(s.ss, ip);
            VW_ASSERT(!vw_share_link_access_is_blocked(s.ss, ip));
        }
        stack_close(&s);
    }
}
VW_TEST_SUITE_END()
