/*
 * test_search.c — integration test for TASK-198 (SEARCH/SEARCH_RESP,
 * docs/PROTOCOL.md §7.12).
 *
 * Drives the real wire message directly (vw_proto_send/vw_proto_recv over
 * the vw_conn_t a normal vw_client_connect login already establishes) —
 * there is no vw_client_search() wrapper yet (that is TASK-199's job), so
 * this hand-encodes the SEARCH payload and hand-decodes SEARCH_RESP rather
 * than waiting for it. This is exactly the "verified with a real cross-user
 * test, not just code inspection" acceptance criterion TASK-198 itself
 * calls for; TASK-202 (QA.06) is the broader permission/fuzz sweep across
 * every layer once TASK-199/200/201 exist too.
 *
 * Covers:
 *   - owner sees both of their own matching files, is_shared == 0
 *   - a grantee (VIEW grant on the containing folder) sees only the
 *     shared file via search, is_shared == 1 — never the owner's other,
 *     unshared file with a matching name
 *   - a stranger with no access at all gets count == 0, error_code ==
 *     VW_OK, truncated == 0 — the match is invisible, not merely denied
 *   - an oversized query is rejected with VW_ERR_INVALID_ARG before any
 *     match could occur
 *   - a scoped (LINK_ACCESS-redeemed anonymous) session is rejected with
 *     VW_ERR_PERMISSION, per §7.12's "no scoped-session support"
 *   - case-insensitive matching (query case differs from the filenames)
 *
 * Usage: test_search <host> <port> <cert_path>
 *          <owner_user> <owner_pass> <grantee_user> <grantee_pass>
 *          <stranger_user> <stranger_pass>
 * (cert_path is accepted for symmetry with the Python fixtures but unused,
 * same rationale as test_shared_sync.c.)
 */

#include "vw_client_core.h"
#include "vw_fs.h"
#include "vw_crypto.h"
#include "vw_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <sys/stat.h>
#  include <unistd.h>
#  define VW_PID() ((unsigned)getpid())
#endif

/* ── Minimal TAP-ish harness (mirrors test_shared_sync.c) ────────────────── */

static int g_checks = 0, g_failed = 0;

#define CHECK(cond, msg)                                                     \
    do {                                                                     \
        g_checks++;                                                         \
        if (cond) {                                                         \
            printf("ok %d - %s\n", g_checks, msg);                           \
        } else {                                                             \
            printf("not ok %d - %s\n", g_checks, msg);                       \
            printf("  # FAILED at %s:%d\n", __FILE__, __LINE__);             \
            g_failed++;                                                      \
        }                                                                    \
    } while (0)

static void make_tmpdir(char *out, size_t sz) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_search_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_search_%u", VW_PID());
    mkdir(out, 0700);
#endif
}

static void path_join(char *out, size_t sz, const char *dir, const char *name) {
#ifdef _WIN32
    snprintf(out, sz, "%s\\%s", dir, name);
#else
    snprintf(out, sz, "%s/%s", dir, name);
#endif
}

static int write_bytes(const char *path, const char *data) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t len = strlen(data);
    size_t written = len ? fwrite(data, 1, len, f) : 0;
    fclose(f);
    return (written == len) ? 0 : -1;
}

/* ── Raw SEARCH request/response ──────────────────────────────────────────
 * Not a reusable client API — just enough to drive the real wire message
 * for this test. TASK-199 supersedes this with a proper vw_client_search().
 */

#define SEARCH_MAX_ENTRIES 16

typedef struct {
    uint64_t file_id;
    char     name[64];
    uint8_t  is_dir;
    uint8_t  is_shared;
} search_entry_t;

typedef struct {
    uint32_t       error_code;   /* only meaningful if is_error == 0 */
    int            is_error;     /* 1 if the server sent VW_MSG_ERROR instead */
    uint32_t       err_code;     /* decoded VW_MSG_ERROR code, if is_error */
    uint32_t       count;
    uint8_t        truncated;
    search_entry_t entries[SEARCH_MAX_ENTRIES];
} search_result_t;

static vw_err_t raw_search(vw_client_sess_t *sess, const char *query,
                            uint16_t query_len, search_result_t *out)
{
    memset(out, 0, sizeof(*out));

    vw_conn_t *conn = vw_client_conn(sess);
    uint8_t token[VW_TOKEN_BYTES];
    vw_client_get_token(sess, token);

    uint8_t req[VW_TOKEN_BYTES + 2 + 512];
    memcpy(req, token, VW_TOKEN_BYTES);
    uint32_t off = VW_TOKEN_BYTES;
    vw_err_t err = vw_proto_write_str(req, sizeof(req), &off, query, query_len);
    if (err != VW_OK) return err;

    err = vw_proto_send(conn, VW_MSG_SEARCH, req, off);
    if (err != VW_OK) return err;

    static uint8_t rbuf[VW_MAX_MSG_BYTES];
    vw_msg_type_t rtype;
    uint32_t rlen;
    err = vw_proto_recv(conn, &rtype, rbuf, sizeof(rbuf), &rlen);
    if (err != VW_OK) return err;

    if (rtype == VW_MSG_ERROR) {
        uint32_t code; const char *msg; uint16_t msg_len;
        if (vw_proto_decode_error(rbuf, rlen, &code, &msg, &msg_len) != VW_OK)
            return VW_ERR_PROTO_INVALID;
        out->is_error = 1;
        out->err_code = code;
        return VW_OK;
    }
    if (rtype != VW_MSG_SEARCH_RESP) return VW_ERR_PROTO_INVALID;

    uint32_t roff = 0;
    if (roff + 9u > rlen) return VW_ERR_PROTO_TRUNCATED;
    out->error_code = vw_read_u32le(rbuf + roff); roff += 4u;
    out->count      = vw_read_u32le(rbuf + roff); roff += 4u;
    out->truncated  = rbuf[roff++];

    for (uint32_t i = 0; i < out->count; i++) {
        uint64_t file_id = vw_read_u64le(rbuf + roff); roff += 8u;
        const char *name; uint16_t name_len;
        err = vw_proto_read_str(rbuf, rlen, &roff, &name, &name_len);
        if (err != VW_OK) return err;
        if (roff + 1u + 8u + 8u + 8u + 1u > rlen) return VW_ERR_PROTO_TRUNCATED;
        uint8_t is_dir = rbuf[roff++];
        roff += 8u; /* size_bytes, unused by this test */
        roff += 8u; /* mtime_unix, unused by this test */
        roff += 8u; /* vault_id, unused by this test */
        uint8_t is_shared = rbuf[roff++];

        if (i < SEARCH_MAX_ENTRIES) {
            out->entries[i].file_id = file_id;
            uint16_t copy_len = name_len < 63u ? name_len : 63u;
            memcpy(out->entries[i].name, name, copy_len);
            out->entries[i].name[copy_len] = '\0';
            out->entries[i].is_dir    = is_dir;
            out->entries[i].is_shared = is_shared;
        }
    }
    return VW_OK;
}

static int result_has_file(const search_result_t *r, uint64_t file_id, uint8_t expect_shared)
{
    uint32_t n = r->count < SEARCH_MAX_ENTRIES ? r->count : SEARCH_MAX_ENTRIES;
    for (uint32_t i = 0; i < n; i++)
        if (r->entries[i].file_id == file_id)
            return r->entries[i].is_shared == expect_shared;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 10) {
        fprintf(stderr,
                "usage: %s <host> <port> <cert_path> <owner_user> <owner_pass> "
                "<grantee_user> <grantee_pass> <stranger_user> <stranger_pass>\n", argv[0]);
        return 2;
    }
    const char *host           = argv[1];
    uint16_t    port           = (uint16_t)atoi(argv[2]);
    const char *owner_user     = argv[4];
    const char *owner_pass     = argv[5];
    const char *grantee_user   = argv[6];
    const char *grantee_pass   = argv[7];
    const char *stranger_user  = argv[8];
    const char *stranger_pass  = argv[9];

    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");

    if (vw_crypto_init() != VW_OK) {
        fprintf(stderr, "vw_crypto_init failed\n");
        return 1;
    }

    char tmpdir[512];
    make_tmpdir(tmpdir, sizeof(tmpdir));

    vw_client_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host             = host;
    cfg.port             = port;
    cfg.cert_verify      = VW_CERT_VERIFY_NONE;
    cfg.ca_cert_pem_path = NULL;
    cfg.conn_opts        = NULL;

    /* ── Owner: folder + shared file + unshared top-level file ────────── */

    vw_client_sess_t *owner_sess = NULL;
    vw_err_t err = vw_client_connect(&cfg, owner_user, (uint16_t)strlen(owner_user),
                                      owner_pass, strlen(owner_pass), NULL, NULL, &owner_sess);
    CHECK(err == VW_OK, "owner: connect/login");
    if (err != VW_OK) return 1;

    uint64_t folder_id = 0;
    err = vw_client_file_mkdir(owner_sess, 0, "search_root", &folder_id);
    CHECK(err == VW_OK && folder_id != 0, "owner: mkdir search_root");

    char shared_local[600], unshared_local[600];
    path_join(shared_local, sizeof(shared_local), tmpdir, "shared_src.txt");
    path_join(unshared_local, sizeof(unshared_local), tmpdir, "unshared_src.txt");
    write_bytes(shared_local, "shared content");
    write_bytes(unshared_local, "unshared content");

    err = vw_client_file_upload(owner_sess, "/search_root/findme_alpha_shared.txt",
                                 shared_local, NULL, NULL);
    CHECK(err == VW_OK, "owner: upload shared file into search_root");

    err = vw_client_file_upload(owner_sess, "/findme_alpha_owner.txt",
                                 unshared_local, NULL, NULL);
    CHECK(err == VW_OK, "owner: upload unshared top-level file");

    uint64_t shared_file_id = 0, unshared_file_id = 0;
    {
        vw_file_entry_t st;
        err = vw_client_file_stat(owner_sess, "/search_root/findme_alpha_shared.txt", &st);
        CHECK(err == VW_OK, "owner: stat shared file");
        shared_file_id = st.file_id;

        err = vw_client_file_stat(owner_sess, "/findme_alpha_owner.txt", &st);
        CHECK(err == VW_OK, "owner: stat unshared file");
        unshared_file_id = st.file_id;
    }

    uint64_t share_id = 0;
    err = vw_client_share_grant(owner_sess, folder_id, grantee_user, VW_PERM_VIEW, 0, &share_id);
    CHECK(err == VW_OK && share_id != 0, "owner: grant VIEW on search_root to grantee");

    /* ── Owner's own search: both matches, both unshared from their view ── */

    search_result_t r;
    err = raw_search(owner_sess, "FINDME_ALPHA", 12, &r);
    CHECK(err == VW_OK && !r.is_error && r.error_code == VW_OK,
          "owner: search succeeds (case-differing query)");
    CHECK(r.count >= 2, "owner: search finds both of their own matching files");
    CHECK(result_has_file(&r, shared_file_id, 0), "owner: shared file listed with is_shared=0 (they're the owner)");
    CHECK(result_has_file(&r, unshared_file_id, 0), "owner: unshared file listed with is_shared=0");

    /* ── Result cap boundary: 201 matches must yield count=200, truncated=1 ── */

    {
        int mkdir_failed = 0;
        for (int i = 0; i < 201; i++) {
            char dirname[32];
            snprintf(dirname, sizeof(dirname), "capdir_%03d", i);
            uint64_t dummy_id = 0;
            if (vw_client_file_mkdir(owner_sess, 0, dirname, &dummy_id) != VW_OK || dummy_id == 0) {
                mkdir_failed = 1;
                break;
            }
        }
        CHECK(!mkdir_failed, "owner: created 201 distinctly-matching directories for the cap test");

        err = raw_search(owner_sess, "capdir_", 7, &r);
        CHECK(err == VW_OK && !r.is_error && r.error_code == VW_OK, "owner: cap-boundary search succeeds");
        CHECK(r.count == 200, "owner: result cap stops at exactly 200 entries, not 201");
        CHECK(r.truncated == 1, "owner: truncated=1 when more matches existed than the cap");
    }

    /* ── Grantee: only the file actually shared with them, is_shared=1 ──── */

    vw_client_sess_t *grantee_sess = NULL;
    err = vw_client_connect(&cfg, grantee_user, (uint16_t)strlen(grantee_user),
                             grantee_pass, strlen(grantee_pass), NULL, NULL, &grantee_sess);
    CHECK(err == VW_OK, "grantee: connect/login");
    if (err == VW_OK) {
        err = raw_search(grantee_sess, "findme_alpha", 12, &r);
        CHECK(err == VW_OK && !r.is_error && r.error_code == VW_OK, "grantee: search succeeds");
        CHECK(r.count == 1, "grantee: search finds exactly the one shared file, not the owner's unshared one");
        CHECK(result_has_file(&r, shared_file_id, 1), "grantee: shared file listed with is_shared=1");
        CHECK(!result_has_file(&r, unshared_file_id, 0) && !result_has_file(&r, unshared_file_id, 1),
              "grantee: owner's unshared file never appears, in any form");

        /* Oversized query: rejected before any scan, never a match. */
        char big_query[300];
        memset(big_query, 'a', sizeof(big_query));
        err = raw_search(grantee_sess, big_query, sizeof(big_query), &r);
        CHECK(err == VW_OK && r.is_error && r.err_code == (uint32_t)VW_ERR_INVALID_ARG,
              "grantee: oversized query rejected with VW_ERR_INVALID_ARG");
    }
    /* Closed before connecting the next user: the test server's default
     * max_workers (2) only supports two live connections at once, and
     * this test needs owner_sess held open for the LINK_CREATE step at
     * the end — so grantee/stranger/scoped sessions are each opened,
     * used, and closed in turn rather than all held concurrently. */
    if (grantee_sess) { vw_client_close(grantee_sess); grantee_sess = NULL; }

    /* ── Stranger: no access at all — the match must be invisible, not just denied ── */

    vw_client_sess_t *stranger_sess = NULL;
    err = vw_client_connect(&cfg, stranger_user, (uint16_t)strlen(stranger_user),
                             stranger_pass, strlen(stranger_pass), NULL, NULL, &stranger_sess);
    CHECK(err == VW_OK, "stranger: connect/login");
    if (err == VW_OK) {
        err = raw_search(stranger_sess, "findme_alpha", 12, &r);
        CHECK(err == VW_OK && !r.is_error, "stranger: search itself is not an error");
        CHECK(r.error_code == VW_OK, "stranger: error_code is VW_OK, not a permission error");
        CHECK(r.count == 0, "stranger: count is 0 — no visible match, not merely an empty page");
        CHECK(r.truncated == 0, "stranger: truncated is 0 (nothing was hidden by the cap either)");
    }
    if (stranger_sess) { vw_client_close(stranger_sess); stranger_sess = NULL; }

    /* ── Scoped session (public link redeem): rejected outright ─────────── */

    uint8_t link_token[32];
    uint64_t link_share_id = 0;
    err = vw_client_link_create(owner_sess, shared_file_id, VW_PERM_VIEW, 0, NULL,
                                 &link_share_id, link_token);
    CHECK(err == VW_OK && link_share_id != 0, "owner: create public link on shared file");
    if (err == VW_OK) {
        vw_client_sess_t *scoped_sess = NULL;
        err = vw_client_link_access(&cfg, link_token, NULL, &scoped_sess);
        CHECK(err == VW_OK, "anonymous: redeem link");
        if (err == VW_OK) {
            err = raw_search(scoped_sess, "findme_alpha", 12, &r);
            CHECK(err == VW_OK && r.is_error && r.err_code == (uint32_t)VW_ERR_PERMISSION,
                  "scoped session: SEARCH rejected with VW_ERR_PERMISSION");
            vw_client_close(scoped_sess);
        }
    }

    vw_client_close(owner_sess);

    printf("1..%d\n", g_checks);
    return g_failed ? 1 : 0;
}
