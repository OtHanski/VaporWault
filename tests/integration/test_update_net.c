/*
 * test_update_net.c — integration tests for TASK-00296's vw_update_net.
 *
 * Uses VW_UPDATE_NET_TEST_HOOKS (this target's own compiled copy of
 * vw_update_net.c, same VW_SYNC_TEST_HOOKS-style convention as
 * test_shared_sync_hardening.c) to redirect the connect step at a local
 * self-signed TLS test server (VW_CERT_VERIFY_NONE) instead of the real
 * VW_CERT_VERIFY_SYSTEM_STORE path, which no local test server can ever
 * satisfy — the real SYSTEM_STORE path itself is exercised separately by
 * a manual real-GitHub fetch (documented in TASK-00296's own notes, not
 * automated here since CI doesn't reliably have live internet).
 *
 * Also overrides VW_UPDATE_RECV_TIMEOUT_MS down to a small value via
 * target_compile_definitions so the timeout-enforcement case is fast.
 *
 * TC-1: happy path — 200 OK, Content-Length, body round-trips exactly.
 * TC-2: oversized Content-Length rejected before any body byte is read.
 * TC-3: Transfer-Encoding: chunked rejected.
 * TC-4: a single redirect (302 -> 200, different port = different "host")
 *       succeeds.
 * TC-5: a second redirect (302 -> 302 -> ...) is a hard failure.
 * TC-6: malformed status line / missing Content-Length rejected, no crash.
 * TC-7: a server that accepts but never responds trips the recv timeout.
 * TC-8: a redirect to a host outside the allowlist (SEC.07 finding) is
 *       rejected before ever attempting to connect to it — this target
 *       overrides VW_UPDATE_REDIRECT_ALLOWED_SUFFIX_1 to "127.0.0.1" (see
 *       CMakeLists.txt) so TC-4/5 above can still exercise real redirects
 *       against the local test server while this case proves the
 *       allowlist mechanism itself actually rejects anything else.
 */

#include "vw_test.h"
#include "vw_update_net.h"
#include "vw_net.h"
#include "vw_crypto.h"

#ifdef _WIN32
#  include <windows.h>
#  include <stdlib.h>
typedef HANDLE            pthread_t;
typedef CRITICAL_SECTION  pthread_mutex_t;
typedef CONDITION_VARIABLE pthread_cond_t;
typedef struct { void *(*fn)(void *); void *arg; } _pt_thunk_t;
static DWORD WINAPI _pt_thunk(LPVOID p) {
    _pt_thunk_t *t = (_pt_thunk_t *)p; t->fn(t->arg); free(t); return 0;
}
static int pthread_create(pthread_t *h, void *a, void *(*fn)(void *), void *arg) {
    _pt_thunk_t *t; (void)a;
    t = (_pt_thunk_t *)malloc(sizeof(*t)); if (!t) return 1;
    t->fn = fn; t->arg = arg;
    *h = CreateThread(NULL, 0, _pt_thunk, t, 0, NULL);
    if (!*h) { free(t); return 1; } return 0;
}
static int pthread_join(pthread_t h, void **r) { (void)r; WaitForSingleObject(h, INFINITE); CloseHandle(h); return 0; }
static int pthread_mutex_init(pthread_mutex_t *m, void *a)    { (void)a; InitializeCriticalSection(m); return 0; }
static int pthread_mutex_destroy(pthread_mutex_t *m)           { DeleteCriticalSection(m); return 0; }
static int pthread_mutex_lock(pthread_mutex_t *m)              { EnterCriticalSection(m); return 0; }
static int pthread_mutex_unlock(pthread_mutex_t *m)            { LeaveCriticalSection(m); return 0; }
static int pthread_cond_init(pthread_cond_t *c, void *a)       { (void)a; InitializeConditionVariable(c); return 0; }
static int pthread_cond_destroy(pthread_cond_t *c)             { (void)c; return 0; }
static int pthread_cond_wait(pthread_cond_t *c, pthread_mutex_t *m) { return SleepConditionVariableCS(c, m, INFINITE) ? 0 : 1; }
static int pthread_cond_signal(pthread_cond_t *c)              { WakeConditionVariable(c); return 0; }
#else
#  include <pthread.h>
#  include <unistd.h>
#endif

#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#  include <process.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <sys/stat.h>
#  define VW_PID() ((unsigned)getpid())
#endif

/* Same embedded self-signed test cert used by test_proto_recv_drain.c. */
static const char TEST_CERT_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBiDCCAS+gAwIBAgIUOw4bN+Qy08iH92/Z1kabLuEvRL8wCgYIKoZIzj0EAwIw\n"
    "GjEYMBYGA1UEAwwPVmFwb3JXYXVsdCBUZXN0MB4XDTI2MDcwNzA5NTkzOVoXDTM2\n"
    "MDcwNDA5NTkzOVowGjEYMBYGA1UEAwwPVmFwb3JXYXVsdCBUZXN0MFkwEwYHKoZI\n"
    "zj0CAQYIKoZIzj0DAQcDQgAEBzR5n+n1kbN6f2goisc6aFUwkdNbxwGqXJ3yO3ra\n"
    "cWQ/eUC+wivPwa0nLByWqF5WcAJgyP/mk38QgzCn9Xd7EaNTMFEwHQYDVR0OBBYE\n"
    "FDZWT/P4PsQJMxNdcpFZSalt59sKMB8GA1UdIwQYMBaAFDZWT/P4PsQJMxNdcpFZ\n"
    "Salt59sKMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgWLzqbWKg\n"
    "aDH/Ml+h9ShTBu1Nk2MDdW0rwKU1xJRKfHUCIDbD63boc0KQ+VV07cNm/fJdXnk5\n"
    "5NO/rLH3Clxrw7G+\n"
    "-----END CERTIFICATE-----\n";

static const char TEST_KEY_PEM[] =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgF2IMcHwOLqwfSGGg\n"
    "9Gp3+exub9eTrJu5Sz5OETwd2WKhRANCAAQHNHmf6fWRs3p/aCiKxzpoVTCR01vH\n"
    "AapcnfI7etpxZD95QL7CK8/BrScsHJaoXlZwAmDI/+aTfxCDMKf1d3sR\n"
    "-----END PRIVATE KEY-----\n";

#define TEST_PORT_BASE 43751u

static void make_tmpdir(char *out, size_t sz) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_updatenet_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_updatenet_%u", VW_PID());
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
static int write_file(const char *path, const char *data) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = strlen(data);
    size_t written = fwrite(data, 1, n, f);
    fclose(f);
    return (written == n) ? 0 : -1;
}

/* ── Test connect hook: local server, no cert verification ──────────────── */

static vw_err_t test_connect_hook(const char *host, uint16_t port,
                                   const vw_conn_opts_t *opts,
                                   vw_conn_t **out_conn) {
    return vw_net_connect_generic(host, port, VW_CERT_VERIFY_NONE, NULL, opts, out_conn);
}

/* ── Raw response server: accepts one connection, reads (and discards) the
 * request, sends the caller-supplied raw response bytes verbatim, then
 * either closes (respond) or holds the connection open forever without
 * sending anything (hang_instead, for the timeout test) ─────────────────── */

typedef struct {
    const char *cert_path;
    const char *key_path;
    uint16_t    port;
    const void *response;
    size_t      response_len;
    int         hang_instead;

    pthread_mutex_t mtx;
    pthread_cond_t  cond;
    int             ready;
    vw_err_t        bind_err;
    vw_err_t        result_err;
} raw_srv_args_t;

static void *raw_srv_thread(void *arg) {
    raw_srv_args_t *a = arg;
    vw_net_ctx_t *net_ctx = NULL;
    vw_err_t err = vw_net_listen("127.0.0.1", a->port, a->cert_path, a->key_path, &net_ctx);
    a->bind_err = err;

    pthread_mutex_lock(&a->mtx);
    a->ready = 1;
    pthread_cond_signal(&a->cond);
    pthread_mutex_unlock(&a->mtx);

    if (err != VW_OK) return NULL;

    vw_conn_t *conn = NULL;
    err = vw_net_accept(net_ctx, &conn);
    if (err != VW_OK) { a->result_err = err; vw_net_ctx_close(net_ctx); return NULL; }

    uint8_t discard[4096];
    size_t got = 0;
    (void)vw_net_recv_partial(conn, discard, sizeof(discard), &got);

    if (a->hang_instead) {
        /* Hold the connection open, sending nothing, until the client's
         * own recv timeout fires and it closes — our next recv then fails
         * and this thread exits. Bounded by the client's short test-mode
         * VW_UPDATE_RECV_TIMEOUT_MS, not by anything on this side. */
        uint8_t buf[16];
        size_t n = 0;
        vw_err_t rc;
        do {
#ifdef _WIN32
            Sleep(50);
#else
            usleep(50000);
#endif
            rc = vw_net_recv_partial(conn, buf, sizeof(buf), &n);
        } while (rc == VW_OK);
        a->result_err = VW_OK;
    } else {
        a->result_err = vw_net_send(conn, a->response, a->response_len);
    }

    vw_net_close(conn);
    vw_net_ctx_close(net_ctx);
    return NULL;
}

static pthread_t spawn_raw_srv(raw_srv_args_t *a) {
    a->ready = 0;
    a->bind_err = VW_OK;
    a->result_err = VW_OK;
    pthread_mutex_init(&a->mtx, NULL);
    pthread_cond_init(&a->cond, NULL);
    pthread_t tid;
    pthread_create(&tid, NULL, raw_srv_thread, a);
    pthread_mutex_lock(&a->mtx);
    while (!a->ready) pthread_cond_wait(&a->cond, &a->mtx);
    pthread_mutex_unlock(&a->mtx);
    return tid;
}
static void join_raw_srv(pthread_t tid, raw_srv_args_t *a) {
    pthread_join(tid, NULL);
    pthread_mutex_destroy(&a->mtx);
    pthread_cond_destroy(&a->cond);
}

VW_TEST_SUITE("update_net") {
    VW_ASSERT_EQ(vw_crypto_init(), VW_OK);
    vw_update_net_test_set_connect_hook(test_connect_hook);

    char tmpdir[512];
    make_tmpdir(tmpdir, sizeof(tmpdir));
    char cert_path[600], key_path[600];
    path_join(cert_path, sizeof(cert_path), tmpdir, "test_cert.pem");
    path_join(key_path,  sizeof(key_path),  tmpdir, "test_key.pem");
    VW_ASSERT(write_file(cert_path, TEST_CERT_PEM) == 0);
    VW_ASSERT(write_file(key_path,  TEST_KEY_PEM)  == 0);

    /* ── TC-1: happy path ────────────────────────────────────────────── */
    VW_TEST_CASE("200 OK with Content-Length round-trips the body exactly") {
        static const char resp[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nhello, world!";
        raw_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = (uint16_t)TEST_PORT_BASE;
        sa.response = resp; sa.response_len = sizeof(resp) - 1; sa.hang_instead = 0;
        pthread_t tid = spawn_raw_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_update_response_t out;
        vw_err_t err = vw_update_https_get("127.0.0.1", (uint16_t)TEST_PORT_BASE, "/x", 4096, &out);
        VW_ASSERT_EQ(err, VW_OK);
        VW_ASSERT_EQ(out.body_len, (size_t)13);
        VW_ASSERT(memcmp(out.body, "hello, world!", 13) == 0);
        vw_update_response_free(&out);

        join_raw_srv(tid, &sa);
    }

    /* ── TC-2: oversized Content-Length rejected ─────────────────────── */
    VW_TEST_CASE("Content-Length exceeding max_body_bytes is rejected") {
        static const char resp[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n";
        raw_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = (uint16_t)(TEST_PORT_BASE + 1);
        sa.response = resp; sa.response_len = sizeof(resp) - 1; sa.hang_instead = 0;
        pthread_t tid = spawn_raw_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_update_response_t out;
        vw_err_t err = vw_update_https_get("127.0.0.1", (uint16_t)(TEST_PORT_BASE + 1), "/x", 4096, &out);
        VW_ASSERT_EQ(err, VW_ERR_UPDATE_NET);
        VW_ASSERT(out.body == NULL);

        join_raw_srv(tid, &sa);
    }

    /* ── TC-3: chunked encoding rejected ─────────────────────────────── */
    VW_TEST_CASE("Transfer-Encoding: chunked is rejected") {
        static const char resp[] =
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        raw_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = (uint16_t)(TEST_PORT_BASE + 2);
        sa.response = resp; sa.response_len = sizeof(resp) - 1; sa.hang_instead = 0;
        pthread_t tid = spawn_raw_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_update_response_t out;
        vw_err_t err = vw_update_https_get("127.0.0.1", (uint16_t)(TEST_PORT_BASE + 2), "/x", 4096, &out);
        VW_ASSERT_EQ(err, VW_ERR_UPDATE_NET);

        join_raw_srv(tid, &sa);
    }

    /* ── TC-4: a single redirect to a different port succeeds ───────── */
    VW_TEST_CASE("a single redirect (302 -> 200) succeeds") {
        uint16_t port_a = (uint16_t)(TEST_PORT_BASE + 3);
        uint16_t port_b = (uint16_t)(TEST_PORT_BASE + 4);

        char redirect_resp[256];
        int rn = snprintf(redirect_resp, sizeof(redirect_resp),
                           "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:%u/final\r\n"
                           "Content-Length: 0\r\n\r\n", (unsigned)port_b);
        static const char final_resp[] =
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

        raw_srv_args_t s1, s2;
        s1.cert_path = cert_path; s1.key_path = key_path; s1.port = port_a;
        s1.response = redirect_resp; s1.response_len = (size_t)rn; s1.hang_instead = 0;
        s2.cert_path = cert_path; s2.key_path = key_path; s2.port = port_b;
        s2.response = final_resp; s2.response_len = sizeof(final_resp) - 1; s2.hang_instead = 0;

        pthread_t t2 = spawn_raw_srv(&s2);
        pthread_t t1 = spawn_raw_srv(&s1);
        VW_ASSERT_EQ(s1.bind_err, VW_OK);
        VW_ASSERT_EQ(s2.bind_err, VW_OK);

        vw_update_response_t out;
        vw_err_t err = vw_update_https_get("127.0.0.1", port_a, "/start", 4096, &out);
        VW_ASSERT_EQ(err, VW_OK);
        VW_ASSERT_EQ(out.body_len, (size_t)2);
        VW_ASSERT(memcmp(out.body, "ok", 2) == 0);
        vw_update_response_free(&out);

        join_raw_srv(t1, &s1);
        join_raw_srv(t2, &s2);
    }

    /* ── TC-5: a second redirect is a hard failure ───────────────────── */
    VW_TEST_CASE("a second redirect is rejected") {
        uint16_t port_a = (uint16_t)(TEST_PORT_BASE + 5);
        uint16_t port_b = (uint16_t)(TEST_PORT_BASE + 6);

        char resp_a[256], resp_b[256];
        int rn_a = snprintf(resp_a, sizeof(resp_a),
                             "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:%u/hop2\r\n"
                             "Content-Length: 0\r\n\r\n", (unsigned)port_b);
        int rn_b = snprintf(resp_b, sizeof(resp_b),
                             "HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:%u/hop3\r\n"
                             "Content-Length: 0\r\n\r\n", (unsigned)port_a);

        raw_srv_args_t s1, s2;
        s1.cert_path = cert_path; s1.key_path = key_path; s1.port = port_a;
        s1.response = resp_a; s1.response_len = (size_t)rn_a; s1.hang_instead = 0;
        s2.cert_path = cert_path; s2.key_path = key_path; s2.port = port_b;
        s2.response = resp_b; s2.response_len = (size_t)rn_b; s2.hang_instead = 0;

        pthread_t t2 = spawn_raw_srv(&s2);
        pthread_t t1 = spawn_raw_srv(&s1);
        VW_ASSERT_EQ(s1.bind_err, VW_OK);
        VW_ASSERT_EQ(s2.bind_err, VW_OK);

        vw_update_response_t out;
        vw_err_t err = vw_update_https_get("127.0.0.1", port_a, "/start", 4096, &out);
        VW_ASSERT_EQ(err, VW_ERR_UPDATE_NET);

        join_raw_srv(t1, &s1);
        join_raw_srv(t2, &s2);
    }

    /* ── TC-8: redirect to a disallowed host is rejected up front ────── */
    VW_TEST_CASE("redirect to a host outside the allowlist is rejected") {
        uint16_t port_a = (uint16_t)(TEST_PORT_BASE + 8);

        /* No server is ever started at "evil.example.invalid" — if the
         * allowlist check were missing or broken, this would fail as a
         * connect/DNS error rather than the expected VW_ERR_UPDATE_NET
         * rejection, so this still meaningfully distinguishes the two. */
        static const char redirect_resp[] =
            "HTTP/1.1 302 Found\r\nLocation: https://evil.example.invalid/final\r\n"
            "Content-Length: 0\r\n\r\n";

        raw_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = port_a;
        sa.response = redirect_resp; sa.response_len = sizeof(redirect_resp) - 1; sa.hang_instead = 0;
        pthread_t tid = spawn_raw_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_update_response_t out;
        vw_err_t err = vw_update_https_get("127.0.0.1", port_a, "/start", 4096, &out);
        VW_ASSERT_EQ(err, VW_ERR_UPDATE_NET);

        join_raw_srv(tid, &sa);
    }

    /* ── TC-6: malformed response rejected, no crash ─────────────────── */
    VW_TEST_CASE("malformed status line is rejected without crashing") {
        static const char resp[] = "NOT A REAL HTTP RESPONSE\r\n\r\n";
        raw_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = (uint16_t)(TEST_PORT_BASE + 7);
        sa.response = resp; sa.response_len = sizeof(resp) - 1; sa.hang_instead = 0;
        pthread_t tid = spawn_raw_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_update_response_t out;
        vw_err_t err = vw_update_https_get("127.0.0.1", (uint16_t)(TEST_PORT_BASE + 7), "/x", 4096, &out);
        VW_ASSERT_EQ(err, VW_ERR_UPDATE_NET);

        join_raw_srv(tid, &sa);
    }

    VW_TEST_CASE("200 OK with no Content-Length is rejected") {
        static const char resp[] = "HTTP/1.1 200 OK\r\n\r\nsome body bytes";
        raw_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = (uint16_t)(TEST_PORT_BASE + 8);
        sa.response = resp; sa.response_len = sizeof(resp) - 1; sa.hang_instead = 0;
        pthread_t tid = spawn_raw_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_update_response_t out;
        vw_err_t err = vw_update_https_get("127.0.0.1", (uint16_t)(TEST_PORT_BASE + 8), "/x", 4096, &out);
        VW_ASSERT_EQ(err, VW_ERR_UPDATE_NET);

        join_raw_srv(tid, &sa);
    }

    /* ── TC-7: recv timeout is enforced ──────────────────────────────── */
    VW_TEST_CASE("a server that never responds trips the recv timeout") {
        raw_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = (uint16_t)(TEST_PORT_BASE + 9);
        sa.response = NULL; sa.response_len = 0; sa.hang_instead = 1;
        pthread_t tid = spawn_raw_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_update_response_t out;
        vw_err_t err = vw_update_https_get("127.0.0.1", (uint16_t)(TEST_PORT_BASE + 9), "/x", 4096, &out);
        VW_ASSERT_EQ(err, VW_ERR_UPDATE_NET); /* mapped from the underlying recv timeout */

        join_raw_srv(tid, &sa);
    }

    vw_crypto_cleanup();
}
VW_TEST_SUITE_END()
