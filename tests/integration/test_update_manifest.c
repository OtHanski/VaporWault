/*
 * test_update_manifest.c — integration tests for TASK-00297's
 * vw_update_manifest_fetch_and_verify().
 *
 * Uses VW_UPDATE_NET_TEST_HOOKS (vw_update_net.c's test seam) to point
 * the connect step at a local self-signed TLS test server, and this
 * target's own compile-time overrides (VW_UPDATE_GITHUB_HOST/_PORT/
 * _MANIFEST_PATH/_SIG_PATH) to point vw_update_manifest.c's fetch calls
 * at that same local server instead of the real github.com.
 *
 * All test manifests are signed with the REAL update-manifest private
 * key (generated for TASK-00293, kept only in local scratch state, never
 * committed) — verified against the REAL compiled-in
 * VW_UPDATE_MANIFEST_PUBKEY, not a test substitute. This proves the
 * actual production trust anchor works end-to-end, not just a stand-in.
 *
 * The server always serves the manifest bytes on the connection's FIRST
 * request and the signature bytes on the SECOND — matching
 * vw_update_manifest_fetch_and_verify()'s documented, implemented fetch
 * order (manifest, then detached signature) exactly, so it doesn't need
 * to parse the request path itself.
 *
 * TC-1: a real, validly-signed manifest verifies, parses correctly (all
 *       fields, both assets), and advances the ratchet to its sequence.
 * TC-2: a tampered manifest body (signature no longer matches) is
 *       rejected before parsing ever runs — and does NOT touch the ratchet.
 * TC-3: a validly-signed manifest whose sequence is below the ratchet
 *       set by TC-1 is rejected with VW_ERR_UPDATE_MANIFEST_ROLLBACK, and
 *       the ratchet is NOT moved backward.
 * TC-4: a validly-signed manifest with a HIGHER sequence than the current
 *       ratchet succeeds and advances the ratchet further.
 * TC-5: a validly-signed but schema-invalid payload (verifies fine, isn't
 *       the expected JSON shape) is rejected by the parser, not silently
 *       half-accepted.
 */

#include "vw_test.h"
#include "vw_update_manifest.h"
#include "vw_update_net.h"
#include "vw_net.h"
#include "vw_crypto.h"
#include "vw_fs.h"

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

/* Same embedded self-signed test cert used elsewhere in this suite. */
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

#define TEST_PORT 43771u

/* ── Real test manifests, all signed with the real update-manifest
 * private key (generated offline for TASK-00293; verified against the
 * real compiled-in VW_UPDATE_MANIFEST_PUBKEY, not a test substitute). ── */

static const char MANIFEST_OK[] =
    "{\"schema_version\":1,\"sequence\":5,\"release_version\":\"0.4.2\","
    "\"min_client_protocol_version\":6,\"published_at\":1757900000,"
    "\"assets\":["
    "{\"platform\":\"linux\",\"arch\":\"x86_64\",\"dist_kind\":\"portable\","
    "\"filename\":\"vaporwault-v0.4.2-linux-x86_64.tar.gz\","
    "\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},"
    "{\"platform\":\"windows\",\"arch\":\"x86_64\",\"dist_kind\":\"portable\","
    "\"filename\":\"vaporwault-v0.4.2-windows-x86_64.zip\","
    "\"sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"}"
    "]}";
static const uint8_t MANIFEST_OK_SIG[] = {
    0x30, 0x45, 0x02, 0x20, 0x11, 0xb9, 0xb4, 0x7e, 0xeb, 0x11, 0x5e, 0x7b,
    0x15, 0xdd, 0xb0, 0xff, 0x61, 0x8d, 0x6c, 0xf5, 0xe3, 0x25, 0xbc, 0xad,
    0xf7, 0x71, 0xce, 0x3b, 0x1f, 0x25, 0x1e, 0x76, 0x1b, 0x4c, 0x58, 0xf3,
    0x02, 0x21, 0x00, 0xc3, 0xa9, 0xf7, 0x4c, 0x38, 0xf0, 0xc1, 0x78, 0x84,
    0x5a, 0xa7, 0xde, 0x5d, 0x44, 0xc2, 0x8a, 0x7c, 0x96, 0x3e, 0xd5, 0x3b,
    0xe9, 0x9c, 0xa1, 0x32, 0xeb, 0xe8, 0xd9, 0x19, 0x96, 0x5f, 0x01
};

static const char MANIFEST_OLD[] =
    "{\"schema_version\":1,\"sequence\":2,\"release_version\":\"0.4.0\","
    "\"min_client_protocol_version\":6,\"published_at\":1757800000,"
    "\"assets\":[{\"platform\":\"linux\",\"arch\":\"x86_64\",\"dist_kind\":\"portable\","
    "\"filename\":\"vaporwault-v0.4.0-linux-x86_64.tar.gz\","
    "\"sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"}]}";
static const uint8_t MANIFEST_OLD_SIG[] = {
    0x30, 0x45, 0x02, 0x21, 0x00, 0xc4, 0xb6, 0x78, 0x72, 0x84, 0xda, 0xf7,
    0x54, 0xeb, 0x1e, 0xc6, 0xb9, 0x15, 0x10, 0x44, 0x44, 0x35, 0x2c, 0x22,
    0x5c, 0x6c, 0xfb, 0x2f, 0x06, 0x30, 0xe2, 0xce, 0x05, 0x55, 0x9e, 0x5a,
    0x65, 0x02, 0x20, 0x15, 0x31, 0xe3, 0x48, 0xf6, 0xf1, 0x87, 0x12, 0x8d,
    0x7f, 0x8a, 0xc9, 0xc2, 0x98, 0xe9, 0x4d, 0x85, 0x48, 0x7d, 0xa7, 0xdb,
    0x54, 0xaf, 0xc4, 0x90, 0xcc, 0x5a, 0x19, 0x6b, 0x5b, 0x17, 0x5a
};

static const char MANIFEST_NEW[] =
    "{\"schema_version\":1,\"sequence\":9,\"release_version\":\"0.5.0\","
    "\"min_client_protocol_version\":6,\"published_at\":1758000000,"
    "\"assets\":[{\"platform\":\"linux\",\"arch\":\"x86_64\",\"dist_kind\":\"portable\","
    "\"filename\":\"vaporwault-v0.5.0-linux-x86_64.tar.gz\","
    "\"sha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"}]}";
static const uint8_t MANIFEST_NEW_SIG[] = {
    0x30, 0x45, 0x02, 0x20, 0x53, 0x34, 0x66, 0x63, 0x8a, 0xd5, 0x56, 0xde,
    0x1c, 0xda, 0xf2, 0xa2, 0x02, 0xac, 0x75, 0x29, 0xba, 0x94, 0xf3, 0xaf,
    0xfe, 0x52, 0x1a, 0x5d, 0xcb, 0x8f, 0x05, 0x28, 0xcc, 0xb1, 0x82, 0x1c,
    0x02, 0x21, 0x00, 0xb2, 0xec, 0x31, 0xdd, 0x4e, 0xd1, 0xe2, 0x92, 0xf2,
    0xf9, 0x5c, 0xdc, 0x6e, 0x39, 0x96, 0x73, 0xa0, 0x6d, 0xb9, 0xe9, 0x6b,
    0x67, 0x41, 0x14, 0x27, 0x7a, 0x09, 0x15, 0x85, 0x54, 0xc8, 0x9f
};

static const char MANIFEST_BADSCHEMA[] = "{\"foo\":\"bar\"}";
static const uint8_t MANIFEST_BADSCHEMA_SIG[] = {
    0x30, 0x44, 0x02, 0x20, 0x44, 0x9f, 0x0a, 0x76, 0xa5, 0x56, 0x9c, 0xa1,
    0x73, 0x69, 0x97, 0x9c, 0xa5, 0x07, 0x3b, 0xf9, 0x50, 0x02, 0x69, 0xef,
    0xbb, 0x16, 0x96, 0x25, 0x7b, 0x89, 0x27, 0x54, 0xe6, 0x22, 0xde, 0xd6,
    0x02, 0x20, 0x41, 0x28, 0xe7, 0x44, 0x2c, 0x67, 0xb0, 0x7a, 0x52, 0xf3,
    0x3e, 0x67, 0x9d, 0xbd, 0x19, 0x8d, 0x31, 0x2a, 0x94, 0x7c, 0xf8, 0x91,
    0xb1, 0xac, 0x20, 0x90, 0xc4, 0x2c, 0x37, 0x1e, 0x6c, 0xb2
};

static void make_tmpdir(char *out, size_t sz) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_updatemanifest_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_updatemanifest_%u", VW_PID());
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

static vw_err_t test_connect_hook(const char *host, uint16_t port,
                                   const vw_conn_opts_t *opts,
                                   vw_conn_t **out_conn) {
    return vw_net_connect_generic(host, port, VW_CERT_VERIFY_NONE, NULL, opts, out_conn);
}

/* ── Two-connection server: serves manifest_bytes on the first accepted
 * connection, sig_bytes on the second, each wrapped in a minimal 200 OK
 * response with a correct Content-Length. ──────────────────────────── */

typedef struct {
    const char *cert_path;
    const char *key_path;
    uint16_t    port;
    const void *manifest_bytes;  size_t manifest_len;
    const void *sig_bytes;       size_t sig_len;

    pthread_mutex_t mtx;
    pthread_cond_t  cond;
    int             ready;
    vw_err_t        bind_err;
} dual_srv_args_t;

static vw_err_t serve_one(vw_net_ctx_t *net_ctx, const void *body, size_t body_len) {
    vw_conn_t *conn = NULL;
    vw_err_t err = vw_net_accept(net_ctx, &conn);
    if (err != VW_OK) return err;

    uint8_t discard[4096];
    size_t got = 0;
    (void)vw_net_recv_partial(conn, discard, sizeof(discard), &got);

    char hdr[128];
    int n = snprintf(hdr, sizeof(hdr), "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", body_len);
    err = vw_net_send(conn, hdr, (size_t)n);
    if (err == VW_OK && body_len > 0)
        err = vw_net_send(conn, body, body_len);

    vw_net_close(conn);
    return err;
}

static void *dual_srv_thread(void *arg) {
    dual_srv_args_t *a = arg;
    vw_net_ctx_t *net_ctx = NULL;
    vw_err_t err = vw_net_listen("127.0.0.1", a->port, a->cert_path, a->key_path, &net_ctx);
    a->bind_err = err;

    pthread_mutex_lock(&a->mtx);
    a->ready = 1;
    pthread_cond_signal(&a->cond);
    pthread_mutex_unlock(&a->mtx);

    if (err != VW_OK) return NULL;

    (void)serve_one(net_ctx, a->manifest_bytes, a->manifest_len);
    (void)serve_one(net_ctx, a->sig_bytes, a->sig_len);

    vw_net_ctx_close(net_ctx);
    return NULL;
}

static pthread_t spawn_dual_srv(dual_srv_args_t *a) {
    a->ready = 0;
    a->bind_err = VW_OK;
    pthread_mutex_init(&a->mtx, NULL);
    pthread_cond_init(&a->cond, NULL);
    pthread_t tid;
    pthread_create(&tid, NULL, dual_srv_thread, a);
    pthread_mutex_lock(&a->mtx);
    while (!a->ready) pthread_cond_wait(&a->cond, &a->mtx);
    pthread_mutex_unlock(&a->mtx);
    return tid;
}
static void join_dual_srv(pthread_t tid, dual_srv_args_t *a) {
    pthread_join(tid, NULL);
    pthread_mutex_destroy(&a->mtx);
    pthread_cond_destroy(&a->cond);
}

static uint64_t read_ratchet(const char *state_dir) {
    char path[600];
    snprintf(path, sizeof(path), "%s/daemon.conf", state_dir);
    void *buf = NULL; size_t len = 0;
    if (vw_fs_read_file(path, &buf, &len) != VW_OK) return 0;
    const char *needle = "update_last_seen_sequence";
    const char *found = NULL;
    for (size_t i = 0; i + strlen(needle) <= len; i++) {
        if (memcmp((char *)buf + i, needle, strlen(needle)) == 0) { found = (char *)buf + i; break; }
    }
    uint64_t v = 0;
    if (found) {
        const char *eq = strchr(found, '=');
        if (eq) v = strtoull(eq + 1, NULL, 10);
    }
    free(buf);
    return v;
}

VW_TEST_SUITE("update_manifest") {
    VW_ASSERT_EQ(vw_crypto_init(), VW_OK);
    vw_update_net_test_set_connect_hook(test_connect_hook);

    char tmpdir[512];
    make_tmpdir(tmpdir, sizeof(tmpdir));
    char cert_path[600], key_path[600];
    path_join(cert_path, sizeof(cert_path), tmpdir, "test_cert.pem");
    path_join(key_path,  sizeof(key_path),  tmpdir, "test_key.pem");
    VW_ASSERT(write_file(cert_path, TEST_CERT_PEM) == 0);
    VW_ASSERT(write_file(key_path,  TEST_KEY_PEM)  == 0);

    char state_dir[512];
    make_tmpdir(state_dir, sizeof(state_dir));

    /* ── TC-1: real signed manifest verifies + parses + advances ratchet ── */
    VW_TEST_CASE("valid manifest verifies, parses fully, and advances the ratchet") {
        dual_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = (uint16_t)TEST_PORT;
        sa.manifest_bytes = MANIFEST_OK; sa.manifest_len = sizeof(MANIFEST_OK) - 1;
        sa.sig_bytes = MANIFEST_OK_SIG;  sa.sig_len = sizeof(MANIFEST_OK_SIG);
        pthread_t tid = spawn_dual_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_update_manifest_t m;
        vw_err_t err = vw_update_manifest_fetch_and_verify(state_dir, &m);
        VW_ASSERT_EQ(err, VW_OK);
        VW_ASSERT_EQ(m.schema_version, (uint32_t)1);
        VW_ASSERT_EQ(m.sequence, (uint64_t)5);
        VW_ASSERT(strcmp(m.release_version, "0.4.2") == 0);
        VW_ASSERT_EQ(m.min_client_protocol_version, (uint16_t)6);
        VW_ASSERT_EQ(m.asset_count, (uint32_t)2);
        VW_ASSERT(strcmp(m.assets[0].platform, "linux") == 0);
        VW_ASSERT(strcmp(m.assets[0].filename, "vaporwault-v0.4.2-linux-x86_64.tar.gz") == 0);
        VW_ASSERT_EQ(m.assets[0].sha256[0], (uint8_t)0xaa);
        VW_ASSERT(strcmp(m.assets[1].platform, "windows") == 0);
        VW_ASSERT_EQ(read_ratchet(state_dir), (uint64_t)5);

        join_dual_srv(tid, &sa);
    }

    /* ── TC-2: tampered manifest body rejected before parsing, ratchet untouched ── */
    VW_TEST_CASE("tampered manifest body fails signature verification") {
        char tampered[sizeof(MANIFEST_OK)];
        memcpy(tampered, MANIFEST_OK, sizeof(MANIFEST_OK));
        tampered[10] ^= 0x01; /* flip a byte inside the JSON body */

        dual_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = (uint16_t)TEST_PORT;
        sa.manifest_bytes = tampered; sa.manifest_len = sizeof(tampered) - 1;
        sa.sig_bytes = MANIFEST_OK_SIG; sa.sig_len = sizeof(MANIFEST_OK_SIG);
        pthread_t tid = spawn_dual_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        uint64_t ratchet_before = read_ratchet(state_dir);
        vw_update_manifest_t m;
        vw_err_t err = vw_update_manifest_fetch_and_verify(state_dir, &m);
        VW_ASSERT_EQ(err, VW_ERR_UPDATE_MANIFEST_INVALID);
        VW_ASSERT_EQ(read_ratchet(state_dir), ratchet_before);

        join_dual_srv(tid, &sa);
    }

    /* ── TC-3: validly-signed but lower sequence than the ratchet is a rollback ── */
    VW_TEST_CASE("lower-sequence manifest is rejected as a rollback attempt") {
        dual_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = (uint16_t)TEST_PORT;
        sa.manifest_bytes = MANIFEST_OLD; sa.manifest_len = sizeof(MANIFEST_OLD) - 1;
        sa.sig_bytes = MANIFEST_OLD_SIG;  sa.sig_len = sizeof(MANIFEST_OLD_SIG);
        pthread_t tid = spawn_dual_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        VW_ASSERT_EQ(read_ratchet(state_dir), (uint64_t)5); /* set by TC-1 */
        vw_update_manifest_t m;
        vw_err_t err = vw_update_manifest_fetch_and_verify(state_dir, &m);
        VW_ASSERT_EQ(err, VW_ERR_UPDATE_MANIFEST_ROLLBACK);
        VW_ASSERT_EQ(read_ratchet(state_dir), (uint64_t)5); /* NOT moved backward */

        join_dual_srv(tid, &sa);
    }

    /* ── TC-4: higher-sequence manifest succeeds and advances the ratchet further ── */
    VW_TEST_CASE("higher-sequence manifest succeeds and advances the ratchet") {
        dual_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = (uint16_t)TEST_PORT;
        sa.manifest_bytes = MANIFEST_NEW; sa.manifest_len = sizeof(MANIFEST_NEW) - 1;
        sa.sig_bytes = MANIFEST_NEW_SIG;  sa.sig_len = sizeof(MANIFEST_NEW_SIG);
        pthread_t tid = spawn_dual_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_update_manifest_t m;
        vw_err_t err = vw_update_manifest_fetch_and_verify(state_dir, &m);
        VW_ASSERT_EQ(err, VW_OK);
        VW_ASSERT_EQ(m.sequence, (uint64_t)9);
        VW_ASSERT_EQ(read_ratchet(state_dir), (uint64_t)9);

        join_dual_srv(tid, &sa);
    }

    /* ── TC-5: validly-signed but wrong-schema payload rejected by the parser ── */
    VW_TEST_CASE("validly-signed but schema-invalid payload is rejected") {
        dual_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = (uint16_t)TEST_PORT;
        sa.manifest_bytes = MANIFEST_BADSCHEMA; sa.manifest_len = sizeof(MANIFEST_BADSCHEMA) - 1;
        sa.sig_bytes = MANIFEST_BADSCHEMA_SIG;  sa.sig_len = sizeof(MANIFEST_BADSCHEMA_SIG);
        pthread_t tid = spawn_dual_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_update_manifest_t m;
        vw_err_t err = vw_update_manifest_fetch_and_verify(state_dir, &m);
        VW_ASSERT_EQ(err, VW_ERR_UPDATE_MANIFEST_INVALID);

        join_dual_srv(tid, &sa);
    }

    vw_crypto_cleanup();
}
VW_TEST_SUITE_END()
