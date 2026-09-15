/*
 * test_proto_update_hint.c — integration test for TASK-00292.
 *
 * vw_proto_negotiate() now carries an optional server-version "update hint"
 * as a trailing block on HELLO_OK/VERSION_REJECT. Like vw_proto_recv's
 * TASK-155 desync bug, this needs a real live connection (not just
 * encode/decode round-trips) to prove: (a) a real server->client exchange
 * actually surfaces the hint, (b) the hint survives the hard-rejection path
 * even though vw_client_sess_t doesn't exist yet at that point in a real
 * client caller, and (c) a hand-crafted "old" peer (one that never sends the
 * extension at all, standing in for a pre-TASK-00292 binary since we can't
 * literally recompile one here) is unaffected.
 *
 * TC-1: real server (with a server_version to advertise) <-> real client:
 *       HELLO_OK path, out_hint.present == 1, correct string.
 * TC-2: real server with NO server_version to advertise (NULL) <-> real
 *       client: HELLO_OK path, out_hint.present == 0 — default/legacy shape
 *       unaffected when nothing is configured to advertise.
 * TC-3: hand-crafted "old" client (bare 2-byte HELLO, mirrors the exact
 *       wire shape of a pre-TASK-00292 binary) talking to a real server
 *       whose only supported version is set artificially high so it must
 *       reject — verifies the server's VERSION_REJECT-with-hint encode path
 *       against a raw receiver (an old client would ignore the trailing
 *       bytes; here we inspect them directly to prove they're well-formed).
 * TC-4: hand-crafted server sends a manually-built VERSION_REJECT carrying
 *       the hint block, real client calls vw_proto_negotiate() — verifies
 *       VW_ERR_PROTO_VERSION is returned AND out_hint is populated, i.e.
 *       the hint really does survive the reject path through the real
 *       client-side decode logic, not just in theory.
 * TC-5: malformed/truncated extension (declared version_len exceeds what's
 *       actually in the payload) — must not crash, must yield
 *       out_hint.present == 0 rather than propagating a decode error over a
 *       cosmetic hint.
 */

#include "vw_test.h"
#include "vw_proto.h"
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
#endif

#include <string.h>
#include <stdio.h>

#ifdef _WIN32
#  include <process.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <unistd.h>
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

#define TEST_PORT 43744u

static void make_tmpdir(char *out, size_t sz) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_updatehint_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_updatehint_%u", VW_PID());
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

/* ── Server thread: runs the real server-side vw_proto_negotiate() ─────── */

typedef struct {
    const char *cert_path;
    const char *key_path;
    uint16_t    port;
    const char *server_version; /* may be NULL */

    pthread_mutex_t mtx;
    pthread_cond_t  cond;
    int             ready;
    vw_err_t        bind_err;
    vw_err_t        negotiate_err;
} real_server_args_t;

static void *real_server_thread(void *arg) {
    real_server_args_t *a = arg;

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
    if (err != VW_OK) { a->negotiate_err = err; vw_net_ctx_close(net_ctx); return NULL; }

    uint16_t version;
    a->negotiate_err = vw_proto_negotiate(conn, 1 /*is_server*/, &version,
                                           a->server_version, NULL);

    vw_net_close(conn);
    vw_net_ctx_close(net_ctx);
    return NULL;
}

static pthread_t spawn_real_server(real_server_args_t *a) {
    a->ready = 0;
    a->bind_err = VW_OK;
    a->negotiate_err = VW_OK;
    pthread_mutex_init(&a->mtx, NULL);
    pthread_cond_init(&a->cond, NULL);

    pthread_t tid;
    pthread_create(&tid, NULL, real_server_thread, a);

    pthread_mutex_lock(&a->mtx);
    while (!a->ready) pthread_cond_wait(&a->cond, &a->mtx);
    pthread_mutex_unlock(&a->mtx);
    return tid;
}

static void join_real_server(pthread_t tid, real_server_args_t *a) {
    pthread_join(tid, NULL);
    pthread_mutex_destroy(&a->mtx);
    pthread_cond_destroy(&a->cond);
}

/* ── Raw sender thread: sends caller-supplied bytes verbatim (stands in
 * for either an "old" peer that never sends the extension, or a
 * hand-crafted message shape a real vw_proto_negotiate() caller never
 * itself constructs) ────────────────────────────────────────────────── */

typedef struct {
    const char *cert_path;
    const char *key_path;
    uint16_t    port;
    int         act_as_server; /* 1: vw_net_listen/accept; 0: vw_net_connect */

    vw_msg_type_t send_type;
    const void   *send_payload;
    uint32_t      send_len;

    /* if act_as_server: what we received first (the peer's HELLO) is
     * discarded — we just send send_type/send_payload unconditionally,
     * mirroring how vw_proto_negotiate's real server branch always reads
     * HELLO before replying. */

    pthread_mutex_t mtx;
    pthread_cond_t  cond;
    int             ready;
    vw_err_t        err;
} raw_peer_args_t;

static void *raw_peer_thread(void *arg) {
    raw_peer_args_t *a = arg;
    vw_conn_t *conn = NULL;
    vw_net_ctx_t *net_ctx = NULL;

    if (a->act_as_server) {
        vw_err_t err = vw_net_listen("127.0.0.1", a->port, a->cert_path, a->key_path, &net_ctx);
        a->err = err;
        pthread_mutex_lock(&a->mtx); a->ready = 1; pthread_cond_signal(&a->cond); pthread_mutex_unlock(&a->mtx);
        if (err != VW_OK) return NULL;

        err = vw_net_accept(net_ctx, &conn);
        if (err != VW_OK) { a->err = err; vw_net_ctx_close(net_ctx); return NULL; }

        /* discard the peer's HELLO */
        vw_msg_type_t t; uint8_t discard[64]; uint32_t plen;
        (void)vw_proto_recv(conn, &t, discard, sizeof(discard), &plen);

        a->err = vw_proto_send(conn, a->send_type, a->send_payload, a->send_len);
        vw_net_close(conn);
        vw_net_ctx_close(net_ctx);
    } else {
        pthread_mutex_lock(&a->mtx); a->ready = 1; pthread_cond_signal(&a->cond); pthread_mutex_unlock(&a->mtx);
        vw_err_t err = vw_net_connect("127.0.0.1", a->port, VW_CERT_VERIFY_NONE, NULL, NULL, &conn);
        if (err != VW_OK) { a->err = err; return NULL; }

        a->err = vw_proto_send(conn, a->send_type, a->send_payload, a->send_len);
        vw_net_close(conn);
    }
    return NULL;
}

static pthread_t spawn_raw_peer(raw_peer_args_t *a) {
    a->ready = 0;
    a->err = VW_OK;
    pthread_mutex_init(&a->mtx, NULL);
    pthread_cond_init(&a->cond, NULL);

    pthread_t tid;
    pthread_create(&tid, NULL, raw_peer_thread, a);

    pthread_mutex_lock(&a->mtx);
    while (!a->ready) pthread_cond_wait(&a->cond, &a->mtx);
    pthread_mutex_unlock(&a->mtx);
    return tid;
}

static void join_raw_peer(pthread_t tid, raw_peer_args_t *a) {
    pthread_join(tid, NULL);
    pthread_mutex_destroy(&a->mtx);
    pthread_cond_destroy(&a->cond);
}

VW_TEST_SUITE("proto_update_hint") {

    VW_ASSERT_EQ(vw_crypto_init(), VW_OK);

    char tmpdir[512];
    make_tmpdir(tmpdir, sizeof(tmpdir));
    char cert_path[600], key_path[600];
    path_join(cert_path, sizeof(cert_path), tmpdir, "test_cert.pem");
    path_join(key_path,  sizeof(key_path),  tmpdir, "test_key.pem");
    VW_ASSERT(write_file(cert_path, TEST_CERT_PEM) == 0);
    VW_ASSERT(write_file(key_path,  TEST_KEY_PEM)  == 0);

    /* ── TC-1: real server advertises a version, real client sees it ──── */
    VW_TEST_CASE("real HELLO_OK carries server_version to a real client") {
        real_server_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path;
        sa.port = (uint16_t)TEST_PORT;
        sa.server_version = "0.4.2";
        pthread_t tid = spawn_real_server(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_conn_t *conn = NULL;
        VW_ASSERT_EQ(vw_net_connect("127.0.0.1", (uint16_t)TEST_PORT,
                                     VW_CERT_VERIFY_NONE, NULL, NULL, &conn), VW_OK);

        uint16_t version;
        vw_proto_update_hint_t hint;
        memset(&hint, 0xAA, sizeof(hint)); /* poison — negotiate must fully set present/string */
        vw_err_t err = vw_proto_negotiate(conn, 0, &version, NULL, &hint);
        VW_ASSERT_EQ(err, VW_OK);
        VW_ASSERT_EQ(version, VW_PROTO_VERSION_CURRENT);
        VW_ASSERT_EQ(hint.present, 1);
        VW_ASSERT(strcmp(hint.server_version, "0.4.2") == 0);

        vw_net_close(conn);
        join_real_server(tid, &sa);
        VW_ASSERT_EQ(sa.negotiate_err, VW_OK);
    }

    /* ── TC-2: real server with nothing to advertise → hint absent ─────── */
    VW_TEST_CASE("real HELLO_OK with no server_version → hint absent, same as before TASK-00292") {
        real_server_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path;
        sa.port = (uint16_t)(TEST_PORT + 1);
        sa.server_version = NULL;
        pthread_t tid = spawn_real_server(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_conn_t *conn = NULL;
        VW_ASSERT_EQ(vw_net_connect("127.0.0.1", (uint16_t)(TEST_PORT + 1),
                                     VW_CERT_VERIFY_NONE, NULL, NULL, &conn), VW_OK);

        uint16_t version;
        vw_proto_update_hint_t hint;
        vw_err_t err = vw_proto_negotiate(conn, 0, &version, NULL, &hint);
        VW_ASSERT_EQ(err, VW_OK);
        VW_ASSERT_EQ(hint.present, 0);
        VW_ASSERT_EQ(hint.server_version[0], '\0');

        vw_net_close(conn);
        join_real_server(tid, &sa);
        VW_ASSERT_EQ(sa.negotiate_err, VW_OK);
    }

    /* ── TC-3: hand-crafted "old" client (bare 2-byte HELLO offering a
     * version below VW_PROTO_VERSION_CURRENT) hits the real server's
     * reject path with a server_version configured; inspect the raw
     * VERSION_REJECT bytes it gets back ─────────────────────────────── */
    VW_TEST_CASE("real server's VERSION_REJECT-with-hint is well-formed on the wire") {
        real_server_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path;
        sa.port = (uint16_t)(TEST_PORT + 2);
        sa.server_version = "9.9.9";
        pthread_t tid = spawn_real_server(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_conn_t *conn = NULL;
        VW_ASSERT_EQ(vw_net_connect("127.0.0.1", (uint16_t)(TEST_PORT + 2),
                                     VW_CERT_VERIFY_NONE, NULL, NULL, &conn), VW_OK);

        /* Old-shaped HELLO: max_version = 1 (well below VW_PROTO_VERSION_CURRENT) */
        uint8_t hello[2];
        hello[0] = 1; hello[1] = 0;
        VW_ASSERT_EQ(vw_proto_send(conn, VW_MSG_HELLO, hello, sizeof(hello)), VW_OK);

        vw_msg_type_t type;
        uint8_t buf[128];
        uint32_t plen;
        VW_ASSERT_EQ(vw_proto_recv(conn, &type, buf, sizeof(buf), &plen), VW_OK);
        VW_ASSERT_EQ((int)type, (int)VW_MSG_VERSION_REJECT);
        VW_ASSERT(plen > 4u); /* extension present beyond the fixed min/max fields */

        uint16_t min_v = (uint16_t)(buf[0] | (buf[1] << 8));
        uint16_t max_v = (uint16_t)(buf[2] | (buf[3] << 8));
        VW_ASSERT_EQ(min_v, VW_PROTO_VERSION_CURRENT);
        VW_ASSERT_EQ(max_v, VW_PROTO_VERSION_CURRENT);
        VW_ASSERT_EQ(buf[4], (uint8_t)VW_UPDATE_EXT_VERSION_1);
        uint8_t vlen = buf[5];
        VW_ASSERT_EQ(vlen, (uint8_t)5); /* strlen("9.9.9") */
        VW_ASSERT(memcmp(buf + 6, "9.9.9", 5) == 0);
        VW_ASSERT_EQ(plen, (uint32_t)(6 + 5));

        vw_net_close(conn);
        join_real_server(tid, &sa);
        VW_ASSERT_EQ(sa.negotiate_err, VW_ERR_PROTO_VERSION);
    }

    /* ── TC-4: hand-crafted VERSION_REJECT-with-hint, real client decode ─ */
    VW_TEST_CASE("real client negotiate() surfaces the hint on the reject path") {
        uint8_t reject[4 + 2 + 5];
        reject[0] = (uint8_t)(VW_PROTO_VERSION_CURRENT & 0xFF);
        reject[1] = (uint8_t)(VW_PROTO_VERSION_CURRENT >> 8);
        reject[2] = reject[0];
        reject[3] = reject[1];
        reject[4] = (uint8_t)VW_UPDATE_EXT_VERSION_1;
        reject[5] = 5;
        memcpy(reject + 6, "7.7.7", 5);

        raw_peer_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path;
        sa.port = (uint16_t)(TEST_PORT + 3);
        sa.act_as_server = 1;
        sa.send_type = VW_MSG_VERSION_REJECT;
        sa.send_payload = reject;
        sa.send_len = sizeof(reject);
        pthread_t tid = spawn_raw_peer(&sa);

        vw_conn_t *conn = NULL;
        VW_ASSERT_EQ(vw_net_connect("127.0.0.1", (uint16_t)(TEST_PORT + 3),
                                     VW_CERT_VERIFY_NONE, NULL, NULL, &conn), VW_OK);

        uint16_t version;
        vw_proto_update_hint_t hint;
        memset(&hint, 0xAA, sizeof(hint));
        vw_err_t err = vw_proto_negotiate(conn, 0, &version, NULL, &hint);
        VW_ASSERT_EQ(err, VW_ERR_PROTO_VERSION);
        VW_ASSERT_EQ(hint.present, 1);
        VW_ASSERT(strcmp(hint.server_version, "7.7.7") == 0);

        vw_net_close(conn);
        join_raw_peer(tid, &sa);
        VW_ASSERT_EQ(sa.err, VW_OK);
    }

    /* ── TC-5: truncated extension → hint absent, no crash, no decode error
     * propagated (the underlying negotiate result must still be VW_OK for
     * a HELLO_OK carrying a truncated extension — the cosmetic hint being
     * malformed must never fail an otherwise-valid handshake) ─────────── */
    VW_TEST_CASE("truncated update-hint extension is treated as absent, not fatal") {
        /* HELLO_OK: negotiated_version(2) + server_id(16) + update_ext_ver(1)
         * + server_version_len(1)=20 (claims 20 bytes) but payload actually
         * ends right after the length byte — 0 bytes of string follow. */
        uint8_t bad[18 + 2];
        vw_write_u16le(bad, VW_PROTO_VERSION_CURRENT);
        memset(bad + 2, 0, 16);
        bad[18] = (uint8_t)VW_UPDATE_EXT_VERSION_1;
        bad[19] = 20; /* claims 20 bytes of server_version that aren't there */

        raw_peer_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path;
        sa.port = (uint16_t)(TEST_PORT + 4);
        sa.act_as_server = 1;
        sa.send_type = VW_MSG_HELLO_OK;
        sa.send_payload = bad;
        sa.send_len = sizeof(bad);
        pthread_t tid = spawn_raw_peer(&sa);

        vw_conn_t *conn = NULL;
        VW_ASSERT_EQ(vw_net_connect("127.0.0.1", (uint16_t)(TEST_PORT + 4),
                                     VW_CERT_VERIFY_NONE, NULL, NULL, &conn), VW_OK);

        uint16_t version;
        vw_proto_update_hint_t hint;
        vw_err_t err = vw_proto_negotiate(conn, 0, &version, NULL, &hint);
        VW_ASSERT_EQ(err, VW_OK); /* the handshake itself is still valid */
        VW_ASSERT_EQ(version, VW_PROTO_VERSION_CURRENT);
        VW_ASSERT_EQ(hint.present, 0);

        vw_net_close(conn);
        join_raw_peer(tid, &sa);
        VW_ASSERT_EQ(sa.err, VW_OK);
    }

    vw_crypto_cleanup();
}
VW_TEST_SUITE_END()
