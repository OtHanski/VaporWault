/*
 * test_proto_recv_drain.c — regression test for TASK-155.
 *
 * vw_proto_recv used to return VW_ERR_PROTO_TOO_LARGE (the caller's buffer
 * is too small for the incoming message) WITHOUT draining the payload
 * bytes off the socket. Those bytes stayed queued on the connection, and
 * the *next* vw_proto_recv call on that same connection read them as if
 * they were the start of a brand-new message header — a permanent desync.
 *
 * This is exactly the shape of bug that any single-call unit test would
 * miss: it only shows up across TWO successive calls on the SAME live
 * connection, so it needs a real socket pair, not encode/decode-only
 * testing (see test_vw_proto.c's own header comment on why vw_proto_send/
 * vw_proto_recv are exercised here instead).
 *
 * TC-1: server sends a message whose payload is larger than the client's
 *       receive buffer (mirroring vw_client_file_move's real 4-byte ACK
 *       buffer receiving the server's 6-byte generic VW_MSG_ERROR, the
 *       exact trigger TASK-155 was filed from), then a second, small,
 *       distinguishable message. The client's first vw_proto_recv must
 *       return VW_ERR_PROTO_TOO_LARGE; its SECOND call, on the same
 *       connection, must correctly receive the second message — not a
 *       bogus header decoded from the first message's undrained tail.
 * TC-2: same shape, but the caller's buffer is undersized by just one
 *       byte (an off-by-one boundary check on the drain path).
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

/* Same embedded self-signed test cert used by test_auth_handshake.c. */
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

#define TEST_PORT 43733u

static void make_tmpdir(char *out, size_t sz) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_protodrain_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_protodrain_%u", VW_PID());
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

/* ── Server-side thread: sends two fixed messages, then closes ─────────── */

typedef struct {
    const char *cert_path;
    const char *key_path;
    uint16_t    port;

    const void *msg1_payload;
    uint32_t    msg1_len;
    const void *msg2_payload;
    uint32_t    msg2_len;

    pthread_mutex_t mtx;
    pthread_cond_t  cond;
    int             ready;
    vw_err_t        bind_err;
    vw_err_t        send_err;
} sender_args_t;

static void *sender_thread(void *arg) {
    sender_args_t *a = arg;

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
    if (err != VW_OK) { a->send_err = err; vw_net_ctx_close(net_ctx); return NULL; }

    err = vw_proto_send(conn, VW_MSG_ERROR, a->msg1_payload, a->msg1_len);
    if (err == VW_OK) {
        err = vw_proto_send(conn, VW_MSG_KEEPALIVE, a->msg2_payload, a->msg2_len);
    }
    a->send_err = err;

    vw_net_close(conn);
    vw_net_ctx_close(net_ctx);
    return NULL;
}

static pthread_t spawn_sender(sender_args_t *a) {
    a->ready = 0;
    a->bind_err = VW_OK;
    a->send_err = VW_OK;
    pthread_mutex_init(&a->mtx, NULL);
    pthread_cond_init(&a->cond, NULL);

    pthread_t tid;
    pthread_create(&tid, NULL, sender_thread, a);

    pthread_mutex_lock(&a->mtx);
    while (!a->ready) pthread_cond_wait(&a->cond, &a->mtx);
    pthread_mutex_unlock(&a->mtx);
    return tid;
}

static void join_sender(pthread_t tid, sender_args_t *a) {
    pthread_join(tid, NULL);
    pthread_mutex_destroy(&a->mtx);
    pthread_cond_destroy(&a->cond);
}

VW_TEST_SUITE("proto_recv_drain") {

    VW_ASSERT_EQ(vw_crypto_init(), VW_OK);

    char tmpdir[512];
    make_tmpdir(tmpdir, sizeof(tmpdir));
    /* 600, not 520: tmpdir is a char[512], so GCC's Release-mode
     * -Wformat-truncation can (correctly) see that path_join's "%s/%s"
     * could in the worst case need 512 + "/" + filename + NUL, which
     * exceeds 520 for either filename here. */
    char cert_path[600], key_path[600];
    path_join(cert_path, sizeof(cert_path), tmpdir, "test_cert.pem");
    path_join(key_path,  sizeof(key_path),  tmpdir, "test_key.pem");
    VW_ASSERT(write_file(cert_path, TEST_CERT_PEM) == 0);
    VW_ASSERT(write_file(key_path,  TEST_KEY_PEM)  == 0);

    /* ── TC-1: 6-byte payload into a 4-byte buffer (the real-world shape:
     * VW_MSG_ERROR's minimum 6-byte encoding, vw_client_file_move's real
     * 4-byte rbuf), then a second, distinguishable 4-byte message on the
     * same connection ──────────────────────────────────────────────── */
    VW_TEST_CASE("TOO_LARGE drains payload; next recv on same conn is not desynced") {
        static const uint8_t msg1[6] = { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
        static const uint8_t msg2[4] = { 0x11, 0x22, 0x33, 0x44 };

        sender_args_t sa;
        sa.cert_path = cert_path;
        sa.key_path  = key_path;
        sa.port      = (uint16_t)TEST_PORT;
        sa.msg1_payload = msg1; sa.msg1_len = sizeof(msg1);
        sa.msg2_payload = msg2; sa.msg2_len = sizeof(msg2);
        pthread_t tid = spawn_sender(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_conn_t *conn = NULL;
        VW_ASSERT_EQ(vw_net_connect("127.0.0.1", (uint16_t)TEST_PORT,
                                     VW_CERT_VERIFY_NONE, NULL, NULL, &conn), VW_OK);

        vw_msg_type_t type;
        uint32_t plen;
        uint8_t small_buf[4]; /* mirrors vw_client_file_move's real rbuf[4] */

        vw_err_t err = vw_proto_recv(conn, &type, small_buf, sizeof(small_buf), &plen);
        VW_ASSERT_EQ(err, VW_ERR_PROTO_TOO_LARGE);

        /* The bug: without draining, this second call would read msg1's
         * undrained tail bytes as a bogus header instead of msg2's real
         * one - either a decode error or (worse) garbage type/length. */
        uint8_t buf2[64];
        err = vw_proto_recv(conn, &type, buf2, sizeof(buf2), &plen);
        VW_ASSERT_EQ(err, VW_OK);
        VW_ASSERT_EQ((int)type, (int)VW_MSG_KEEPALIVE);
        VW_ASSERT_EQ(plen, sizeof(msg2));
        VW_ASSERT(memcmp(buf2, msg2, sizeof(msg2)) == 0);

        vw_net_close(conn);
        join_sender(tid, &sa);
        VW_ASSERT_EQ(sa.send_err, VW_OK);
    }

    /* ── TC-2: off-by-one - payload is exactly buf_size+1 ────────────────── */
    VW_TEST_CASE("off-by-one undersized buffer also drains correctly") {
        static const uint8_t msg1[5] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        static const uint8_t msg2[3] = { 0x99, 0x98, 0x97 };

        sender_args_t sa;
        sa.cert_path = cert_path;
        sa.key_path  = key_path;
        sa.port      = (uint16_t)(TEST_PORT + 1);
        sa.msg1_payload = msg1; sa.msg1_len = sizeof(msg1);
        sa.msg2_payload = msg2; sa.msg2_len = sizeof(msg2);
        pthread_t tid = spawn_sender(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_conn_t *conn = NULL;
        VW_ASSERT_EQ(vw_net_connect("127.0.0.1", (uint16_t)(TEST_PORT + 1),
                                     VW_CERT_VERIFY_NONE, NULL, NULL, &conn), VW_OK);

        vw_msg_type_t type;
        uint32_t plen;
        uint8_t tiny_buf[4]; /* exactly one byte short of msg1's 5-byte payload */

        vw_err_t err = vw_proto_recv(conn, &type, tiny_buf, sizeof(tiny_buf), &plen);
        VW_ASSERT_EQ(err, VW_ERR_PROTO_TOO_LARGE);

        uint8_t buf2[64];
        err = vw_proto_recv(conn, &type, buf2, sizeof(buf2), &plen);
        VW_ASSERT_EQ(err, VW_OK);
        VW_ASSERT_EQ((int)type, (int)VW_MSG_KEEPALIVE);
        VW_ASSERT_EQ(plen, sizeof(msg2));
        VW_ASSERT(memcmp(buf2, msg2, sizeof(msg2)) == 0);

        vw_net_close(conn);
        join_sender(tid, &sa);
        VW_ASSERT_EQ(sa.send_err, VW_OK);
    }

    vw_crypto_cleanup();
}
VW_TEST_SUITE_END()
