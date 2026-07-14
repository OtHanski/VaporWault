/*
 * test_vw_net.c — unit tests for the vw_net TLS socket module.
 *
 * TC-1: TLS loopback — 1 KiB echo; byte-exact round trip.
 * TC-2: ALPN — negotiated protocol on the client side is "vw/1".
 * TC-3: Cert reload — new connections succeed after vw_net_ctx_reload_cert.
 * TC-4: Rate limiter — upload_bps throttles to ≥50% of target speed (CI-safe).
 * TC-5: VERIFY_REQUIRED + NULL ca_cert_path → VW_ERR_INVALID_ARG (no network).
 * TC-6: Connect to closed port → error (any non-VW_OK code).
 * TC-7: vw_net_peer_addr returns a non-empty IPv4 string.
 *
 * The server side of each networked test runs on a detached pthread.  The
 * embedded self-signed EC P-256 test certificate (same as test_auth_handshake.c)
 * is written to a per-process temp directory at startup.
 *
 * Port assignments (no collision with test_auth_handshake which uses 43721):
 *   43722 — TC-1, TC-2, TC-7   (shared loopback connection)
 *   43723 — TC-3               (cert reload)
 *   43724 — TC-4               (rate limiter)
 */

#include "vw_test.h"
#include "vw_net.h"
#include "vw_proto.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  include <windows.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <dirent.h>
#  include <sys/stat.h>
#  include <unistd.h>
#  define VW_PID() ((unsigned)getpid())
#endif

/* ── Constants ───────────────────────────────────────────────────────────── */

#define LOOPBACK_BYTES  1024u
#define RATE_BPS        (50u * 1024u)   /* 50 KB/s target rate         */
#define RATE_DATA_BYTES (100u * 1024u)  /* 100 KB → ~2 s at 50 KB/s    */
#define RATE_MIN_MS     1000u           /* lower bound: 50% of expected */

/* ── Monotonic millisecond clock ─────────────────────────────────────────── */

static uint64_t ms_now(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
#endif
}

/* ── Embedded self-signed EC P-256 test cert ─────────────────────────────── */
/* Same cert as tests/integration/test_auth_handshake.c.  CN=VaporWault Test,
 * self-signed, 10-year validity starting 2026-07-07. */

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

/* ── Temp-dir helpers ────────────────────────────────────────────────────── */

static char g_tmpdir[512];

static void make_tmpdir(char *out, size_t sz) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_nettest_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_nettest_%u", VW_PID());
    mkdir(out, 0700);
#endif
}

static void rm_rf(const char *dir) {
#ifdef _WIN32
    char pat[MAX_PATH];
    snprintf(pat, sizeof(pat), "%s\\*", dir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (strcmp(fd.cFileName, ".") && strcmp(fd.cFileName, "..")) {
                char child[MAX_PATH];
                snprintf(child, sizeof(child), "%s\\%s", dir, fd.cFileName);
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) rm_rf(child);
                else DeleteFileA(child);
            }
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryA(dir);
#else
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        char child[512];
        snprintf(child, sizeof(child), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(child, &st) == 0 && S_ISDIR(st.st_mode)) rm_rf(child);
        else remove(child);
    }
    closedir(d);
    rmdir(dir);
#endif
}

static int write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = strlen(text);
    int ok = (fwrite(text, 1, n, f) == n);
    fclose(f);
    return ok ? 0 : -1;
}

/* ── Generic echo-server thread ──────────────────────────────────────────── */

/*
 * Accepts n_accept connections sequentially. For each connection:
 *   - recv xfer_bytes bytes from the client
 *   - echo them back
 *   - close the connection
 * If ctx_out is non-NULL, the server context pointer is stored there so the
 * main thread can call vw_net_ctx_reload_cert() concurrently.
 */
typedef struct {
    const char      *cert_path;
    const char      *key_path;
    uint16_t         port;
    int              n_accept;
    size_t           xfer_bytes;    /* per connection: recv then echo */
    vw_net_ctx_t   **ctx_out;       /* optional: expose ctx to main thread */

    pthread_mutex_t  mtx;
    pthread_cond_t   cond;
    int              ready;         /* listen succeeded */
    int              done;          /* all n_accept connections handled */
    vw_err_t         err;           /* error from vw_net_listen */
} srv_t;

static void *srv_run(void *arg) {
    srv_t *s = arg;
    vw_net_ctx_t *ctx = NULL;

    vw_err_t err = vw_net_listen("127.0.0.1", s->port,
                                   s->cert_path, s->key_path, &ctx);

    pthread_mutex_lock(&s->mtx);
    s->err = err;
    if (s->ctx_out) *s->ctx_out = ctx;
    s->ready = 1;
    pthread_cond_signal(&s->cond);
    pthread_mutex_unlock(&s->mtx);

    if (err != VW_OK) return NULL;

    for (int i = 0; i < s->n_accept; i++) {
        vw_conn_t *conn = NULL;
        if (vw_net_accept(ctx, &conn) != VW_OK) break;

        if (s->xfer_bytes > 0) {
            uint8_t *buf = malloc(s->xfer_bytes);
            if (buf) {
                vw_net_recv(conn, buf, s->xfer_bytes);
                vw_net_send(conn, buf, s->xfer_bytes);
                free(buf);
            }
        }
        vw_net_close(conn);
    }

    vw_net_ctx_close(ctx);
    if (s->ctx_out) *s->ctx_out = NULL;

    pthread_mutex_lock(&s->mtx);
    s->done = 1;
    pthread_cond_signal(&s->cond);
    pthread_mutex_unlock(&s->mtx);
    return NULL;
}

static pthread_t srv_start(srv_t *s) {
    pthread_mutex_init(&s->mtx, NULL);
    pthread_cond_init(&s->cond, NULL);
    s->ready = 0; s->done = 0; s->err = VW_OK;
    pthread_t tid;
    pthread_create(&tid, NULL, srv_run, s);

    pthread_mutex_lock(&s->mtx);
    while (!s->ready) pthread_cond_wait(&s->cond, &s->mtx);
    pthread_mutex_unlock(&s->mtx);
    return tid;
}

static void srv_join(srv_t *s, pthread_t tid) {
    pthread_mutex_lock(&s->mtx);
    while (!s->done) pthread_cond_wait(&s->cond, &s->mtx);
    pthread_mutex_unlock(&s->mtx);
    pthread_join(tid, NULL);
    pthread_mutex_destroy(&s->mtx);
    pthread_cond_destroy(&s->cond);
}

/* ── Test suite ──────────────────────────────────────────────────────────── */

VW_TEST_SUITE("vw_net") {

    /* Write cert and key to a per-process temp directory. */
    make_tmpdir(g_tmpdir, sizeof(g_tmpdir));
    char cert_path[600], key_path[600];
    snprintf(cert_path, sizeof(cert_path), "%s/test.crt", g_tmpdir);
    snprintf(key_path,  sizeof(key_path),  "%s/test.key", g_tmpdir);
    int cert_ok = (write_file(cert_path, TEST_CERT_PEM) == 0 &&
                   write_file(key_path,  TEST_KEY_PEM)  == 0);

    VW_TEST_CASE("setup: cert and key written to temp dir") {
        VW_ASSERT(cert_ok);
    }

    /* ── TC-5: no network needed ─────────────────────────────────────────── */

    VW_TEST_CASE("TC-5: VERIFY_REQUIRED + NULL ca_cert_path → VW_ERR_INVALID_ARG") {
        vw_conn_t *c = NULL;
        vw_err_t err = vw_net_connect("127.0.0.1", 43722,
                                       VW_CERT_VERIFY_REQUIRED, NULL, NULL, &c);
        VW_ASSERT_ERR(err, VW_ERR_INVALID_ARG);
        VW_ASSERT(c == NULL);
    }

    /* ── TC-6: connect to non-listening port ─────────────────────────────── */

    VW_TEST_CASE("TC-6: connect to non-listening port → error") {
        /* Port 1 is reserved and virtually guaranteed to be refused on loopback. */
        vw_conn_t *c = NULL;
        vw_err_t err = vw_net_connect("127.0.0.1", 1,
                                       VW_CERT_VERIFY_NONE, NULL, NULL, &c);
        VW_ASSERT(err != VW_OK);
        VW_ASSERT(c == NULL);
    }

    if (!cert_ok) goto cleanup;

    /* ── TC-1 + TC-2 + TC-7: shared loopback connection on port 43722 ────── */
    {
        srv_t s1;
        s1.cert_path  = cert_path;
        s1.key_path   = key_path;
        s1.port       = 43722;
        s1.n_accept   = 1;
        s1.xfer_bytes = LOOPBACK_BYTES;
        s1.ctx_out    = NULL;
        pthread_t tid1 = srv_start(&s1);

        VW_TEST_CASE("TC-1/2/7 server: vw_net_listen port 43722 ok") {
            VW_ASSERT_ERR(s1.err, VW_OK);
        }

        vw_conn_t *c = NULL;
        vw_err_t conn_err = VW_ERR_INVALID_ARG;
        if (s1.err == VW_OK)
            conn_err = vw_net_connect("127.0.0.1", 43722,
                                      VW_CERT_VERIFY_NONE, NULL, NULL, &c);

        VW_TEST_CASE("TC-1: vw_net_connect succeeded") {
            VW_ASSERT_ERR(conn_err, VW_OK);
            VW_ASSERT(c != NULL);
        }

        VW_TEST_CASE("TC-2: ALPN negotiated to \"vw/1\"") {
            if (c) {
                const char *alpn = vw_net_alpn(c);
                VW_ASSERT(alpn != NULL);
                if (alpn) VW_ASSERT_STR_EQ(alpn, "vw/1");
            } else {
                VW_ASSERT(0);
            }
        }

        VW_TEST_CASE("TC-7: vw_net_peer_addr returns non-empty IPv4 string") {
            if (c) {
                char addr[64] = "";
                vw_err_t ae = vw_net_peer_addr(c, addr, sizeof(addr));
                VW_ASSERT_ERR(ae, VW_OK);
                VW_ASSERT(addr[0] != '\0');
            } else {
                VW_ASSERT(0);
            }
        }

        VW_TEST_CASE("TC-1: 1 KiB echo is byte-exact") {
            if (c) {
                uint8_t snd[LOOPBACK_BYTES], rcv[LOOPBACK_BYTES];
                for (uint32_t i = 0; i < LOOPBACK_BYTES; i++) snd[i] = (uint8_t)i;
                VW_ASSERT_ERR(vw_net_send(c, snd, LOOPBACK_BYTES), VW_OK);
                VW_ASSERT_ERR(vw_net_recv(c, rcv, LOOPBACK_BYTES), VW_OK);
                VW_ASSERT_MEM_EQ(snd, rcv, LOOPBACK_BYTES);
            } else {
                VW_ASSERT(0);
            }
        }

        vw_net_close(c);
        srv_join(&s1, tid1);
    }

    /* ── TC-3: cert reload on port 43723 ─────────────────────────────────── */
    {
        vw_net_ctx_t *srv_ctx = NULL;
        srv_t s3;
        s3.cert_path  = cert_path;
        s3.key_path   = key_path;
        s3.port       = 43723;
        s3.n_accept   = 2;
        s3.xfer_bytes = 32;
        s3.ctx_out    = &srv_ctx;
        pthread_t tid3 = srv_start(&s3);

        VW_TEST_CASE("TC-3: server started on port 43723") {
            VW_ASSERT_ERR(s3.err, VW_OK);
        }

        if (s3.err == VW_OK) {
            /* First connection — before the reload */
            vw_conn_t *c1 = NULL;
            vw_net_connect("127.0.0.1", 43723,
                           VW_CERT_VERIFY_NONE, NULL, NULL, &c1);
            if (c1) {
                uint8_t buf[32];
                memset(buf, 0xAA, sizeof(buf));
                vw_net_send(c1, buf, sizeof(buf));
                vw_net_recv(c1, buf, sizeof(buf));
                vw_net_close(c1);
            }

            /* Hot-swap: reload the same cert (simulates a renewal). */
            vw_err_t reload_err = VW_ERR_INVALID_ARG;
            if (srv_ctx)
                reload_err = vw_net_ctx_reload_cert(srv_ctx, cert_path, key_path);

            VW_TEST_CASE("TC-3: vw_net_ctx_reload_cert returned VW_OK") {
                VW_ASSERT_ERR(reload_err, VW_OK);
            }

            /* Second connection — must succeed after the reload */
            vw_conn_t *c2 = NULL;
            vw_err_t c2_err = vw_net_connect("127.0.0.1", 43723,
                                              VW_CERT_VERIFY_NONE, NULL, NULL, &c2);

            VW_TEST_CASE("TC-3: new connection succeeds after cert reload") {
                VW_ASSERT_ERR(c2_err, VW_OK);
                VW_ASSERT(c2 != NULL);
            }

            if (c2) {
                uint8_t buf[32];
                memset(buf, 0xBB, sizeof(buf));
                vw_net_send(c2, buf, sizeof(buf));
                vw_net_recv(c2, buf, sizeof(buf));
                vw_net_close(c2);
            }
        }
        srv_join(&s3, tid3);
    }

    /* ── TC-4: rate limiter on port 43724 ────────────────────────────────── */
    {
        srv_t s4;
        s4.cert_path  = cert_path;
        s4.key_path   = key_path;
        s4.port       = 43724;
        s4.n_accept   = 1;
        s4.xfer_bytes = RATE_DATA_BYTES; /* server drains the full upload */
        s4.ctx_out    = NULL;
        pthread_t tid4 = srv_start(&s4);

        VW_TEST_CASE("TC-4: server started on port 43724") {
            VW_ASSERT_ERR(s4.err, VW_OK);
        }

        if (s4.err == VW_OK) {
            vw_conn_t *c = NULL;
            vw_err_t err = vw_net_connect("127.0.0.1", 43724,
                                           VW_CERT_VERIFY_NONE, NULL, NULL, &c);
            if (err == VW_OK && c) {
                vw_net_set_rate_limit(c, RATE_BPS, 0);

                uint8_t *data = calloc(1, RATE_DATA_BYTES);
                uint64_t t0 = ms_now();
                vw_net_send(c, data, RATE_DATA_BYTES);
                uint64_t elapsed_ms = ms_now() - t0;
                free(data);
                vw_net_close(c);

                VW_TEST_CASE("TC-4: send 100 KB at 50 KB/s took ≥1000 ms") {
                    VW_ASSERT(elapsed_ms >= RATE_MIN_MS);
                }
            } else {
                /* Record a failure so the test binary exits non-zero. */
                VW_TEST_CASE("TC-4: send 100 KB at 50 KB/s took ≥1000 ms") {
                    VW_ASSERT(0); /* connect failed — cannot test rate limiter */
                }
            }
        }
        srv_join(&s4, tid4);
    }

cleanup:
    rm_rf(g_tmpdir);
}

VW_TEST_SUITE_END()
