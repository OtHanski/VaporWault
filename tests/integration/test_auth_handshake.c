/*
 * test_auth_handshake.c — integration test for TASK-011.
 *
 * Runs a server thread over localhost TLS and exercises:
 *   TC-1: successful login (no 2FA)
 *   TC-2: wrong password → AUTH_FAIL / VW_ERR_AUTH_BAD_CREDS
 *   TC-3: SESSION_RESUME — token replacement, new token returned
 *
 * The test embeds a self-signed EC P-256 test certificate and writes it to
 * a temp directory at runtime. The client uses VW_CERT_VERIFY_NONE because
 * the cert has no meaningful SAN for localhost.
 *
 * Password setup (Phase 1 protocol, PROTOCOL.md §8.1):
 *   The server stores Argon2id(SHA-256(password), random_salt) as the hash.
 *   The client sends SHA-256(password) as auth_token on the wire.
 *   Both sides call vw_crypto_sha256 on the raw password string.
 *
 * NOTE: vw_auth_hash_password runs Argon2id (64 MiB, 3 passes).  Each
 *       invocation takes several seconds; this test takes ~10–30 s total.
 */

#include "vw_test.h"

/* server modules */
#include "vw_auth.h"
#include "vw_auth_provider.h"
#include "vw_oplog.h"
#include "vw_server_core.h"
#include "vw_smtp.h"
#include "vw_store.h"

/* client module */
#include "vw_client_core.h"

/* core */
#include "vw_crypto.h"
#include "vw_net.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <windows.h>
#  include <process.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <dirent.h>
#  include <sys/stat.h>
#  include <unistd.h>
#  define VW_PID() ((unsigned)getpid())
#endif

/* ── Embedded test certificate (EC P-256, self-signed, CN=VaporWault Test) ── */

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

/* ── Port ────────────────────────────────────────────────────────────────── */

#define TEST_PORT 43721u

/* ── Temp-directory helpers (adapted from test_vw_oplog.c) ─────────────── */

static void make_tmpdir(char *out, size_t sz)
{
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_authtest_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_authtest_%u", VW_PID());
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
            rm_rf(child);
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
        struct stat st;
        if (stat(child, &st) == 0 && S_ISDIR(st.st_mode))
            rm_rf(child);
        else
            remove(child);
    }
    closedir(d);
    rmdir(dir);
#endif
}

static void path_join(char *out, size_t sz, const char *dir, const char *name)
{
#ifdef _WIN32
    snprintf(out, sz, "%s\\%s", dir, name);
#else
    snprintf(out, sz, "%s/%s", dir, name);
#endif
}

static int write_file(const char *path, const char *data)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = strlen(data);
    size_t written = fwrite(data, 1, n, f);
    fclose(f);
    return (written == n) ? 0 : -1;
}

/* ── Server thread ───────────────────────────────────────────────────────── */

typedef struct {
    const char      *cert_path;
    const char      *key_path;
    vw_server_ctx_t *srv_ctx;
    int              connections_to_handle;

    pthread_mutex_t  mtx;
    pthread_cond_t   cond;
    int              ready;       /* server is listening (or failed) */

    vw_err_t         bind_err;   /* error from vw_net_listen */
    vw_err_t         last_err;   /* error from last vw_server_conn_handle */
    vw_session_info_t last_info;
} srv_args_t;

static void *server_thread(void *arg)
{
    srv_args_t *a = arg;

    vw_net_ctx_t *net_ctx = NULL;
    vw_err_t err = vw_net_listen("127.0.0.1", (uint16_t)TEST_PORT,
                                   a->cert_path, a->key_path, &net_ctx);
    a->bind_err = err;

    pthread_mutex_lock(&a->mtx);
    a->ready = 1;
    pthread_cond_signal(&a->cond);
    pthread_mutex_unlock(&a->mtx);

    if (err != VW_OK) return NULL;

    for (int i = 0; i < a->connections_to_handle; i++) {
        vw_conn_t *conn = NULL;
        err = vw_net_accept(net_ctx, &conn);
        if (err != VW_OK) { a->last_err = err; break; }

        vw_session_info_t info;
        memset(&info, 0, sizeof(info));
        a->last_err = vw_server_conn_handle(a->srv_ctx, conn, &info);
        a->last_info = info;
        vw_net_close(conn);
    }

    vw_net_ctx_close(net_ctx);
    return NULL;
}

/* Spawn a server thread, wait until it signals ready. */
static pthread_t spawn_server(srv_args_t *a, int conns)
{
    a->connections_to_handle = conns;
    a->ready = 0;
    a->bind_err = VW_OK;
    a->last_err = VW_OK;
    memset(&a->last_info, 0, sizeof(a->last_info));
    pthread_mutex_init(&a->mtx, NULL);
    pthread_cond_init(&a->cond, NULL);

    pthread_t tid;
    pthread_create(&tid, NULL, server_thread, a);

    pthread_mutex_lock(&a->mtx);
    while (!a->ready) pthread_cond_wait(&a->cond, &a->mtx);
    pthread_mutex_unlock(&a->mtx);

    return tid;
}

static void join_server(pthread_t tid, srv_args_t *a)
{
    pthread_join(tid, NULL);
    pthread_mutex_destroy(&a->mtx);
    pthread_cond_destroy(&a->cond);
}

/* ── Test constants ──────────────────────────────────────────────────────── */

#define TEST_USERNAME     "testuser"
#define TEST_USERNAME_LEN 8u
#define TEST_PASSWORD     "testpass"
#define TEST_PASSWORD_LEN 8u

/* ── Test suite ──────────────────────────────────────────────────────────── */

VW_TEST_SUITE("auth_handshake") {

    /* ── Setup ─────────────────────────────────────────────────────────── */

    VW_ASSERT_EQ(vw_crypto_init(), VW_OK);

    char tmpdir[512];
    make_tmpdir(tmpdir, sizeof(tmpdir));

    char cert_path[520], key_path[520];
    path_join(cert_path, sizeof(cert_path), tmpdir, "test_cert.pem");
    path_join(key_path,  sizeof(key_path),  tmpdir, "test_key.pem");
    VW_ASSERT(write_file(cert_path, TEST_CERT_PEM) == 0);
    VW_ASSERT(write_file(key_path,  TEST_KEY_PEM)  == 0);

    char oplog_dir[520], data_dir[520];
    path_join(oplog_dir, sizeof(oplog_dir), tmpdir, "oplog");
    path_join(data_dir,  sizeof(data_dir),  tmpdir, "data");

    vw_oplog_t *oplog = NULL;
    VW_ASSERT_EQ(vw_oplog_open(oplog_dir, &oplog), VW_OK);

    vw_store_t *store = NULL;
    VW_ASSERT_EQ(vw_store_open(data_dir, oplog, &store), VW_OK);

    /* SMTP config all-zero: vw_auth_begin_login sends OTP only when
     * otp_enabled==1; the test user has otp_enabled==0. */
    vw_smtp_cfg_t smtp_cfg;
    memset(&smtp_cfg, 0, sizeof(smtp_cfg));

    vw_auth_ctx_t *auth = NULL;
    VW_ASSERT_EQ(vw_auth_open(store, &smtp_cfg, NULL, &auth), VW_OK);

    /* Create test user.
     * Password hash = Argon2id(SHA-256(TEST_PASSWORD), random_salt).
     * The client sends SHA-256(TEST_PASSWORD) as auth_token. */
    uint8_t sha_pw[32];
    VW_ASSERT_EQ(vw_crypto_sha256(TEST_PASSWORD, TEST_PASSWORD_LEN, sha_pw), VW_OK);

    vw_user_record_t urec;
    memset(&urec, 0, sizeof(urec));
    memcpy(urec.username, TEST_USERNAME, TEST_USERNAME_LEN);
    memcpy(urec.email, "test@example.com", 16);
    urec.is_active   = 1;
    urec.otp_enabled = 0;
    VW_ASSERT_EQ(vw_auth_hash_password(sha_pw, sizeof(sha_pw),
                                        urec.password_hash,
                                        urec.password_salt), VW_OK);
    uint64_t test_uid;
    VW_ASSERT_EQ(vw_store_user_create(store, &urec, &test_uid), VW_OK);

    vw_server_ctx_t *srv_ctx = NULL;
    VW_ASSERT_EQ(vw_server_ctx_open(auth, store, NULL, &srv_ctx), VW_OK);

    vw_client_cfg_t cli_cfg;
    memset(&cli_cfg, 0, sizeof(cli_cfg));
    cli_cfg.host          = "127.0.0.1";
    cli_cfg.port          = (uint16_t)TEST_PORT;
    cli_cfg.cert_verify   = VW_CERT_VERIFY_NONE;
    cli_cfg.ca_cert_pem_path = NULL;
    cli_cfg.conn_opts     = NULL;

    srv_args_t sa;
    sa.cert_path = cert_path;
    sa.key_path  = key_path;
    sa.srv_ctx   = srv_ctx;

    /* saved_token persists between TC-1 and TC-3 */
    uint8_t saved_token[VW_TOKEN_BYTES];
    memset(saved_token, 0, sizeof(saved_token));

    /* ── TC-1: successful login (no 2FA) ─────────────────────────────────── */
    VW_TEST_CASE("login no 2FA") {
        pthread_t tid = spawn_server(&sa, 1);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_client_sess_t *sess = NULL;
        vw_err_t err = vw_client_connect(&cli_cfg,
                                          TEST_USERNAME, TEST_USERNAME_LEN,
                                          TEST_PASSWORD, TEST_PASSWORD_LEN,
                                          NULL, NULL, &sess);
        VW_ASSERT_EQ(err, VW_OK);

        join_server(tid, &sa);
        VW_ASSERT_EQ(sa.last_err, VW_OK);

        if (err == VW_OK) {
            /* expires_at must be in the future (non-zero timestamp) */
            VW_ASSERT(vw_client_expires_at_of(sess) > 0);
            VW_ASSERT_EQ(vw_client_user_id_of(sess), test_uid);
            /* save token for TC-3 */
            vw_client_get_token(sess, saved_token);
            vw_client_close(sess);
        }
    }

    /* ── TC-2: wrong password → AUTH_FAIL ───────────────────────────────── */
    VW_TEST_CASE("wrong password returns AUTH_BAD_CREDS") {
        pthread_t tid = spawn_server(&sa, 1);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_client_sess_t *sess = NULL;
        vw_err_t err = vw_client_connect(&cli_cfg,
                                          TEST_USERNAME, TEST_USERNAME_LEN,
                                          "wrongpassword", 13u,
                                          NULL, NULL, &sess);
        VW_ASSERT_EQ(err, VW_ERR_AUTH_BAD_CREDS);
        VW_ASSERT(sess == NULL);

        join_server(tid, &sa);
        /* Server should have sent AUTH_FAIL and returned an auth error */
        VW_ASSERT(sa.last_err != VW_OK);
    }

    /* ── TC-3: SESSION_RESUME — new token issued ─────────────────────────── */
    VW_TEST_CASE("session resume issues new token") {
        pthread_t tid = spawn_server(&sa, 1);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_client_sess_t *sess = NULL;
        vw_err_t err = vw_client_resume(&cli_cfg, saved_token, &sess);
        VW_ASSERT_EQ(err, VW_OK);

        join_server(tid, &sa);
        VW_ASSERT_EQ(sa.last_err, VW_OK);

        if (err == VW_OK) {
            uint8_t new_token[VW_TOKEN_BYTES];
            vw_client_get_token(sess, new_token);
            /* The new token must differ from the old one (single-use) */
            VW_ASSERT(memcmp(new_token, saved_token, VW_TOKEN_BYTES) != 0);
            VW_ASSERT(vw_client_expires_at_of(sess) > 0);
            VW_ASSERT_EQ(vw_client_user_id_of(sess), test_uid);
            vw_client_close(sess);
        }
    }

    /* ── Teardown ────────────────────────────────────────────────────────── */

    vw_server_ctx_close(srv_ctx);
    vw_auth_close(auth);
    vw_store_close(store);
    vw_oplog_close(oplog);
    vw_crypto_cleanup();
    rm_rf(tmpdir);
}
VW_TEST_SUITE_END()
