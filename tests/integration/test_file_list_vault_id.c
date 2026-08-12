/*
 * test_file_list_vault_id.c — regression test for TASK-156.
 *
 * FILE_LIST_RESP used to never carry a per-entry vault_id at all (revision
 * 14 deliberately left it out, reasoning that populating it would cost one
 * version lookup per entry — see docs/PROTOCOL.md §7.2's note and this
 * task's own filing for why that reasoning has since been revisited).
 * vw_client_file_entry_t.vault_id was always 0 from vw_client_file_list,
 * even for a genuinely vault-encrypted file, forcing every real consumer
 * (the native GUI's capped, per-file-round-trip refresh_vault_badges; the
 * web gateway's folder-level-only workaround) into an inferior substitute.
 *
 * This test drives a real client/server pair (like test_auth_handshake.c)
 * rather than testing encode/decode in isolation, because the bug this
 * regresses spans two modules that only ever meet on the wire: the
 * server's handle_file_list (src/server/vw_file_handlers.c) and the
 * client's recv_file_list_resp (src/client/vw_client_core.c).
 *
 * Sets up a vault-encrypted-*shaped* version directly via the store API
 * (vw_store_version_create with vault_id != 0) rather than through the
 * real Argon2id/AES-GCM vault crypto pipeline — this test's job is to
 * verify the wire plumbing carries vault_id through correctly, not to
 * re-verify the crypto itself (already covered by test_vault_e2ee.c/
 * test_vault_regression.c).
 */

#include "vw_test.h"

#include "vw_auth.h"
#include "vw_auth_provider.h"
#include "vw_oplog.h"
#include "vw_server_core.h"
#include "vw_smtp.h"
#include "vw_store.h"
#include "vw_storage.h"
#include "vw_file_handlers.h"

#include "vw_client_core.h"

#include "vw_crypto.h"
#include "vw_net.h"

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <process.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <dirent.h>
#  include <sys/stat.h>
#  include <unistd.h>
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

#define TEST_PORT 43744u

static void make_tmpdir(char *out, size_t sz) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_flvid_%u", tmp, VW_PID());
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_flvid_%u", VW_PID());
    mkdir(out, 0700);
#endif
}

static void rm_rf(const char *dir) {
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

typedef struct {
    const char      *cert_path;
    const char      *key_path;
    vw_server_ctx_t *srv_ctx;

    pthread_mutex_t  mtx;
    pthread_cond_t   cond;
    int              ready;

    vw_err_t         bind_err;
    vw_err_t         last_err;
} srv_args_t;

static void *server_thread(void *arg) {
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

    vw_conn_t *conn = NULL;
    err = vw_net_accept(net_ctx, &conn);
    if (err == VW_OK) {
        vw_session_info_t info;
        memset(&info, 0, sizeof(info));
        a->last_err = vw_server_conn_handle(a->srv_ctx, conn, &info);

        /* vw_server_conn_handle only performs the auth handshake -
         * everything after (FILE_LIST, FILE_STAT, ...) is the accept
         * loop's own job to receive and dispatch, per
         * vw_file_handlers.h's own doc comment and vw_server_main.c's
         * real handle_connection(). Mirror that here instead of the
         * bare single vw_server_conn_handle call test_auth_handshake.c
         * uses (which never sends anything post-auth). */
        if (a->last_err == VW_OK) {
            uint8_t *buf = malloc(VW_MAX_MSG_BYTES);
            if (buf) {
                for (;;) {
                    vw_msg_type_t type;
                    uint32_t plen;
                    vw_err_t rerr = vw_proto_recv(conn, &type, buf, VW_MAX_MSG_BYTES, &plen);
                    if (rerr != VW_OK) break; /* client closed the connection */
                    rerr = vw_server_dispatch_file_op(a->srv_ctx, conn, type, buf, plen);
                    if (rerr == VW_ERR_AUTH_REQUIRED || rerr == VW_ERR_PROTO_INVALID) break;
                }
                free(buf);
            }
        }

        vw_net_close(conn);
    } else {
        a->last_err = err;
    }

    vw_net_ctx_close(net_ctx);
    return NULL;
}

static pthread_t spawn_server(srv_args_t *a) {
    a->ready = 0;
    a->bind_err = VW_OK;
    a->last_err = VW_OK;
    pthread_mutex_init(&a->mtx, NULL);
    pthread_cond_init(&a->cond, NULL);

    pthread_t tid;
    pthread_create(&tid, NULL, server_thread, a);

    pthread_mutex_lock(&a->mtx);
    while (!a->ready) pthread_cond_wait(&a->cond, &a->mtx);
    pthread_mutex_unlock(&a->mtx);
    return tid;
}

static void join_server(pthread_t tid, srv_args_t *a) {
    pthread_join(tid, NULL);
    pthread_mutex_destroy(&a->mtx);
    pthread_cond_destroy(&a->cond);
}

#define TEST_USERNAME     "vidlisttest"
#define TEST_USERNAME_LEN 11u
#define TEST_PASSWORD     "vidlistpass"
#define TEST_PASSWORD_LEN 11u
#define TEST_VAULT_ID     ((uint64_t)424242u)

VW_TEST_SUITE("file_list_vault_id") {

    VW_ASSERT_EQ(vw_crypto_init(), VW_OK);

    char tmpdir[512];
    make_tmpdir(tmpdir, sizeof(tmpdir));
    char cert_path[520], key_path[520];
    path_join(cert_path, sizeof(cert_path), tmpdir, "test_cert.pem");
    path_join(key_path,  sizeof(key_path),  tmpdir, "test_key.pem");
    VW_ASSERT(write_file(cert_path, TEST_CERT_PEM) == 0);
    VW_ASSERT(write_file(key_path,  TEST_KEY_PEM)  == 0);

    char oplog_dir[520], data_dir[520], files_dir[520], chunks_dir[520];
    path_join(oplog_dir,  sizeof(oplog_dir),  tmpdir, "oplog");
    path_join(data_dir,   sizeof(data_dir),   tmpdir, "data");
    path_join(files_dir,  sizeof(files_dir),  tmpdir, "files");
    path_join(chunks_dir, sizeof(chunks_dir), tmpdir, "chunks");

    vw_oplog_t *oplog = NULL;
    VW_ASSERT_EQ(vw_oplog_open(oplog_dir, &oplog), VW_OK);

    vw_store_t *store = NULL;
    VW_ASSERT_EQ(vw_store_open(data_dir, oplog, &store), VW_OK);

    vw_file_store_t *fs = NULL;
    VW_ASSERT_EQ(vw_file_store_open(files_dir, oplog, &fs), VW_OK);

    vw_storage_t *chunk_store = NULL;
    VW_ASSERT_EQ(vw_storage_open(chunks_dir, &chunk_store), VW_OK);
    vw_storage_set_store(chunk_store, store);

    vw_smtp_cfg_t smtp_cfg;
    memset(&smtp_cfg, 0, sizeof(smtp_cfg));

    vw_auth_ctx_t *auth = NULL;
    VW_ASSERT_EQ(vw_auth_open(store, &smtp_cfg, NULL, &auth), VW_OK);

    uint8_t sha_pw[32];
    VW_ASSERT_EQ(vw_crypto_sha256(TEST_PASSWORD, TEST_PASSWORD_LEN, sha_pw), VW_OK);

    vw_user_record_t urec;
    memset(&urec, 0, sizeof(urec));
    memcpy(urec.username, TEST_USERNAME, TEST_USERNAME_LEN);
    memcpy(urec.email, "vidlist@example.com", 20);
    urec.is_active   = 1;
    urec.otp_enabled = 0;
    VW_ASSERT_EQ(vw_auth_hash_password(sha_pw, sizeof(sha_pw),
                                        urec.password_hash,
                                        urec.password_salt), VW_OK);
    uint64_t test_uid;
    VW_ASSERT_EQ(vw_store_user_create(store, &urec, &test_uid), VW_OK);

    /* ── Directly create two files: one vault-encrypted-shaped, one plain,
     * both at the root ─────────────────────────────────────────────────── */

    vw_file_record_t frec;
    memset(&frec, 0, sizeof(frec));
    frec.owner_id      = test_uid;
    frec.parent_dir_id = 0;
    frec.entry_type    = VW_ENTRY_FILE;
    snprintf(frec.name, sizeof(frec.name), "encrypted.txt");
    uint64_t enc_file_id = 0;
    VW_ASSERT_EQ(vw_store_file_create(fs, &frec, &enc_file_id), VW_OK);

    /* vw_store_version_create cross-checks vault_id and wrapped_dek must
     * agree (both absent or both present, TASK-098) - this test isn't
     * exercising real vault crypto, so any nonempty placeholder bytes
     * satisfy that invariant without needing a real wrapped key. */
    static const uint8_t fake_wrapped_dek[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

    vw_version_record_t vrec;
    memset(&vrec, 0, sizeof(vrec));
    vrec.file_id    = enc_file_id;
    vrec.created_at = (uint64_t)1u;
    vrec.size_bytes = 0;
    vrec.chunk_count = 0;
    vrec.vault_id   = TEST_VAULT_ID;
    uint64_t enc_version_id = 0;
    VW_ASSERT_EQ(vw_store_version_create(fs, &vrec, NULL,
                                          fake_wrapped_dek, sizeof(fake_wrapped_dek),
                                          &enc_version_id), VW_OK);

    /* handle_file_commit's own pattern: version created, then the file
     * record's current_version_id is updated separately. */
    vw_file_record_t enc_rec_updated;
    VW_ASSERT_EQ(vw_store_file_get_by_id(fs, enc_file_id, &enc_rec_updated), VW_OK);
    enc_rec_updated.current_version_id = enc_version_id;
    VW_ASSERT_EQ(vw_store_file_update(fs, enc_file_id, &enc_rec_updated), VW_OK);

    memset(&frec, 0, sizeof(frec));
    frec.owner_id      = test_uid;
    frec.parent_dir_id = 0;
    frec.entry_type    = VW_ENTRY_FILE;
    snprintf(frec.name, sizeof(frec.name), "plain.txt");
    uint64_t plain_file_id = 0;
    VW_ASSERT_EQ(vw_store_file_create(fs, &frec, &plain_file_id), VW_OK);

    memset(&vrec, 0, sizeof(vrec));
    vrec.file_id    = plain_file_id;
    vrec.created_at = (uint64_t)1u;
    vrec.size_bytes = 0;
    vrec.chunk_count = 0;
    vrec.vault_id   = 0;
    uint64_t plain_version_id = 0;
    VW_ASSERT_EQ(vw_store_version_create(fs, &vrec, NULL, NULL, 0, &plain_version_id), VW_OK);

    vw_file_record_t plain_rec_updated;
    VW_ASSERT_EQ(vw_store_file_get_by_id(fs, plain_file_id, &plain_rec_updated), VW_OK);
    plain_rec_updated.current_version_id = plain_version_id;
    VW_ASSERT_EQ(vw_store_file_update(fs, plain_file_id, &plain_rec_updated), VW_OK);

    vw_server_ctx_t *srv_ctx = NULL;
    VW_ASSERT_EQ(vw_server_ctx_open(auth, store, NULL, &srv_ctx), VW_OK);
    vw_server_ctx_set_file_stores(srv_ctx, fs, chunk_store);

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

    VW_TEST_CASE("FILE_LIST_RESP carries the real per-entry vault_id") {
        pthread_t tid = spawn_server(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        vw_client_sess_t *sess = NULL;
        VW_ASSERT_EQ(vw_client_connect(&cli_cfg,
                                        TEST_USERNAME, TEST_USERNAME_LEN,
                                        TEST_PASSWORD, TEST_PASSWORD_LEN,
                                        NULL, NULL, &sess), VW_OK);

        vw_file_entry_t *entries = NULL;
        uint32_t count = 0;
        vw_err_t err = vw_client_file_list(sess, "/", 0, &entries, &count);
        VW_ASSERT_EQ(err, VW_OK);
        VW_ASSERT_EQ(count, 2u);

        int found_encrypted = 0, found_plain = 0;
        for (uint32_t i = 0; i < count; i++) {
            if (strcmp(entries[i].name, "encrypted.txt") == 0) {
                found_encrypted = 1;
                /* The actual regression check: this used to always be 0. */
                VW_ASSERT_EQ(entries[i].vault_id, TEST_VAULT_ID);
            } else if (strcmp(entries[i].name, "plain.txt") == 0) {
                found_plain = 1;
                VW_ASSERT_EQ(entries[i].vault_id, (uint64_t)0);
            }
        }
        VW_ASSERT(found_encrypted);
        VW_ASSERT(found_plain);

        /* Cross-check: FILE_STAT on the same file must agree — the
         * listing's vault_id isn't a different, inconsistent source of
         * truth from the one this project already trusted. */
        vw_file_entry_t stat_entry;
        VW_ASSERT_EQ(vw_client_file_stat(sess, "/encrypted.txt", &stat_entry), VW_OK);
        VW_ASSERT_EQ(stat_entry.vault_id, TEST_VAULT_ID);

        free(entries);
        vw_client_close(sess);

        join_server(tid, &sa);
        VW_ASSERT_EQ(sa.last_err, VW_OK);
    }

    vw_server_ctx_close(srv_ctx);
    vw_auth_close(auth);
    vw_storage_close(chunk_store);
    vw_file_store_close(fs);
    vw_store_close(store);
    vw_oplog_close(oplog);
    vw_crypto_cleanup();
    rm_rf(tmpdir);
}
VW_TEST_SUITE_END()
