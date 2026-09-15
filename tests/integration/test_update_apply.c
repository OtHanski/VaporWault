/*
 * test_update_apply.c — integration tests for TASK-00298's
 * vw_update_download_and_verify_asset() and vw_update_stage_and_apply()
 * (src/client/vw_update.c).
 *
 * Uses VW_UPDATE_NET_TEST_HOOKS (vw_update_net.c's test seam) with a
 * REDIRECTING connect hook: unlike test_update_manifest.c/test_update_net.c
 * (which use compile-time VW_UPDATE_GITHUB_HOST overrides inside the file
 * being tested), vw_update.c hardcodes "github.com" with no such override
 * — by design, it's the manifest's OWN signed, version-pinned URL that
 * matters in production, never a second `latest`. So this test's hook
 * ignores whatever host/port it's called with and always connects to the
 * local test server instead; the hook is exactly the seam meant for this
 * (see vw_update_net.h's own doc comment on the hook).
 *
 * TC-1: happy path — server serves an asset whose SHA-256 matches the
 *       manifest exactly; the verified bytes land on disk unmodified.
 * TC-2: SHA-256 mismatch — server serves DIFFERENT bytes than the
 *       manifest's signed hash describes; rejected, and nothing is ever
 *       written to the staging directory.
 * TC-3: no asset in the manifest matches this platform/arch/portable
 *       dist_kind — rejected before any network activity.
 * TC-4: vw_update_stage_and_apply extracts a correctly-shaped archive (one
 *       top-level directory wrapping the payload, matching release.yml's
 *       real layout) and resolves the nested payload directory correctly
 *       — this is the TASK-00298 fix under test: passing the bare
 *       extraction directory as --staging (the pre-fix behavior) would
 *       have silently done nothing on Windows or corrupted the install on
 *       POSIX. Only the synchronous extraction+resolution phase is
 *       checked here — the actual file swap is the spawned
 *       vapourwault-updater's own job, already covered end-to-end (with a
 *       controlled, already-exited --wait-pid) by test_updater_main.c;
 *       that helper here always waits on THIS test process's own live PID,
 *       so nothing spawned by vw_update_stage_and_apply can be observed
 *       finishing within this test's lifetime.
 * TC-5: an archive that does NOT have the expected one-directory-wrapper
 *       shape (a real, if unlikely, CI packaging regression) is rejected
 *       with VW_ERR_IO rather than silently resolved to the wrong path.
 */

#include "vw_test.h"
#include "vw_update.h"
#include "vw_update_manifest.h"
#include "vw_update_net.h"
#include "vw_net.h"
#include "vw_crypto.h"
#include "vw_fs.h"

#ifdef _WIN32
#  include <windows.h>
#  include <process.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <sys/stat.h>
#  define VW_PID() ((unsigned)getpid())
#endif

#ifdef _WIN32
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
#include <stdlib.h>

/* Must track vw_update.c's own internal VW_UPDATE_PLATFORM/VW_UPDATE_ARCH
 * macros (not exposed via vw_update.h — they're this platform's fixed
 * identity, not something a caller ever varies) so this test's manifest
 * fixtures actually match what find_matching_asset() looks for. */
#ifdef _WIN32
#  define TEST_PLATFORM "windows"
#else
#  define TEST_PLATFORM "linux"
#endif
#define TEST_ARCH "x86_64"

#define TEST_PORT 43772u

/* Same embedded self-signed test cert/key used elsewhere in this suite. */
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

#ifndef VW_TEST_SCRATCH_ROOT
#error "VW_TEST_SCRATCH_ROOT must be defined by CMake"
#endif

/*
 * Deliberately NOT under the system %TEMP%/tmp — this sandboxed dev
 * environment blocks executing a freshly-copied .exe placed there (found
 * earlier this session testing vw_update_stage_and_apply directly: a real
 * .exe under %TEMP% got "Access is denied" on CreateProcess), and TC-4
 * below needs to actually spawn the real vapourwault-updater binary out
 * of install_dir. VW_TEST_SCRATCH_ROOT (a subdirectory of the build tree,
 * where the sandbox already allows running this project's own binaries
 * from) sidesteps that restriction entirely.
 */
static int g_seq = 0;
static void make_tmpdir(char *out, size_t sz) {
#ifdef _WIN32
    CreateDirectoryA(VW_TEST_SCRATCH_ROOT, NULL);
    snprintf(out, sz, "%s/vw_updateapply_%u_%d", VW_TEST_SCRATCH_ROOT, VW_PID(), ++g_seq);
    CreateDirectoryA(out, NULL);
#else
    mkdir(VW_TEST_SCRATCH_ROOT, 0700);
    snprintf(out, sz, "%s/vw_updateapply_%u_%d", VW_TEST_SCRATCH_ROOT, VW_PID(), ++g_seq);
    mkdir(out, 0700);
#endif
}
static void path_join(char *out, size_t sz, const char *dir, const char *name) {
    snprintf(out, sz, "%s/%s", dir, name);
}
static int write_bytes(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    return (written == len) ? 0 : -1;
}
static int copy_file(const char *from, const char *to) {
    FILE *in = fopen(from, "rb");
    if (!in) return -1;
    FILE *out = fopen(to, "wb");
    if (!out) { fclose(in); return -1; }
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { fclose(in); fclose(out); return -1; }
    }
    fclose(in); fclose(out);
    return 0;
}
static int file_exists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}
static int read_all(const char *path, char *out, size_t out_cap) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(out, 1, out_cap - 1, f);
    fclose(f);
    out[n] = '\0';
    return 0;
}

/* Spawns "tar" synchronously with the given argv (no shell), matching
 * vw_update.c's own run_process_sync — duplicated here rather than shared,
 * same rationale as test_updater_main.c's own standalone process helpers. */
static int run_cmd(char *const argv[]) {
#ifdef _WIN32
    char cmdline[4096];
    size_t off = 0;
    for (int i = 0; argv[i]; i++) {
        size_t len = strlen(argv[i]);
        if (i > 0) cmdline[off++] = ' ';
        cmdline[off++] = '"';
        memcpy(cmdline + off, argv[i], len);
        off += len;
        cmdline[off++] = '"';
    }
    cmdline[off] = '\0';
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                         NULL, NULL, &si, &pi))
        return -1;
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)code;
#else
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) { execvp(argv[0], argv); _exit(127); }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
}

/* Builds a real tar.gz at out_archive_path containing exactly one
 * top-level directory (stage_name), with one file (dummyfile.txt =
 * file_contents) inside it — the same shape release.yml's own staging
 * step produces (see vw_update.c's vw_update_stage_and_apply comment). */
static int build_stage_archive(const char *parent_dir, const char *stage_name,
                                 const char *file_contents,
                                 char *out_archive_path, size_t out_cap) {
    char stage_dir[600];
    path_join(stage_dir, sizeof(stage_dir), parent_dir, stage_name);
#ifdef _WIN32
    CreateDirectoryA(stage_dir, NULL);
#else
    mkdir(stage_dir, 0700);
#endif
    char payload_file[700];
    path_join(payload_file, sizeof(payload_file), stage_dir, "dummyfile.txt");
    if (write_bytes(payload_file, file_contents, strlen(file_contents)) != 0) return -1;

    char archive_name[300];
    snprintf(archive_name, sizeof(archive_name), "%s.tar.gz", stage_name);
    snprintf(out_archive_path, out_cap, "%s/%s", parent_dir, archive_name);

    char *argv[] = { (char *)"tar", (char *)"-czf", out_archive_path,
                      (char *)"-C", (char *)parent_dir, (char *)stage_name, NULL };
    return run_cmd(argv);
}

/* Same "one connection, one 200 OK response" pattern as
 * test_update_manifest.c's dual_srv, collapsed to a single response since
 * vw_update_download_and_verify_asset makes exactly one HTTP request. */
typedef struct {
    const char *cert_path, *key_path;
    uint16_t    port;
    const void *body; size_t body_len;
    pthread_mutex_t mtx; pthread_cond_t cond; int ready; vw_err_t bind_err;
} single_srv_args_t;

static void *single_srv_thread(void *arg) {
    single_srv_args_t *a = arg;
    vw_net_ctx_t *net_ctx = NULL;
    vw_err_t err = vw_net_listen("127.0.0.1", a->port, a->cert_path, a->key_path, &net_ctx);
    a->bind_err = err;
    pthread_mutex_lock(&a->mtx);
    a->ready = 1;
    pthread_cond_signal(&a->cond);
    pthread_mutex_unlock(&a->mtx);
    if (err != VW_OK) return NULL;

    vw_conn_t *conn = NULL;
    if (vw_net_accept(net_ctx, &conn) == VW_OK) {
        uint8_t discard[4096]; size_t got = 0;
        (void)vw_net_recv_partial(conn, discard, sizeof(discard), &got);
        char hdr[128];
        int n = snprintf(hdr, sizeof(hdr), "HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", a->body_len);
        if (vw_net_send(conn, hdr, (size_t)n) == VW_OK && a->body_len > 0)
            (void)vw_net_send(conn, a->body, a->body_len);
        vw_net_close(conn);
    }
    vw_net_ctx_close(net_ctx);
    return NULL;
}
static pthread_t spawn_single_srv(single_srv_args_t *a) {
    a->ready = 0; a->bind_err = VW_OK;
    pthread_mutex_init(&a->mtx, NULL);
    pthread_cond_init(&a->cond, NULL);
    pthread_t tid;
    pthread_create(&tid, NULL, single_srv_thread, a);
    pthread_mutex_lock(&a->mtx);
    while (!a->ready) pthread_cond_wait(&a->cond, &a->mtx);
    pthread_mutex_unlock(&a->mtx);
    return tid;
}
static void join_single_srv(pthread_t tid, single_srv_args_t *a) {
    pthread_join(tid, NULL);
    pthread_mutex_destroy(&a->mtx);
    pthread_cond_destroy(&a->cond);
}

/* Ignores whatever host/port vw_update.c thinks it's connecting to
 * ("github.com", 443) and always dials the local test server instead —
 * see this file's header comment for why this (not a compile-time host
 * override) is the right seam for vw_update.c specifically. */
static vw_err_t redirect_connect_hook(const char *host, uint16_t port,
                                       const vw_conn_opts_t *opts,
                                       vw_conn_t **out_conn) {
    (void)host; (void)port;
    return vw_net_connect_generic("127.0.0.1", (uint16_t)TEST_PORT, VW_CERT_VERIFY_NONE,
                                   NULL, opts, out_conn);
}

static void make_manifest_with_asset(vw_update_manifest_t *m, const char *filename,
                                      const uint8_t sha256[32]) {
    memset(m, 0, sizeof(*m));
    m->schema_version = 1;
    m->sequence = 1;
    snprintf(m->release_version, sizeof(m->release_version), "9.9.9");
    m->min_client_protocol_version = 1;
    m->asset_count = 1;
    snprintf(m->assets[0].platform, sizeof(m->assets[0].platform), "%s", TEST_PLATFORM);
    snprintf(m->assets[0].arch, sizeof(m->assets[0].arch), "%s", TEST_ARCH);
    snprintf(m->assets[0].dist_kind, sizeof(m->assets[0].dist_kind), "portable");
    snprintf(m->assets[0].filename, sizeof(m->assets[0].filename), "%s", filename);
    memcpy(m->assets[0].sha256, sha256, 32);
}

VW_TEST_SUITE("update_apply") {
    VW_ASSERT_EQ(vw_crypto_init(), VW_OK);
    vw_update_net_test_set_connect_hook(redirect_connect_hook);

    char tmpdir[512];
    make_tmpdir(tmpdir, sizeof(tmpdir));
    char cert_path[600], key_path[600];
    path_join(cert_path, sizeof(cert_path), tmpdir, "test_cert.pem");
    path_join(key_path,  sizeof(key_path),  tmpdir, "test_key.pem");
    VW_ASSERT(write_bytes(cert_path, TEST_CERT_PEM, sizeof(TEST_CERT_PEM) - 1) == 0);
    VW_ASSERT(write_bytes(key_path,  TEST_KEY_PEM,  sizeof(TEST_KEY_PEM) - 1)  == 0);

    /* ── TC-1: happy path ── */
    VW_TEST_CASE("matching SHA-256 asset downloads and verifies successfully") {
        char parent[512]; make_tmpdir(parent, sizeof(parent));
        const char *stage_name = "vaporwault-v9.9.9-teststage";
        const char *contents = "REAL-ASSET-BYTES-V1";
        char archive_path[700];
        VW_ASSERT_EQ(build_stage_archive(parent, stage_name, contents, archive_path, sizeof(archive_path)), 0);

        char body[65536]; size_t body_len;
        {
            FILE *f = fopen(archive_path, "rb");
            VW_ASSERT(f != NULL);
            body_len = fread(body, 1, sizeof(body), f);
            fclose(f);
        }
        uint8_t hash[VW_HASH_BYTES];
        VW_ASSERT_EQ(vw_crypto_sha256((const uint8_t *)body, body_len, hash), VW_OK);

        vw_update_manifest_t m;
        make_manifest_with_asset(&m, "vaporwault-v9.9.9-teststage.tar.gz", hash);

        single_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = (uint16_t)TEST_PORT;
        sa.body = body; sa.body_len = body_len;
        pthread_t tid = spawn_single_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        char staging_dir[512]; make_tmpdir(staging_dir, sizeof(staging_dir));
        char out_path[700];
        vw_err_t err = vw_update_download_and_verify_asset(&m, staging_dir, out_path, sizeof(out_path));
        VW_ASSERT_EQ(err, VW_OK);
        VW_ASSERT(file_exists(out_path));

        /* out_path holds the raw downloaded archive bytes (the .tar.gz
         * blob itself), not the plain-text payload wrapped inside it —
         * compare against the served bytes, byte-for-byte. */
        char downloaded[65536]; size_t downloaded_len;
        {
            FILE *f = fopen(out_path, "rb");
            VW_ASSERT(f != NULL);
            downloaded_len = fread(downloaded, 1, sizeof(downloaded), f);
            fclose(f);
        }
        VW_ASSERT_EQ(downloaded_len, body_len);
        VW_ASSERT(memcmp(downloaded, body, body_len) == 0);

        join_single_srv(tid, &sa);
    }

    /* ── TC-2: SHA-256 mismatch ── */
    VW_TEST_CASE("SHA-256 mismatch is rejected and nothing is written") {
        const char *served_contents = "ACTUALLY-SERVED-BYTES";
        uint8_t wrong_hash[32];
        memset(wrong_hash, 0xAB, sizeof(wrong_hash)); /* deliberately does not match */

        vw_update_manifest_t m;
        make_manifest_with_asset(&m, "mismatched-asset.tar.gz", wrong_hash);

        single_srv_args_t sa;
        sa.cert_path = cert_path; sa.key_path = key_path; sa.port = (uint16_t)TEST_PORT;
        sa.body = served_contents; sa.body_len = strlen(served_contents);
        pthread_t tid = spawn_single_srv(&sa);
        VW_ASSERT_EQ(sa.bind_err, VW_OK);

        char staging_dir[512]; make_tmpdir(staging_dir, sizeof(staging_dir));
        char out_path[700];
        vw_err_t err = vw_update_download_and_verify_asset(&m, staging_dir, out_path, sizeof(out_path));
        VW_ASSERT_EQ(err, VW_ERR_UPDATE_ASSET_MISMATCH);

        char expected_path[700];
        path_join(expected_path, sizeof(expected_path), staging_dir, "mismatched-asset.tar.gz");
        VW_ASSERT(!file_exists(expected_path));

        join_single_srv(tid, &sa);
    }

    /* ── TC-3: no matching asset — rejected before any network activity ── */
    VW_TEST_CASE("no asset matches this platform/arch/portable — rejected, no network needed") {
        vw_update_manifest_t m;
        memset(&m, 0, sizeof(m));
        m.asset_count = 1;
        snprintf(m.assets[0].platform, sizeof(m.assets[0].platform), "some-other-os");
        snprintf(m.assets[0].arch, sizeof(m.assets[0].arch), "%s", TEST_ARCH);
        snprintf(m.assets[0].dist_kind, sizeof(m.assets[0].dist_kind), "portable");
        snprintf(m.assets[0].filename, sizeof(m.assets[0].filename), "other.tar.gz");

        char staging_dir[512]; make_tmpdir(staging_dir, sizeof(staging_dir));
        char out_path[700];
        vw_err_t err = vw_update_download_and_verify_asset(&m, staging_dir, out_path, sizeof(out_path));
        VW_ASSERT_EQ(err, VW_ERR_UPDATE_ASSET_MISMATCH);
    }

    /* ── TC-4: stage_and_apply resolves the nested payload directory ── */
    VW_TEST_CASE("stage_and_apply extracts and resolves the nested payload directory") {
        char parent[512]; make_tmpdir(parent, sizeof(parent));
        const char *stage_name = "vaporwault-v9.9.9-linux-x86_64";
        const char *contents = "STAGE-AND-APPLY-PAYLOAD";
        char archive_path[700];
        VW_ASSERT_EQ(build_stage_archive(parent, stage_name, contents, archive_path, sizeof(archive_path)), 0);

        char install_dir[512]; make_tmpdir(install_dir, sizeof(install_dir));
#ifdef _WIN32
        const char *updater_name = "vapourwault-updater.exe";
#else
        const char *updater_name = "vapourwault-updater";
#endif
        char updater_dst[700];
        path_join(updater_dst, sizeof(updater_dst), install_dir, updater_name);
        VW_ASSERT(copy_file(VW_UPDATER_EXE_PATH, updater_dst) == 0);
#ifndef _WIN32
        chmod(updater_dst, 0755);
#endif

        vw_err_t err = vw_update_stage_and_apply(archive_path, install_dir);
        VW_ASSERT_EQ(err, VW_OK);

        /* Verify the synchronous extraction+resolution phase directly —
         * see this file's header comment for why the async swap itself
         * is out of scope here. */
        char extracted_payload[900];
        snprintf(extracted_payload, sizeof(extracted_payload), "%s/extracted/%s/dummyfile.txt",
                 parent, stage_name);
        VW_ASSERT(file_exists(extracted_payload));
        char got[128];
        VW_ASSERT(read_all(extracted_payload, got, sizeof(got)) == 0);
        VW_ASSERT(strcmp(got, contents) == 0);
    }

    /* ── TC-5: archive missing the expected wrapper directory is rejected ── */
    VW_TEST_CASE("archive without the expected one-directory wrapper is rejected") {
        char parent[512]; make_tmpdir(parent, sizeof(parent));
        char flat_file[700];
        path_join(flat_file, sizeof(flat_file), parent, "flat.txt");
        VW_ASSERT(write_bytes(flat_file, "flat", 4) == 0);

        char archive_path[700];
        snprintf(archive_path, sizeof(archive_path), "%s/flat-vaporwault-v1.0.0-linux-x86_64.tar.gz", parent);
        char *argv[] = { (char *)"tar", (char *)"-czf", archive_path,
                          (char *)"-C", parent, (char *)"flat.txt", NULL };
        VW_ASSERT_EQ(run_cmd(argv), 0);

        char install_dir[512]; make_tmpdir(install_dir, sizeof(install_dir));
        vw_err_t err = vw_update_stage_and_apply(archive_path, install_dir);
        VW_ASSERT_EQ(err, VW_ERR_IO);
    }

    vw_crypto_cleanup();
}
VW_TEST_SUITE_END()
