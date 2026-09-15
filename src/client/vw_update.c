#include "vw_update.h"
#include "vw_update_net.h"
#include "../core/vw_crypto.h"
#include "../core/vw_fs.h"
#include "vw_version.h"   /* VW_VERSION_STRING — generated, see vw_version INTERFACE target */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <signal.h>
#  include <errno.h>
#  include <time.h>
#endif

/* ── Version string comparison (TASK-00298) ──────────────────────────────
 * Deliberately narrow: major.minor.patch integers only, no semver
 * pre-release/build-metadata — this project's own release tags
 * (docs/RELEASE.md) are always plain MAJOR.MINOR.PATCH, so this is a
 * documented, accepted scope limit, not an oversight. */

typedef struct { int major, minor, patch; } vw_semver_t;

static int parse_semver(const char *s, vw_semver_t *out) {
    if (!s) return -1;
    int n = sscanf(s, "%d.%d.%d", &out->major, &out->minor, &out->patch);
    return (n == 3) ? 0 : -1;
}

/* Returns >0 if a > b, <0 if a < b, 0 if equal. Unparseable inputs sort as
 * "not newer" (never trigger a false-positive update prompt on garbage). */
static int semver_cmp(const char *a_str, const char *b_str) {
    vw_semver_t a, b;
    if (parse_semver(a_str, &a) != 0) return 0;
    if (parse_semver(b_str, &b) != 0) return 0;
    if (a.major != b.major) return a.major - b.major;
    if (a.minor != b.minor) return a.minor - b.minor;
    return a.patch - b.patch;
}

int vw_update_version_is_newer_than_current(const char *candidate_version) {
    return semver_cmp(candidate_version, VW_VERSION_STRING) > 0;
}

int vw_update_daily_check_due(int64_t last_check_unix, int64_t now_unix,
                               uint32_t interval_secs) {
    if (last_check_unix == 0) return 1;
    if (now_unix < last_check_unix) return 0; /* clock moved backward — not a reason to check */
    return (now_unix - last_check_unix) >= (int64_t)interval_secs;
}

vw_err_t vw_update_check_trigger(const char *state_dir,
                                  const char *server_advertised_version,
                                  vw_update_manifest_t *out_manifest,
                                  int *out_available) {
    if (out_available) *out_available = 0;
    if (!state_dir || !out_manifest || !out_available) return VW_ERR_INVALID_ARG;
    if (!server_advertised_version || server_advertised_version[0] == '\0')
        return VW_OK; /* nothing to compare against — not an error */

    if (semver_cmp(server_advertised_version, VW_VERSION_STRING) <= 0)
        return VW_OK; /* hint doesn't look newer — no need to even check GitHub */

    /* The hint looks newer: go verify against the real source of truth.
     * The hint itself is never trusted further than this point. */
    vw_err_t err = vw_update_manifest_fetch_and_verify(state_dir, out_manifest);
    if (err != VW_OK) return err; /* rollback/invalid/net — caller logs, never fatal */

    if (semver_cmp(out_manifest->release_version, VW_VERSION_STRING) > 0)
        *out_available = 1;
    return VW_OK;
}

/* ── Asset download + verify ─────────────────────────────────────────── */

#ifdef _WIN32
#  define VW_UPDATE_PLATFORM "windows"
#else
#  define VW_UPDATE_PLATFORM "linux"
#endif
#define VW_UPDATE_ARCH "x86_64"

#define VW_UPDATE_ASSET_MAX_BYTES (256u * 1024u * 1024u) /* generous cap for a portable archive */

static const vw_update_manifest_asset_t *find_matching_asset(const vw_update_manifest_t *m) {
    for (uint32_t i = 0; i < m->asset_count; i++) {
        const vw_update_manifest_asset_t *a = &m->assets[i];
        if (strcmp(a->platform, VW_UPDATE_PLATFORM) == 0 &&
            strcmp(a->arch, VW_UPDATE_ARCH) == 0 &&
            strcmp(a->dist_kind, "portable") == 0)
            return a;
    }
    return NULL;
}

vw_err_t vw_update_download_and_verify_asset(const vw_update_manifest_t *m,
                                              const char *staging_dir,
                                              char *out_archive_path,
                                              size_t out_cap) {
    if (!m || !staging_dir || !out_archive_path || out_cap == 0) return VW_ERR_INVALID_ARG;

    const vw_update_manifest_asset_t *asset = find_matching_asset(m);
    if (!asset) return VW_ERR_UPDATE_ASSET_MISMATCH;

    /* The manifest's OWN signed, version-pinned URL — never `latest` a
     * second time (see this file's header comment / vw_update.h). */
    char path[600];
    int pn = snprintf(path, sizeof(path), "/OtHanski/VaporWault/releases/download/v%s/%s",
                       m->release_version, asset->filename);
    if (pn <= 0 || (size_t)pn >= sizeof(path)) return VW_ERR_INVALID_ARG;

    vw_update_response_t resp;
    memset(&resp, 0, sizeof(resp));
    vw_err_t err = vw_update_https_get("github.com", 443, path,
                                        VW_UPDATE_ASSET_MAX_BYTES, &resp);
    if (err != VW_OK) return VW_ERR_UPDATE_NET;

    uint8_t hash[VW_HASH_BYTES];
    err = vw_crypto_sha256(resp.body, resp.body_len, hash);
    if (err != VW_OK) { vw_update_response_free(&resp); return VW_ERR_UPDATE_ASSET_MISMATCH; }

    if (memcmp(hash, asset->sha256, VW_HASH_BYTES) != 0) {
        vw_update_response_free(&resp);
        return VW_ERR_UPDATE_ASSET_MISMATCH; /* nothing written to disk on mismatch */
    }

    int wn = snprintf(out_archive_path, out_cap, "%s/%s", staging_dir, asset->filename);
    if (wn <= 0 || (size_t)wn >= out_cap) { vw_update_response_free(&resp); return VW_ERR_INVALID_ARG; }

    err = vw_fs_atomic_write(out_archive_path, resp.body, resp.body_len);
    vw_update_response_free(&resp);
    return err;
}

/* ── Process spawning helpers (cross-platform) ───────────────────────────
 * Deliberately minimal: no shell involved anywhere (argv-array style
 * spawning on both platforms), since every argument here is a filesystem
 * path this process resolved itself, not external input — but avoiding a
 * shell entirely is still the correct default regardless. */

#ifdef _WIN32
/* Windows has no real argv for CreateProcess — build one quoted command
 * line string. Sufficient for our own controlled paths (handles spaces,
 * never has to handle an embedded '"' since none of our paths ever
 * contain one). */
static int build_win_cmdline(char *out, size_t out_cap, char *const argv[]) {
    size_t off = 0;
    for (int i = 0; argv[i]; i++) {
        size_t len = strlen(argv[i]);
        if (off + len + 4 >= out_cap) return -1;
        if (i > 0) out[off++] = ' ';
        out[off++] = '"';
        memcpy(out + off, argv[i], len);
        off += len;
        out[off++] = '"';
    }
    out[off] = '\0';
    return 0;
}
#endif

static vw_err_t run_process_sync(char *const argv[]) {
#ifdef _WIN32
    char cmdline[4096];
    if (build_win_cmdline(cmdline, sizeof(cmdline), argv) != 0) return VW_ERR_IO;

    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                         NULL, NULL, &si, &pi))
        return VW_ERR_IO;
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (code == 0) ? VW_OK : VW_ERR_IO;
#else
    pid_t pid = fork();
    if (pid < 0) return VW_ERR_IO;
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127); /* execvp only returns on failure */
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return VW_ERR_IO;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? VW_OK : VW_ERR_IO;
#endif
}

static vw_err_t spawn_process_detached(char *const argv[]) {
#ifdef _WIN32
    char cmdline[4096];
    if (build_win_cmdline(cmdline, sizeof(cmdline), argv) != 0) return VW_ERR_IO;

    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    /* DETACHED_PROCESS: the helper gets no console of its own and is not
     * killed when this process exits (ordinary Win32 child-process
     * semantics already don't tie a child's lifetime to its parent's —
     * this flag only detaches console/stdio inheritance). */
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                         CREATE_NO_WINDOW | DETACHED_PROCESS,
                         NULL, NULL, &si, &pi))
        return VW_ERR_IO;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return VW_OK;
#else
    pid_t pid = fork();
    if (pid < 0) return VW_ERR_IO;
    if (pid == 0) {
        /* Detach from the parent's session so the updater survives this
         * process exiting cleanly, matching a standard (single-fork,
         * sufficient here since we don't need this process to keep
         * running independently of anything — it exits right after this
         * call anyway) daemonization step. */
        setsid();
        execvp(argv[0], argv);
        _exit(127);
    }
    /* Deliberately not waitpid()'d — this process is about to exit, and
     * once it does, the detached child's parent PID is reassigned to
     * init/systemd, which reaps it normally. */
    return VW_OK;
#endif
}

/* ── Extraction + handoff to vapourwault-updater ─────────────────────── */

#ifdef _WIN32
#  define VW_UPDATER_EXE_NAME "vapourwault-updater.exe"
#  define VW_DAEMON_EXE_NAME  "vapourwault-daemon.exe"
#else
#  define VW_UPDATER_EXE_NAME "vapourwault-updater"
#  define VW_DAEMON_EXE_NAME  "vapourwault-daemon"
#endif

static uint64_t current_pid(void) {
#ifdef _WIN32
    return (uint64_t)GetCurrentProcessId();
#else
    return (uint64_t)getpid();
#endif
}

vw_err_t vw_update_stage_and_apply(const char *archive_path,
                                    const char *install_dir) {
    if (!archive_path || !install_dir) return VW_ERR_INVALID_ARG;

    /* Derive <archive's directory>/extracted as the extraction target, and
     * keep the archive's own filename (the part after the last slash) —
     * archive_path is always <staging_dir>/<filename> (see
     * vw_update_download_and_verify_asset above), and the filename (minus
     * its .tar.gz/.zip extension) is also the name of the single top-level
     * directory the release archive wraps its payload in (see below). */
    char staging_dir[560];
    const char *filename;
    {
        const char *slash = strrchr(archive_path, '/');
#ifdef _WIN32
        const char *bslash = strrchr(archive_path, '\\');
        if (!slash || (bslash && bslash > slash)) slash = bslash;
#endif
        if (!slash) return VW_ERR_INVALID_ARG;
        size_t dirlen = (size_t)(slash - archive_path);
        if (dirlen >= sizeof(staging_dir)) return VW_ERR_INVALID_ARG;
        memcpy(staging_dir, archive_path, dirlen);
        staging_dir[dirlen] = '\0';
        filename = slash + 1;
    }

    char extract_dir[600];
    int en = snprintf(extract_dir, sizeof(extract_dir), "%s/extracted", staging_dir);
    if (en <= 0 || (size_t)en >= sizeof(extract_dir)) return VW_ERR_INVALID_ARG;

    vw_err_t err = vw_fs_ensure_dir(extract_dir);
    if (err != VW_OK) return err;

    /* One uniform extraction command on both platforms: Linux always
     * produces a real .tar.gz here (GNU tar auto-detects gzip via -xf,
     * no explicit -z needed on any modern GNU tar); Windows always
     * produces a real .zip (Windows' own built-in tar.exe, bsdtar/
     * libarchive since Windows 10 1803, auto-detects the zip format via
     * -xf too) — see this task's own implementation notes for why no
     * hand-rolled archive/decompression parser was written instead. */
    char *tar_argv[] = { (char *)"tar", (char *)"-xf", (char *)archive_path,
                          (char *)"-C", extract_dir, NULL };
    err = run_process_sync(tar_argv);
    if (err != VW_OK) return err;

    /* release.yml's staging step (both platforms) archives a DIRECTORY,
     * not that directory's contents: `tar czf "$STAGE.tar.gz" "$STAGE"` /
     * `Compress-Archive -Path $stage`, where $STAGE/$stage is named
     * exactly like the archive's own filename minus its extension (e.g.
     * archive "vaporwault-v0.4.2-linux-x86_64.tar.gz" unpacks to
     * "vaporwault-v0.4.2-linux-x86_64/<the actual binaries>"). So the
     * real payload sits one level below extract_dir, at
     * extract_dir/<stage_name> — never at extract_dir itself. Passing
     * extract_dir directly as vapourwault-updater's --staging would make
     * swap_all() see a single top-level directory entry: silently
     * installing NOTHING on Windows (its directory-entries are skipped)
     * or renaming that whole directory into place under the wrong name on
     * POSIX — either way a "successful" update that changed nothing or
     * corrupted the install, which is exactly why this is resolved here
     * with a hard failure rather than left for swap_all to discover. */
    char stage_name[300];
    {
        size_t flen = strlen(filename);
        size_t stage_len = flen;
        static const char *const known_exts[] = { ".tar.gz", ".zip" };
        for (size_t i = 0; i < sizeof(known_exts) / sizeof(known_exts[0]); i++) {
            size_t elen = strlen(known_exts[i]);
            if (flen > elen && strcmp(filename + flen - elen, known_exts[i]) == 0) {
                stage_len = flen - elen;
                break;
            }
        }
        if (stage_len == 0 || stage_len >= sizeof(stage_name)) return VW_ERR_INVALID_ARG;
        memcpy(stage_name, filename, stage_len);
        stage_name[stage_len] = '\0';
    }

    char payload_dir[900];
    int pdn = snprintf(payload_dir, sizeof(payload_dir), "%s/%s", extract_dir, stage_name);
    if (pdn <= 0 || (size_t)pdn >= sizeof(payload_dir)) return VW_ERR_INVALID_ARG;
    if (!vw_fs_exists(payload_dir)) return VW_ERR_IO; /* archive didn't have the expected layout */

    char updater_path[600];
    int un = snprintf(updater_path, sizeof(updater_path), "%s/%s", install_dir, VW_UPDATER_EXE_NAME);
    if (un <= 0 || (size_t)un >= sizeof(updater_path)) return VW_ERR_INVALID_ARG;

    char daemon_path[600];
    int dn = snprintf(daemon_path, sizeof(daemon_path), "%s/%s", install_dir, VW_DAEMON_EXE_NAME);
    if (dn <= 0 || (size_t)dn >= sizeof(daemon_path)) return VW_ERR_INVALID_ARG;

    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%llu", (unsigned long long)current_pid());

    char *updater_argv[] = {
        updater_path,
        (char *)"--staging", payload_dir,
        (char *)"--target", (char *)install_dir,
        (char *)"--wait-pid", pid_str,
        (char *)"--relaunch", daemon_path,
        NULL
    };
    return spawn_process_detached(updater_argv);
}
