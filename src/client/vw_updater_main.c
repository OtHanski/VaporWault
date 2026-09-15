/*
 * vapourwault-updater — the client auto-update feature's file-swap +
 * relaunch helper (TASK-00298, ARCHITECTURE.md Phase 23).
 *
 * Deliberately standalone: no vw_core linkage (just raw file
 * rename/unlink + wait-for-pid + spawn-process), so it can safely swap
 * out the daemon binary (and, in principle, vw_core itself if it were
 * ever shipped as a shared library — it isn't, everything here is static,
 * but the design still holds) without depending on any file this update
 * might itself be replacing.
 *
 *   vapourwault-updater --staging <dir> --target <install_dir>
 *                        --wait-pid <old_pid> --relaunch <exe>
 *
 * All four arguments are mandatory — this never runs with a target
 * directory it wasn't explicitly told to use, and never operates without
 * a valid --wait-pid (see the argument validation below).
 *
 * Steps: wait (bounded) for the old process to exit; for every top-level
 * file in --staging, rename the current file in --target to <file>.old,
 * rename the staged file into --target, then best-effort delete the
 * .old backup (a lingering .old is a disclosed, harmless leftover, not a
 * correctness issue — cleaned up on the next update cycle instead); spawn
 * --relaunch (detached, not waited on); exit.
 *
 * Used identically on both platforms for one symmetric, single-tested
 * mechanism — Linux's rename/unlink-while-running semantics don't
 * strictly require a separate helper, but a second, divergent restart
 * code path per platform would be worse than the small overlap.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <unistd.h>
#  include <sys/types.h>
#  include <signal.h>
#  include <dirent.h>
#  include <errno.h>
#  include <time.h>
#endif

#define VW_UPDATER_MAX_WAIT_SECS 60

static void die(const char *why) {
    fprintf(stderr, "vapourwault-updater: %s\n", why);
    exit(1);
}

static void join_path(char *out, size_t out_sz, const char *dir, const char *name) {
#ifdef _WIN32
    snprintf(out, out_sz, "%s\\%s", dir, name);
#else
    snprintf(out, out_sz, "%s/%s", dir, name);
#endif
}

/* ── Wait (bounded) for the old process to exit ─────────────────────────
 * A stuck old process doesn't abort the update — the rename-based swap
 * below can still succeed even against a still-running old binary on
 * both platforms (Windows allows renaming an open file's directory
 * entry, just not overwriting its content in place; Linux's rename/
 * unlink-while-open semantics need no special handling at all) — so this
 * is a best-effort wait, not a hard precondition. */
#ifdef _WIN32
static void wait_for_pid(uint64_t pid) {
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
    if (!h) return; /* already gone, or never existed — proceed either way */
    WaitForSingleObject(h, VW_UPDATER_MAX_WAIT_SECS * 1000);
    CloseHandle(h);
}
#else
static void wait_for_pid(uint64_t pid) {
    for (int i = 0; i < VW_UPDATER_MAX_WAIT_SECS * 10; i++) {
        if (kill((pid_t)pid, 0) != 0 && errno == ESRCH) return; /* exited */
        struct timespec ts = { 0, 100000000L }; /* 100ms */
        nanosleep(&ts, NULL);
    }
}
#endif

/* ── Detached relaunch ───────────────────────────────────────────────── */

#ifdef _WIN32
static void relaunch(const char *exe_path) {
    char cmdline[1024];
    snprintf(cmdline, sizeof(cmdline), "\"%s\"", exe_path);
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW | DETACHED_PROCESS,
                        NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}
#else
static void relaunch(const char *exe_path) {
    pid_t pid = fork();
    if (pid < 0) return;
    if (pid == 0) {
        setsid();
        execl(exe_path, exe_path, (char *)NULL);
        _exit(127);
    }
}
#endif

/* ── Swap: for every top-level file in staging_dir, back up the current
 * file in target_dir, move the staged one into place, then best-effort
 * clean up the backup ─────────────────────────────────────────────────── */

#ifdef _WIN32
/* A file this process (or the download/extract step just before it) wrote
 * moments ago can be transiently locked by Windows Defender's real-time
 * scan or an indexer, failing MoveFileA with a sharing violation for a
 * short window even though nothing in this process itself still holds it
 * open — observed directly while testing this helper (a real, if rare,
 * production risk for exactly this reason, not merely a test artifact).
 * Bounded retry-with-backoff, same shape real-world Windows installers use
 * for this exact class of transient failure. */
static BOOL move_with_retry(const char *from, const char *to) {
    for (int attempt = 0; attempt < 20; attempt++) {
        if (MoveFileA(from, to)) return TRUE;
        Sleep(50);
    }
    return FALSE;
}

static void swap_all(const char *staging_dir, const char *target_dir) {
    char pattern[600];
    snprintf(pattern, sizeof(pattern), "%s\\*", staging_dir);

    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

        char staged[600], current[600], backup[620];
        join_path(staged,  sizeof(staged),  staging_dir, fd.cFileName);
        join_path(current, sizeof(current), target_dir,  fd.cFileName);
        snprintf(backup, sizeof(backup), "%s.old", current);

        DeleteFileA(backup); /* clear out a leftover from a prior interrupted cycle */
        BOOL had_current = move_with_retry(current, backup);

        if (!move_with_retry(staged, current)) {
            fprintf(stderr, "vapourwault-updater: failed to install %s, restoring backup\n", fd.cFileName);
            if (had_current) move_with_retry(backup, current); /* best-effort recovery */
            continue;
        }
        if (had_current) DeleteFileA(backup); /* best-effort; a lingering .old is harmless */
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}
#else
static void swap_all(const char *staging_dir, const char *target_dir) {
    DIR *d = opendir(staging_dir);
    if (!d) return;

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;

        char staged[600], current[600], backup[620];
        join_path(staged,  sizeof(staged),  staging_dir, e->d_name);
        join_path(current, sizeof(current), target_dir,  e->d_name);
        snprintf(backup, sizeof(backup), "%s.old", current);

        remove(backup); /* clear out a leftover from a prior interrupted cycle */
        int had_current = (rename(current, backup) == 0);

        if (rename(staged, current) != 0) {
            fprintf(stderr, "vapourwault-updater: failed to install %s, restoring backup\n", e->d_name);
            if (had_current) rename(backup, current); /* best-effort recovery */
            continue;
        }
        if (had_current) remove(backup); /* best-effort; a lingering .old is harmless */
    }
    closedir(d);
}
#endif

int main(int argc, char **argv) {
    const char *staging = NULL, *target = NULL, *relaunch_exe = NULL;
    uint64_t wait_pid = 0;
    int have_wait_pid = 0;

    for (int i = 1; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "--staging") == 0) staging = argv[i + 1];
        else if (strcmp(argv[i], "--target") == 0) target = argv[i + 1];
        else if (strcmp(argv[i], "--relaunch") == 0) relaunch_exe = argv[i + 1];
        else if (strcmp(argv[i], "--wait-pid") == 0) {
            char *end = NULL;
            wait_pid = strtoull(argv[i + 1], &end, 10);
            have_wait_pid = (end && *end == '\0' && wait_pid > 0);
        }
    }

    /* All four are mandatory — never run with a target directory (or
     * anything else) implied/defaulted rather than explicitly given. */
    if (!staging || !target || !relaunch_exe || !have_wait_pid)
        die("usage: --staging <dir> --target <dir> --wait-pid <pid> --relaunch <exe> (all required)");

    wait_for_pid(wait_pid);
    swap_all(staging, target);
    relaunch(relaunch_exe);
    return 0;
}
