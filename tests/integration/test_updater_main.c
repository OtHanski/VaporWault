/*
 * test_updater_main.c — integration tests for TASK-00298's
 * vapourwault-updater helper (src/client/vw_updater_main.c).
 *
 * Invokes the REAL built vapourwault-updater binary as a subprocess with
 * controlled argv, rather than linking its source — it is deliberately a
 * standalone, no-vw_core-linkage binary (see its own header comment), so
 * exercising it as a real child process is what actually proves its
 * argument validation and file-swap behavior, not a stand-in.
 *
 * --wait-pid needs a PID that is ALREADY gone by the time the updater
 * checks it (wait_for_pid polls kill(pid,0)/OpenProcess in a loop, up to
 * 60s) — never this test process's own PID, which stays alive for the
 * whole run. spawn_and_reap_get_exited_pid() below spawns a trivial child,
 * waits for it to fully exit (reaping it on POSIX), and returns that now-
 * dead PID, so wait_for_pid() returns immediately instead of stalling
 * every test case for up to a minute.
 *
 * TC-1..4: missing/invalid required arguments each exit 1 (die()) without
 *          touching the filesystem.
 * TC-5: happy path — staging has a file that also exists in target
 *       (had_current=1 path): backed up, replaced, backup cleaned up.
 * TC-6: staging has a file that does NOT exist in target yet
 *       (had_current=0 path): just moved into place, no stray .old.
 * TC-7: multiple files in one staging dir are all applied in one run.
 */

#include "vw_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <process.h>
#  define VW_PID() ((unsigned)GetCurrentProcessId())
#else
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <sys/stat.h>
#  include <signal.h>
#  define VW_PID() ((unsigned)getpid())
#endif

#ifndef VW_UPDATER_EXE_PATH
#error "VW_UPDATER_EXE_PATH must be defined by CMake to the real vapourwault-updater binary"
#endif

/* ── small cross-platform process/file helpers (test-only; deliberately
 * not shared with src/client/vw_update.c's own copies — this test must
 * keep working even if that file's helpers change shape). ─────────────── */

static int run_and_wait(char *const argv[]) {
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
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)code;
#else
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
}

/* Returns a PID that is guaranteed to already be dead by the time this
 * returns (see this file's header comment). */
static uint64_t spawn_and_reap_get_exited_pid(void) {
#ifdef _WIN32
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    char cmdline[] = "cmd.exe /c exit 0";
    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                         NULL, NULL, &si, &pi))
        return 999999; /* implausible PID; wait_for_pid's OpenProcess will fail harmlessly */
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD pid = pi.dwProcessId;
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (uint64_t)pid;
#else
    pid_t pid = fork();
    if (pid == 0) _exit(0);
    int status = 0;
    waitpid(pid, &status, 0); /* fully reaped: kill(pid,0) now returns ESRCH */
    return (uint64_t)pid;
#endif
}

/* A monotonic per-process counter, not clock() — clock()'s resolution
 * (process CPU time, ~15ms granularity on Windows) repeats across the
 * back-to-back calls this test makes within the same test case, which
 * previously collided staging_dir with target_dir outright (both
 * resolving to the identical path) and corrupted every assertion downstream
 * — a real bug in this test helper, found via a debug rebuild with
 * per-attempt Win32 error logging, not in vw_updater_main.c itself. */
static int g_tmpdir_seq = 0;

static void make_tmpdir(char *out, size_t sz) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_updatermain_%u_%d", tmp, VW_PID(), ++g_tmpdir_seq);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_updatermain_%u_%d", VW_PID(), ++g_tmpdir_seq);
    mkdir(out, 0700);
#endif
}
static void path_join(char *out, size_t sz, const char *dir, const char *name) {
    snprintf(out, sz, "%s/%s", dir, name);
}
static int write_text(const char *path, const char *data) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t n = strlen(data);
    size_t written = fwrite(data, 1, n, f);
    fclose(f);
    return (written == n) ? 0 : -1;
}
static int read_text(const char *path, char *out, size_t out_sz) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(out, 1, out_sz - 1, f);
    fclose(f);
    out[n] = '\0';
    return 0;
}
static int file_exists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

VW_TEST_SUITE("updater_main") {
    const char *updater = VW_UPDATER_EXE_PATH;

    /* ── TC-1..4: mandatory-argument validation ── */
    VW_TEST_CASE("no arguments at all exits 1") {
        char *argv[] = { (char *)updater, NULL };
        VW_ASSERT_EQ(run_and_wait(argv), 1);
    }
    VW_TEST_CASE("missing --wait-pid exits 1") {
        char *argv[] = { (char *)updater,
            (char *)"--staging", (char *)".", (char *)"--target", (char *)".",
            (char *)"--relaunch", (char *)"nope", NULL };
        VW_ASSERT_EQ(run_and_wait(argv), 1);
    }
    VW_TEST_CASE("non-numeric --wait-pid exits 1") {
        char *argv[] = { (char *)updater,
            (char *)"--staging", (char *)".", (char *)"--target", (char *)".",
            (char *)"--wait-pid", (char *)"not-a-number",
            (char *)"--relaunch", (char *)"nope", NULL };
        VW_ASSERT_EQ(run_and_wait(argv), 1);
    }
    VW_TEST_CASE("zero --wait-pid exits 1 (never treated as a real PID)") {
        char *argv[] = { (char *)updater,
            (char *)"--staging", (char *)".", (char *)"--target", (char *)".",
            (char *)"--wait-pid", (char *)"0",
            (char *)"--relaunch", (char *)"nope", NULL };
        VW_ASSERT_EQ(run_and_wait(argv), 1);
    }

    /* ── TC-5..7: real file-swap behavior ── */
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%llu",
             (unsigned long long)spawn_and_reap_get_exited_pid());

    VW_TEST_CASE("existing target file is backed up, replaced, and backup cleaned up") {
        char staging[512], target[512];
        make_tmpdir(staging, sizeof(staging));
        make_tmpdir(target, sizeof(target));

        char staged_file[560], current_file[560], backup_file[580];
        path_join(staged_file, sizeof(staged_file), staging, "payload.txt");
        path_join(current_file, sizeof(current_file), target, "payload.txt");
        snprintf(backup_file, sizeof(backup_file), "%s.old", current_file);

        VW_ASSERT(write_text(staged_file, "STAGED-V2") == 0);
        VW_ASSERT(write_text(current_file, "OLD-V1") == 0);

        char *argv[] = { (char *)updater,
            (char *)"--staging", staging, (char *)"--target", target,
            (char *)"--wait-pid", pid_str,
            (char *)"--relaunch", (char *)"vw-test-nonexistent-relaunch-target", NULL };
        VW_ASSERT_EQ(run_and_wait(argv), 0);

        char content[64];
        VW_ASSERT(read_text(current_file, content, sizeof(content)) == 0);
        VW_ASSERT(strcmp(content, "STAGED-V2") == 0);
        VW_ASSERT(!file_exists(backup_file));
        VW_ASSERT(!file_exists(staged_file)); /* moved, not copied */
    }

    VW_TEST_CASE("new file with no pre-existing target counterpart is moved into place") {
        char staging[512], target[512];
        make_tmpdir(staging, sizeof(staging));
        make_tmpdir(target, sizeof(target));

        char staged_file[560], current_file[560], backup_file[580];
        path_join(staged_file, sizeof(staged_file), staging, "newfile.txt");
        path_join(current_file, sizeof(current_file), target, "newfile.txt");
        snprintf(backup_file, sizeof(backup_file), "%s.old", current_file);

        VW_ASSERT(write_text(staged_file, "NEWCONTENT") == 0);

        char *argv[] = { (char *)updater,
            (char *)"--staging", staging, (char *)"--target", target,
            (char *)"--wait-pid", pid_str,
            (char *)"--relaunch", (char *)"vw-test-nonexistent-relaunch-target", NULL };
        VW_ASSERT_EQ(run_and_wait(argv), 0);

        char content[64];
        VW_ASSERT(read_text(current_file, content, sizeof(content)) == 0);
        VW_ASSERT(strcmp(content, "NEWCONTENT") == 0);
        VW_ASSERT(!file_exists(backup_file));
    }

    VW_TEST_CASE("multiple staged files are all applied in one run") {
        char staging[512], target[512];
        make_tmpdir(staging, sizeof(staging));
        make_tmpdir(target, sizeof(target));

        char sa[560], sb[560], ca[560], cb[560];
        path_join(sa, sizeof(sa), staging, "a.txt");
        path_join(sb, sizeof(sb), staging, "b.txt");
        path_join(ca, sizeof(ca), target, "a.txt");
        path_join(cb, sizeof(cb), target, "b.txt");

        VW_ASSERT(write_text(sa, "A2") == 0);
        VW_ASSERT(write_text(sb, "B2") == 0);
        VW_ASSERT(write_text(ca, "A1") == 0);
        /* b.txt has no pre-existing target counterpart */

        char *argv[] = { (char *)updater,
            (char *)"--staging", staging, (char *)"--target", target,
            (char *)"--wait-pid", pid_str,
            (char *)"--relaunch", (char *)"vw-test-nonexistent-relaunch-target", NULL };
        VW_ASSERT_EQ(run_and_wait(argv), 0);

        char content[64];
        VW_ASSERT(read_text(ca, content, sizeof(content)) == 0);
        VW_ASSERT(strcmp(content, "A2") == 0);
        VW_ASSERT(read_text(cb, content, sizeof(content)) == 0);
        VW_ASSERT(strcmp(content, "B2") == 0);
    }
}
VW_TEST_SUITE_END()
