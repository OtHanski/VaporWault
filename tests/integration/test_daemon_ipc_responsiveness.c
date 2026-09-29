/*
 * test_daemon_ipc_responsiveness.c — TASK-00306 regression.
 *
 * vw_daemon_run()'s main loop only reached its "accept and dispatch
 * pending IPC connections" step once per vw_watcher_wait() call, and that
 * call blocked for the FULL configured sync_interval_ms whenever there
 * were zero watched roots (Windows: a plain Sleep(timeout_ms); Linux:
 * poll() on the inotify fd, which never fires early since there's
 * nothing to watch). "Zero watched roots" is the state of every
 * freshly-installed daemon with no configured accounts yet — not a rare
 * edge case — so an IPC request landing moments after such a daemon
 * started could sit unanswered for up to the full sync_interval_ms
 * (production default 30s), looking exactly like a hang from the
 * outside. See TASK-00306 for the full incident and root cause.
 *
 * Deliberately spawns the daemon with NO sync_interval_ms override in
 * daemon.conf — this test's entire point is proving the fix holds at the
 * REAL production default (30000ms), unlike test_ipc_update.c's TC-1/
 * TC-2, which predate this fix and pin sync_interval_ms=200 specifically
 * to route around this bug (see that file's own comment at its
 * daemon.conf-writing call site).
 *
 * Uses the plain "status" command (read-only, no daemon.conf rewrite) for
 * both round trips — test_ipc_update.c's own comment documents a
 * separate, unconfirmed sandbox quirk around a config-rewriting request
 * immediately followed by a live re-query; "status" alone sidesteps that
 * without weakening what this test is actually proving (raw main-loop
 * IPC responsiveness, unrelated to what the request's handler does).
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <sys/stat.h>
#  include <sys/select.h>
#  include <sys/time.h>
#  include <signal.h>
#endif

#ifndef VW_DAEMON_EXE_PATH
#error "VW_DAEMON_EXE_PATH must be defined by CMake"
#endif
#ifndef VW_CLI_EXE_PATH
#error "VW_CLI_EXE_PATH must be defined by CMake"
#endif

static int g_failed = 0;
static int g_count  = 0;

#define CHECK(cond, desc) do { \
    g_count++; \
    if (cond) { printf("ok %d - %s\n", g_count, desc); } \
    else { printf("not ok %d - %s\n", g_count, desc); g_failed++; } \
} while (0)

static uint64_t now_ms(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
#endif
}

/* ── Process spawn + stdout/stderr capture (self-contained, same
 * duplication rationale as test_ipc_update.c/test_updater_main.c's own
 * process helpers) ──────────────────────────────────────────────────── */

typedef struct { int exit_code; char out[4096]; } run_result_t;

#ifdef _WIN32
static void run_capture(char *const argv[], run_result_t *r) {
    memset(r, 0, sizeof(*r));
    r->exit_code = -1;

    SECURITY_ATTRIBUTES sa; ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    HANDLE read_h = NULL, write_h = NULL;
    if (!CreatePipe(&read_h, &write_h, &sa, 0)) return;
    SetHandleInformation(read_h, HANDLE_FLAG_INHERIT, 0);

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
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = write_h;
    si.hStdError  = write_h;
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                         NULL, NULL, &si, &pi)) {
        CloseHandle(read_h); CloseHandle(write_h);
        return;
    }
    CloseHandle(write_h); /* our copy — child's own copy keeps the pipe open until it exits */

    size_t total = 0;
    time_t deadline = time(NULL) + 30;
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(read_h, NULL, 0, NULL, &avail, NULL)) break; /* pipe broken == EOF */
        if (avail == 0) {
            if (time(NULL) >= deadline) { TerminateProcess(pi.hProcess, 1); break; }
            Sleep(50);
            continue;
        }
        DWORD got = 0;
        if (!ReadFile(read_h, r->out + total, (DWORD)(sizeof(r->out) - 1 - total), &got, NULL) || got == 0)
            break;
        total += got;
        if (total >= sizeof(r->out) - 1) break;
        deadline = time(NULL) + 30; /* still making progress — extend the bound */
    }
    r->out[total] = '\0';
    CloseHandle(read_h);

    if (WaitForSingleObject(pi.hProcess, 30000) == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        r->exit_code = -1;
    } else {
        DWORD code = 1;
        GetExitCodeProcess(pi.hProcess, &code);
        r->exit_code = (int)code;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
#else
static void run_capture(char *const argv[], run_result_t *r) {
    memset(r, 0, sizeof(*r));
    r->exit_code = -1;

    int pipefd[2];
    if (pipe(pipefd) != 0) return;

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return; }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], 1);
        dup2(pipefd[1], 2);
        close(pipefd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);

    size_t total = 0;
    time_t deadline = time(NULL) + 30;
    for (;;) {
        fd_set rfds; FD_ZERO(&rfds); FD_SET(pipefd[0], &rfds);
        struct timeval tv; tv.tv_sec = 1; tv.tv_usec = 0;
        int sel = select(pipefd[0] + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) break;
        if (sel == 0) { if (time(NULL) >= deadline) { kill(pid, SIGKILL); break; } continue; }
        ssize_t got = read(pipefd[0], r->out + total, sizeof(r->out) - 1 - total);
        if (got <= 0) break;
        total += (size_t)got;
        if (total >= sizeof(r->out) - 1) break;
    }
    r->out[total] = '\0';
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    r->exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}
#endif

#ifdef _WIN32
static DWORD g_daemon_pid = 0;
#else
static pid_t g_daemon_pid = 0;
#endif

static void spawn_daemon_detached(const char *state_dir) {
#ifdef _WIN32
    char cmdline[1024];
    snprintf(cmdline, sizeof(cmdline), "\"%s\" --state-dir \"%s\"", VW_DAEMON_EXE_PATH, state_dir);
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                    NULL, NULL, &si, &pi);
    g_daemon_pid = pi.dwProcessId;
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
#else
    pid_t pid = fork();
    if (pid == 0) {
        setsid();
        execl(VW_DAEMON_EXE_PATH, VW_DAEMON_EXE_PATH, "--state-dir", state_dir, (char *)NULL);
        _exit(127);
    }
    g_daemon_pid = pid;
#endif
}

static void kill_daemon_forcefully(void) {
#ifdef _WIN32
    if (g_daemon_pid == 0) return;
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, g_daemon_pid);
    if (h) { TerminateProcess(h, 1); CloseHandle(h); }
#else
    if (g_daemon_pid <= 0) return;
    kill(g_daemon_pid, SIGKILL);
    int status = 0;
    waitpid(g_daemon_pid, &status, 0);
#endif
}

static int g_seq = 0;
static void make_tmpdir(char *out, size_t sz) {
#ifdef _WIN32
    char tmp[MAX_PATH];
    GetTempPathA((DWORD)sizeof(tmp), tmp);
    snprintf(out, sz, "%svw_ipcresp_%lu_%d", tmp, (unsigned long)GetCurrentProcessId(), ++g_seq);
    CreateDirectoryA(out, NULL);
#else
    snprintf(out, sz, "/tmp/vw_ipcresp_%d_%d", (int)getpid(), ++g_seq);
    mkdir(out, 0700);
#endif
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("TAP version 13\n");

    char state_dir[512];
    make_tmpdir(state_dir, sizeof(state_dir));

#ifdef _WIN32
    unsigned port = 48500u + (GetCurrentProcessId() % 1000u);
#else
    unsigned port = 48500u + ((unsigned)getpid() % 1000u);
#endif
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", port);

    /* Pre-seed only ipc_port — sync_interval_ms is deliberately left
     * unset so the daemon falls back to its real production default
     * (30000ms, DEFAULT_SYNC_MS in vw_daemon.c). Zero accounts means
     * zero watched roots, the exact condition TASK-00306 found. */
    {
        char conf_path[600];
        snprintf(conf_path, sizeof(conf_path), "%s/daemon.conf", state_dir);
        FILE *f = fopen(conf_path, "w");
        if (f) {
            fprintf(f, "ipc_port = %u\n", port);
            fclose(f);
        }
    }

    spawn_daemon_detached(state_dir);

    /* Wait (bounded) for the IPC port to actually come up. */
    int ready = 0;
    for (int i = 0; i < 40 && !ready; i++) {
        char *argv[] = { (char *)VW_CLI_EXE_PATH, (char *)"--ipc-port", port_str,
                          (char *)"status", NULL };
        run_result_t r;
        run_capture(argv, &r);
        if (r.exit_code == 0) ready = 1;
        else {
#ifdef _WIN32
            Sleep(250);
#else
            struct timespec ts = { 0, 250000000L };
            nanosleep(&ts, NULL);
#endif
        }
    }
    CHECK(ready, "daemon starts and IPC port becomes reachable via \"status\"");

    /* ── TC-1/TC-2: two "status" round trips moments apart, both prompt.
     *
     * Before TASK-00306's fix, the main loop's one call to
     * vw_watcher_wait(watcher, sync_interval_ms) blocked for the ENTIRE
     * 30000ms whenever (as here) there were zero watched roots, and the
     * IPC-accept step was only reached once per that wait — so whichever
     * of these two calls landed while the daemon was mid-wait could be
     * delayed by anywhere up to the full 30s, non-deterministically. The
     * 5000ms bound below is generous CI slack (subprocess spawn +
     * connect overhead included) while still being decisively far below
     * that 30s worst case — the actual fix bounds each wait chunk to
     * VW_DAEMON_MAX_WAIT_CHUNK_MS (1000ms, vw_daemon.c). */
    for (int i = 1; i <= 2; i++) {
        char *argv[] = { (char *)VW_CLI_EXE_PATH, (char *)"--ipc-port", port_str,
                          (char *)"status", NULL };
        run_result_t r;
        uint64_t start = now_ms();
        run_capture(argv, &r);
        uint64_t elapsed = now_ms() - start;

        char desc[128];
        snprintf(desc, sizeof(desc), "status round trip #%d exits 0", i);
        CHECK(r.exit_code == 0, desc);
        snprintf(desc, sizeof(desc),
                 "status round trip #%d completes promptly (<5000ms, was %llums)",
                 i, (unsigned long long)elapsed);
        CHECK(elapsed < 5000, desc);
    }

    kill_daemon_forcefully();

    printf("1..%d\n", g_count);
    return g_failed > 0 ? 1 : 0;
}
