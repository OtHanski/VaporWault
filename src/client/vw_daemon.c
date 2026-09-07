#include "vw_daemon.h"
#include "vw_cache.h"
#include "vw_sync.h"
#include "vw_watch.h"
#include "vw_ipc.h"
#include "vw_client_core.h"
#include "vw_vault.h"
#include "../core/vw_fs.h"
#include "../core/vw_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#  include <windows.h>
#  include <io.h>
#  include <fcntl.h>
#  define getpid (int)GetCurrentProcessId
#else
#  include <unistd.h>
#  include <signal.h>
#  include <sys/stat.h>
#  include <fcntl.h>
#endif

/* ── Defaults ────────────────────────────────────────────────────────────── */

#define DEFAULT_PORT         4430u
#define DEFAULT_IPC_PORT     VW_IPC_DEFAULT_PORT
#define DEFAULT_SYNC_MS      30000u
#define SESSION_TOKEN_FILE   "session.tok"
#define LOGIN_TOKEN_FILE     "login_token.bin"
#define PID_FILE             "daemon.pid"
#define LOG_FILE             "daemon.log"
#define CONFIG_FILE          "daemon.conf"
#define LOG_ROTATE_BYTES     (10 * 1024 * 1024L)

/* Multi-account (TASK-161): {state_dir}/accounts/<account_id>/, each
 * holding its own account.conf/cache.db/sync_folders.db/session.tok/
 * offline_queue.db — see vw_daemon.h's header comment for the full layout. */
#define ACCOUNTS_DIR         "accounts"
#define ACCOUNT_CONFIG_FILE  "account.conf"
#define MAX_ACCOUNTS         32u

/* ── Logging ─────────────────────────────────────────────────────────────── */

typedef enum { LOG_ERROR = 0, LOG_WARN = 1, LOG_INFO = 2, LOG_DEBUG = 3 } log_lvl_t;

static FILE      *g_log_fp    = NULL;
static log_lvl_t  g_log_level = LOG_INFO;
static char       g_log_path[512];
static long       g_log_bytes = 0;
static int        g_log_to_file = 0;

static const char *lvl_str(log_lvl_t l) {
    switch (l) {
    case LOG_ERROR: return "ERROR";
    case LOG_WARN:  return "WARN ";
    case LOG_INFO:  return "INFO ";
    default:        return "DEBUG";
    }
}

static void log_rotate(void) {
    if (!g_log_fp || !g_log_to_file) return;
    fclose(g_log_fp); g_log_fp = NULL;
    /* Remove .2, rename .1 → .2, current → .1 */
    char p1[528], p2[528];
    snprintf(p1, sizeof(p1), "%s.1", g_log_path);
    snprintf(p2, sizeof(p2), "%s.2", g_log_path);
    remove(p2);
    rename(p1, p2);
    rename(g_log_path, p1);
    g_log_fp = fopen(g_log_path, "w");
    g_log_bytes = 0;
}

static void vw_log(log_lvl_t level, const char *fmt, ...) {
    if (level > g_log_level) return;

    time_t t = time(NULL);
    struct tm *tm_info;
#ifdef _WIN32
    struct tm tm_buf;
    localtime_s(&tm_buf, &t);
    tm_info = &tm_buf;
#else
    struct tm tm_buf;
    localtime_r(&t, &tm_buf);
    tm_info = &tm_buf;
#endif
    char ts[24];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);

    FILE *fp = g_log_to_file ? g_log_fp : stderr;
    if (!fp) fp = stderr;

    va_list ap;
    va_start(ap, fmt);
    int written = fprintf(fp, "[%s] %s ", ts, lvl_str(level));
    written += vfprintf(fp, fmt, ap);
    written += fprintf(fp, "\n");
    va_end(ap);
    fflush(fp);

    if (g_log_to_file) {
        g_log_bytes += written;
        if (g_log_bytes >= LOG_ROTATE_BYTES) log_rotate();
    }
}

static void log_init(const char *state_dir, int to_file) {
    const char *env = getenv("VW_LOG_LEVEL");
    if (env) {
        if (strcmp(env, "ERROR") == 0) g_log_level = LOG_ERROR;
        else if (strcmp(env, "WARN")  == 0) g_log_level = LOG_WARN;
        else if (strcmp(env, "DEBUG") == 0) g_log_level = LOG_DEBUG;
        else g_log_level = LOG_INFO;
    }
    g_log_to_file = to_file;
    if (to_file && state_dir) {
        { size_t _sl = strlen(state_dir), _fl = sizeof(LOG_FILE) - 1;
          if (_sl + 1 + _fl + 1 > sizeof(g_log_path)) _sl = sizeof(g_log_path) - _fl - 2;
          memcpy(g_log_path, state_dir, _sl); g_log_path[_sl] = '/';
          memcpy(g_log_path + _sl + 1, LOG_FILE, _fl + 1); }
        g_log_fp = fopen(g_log_path, "a");
        if (!g_log_fp) {
            g_log_fp = NULL;
            g_log_to_file = 0;
        }
    }
}

/* ── Shutdown flag ───────────────────────────────────────────────────────── */

#ifdef _WIN32
static volatile int g_shutdown = 0;
static BOOL WINAPI ctrl_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        g_shutdown = 1; return TRUE;
    }
    return FALSE;
}
#else
static volatile sig_atomic_t g_shutdown = 0;
static void sig_handler(int sig) { (void)sig; g_shutdown = 1; }
#endif

static void install_signal_handlers(void) {
#ifdef _WIN32
    SetConsoleCtrlHandler(ctrl_handler, TRUE);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sa.sa_flags   = SA_RESTART;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
#endif
}

/* ── PID file ────────────────────────────────────────────────────────────── */

static char g_pid_path[512];

static int pid_is_running(int pid) {
#ifdef _WIN32
    HANDLE h = OpenProcess(SYNCHRONIZE, FALSE, (DWORD)pid);
    if (!h) return 0;
    CloseHandle(h); return 1;
#else
    return kill(pid, 0) == 0;
#endif
}

static vw_err_t pid_file_create(const char *state_dir) {
    { size_t _sl = strlen(state_dir), _fl = sizeof(PID_FILE) - 1;
      if (_sl + 1 + _fl + 1 > sizeof(g_pid_path)) _sl = sizeof(g_pid_path) - _fl - 2;
      memcpy(g_pid_path, state_dir, _sl); g_pid_path[_sl] = '/';
      memcpy(g_pid_path + _sl + 1, PID_FILE, _fl + 1); }

    /* Check if a running daemon already holds the PID file */
    FILE *fp = fopen(g_pid_path, "r");
    if (fp) {
        int old_pid = 0;
        if (fscanf(fp, "%d", &old_pid) != 1) old_pid = 0;
        fclose(fp);
        if (old_pid > 0 && pid_is_running(old_pid)) {
            vw_log(LOG_ERROR, "daemon already running (pid %d)", old_pid);
            return VW_ERR_ALREADY_EXISTS;
        }
        remove(g_pid_path); /* stale pid file */
    }

    /* Atomically create the PID file (O_EXCL) */
#ifdef _WIN32
    HANDLE h = CreateFileA(g_pid_path, GENERIC_WRITE, 0, NULL,
                            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return VW_ERR_IO;
    char buf[16];
    DWORD n = (DWORD)snprintf(buf, sizeof(buf), "%d\n", getpid());
    DWORD written;
    WriteFile(h, buf, n, &written, NULL);
    CloseHandle(h);
#else
    int fd = open(g_pid_path, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0) return VW_ERR_IO;
    char buf[16];
    int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
    if (write(fd, buf, (size_t)n) != n) { close(fd); return VW_ERR_IO; }
    close(fd);
#endif
    return VW_OK;
}

static void pid_file_remove(void) {
    if (g_pid_path[0]) remove(g_pid_path);
}

/* ── Session token ───────────────────────────────────────────────────────── */

static vw_err_t tok_load(const char *state_dir, uint8_t out_tok[VW_TOKEN_BYTES]) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", state_dir, SESSION_TOKEN_FILE);

#ifndef _WIN32
    struct stat st;
    if (stat(path, &st) != 0) return VW_ERR_NOT_FOUND;
    if ((st.st_mode & 0777) != 0600) {
        vw_log(LOG_WARN, "session.tok has wrong permissions (%03o) — ignoring",
               (unsigned)(st.st_mode & 0777));
        return VW_ERR_NOT_FOUND;
    }
#endif

    void *data = NULL; size_t len = 0;
    vw_err_t err = vw_fs_read_file(path, &data, &len);
    if (err != VW_OK) return err;
    if (len < VW_TOKEN_BYTES) { free(data); return VW_ERR_NOT_FOUND; }
    memcpy(out_tok, data, VW_TOKEN_BYTES);
    free(data);
    return VW_OK;
}

static vw_err_t tok_save(const char *state_dir, const uint8_t tok[VW_TOKEN_BYTES]) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", state_dir, SESSION_TOKEN_FILE);
#ifdef _WIN32
    /* Write file; restrict ACL to current user (simplified: use normal file) */
    return vw_fs_atomic_write(path, tok, VW_TOKEN_BYTES);
#else
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return VW_ERR_IO;
    vw_err_t err = VW_OK;
    if ((size_t)write(fd, tok, VW_TOKEN_BYTES) != VW_TOKEN_BYTES) err = VW_ERR_IO;
    close(fd);
    return err;
#endif
}

/* ── Login token (TASK-173) ───────────────────────────────────────────────
 * SHA-256(password) — the exact 32 bytes AUTH_REQUEST sends on the wire,
 * never the raw password — retained so an automatic, unattended fallback
 * connect (vw_client_connect_with_hash) can authenticate fresh against a
 * replica without a stored SESSION_RESUME token, which is meaningless on
 * any server other than the one that issued it. Same sensitivity class
 * and on-disk protection as session.tok (mode 0600, same "wrong
 * permissions -> ignore" load-time check) — this is not a new class of
 * persisted secret, just a second file of the same kind. Written whenever
 * ACCOUNT_ADD_REQ supplies a password (new account or re-authentication);
 * never written for a plain reconnect (which only ever has a session
 * token, not a password, by then). */

static vw_err_t login_token_load(const char *account_dir, uint8_t out_tok[VW_TOKEN_BYTES]) {
    /* 700, not 512: account_dir is a char[600] in every real caller (see
     * scan_accounts_cb/account_ctx_open_existing) — GCC's Release-mode
     * -Wformat-truncation can see that bound through inlining and correctly
     * flags 512 as too small for account_dir's worst case (599) + "/" +
     * the longest filename constant + NUL. */
    char path[700];
    snprintf(path, sizeof(path), "%s/%s", account_dir, LOGIN_TOKEN_FILE);

#ifndef _WIN32
    struct stat st;
    if (stat(path, &st) != 0) return VW_ERR_NOT_FOUND;
    if ((st.st_mode & 0777) != 0600) {
        vw_log(LOG_WARN, "login_token.bin has wrong permissions (%03o) — ignoring",
               (unsigned)(st.st_mode & 0777));
        return VW_ERR_NOT_FOUND;
    }
#endif

    void *data = NULL; size_t len = 0;
    vw_err_t err = vw_fs_read_file(path, &data, &len);
    if (err != VW_OK) return err;
    if (len < VW_TOKEN_BYTES) { free(data); return VW_ERR_NOT_FOUND; }
    memcpy(out_tok, data, VW_TOKEN_BYTES);
    free(data);
    return VW_OK;
}

static vw_err_t login_token_save(const char *account_dir, const uint8_t tok[VW_TOKEN_BYTES]) {
    /* See login_token_load's identical comment on why 700, not 512. */
    char path[700];
    snprintf(path, sizeof(path), "%s/%s", account_dir, LOGIN_TOKEN_FILE);
#ifdef _WIN32
    return vw_fs_atomic_write(path, tok, VW_TOKEN_BYTES);
#else
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return VW_ERR_IO;
    vw_err_t err = VW_OK;
    if ((size_t)write(fd, tok, VW_TOKEN_BYTES) != VW_TOKEN_BYTES) err = VW_ERR_IO;
    close(fd);
    return err;
#endif
}

/* ── Config parser ───────────────────────────────────────────────────────── */

static void cfg_defaults(vw_daemon_cfg_t *c) {
    c->ipc_port        = (uint16_t)DEFAULT_IPC_PORT;
    c->sync_interval_ms = DEFAULT_SYNC_MS;
}

static void cfg_apply_kv(vw_daemon_cfg_t *c, const char *key, const char *val) {
    if (strcmp(key, "ipc_port")   == 0)
        c->ipc_port = (uint16_t)strtoul(val, NULL, 10);
    else if (strcmp(key, "sync_interval_ms") == 0)
        c->sync_interval_ms = (uint32_t)strtoul(val, NULL, 10);
    /* Unknown keys are silently ignored (forward-compat) — this also
     * quietly absorbs a pre-TASK-161 daemon.conf's now-relocated
     * server_host/server_port/ca_cert_pem_path/username keys without
     * needing an explicit migration: they're simply dropped, and the
     * daemon starts with zero configured accounts until `account add`
     * (vapourwault-cli) or the GUI's "Add account" flow is used. This
     * project is pre-1.0 with no real migration story needed yet. */
}

vw_err_t vw_daemon_cfg_load(const char *state_dir, vw_daemon_cfg_t *out) {
    if (!state_dir || !out) return VW_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));
    snprintf(out->state_dir, sizeof(out->state_dir), "%s", state_dir);
    cfg_defaults(out);

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", state_dir, CONFIG_FILE);
    FILE *fp = fopen(path, "r");
    if (!fp) return VW_OK; /* no config → all defaults */

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        /* Strip trailing newline */
        size_t ln = strlen(line);
        while (ln > 0 && (line[ln-1] == '\n' || line[ln-1] == '\r'))
            line[--ln] = '\0';
        /* Skip blank lines and comments */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#') continue;
        /* Find '=' */
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = p; char *val = eq + 1;
        /* Trim key */
        size_t kl = strlen(key);
        while (kl > 0 && (key[kl-1] == ' ' || key[kl-1] == '\t')) key[--kl] = '\0';
        /* Trim val leading space */
        while (*val == ' ' || *val == '\t') val++;
        cfg_apply_kv(out, key, val);
    }
    fclose(fp);
    return VW_OK;
}

vw_err_t vw_daemon_cfg_write_defaults(const char *state_dir,
                                       const vw_daemon_cfg_t *cfg) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", state_dir, CONFIG_FILE);
    FILE *fp = fopen(path, "r");
    if (fp) { fclose(fp); return VW_OK; } /* already exists */

    fp = fopen(path, "w");
    if (!fp) return VW_ERR_IO;
    fprintf(fp, "# VaporWault daemon configuration\n");
    fprintf(fp, "ipc_port        = %u\n", (unsigned)cfg->ipc_port);
    fprintf(fp, "sync_interval_ms = %u\n", (unsigned)cfg->sync_interval_ms);
    fclose(fp);
    return VW_OK;
}

/* ── Per-account config (TASK-161) ────────────────────────────────────────
 * {state_dir}/accounts/<account_id>/account.conf — same simple INI format
 * as daemon.conf above, one file per account. Not meant to be hand-edited;
 * written by account_ctx_create() below in response to
 * VW_IPC_ACCOUNT_ADD_REQ. */

/* TASK-192/193: one sync folder's selective-sync exclude patterns, as
 * persisted in account.conf (repeatable "exclude = <local_root>|<pattern>"
 * lines — see account_cfg_apply_kv/_save below) and mirrored into the
 * live vw_sync_ctx_t (vw_sync_set_folder_excludes) whenever this account
 * comes up or the rules change. account.conf, unlike sync_folders.db, is
 * a plain re-serialized-in-full text file, so this can be a genuinely
 * variable-length list with no on-disk-format/migration concern — see
 * TASK-193's implementation notes for why that rules out storing this on
 * vw_sync_folder_t itself (a fixed 1040-byte record with zero reserved
 * bytes to spare). */
typedef struct {
    char      local_root[512];
    char    **patterns;
    uint32_t  count;
} vw_folder_excludes_cfg_t;

typedef struct {
    uint32_t account_id;
    char     label[64];
    char     server_host[256];
    uint16_t server_port;
    char     ca_cert_pem_path[512];
    char     username[64];
    /* TASK-173: optional read-only fallback server — a vw_cluster replica
     * of this same account's primary. Unset (fallback_host[0] == '\0') =
     * today's behavior, fully unchanged; this is opt-in per account, never
     * implicitly derived from the primary's own settings. */
    char     fallback_host[256];
    uint16_t fallback_port;
    char     fallback_ca_cert_pem_path[512];
    vw_folder_excludes_cfg_t *folder_excludes;
    uint32_t                  folder_excludes_count;
} vw_account_cfg_t;

static vw_folder_excludes_cfg_t *account_cfg_find_excludes(vw_account_cfg_t *c,
                                                            const char *local_root) {
    for (uint32_t i = 0; i < c->folder_excludes_count; i++)
        if (strcmp(c->folder_excludes[i].local_root, local_root) == 0)
            return &c->folder_excludes[i];
    return NULL;
}

/* Frees every pattern/array owned by c->folder_excludes and resets it to
 * empty — call exactly once per vw_account_cfg_t before it goes out of
 * scope or is overwritten wholesale (e.g. `existing->cfg = acfg;` in
 * ACCOUNT_ADD_REQ — see that handler's own carry-over comment for why
 * re-auth must copy the pointer across first rather than free it). */
static void account_cfg_free_excludes(vw_account_cfg_t *c) {
    for (uint32_t i = 0; i < c->folder_excludes_count; i++) {
        vw_folder_excludes_cfg_t *fe = &c->folder_excludes[i];
        for (uint32_t j = 0; j < fe->count; j++) free(fe->patterns[j]);
        free(fe->patterns);
    }
    free(c->folder_excludes);
    c->folder_excludes = NULL;
    c->folder_excludes_count = 0;
}

/* Appends pattern to local_root's rule list, creating the list if this is
 * the first rule for that folder. Used only while loading account.conf
 * line-by-line (account_cfg_apply_kv) — the live "replace this folder's
 * whole rule set" operation (VW_IPC_FOLDER_SET_EXCLUDES_REQ) clears any
 * existing entry first via account_cfg_free_excludes on just that one
 * folder's slot, see the handler itself. */
static vw_err_t account_cfg_add_exclude(vw_account_cfg_t *c, const char *local_root,
                                         const char *pattern) {
    vw_folder_excludes_cfg_t *fe = account_cfg_find_excludes(c, local_root);
    if (!fe) {
        vw_folder_excludes_cfg_t *tmp = realloc(c->folder_excludes,
            (c->folder_excludes_count + 1u) * sizeof(*tmp));
        if (!tmp) return VW_ERR_OOM;
        c->folder_excludes = tmp;
        fe = &c->folder_excludes[c->folder_excludes_count++];
        memset(fe, 0, sizeof(*fe));
        snprintf(fe->local_root, sizeof(fe->local_root), "%s", local_root);
    }
    char **tmp = realloc(fe->patterns, (fe->count + 1u) * sizeof(char *));
    if (!tmp) return VW_ERR_OOM;
    fe->patterns = tmp;
    fe->patterns[fe->count] = strdup(pattern);
    if (!fe->patterns[fe->count]) return VW_ERR_OOM;
    fe->count++;
    return VW_OK;
}

static void account_cfg_apply_kv(vw_account_cfg_t *c, const char *key, const char *val) {
    if (strcmp(key, "label") == 0)
        snprintf(c->label, sizeof(c->label), "%s", val);
    else if (strcmp(key, "server_host") == 0)
        snprintf(c->server_host, sizeof(c->server_host), "%s", val);
    else if (strcmp(key, "server_port") == 0)
        c->server_port = (uint16_t)strtoul(val, NULL, 10);
    else if (strcmp(key, "ca_cert_pem_path") == 0)
        snprintf(c->ca_cert_pem_path, sizeof(c->ca_cert_pem_path), "%s", val);
    else if (strcmp(key, "username") == 0)
        snprintf(c->username, sizeof(c->username), "%s", val);
    else if (strcmp(key, "fallback_host") == 0)
        snprintf(c->fallback_host, sizeof(c->fallback_host), "%s", val);
    else if (strcmp(key, "fallback_port") == 0)
        c->fallback_port = (uint16_t)strtoul(val, NULL, 10);
    else if (strcmp(key, "fallback_ca_cert_pem_path") == 0)
        snprintf(c->fallback_ca_cert_pem_path, sizeof(c->fallback_ca_cert_pem_path), "%s", val);
    else if (strcmp(key, "exclude") == 0) {
        /* "exclude = <local_root>|<pattern>" — split on the first '|'.
         * local_root itself is a filesystem path and may legitimately
         * contain many characters but never '|' in practice on any
         * platform this project targets; a malformed line (no '|') is
         * silently ignored rather than corrupting some other field,
         * matching this function's existing "unknown key -> no-op"
         * posture for the rest of this parser. */
        const char *bar = strchr(val, '|');
        if (bar && bar != val) {
            char root[512];
            size_t rl = (size_t)(bar - val);
            if (rl >= sizeof(root)) rl = sizeof(root) - 1u;
            memcpy(root, val, rl); root[rl] = '\0';
            (void)account_cfg_add_exclude(c, root, bar + 1);
        }
    }
}

/* accounts_dir is {state_dir}/accounts/<account_id> (no trailing slash). */
static vw_err_t account_cfg_load(const char *account_dir, vw_account_cfg_t *out) {
    /* See login_token_load's comment (this file) on why 700, not 600. */
    char path[700];
    snprintf(path, sizeof(path), "%s/%s", account_dir, ACCOUNT_CONFIG_FILE);
    FILE *fp = fopen(path, "r");
    if (!fp) return VW_ERR_NOT_FOUND;

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        size_t ln = strlen(line);
        while (ln > 0 && (line[ln-1] == '\n' || line[ln-1] == '\r'))
            line[--ln] = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#') continue;
        char *eq = strchr(p, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = p; char *val = eq + 1;
        size_t kl = strlen(key);
        while (kl > 0 && (key[kl-1] == ' ' || key[kl-1] == '\t')) key[--kl] = '\0';
        while (*val == ' ' || *val == '\t') val++;
        account_cfg_apply_kv(out, key, val);
    }
    fclose(fp);
    return VW_OK;
}

static vw_err_t account_cfg_save(const char *account_dir, const vw_account_cfg_t *cfg) {
    /* See login_token_load's comment (this file) on why 700, not 600. */
    char path[700];
    snprintf(path, sizeof(path), "%s/%s", account_dir, ACCOUNT_CONFIG_FILE);
    FILE *fp = fopen(path, "w");
    if (!fp) return VW_ERR_IO;
    fprintf(fp, "# VaporWault account configuration — managed by the daemon, do not hand-edit\n");
    fprintf(fp, "label            = %s\n", cfg->label);
    fprintf(fp, "server_host      = %s\n", cfg->server_host);
    fprintf(fp, "server_port      = %u\n", (unsigned)cfg->server_port);
    fprintf(fp, "ca_cert_pem_path = %s\n", cfg->ca_cert_pem_path);
    fprintf(fp, "username         = %s\n", cfg->username);
    fprintf(fp, "fallback_host              = %s\n", cfg->fallback_host);
    fprintf(fp, "fallback_port              = %u\n", (unsigned)cfg->fallback_port);
    fprintf(fp, "fallback_ca_cert_pem_path  = %s\n", cfg->fallback_ca_cert_pem_path);
    for (uint32_t i = 0; i < cfg->folder_excludes_count; i++) {
        const vw_folder_excludes_cfg_t *fe = &cfg->folder_excludes[i];
        for (uint32_t j = 0; j < fe->count; j++)
            fprintf(fp, "exclude          = %s|%s\n", fe->local_root, fe->patterns[j]);
    }
    fclose(fp);
    return VW_OK;
}

/* ── IPC message helpers ─────────────────────────────────────────────────── */

static void ipc_send_u32(vw_ipc_conn_t *conn, vw_ipc_msg_t type, uint32_t code) {
    uint8_t buf[4];
    vw_write_u32le(buf, code);
    vw_ipc_send(conn, type, buf, 4);
}

/* ── Vault registry (TASK-100) ────────────────────────────────────────────
 * The daemon's IPC loop is single-threaded (handle_ipc_client is called
 * synchronously from vw_daemon_run's main loop — see that function), so
 * this needs no locking, same as every other piece of `dc` state. Holds
 * unlocked vw_vault_t handles (unwrapped VK in memory) for the daemon
 * process's lifetime, exactly mirroring how dc->sess holds the account
 * session for the same lifetime — the passphrase itself is never stored,
 * only used transiently to derive the KEK during VAULT_CREATE/_UNLOCK.
 */
typedef struct {
    uint64_t    vault_id;
    vw_vault_t *vault;
} daemon_vault_entry_t;

typedef struct {
    daemon_vault_entry_t *entries;
    size_t                count;
    size_t                cap;
} daemon_vault_registry_t;

static vw_vault_t *vault_registry_find(daemon_vault_registry_t *reg, uint64_t vault_id) {
    for (size_t i = 0; i < reg->count; i++)
        if (reg->entries[i].vault_id == vault_id) return reg->entries[i].vault;
    return NULL;
}

/* Takes ownership of `vault` (caller must not vw_vault_close it itself).
 * If vault_id is already registered, the old handle is closed and
 * replaced — VAULT_CREATE/_UNLOCK are idempotent from the caller's view. */
static vw_err_t vault_registry_put(daemon_vault_registry_t *reg, uint64_t vault_id,
                                    vw_vault_t *vault) {
    for (size_t i = 0; i < reg->count; i++) {
        if (reg->entries[i].vault_id == vault_id) {
            vw_vault_close(reg->entries[i].vault);
            reg->entries[i].vault = vault;
            return VW_OK;
        }
    }
    if (reg->count >= reg->cap) {
        size_t new_cap = reg->cap ? reg->cap * 2 : 4;
        daemon_vault_entry_t *ne = realloc(reg->entries, new_cap * sizeof(*ne));
        if (!ne) {
            /* TASK-106 review finding: this function's contract is
             * "takes ownership unconditionally" — honor that even on
             * this failure path, or the caller (which trusts the
             * contract and never closes `vault` itself) leaks a live
             * unwrapped VK. */
            vw_vault_close(vault);
            return VW_ERR_OOM;
        }
        reg->entries = ne;
        reg->cap = new_cap;
    }
    reg->entries[reg->count].vault_id = vault_id;
    reg->entries[reg->count].vault    = vault;
    reg->count++;
    return VW_OK;
}

static void vault_registry_close_all(daemon_vault_registry_t *reg) {
    for (size_t i = 0; i < reg->count; i++)
        vw_vault_close(reg->entries[i].vault);
    free(reg->entries);
    reg->entries = NULL;
    reg->count = reg->cap = 0;
}

/* ── Account contexts (TASK-161) ──────────────────────────────────────────
 * One per configured account. The daemon's IPC loop and sync loop are both
 * single-threaded (handle_ipc_client and the round-robin sync pass in
 * vw_daemon_run are called synchronously from the same main loop — see that
 * function), so this array needs no locking, same reasoning as the vault
 * registry above (now one of this struct's own fields, no longer global).
 */
/* TASK-173: which server `sess` is actually connected to right now. */
typedef enum {
    VW_ACCOUNT_CONN_OFFLINE  = 0,  /* sess == NULL */
    VW_ACCOUNT_CONN_PRIMARY  = 1,
    VW_ACCOUNT_CONN_FALLBACK = 2,  /* read-only — see vw_sync_set_read_only */
} vw_account_conn_mode_t;

typedef struct {
    uint32_t   account_id;
    char       account_dir[600];  /* {state_dir}/accounts/<account_id> */
    vw_account_cfg_t         cfg;
    vw_cache_t              *cache;
    vw_sync_ctx_t           *sync_ctx;
    vw_client_sess_t        *sess;      /* NULL if currently offline */
    vw_account_conn_mode_t   conn_mode; /* meaningful only while sess != NULL */
    daemon_vault_registry_t  vaults;    /* TASK-100: unlocked vw_vault_t handles */
    int64_t    last_sync_at;
    uint32_t   error_count;
    /* TASK-173: SHA-256(password), retained only in memory + login_token.bin
     * (never the raw password) so an automatic fallback connect can
     * authenticate without user interaction. have_login_token == 0 means no
     * password has been supplied this process (or on disk) yet — a fallback
     * is configured but simply can't be used automatically until the next
     * ACCOUNT_ADD_REQ (re-authentication) supplies one. */
    uint8_t    login_token[VW_TOKEN_BYTES];
    int        have_login_token;
} vw_account_ctx_t;

typedef struct {
    vw_account_ctx_t *accounts;
    size_t            count;
    size_t            cap;
    uint32_t          next_account_id;  /* monotonic; never reused */
} account_registry_t;

static vw_account_ctx_t *account_find(account_registry_t *reg, uint32_t account_id) {
    for (size_t i = 0; i < reg->count; i++)
        if (reg->accounts[i].account_id == account_id) return &reg->accounts[i];
    return NULL;
}

/*
 * TASK-173: true while this account is connected to its read-only
 * fallback rather than the primary. Callers use this to reject
 * write-shaped IPC requests (SHARE_GRANT/REVOKE, LINK_CREATE/REVOKE,
 * FILE_MKDIR, VAULT_CREATE, VAULT_UPLOAD) with VW_ERR_READ_ONLY_FALLBACK
 * rather than actually attempting them against the fallback session —
 * these are synchronous, user-initiated requests with no offline-queue
 * equivalent (unlike the automatic sync engine's own file actions, which
 * vw_sync_set_read_only already handles). Only meaningful while a->sess
 * is non-NULL; callers must still check that separately (a fully offline
 * account is VW_ERR_AUTH_REQUIRED, not this).
 */
static int account_is_read_only(const vw_account_ctx_t *a) {
    return a->conn_mode == VW_ACCOUNT_CONN_FALLBACK;
}

/* Appends a zero-initialized slot and returns a pointer to it, or NULL on
 * OOM. The returned pointer is only valid until the next account_add_slot
 * call (the backing array may realloc) — callers must re-look-up via
 * account_find after that, never hold this pointer across one. */
static vw_account_ctx_t *account_add_slot(account_registry_t *reg) {
    if (reg->count >= reg->cap) {
        size_t new_cap = reg->cap ? reg->cap * 2 : 4;
        vw_account_ctx_t *ne = realloc(reg->accounts, new_cap * sizeof(*ne));
        if (!ne) return NULL;
        reg->accounts = ne;
        reg->cap = new_cap;
    }
    vw_account_ctx_t *a = &reg->accounts[reg->count++];
    memset(a, 0, sizeof(*a));
    return a;
}

/* {state_dir}/accounts/<account_id> — no trailing slash. */
static void account_dir_path(const char *state_dir, uint32_t account_id,
                              char *out, size_t out_size) {
    snprintf(out, out_size, "%s/%s/%u", state_dir, ACCOUNTS_DIR, (unsigned)account_id);
}

/* Deletes every file directly inside dir, then the (now-empty) directory
 * itself. accounts/<id>/ is deliberately kept flat (account.conf, cache.db,
 * sync_folders.db, session.tok, offline_queue.db — see vw_daemon.h's header
 * comment) specifically so this doesn't need general recursive-delete
 * logic; vw_fs.h has no directory-removal primitive at all today (only
 * vw_fs_delete for files), so the final rmdir/RemoveDirectory step is done
 * here directly rather than adding one for this single call site. */
static int delete_dir_entry_cb(const char *name, void *userdata) {
    const char *dir = (const char *)userdata;
    char path[700];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    (void)vw_fs_delete(path);
    return 0;
}

static void delete_account_dir(const char *account_dir) {
    (void)vw_fs_list_dir(account_dir, delete_dir_entry_cb, (void *)account_dir);
#ifdef _WIN32
    RemoveDirectoryA(account_dir);
#else
    rmdir(account_dir);
#endif
}

/* ── IPC dispatch ────────────────────────────────────────────────────────── */

typedef struct {
    account_registry_t *accounts;
    vw_watcher_t        *watcher;
    int                 *sync_now_flag;
    int                 *shutdown_flag;
    const char          *state_dir;   /* daemon-global root, for account_dir_path */
} ipc_dispatch_ctx_t;

/* otp_cb userdata for VW_IPC_ACCOUNT_ADD_REQ: hands a pre-supplied OTP code
 * (if any) to vw_client_connect() synchronously, since the whole login
 * round-trip (including 2FA) happens within a single ACCOUNT_ADD_REQ/RESP
 * exchange — the caller re-issues ACCOUNT_ADD_REQ with the OTP filled in
 * (and the same account_id, if this was a re-authentication) if the first
 * attempt reports VW_ERR_AUTH_2FA_REQUIRED. */
typedef struct { const char *otp; uint16_t otp_len; } login_otp_ctx_t;

static vw_err_t login_otp_cb(void *userdata, char *otp_buf, uint16_t *otp_len) {
    login_otp_ctx_t *c = (login_otp_ctx_t *)userdata;
    if (!c->otp || c->otp_len == 0) return VW_ERR_AUTH_2FA_REQUIRED;
    uint16_t n = c->otp_len > 8u ? 8u : c->otp_len;
    memcpy(otp_buf, c->otp, n);
    *otp_len = n;
    return VW_OK;
}

static void handle_ipc_client(vw_ipc_conn_t *conn, ipc_dispatch_ctx_t *dc) {
    /* Set 1-second recv timeout */
    vw_ipc_conn_set_recv_timeout(conn, 1000);

    uint8_t buf[65536];
    vw_ipc_msg_t type;
    uint32_t plen = 0;
    vw_err_t err = vw_ipc_recv(conn, &type, buf, sizeof(buf), &plen);
    if (err != VW_OK) {
        vw_log(LOG_DEBUG, "IPC client recv failed (rc=%d) — disconnected or timed out", (int)err);
        /* buf may hold a partially-received password (LOGIN_REQ) even on
         * failure — zero it on this early-return path too. */
        memset(buf, 0, sizeof(buf));
        return;
    }

    switch (type) {

    case VW_IPC_STATUS_REQ: {
        /* Daemon-global aggregate across every configured account
         * (TASK-161) — see VW_IPC_ACCOUNT_LIST_RESP for the per-account
         * breakdown of every field here. */
        uint8_t any_connected = 0, any_syncing = 0, any_on_fallback = 0;
        int64_t max_last_sync = 0;
        uint32_t total_pending = 0, total_errors = 0, total_perm_denied = 0;
        uint32_t total_folders = 0, paused_folders = 0;
        for (size_t i = 0; i < dc->accounts->count; i++) {
            vw_account_ctx_t *a = &dc->accounts->accounts[i];
            if (a->sess) any_connected = 1;
            if (a->conn_mode == VW_ACCOUNT_CONN_FALLBACK) any_on_fallback = 1;
            uint64_t bd = 0, bt = 0;
            vw_sync_get_progress(a->sync_ctx, &bd, &bt);
            if (bd < bt) any_syncing = 1;
            if (a->last_sync_at > max_last_sync) max_last_sync = a->last_sync_at;
            total_pending += vw_sync_pending_count(a->sync_ctx);
            total_errors  += a->error_count;
            total_perm_denied += vw_sync_permission_denied_count(a->sync_ctx);
            /* "all sync paused" (below) is now computed straight from every
             * account's own folder-level paused bits (TASK-161) rather than
             * a separate tracked flag — PAUSE_REQ/RESUME_REQ are per-account
             * now, so there is no single daemon-global toggle left to set. */
            vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
            vw_cache_folder_list(a->cache, &folders, &nf);
            total_folders += nf;
            for (uint32_t j = 0; j < nf; j++) if (folders[j].paused) paused_folders++;
            free(folders);
        }
        uint8_t resp[29]; uint32_t off = 0;
        resp[off++] = any_connected;
        resp[off++] = any_syncing;
        resp[off++] = (total_folders > 0 && paused_folders == total_folders) ? 1 : 0;
        resp[off++] = 0;                        /* _pad */
        vw_write_u64le(resp + off, (uint64_t)max_last_sync); off += 8;
        vw_write_u32le(resp + off, total_pending); off += 4; /* pending_uploads */
        vw_write_u32le(resp + off, 0);       off += 4; /* pending_downloads */
        vw_write_u32le(resp + off, total_errors); off += 4;
        /* TASK-113: distinct from error_count above — a permission-denied
         * shared-folder auto-mkdir is its own specific signal, not lumped
         * in with every other kind of action failure. */
        vw_write_u32le(resp + off, total_perm_denied); off += 4;
        /* TASK-173: trailing field, same pattern as permission_denied_count
         * above — 1 if at least one account is currently on its read-only
         * fallback rather than the primary. */
        resp[off++] = any_on_fallback;
        vw_ipc_send(conn, VW_IPC_STATUS_RESP, resp, off);
        break;
    }

    case VW_IPC_SYNC_NOW_REQ:
        *dc->sync_now_flag = 1;
        ipc_send_u32(conn, VW_IPC_SYNC_NOW_RESP, 0);
        break;

    case VW_IPC_ACCOUNT_LIST_REQ: {
        uint8_t *rbuf = malloc(65536);
        if (!rbuf) { vw_ipc_send(conn, VW_IPC_ACCOUNT_LIST_RESP, NULL, 0); break; }
        uint32_t roff = 4;
        uint32_t written = 0;
        for (size_t i = 0; i < dc->accounts->count && roff + 900 < 65536; i++) {
            vw_account_ctx_t *a = &dc->accounts->accounts[i];
            vw_write_u32le(rbuf + roff, a->account_id); roff += 4;
            uint16_t llen = (uint16_t)strnlen(a->cfg.label, sizeof(a->cfg.label));
            vw_ipc_write_str(rbuf, 65536, &roff, a->cfg.label, llen);
            uint16_t ulen = (uint16_t)strnlen(a->cfg.username, sizeof(a->cfg.username));
            vw_ipc_write_str(rbuf, 65536, &roff, a->cfg.username, ulen);
            uint16_t hlen = (uint16_t)strnlen(a->cfg.server_host, sizeof(a->cfg.server_host));
            vw_ipc_write_str(rbuf, 65536, &roff, a->cfg.server_host, hlen);
            rbuf[roff++] = a->sess ? 1 : 0;
            vw_write_u32le(rbuf + roff, vw_sync_pending_count(a->sync_ctx)); roff += 4;
            vw_write_u32le(rbuf + roff, 0); roff += 4; /* pending_downloads */
            /* TASK-173: trailing field — vw_account_conn_mode_t (0=offline,
             * 1=primary, 2=fallback/read-only). Meaningful even when
             * `connected` above is 0 (always VW_ACCOUNT_CONN_OFFLINE then). */
            rbuf[roff++] = (uint8_t)a->conn_mode;
            written++;
        }
        vw_write_u32le(rbuf, written);
        vw_ipc_send(conn, VW_IPC_ACCOUNT_LIST_RESP, rbuf, roff);
        free(rbuf);
        break;
    }

    case VW_IPC_ACCOUNT_ADD_REQ: {
        uint32_t off = 0;
        if (off + 4u > plen) { ipc_send_u32(conn, VW_IPC_ACCOUNT_ADD_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t req_account_id = vw_read_u32le(buf + off); off += 4u;
        const char *label = NULL, *host = NULL, *ca_path = NULL, *username = NULL, *pw = NULL, *otp = NULL;
        uint16_t label_len = 0, host_len = 0, ca_len = 0, user_len = 0, pw_len = 0, otp_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &label, &label_len);
        if (err == VW_OK) err = vw_ipc_read_str(buf, plen, &off, &host, &host_len);
        uint16_t server_port = 0;
        if (err == VW_OK && off + 2u <= plen) { server_port = vw_read_u16le(buf + off); off += 2u; }
        else if (err == VW_OK) err = VW_ERR_PROTO_TRUNCATED;
        if (err == VW_OK) err = vw_ipc_read_str(buf, plen, &off, &ca_path, &ca_len);
        if (err == VW_OK) err = vw_ipc_read_str(buf, plen, &off, &username, &user_len);
        if (err == VW_OK) err = vw_ipc_read_str(buf, plen, &off, &pw, &pw_len);
        if (err == VW_OK) err = vw_ipc_read_str(buf, plen, &off, &otp, &otp_len);
        if (err != VW_OK || pw_len == 0 || host_len == 0 || user_len == 0) {
            ipc_send_u32(conn, VW_IPC_ACCOUNT_ADD_RESP,
                         (uint32_t)(err != VW_OK ? err : VW_ERR_INVALID_ARG));
            break;
        }

        /* TASK-173: optional trailing fallback fields. Absent for any
         * caller built before this task (or one simply not configuring a
         * fallback) — malformed/short trailing bytes are treated as "not
         * supplied" rather than failing the whole account add/re-auth over
         * an optional field. */
        const char *fb_host = NULL, *fb_ca = NULL;
        uint16_t fb_host_len = 0, fb_ca_len = 0, fb_port = 0;
        if (off < plen) {
            vw_err_t ferr = vw_ipc_read_str(buf, plen, &off, &fb_host, &fb_host_len);
            if (ferr == VW_OK && off + 2u <= plen) {
                fb_port = vw_read_u16le(buf + off); off += 2u;
                ferr = vw_ipc_read_str(buf, plen, &off, &fb_ca, &fb_ca_len);
            } else if (ferr == VW_OK) {
                ferr = VW_ERR_PROTO_TRUNCATED;
            }
            if (ferr != VW_OK) { fb_host = NULL; fb_host_len = 0; fb_port = 0; fb_ca = NULL; fb_ca_len = 0; }
        }

        vw_account_ctx_t *existing = req_account_id != 0
            ? account_find(dc->accounts, req_account_id) : NULL;
        if (req_account_id != 0 && !existing) {
            ipc_send_u32(conn, VW_IPC_ACCOUNT_ADD_RESP, (uint32_t)VW_ERR_NOT_FOUND);
            break;
        }

        vw_account_cfg_t acfg;
        memset(&acfg, 0, sizeof(acfg));
        size_t cpy;
        cpy = label_len < sizeof(acfg.label)-1u ? label_len : sizeof(acfg.label)-1u;
        memcpy(acfg.label, label, cpy);
        cpy = host_len < sizeof(acfg.server_host)-1u ? host_len : sizeof(acfg.server_host)-1u;
        memcpy(acfg.server_host, host, cpy);
        acfg.server_port = server_port;
        cpy = ca_len < sizeof(acfg.ca_cert_pem_path)-1u ? ca_len : sizeof(acfg.ca_cert_pem_path)-1u;
        memcpy(acfg.ca_cert_pem_path, ca_path, cpy);
        cpy = user_len < sizeof(acfg.username)-1u ? user_len : sizeof(acfg.username)-1u;
        memcpy(acfg.username, username, cpy);

        if (fb_host_len > 0) {
            cpy = fb_host_len < sizeof(acfg.fallback_host)-1u ? fb_host_len : sizeof(acfg.fallback_host)-1u;
            memcpy(acfg.fallback_host, fb_host, cpy);
            acfg.fallback_port = fb_port;
            cpy = fb_ca_len < sizeof(acfg.fallback_ca_cert_pem_path)-1u ? fb_ca_len : sizeof(acfg.fallback_ca_cert_pem_path)-1u;
            memcpy(acfg.fallback_ca_cert_pem_path, fb_ca, cpy);
        } else if (existing) {
            /* Re-authenticating (e.g. after a password change) without
             * re-supplying fallback fields keeps whatever was already
             * configured — this request's job is re-auth, not clearing an
             * unrelated setting just because it wasn't repeated. */
            memcpy(acfg.fallback_host, existing->cfg.fallback_host, sizeof(acfg.fallback_host));
            acfg.fallback_port = existing->cfg.fallback_port;
            memcpy(acfg.fallback_ca_cert_pem_path, existing->cfg.fallback_ca_cert_pem_path,
                   sizeof(acfg.fallback_ca_cert_pem_path));
        }

        char pw_buf[256]; char otp_buf_local[16];
        cpy = pw_len < sizeof(pw_buf)-1u ? pw_len : sizeof(pw_buf)-1u;
        memcpy(pw_buf, pw, cpy); pw_buf[cpy] = '\0';
        cpy = otp_len < sizeof(otp_buf_local)-1u ? otp_len : sizeof(otp_buf_local)-1u;
        memcpy(otp_buf_local, otp, cpy); otp_buf_local[cpy] = '\0';

        vw_client_cfg_t cc;
        memset(&cc, 0, sizeof(cc));
        cc.host             = acfg.server_host;
        cc.port             = acfg.server_port;
        cc.cert_verify      = VW_CERT_VERIFY_REQUIRED;
        cc.ca_cert_pem_path = acfg.ca_cert_pem_path[0] ? acfg.ca_cert_pem_path : NULL;

        login_otp_ctx_t octx;
        octx.otp     = (otp_len > 0) ? otp_buf_local : NULL;
        octx.otp_len = (uint16_t)strlen(otp_buf_local);

        vw_client_sess_t *new_sess = NULL;
        vw_err_t rc = vw_client_connect(&cc, acfg.username, (uint16_t)strlen(acfg.username),
                                         pw_buf, strlen(pw_buf), login_otp_cb, &octx, &new_sess);

        /* TASK-173: retain SHA-256(password) — never the raw password
         * itself — for an unattended fallback connect later. Computed
         * before pw_buf is wiped below, regardless of rc: on 2FA-challenge
         * failure this connect attempt fails, but the same token would be
         * needed on the immediate retry-with-otp call the caller makes
         * next, so there's no reason to gate this on rc == VW_OK. */
        uint8_t login_tok[VW_TOKEN_BYTES];
        int have_login_tok = (vw_crypto_sha256(pw_buf, strlen(pw_buf), login_tok) == VW_OK);

        memset(pw_buf, 0, sizeof(pw_buf));
        memset(otp_buf_local, 0, sizeof(otp_buf_local));

        uint32_t out_account_id = req_account_id;
        if (rc == VW_OK) {
            char account_dir[600];
            if (existing) {
                snprintf(account_dir, sizeof(account_dir), "%s", existing->account_dir);
            } else {
                out_account_id = dc->accounts->next_account_id++;
                account_dir_path(dc->state_dir, out_account_id, account_dir, sizeof(account_dir));
            }
            rc = vw_fs_ensure_dir(account_dir);
            if (rc == VW_OK) rc = account_cfg_save(account_dir, &acfg);
            uint8_t tok[VW_TOKEN_BYTES];
            if (rc == VW_OK) {
                vw_client_get_token(new_sess, tok);
                rc = tok_save(account_dir, tok);
                memset(tok, 0, sizeof(tok));
            }
            if (rc == VW_OK && have_login_tok)
                rc = login_token_save(account_dir, login_tok);

            if (rc == VW_OK && existing) {
                vw_client_close(existing->sess); /* old token already superseded */
                existing->sess       = new_sess;
                existing->conn_mode  = VW_ACCOUNT_CONN_PRIMARY;
                /* TASK-192/193: ACCOUNT_ADD_REQ never carries exclude
                 * rules (they're set via a dedicated IPC message) — carry
                 * the existing heap-owned list across the whole-struct
                 * assignment below rather than let it leak (acfg's own
                 * slot is still zeroed/empty at this point) or silently
                 * wipe every configured rule on a routine re-auth. */
                acfg.folder_excludes       = existing->cfg.folder_excludes;
                acfg.folder_excludes_count = existing->cfg.folder_excludes_count;
                existing->cfg        = acfg;
                if (have_login_tok) {
                    memcpy(existing->login_token, login_tok, VW_TOKEN_BYTES);
                    existing->have_login_token = 1;
                }
                vw_sync_set_session(existing->sync_ctx, new_sess);
                vw_sync_set_read_only(existing->sync_ctx, 0);
            } else if (rc == VW_OK) {
                vw_cache_t *cache = NULL;
                rc = vw_cache_open(account_dir, &cache);
                vw_sync_ctx_t *sync_ctx = NULL;
                if (rc == VW_OK) {
                    vw_sync_cfg_t sc;
                    sc.sess = new_sess; sc.cache = cache; sc.state_dir = account_dir;
                    rc = vw_sync_open(&sc, &sync_ctx);
                    if (rc != VW_OK) vw_cache_close(cache);
                }
                if (rc == VW_OK) {
                    vw_account_ctx_t *a = account_add_slot(dc->accounts);
                    if (!a) { rc = VW_ERR_OOM; vw_sync_close(sync_ctx); vw_cache_close(cache); }
                    else {
                        a->account_id = out_account_id;
                        snprintf(a->account_dir, sizeof(a->account_dir), "%s", account_dir);
                        a->cfg = acfg;
                        a->cache = cache;
                        a->sync_ctx = sync_ctx;
                        a->sess = new_sess;
                        a->conn_mode = VW_ACCOUNT_CONN_PRIMARY;
                        if (have_login_tok) {
                            memcpy(a->login_token, login_tok, VW_TOKEN_BYTES);
                            a->have_login_token = 1;
                        }
                    }
                }
            }
            if (rc != VW_OK) vw_client_close(new_sess);
            else vw_log(LOG_INFO, "account '%s' (id=%u) authenticated", acfg.username, (unsigned)out_account_id);
        }
        memset(login_tok, 0, sizeof(login_tok)); /* wipe the local copy either way */

        uint8_t resp[8];
        vw_write_u32le(resp, (uint32_t)rc);
        vw_write_u32le(resp + 4u, rc == VW_OK ? out_account_id : 0u);
        vw_ipc_send(conn, VW_IPC_ACCOUNT_ADD_RESP, resp, sizeof(resp));
        break;
    }

    case VW_IPC_ACCOUNT_REMOVE_REQ: {
        if (plen < 4u) { ipc_send_u32(conn, VW_IPC_ACCOUNT_REMOVE_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf);
        size_t idx = SIZE_MAX;
        for (size_t i = 0; i < dc->accounts->count; i++)
            if (dc->accounts->accounts[i].account_id == account_id) { idx = i; break; }
        if (idx == SIZE_MAX) {
            ipc_send_u32(conn, VW_IPC_ACCOUNT_REMOVE_RESP, (uint32_t)VW_ERR_NOT_FOUND);
            break;
        }
        vw_account_ctx_t *a = &dc->accounts->accounts[idx];
        vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
        vw_cache_folder_list(a->cache, &folders, &nf);
        for (uint32_t i = 0; i < nf; i++) vw_watcher_remove(dc->watcher, folders[i].local_root);
        free(folders);
        vault_registry_close_all(&a->vaults);
        vw_sync_close(a->sync_ctx);
        if (a->sess) vw_client_logout(a->sess);
        vw_cache_close(a->cache);
        account_cfg_free_excludes(&a->cfg);
        delete_account_dir(a->account_dir);
        /* Shift the tail down over the removed slot — order doesn't matter,
         * this array is only ever iterated in full, never indexed by
         * position. */
        memmove(a, a + 1, (dc->accounts->count - idx - 1) * sizeof(*a));
        dc->accounts->count--;
        ipc_send_u32(conn, VW_IPC_ACCOUNT_REMOVE_RESP, 0);
        break;
    }

    case VW_IPC_PAUSE_REQ: {
        uint32_t off = 0;
        if (off + 4u > plen) { ipc_send_u32(conn, VW_IPC_PAUSE_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a) { ipc_send_u32(conn, VW_IPC_PAUSE_RESP, (uint32_t)VW_ERR_INVALID_ARG); break; }
        const char *lroot = NULL; uint16_t lroot_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &lroot, &lroot_len);
        if (err != VW_OK) { ipc_send_u32(conn, VW_IPC_PAUSE_RESP, (uint32_t)err); break; }
        if (lroot_len == 0) {
            /* Pause all (within this account) */
            vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
            vw_cache_folder_list(a->cache, &folders, &nf);
            for (uint32_t i = 0; i < nf; i++)
                vw_cache_folder_set_paused(a->cache, folders[i].local_root, 1);
            free(folders);
        } else {
            char path[512];
            size_t cl = lroot_len < sizeof(path) - 1 ? lroot_len : sizeof(path) - 1;
            memcpy(path, lroot, cl); path[cl] = '\0';
            vw_cache_folder_set_paused(a->cache, path, 1);
        }
        ipc_send_u32(conn, VW_IPC_PAUSE_RESP, 0);
        break;
    }

    case VW_IPC_RESUME_REQ: {
        uint32_t off = 0;
        if (off + 4u > plen) { ipc_send_u32(conn, VW_IPC_RESUME_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a) { ipc_send_u32(conn, VW_IPC_RESUME_RESP, (uint32_t)VW_ERR_INVALID_ARG); break; }
        const char *lroot = NULL; uint16_t lroot_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &lroot, &lroot_len);
        if (err != VW_OK) { ipc_send_u32(conn, VW_IPC_RESUME_RESP, (uint32_t)err); break; }
        if (lroot_len == 0) {
            vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
            vw_cache_folder_list(a->cache, &folders, &nf);
            for (uint32_t i = 0; i < nf; i++)
                vw_cache_folder_set_paused(a->cache, folders[i].local_root, 0);
            free(folders);
        } else {
            char path[512];
            size_t cl = lroot_len < sizeof(path) - 1 ? lroot_len : sizeof(path) - 1;
            memcpy(path, lroot, cl); path[cl] = '\0';
            vw_cache_folder_set_paused(a->cache, path, 0);
        }
        ipc_send_u32(conn, VW_IPC_RESUME_RESP, 0);
        break;
    }

    case VW_IPC_FOLDER_ADD_REQ: {
        uint32_t off = 0;
        if (off + 4u > plen) { ipc_send_u32(conn, VW_IPC_FOLDER_ADD_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a) { ipc_send_u32(conn, VW_IPC_FOLDER_ADD_RESP, (uint32_t)VW_ERR_INVALID_ARG); break; }
        const char *lroot = NULL, *vroot = NULL;
        uint16_t ll = 0, vl = 0;
        err = vw_ipc_read_str(buf, plen, &off, &lroot, &ll);
        if (err == VW_OK) err = vw_ipc_read_str(buf, plen, &off, &vroot, &vl);
        if (err != VW_OK) { ipc_send_u32(conn, VW_IPC_FOLDER_ADD_RESP, (uint32_t)err); break; }
        vw_sync_folder_t f;
        memset(&f, 0, sizeof(f));
        size_t al = ll < sizeof(f.local_root)-1 ? ll : sizeof(f.local_root)-1;
        memcpy(f.local_root, lroot, al); f.local_root[al] = '\0';
        al = vl < sizeof(f.virtual_root)-1 ? vl : sizeof(f.virtual_root)-1;
        memcpy(f.virtual_root, vroot, al); f.virtual_root[al] = '\0';
        err = vw_cache_folder_add(a->cache, &f);
        if (err == VW_OK)
            vw_watcher_add(dc->watcher, f.local_root);
        ipc_send_u32(conn, VW_IPC_FOLDER_ADD_RESP, (uint32_t)err);
        break;
    }

    case VW_IPC_FOLDER_ADD_SHARED_REQ: {
        uint32_t off = 0;
        if (off + 4u > plen) { ipc_send_u32(conn, VW_IPC_FOLDER_ADD_SHARED_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a) { ipc_send_u32(conn, VW_IPC_FOLDER_ADD_SHARED_RESP, (uint32_t)VW_ERR_INVALID_ARG); break; }
        if (!a->sess) {
            ipc_send_u32(conn, VW_IPC_FOLDER_ADD_SHARED_RESP, (uint32_t)VW_ERR_AUTH_REQUIRED);
            break;
        }
        const char *lroot = NULL, *vroot = NULL;
        uint16_t ll = 0, vl = 0;
        err = vw_ipc_read_str(buf, plen, &off, &lroot, &ll);
        if (err == VW_OK) err = vw_ipc_read_str(buf, plen, &off, &vroot, &vl);
        if (err == VW_OK && off + 8u > plen) err = VW_ERR_PROTO_TRUNCATED;
        if (err != VW_OK) {
            ipc_send_u32(conn, VW_IPC_FOLDER_ADD_SHARED_RESP, (uint32_t)err);
            break;
        }
        uint64_t remote_dir_id = vw_read_u64le(buf + off);

        /* TASK-106: remote_dir_id must already be a directory the caller
         * has at least VIEW access to — checked up front so a bad id fails
         * immediately with a clear error instead of silently never syncing. */
        vw_file_entry_t dir_entry;
        vw_err_t rc = vw_client_file_stat_by_id(a->sess, remote_dir_id, &dir_entry);
        if (rc == VW_OK && dir_entry.entry_type != VW_ENTRY_DIR)
            rc = VW_ERR_INVALID_ARG;
        if (rc == VW_OK) {
            vw_sync_folder_t f;
            memset(&f, 0, sizeof(f));
            size_t al = ll < sizeof(f.local_root)-1 ? ll : sizeof(f.local_root)-1;
            memcpy(f.local_root, lroot, al); f.local_root[al] = '\0';
            al = vl < sizeof(f.virtual_root)-1 ? vl : sizeof(f.virtual_root)-1;
            memcpy(f.virtual_root, vroot, al); f.virtual_root[al] = '\0';
            f.remote_dir_id = remote_dir_id;
            rc = vw_cache_folder_add(a->cache, &f);
            if (rc == VW_OK)
                vw_watcher_add(dc->watcher, f.local_root);
        }
        ipc_send_u32(conn, VW_IPC_FOLDER_ADD_SHARED_RESP, (uint32_t)rc);
        break;
    }

    case VW_IPC_FOLDER_REMOVE_REQ: {
        uint32_t off = 0;
        if (off + 4u > plen) { ipc_send_u32(conn, VW_IPC_FOLDER_REMOVE_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a) { ipc_send_u32(conn, VW_IPC_FOLDER_REMOVE_RESP, (uint32_t)VW_ERR_INVALID_ARG); break; }
        const char *lroot = NULL; uint16_t ll = 0;
        err = vw_ipc_read_str(buf, plen, &off, &lroot, &ll);
        if (err != VW_OK) { ipc_send_u32(conn, VW_IPC_FOLDER_REMOVE_RESP, (uint32_t)err); break; }
        char path[512];
        size_t cl = ll < sizeof(path)-1 ? ll : sizeof(path)-1;
        memcpy(path, lroot, cl); path[cl] = '\0';
        vw_watcher_remove(dc->watcher, path);
        err = vw_cache_folder_remove(a->cache, path);
        ipc_send_u32(conn, VW_IPC_FOLDER_REMOVE_RESP, (uint32_t)err);
        break;
    }

    case VW_IPC_FOLDER_LIST_REQ: {
        if (plen < 4u) { vw_ipc_send(conn, VW_IPC_FOLDER_LIST_RESP, NULL, 0); break; }
        uint32_t account_id = vw_read_u32le(buf);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a) { vw_ipc_send(conn, VW_IPC_FOLDER_LIST_RESP, NULL, 0); break; }
        vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
        (void)vw_cache_folder_list(a->cache, &folders, &nf);
        /* Encode: u32 count + per-entry (str local_root, str virtual_root,
         * u8 paused, u8 pause_reason [TASK-111], u64 remote_dir_id [TASK-106],
         * u16 exclude_count + exclude_count*str pattern [TASK-192/193]) */
        uint8_t rbuf[65536]; uint32_t roff = 0;
        vw_write_u32le(rbuf + roff, nf); roff += 4;
        for (uint32_t i = 0; i < nf && roff < sizeof(rbuf) - 3072; i++) {
            uint16_t llen = (uint16_t)strnlen(folders[i].local_root,
                                               sizeof(folders[i].local_root));
            uint16_t vlen = (uint16_t)strnlen(folders[i].virtual_root,
                                               sizeof(folders[i].virtual_root));
            vw_ipc_write_str(rbuf, sizeof(rbuf), &roff,
                              folders[i].local_root, llen);
            vw_ipc_write_str(rbuf, sizeof(rbuf), &roff,
                              folders[i].virtual_root, vlen);
            rbuf[roff++] = folders[i].paused;
            rbuf[roff++] = folders[i].pause_reason;
            vw_write_u64le(rbuf + roff, folders[i].remote_dir_id); roff += 8u;

            vw_folder_excludes_cfg_t *fe =
                account_cfg_find_excludes(&a->cfg, folders[i].local_root);
            uint16_t ecount = fe ? (uint16_t)(fe->count < 64u ? fe->count : 64u) : 0u;
            vw_write_u16le(rbuf + roff, ecount); roff += 2u;
            for (uint16_t j = 0; j < ecount && roff < sizeof(rbuf) - 600; j++) {
                uint16_t plen2 = (uint16_t)strlen(fe->patterns[j]);
                vw_ipc_write_str(rbuf, sizeof(rbuf), &roff, fe->patterns[j], plen2);
            }
        }
        free(folders);
        vw_ipc_send(conn, VW_IPC_FOLDER_LIST_RESP, rbuf, roff);
        break;
    }

    case VW_IPC_FOLDER_SET_EXCLUDES_REQ: {
        uint32_t off = 0;
        if (off + 4u > plen) { ipc_send_u32(conn, VW_IPC_FOLDER_SET_EXCLUDES_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a) { ipc_send_u32(conn, VW_IPC_FOLDER_SET_EXCLUDES_RESP, (uint32_t)VW_ERR_INVALID_ARG); break; }

        const char *lroot = NULL; uint16_t ll = 0;
        err = vw_ipc_read_str(buf, plen, &off, &lroot, &ll);
        if (err != VW_OK || off + 2u > plen) {
            ipc_send_u32(conn, VW_IPC_FOLDER_SET_EXCLUDES_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED);
            break;
        }
        uint16_t count = vw_read_u16le(buf + off); off += 2u;

        char root_buf[512];
        size_t rl = ll < sizeof(root_buf) - 1u ? ll : sizeof(root_buf) - 1u;
        memcpy(root_buf, lroot, rl); root_buf[rl] = '\0';

        /* count is capped at 64 patterns — same personal-scale ceiling
         * FOLDER_LIST_RESP's own encode loop above already applies when
         * reading these back. */
        if (count > 64u) { ipc_send_u32(conn, VW_IPC_FOLDER_SET_EXCLUDES_RESP, (uint32_t)VW_ERR_INVALID_ARG); break; }
        char pat_bufs[64][256];
        const char *pat_ptrs[64];
        vw_err_t perr = VW_OK;
        for (uint16_t i = 0; i < count && perr == VW_OK; i++) {
            const char *p = NULL; uint16_t plen2 = 0;
            perr = vw_ipc_read_str(buf, plen, &off, &p, &plen2);
            if (perr == VW_OK) {
                size_t cl = plen2 < sizeof(pat_bufs[i]) - 1u ? plen2 : sizeof(pat_bufs[i]) - 1u;
                memcpy(pat_bufs[i], p, cl); pat_bufs[i][cl] = '\0';
                pat_ptrs[i] = pat_bufs[i];
            }
        }
        if (perr != VW_OK) { ipc_send_u32(conn, VW_IPC_FOLDER_SET_EXCLUDES_RESP, (uint32_t)perr); break; }

        vw_sync_folder_t *folders2 = NULL; uint32_t nf2 = 0;
        (void)vw_cache_folder_list(a->cache, &folders2, &nf2);
        int found = 0;
        for (uint32_t i = 0; i < nf2; i++)
            if (strcmp(folders2[i].local_root, root_buf) == 0) { found = 1; break; }
        free(folders2);
        if (!found) { ipc_send_u32(conn, VW_IPC_FOLDER_SET_EXCLUDES_RESP, (uint32_t)VW_ERR_NOT_FOUND); break; }

        /* Wholesale replace, not incremental append: clear this one
         * folder's existing rules (keeping its slot, so the add loop
         * below re-populates it fresh) before adding the new set. */
        vw_folder_excludes_cfg_t *fe = account_cfg_find_excludes(&a->cfg, root_buf);
        if (fe) {
            for (uint32_t i = 0; i < fe->count; i++) free(fe->patterns[i]);
            free(fe->patterns);
            fe->patterns = NULL;
            fe->count = 0;
        }
        vw_err_t rc = VW_OK;
        for (uint16_t i = 0; i < count && rc == VW_OK; i++)
            rc = account_cfg_add_exclude(&a->cfg, root_buf, pat_ptrs[i]);
        if (rc == VW_OK) rc = account_cfg_save(a->account_dir, &a->cfg);
        if (rc == VW_OK)
            rc = vw_sync_set_folder_excludes(a->sync_ctx, root_buf, pat_ptrs, count);
        ipc_send_u32(conn, VW_IPC_FOLDER_SET_EXCLUDES_RESP, (uint32_t)rc);
        break;
    }

    case VW_IPC_FILE_LIST_REQ: {
        uint32_t off = 0;
        if (off + 4u > plen) { vw_ipc_send(conn, VW_IPC_FILE_LIST_RESP, NULL, 0); break; }
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a) { vw_ipc_send(conn, VW_IPC_FILE_LIST_RESP, NULL, 0); break; }
        const char *prefix = NULL; uint16_t pl = 0;
        uint8_t filter = VW_IPC_FILTER_ALL;
        err = vw_ipc_read_str(buf, plen, &off, &prefix, &pl);
        if (err == VW_OK && off < plen) filter = buf[off];
        int state_filter = (filter == VW_IPC_FILTER_ALL) ? -1 : (int)filter;
        vw_cache_entry_t *entries = NULL; uint32_t ne = 0;
        (void)vw_cache_list(a->cache, state_filter, &entries, &ne);
        uint8_t *rbuf = malloc(65536);
        if (!rbuf) { free(entries); vw_ipc_send(conn, VW_IPC_FILE_LIST_RESP, NULL, 0); break; }
        uint32_t roff = 4; /* count patched in below once the real written count is known */
        uint32_t written = 0;
        for (uint32_t i = 0; i < ne && roff + 2048 < 65536; i++) {
            const vw_cache_entry_t *e = &entries[i];
            /* Filter by virtual prefix if provided */
            if (pl > 0 && prefix) {
                char pfx[512];
                size_t cl = pl < sizeof(pfx)-1 ? pl : sizeof(pfx)-1;
                memcpy(pfx, prefix, cl); pfx[cl] = '\0';
                if (strncmp(e->virtual_path, pfx, cl) != 0) continue;
            }
            uint16_t vplen = (uint16_t)strnlen(e->virtual_path, sizeof(e->virtual_path));
            uint16_t lplen = (uint16_t)strnlen(e->local_path,   sizeof(e->local_path));
            vw_ipc_write_str(rbuf, 65536, &roff, e->virtual_path, vplen);
            vw_ipc_write_str(rbuf, 65536, &roff, e->local_path,   lplen);
            vw_write_u32le(rbuf + roff, (uint32_t)e->sync_state); roff += 4;
            rbuf[roff++] = e->entry_type;
            vw_write_u64le(rbuf + roff, (uint64_t)e->server_mtime); roff += 8;
            vw_write_u64le(rbuf + roff, (uint64_t)e->local_mtime);  roff += 8;
            vw_write_u64le(rbuf + roff, e->server_size);             roff += 8;
            vw_write_u64le(rbuf + roff, e->file_id);                 roff += 8;
            vw_write_u64le(rbuf + roff, e->vault_id);                roff += 8;
            written++;
        }
        /* Patch the real count now — cannot have been known up front since
         * the prefix filter above may skip entries (TASK-096 fix: this
         * previously wrote the raw pre-filter count `ne`, silently
         * corrupting the decode whenever a prefix filter actually excluded
         * anything, since the header would then overstate how many
         * entries the receiver should try to read). */
        vw_write_u32le(rbuf, written);
        free(entries);
        vw_ipc_send(conn, VW_IPC_FILE_LIST_RESP, rbuf, roff);
        free(rbuf);
        break;
    }

    case VW_IPC_SHUTDOWN_REQ:
        ipc_send_u32(conn, VW_IPC_SHUTDOWN_RESP, 0);
        *dc->shutdown_flag = 1;
        break;

    case VW_IPC_SHARE_GRANT_REQ: {
        uint32_t off = 0;
        if (off + 4u > plen) { ipc_send_u32(conn, VW_IPC_SHARE_GRANT_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *account = account_find(dc->accounts, account_id);
        const char *path = NULL; uint16_t path_len = 0;
        const char *tgt = NULL; uint16_t tgt_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &path, &path_len);
        if (err == VW_OK) err = vw_ipc_read_str(buf, plen, &off, &tgt, &tgt_len);
        uint8_t permission = 0; int64_t expires_at = 0;
        if (err == VW_OK && off + 1u + 8u <= plen) {
            permission = buf[off]; off += 1u;
            expires_at = (int64_t)vw_read_u64le(buf + off); off += 8u;
        } else if (err == VW_OK) {
            err = VW_ERR_PROTO_TRUNCATED;
        }
        if (err != VW_OK || !account || !account->sess) {
            uint8_t rbuf[12] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!account ? VW_ERR_INVALID_ARG :
                                             !account->sess ? VW_ERR_AUTH_REQUIRED : err));
            vw_ipc_send(conn, VW_IPC_SHARE_GRANT_RESP, rbuf, sizeof(rbuf));
            break;
        }
        if (account_is_read_only(account)) {
            uint8_t rbuf[12] = {0};
            vw_write_u32le(rbuf, (uint32_t)VW_ERR_READ_ONLY_FALLBACK);
            vw_ipc_send(conn, VW_IPC_SHARE_GRANT_RESP, rbuf, sizeof(rbuf));
            break;
        }
        char path_buf[VW_MAX_PATH_BYTES + 1];
        char tgt_buf[VW_MAX_USERNAME_BYTES + 1];
        size_t pcopy = path_len < sizeof(path_buf) - 1u ? path_len : sizeof(path_buf) - 1u;
        memcpy(path_buf, path, pcopy); path_buf[pcopy] = '\0';
        size_t tcopy = tgt_len < sizeof(tgt_buf) - 1u ? tgt_len : sizeof(tgt_buf) - 1u;
        memcpy(tgt_buf, tgt, tcopy); tgt_buf[tcopy] = '\0';

        vw_file_entry_t entry;
        vw_err_t rc = vw_client_file_stat(account->sess, path_buf, &entry);
        uint64_t share_id = 0;
        if (rc == VW_OK)
            rc = vw_client_share_grant(account->sess, entry.file_id, tgt_buf,
                                        (vw_perm_t)permission, expires_at, &share_id);
        uint8_t rbuf[12];
        vw_write_u32le(rbuf, (uint32_t)rc);
        vw_write_u64le(rbuf + 4u, share_id);
        vw_ipc_send(conn, VW_IPC_SHARE_GRANT_RESP, rbuf, sizeof(rbuf));
        break;
    }

    case VW_IPC_SHARE_REVOKE_REQ:
    case VW_IPC_LINK_REVOKE_REQ: {
        vw_ipc_msg_t resp_type = (type == VW_IPC_SHARE_REVOKE_REQ)
                                  ? VW_IPC_SHARE_REVOKE_RESP : VW_IPC_LINK_REVOKE_RESP;
        if (plen < 12u) { ipc_send_u32(conn, resp_type, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            ipc_send_u32(conn, resp_type, (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            break;
        }
        if (account_is_read_only(a)) {
            ipc_send_u32(conn, resp_type, (uint32_t)VW_ERR_READ_ONLY_FALLBACK);
            break;
        }
        uint64_t share_id = vw_read_u64le(buf + 4u);
        vw_err_t rc = (type == VW_IPC_SHARE_REVOKE_REQ)
                      ? vw_client_share_revoke(a->sess, share_id)
                      : vw_client_link_revoke(a->sess, share_id);
        ipc_send_u32(conn, resp_type, (uint32_t)rc);
        break;
    }

    case VW_IPC_SHARE_LIST_REQ: {
        if (plen < 4u) { ipc_send_u32(conn, VW_IPC_SHARE_LIST_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf);
        uint8_t mode = (plen >= 5u) ? buf[4] : 0;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            uint8_t rbuf[8] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            vw_ipc_send(conn, VW_IPC_SHARE_LIST_RESP, rbuf, sizeof(rbuf));
            break;
        }
        vw_share_entry_t *entries = NULL; uint32_t count = 0;
        vw_err_t rc = vw_client_share_list(a->sess, mode, &entries, &count);
        uint8_t *rbuf = malloc(65536);
        if (!rbuf) { free(entries); ipc_send_u32(conn, VW_IPC_SHARE_LIST_RESP, (uint32_t)VW_ERR_OOM); break; }
        uint32_t roff = 0;
        vw_write_u32le(rbuf + roff, (uint32_t)rc); roff += 4;
        vw_write_u32le(rbuf + roff, (rc == VW_OK) ? count : 0u); roff += 4;
        if (rc == VW_OK) {
            for (uint32_t i = 0; i < count && roff + 256 < 65536; i++) {
                vw_write_u64le(rbuf + roff, entries[i].share_id); roff += 8;
                vw_write_u64le(rbuf + roff, entries[i].file_id);  roff += 8;
                uint16_t nlen = (uint16_t)strnlen(entries[i].name, sizeof(entries[i].name));
                vw_ipc_write_str(rbuf, 65536, &roff, entries[i].name, nlen);
                rbuf[roff++] = entries[i].share_type;
                uint16_t tlen = (uint16_t)strnlen(entries[i].target_username, sizeof(entries[i].target_username));
                vw_ipc_write_str(rbuf, 65536, &roff, entries[i].target_username, tlen);
                rbuf[roff++] = entries[i].permission;
                vw_write_u64le(rbuf + roff, (uint64_t)entries[i].created_at); roff += 8;
                vw_write_u64le(rbuf + roff, (uint64_t)entries[i].expires_at); roff += 8;
                rbuf[roff++] = entries[i].revoked;
            }
        }
        free(entries);
        vw_ipc_send(conn, VW_IPC_SHARE_LIST_RESP, rbuf, roff);
        free(rbuf);
        break;
    }

    case VW_IPC_LINK_CREATE_REQ: {
        uint32_t off = 0;
        if (off + 4u > plen) { ipc_send_u32(conn, VW_IPC_LINK_CREATE_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        const char *path = NULL; uint16_t path_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &path, &path_len);
        uint8_t permission = 0; int64_t expires_at = 0;
        if (err == VW_OK && off + 1u + 8u <= plen) {
            permission = buf[off]; off += 1u;
            expires_at = (int64_t)vw_read_u64le(buf + off); off += 8u;
        } else if (err == VW_OK) {
            err = VW_ERR_PROTO_TRUNCATED;
        }
        /* TASK-186/188: optional trailing password field. */
        const char *password = NULL; uint16_t password_len = 0;
        if (err == VW_OK && off < plen)
            err = vw_ipc_read_str(buf, plen, &off, &password, &password_len);
        if (err != VW_OK || !a || !a->sess) {
            uint8_t rbuf[44] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : !a->sess ? VW_ERR_AUTH_REQUIRED : err));
            vw_ipc_send(conn, VW_IPC_LINK_CREATE_RESP, rbuf, sizeof(rbuf));
            break;
        }
        if (account_is_read_only(a)) {
            uint8_t rbuf[44] = {0};
            vw_write_u32le(rbuf, (uint32_t)VW_ERR_READ_ONLY_FALLBACK);
            vw_ipc_send(conn, VW_IPC_LINK_CREATE_RESP, rbuf, sizeof(rbuf));
            break;
        }
        char path_buf[VW_MAX_PATH_BYTES + 1];
        size_t pcopy = path_len < sizeof(path_buf) - 1u ? path_len : sizeof(path_buf) - 1u;
        memcpy(path_buf, path, pcopy); path_buf[pcopy] = '\0';

        char password_buf[257];
        size_t wcopy = password_len < sizeof(password_buf) - 1u ? password_len : sizeof(password_buf) - 1u;
        if (password && wcopy) memcpy(password_buf, password, wcopy);
        password_buf[wcopy] = '\0';

        vw_file_entry_t entry;
        vw_err_t rc = vw_client_file_stat(a->sess, path_buf, &entry);
        uint64_t share_id = 0;
        uint8_t link_token[32] = {0};
        if (rc == VW_OK)
            rc = vw_client_link_create(a->sess, entry.file_id, (vw_perm_t)permission,
                                        expires_at, wcopy ? password_buf : NULL,
                                        &share_id, link_token);
        memset(password_buf, 0, sizeof(password_buf));
        uint8_t rbuf[4u + 8u + 32u];
        vw_write_u32le(rbuf, (uint32_t)rc);
        vw_write_u64le(rbuf + 4u, share_id);
        memcpy(rbuf + 12u, link_token, 32u);
        vw_ipc_send(conn, VW_IPC_LINK_CREATE_RESP, rbuf, sizeof(rbuf));
        memset(rbuf, 0, sizeof(rbuf));
        memset(link_token, 0, sizeof(link_token));
        break;
    }

    case VW_IPC_LINK_LIST_REQ: {
        if (plen < 4u) { ipc_send_u32(conn, VW_IPC_LINK_LIST_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf);
        uint64_t file_id_filter = (plen >= 12u) ? vw_read_u64le(buf + 4u) : 0u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            uint8_t rbuf[8] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            vw_ipc_send(conn, VW_IPC_LINK_LIST_RESP, rbuf, sizeof(rbuf));
            break;
        }
        vw_link_entry_t *entries = NULL; uint32_t count = 0;
        vw_err_t rc = vw_client_link_list(a->sess, file_id_filter, &entries, &count);
        uint8_t *rbuf = malloc(65536);
        if (!rbuf) { free(entries); ipc_send_u32(conn, VW_IPC_LINK_LIST_RESP, (uint32_t)VW_ERR_OOM); break; }
        uint32_t roff = 0;
        vw_write_u32le(rbuf + roff, (uint32_t)rc); roff += 4;
        vw_write_u32le(rbuf + roff, (rc == VW_OK) ? count : 0u); roff += 4;
        if (rc == VW_OK) {
            for (uint32_t i = 0; i < count && roff + 256 < 65536; i++) {
                vw_write_u64le(rbuf + roff, entries[i].share_id); roff += 8;
                vw_write_u64le(rbuf + roff, entries[i].file_id);  roff += 8;
                uint16_t nlen = (uint16_t)strnlen(entries[i].name, sizeof(entries[i].name));
                vw_ipc_write_str(rbuf, 65536, &roff, entries[i].name, nlen);
                rbuf[roff++] = entries[i].permission;
                vw_write_u64le(rbuf + roff, (uint64_t)entries[i].created_at); roff += 8;
                vw_write_u64le(rbuf + roff, (uint64_t)entries[i].expires_at); roff += 8;
                rbuf[roff++] = entries[i].revoked;
                rbuf[roff++] = entries[i].has_password; /* TASK-186/188 */
            }
        }
        free(entries);
        vw_ipc_send(conn, VW_IPC_LINK_LIST_RESP, rbuf, roff);
        free(rbuf);
        break;
    }

    case VW_IPC_FILE_MKDIR_REQ: {
        if (plen < 12u) {
            ipc_send_u32(conn, VW_IPC_FILE_MKDIR_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED);
            break;
        }
        uint32_t account_id = vw_read_u32le(buf);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            uint8_t rbuf[12] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            vw_ipc_send(conn, VW_IPC_FILE_MKDIR_RESP, rbuf, sizeof(rbuf));
            break;
        }
        if (account_is_read_only(a)) {
            uint8_t rbuf[12] = {0};
            vw_write_u32le(rbuf, (uint32_t)VW_ERR_READ_ONLY_FALLBACK);
            vw_ipc_send(conn, VW_IPC_FILE_MKDIR_RESP, rbuf, sizeof(rbuf));
            break;
        }
        uint64_t new_parent_dir_id = vw_read_u64le(buf + 4u);
        uint32_t off = 12u;
        const char *name = NULL; uint16_t name_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &name, &name_len);
        char name_buf[256];
        uint64_t dir_id = 0;
        vw_err_t rc = err;
        if (rc == VW_OK) {
            if (name_len >= sizeof(name_buf)) rc = VW_ERR_INVALID_ARG;
            else {
                memcpy(name_buf, name, name_len); name_buf[name_len] = '\0';
                rc = vw_client_file_mkdir(a->sess, new_parent_dir_id, name_buf, &dir_id);
            }
        }
        uint8_t rbuf[12];
        vw_write_u32le(rbuf, (uint32_t)rc);
        vw_write_u64le(rbuf + 4u, dir_id);
        vw_ipc_send(conn, VW_IPC_FILE_MKDIR_RESP, rbuf, sizeof(rbuf));
        break;
    }

    case VW_IPC_VAULT_CREATE_REQ: {
        if (plen < 12u) {
            ipc_send_u32(conn, VW_IPC_VAULT_CREATE_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED);
            break;
        }
        uint32_t account_id = vw_read_u32le(buf);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            uint8_t rbuf[12] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            vw_ipc_send(conn, VW_IPC_VAULT_CREATE_RESP, rbuf, sizeof(rbuf));
            break;
        }
        if (account_is_read_only(a)) {
            uint8_t rbuf[12] = {0};
            vw_write_u32le(rbuf, (uint32_t)VW_ERR_READ_ONLY_FALLBACK);
            vw_ipc_send(conn, VW_IPC_VAULT_CREATE_RESP, rbuf, sizeof(rbuf));
            break;
        }
        uint64_t folder_file_id = vw_read_u64le(buf + 4u);
        uint32_t off = 12u;
        const char *pass = NULL; uint16_t pass_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &pass, &pass_len);

        vw_vault_t *vault = NULL;
        uint64_t vault_id = 0;
        vw_err_t rc = err;
        if (rc == VW_OK)
            rc = vw_vault_setup(a->sess, folder_file_id, pass, pass_len, NULL, &vault, &vault_id);
        if (rc == VW_OK) rc = vault_registry_put(&a->vaults, vault_id, vault);

        uint8_t rbuf[12];
        vw_write_u32le(rbuf, (uint32_t)rc);
        vw_write_u64le(rbuf + 4u, vault_id);
        vw_ipc_send(conn, VW_IPC_VAULT_CREATE_RESP, rbuf, sizeof(rbuf));
        break;
    }

    case VW_IPC_VAULT_UNLOCK_REQ: {
        if (plen < 12u) {
            ipc_send_u32(conn, VW_IPC_VAULT_UNLOCK_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED);
            break;
        }
        uint32_t account_id = vw_read_u32le(buf);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            ipc_send_u32(conn, VW_IPC_VAULT_UNLOCK_RESP,
                         (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            break;
        }
        uint64_t vault_id = vw_read_u64le(buf + 4u);
        uint32_t off = 12u;
        const char *pass = NULL; uint16_t pass_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &pass, &pass_len);

        vw_vault_t *vault = NULL;
        vw_err_t rc = err;
        if (rc == VW_OK)
            rc = vw_vault_unlock(a->sess, vault_id, pass, pass_len, &vault);
        if (rc == VW_OK) rc = vault_registry_put(&a->vaults, vault_id, vault);

        ipc_send_u32(conn, VW_IPC_VAULT_UNLOCK_RESP, (uint32_t)rc);
        break;
    }

    case VW_IPC_VAULT_LIST_REQ: {
        if (plen < 4u) { ipc_send_u32(conn, VW_IPC_VAULT_LIST_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            uint8_t rbuf[8] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            vw_ipc_send(conn, VW_IPC_VAULT_LIST_RESP, rbuf, sizeof(rbuf));
            break;
        }
        vw_vault_entry_t *entries = NULL; uint32_t count = 0;
        vw_err_t rc = vw_client_vault_list(a->sess, &entries, &count);
        uint8_t *rbuf = malloc(8u + (size_t)count * 24u);
        if (!rbuf) { free(entries); ipc_send_u32(conn, VW_IPC_VAULT_LIST_RESP, (uint32_t)VW_ERR_OOM); break; }
        uint32_t roff = 0;
        vw_write_u32le(rbuf + roff, (uint32_t)rc); roff += 4;
        vw_write_u32le(rbuf + roff, (rc == VW_OK) ? count : 0u); roff += 4;
        if (rc == VW_OK) {
            for (uint32_t i = 0; i < count; i++) {
                vw_write_u64le(rbuf + roff, entries[i].vault_id);                  roff += 8;
                vw_write_u64le(rbuf + roff, entries[i].folder_file_id);            roff += 8;
                vw_write_u64le(rbuf + roff, (uint64_t)entries[i].created_at);      roff += 8;
            }
        }
        free(entries);
        vw_ipc_send(conn, VW_IPC_VAULT_LIST_RESP, rbuf, roff);
        free(rbuf);
        break;
    }

    case VW_IPC_VAULT_UPLOAD_REQ: {
        if (plen < 20u) {
            uint8_t rbuf[20] = {0};
            vw_write_u32le(rbuf, (uint32_t)VW_ERR_PROTO_TRUNCATED);
            vw_ipc_send(conn, VW_IPC_VAULT_UPLOAD_RESP, rbuf, sizeof(rbuf));
            break;
        }
        uint32_t account_id = vw_read_u32le(buf);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            uint8_t rbuf[20] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            vw_ipc_send(conn, VW_IPC_VAULT_UPLOAD_RESP, rbuf, sizeof(rbuf));
            break;
        }
        if (account_is_read_only(a)) {
            uint8_t rbuf[20] = {0};
            vw_write_u32le(rbuf, (uint32_t)VW_ERR_READ_ONLY_FALLBACK);
            vw_ipc_send(conn, VW_IPC_VAULT_UPLOAD_RESP, rbuf, sizeof(rbuf));
            break;
        }
        uint64_t vault_id = vw_read_u64le(buf + 4u);
        uint64_t file_id  = vw_read_u64le(buf + 12u);
        uint32_t off = 20u;
        const char *leaf = NULL; uint16_t leaf_len = 0;
        const char *lpath = NULL; uint16_t lpath_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &leaf, &leaf_len);
        if (err == VW_OK) err = vw_ipc_read_str(buf, plen, &off, &lpath, &lpath_len);

        char leaf_buf[256], lpath_buf[1024];
        uint64_t out_file_id = 0, out_version_id = 0;
        vw_err_t rc = err;
        vw_vault_t *vault = (rc == VW_OK) ? vault_registry_find(&a->vaults, vault_id) : NULL;
        if (rc == VW_OK && !vault) rc = VW_ERR_AUTH_REQUIRED;
        if (rc == VW_OK && (leaf_len >= sizeof(leaf_buf) || lpath_len >= sizeof(lpath_buf)))
            rc = VW_ERR_INVALID_ARG;
        if (rc == VW_OK) {
            memcpy(leaf_buf, leaf, leaf_len); leaf_buf[leaf_len] = '\0';
            memcpy(lpath_buf, lpath, lpath_len); lpath_buf[lpath_len] = '\0';
            rc = vw_vault_upload_file(vault, a->sess, file_id,
                                       file_id == 0 ? leaf_buf : NULL, lpath_buf,
                                       NULL, NULL, &out_file_id, &out_version_id);
        }
        uint8_t rbuf[20];
        vw_write_u32le(rbuf, (uint32_t)rc);
        vw_write_u64le(rbuf + 4u, out_file_id);
        vw_write_u64le(rbuf + 12u, out_version_id);
        vw_ipc_send(conn, VW_IPC_VAULT_UPLOAD_RESP, rbuf, sizeof(rbuf));
        break;
    }

    case VW_IPC_VAULT_DOWNLOAD_REQ: {
        if (plen < 20u) {
            ipc_send_u32(conn, VW_IPC_VAULT_DOWNLOAD_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED);
            break;
        }
        uint32_t account_id = vw_read_u32le(buf);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            ipc_send_u32(conn, VW_IPC_VAULT_DOWNLOAD_RESP,
                         (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            break;
        }
        uint64_t vault_id = vw_read_u64le(buf + 4u);
        uint64_t file_id  = vw_read_u64le(buf + 12u);
        uint32_t off = 20u;
        const char *lpath = NULL; uint16_t lpath_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &lpath, &lpath_len);

        char lpath_buf[1024];
        vw_err_t rc = err;
        vw_vault_t *vault = (rc == VW_OK) ? vault_registry_find(&a->vaults, vault_id) : NULL;
        if (rc == VW_OK && !vault) rc = VW_ERR_AUTH_REQUIRED;
        if (rc == VW_OK && lpath_len >= sizeof(lpath_buf)) rc = VW_ERR_INVALID_ARG;
        if (rc == VW_OK) {
            memcpy(lpath_buf, lpath, lpath_len); lpath_buf[lpath_len] = '\0';
            rc = vw_vault_download_file(vault, a->sess, file_id, lpath_buf, NULL, NULL);
        }
        ipc_send_u32(conn, VW_IPC_VAULT_DOWNLOAD_RESP, (uint32_t)rc);
        break;
    }

    case VW_IPC_VERSION_LIST_REQ: {
        if (plen < 4u) { ipc_send_u32(conn, VW_IPC_VERSION_LIST_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t off = 0;
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        const char *path = NULL; uint16_t path_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &path, &path_len);
        if (err != VW_OK || !a || !a->sess) {
            uint8_t rbuf[8] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : !a->sess ? VW_ERR_AUTH_REQUIRED : err));
            vw_ipc_send(conn, VW_IPC_VERSION_LIST_RESP, rbuf, sizeof(rbuf));
            break;
        }
        char path_buf[VW_MAX_PATH_BYTES + 1];
        size_t pcopy = path_len < sizeof(path_buf) - 1u ? path_len : sizeof(path_buf) - 1u;
        memcpy(path_buf, path, pcopy); path_buf[pcopy] = '\0';

        vw_version_entry_t *entries = NULL; uint32_t count = 0;
        vw_err_t rc = vw_client_version_list(a->sess, path_buf, &entries, &count);
        uint8_t *rbuf = malloc(65536);
        if (!rbuf) { free(entries); ipc_send_u32(conn, VW_IPC_VERSION_LIST_RESP, (uint32_t)VW_ERR_OOM); break; }
        uint32_t roff = 0;
        vw_write_u32le(rbuf + roff, (uint32_t)rc); roff += 4;
        vw_write_u32le(rbuf + roff, (rc == VW_OK) ? count : 0u); roff += 4;
        if (rc == VW_OK) {
            for (uint32_t i = 0; i < count && roff + 24u <= 65536u; i++) {
                vw_write_u64le(rbuf + roff, entries[i].version_id); roff += 8;
                vw_write_u64le(rbuf + roff, (uint64_t)entries[i].created_at); roff += 8;
                vw_write_u64le(rbuf + roff, entries[i].size_bytes); roff += 8;
            }
        }
        free(entries);
        vw_ipc_send(conn, VW_IPC_VERSION_LIST_RESP, rbuf, roff);
        free(rbuf);
        break;
    }

    case VW_IPC_VERSION_RESTORE_REQ: {
        uint32_t off = 0;
        if (off + 4u > plen) { ipc_send_u32(conn, VW_IPC_VERSION_RESTORE_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        const char *path = NULL; uint16_t path_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &path, &path_len);
        uint64_t version_id = 0;
        if (err == VW_OK && off + 8u <= plen) {
            version_id = vw_read_u64le(buf + off); off += 8u;
        } else if (err == VW_OK) {
            err = VW_ERR_PROTO_TRUNCATED;
        }
        if (err != VW_OK || !a || !a->sess) {
            ipc_send_u32(conn, VW_IPC_VERSION_RESTORE_RESP,
                         (uint32_t)(!a ? VW_ERR_INVALID_ARG : !a->sess ? VW_ERR_AUTH_REQUIRED : err));
            break;
        }
        if (account_is_read_only(a)) {
            ipc_send_u32(conn, VW_IPC_VERSION_RESTORE_RESP, (uint32_t)VW_ERR_READ_ONLY_FALLBACK);
            break;
        }
        char path_buf[VW_MAX_PATH_BYTES + 1];
        size_t pcopy = path_len < sizeof(path_buf) - 1u ? path_len : sizeof(path_buf) - 1u;
        memcpy(path_buf, path, pcopy); path_buf[pcopy] = '\0';

        vw_err_t rc = vw_client_version_restore(a->sess, path_buf, version_id);
        ipc_send_u32(conn, VW_IPC_VERSION_RESTORE_RESP, (uint32_t)rc);
        break;
    }

    case VW_IPC_SEARCH_REQ: {
        if (plen < 4u) { ipc_send_u32(conn, VW_IPC_SEARCH_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t off = 0;
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        const char *query = NULL; uint16_t query_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &query, &query_len);
        if (err != VW_OK || !a || !a->sess) {
            uint8_t rbuf[9] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : !a->sess ? VW_ERR_AUTH_REQUIRED : err));
            vw_ipc_send(conn, VW_IPC_SEARCH_RESP, rbuf, sizeof(rbuf));
            break;
        }
        char query_buf[257];
        size_t qcopy = query_len < sizeof(query_buf) - 1u ? query_len : sizeof(query_buf) - 1u;
        memcpy(query_buf, query, qcopy); query_buf[qcopy] = '\0';

        vw_search_entry_t *entries = NULL; uint32_t count = 0; uint8_t truncated = 0;
        vw_err_t rc = vw_client_search(a->sess, query_buf, &entries, &count, &truncated);
        uint8_t *rbuf = malloc(65536);
        if (!rbuf) { free(entries); ipc_send_u32(conn, VW_IPC_SEARCH_RESP, (uint32_t)VW_ERR_OOM); break; }
        uint32_t roff = 0;
        vw_write_u32le(rbuf + roff, (uint32_t)rc); roff += 4u;
        vw_write_u32le(rbuf + roff, (rc == VW_OK) ? count : 0u); roff += 4u;
        rbuf[roff++] = (rc == VW_OK) ? truncated : 0u;
        if (rc == VW_OK) {
            for (uint32_t i = 0; i < count; i++) {
                uint16_t name_len = (uint16_t)strlen(entries[i].name);
                uint32_t entry_cap = 8u + 2u + name_len + 1u + 8u + 8u + 8u + 1u;
                if (roff + entry_cap > 65536u) break; /* defensive; server's own 200-cap keeps this well under */
                vw_write_u64le(rbuf + roff, entries[i].file_id); roff += 8u;
                (void)vw_ipc_write_str(rbuf, 65536u, &roff, entries[i].name, name_len);
                rbuf[roff++] = entries[i].is_dir;
                vw_write_u64le(rbuf + roff, entries[i].size_bytes); roff += 8u;
                vw_write_u64le(rbuf + roff, (uint64_t)entries[i].mtime_unix); roff += 8u;
                vw_write_u64le(rbuf + roff, entries[i].vault_id); roff += 8u;
                rbuf[roff++] = entries[i].is_shared;
            }
        }
        free(entries);
        vw_ipc_send(conn, VW_IPC_SEARCH_RESP, rbuf, roff);
        free(rbuf);
        break;
    }

    case VW_IPC_NOTIFY_PREFS_GET_REQ: {
        if (plen < 4u) { ipc_send_u32(conn, VW_IPC_NOTIFY_PREFS_GET_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            uint8_t rbuf[8] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            vw_ipc_send(conn, VW_IPC_NOTIFY_PREFS_GET_RESP, rbuf, sizeof(rbuf));
            break;
        }
        /* Read-only fallback restricts writes, not reads (§7.13/TASK-209's
         * own acceptance criterion) — always dispatched, even on fallback. */
        uint32_t prefs = 0;
        vw_err_t rc = vw_client_notify_prefs_get(a->sess, &prefs);
        uint8_t rbuf[8];
        vw_write_u32le(rbuf, (uint32_t)rc);
        vw_write_u32le(rbuf + 4, (rc == VW_OK) ? prefs : 0u);
        vw_ipc_send(conn, VW_IPC_NOTIFY_PREFS_GET_RESP, rbuf, sizeof(rbuf));
        break;
    }

    case VW_IPC_NOTIFY_PREFS_SET_REQ: {
        if (plen < 8u) { ipc_send_u32(conn, VW_IPC_NOTIFY_PREFS_SET_ACK, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf);
        uint32_t requested  = vw_read_u32le(buf + 4);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            uint8_t rbuf[8] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            vw_ipc_send(conn, VW_IPC_NOTIFY_PREFS_SET_ACK, rbuf, sizeof(rbuf));
            break;
        }
        if (account_is_read_only(a)) {
            uint8_t rbuf[8] = {0};
            vw_write_u32le(rbuf, (uint32_t)VW_ERR_READ_ONLY_FALLBACK);
            vw_ipc_send(conn, VW_IPC_NOTIFY_PREFS_SET_ACK, rbuf, sizeof(rbuf));
            break;
        }
        uint32_t stored = 0;
        vw_err_t rc = vw_client_notify_prefs_set(a->sess, requested, &stored);
        uint8_t rbuf[8];
        vw_write_u32le(rbuf, (uint32_t)rc);
        vw_write_u32le(rbuf + 4, stored);
        vw_ipc_send(conn, VW_IPC_NOTIFY_PREFS_SET_ACK, rbuf, sizeof(rbuf));
        break;
    }

    case VW_IPC_ACCOUNT_EMAIL_GET_REQ: {
        if (plen < 4u) { ipc_send_u32(conn, VW_IPC_ACCOUNT_EMAIL_GET_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            uint8_t rbuf[4u + 2u] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            vw_ipc_send(conn, VW_IPC_ACCOUNT_EMAIL_GET_RESP, rbuf, sizeof(rbuf));
            break;
        }
        /* Read-only fallback restricts writes, not reads (same posture as
         * NOTIFY_PREFS_GET above) — always dispatched, even on fallback. */
        char email[129];
        vw_err_t rc = vw_client_account_email_get(a->sess, email, sizeof(email));
        uint8_t rbuf[4u + 2u + 128u];
        uint32_t roff = 0;
        vw_write_u32le(rbuf, (uint32_t)rc); roff += 4u;
        (void)vw_ipc_write_str(rbuf, sizeof(rbuf), &roff, (rc == VW_OK) ? email : "",
                                (uint16_t)((rc == VW_OK) ? strlen(email) : 0u));
        vw_ipc_send(conn, VW_IPC_ACCOUNT_EMAIL_GET_RESP, rbuf, roff);
        break;
    }

    case VW_IPC_ACCOUNT_EMAIL_SET_REQ: {
        if (plen < 4u) { ipc_send_u32(conn, VW_IPC_ACCOUNT_EMAIL_SET_ACK, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t off = 0;
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        const char *email = NULL; uint16_t email_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &email, &email_len);
        if (err != VW_OK || !a || !a->sess) {
            uint8_t rbuf[4u + 2u] = {0};
            vw_write_u32le(rbuf, (uint32_t)(err != VW_OK ? VW_ERR_PROTO_TRUNCATED :
                                             !a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            vw_ipc_send(conn, VW_IPC_ACCOUNT_EMAIL_SET_ACK, rbuf, sizeof(rbuf));
            break;
        }
        if (account_is_read_only(a)) {
            uint8_t rbuf[4u + 2u] = {0};
            vw_write_u32le(rbuf, (uint32_t)VW_ERR_READ_ONLY_FALLBACK);
            vw_ipc_send(conn, VW_IPC_ACCOUNT_EMAIL_SET_ACK, rbuf, sizeof(rbuf));
            break;
        }
        char email_buf[129];
        size_t ecopy = email_len < sizeof(email_buf) - 1u ? email_len : sizeof(email_buf) - 1u;
        memcpy(email_buf, email, ecopy); email_buf[ecopy] = '\0';

        char stored[129];
        vw_err_t rc = vw_client_account_email_set(a->sess, email_buf, stored, sizeof(stored));
        uint8_t rbuf[4u + 2u + 128u];
        uint32_t roff = 0;
        vw_write_u32le(rbuf, (uint32_t)rc); roff += 4u;
        (void)vw_ipc_write_str(rbuf, sizeof(rbuf), &roff, (rc == VW_OK) ? stored : "",
                                (uint16_t)((rc == VW_OK) ? strlen(stored) : 0u));
        vw_ipc_send(conn, VW_IPC_ACCOUNT_EMAIL_SET_ACK, rbuf, roff);
        break;
    }

    case VW_IPC_VERSION_LIST_BY_ID_REQ: {
        if (plen < 12u) { ipc_send_u32(conn, VW_IPC_VERSION_LIST_BY_ID_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf);
        uint64_t file_id = vw_read_u64le(buf + 4);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            uint8_t rbuf[8] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            vw_ipc_send(conn, VW_IPC_VERSION_LIST_BY_ID_RESP, rbuf, sizeof(rbuf));
            break;
        }

        vw_version_entry_t *entries = NULL; uint32_t count = 0;
        vw_err_t rc = vw_client_version_list_by_id(a->sess, file_id, &entries, &count);
        uint8_t *rbuf = malloc(65536);
        if (!rbuf) { free(entries); ipc_send_u32(conn, VW_IPC_VERSION_LIST_BY_ID_RESP, (uint32_t)VW_ERR_OOM); break; }
        uint32_t roff = 0;
        vw_write_u32le(rbuf + roff, (uint32_t)rc); roff += 4;
        vw_write_u32le(rbuf + roff, (rc == VW_OK) ? count : 0u); roff += 4;
        if (rc == VW_OK) {
            for (uint32_t i = 0; i < count && roff + 24u <= 65536u; i++) {
                vw_write_u64le(rbuf + roff, entries[i].version_id); roff += 8;
                vw_write_u64le(rbuf + roff, (uint64_t)entries[i].created_at); roff += 8;
                vw_write_u64le(rbuf + roff, entries[i].size_bytes); roff += 8;
            }
        }
        free(entries);
        vw_ipc_send(conn, VW_IPC_VERSION_LIST_BY_ID_RESP, rbuf, roff);
        free(rbuf);
        break;
    }

    case VW_IPC_VERSION_RESTORE_BY_ID_REQ: {
        if (plen < 12u) { ipc_send_u32(conn, VW_IPC_VERSION_RESTORE_BY_ID_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf);
        uint64_t version_id = vw_read_u64le(buf + 4);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            ipc_send_u32(conn, VW_IPC_VERSION_RESTORE_BY_ID_RESP,
                         (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            break;
        }
        if (account_is_read_only(a)) {
            ipc_send_u32(conn, VW_IPC_VERSION_RESTORE_BY_ID_RESP, (uint32_t)VW_ERR_READ_ONLY_FALLBACK);
            break;
        }
        vw_err_t rc = vw_client_version_restore_by_id(a->sess, version_id);
        ipc_send_u32(conn, VW_IPC_VERSION_RESTORE_BY_ID_RESP, (uint32_t)rc);
        break;
    }

    case VW_IPC_ACCOUNT_2FA_SET_REQ: {
        uint32_t off = 0;
        if (off + 4u > plen) { ipc_send_u32(conn, VW_IPC_ACCOUNT_2FA_SET_ACK, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf + off); off += 4u;
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        const char *pw = NULL; uint16_t pw_len = 0;
        vw_err_t perr = vw_ipc_read_str(buf, plen, &off, &pw, &pw_len);
        uint8_t enable = 0;
        if (perr == VW_OK && off + 1u <= plen) {
            enable = buf[off]; off += 1u;
        } else if (perr == VW_OK) {
            perr = VW_ERR_PROTO_TRUNCATED;
        }
        if (perr != VW_OK || pw_len == 0 || !a || !a->sess) {
            uint8_t rbuf[5] = {0};
            vw_write_u32le(rbuf, (uint32_t)(perr != VW_OK ? perr :
                                             pw_len == 0 ? VW_ERR_INVALID_ARG :
                                             !a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            vw_ipc_send(conn, VW_IPC_ACCOUNT_2FA_SET_ACK, rbuf, sizeof(rbuf));
            break;
        }
        if (account_is_read_only(a)) {
            uint8_t rbuf[5] = {0};
            vw_write_u32le(rbuf, (uint32_t)VW_ERR_READ_ONLY_FALLBACK);
            vw_ipc_send(conn, VW_IPC_ACCOUNT_2FA_SET_ACK, rbuf, sizeof(rbuf));
            break;
        }
        uint8_t stored = 0;
        vw_err_t rc = vw_client_account_2fa_set(a->sess, pw, pw_len,
                                                 enable ? 1 : 0, &stored);
        uint8_t rbuf[5];
        vw_write_u32le(rbuf, (uint32_t)rc);
        rbuf[4] = (rc == VW_OK) ? stored : 0;
        vw_ipc_send(conn, VW_IPC_ACCOUNT_2FA_SET_ACK, rbuf, sizeof(rbuf));
        break;
    }

    case VW_IPC_ACCOUNT_2FA_GET_REQ: {
        if (plen < 4u) { ipc_send_u32(conn, VW_IPC_ACCOUNT_2FA_GET_RESP, (uint32_t)VW_ERR_PROTO_TRUNCATED); break; }
        uint32_t account_id = vw_read_u32le(buf);
        vw_account_ctx_t *a = account_find(dc->accounts, account_id);
        if (!a || !a->sess) {
            uint8_t rbuf[5] = {0};
            vw_write_u32le(rbuf, (uint32_t)(!a ? VW_ERR_INVALID_ARG : VW_ERR_AUTH_REQUIRED));
            vw_ipc_send(conn, VW_IPC_ACCOUNT_2FA_GET_RESP, rbuf, sizeof(rbuf));
            break;
        }
        uint8_t enabled = 0;
        vw_err_t rc = vw_client_account_2fa_get(a->sess, &enabled);
        uint8_t rbuf[5];
        vw_write_u32le(rbuf, (uint32_t)rc);
        rbuf[4] = (rc == VW_OK) ? enabled : 0;
        vw_ipc_send(conn, VW_IPC_ACCOUNT_2FA_GET_RESP, rbuf, sizeof(rbuf));
        break;
    }

    default:
        break; /* unknown message: ignore */
    }

    /* buf may have held a raw password (ACCOUNT_ADD_REQ) — zero it
     * unconditionally, matching the admin IPC's payload-zeroing convention. */
    memset(buf, 0, sizeof(buf));
}

/* ── Connection attempt ──────────────────────────────────────────────────── */

/*
 * TASK-173: the single place that ever assigns a->sess/a->conn_mode —
 * keeps them, and the sync context's mirrored session/read_only flags,
 * moving together so no call site can set one without the others. Pass
 * sess = NULL to go offline (mode is ignored in that case).
 */
static void account_set_conn(vw_account_ctx_t *a, vw_client_sess_t *sess,
                              vw_account_conn_mode_t mode) {
    a->sess      = sess;
    a->conn_mode = sess ? mode : VW_ACCOUNT_CONN_OFFLINE;
    vw_sync_set_session(a->sync_ctx, a->sess);
    vw_sync_set_read_only(a->sync_ctx, a->conn_mode == VW_ACCOUNT_CONN_FALLBACK);
}

/* Try a session-token resume against the primary. Returns NULL (offline)
 * if no valid token is on disk or the resume itself fails — never attempts
 * a fresh password login (the daemon has no password to use here; see
 * try_connect_fallback for why the fallback path is different). */
static vw_client_sess_t *try_connect_primary(const vw_account_cfg_t *acfg,
                                               const char *account_dir) {
    if (!acfg->server_host[0]) return NULL;

    vw_client_cfg_t cc;
    memset(&cc, 0, sizeof(cc));
    cc.host         = acfg->server_host;
    cc.port         = acfg->server_port;
    cc.cert_verify      = VW_CERT_VERIFY_REQUIRED;
    cc.ca_cert_pem_path = acfg->ca_cert_pem_path[0] ? acfg->ca_cert_pem_path : NULL;

    /* Try session token resume first */
    uint8_t tok[VW_TOKEN_BYTES];
    if (tok_load(account_dir, tok) == VW_OK) {
        vw_client_sess_t *sess = NULL;
        if (vw_client_resume(&cc, tok, &sess) == VW_OK) {
            vw_log(LOG_INFO, "session resumed for account '%s'", acfg->username);
            /* Persist fresh token */
            vw_client_get_token(sess, tok);
            tok_save(account_dir, tok);
            return sess;
        }
        vw_log(LOG_WARN, "session resume failed for account '%s', continuing offline", acfg->username);
    }

    /* No valid token: offline mode */
    return NULL;
}

/*
 * TASK-173: attempt an unattended fresh connect against this account's
 * configured fallback server, using the retained login_token (SHA-256 of
 * the last password this account authenticated with) instead of a saved
 * SESSION_RESUME token — a primary-issued resume token is meaningless
 * against a different server (§7.1). Returns NULL if no fallback is
 * configured, no login_token is available yet (e.g. daemon just restarted
 * and this account hasn't re-authenticated since), or the connect itself
 * fails (including VW_ERR_AUTH_2FA_REQUIRED — no OTP callback is passed;
 * this is a background, unattended attempt, so a 2FA-enabled account
 * simply can't fail over automatically).
 */
static vw_client_sess_t *try_connect_fallback(vw_account_ctx_t *a) {
    if (!a->cfg.fallback_host[0] || !a->have_login_token) return NULL;

    vw_client_cfg_t cc;
    memset(&cc, 0, sizeof(cc));
    cc.host             = a->cfg.fallback_host;
    cc.port             = a->cfg.fallback_port;
    cc.cert_verify      = VW_CERT_VERIFY_REQUIRED;
    cc.ca_cert_pem_path = a->cfg.fallback_ca_cert_pem_path[0]
                          ? a->cfg.fallback_ca_cert_pem_path : NULL;

    vw_client_sess_t *sess = NULL;
    vw_err_t rc = vw_client_connect_with_hash(&cc, a->cfg.username,
                                               (uint16_t)strlen(a->cfg.username),
                                               a->login_token, NULL, NULL, &sess);
    if (rc != VW_OK) {
        vw_log(LOG_WARN, "fallback connect failed for account '%s': %d",
               a->cfg.username, (int)rc);
        return NULL;
    }
    vw_log(LOG_INFO, "account '%s' connected to its read-only fallback %s:%u",
           a->cfg.username, a->cfg.fallback_host, (unsigned)a->cfg.fallback_port);
    return sess;
}

/*
 * TASK-173: assumes a->sess is already NULL (caller closed/logged out any
 * prior session first). Tries primary, then — only if that fails — the
 * fallback. Leaves the account offline (a->sess stays NULL) if neither
 * works. Used both at startup and by the round-robin reconnect loop.
 */
static void account_reconnect(vw_account_ctx_t *a) {
    vw_client_sess_t *sess = try_connect_primary(&a->cfg, a->account_dir);
    if (sess) {
        account_set_conn(a, sess, VW_ACCOUNT_CONN_PRIMARY);
        vw_log(LOG_INFO, "reconnected account '%s' to primary", a->cfg.username);
        return;
    }
    sess = try_connect_fallback(a);
    if (sess) account_set_conn(a, sess, VW_ACCOUNT_CONN_FALLBACK);
}

/* Opens (or reopens, at startup) one account's context from its already-
 * existing accounts/<account_id>/ subtree: loads account.conf, opens its
 * cache + sync context, and attempts a token resume (primary) then, if
 * that fails and a fallback is configured, a fresh fallback connect.
 * Returns VW_OK with *out populated (sess may be NULL — offline) on
 * success. login_token is loaded from disk (if present) regardless of
 * whether it ends up being used this call — it's still needed later if
 * the primary later goes down mid-session (see the round-robin loop). */
static vw_err_t account_ctx_open_existing(const char *account_dir, uint32_t account_id,
                                            vw_account_ctx_t *out) {
    memset(out, 0, sizeof(*out));
    out->account_id = account_id;
    snprintf(out->account_dir, sizeof(out->account_dir), "%s", account_dir);

    vw_err_t err = account_cfg_load(account_dir, &out->cfg);
    if (err != VW_OK) return err;

    err = vw_cache_open(account_dir, &out->cache);
    if (err != VW_OK) return err;

    out->have_login_token =
        (login_token_load(account_dir, out->login_token) == VW_OK);

    out->sess = try_connect_primary(&out->cfg, account_dir);
    if (out->sess) {
        out->conn_mode = VW_ACCOUNT_CONN_PRIMARY;
    } else {
        out->sess = try_connect_fallback(out);
        if (out->sess) out->conn_mode = VW_ACCOUNT_CONN_FALLBACK;
    }

    vw_sync_cfg_t sc;
    sc.sess = out->sess; sc.cache = out->cache; sc.state_dir = account_dir;
    err = vw_sync_open(&sc, &out->sync_ctx);
    if (err != VW_OK) {
        if (out->sess) vw_client_close(out->sess);
        vw_cache_close(out->cache);
        account_cfg_free_excludes(&out->cfg);
        return err;
    }
    /* TASK-192/193: mirror the persisted rules into the freshly-opened
     * live sync engine — account.conf is the durable source of truth,
     * vw_sync_ctx_t's own copy (see vw_sync_set_folder_excludes) is what
     * vw_sync_run actually consults each cycle. */
    for (uint32_t i = 0; i < out->cfg.folder_excludes_count; i++) {
        const vw_folder_excludes_cfg_t *fe = &out->cfg.folder_excludes[i];
        (void)vw_sync_set_folder_excludes(out->sync_ctx, fe->local_root,
                                           (const char *const *)fe->patterns, fe->count);
    }
    if (out->conn_mode == VW_ACCOUNT_CONN_FALLBACK)
        vw_sync_set_read_only(out->sync_ctx, 1);
    return VW_OK;
}

/* Scans {state_dir}/accounts/ for existing account_id subdirectories and
 * opens each one via account_ctx_open_existing, populating reg. A
 * subdirectory whose name isn't a plain decimal number, or that fails to
 * open (corrupt/incomplete — e.g. missing account.conf), is skipped with a
 * warning rather than aborting the whole daemon startup: one bad account
 * must not take every other configured account offline. */
typedef struct { const char *state_dir; account_registry_t *reg; } scan_ud_t;

static int scan_accounts_cb(const char *name, void *userdata) {
    scan_ud_t *ud = (scan_ud_t *)userdata;
    char *endp = NULL;
    unsigned long id_ul = strtoul(name, &endp, 10);
    if (!endp || *endp != '\0' || id_ul == 0) return 0; /* not a plain number, or 0 (invalid) */
    uint32_t account_id = (uint32_t)id_ul;

    char account_dir[600];
    snprintf(account_dir, sizeof(account_dir), "%s/%s/%s", ud->state_dir, ACCOUNTS_DIR, name);

    vw_account_ctx_t tmp;
    vw_err_t err = account_ctx_open_existing(account_dir, account_id, &tmp);
    if (err != VW_OK) {
        vw_log(LOG_WARN, "skipping unreadable account dir '%s': %d", account_dir, (int)err);
        return 0;
    }
    vw_account_ctx_t *slot = account_add_slot(ud->reg);
    if (!slot) {
        vw_log(LOG_ERROR, "OOM adding account slot for '%s'", account_dir);
        if (tmp.sess) vw_client_close(tmp.sess);
        vw_sync_close(tmp.sync_ctx);
        vw_cache_close(tmp.cache);
        account_cfg_free_excludes(&tmp.cfg);
        return 0;
    }
    *slot = tmp;
    if (account_id >= ud->reg->next_account_id) ud->reg->next_account_id = account_id + 1;
    return 0;
}

static void account_registry_scan(const char *state_dir, account_registry_t *reg) {
    char accounts_root[600];
    snprintf(accounts_root, sizeof(accounts_root), "%s/%s", state_dir, ACCOUNTS_DIR);
    vw_fs_ensure_dir(accounts_root);
    scan_ud_t ud = { state_dir, reg };
    (void)vw_fs_list_dir(accounts_root, scan_accounts_cb, &ud);
}

/* ── Main event loop ─────────────────────────────────────────────────────── */

vw_err_t vw_daemon_run(const vw_daemon_cfg_t *cfg, int daemon_mode) {
    if (!cfg) return VW_ERR_INVALID_ARG;

    /* Daemonize on Linux if requested */
#if defined(__linux__)
    if (daemon_mode) {
        if (daemon(1, 0) != 0) {
            fprintf(stderr, "daemon() failed: %s\n", strerror(errno));
            return VW_ERR_IO;
        }
    }
#endif

    log_init(cfg->state_dir, daemon_mode);
    install_signal_handlers();

    vw_log(LOG_INFO, "VaporWault daemon starting");

    /* TASK-100 finding: nothing in the daemon's process lifetime called
     * vw_crypto_init() before vaults existed — login only ever needed
     * vw_crypto_sha256 (no init required) and Argon2id runs server-side,
     * so this was a latent gap invisible until VAULT_CREATE/_UNLOCK
     * needed vw_crypto_random/_vault_derive_kek/_aes256gcm_* in this
     * process. Without it, vw_crypto_random() fails fast with
     * VW_ERR_CRYPTO (see vw_crypto.c's g_initialized guard), which is
     * exactly what surfaced this via the TASK-100 IPC diagnostic check. */
    if (vw_crypto_init() != VW_OK) {
        vw_log(LOG_ERROR, "vw_crypto_init failed");
        return VW_ERR_CRYPTO;
    }

    vw_err_t err = vw_fs_ensure_dir(cfg->state_dir);
    if (err != VW_OK) {
        vw_log(LOG_ERROR, "cannot create state_dir: %s", cfg->state_dir);
        return err;
    }

    /* 1. Scan and open every already-configured account (TASK-161) */
    account_registry_t accounts = {0};
    accounts.next_account_id = 1; /* 0 is reserved for "create new" in ACCOUNT_ADD_REQ */
    account_registry_scan(cfg->state_dir, &accounts);
    vw_log(LOG_INFO, "loaded %zu configured account(s)", accounts.count);

    /* 2. Open IPC server */
    vw_ipc_server_t *ipc_srv = NULL;
    err = vw_ipc_server_open(cfg->ipc_port, &ipc_srv);
    if (err != VW_OK) {
        vw_log(LOG_ERROR, "cannot bind IPC port %u", (unsigned)cfg->ipc_port);
        for (size_t i = 0; i < accounts.count; i++) {
            vw_account_ctx_t *a = &accounts.accounts[i];
            vw_sync_close(a->sync_ctx);
            if (a->sess) vw_client_close(a->sess);
            vw_cache_close(a->cache);
            account_cfg_free_excludes(&a->cfg);
        }
        free(accounts.accounts);
        return err;
    }

    /* 3. Write PID file (after IPC bind confirms we're not a duplicate) */
    err = pid_file_create(cfg->state_dir);
    if (err != VW_OK) {
        vw_ipc_server_close(ipc_srv);
        for (size_t i = 0; i < accounts.count; i++) {
            vw_account_ctx_t *a = &accounts.accounts[i];
            vw_sync_close(a->sync_ctx);
            if (a->sess) vw_client_close(a->sess);
            vw_cache_close(a->cache);
            account_cfg_free_excludes(&a->cfg);
        }
        free(accounts.accounts);
        return err;
    }

    /* 4. Open one shared watcher and add every account's sync folders to it.
     * A single watcher across all accounts is safe: vw_sync_mark_local_
     * modified() (step 6 below) already self-scopes to whichever account's
     * own registered folders a given path falls under (it walks that
     * account's own vw_cache_folder_list and no-ops if nothing matches) —
     * see vw_sync.c. There is no need to track which account owns which
     * local_root at this layer. */
    vw_watcher_t *watcher = NULL;
    err = vw_watcher_open(1024, &watcher);
    if (err != VW_OK) {
        vw_log(LOG_WARN, "watcher init failed (%d), continuing without watch", (int)err);
        watcher = NULL;
    }
    if (watcher) {
        for (size_t i = 0; i < accounts.count; i++) {
            vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
            vw_cache_folder_list(accounts.accounts[i].cache, &folders, &nf);
            for (uint32_t j = 0; j < nf; j++)
                vw_watcher_add(watcher, folders[j].local_root);
            free(folders);
        }
    }

    if (accounts.count == 0)
        vw_log(LOG_INFO, "no accounts configured yet — waiting for VW_IPC_ACCOUNT_ADD_REQ");

    /* ── Main loop ──────────────────────────────────────────────────────── */

    int sync_now = 0;
    int shutdown  = 0;

    ipc_dispatch_ctx_t dc;
    dc.accounts      = &accounts;
    dc.watcher       = watcher;
    dc.sync_now_flag = &sync_now;
    dc.shutdown_flag = &shutdown;
    dc.state_dir     = cfg->state_dir;

    vw_log(LOG_INFO, "daemon ready (ipc_port=%u sync_interval=%ums)",
           (unsigned)cfg->ipc_port, (unsigned)cfg->sync_interval_ms);

    while (!g_shutdown && !shutdown) {

        /* a. Wait for filesystem events (or timeout) */
        if (watcher) {
            vw_watcher_wait(watcher, cfg->sync_interval_ms);

            /* b. Drain watch events */
            if (vw_watcher_overflowed(watcher)) {
                vw_log(LOG_WARN, "watcher ring overflow — full rescan queued");
                sync_now = 1;
            }
            vw_watch_event_t evts[256]; uint32_t nevts = 256;
            vw_watcher_drain(watcher, evts, &nevts);
            for (uint32_t i = 0; i < nevts; i++) {
                if (evts[i].type == VW_WATCH_CREATED ||
                    evts[i].type == VW_WATCH_MODIFIED ||
                    evts[i].type == VW_WATCH_MOVED) {
                    for (size_t j = 0; j < accounts.count; j++) {
                        vw_sync_ctx_t *sc2 = accounts.accounts[j].sync_ctx;
                        vw_sync_mark_local_modified(sc2, evts[i].path);
                        if (evts[i].type == VW_WATCH_MOVED && evts[i].old_path[0]) {
                            /* old_path was deleted */
                            vw_sync_mark_local_modified(sc2, evts[i].old_path);
                        }
                    }
                }
                /* DELETED events: next sync walk will detect the missing file */
            }
        } else {
            /* No watcher: sleep for sync interval (poll-only mode) */
#ifdef _WIN32
            Sleep(cfg->sync_interval_ms);
#else
            struct timespec ts;
            ts.tv_sec  = cfg->sync_interval_ms / 1000;
            ts.tv_nsec = (cfg->sync_interval_ms % 1000) * 1000000L;
            nanosleep(&ts, NULL);
#endif
        }

        /* c. Accept and dispatch pending IPC connections */
        {
            vw_ipc_conn_t *client = NULL;
            while (vw_ipc_server_try_accept(ipc_srv, &client) == VW_OK) {
                handle_ipc_client(client, &dc);
                vw_ipc_conn_close(client);
                client = NULL;
                if (shutdown) break;
            }
        }

        if (shutdown || g_shutdown) break;

        /* d. Round-robin one sync cycle per account (TASK-161) — every
         * configured account keeps syncing every tick regardless of which
         * one, if any, a connected GUI/CLI happens to be querying right
         * now. Reconnect-if-needed is per account too. */
        for (size_t i = 0; i < accounts.count; i++) {
            vw_account_ctx_t *a = &accounts.accounts[i];

            if (!a->sess) {
                account_reconnect(a);
            } else if (a->conn_mode == VW_ACCOUNT_CONN_FALLBACK) {
                /* TASK-173 acceptance criterion: keep probing the primary
                 * in the background while parked on the read-only
                 * fallback, so the daemon transparently switches back
                 * (and the next vw_sync_run drains the offline queue)
                 * the moment the primary is reachable again — never just
                 * stays on the fallback indefinitely. A failed probe
                 * leaves the working fallback connection untouched. */
                vw_client_sess_t *primary_sess = try_connect_primary(&a->cfg, a->account_dir);
                if (primary_sess) {
                    vw_client_logout(a->sess);  /* the fallback session */
                    account_set_conn(a, primary_sess, VW_ACCOUNT_CONN_PRIMARY);
                    vw_log(LOG_INFO, "account '%s' reconnected to primary; leaving fallback",
                           a->cfg.username);
                } else {
                    int64_t exp = vw_client_expires_at_of(a->sess);
                    if (exp > 0 && (int64_t)time(NULL) >= exp) {
                        vw_log(LOG_INFO, "fallback session expired for account '%s', re-connecting",
                               a->cfg.username);
                        vw_client_close(a->sess);
                        account_set_conn(a, NULL, VW_ACCOUNT_CONN_OFFLINE);
                        account_reconnect(a);
                    }
                }
            } else {
                int64_t exp = vw_client_expires_at_of(a->sess);
                if (exp > 0 && (int64_t)time(NULL) >= exp) {
                    vw_log(LOG_INFO, "session expired for account '%s', re-connecting", a->cfg.username);
                    vw_client_close(a->sess);
                    account_set_conn(a, NULL, VW_ACCOUNT_CONN_OFFLINE);
                    account_reconnect(a);
                }
            }

            a->error_count = 0;
            vw_err_t serr = vw_sync_run(a->sync_ctx);
            if (serr == VW_OK) {
                a->last_sync_at = (int64_t)time(NULL);
                vw_log(LOG_DEBUG, "sync cycle complete for '%s' (pending=%u)",
                       a->cfg.username, (unsigned)vw_sync_pending_count(a->sync_ctx));
            } else {
                a->error_count++;
                vw_log(LOG_WARN, "sync cycle error for '%s': %d", a->cfg.username, (int)serr);
                if (serr == VW_ERR_NET_CLOSED || serr == VW_ERR_NET_TIMEOUT) {
                    if (a->sess) {
                        vw_client_close(a->sess);
                        account_set_conn(a, NULL, VW_ACCOUNT_CONN_OFFLINE);
                    }
                }
            }
            /* TASK-112: fold in per-action failures (e.g. quota rejections)
             * that vw_sync_run itself treats as non-fatal for the cycle. */
            uint32_t action_errs = vw_sync_action_error_count(a->sync_ctx);
            if (action_errs > 0)
                vw_log(LOG_WARN, "sync cycle for '%s' had %u action error(s)",
                       a->cfg.username, (unsigned)action_errs);
            a->error_count += action_errs;

            /* TASK-113: logged distinctly, and NOT folded into error_count —
             * status reports it as its own field so a permission problem
             * doesn't look like every other kind of action failure. */
            uint32_t perm_denied = vw_sync_permission_denied_count(a->sync_ctx);
            if (perm_denied > 0)
                vw_log(LOG_WARN,
                       "sync cycle for '%s' had %u permission-denied shared-folder mkdir attempt(s)",
                       a->cfg.username, (unsigned)perm_denied);
        }

        sync_now = 0;
    }

    /* ── Shutdown ───────────────────────────────────────────────────────── */
    vw_log(LOG_INFO, "shutting down");

    for (size_t i = 0; i < accounts.count; i++) {
        vw_account_ctx_t *a = &accounts.accounts[i];
        vault_registry_close_all(&a->vaults);
        vw_sync_close(a->sync_ctx);
        /* vw_client_close(), not vw_client_logout(): this is the daemon
         * process exiting (SIGTERM/service stop), not a user-initiated
         * logout — the persisted session.tok is meant to let the next
         * daemon start resume this exact session (vw_client_resume's own
         * doc pairs it with vw_client_close for this reason). Since
         * TASK-237 made AUTH_LOGOUT actually revoke the session
         * server-side, calling vw_client_logout() here was silently
         * invalidating the very token a restart is supposed to resume. */
        if (a->sess) vw_client_close(a->sess);
        vw_cache_close(a->cache);
        account_cfg_free_excludes(&a->cfg);
    }
    free(accounts.accounts);
    vw_watcher_close(watcher);
    vw_ipc_server_close(ipc_srv);
    pid_file_remove();
    vw_crypto_cleanup();

    if (g_log_fp && g_log_to_file) fclose(g_log_fp);
    return VW_OK;
}
