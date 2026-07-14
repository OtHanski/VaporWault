#include "vw_daemon.h"
#include "vw_cache.h"
#include "vw_sync.h"
#include "vw_watch.h"
#include "vw_ipc.h"
#include "vw_client_core.h"
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
#define PID_FILE             "daemon.pid"
#define LOG_FILE             "daemon.log"
#define CONFIG_FILE          "daemon.conf"
#define LOG_ROTATE_BYTES     (10 * 1024 * 1024L)

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
        snprintf(g_log_path, sizeof(g_log_path), "%s/%s", state_dir, LOG_FILE);
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
    snprintf(g_pid_path, sizeof(g_pid_path), "%s/%s", state_dir, PID_FILE);

    /* Check if a running daemon already holds the PID file */
    FILE *fp = fopen(g_pid_path, "r");
    if (fp) {
        int old_pid = 0;
        fscanf(fp, "%d", &old_pid);
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
    (void)write(fd, buf, (size_t)n);
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

/* ── Config parser ───────────────────────────────────────────────────────── */

static void cfg_defaults(vw_daemon_cfg_t *c) {
    c->server_port     = (uint16_t)DEFAULT_PORT;
    c->ipc_port        = (uint16_t)DEFAULT_IPC_PORT;
    c->sync_interval_ms = DEFAULT_SYNC_MS;
}

static void cfg_apply_kv(vw_daemon_cfg_t *c, const char *key, const char *val) {
    if (strcmp(key, "server_host")      == 0)
        snprintf(c->server_host, sizeof(c->server_host), "%s", val);
    else if (strcmp(key, "server_port") == 0)
        c->server_port = (uint16_t)strtoul(val, NULL, 10);
    else if (strcmp(key, "ca_cert_pem_path") == 0)
        snprintf(c->ca_cert_pem_path, sizeof(c->ca_cert_pem_path), "%s", val);
    else if (strcmp(key, "username")    == 0)
        snprintf(c->username, sizeof(c->username), "%s", val);
    else if (strcmp(key, "ipc_port")   == 0)
        c->ipc_port = (uint16_t)strtoul(val, NULL, 10);
    else if (strcmp(key, "sync_interval_ms") == 0)
        c->sync_interval_ms = (uint32_t)strtoul(val, NULL, 10);
    /* Unknown keys are silently ignored (forward-compat). */
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
    fprintf(fp, "server_host     = %s\n", cfg->server_host[0] ? cfg->server_host : "localhost");
    fprintf(fp, "server_port     = %u\n", (unsigned)cfg->server_port);
    fprintf(fp, "ca_cert_pem_path = %s\n", cfg->ca_cert_pem_path);
    fprintf(fp, "username        = %s\n", cfg->username);
    fprintf(fp, "ipc_port        = %u\n", (unsigned)cfg->ipc_port);
    fprintf(fp, "sync_interval_ms = %u\n", (unsigned)cfg->sync_interval_ms);
    fclose(fp);
    return VW_OK;
}

/* ── IPC message helpers ─────────────────────────────────────────────────── */

static void ipc_send_u32(vw_ipc_conn_t *conn, vw_ipc_msg_t type, uint32_t code) {
    uint8_t buf[4];
    vw_write_u32le(buf, code);
    vw_ipc_send(conn, type, buf, 4);
}

/* ── IPC dispatch ────────────────────────────────────────────────────────── */

typedef struct {
    vw_cache_t       *cache;
    vw_sync_ctx_t    *sync_ctx;
    vw_watcher_t     *watcher;
    vw_client_sess_t *sess;
    int               paused_all;
    int64_t           last_sync_at;
    uint32_t          error_count;
    int              *sync_now_flag;
    int              *shutdown_flag;
} ipc_dispatch_ctx_t;

static void handle_ipc_client(vw_ipc_conn_t *conn, ipc_dispatch_ctx_t *dc) {
    /* Set 1-second recv timeout */
    vw_ipc_conn_set_recv_timeout(conn, 1000);

    uint8_t buf[65536];
    vw_ipc_msg_t type;
    uint32_t plen = 0;
    vw_err_t err = vw_ipc_recv(conn, &type, buf, sizeof(buf), &plen);
    if (err != VW_OK) return; /* client disconnected or timeout */

    switch (type) {

    case VW_IPC_STATUS_REQ: {
        uint64_t bd = 0, bt = 0;
        vw_sync_get_progress(dc->sync_ctx, &bd, &bt);
        uint8_t resp[24]; uint32_t off = 0;
        resp[off++] = dc->sess ? 1 : 0;        /* connected */
        resp[off++] = (bd < bt) ? 1 : 0;       /* syncing */
        resp[off++] = (uint8_t)dc->paused_all;
        resp[off++] = 0;                        /* _pad */
        vw_write_u64le(resp + off, (uint64_t)dc->last_sync_at); off += 8;
        uint32_t pending = vw_sync_pending_count(dc->sync_ctx);
        vw_write_u32le(resp + off, pending); off += 4; /* pending_uploads */
        vw_write_u32le(resp + off, 0);       off += 4; /* pending_downloads */
        vw_write_u32le(resp + off, dc->error_count); off += 4;
        vw_ipc_send(conn, VW_IPC_STATUS_RESP, resp, off);
        break;
    }

    case VW_IPC_SYNC_NOW_REQ:
        *dc->sync_now_flag = 1;
        ipc_send_u32(conn, VW_IPC_SYNC_NOW_RESP, 0);
        break;

    case VW_IPC_PAUSE_REQ: {
        uint32_t off = 0;
        const char *lroot = NULL; uint16_t lroot_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &lroot, &lroot_len);
        if (err != VW_OK) { ipc_send_u32(conn, VW_IPC_PAUSE_RESP, (uint32_t)err); break; }
        if (lroot_len == 0) {
            /* Pause all */
            vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
            vw_cache_folder_list(dc->cache, &folders, &nf);
            for (uint32_t i = 0; i < nf; i++)
                vw_cache_folder_set_paused(dc->cache, folders[i].local_root, 1);
            free(folders);
            dc->paused_all = 1;
        } else {
            char path[512];
            size_t cl = lroot_len < sizeof(path) - 1 ? lroot_len : sizeof(path) - 1;
            memcpy(path, lroot, cl); path[cl] = '\0';
            vw_cache_folder_set_paused(dc->cache, path, 1);
        }
        ipc_send_u32(conn, VW_IPC_PAUSE_RESP, 0);
        break;
    }

    case VW_IPC_RESUME_REQ: {
        uint32_t off = 0;
        const char *lroot = NULL; uint16_t lroot_len = 0;
        err = vw_ipc_read_str(buf, plen, &off, &lroot, &lroot_len);
        if (err != VW_OK) { ipc_send_u32(conn, VW_IPC_RESUME_RESP, (uint32_t)err); break; }
        if (lroot_len == 0) {
            vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
            vw_cache_folder_list(dc->cache, &folders, &nf);
            for (uint32_t i = 0; i < nf; i++)
                vw_cache_folder_set_paused(dc->cache, folders[i].local_root, 0);
            free(folders);
            dc->paused_all = 0;
        } else {
            char path[512];
            size_t cl = lroot_len < sizeof(path) - 1 ? lroot_len : sizeof(path) - 1;
            memcpy(path, lroot, cl); path[cl] = '\0';
            vw_cache_folder_set_paused(dc->cache, path, 0);
        }
        ipc_send_u32(conn, VW_IPC_RESUME_RESP, 0);
        break;
    }

    case VW_IPC_FOLDER_ADD_REQ: {
        uint32_t off = 0;
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
        err = vw_cache_folder_add(dc->cache, &f);
        if (err == VW_OK)
            vw_watcher_add(dc->watcher, f.local_root);
        ipc_send_u32(conn, VW_IPC_FOLDER_ADD_RESP, (uint32_t)err);
        break;
    }

    case VW_IPC_FOLDER_REMOVE_REQ: {
        uint32_t off = 0;
        const char *lroot = NULL; uint16_t ll = 0;
        err = vw_ipc_read_str(buf, plen, &off, &lroot, &ll);
        if (err != VW_OK) { ipc_send_u32(conn, VW_IPC_FOLDER_REMOVE_RESP, (uint32_t)err); break; }
        char path[512];
        size_t cl = ll < sizeof(path)-1 ? ll : sizeof(path)-1;
        memcpy(path, lroot, cl); path[cl] = '\0';
        vw_watcher_remove(dc->watcher, path);
        err = vw_cache_folder_remove(dc->cache, path);
        ipc_send_u32(conn, VW_IPC_FOLDER_REMOVE_RESP, (uint32_t)err);
        break;
    }

    case VW_IPC_FOLDER_LIST_REQ: {
        vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
        (void)vw_cache_folder_list(dc->cache, &folders, &nf);
        /* Encode: u32 count + per-entry (str local_root, str virtual_root, u8 paused) */
        uint8_t rbuf[65536]; uint32_t roff = 0;
        vw_write_u32le(rbuf + roff, nf); roff += 4;
        for (uint32_t i = 0; i < nf && roff < sizeof(rbuf) - 1040; i++) {
            uint16_t llen = (uint16_t)strnlen(folders[i].local_root,
                                               sizeof(folders[i].local_root));
            uint16_t vlen = (uint16_t)strnlen(folders[i].virtual_root,
                                               sizeof(folders[i].virtual_root));
            vw_ipc_write_str(rbuf, sizeof(rbuf), &roff,
                              folders[i].local_root, llen);
            vw_ipc_write_str(rbuf, sizeof(rbuf), &roff,
                              folders[i].virtual_root, vlen);
            rbuf[roff++] = folders[i].paused;
        }
        free(folders);
        vw_ipc_send(conn, VW_IPC_FOLDER_LIST_RESP, rbuf, roff);
        break;
    }

    case VW_IPC_FILE_LIST_REQ: {
        uint32_t off = 0;
        const char *prefix = NULL; uint16_t pl = 0;
        uint8_t filter = VW_IPC_FILTER_ALL;
        err = vw_ipc_read_str(buf, plen, &off, &prefix, &pl);
        if (err == VW_OK && off < plen) filter = buf[off];
        int state_filter = (filter == VW_IPC_FILTER_ALL) ? -1 : (int)filter;
        vw_cache_entry_t *entries = NULL; uint32_t ne = 0;
        (void)vw_cache_list(dc->cache, state_filter, &entries, &ne);
        uint8_t *rbuf = malloc(65536);
        if (!rbuf) { free(entries); vw_ipc_send(conn, VW_IPC_FILE_LIST_RESP, NULL, 0); break; }
        uint32_t roff = 0;
        vw_write_u32le(rbuf + roff, ne); roff += 4;
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
        }
        free(entries);
        vw_ipc_send(conn, VW_IPC_FILE_LIST_RESP, rbuf, roff);
        free(rbuf);
        break;
    }

    case VW_IPC_SHUTDOWN_REQ:
        ipc_send_u32(conn, VW_IPC_SHUTDOWN_RESP, 0);
        *dc->shutdown_flag = 1;
        break;

    default:
        break; /* unknown message: ignore */
    }
}

/* ── Connection attempt ──────────────────────────────────────────────────── */

static vw_client_sess_t *try_connect(const vw_daemon_cfg_t *cfg,
                                      const char *state_dir) {
    if (!cfg->server_host[0]) return NULL;

    vw_client_cfg_t cc;
    memset(&cc, 0, sizeof(cc));
    cc.host         = cfg->server_host;
    cc.port         = cfg->server_port;
    cc.cert_verify      = VW_CERT_VERIFY_REQUIRED;
    cc.ca_cert_pem_path = cfg->ca_cert_pem_path[0] ? cfg->ca_cert_pem_path : NULL;

    /* Try session token resume first */
    uint8_t tok[VW_TOKEN_BYTES];
    if (tok_load(state_dir, tok) == VW_OK) {
        vw_client_sess_t *sess = NULL;
        if (vw_client_resume(&cc, tok, &sess) == VW_OK) {
            vw_log(LOG_INFO, "session resumed");
            /* Persist fresh token */
            vw_client_get_token(sess, tok);
            tok_save(state_dir, tok);
            return sess;
        }
        vw_log(LOG_WARN, "session resume failed, continuing offline");
    }

    /* No valid token: offline mode */
    return NULL;
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

    vw_err_t err = vw_fs_ensure_dir(cfg->state_dir);
    if (err != VW_OK) {
        vw_log(LOG_ERROR, "cannot create state_dir: %s", cfg->state_dir);
        return err;
    }

    /* 1. Open cache */
    vw_cache_t *cache = NULL;
    err = vw_cache_open(cfg->state_dir, &cache);
    if (err != VW_OK) { vw_log(LOG_ERROR, "vw_cache_open failed: %d", (int)err); return err; }

    /* 2. Open IPC server */
    vw_ipc_server_t *ipc_srv = NULL;
    err = vw_ipc_server_open(cfg->ipc_port, &ipc_srv);
    if (err != VW_OK) {
        vw_log(LOG_ERROR, "cannot bind IPC port %u", (unsigned)cfg->ipc_port);
        vw_cache_close(cache); return err;
    }

    /* 3. Write PID file (after IPC bind confirms we're not a duplicate) */
    err = pid_file_create(cfg->state_dir);
    if (err != VW_OK) {
        vw_ipc_server_close(ipc_srv); vw_cache_close(cache); return err;
    }

    /* 4. Open watcher */
    vw_watcher_t *watcher = NULL;
    err = vw_watcher_open(1024, &watcher);
    if (err != VW_OK) {
        vw_log(LOG_WARN, "watcher init failed (%d), continuing without watch", (int)err);
        watcher = NULL;
    }

    /* 5. Add configured sync folders to watcher */
    if (watcher) {
        vw_sync_folder_t *folders = NULL; uint32_t nf = 0;
        vw_cache_folder_list(cache, &folders, &nf);
        for (uint32_t i = 0; i < nf; i++)
            vw_watcher_add(watcher, folders[i].local_root);
        free(folders);
    }

    /* 6. Attempt server connection */
    vw_client_sess_t *sess = try_connect(cfg, cfg->state_dir);
    if (!sess) vw_log(LOG_INFO, "starting in offline mode");

    /* 7. Open sync context */
    vw_sync_ctx_t *sync_ctx = NULL;
    vw_sync_cfg_t sc;
    sc.sess      = sess;
    sc.cache     = cache;
    sc.state_dir = cfg->state_dir;
    err = vw_sync_open(&sc, &sync_ctx);
    if (err != VW_OK) {
        vw_log(LOG_ERROR, "vw_sync_open failed: %d", (int)err);
        if (sess) vw_client_logout(sess);
        vw_watcher_close(watcher);
        vw_ipc_server_close(ipc_srv);
        vw_cache_close(cache);
        pid_file_remove();
        return err;
    }

    /* ── Main loop ──────────────────────────────────────────────────────── */

    int sync_now = 0;
    int shutdown  = 0;
    int64_t last_sync_at = 0;
    uint32_t error_count  = 0;

    ipc_dispatch_ctx_t dc;
    dc.cache         = cache;
    dc.sync_ctx      = sync_ctx;
    dc.watcher       = watcher;
    dc.sess          = sess;
    dc.paused_all    = 0;
    dc.last_sync_at  = 0;
    dc.error_count   = 0;
    dc.sync_now_flag = &sync_now;
    dc.shutdown_flag = &shutdown;

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
                    vw_sync_mark_local_modified(sync_ctx, evts[i].path);
                    if (evts[i].type == VW_WATCH_MOVED && evts[i].old_path[0]) {
                        /* old_path was deleted */
                        vw_sync_mark_local_modified(sync_ctx, evts[i].old_path);
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
                dc.sess         = sess;
                dc.last_sync_at = last_sync_at;
                dc.error_count  = error_count;
                handle_ipc_client(client, &dc);
                vw_ipc_conn_close(client);
                client = NULL;
                if (shutdown) break;
            }
        }

        if (shutdown || g_shutdown) break;

        /* e. Reconnect if session is absent or expired */
        if (!sess) {
            sess = try_connect(cfg, cfg->state_dir);
            if (sess) {
                vw_sync_set_session(sync_ctx, sess);
                vw_log(LOG_INFO, "reconnected to server");
            }
        } else {
            /* Check if session has expired */
            int64_t exp = vw_client_expires_at_of(sess);
            if (exp > 0 && (int64_t)time(NULL) >= exp) {
                vw_log(LOG_INFO, "session expired, re-connecting");
                vw_client_close(sess); sess = NULL;
                vw_sync_set_session(sync_ctx, NULL);
                sess = try_connect(cfg, cfg->state_dir);
                if (sess) vw_sync_set_session(sync_ctx, sess);
            }
        }

        /* f. Sync cycle */
        error_count = 0;
        vw_err_t serr = vw_sync_run(sync_ctx);
        if (serr == VW_OK) {
            last_sync_at = (int64_t)time(NULL);
            vw_log(LOG_DEBUG, "sync cycle complete (pending=%u)",
                   (unsigned)vw_sync_pending_count(sync_ctx));
        } else {
            error_count++;
            vw_log(LOG_WARN, "sync cycle error: %d", (int)serr);
            if (serr == VW_ERR_NET_CLOSED || serr == VW_ERR_NET_TIMEOUT) {
                /* Session may be dead */
                if (sess) {
                    vw_client_close(sess); sess = NULL;
                    vw_sync_set_session(sync_ctx, NULL);
                }
            }
        }

        sync_now = 0;
    }

    /* ── Shutdown ───────────────────────────────────────────────────────── */
    vw_log(LOG_INFO, "shutting down");

    vw_sync_close(sync_ctx);
    if (sess) vw_client_logout(sess);
    vw_watcher_close(watcher);
    vw_ipc_server_close(ipc_srv);
    vw_cache_close(cache);
    pid_file_remove();

    if (g_log_fp && g_log_to_file) fclose(g_log_fp);
    return VW_OK;
}
