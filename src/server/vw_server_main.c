/*
 * vw_server_main.c — VaporWault server lifecycle implementation.
 *
 * Startup sequence:
 *   vw_oplog_open → vw_store_open → vw_file_store_open → vw_storage_open
 *   → vw_auth_open → vw_server_ctx_open → vw_net_listen
 *   → vw_admin_server_start → PID file → accept loop → clean shutdown
 *
 * Accept loop (single-threaded, Phase 4):
 *   For each accepted connection:
 *     1. Set 30 s recv timeout (slow-loris guard).
 *     2. vw_server_conn_handle — auth handshake.
 *     3. On success: recv messages and dispatch to vw_server_dispatch_file_op.
 *     4. Close connection.
 *
 * Signal handling (POSIX): SIGTERM/SIGINT set g_running=0; SIGHUP triggers
 * cert reload. Windows: SetConsoleCtrlHandler.
 */

#include "vw_server_main.h"
#include "vw_server_core.h"
#include "vw_file_handlers.h"
#include "vw_invite.h"
#include "vw_recovery.h"
#include "vw_store.h"
#include "vw_storage.h"
#include "vw_auth.h"
#include "vw_admin.h"
#include "vw_acme.h"
#include "vw_oplog.h"
#include "vw_smtp.h"
#include "vw_cluster.h"
#include "../core/vw_net.h"
#include "../core/vw_proto.h"
#include "../core/vw_fs.h"
#include "../core/vw_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#  include <windows.h>
#  define VW_GETPID() ((unsigned long)GetCurrentProcessId())
#else
#  include <unistd.h>
#  include <signal.h>
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <pthread.h>
#  define VW_GETPID() ((unsigned long)getpid())
#endif

/* ── Logging ─────────────────────────────────────────────────────────────── */

typedef enum { LOG_ERROR = 0, LOG_WARN, LOG_INFO, LOG_DEBUG } vw_log_level_t;

static vw_log_level_t  g_log_level = LOG_INFO;
static FILE           *g_log_fp    = NULL;  /* NULL → stderr */
static const char     *g_log_path  = NULL;
static long            g_log_size  = 0;

#define LOG_MAX_BYTES  (10L * 1024L * 1024L)

static const char *level_str(vw_log_level_t l) {
    switch (l) {
    case LOG_ERROR: return "ERROR"; case LOG_WARN:  return "WARN";
    case LOG_INFO:  return "INFO";  case LOG_DEBUG: return "DEBUG";
    default:        return "?";
    }
}

static vw_log_level_t parse_log_level(const char *s) {
    if (!s || !*s)              return LOG_INFO;
    if (!strcmp(s, "ERROR"))    return LOG_ERROR;
    if (!strcmp(s, "WARN"))     return LOG_WARN;
    if (!strcmp(s, "DEBUG"))    return LOG_DEBUG;
    return LOG_INFO;
}

static void log_rotate(void) {
    if (!g_log_path || !g_log_fp) return;
    fclose(g_log_fp); g_log_fp = NULL;
    char old2[600], old1[600];
    snprintf(old2, sizeof(old2), "%s.2", g_log_path);
    snprintf(old1, sizeof(old1), "%s.1", g_log_path);
    remove(old2); rename(old1, old2); rename(g_log_path, old1);
    g_log_fp   = fopen(g_log_path, "a");
    g_log_size = 0;
}

/* Protects the log FILE* and g_log_size; also serialises vw_log calls from workers. */
#ifndef _WIN32
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
#  define LOG_LOCK()   pthread_mutex_lock(&g_log_mutex)
#  define LOG_UNLOCK() pthread_mutex_unlock(&g_log_mutex)
#else
#  define LOG_LOCK()   (void)0
#  define LOG_UNLOCK() (void)0
#endif

static void vw_log(vw_log_level_t level, const char *fmt, ...) {
    if (level > g_log_level) return;
    FILE *out = g_log_fp ? g_log_fp : stderr;
    time_t now = time(NULL);
    struct tm tm;
#ifdef _WIN32
    gmtime_s(&tm, &now);
#else
    gmtime_r(&now, &tm);
#endif
    char ts[80];
    snprintf(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
    LOG_LOCK();
    va_list ap; va_start(ap, fmt);
    int n  = fprintf(out, "[%s] %s  ", ts, level_str(level));
        n += vfprintf(out, fmt, ap);
        n += fprintf(out, "\n");
    va_end(ap);
    fflush(out);
    g_log_size += n;
    if (g_log_size >= LOG_MAX_BYTES) log_rotate();
    LOG_UNLOCK();
}

static void log_init(const char *path) {
    g_log_path = path;
    g_log_fp   = fopen(path, "a");
    if (!g_log_fp)
        fprintf(stderr, "warn: cannot open log %s\n", path);
}

/* ── Signal handling ─────────────────────────────────────────────────────── */

static volatile int  g_running     = 1;
static volatile int  g_reload_cert = 0;
static vw_net_ctx_t *g_net_ctx     = NULL;

void vw_server_main_request_stop(void) { g_running = 0; }

#ifdef _WIN32
static BOOL WINAPI ctrl_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        g_running = 0;
        return TRUE;
    }
    return FALSE;
}
#else
static void sig_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) g_running = 0;
    else if (sig == SIGHUP)              g_reload_cert = 1;
}
#endif

static void signals_install(void) {
#ifdef _WIN32
    SetConsoleCtrlHandler(ctrl_handler, TRUE);
#else
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGHUP,  &sa, NULL);
    signal(SIGPIPE, SIG_IGN);
#endif
}

/* ── PID file ────────────────────────────────────────────────────────────── */

static char g_pid_path[600];

static int pid_file_create(const char *data_dir) {
    snprintf(g_pid_path, sizeof(g_pid_path), "%s/server.pid", data_dir);
#ifdef _WIN32
    /* Check for an existing live process. */
    FILE *pf = fopen(g_pid_path, "r");
    if (pf) {
        unsigned long existing = 0;
        fscanf(pf, "%lu", &existing);
        fclose(pf);
        HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)existing);
        if (h) { CloseHandle(h); return -1; }  /* alive */
        remove(g_pid_path);
    }
    pf = fopen(g_pid_path, "w");
    if (!pf) return -1;
    fprintf(pf, "%lu\n", VW_GETPID());
    fclose(pf);
#else
    int fd = open(g_pid_path, O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0) {
        if (errno != EEXIST) return -1;
        /* Stale? Read existing PID and check if the process is alive. */
        FILE *pf = fopen(g_pid_path, "r");
        int existing = 0;
        if (pf) { if (fscanf(pf, "%d", &existing) != 1) existing = 0; fclose(pf); }
        if (existing > 0 && kill((pid_t)existing, 0) == 0) return -1;  /* alive */
        remove(g_pid_path);
        fd = open(g_pid_path, O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd < 0) return -1;
    }
    char buf[32];
    int  n = snprintf(buf, sizeof(buf), "%lu\n", VW_GETPID());
    if (n > 0) {
        size_t pos = 0, total = (size_t)n;
        while (pos < total) {
            ssize_t w = write(fd, buf + pos, total - pos);
            if (w < 0) { if (errno == EINTR) continue; break; }
            pos += (size_t)w;
        }
    }
    close(fd);
#endif
    return 0;
}

static void pid_file_remove(void) {
    if (g_pid_path[0]) remove(g_pid_path);
}

/* ── Config defaults and I/O ─────────────────────────────────────────────── */

static void cfg_defaults(vw_server_main_cfg_t *c) {
    memset(c, 0, sizeof(*c));
    strncpy(c->listen_host,    "0.0.0.0",                     sizeof(c->listen_host)    - 1);
    c->listen_port = 4430;
    strncpy(c->data_dir,       "/var/lib/vapourwaultd",        sizeof(c->data_dir)       - 1);
    strncpy(c->cert_pem_path,  "/etc/vapourwaultd/server.crt", sizeof(c->cert_pem_path)  - 1);
    strncpy(c->key_pem_path,   "/etc/vapourwaultd/server.key", sizeof(c->key_pem_path)   - 1);
    strncpy(c->log_level,      "INFO",                         sizeof(c->log_level)      - 1);
    c->max_connections  = 256;
    c->max_workers      = 4;
    strncpy(c->admin_socket, VW_ADMIN_DEFAULT_SOCKET, sizeof(c->admin_socket) - 1);
    c->acme.enabled     = 0;
    strncpy(c->acme.directory,   VW_ACME_DEFAULT_DIRECTORY,
            sizeof(c->acme.directory)   - 1);
    strncpy(c->acme.account_key, VW_ACME_DEFAULT_ACCOUNT_KEY,
            sizeof(c->acme.account_key) - 1);
    c->acme.renew_days  = VW_ACME_DEFAULT_RENEW_DAYS;
    c->gc.interval_secs             = VW_GC_DEFAULT_INTERVAL_SECS;
    c->cluster.cluster_port         = 9010;
    c->cluster.is_replica           = 0;
    c->cluster.replica_poll_interval_secs = 5;
    c->smtp.port        = 587;
    strncpy(c->smtp.from_name, "VaporWault", sizeof(c->smtp.from_name) - 1);
    c->smtp.tls_mode    = VW_SMTP_TLS_STARTTLS;
    c->smtp.verify_cert = 1;
}

vw_err_t vw_server_main_cfg_load(const char *path, vw_server_main_cfg_t *out) {
    cfg_defaults(out);
    FILE *f = fopen(path, "r");
    if (!f) return VW_ERR_IO;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n'); if (nl) *nl = '\0';
        char *p  = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\0') continue;
        char *eq = strchr(p, '='); if (!eq) continue;
        *eq = '\0';
        char *key = p, *val = eq + 1;
        /* Trim key (trailing) */
        char *ke = key + strlen(key) - 1;
        while (ke >= key && (*ke == ' ' || *ke == '\t')) *ke-- = '\0';
        /* Trim val (leading + trailing) */
        while (*val == ' ' || *val == '\t') val++;
        char *ve = val + strlen(val) - 1;
        while (ve >= val && (*ve == ' ' || *ve == '\t')) *ve-- = '\0';

#define S(f, k) if (!strcmp(key, k)) { strncpy(f, val, sizeof(f)-1); continue; }
#define U(f, k) if (!strcmp(key, k)) { f = (uint16_t)strtoul(val,NULL,10); continue; }
#define I(f, k) if (!strcmp(key, k)) { f = (uint32_t)strtoul(val,NULL,10); continue; }
        S(out->listen_host,       "listen_host")
        U(out->listen_port,       "listen_port")
        S(out->data_dir,          "data_dir")
        S(out->cert_pem_path,     "cert_pem_path")
        S(out->key_pem_path,      "key_pem_path")
        S(out->log_level,         "log_level")
        I(out->max_connections,   "max_connections")
        I(out->max_workers,       "max_workers")
        S(out->admin_socket,      "admin_socket")
        S(out->smtp.host,         "smtp_host")
        U(out->smtp.port,         "smtp_port")
        S(out->smtp.username,     "smtp_username")
        S(out->smtp.password,     "smtp_password")
        S(out->smtp.from_addr,    "smtp_from_addr")
        S(out->smtp.from_name,    "smtp_from_name")
        S(out->smtp.ca_cert_path, "smtp_ca_cert_path")
        if (!strcmp(key, "smtp_verify_cert")) {
            out->smtp.verify_cert = (int)strtol(val, NULL, 10); continue; }
        if (!strcmp(key, "smtp_tls_mode")) {
            if      (!strcmp(val, "none"))   out->smtp.tls_mode = VW_SMTP_TLS_NONE;
            else if (!strcmp(val, "smtps"))  out->smtp.tls_mode = VW_SMTP_TLS_SMTPS;
            else                             out->smtp.tls_mode = VW_SMTP_TLS_STARTTLS;
            continue; }
        if (!strcmp(key, "acme_enabled")) {
            out->acme.enabled = (int)strtol(val, NULL, 10); continue; }
        S(out->acme.directory,   "acme_directory")
        S(out->acme.contact,     "acme_contact")
        S(out->acme.domain,      "acme_domain")
        S(out->acme.account_key, "acme_account_key")
        S(out->acme.dns_hook,    "acme_dns_hook")
        S(out->acme.http_root,   "acme_http_root")
        if (!strcmp(key, "acme_renew_days")) {
            out->acme.renew_days = (uint32_t)strtoul(val, NULL, 10); continue; }
        if (!strcmp(key, "gc_interval_secs")) {
            out->gc.interval_secs = (uint32_t)strtoul(val, NULL, 10); continue; }
        U(out->cluster.cluster_port,    "cluster_port")
        if (!strcmp(key, "cluster_is_replica")) {
            out->cluster.is_replica = (uint8_t)strtoul(val, NULL, 10); continue; }
        S(out->cluster.primary_host,    "cluster_primary_host")
        if (!strcmp(key, "cluster_primary_port")) {
            out->cluster.primary_cluster_port =
                (uint16_t)strtoul(val, NULL, 10); continue; }
        if (!strcmp(key, "cluster_poll_interval_secs")) {
            out->cluster.replica_poll_interval_secs =
                (uint32_t)strtoul(val, NULL, 10); continue; }
#undef S
#undef U
#undef I
    }
    fclose(f);
    return VW_OK;
}

vw_err_t vw_server_main_cfg_write_defaults(const char *path,
                                             const vw_server_main_cfg_t *cfg) {
    if (vw_fs_exists(path)) return VW_OK;
    FILE *f = fopen(path, "w");
    if (!f) return VW_ERR_IO;
    fprintf(f,
        "# VaporWault server configuration\n"
        "listen_host      = %s\n"
        "listen_port      = %u\n"
        "data_dir         = %s\n"
        "cert_pem_path    = %s\n"
        "key_pem_path     = %s\n"
        "log_level        = %s\n"
        "max_connections  = %u\n"
        "max_workers      = %u\n"
        "admin_socket     = %s\n\n"
        "# ACME: set acme_enabled = 1 to enable automatic Let's Encrypt renewal\n"
        "acme_enabled      = 0\n"
        "acme_directory    = %s\n"
        "acme_contact      = \n"
        "acme_domain       = \n"
        "acme_account_key  = %s\n"
        "acme_dns_hook     = \n"
        "acme_http_root    = \n"
        "acme_renew_days   = %u\n\n"
        "# SMTP: leave smtp_host empty to disable\n"
        "smtp_host         = \n"
        "smtp_port         = %u\n"
        "smtp_tls_mode     = starttls\n"
        "smtp_username     = \n"
        "smtp_password     = \n"
        "smtp_from_addr    = \n"
        "smtp_from_name    = VaporWault\n"
        "smtp_verify_cert  = 1\n"
        "smtp_ca_cert_path = \n\n"
        "# GC: set gc_interval_secs = 0 to disable the garbage-collection thread\n"
        "gc_interval_secs  = %u\n\n"
        "# Cluster: set cluster_port = 0 to disable cluster replication\n"
        "cluster_port              = %u\n"
        "cluster_is_replica        = 0\n"
        "cluster_primary_host      = \n"
        "cluster_primary_port      = 9010\n"
        "cluster_poll_interval_secs = %u\n",
        cfg->listen_host, cfg->listen_port,
        cfg->data_dir, cfg->cert_pem_path, cfg->key_pem_path,
        cfg->log_level, cfg->max_connections, cfg->max_workers,
        cfg->admin_socket,
        cfg->acme.directory, cfg->acme.account_key,
        (unsigned)cfg->acme.renew_days,
        cfg->smtp.port,
        (unsigned)cfg->gc.interval_secs,
        (unsigned)cfg->cluster.cluster_port,
        (unsigned)cfg->cluster.replica_poll_interval_secs);
    fclose(f);
    return VW_OK;
}

/* ── Config validation ───────────────────────────────────────────────────── */

static int cfg_validate(const vw_server_main_cfg_t *c, int check_only) {
    if (c->listen_port == 0) {
        vw_log(LOG_ERROR, "config: listen_port must not be zero"); return 1; }
    if (c->data_dir[0] == '\0') {
        vw_log(LOG_ERROR, "config: data_dir must not be empty"); return 1; }
    if (!check_only) {
        if (c->cert_pem_path[0] == '\0') {
            vw_log(LOG_ERROR, "config: cert_pem_path must not be empty"); return 1; }
        if (c->key_pem_path[0] == '\0') {
            vw_log(LOG_ERROR, "config: key_pem_path must not be empty"); return 1; }
    }
    if (c->smtp.host[0] != '\0') {
        char smtp_err[256];
        if (vw_smtp_validate_cfg(&c->smtp, smtp_err, sizeof(smtp_err)) != VW_OK) {
            vw_log(LOG_ERROR, "config SMTP: %s", smtp_err); return 1; }
    }
    return 0;
}

/* ── Thread pool (POSIX only) ────────────────────────────────────────────── */

#define POOL_WORKERS_MAX  64u   /* also used on Windows for config clamping */

#ifndef _WIN32

#define POOL_QUEUE_MIN    16u

typedef struct {
    vw_server_ctx_t *sctx;
    vw_conn_t       *conn;
} pool_task_t;

typedef struct {
    pool_task_t     *queue;      /* ring buffer, capacity = queue_cap          */
    uint32_t         queue_cap;
    uint32_t         head;
    uint32_t         tail;
    uint32_t         count;
    int              shutdown;
    pthread_mutex_t  mutex;
    pthread_cond_t   not_empty;
    pthread_cond_t   not_full;
} thread_pool_t;

static thread_pool_t g_pool;

static void handle_connection(vw_server_ctx_t *sctx, vw_conn_t *conn);

static void *pool_worker(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_pool.mutex);
        while (g_pool.count == 0 && !g_pool.shutdown)
            pthread_cond_wait(&g_pool.not_empty, &g_pool.mutex);
        if (g_pool.shutdown && g_pool.count == 0) {
            pthread_mutex_unlock(&g_pool.mutex);
            return NULL;
        }
        pool_task_t t = g_pool.queue[g_pool.head];
        g_pool.head = (g_pool.head + 1) % g_pool.queue_cap;
        g_pool.count--;
        pthread_cond_signal(&g_pool.not_full);
        pthread_mutex_unlock(&g_pool.mutex);

        handle_connection(t.sctx, t.conn);
        vw_net_close(t.conn);
    }
}

static int pool_init(uint32_t n_workers) {
    uint32_t cap = n_workers * 4;
    if (cap < POOL_QUEUE_MIN) cap = POOL_QUEUE_MIN;
    g_pool.queue = malloc(cap * sizeof(pool_task_t));
    if (!g_pool.queue) return -1;
    g_pool.queue_cap = cap;
    g_pool.head = g_pool.tail = g_pool.count = 0;
    g_pool.shutdown = 0;
    pthread_mutex_init(&g_pool.mutex, NULL);
    pthread_cond_init(&g_pool.not_empty, NULL);
    pthread_cond_init(&g_pool.not_full, NULL);
    return 0;
}

static void pool_enqueue(vw_server_ctx_t *sctx, vw_conn_t *conn) {
    pthread_mutex_lock(&g_pool.mutex);
    while (g_pool.count == g_pool.queue_cap && !g_pool.shutdown)
        pthread_cond_wait(&g_pool.not_full, &g_pool.mutex);
    if (!g_pool.shutdown) {
        g_pool.queue[g_pool.tail].sctx = sctx;
        g_pool.queue[g_pool.tail].conn = conn;
        g_pool.tail = (g_pool.tail + 1) % g_pool.queue_cap;
        g_pool.count++;
        pthread_cond_signal(&g_pool.not_empty);
    } else {
        /* Pool already shut down — close connection immediately. */
        vw_net_close(conn);
    }
    pthread_mutex_unlock(&g_pool.mutex);
}

static void pool_shutdown_and_join(pthread_t *threads, uint32_t n) {
    pthread_mutex_lock(&g_pool.mutex);
    g_pool.shutdown = 1;
    pthread_cond_broadcast(&g_pool.not_empty);
    pthread_cond_broadcast(&g_pool.not_full);
    pthread_mutex_unlock(&g_pool.mutex);
    for (uint32_t i = 0; i < n; i++)
        pthread_join(threads[i], NULL);
    free(g_pool.queue);
    g_pool.queue = NULL;
    pthread_mutex_destroy(&g_pool.mutex);
    pthread_cond_destroy(&g_pool.not_empty);
    pthread_cond_destroy(&g_pool.not_full);
}

#endif /* !_WIN32 */

/* ── Connection handler ──────────────────────────────────────────────────── */

static void handle_connection(vw_server_ctx_t *sctx, vw_conn_t *conn) {
    /* Slow-loris guard: 30 s timeout during the auth phase. */
    vw_net_conn_set_recv_timeout(conn, 30000);

    vw_session_info_t info;
    if (vw_server_conn_handle(sctx, conn, &info) != VW_OK) return;

    /* Authenticated — extend timeout for file-transfer operations. */
    vw_net_conn_set_recv_timeout(conn, 120000);

    uint8_t *buf = malloc(VW_MAX_MSG_BYTES);
    if (!buf) return;

    for (;;) {
        vw_msg_type_t type; uint32_t plen;
        vw_err_t err = vw_proto_recv(conn, &type, buf, VW_MAX_MSG_BYTES, &plen);
        if (err == VW_ERR_NET_CLOSED) break;
        if (err != VW_OK) { vw_log(LOG_DEBUG, "recv error %d", (int)err); break; }

        err = vw_server_dispatch_file_op(sctx, conn, type, buf, plen);
        if (err == VW_ERR_AUTH_REQUIRED || err == VW_ERR_PROTO_INVALID) break;
        if (err == VW_ERR_NOT_IMPL)
            vw_log(LOG_WARN, "unhandled msg type 0x%04x", (unsigned)type);
    }
    free(buf);
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int vw_server_main_run(int argc, char *argv[]) {
    const char *cfg_path   = NULL;
    int         do_daemon  = 0;
    int         check_only = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            fprintf(stdout,
                "Usage: vapourwaultd [--config <path>] [--daemon] [--check-config]\n"
                "  --config <path>   Config file (default: ./server.conf or\n"
                "                    /etc/vapourwaultd/server.conf)\n"
                "  --daemon          Daemonise after binding (POSIX only)\n"
                "  --check-config    Validate config and exit 0/1 without binding\n"
                "  --help            Print this message and exit\n");
            return 0;
        }
        if (!strcmp(argv[i], "--config") && i + 1 < argc) { cfg_path = argv[++i]; continue; }
        if (!strcmp(argv[i], "--daemon"))       { do_daemon  = 1; continue; }
        if (!strcmp(argv[i], "--check-config")) { check_only = 1; continue; }
    }

    /* Locate config file. */
    if (!cfg_path) {
        cfg_path = vw_fs_exists("server.conf")
                       ? "server.conf"
                       : "/etc/vapourwaultd/server.conf";
    }

    /* Load config. */
    vw_server_main_cfg_t cfg;
    if (vw_server_main_cfg_load(cfg_path, &cfg) != VW_OK) {
        cfg_defaults(&cfg);
        vw_log(LOG_WARN, "config not found (%s) — using defaults", cfg_path);
    }

    /* Env var overrides log level. */
    const char *env_level = getenv("VW_LOG_LEVEL");
    g_log_level = parse_log_level(env_level ? env_level : cfg.log_level);
    if (cfg.max_connections == 0) cfg.max_connections = 256;
    if (cfg.max_workers == 0)     cfg.max_workers     = 4;
    if (cfg.max_workers > POOL_WORKERS_MAX) cfg.max_workers = POOL_WORKERS_MAX;

    /* Validate config. */
    if (cfg_validate(&cfg, check_only)) return 1;
    if (check_only) { fprintf(stdout, "config OK\n"); return 0; }

    /* Ensure data dir exists. */
    if (vw_fs_ensure_dir(cfg.data_dir) != VW_OK) {
        vw_log(LOG_ERROR, "cannot create data_dir %s", cfg.data_dir); return 1; }

    /* Open subsystems in dependency order. */
    vw_oplog_t        *oplog      = NULL;
    vw_store_t        *store      = NULL;
    vw_file_store_t   *file_store = NULL;
    vw_storage_t        *chunks         = NULL;
    vw_auth_ctx_t       *auth           = NULL;
    vw_server_ctx_t     *sctx           = NULL;
    vw_invite_store_t   *invite_store   = NULL;
    vw_recovery_store_t *recovery_store = NULL;
    vw_net_ctx_t        *net_ctx        = NULL;
    vw_admin_server_t *admin_srv    = NULL;
    vw_acme_ctx_t     *acme_ctx     = NULL;
    vw_gc_ctx_t       *gc_ctx       = NULL;
    vw_cluster_t      *cluster      = NULL;
    int                rc           = 1;

    if (vw_oplog_open(cfg.data_dir, &oplog) != VW_OK) {
        vw_log(LOG_ERROR, "vw_oplog_open failed"); goto shutdown; }
    if (vw_store_open(cfg.data_dir, oplog, &store) != VW_OK) {
        vw_log(LOG_ERROR, "vw_store_open failed"); goto shutdown; }
    if (vw_file_store_open(cfg.data_dir, oplog, &file_store) != VW_OK) {
        vw_log(LOG_ERROR, "vw_file_store_open failed"); goto shutdown; }
    if (vw_storage_open(cfg.data_dir, &chunks) != VW_OK) {
        vw_log(LOG_ERROR, "vw_storage_open failed"); goto shutdown; }

    /* Seed the mbedTLS entropy/CTR-DRBG context used by vw_crypto_random()
     * (and, transitively, Argon2id password hashing). Must happen before
     * any subsystem that may hash a password — vw_auth_open is the first. */
    if (vw_crypto_init() != VW_OK) {
        vw_log(LOG_ERROR, "vw_crypto_init failed"); goto shutdown; }

    {
        const vw_smtp_cfg_t *smtp = (cfg.smtp.host[0] != '\0') ? &cfg.smtp : NULL;
        if (vw_auth_open(store, smtp, NULL, &auth) != VW_OK) {
            vw_log(LOG_ERROR, "vw_auth_open failed"); goto shutdown; }
    }

    if (vw_server_ctx_open(auth, store, NULL, &sctx) != VW_OK) {
        vw_log(LOG_ERROR, "vw_server_ctx_open failed"); goto shutdown; }
    vw_server_ctx_set_file_stores(sctx, file_store, chunks);
    vw_server_ctx_set_oplog(sctx, oplog);
    vw_storage_set_store(chunks, store);

    if (vw_invite_store_open(cfg.data_dir, &invite_store) != VW_OK) {
        vw_log(LOG_WARN, "invite store open failed — invites disabled");
    } else {
        vw_server_ctx_set_invite_store(sctx, invite_store);
        vw_log(LOG_INFO, "invite store opened");
    }

    if (vw_recovery_store_open(cfg.data_dir, &recovery_store) != VW_OK) {
        vw_log(LOG_WARN, "recovery store open failed — password recovery disabled");
    } else {
        const vw_smtp_cfg_t *smtp =
            (cfg.smtp.host[0] != '\0') ? &cfg.smtp : NULL;
        vw_server_ctx_set_recovery(sctx, recovery_store, smtp);
        if (!smtp)
            vw_log(LOG_WARN, "password recovery enabled but SMTP not configured — codes will not be sent");
        else
            vw_log(LOG_INFO, "password recovery enabled");
    }

    if (vw_net_listen(cfg.listen_host[0] ? cfg.listen_host : NULL,
                      cfg.listen_port,
                      cfg.cert_pem_path, cfg.key_pem_path, &net_ctx) != VW_OK) {
        vw_log(LOG_ERROR, "vw_net_listen %s:%u failed",
               cfg.listen_host, cfg.listen_port);
        goto shutdown;
    }
    g_net_ctx = net_ctx;

    {
        vw_admin_ctx_t actx;
        actx.store = store;
        actx.oplog = oplog;
        if (vw_admin_server_start(cfg.admin_socket, &actx, &admin_srv) != VW_OK)
            vw_log(LOG_WARN, "admin IPC server failed to bind on '%s' — continuing without it",
                   cfg.admin_socket);
        else if (admin_srv)
            vw_log(LOG_INFO, "admin IPC server listening on '%s'", cfg.admin_socket);
    }

    /* Start ACME renewal (no-op when acme.enabled == 0). */
    if (vw_acme_ctx_create(&cfg.acme, cfg.cert_pem_path, cfg.key_pem_path,
                            &acme_ctx) != VW_OK)
        vw_log(LOG_WARN, "ACME initialisation failed — continuing without automatic renewal");
    else if (acme_ctx) {
        if (vw_acme_start(acme_ctx, net_ctx) != VW_OK) {
            vw_log(LOG_WARN, "ACME renewal thread failed to start");
            vw_acme_ctx_destroy(acme_ctx);
            acme_ctx = NULL;
        } else {
            vw_log(LOG_INFO, "ACME renewal enabled for %s (renew at <%u days)",
                   cfg.acme.domain, (unsigned)cfg.acme.renew_days);
        }
    }

    /* Open and start cluster module before GC so the GC can use the cluster
     * sync watermark when deciding how far to truncate the oplog. */
    if (cfg.cluster.cluster_port != 0 || cfg.cluster.is_replica) {
        if (vw_cluster_open(cfg.data_dir, &cfg.cluster,
                            cfg.cert_pem_path, cfg.key_pem_path, oplog,
                            &cluster) != VW_OK) {
            vw_log(LOG_WARN, "vw_cluster_open failed — running without cluster replication");
        } else if (vw_cluster_start(cluster) != VW_OK) {
            vw_log(LOG_WARN, "cluster accept thread failed to start — running without cluster replication");
            vw_cluster_close(cluster);
            cluster = NULL;
        } else {
            vw_log(LOG_INFO, "cluster listener started on port %u",
                   (unsigned)cfg.cluster.cluster_port);
        }
    }

    /* Expose cluster to TLS handler (for CLUSTER_STATUS). NULL is fine. */
    vw_server_ctx_set_cluster(sctx, cluster);

    /* Start GC thread. cluster may be NULL (single-node mode). */
    if (vw_gc_create(&cfg.gc, store, file_store, chunks, oplog, cluster, &gc_ctx) != VW_OK) {
        vw_log(LOG_WARN, "GC context allocation failed — running without GC");
    } else if (vw_gc_start(gc_ctx) != VW_OK) {
        vw_log(LOG_WARN, "GC thread failed to start — running without GC");
        vw_gc_destroy(gc_ctx);
        gc_ctx = NULL;
    } else if (cfg.gc.interval_secs > 0) {
        vw_log(LOG_INFO, "GC thread started (interval %u s)", cfg.gc.interval_secs);
    }

    if (pid_file_create(cfg.data_dir) < 0) {
        vw_log(LOG_ERROR, "daemon already running or cannot write PID file");
        goto shutdown;
    }

#ifndef _WIN32
    if (do_daemon) {
        char log_path[600];
        snprintf(log_path, sizeof(log_path), "%s/server.log", cfg.data_dir);
        if (daemon(1, 0) < 0) {
            vw_log(LOG_ERROR, "daemon() failed: %s", strerror(errno));
            pid_file_remove();
            goto shutdown;
        }
        log_init(log_path);
    }
#else
    (void)do_daemon;
#endif

    signals_install();

#ifndef _WIN32
    /* ── Thread pool startup ───────────────────────────────────────────────── */
    pthread_t workers[POOL_WORKERS_MAX];
    uint32_t  n_workers = 0;

    if (pool_init(cfg.max_workers) < 0) {
        vw_log(LOG_ERROR, "thread pool allocation failed"); goto shutdown; }

    for (; n_workers < cfg.max_workers; n_workers++) {
        if (pthread_create(&workers[n_workers], NULL, pool_worker, NULL) != 0) {
            vw_log(LOG_ERROR, "pthread_create failed at worker %u", n_workers);
            break;
        }
    }
    if (n_workers == 0) {
        pool_shutdown_and_join(workers, 0); goto shutdown;
    }
    if (n_workers < cfg.max_workers)
        vw_log(LOG_WARN, "only %u/%u workers started", n_workers, cfg.max_workers);

    vw_log(LOG_INFO, "VaporWault server listening on %s:%u (workers=%u)",
           cfg.listen_host[0] ? cfg.listen_host : "0.0.0.0",
           cfg.listen_port, n_workers);

    /* Accept loop — main thread enqueues; workers handle. */
    while (g_running) {
        if (g_reload_cert) {
            g_reload_cert = 0;
            if (vw_net_ctx_reload_cert(net_ctx, cfg.cert_pem_path, cfg.key_pem_path) == VW_OK)
                vw_log(LOG_INFO, "TLS certificate reloaded");
            else
                vw_log(LOG_WARN, "cert reload failed");
        }
        vw_conn_t *conn = NULL;
        if (vw_net_accept(net_ctx, &conn) != VW_OK) break;
        char peer[64] = "";
        vw_net_peer_addr(conn, peer, sizeof(peer));
        vw_log(LOG_DEBUG, "accepted connection from %s", peer);
        pool_enqueue(sctx, conn);
    }

    vw_log(LOG_INFO, "shutting down — draining %u worker(s)", n_workers);
    pool_shutdown_and_join(workers, n_workers);

#else   /* Windows — single-threaded (thread pool not implemented) */
    vw_log(LOG_INFO, "VaporWault server listening on %s:%u (single-threaded)",
           cfg.listen_host[0] ? cfg.listen_host : "0.0.0.0", cfg.listen_port);

    while (g_running) {
        if (g_reload_cert) {
            g_reload_cert = 0;
            if (vw_net_ctx_reload_cert(net_ctx, cfg.cert_pem_path, cfg.key_pem_path) == VW_OK)
                vw_log(LOG_INFO, "TLS certificate reloaded");
            else
                vw_log(LOG_WARN, "cert reload failed");
        }
        vw_conn_t *conn = NULL;
        if (vw_net_accept(net_ctx, &conn) != VW_OK) break;
        char peer[64] = "";
        vw_net_peer_addr(conn, peer, sizeof(peer));
        vw_log(LOG_DEBUG, "accepted connection from %s", peer);
        handle_connection(sctx, conn);
        vw_net_close(conn);
    }
    vw_log(LOG_INFO, "shutting down");
#endif  /* _WIN32 */

    rc = 0;

shutdown:
    /* pid_file_remove is a no-op if the PID file was never created. */
    pid_file_remove();
    vw_cluster_close(cluster);
    vw_gc_stop(gc_ctx);
    vw_gc_destroy(gc_ctx);
    vw_acme_stop(acme_ctx);
    vw_acme_ctx_destroy(acme_ctx);
    if (admin_srv) vw_admin_server_stop(admin_srv);
    g_net_ctx = NULL;
    if (net_ctx)    vw_net_ctx_close(net_ctx);
    if (sctx)       vw_server_ctx_close(sctx);
    if (auth)       vw_auth_close(auth);
    if (chunks)     vw_storage_close(chunks);
    if (recovery_store) vw_recovery_store_close(recovery_store);
    if (invite_store)   vw_invite_store_close(invite_store);
    if (file_store)   vw_file_store_close(file_store);
    if (store)        vw_store_close(store);
    if (oplog)      vw_oplog_close(oplog);
    vw_crypto_cleanup();
    if (g_log_fp)   { fclose(g_log_fp); g_log_fp = NULL; }
    return rc;
}
