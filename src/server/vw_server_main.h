#ifndef VW_SERVER_MAIN_H
#define VW_SERVER_MAIN_H

/*
 * vw_server_main — VaporWault server entry point and lifecycle.
 *
 * Owns: config file parsing, startup sequencing (oplog → store → auth →
 * net listen), the single-threaded accept loop, signal handling, log
 * rotation, and PID file management.
 *
 * Usage (from main.c):
 *   return vw_server_main_run(argc, argv);
 */

#include "../core/vw_proto.h"
#include "vw_smtp.h"
#include "vw_acme.h"
#include "vw_gc.h"
#include "vw_cluster.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Server config ───────────────────────────────────────────────────────── */

typedef struct {
    char          listen_host[256];   /* bind address; empty = 0.0.0.0     */
    uint16_t      listen_port;        /* TLS listen port; default 4430      */
    char          data_dir[512];      /* root for store/, chunks/, oplog/   */
    char          cert_pem_path[512]; /* TLS server certificate PEM         */
    char          key_pem_path[512];  /* TLS private key PEM                */
    char          log_level[16];      /* ERROR|WARN|INFO|DEBUG; default INFO */
    uint32_t      max_connections;    /* soft limit; 0 = 256                */
    uint32_t      max_workers;        /* thread pool size; 0 = 4; max 64    */
    char          admin_socket[108];  /* admin Unix socket path; "" = disabled */
    vw_smtp_cfg_t    smtp;               /* email config; smtp.host[0]=='\0' → disabled */
    vw_acme_cfg_t    acme;               /* ACME cert renewal; acme.enabled==0 → disabled */
    vw_gc_cfg_t      gc;                 /* GC thread; gc.interval_secs==0 → disabled    */
    vw_cluster_cfg_t cluster;            /* cluster replication; cluster_port==0 → disabled */
} vw_server_main_cfg_t;

/* ── Config file I/O ─────────────────────────────────────────────────────── */

/*
 * Parse a server.conf INI file into *out. Missing keys use defaults.
 * Returns VW_OK or VW_ERR_IO (file not found / unreadable).
 */
vw_err_t vw_server_main_cfg_load(const char *path, vw_server_main_cfg_t *out);

/*
 * Write a default server.conf to path. Does NOT overwrite if the file
 * already exists (returns VW_OK silently). Returns VW_ERR_IO on write error.
 */
vw_err_t vw_server_main_cfg_write_defaults(const char *path,
                                             const vw_server_main_cfg_t *cfg);

/* ── Entry point ─────────────────────────────────────────────────────────── */

/*
 * Parse argv, load config, open all subsystems, run the accept loop.
 * Does not return until shutdown (SIGTERM/SIGINT) or fatal startup error.
 * Returns 0 on clean shutdown, 1 on error.
 *
 * Supported flags:
 *   --config <path>      Override default config file location.
 *   --daemon             Daemonise after binding (POSIX only).
 *   --check-config       Validate config and exit 0/1; do not bind.
 *   --help               Print usage and exit 0.
 */
int vw_server_main_run(int argc, char *argv[]);

/*
 * Signal the running server to stop cleanly.  Thread-safe; may be called
 * from a Windows service control handler or any other thread.
 * Has no effect if vw_server_main_run() has not yet started.
 */
void vw_server_main_request_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* VW_SERVER_MAIN_H */
