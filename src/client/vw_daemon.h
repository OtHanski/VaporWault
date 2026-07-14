#ifndef VW_DAEMON_H
#define VW_DAEMON_H

/*
 * vw_daemon — VaporWault client daemon.
 *
 * Owns the sync engine, filesystem watcher, IPC server, and server connection
 * lifecycle. Runs as a single-threaded event loop on the main thread.
 *
 * Security:
 *   - session.tok is checked for mode 0600 before loading (POSIX).
 *   - PID file is created with O_EXCL to prevent TOCTOU races.
 *   - No session tokens are written to the log (SEC.07).
 */

#include "../core/vw_proto.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char     state_dir[512];        /* cache.db, offline_queue.db, session.tok */
    char     server_host[256];      /* server hostname                          */
    uint16_t server_port;           /* server TLS port (default 4430)          */
    char     ca_cert_pem_path[512]; /* CA cert PEM; empty = system store       */
    char     username[64];          /* server username                         */
    uint16_t ipc_port;              /* IPC listen port (default 47832)         */
    uint32_t sync_interval_ms;      /* periodic sync interval (default 30 000) */
} vw_daemon_cfg_t;

/*
 * Load config from {state_dir}/daemon.conf (simple INI; missing keys get
 * defaults). Returns VW_OK even if the file does not exist (all defaults).
 */
vw_err_t vw_daemon_cfg_load(const char *state_dir, vw_daemon_cfg_t *out);

/*
 * Write default config to {state_dir}/daemon.conf if not present.
 */
vw_err_t vw_daemon_cfg_write_defaults(const char *state_dir,
                                       const vw_daemon_cfg_t *cfg);

/*
 * Start the daemon. Blocks until clean shutdown or fatal error.
 * daemon_mode: 1 if --daemon was passed (daemonize on Linux, log to file).
 */
vw_err_t vw_daemon_run(const vw_daemon_cfg_t *cfg, int daemon_mode);

#ifdef __cplusplus
}
#endif

#endif /* VW_DAEMON_H */
