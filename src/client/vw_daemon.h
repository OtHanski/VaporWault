#ifndef VW_DAEMON_H
#define VW_DAEMON_H

/*
 * vw_daemon — VaporWault client daemon.
 *
 * Owns the sync engine, filesystem watcher, IPC server, and server connection
 * lifecycle for every configured account. Runs as a single-threaded event
 * loop on the main thread — one process, N concurrently-connected accounts,
 * each with its own server session/cache/vault registry, round-robin
 * scheduled on this one thread (TASK-161; see ARCHITECTURE.md's "Multi-
 * account daemon model" decision for why this is one process with N account
 * contexts rather than N daemon processes).
 *
 * On-disk layout under {state_dir}:
 *   daemon.conf              global settings (ipc_port, sync_interval_ms)
 *   daemon.log, daemon.pid
 *   accounts/<account_id>/
 *     account.conf           label, server_host, server_port,
 *                             ca_cert_pem_path, username, and (TASK-173,
 *                             optional) fallback_host/fallback_port/
 *                             fallback_ca_cert_pem_path
 *     cache.db, sync_folders.db, session.tok, offline_queue.db,
 *     login_token.bin        TASK-173: SHA-256(password) — never the raw
 *                             password — retained so an unattended fallback
 *                             connect can authenticate fresh (a primary-
 *                             issued session.tok is meaningless on a
 *                             different server). Same 0600/"ignore on wrong
 *                             permissions" protection as session.tok.
 *
 * Security:
 *   - Each account's session.tok is checked for mode 0600 before loading
 *     (POSIX).
 *   - PID file is created with O_EXCL to prevent TOCTOU races.
 *   - No session tokens are written to the log (SEC.07).
 */

#include "../core/vw_proto.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char     state_dir[512];        /* daemon-global root — see this file's
                                      * header comment for the on-disk layout
                                      * underneath it */
    uint16_t ipc_port;              /* IPC listen port (default 47832)         */
    uint32_t sync_interval_ms;      /* periodic sync interval (default 30 000) */
} vw_daemon_cfg_t;

/*
 * Load config from {state_dir}/daemon.conf (simple INI; missing keys get
 * defaults). Returns VW_OK even if the file does not exist (all defaults).
 * Per-account settings (server_host, username, etc.) are no longer part of
 * this file — see accounts/<account_id>/account.conf, managed internally by
 * vw_daemon.c via VW_IPC_ACCOUNT_ADD_REQ, not hand-edited.
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
