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
#include "vw_client_core.h"   /* vw_update_install_kind_t */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * TASK-00298: client auto-update consent policy (ARCHITECTURE.md Phase 23).
 * NOTIFY (the default): the daemon only ever records that an update is
 * available (surfaced later via IPC/GUI, TASK-00299/300) — a human must
 * click "Update Now" to actually apply it. AUTO: an opt-in, hands-off mode
 * for headless/unattended setups — the daemon applies a detected update
 * itself, with no prompt, restarting on its own.
 */
typedef enum {
    VW_UPDATE_POLICY_NOTIFY = 0,
    VW_UPDATE_POLICY_AUTO   = 1,
} vw_update_policy_t;

typedef struct {
    char     state_dir[512];        /* daemon-global root — see this file's
                                      * header comment for the on-disk layout
                                      * underneath it */
    uint16_t ipc_port;              /* IPC listen port (default 47832)         */
    uint32_t sync_interval_ms;      /* periodic sync interval (default 30 000) */
    vw_update_policy_t update_policy; /* TASK-00298; default VW_UPDATE_POLICY_NOTIFY */
} vw_daemon_cfg_t;

/*
 * TASK-00298/00299: current update-availability status, as last observed
 * by either a hint-triggered check (on an ordinary reconnect/resume) or
 * the auto-policy daily background check. Queried by the IPC layer
 * (VW_IPC_UPDATE_STATUS_REQ, TASK-00299) — not stored here as a full
 * manifest, since applying an update always re-fetches and re-verifies
 * fresh rather than trusting a potentially-stale cached copy.
 */
typedef struct {
    int  available;
    char server_version[64];    /* raw hint last advertised by the connected
                                  * server (informational/untrusted — see
                                  * vw_update.h; empty if the last check that
                                  * found something available was the daily
                                  * auto-policy timer, which has no server
                                  * connection to get a hint from) */
    char manifest_version[64];  /* the independently-verified manifest's own
                                  * release_version — what "Update Now"
                                  * would actually install; empty if
                                  * available == 0 */
    vw_update_install_kind_t install_kind; /* computed fresh on every query
                                  * (a cheap filesystem check, TASK-00295) —
                                  * never cached, so this can't go stale
                                  * between an update becoming available and
                                  * a caller actually checking it */
} vw_daemon_update_status_t;

/*
 * Returns the daemon's current update-availability snapshot. Safe to call
 * from the same thread vw_daemon_run() runs on only (this daemon is
 * single-threaded by design — see this file's header comment).
 */
void vw_daemon_get_update_status(vw_daemon_update_status_t *out);

/*
 * Applies whatever update was last observed as available (re-fetches and
 * re-verifies the manifest fresh — never trusts the cached status above
 * for the actual install decision), downloads and verifies the matching
 * asset, stages it, and — only on success — triggers this daemon's own
 * existing graceful-shutdown path so the update can complete on restart.
 * Returns VW_ERR_NOT_FOUND if vw_daemon_get_update_status() would report
 * nothing available. Used both by the AUTO policy (called automatically)
 * and, in NOTIFY mode, by a future VW_IPC_UPDATE_APPLY_REQ handler
 * (TASK-00299) once a human clicks "Update Now".
 */
vw_err_t vw_daemon_apply_update_now(void);

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
