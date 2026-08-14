/*
 * vw_client_cli — VaporWault CLI frontend.
 *
 * Connects to the running daemon via IPC (plain TCP, loopback) and issues
 * commands. All IPC messages use the same 8-byte framing as the wire protocol.
 * No direct server connection is made here; the daemon owns that.
 */

#include "vw_client_cli.h"
#include "vw_ipc.h"
#include "vw_cache.h"         /* vw_sync_state_t, VW_ENTRY_FILE, VW_ENTRY_DIR */
#include "../core/vw_proto.h" /* vw_read_u32le, vw_read_u64le, vw_err_t       */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#  define WIN32_LEAN_AND_MEAN
#  include <winsock2.h>
#endif

/* ── Utility helpers ─────────────────────────────────────────────────────── */

static void human_size(uint64_t bytes, char *buf, size_t bufsz) {
    if (bytes < 1024ULL)
        snprintf(buf, bufsz, "%llu B",   (unsigned long long)bytes);
    else if (bytes < 1024ULL * 1024)
        snprintf(buf, bufsz, "%.1f KB",  (double)bytes / 1024.0);
    else if (bytes < 1024ULL * 1024 * 1024)
        snprintf(buf, bufsz, "%.1f MB",  (double)bytes / (1024.0 * 1024.0));
    else
        snprintf(buf, bufsz, "%.1f GB",  (double)bytes / (1024.0 * 1024.0 * 1024.0));
}

/* Format a Unix timestamp as "YYYY-MM-DD HH:MM:SS" (UTC) or "never". */
static void format_ts(int64_t unix_ts, char *buf, size_t bufsz, int utc_label) {
    if (unix_ts == 0) {
        snprintf(buf, bufsz, "never");
        return;
    }
    time_t t = (time_t)unix_ts;
    struct tm tm_val;
#ifdef _WIN32
    gmtime_s(&tm_val, &t);
#else
    gmtime_r(&t, &tm_val);
#endif
    if (utc_label)
        strftime(buf, bufsz, "%Y-%m-%d %H:%M:%S UTC", &tm_val);
    else
        strftime(buf, bufsz, "%Y-%m-%d %H:%M:%S", &tm_val);
}

static const char *sync_state_str(uint32_t state) {
    switch ((vw_sync_state_t)state) {
    case VW_SYNC_SYNCED:     return "synced";
    case VW_SYNC_LOCAL_MOD:  return "local_mod";
    case VW_SYNC_REMOTE_MOD: return "remote_mod";
    case VW_SYNC_CONFLICT:   return "conflict";
    case VW_SYNC_LOCAL_DEL:  return "local_del";
    case VW_SYNC_REMOTE_DEL: return "remote_del";
    case VW_SYNC_NEW_LOCAL:  return "new_local";
    default:                 return "unknown";
    }
}

/* ── IPC helpers ─────────────────────────────────────────────────────────── */

static vw_ipc_conn_t *cli_connect(uint16_t port) {
    vw_ipc_conn_t *conn = NULL;
    vw_err_t err = vw_ipc_connect(port, &conn);
    if (err != VW_OK) {
        fprintf(stderr, "error: VaporWault daemon is not running\n");
        return NULL;
    }
    return conn;
}

/* Send request, receive response, verify type. */
static vw_err_t ipc_rpc(vw_ipc_conn_t *conn,
                          vw_ipc_msg_t req_type,
                          const void *req_payload, uint32_t req_len,
                          vw_ipc_msg_t expected_resp,
                          void *resp_buf, uint32_t resp_bufsz,
                          uint32_t *out_resp_len) {
    vw_err_t err = vw_ipc_send(conn, req_type, req_payload, req_len);
    if (err != VW_OK) return err;

    vw_ipc_msg_t got_type;
    err = vw_ipc_recv(conn, &got_type, resp_buf, resp_bufsz, out_resp_len);
    if (err != VW_OK) return err;

    if (got_type != expected_resp) return VW_ERR_PROTO_INVALID;
    return VW_OK;
}

/* Read u32 error code from response payload; print and return 1 if nonzero. */
static int check_u32_resp(const uint8_t *buf, uint32_t plen, const char *cmd) {
    if (plen < 4) {
        fprintf(stderr, "%s: truncated response\n", cmd);
        return 1;
    }
    uint32_t code = vw_read_u32le(buf);
    if (code != 0) {
        fprintf(stderr, "%s: daemon returned error %u\n", cmd, code);
        return 1;
    }
    return 0;
}

/* One decoded VW_IPC_ACCOUNT_LIST_RESP entry. */
typedef struct {
    uint32_t account_id;
    char     label[64];
    char     username[64];
    char     server_host[256];
    uint8_t  connected;
} account_list_entry_t;

/*
 * Fetches VW_IPC_ACCOUNT_LIST_RESP and decodes every entry into *out
 * (caller-provided array of cap entries). Returns the real count on
 * success (may exceed cap — caller should size cap generously, this CLI
 * has no pagination), or -1 on IPC/decode failure (error already printed).
 */
static int fetch_account_list(vw_ipc_conn_t *conn, account_list_entry_t *out, int cap) {
    uint8_t *resp = malloc(65536);
    if (!resp) { fprintf(stderr, "error: out of memory\n"); return -1; }
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_ACCOUNT_LIST_REQ, NULL, 0,
                             VW_IPC_ACCOUNT_LIST_RESP, resp, 65536, &rlen);
    if (err != VW_OK) {
        fprintf(stderr, "error: IPC error %d listing accounts\n", (int)err);
        free(resp);
        return -1;
    }
    if (rlen < 4u) { free(resp); fprintf(stderr, "error: truncated account list\n"); return -1; }
    uint32_t count = vw_read_u32le(resp);
    uint32_t off = 4u;
    int written = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t acc_id;
        const char *label, *username, *host;
        uint16_t label_len, user_len, host_len;
        if (off + 4u > rlen) break;
        acc_id = vw_read_u32le(resp + off); off += 4u;
        if (vw_ipc_read_str(resp, rlen, &off, &label, &label_len) != VW_OK) break;
        if (vw_ipc_read_str(resp, rlen, &off, &username, &user_len) != VW_OK) break;
        if (vw_ipc_read_str(resp, rlen, &off, &host, &host_len) != VW_OK) break;
        if (off + 1u + 8u > rlen) break;
        uint8_t connected = resp[off]; off += 1u;
        off += 8u; /* pending_uploads (u32) + pending_downloads (u32) */
        if (written < cap) {
            account_list_entry_t *e = &out[written];
            e->account_id = acc_id;
            size_t cl;
            cl = label_len < sizeof(e->label)-1u ? label_len : sizeof(e->label)-1u;
            memcpy(e->label, label, cl); e->label[cl] = '\0';
            cl = user_len < sizeof(e->username)-1u ? user_len : sizeof(e->username)-1u;
            memcpy(e->username, username, cl); e->username[cl] = '\0';
            cl = host_len < sizeof(e->server_host)-1u ? host_len : sizeof(e->server_host)-1u;
            memcpy(e->server_host, host, cl); e->server_host[cl] = '\0';
            e->connected = connected;
        }
        written++;
    }
    free(resp);
    return written;
}

static void print_account_list_hint(const account_list_entry_t *accts, int n) {
    for (int i = 0; i < n; i++) {
        fprintf(stderr, "    id=%u  label=%s  username=%s  server=%s  %s\n",
                (unsigned)accts[i].account_id, accts[i].label, accts[i].username,
                accts[i].server_host, accts[i].connected ? "connected" : "offline");
    }
}

/*
 * Resolves the account_id an account-scoped command should use.
 *
 * Opens and closes its own one-shot IPC connection — every daemon IPC
 * connection handles exactly one request then gets closed by the daemon
 * (see vw_daemon.c's main loop), so this cannot share a connection the
 * caller intends to reuse for its own follow-up request; callers must
 * call this *before* opening their own connection for the actual command,
 * not pass an already-open one in.
 *
 * account_arg (from --account <label-or-id>, or NULL):
 *   - NULL: succeeds only when exactly one account is configured
 *     (preserves the zero-config single-account UX — no flag needed for
 *     the common case); fails listing every configured account otherwise.
 *   - non-NULL, all-digits: matched against account_id first.
 *   - non-NULL, otherwise (or no numeric match): matched against label,
 *     falling back to username (label defaults to username on `account
 *     add`, so this covers the common "I typed my username" case too).
 */
static int resolve_account_id(uint16_t ipc_port, const char *account_arg, uint32_t *out_id) {
    vw_ipc_conn_t *conn = cli_connect(ipc_port);
    if (!conn) return 1;
    account_list_entry_t accts[64];
    int n = fetch_account_list(conn, accts, 64);
    vw_ipc_conn_close(conn);
    if (n < 0) return 1;
    if (n > 64) n = 64; /* this CLI has no pagination; 64 accounts is far beyond this project's scale */

    if (!account_arg) {
        if (n == 0) {
            fprintf(stderr, "error: no account configured — run `%s account add ...` first\n",
                    "vapourwault-cli");
            return 1;
        }
        if (n > 1) {
            fprintf(stderr, "error: multiple accounts configured — pass --account <label-or-id>:\n");
            print_account_list_hint(accts, n);
            return 1;
        }
        *out_id = accts[0].account_id;
        return 0;
    }

    int all_digits = account_arg[0] != '\0';
    for (const char *p = account_arg; *p; p++) if (*p < '0' || *p > '9') { all_digits = 0; break; }
    if (all_digits) {
        uint32_t wanted = (uint32_t)strtoul(account_arg, NULL, 10);
        for (int i = 0; i < n; i++) {
            if (accts[i].account_id == wanted) { *out_id = wanted; return 0; }
        }
    }
    for (int i = 0; i < n; i++) {
        if (strcmp(accts[i].label, account_arg) == 0 || strcmp(accts[i].username, account_arg) == 0) {
            *out_id = accts[i].account_id;
            return 0;
        }
    }
    fprintf(stderr, "error: no account matches --account '%s'. Configured accounts:\n", account_arg);
    print_account_list_hint(accts, n);
    return 1;
}

/* ── Subcommand: status ───────────────────────────────────────────────────── */

/*
 * STATUS_RESP layout (24 bytes, or 28 with the TASK-113 permission_denied_count
 * field — older/newer builds always match since client and daemon ship
 * together, but this reads it defensively via rlen anyway):
 *   u8  connected, u8 syncing, u8 paused, u8 _pad,
 *   i64 last_sync_at, u32 pending_uploads, u32 pending_downloads,
 *   u32 error_count, u32 permission_denied_count
 */
static int cmd_status(vw_ipc_conn_t *conn) {
    uint8_t resp[32];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_STATUS_REQ, NULL, 0,
                             VW_IPC_STATUS_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) {
        fprintf(stderr, "status: IPC error %d\n", (int)err);
        return 1;
    }
    if (rlen < 24) {
        fprintf(stderr, "status: truncated response (%u bytes)\n", rlen);
        return 1;
    }

    uint8_t  connected  = resp[0];
    uint8_t  syncing    = resp[1];
    uint8_t  paused     = resp[2];
    int64_t  last_sync  = (int64_t)vw_read_u64le(resp + 4);
    uint32_t uploads    = vw_read_u32le(resp + 12);
    uint32_t downloads  = vw_read_u32le(resp + 16);
    uint32_t errors     = vw_read_u32le(resp + 20);
    uint32_t perm_denied = (rlen >= 28) ? vw_read_u32le(resp + 24) : 0;

    char ts_buf[32];
    format_ts(last_sync, ts_buf, sizeof(ts_buf), 1);

    printf("VaporWault daemon status\n");
    printf("  Server:    %s\n", connected ? "connected" : "offline");
    printf("  Syncing:   %s\n", syncing   ? "yes" : "no");
    printf("  Paused:    %s\n", paused    ? "yes" : "no");
    printf("  Last sync: %s\n", ts_buf);
    printf("  Pending:   %u uploads, %u downloads, %u errors\n",
           uploads, downloads, errors);
    printf("  Permission-denied (shared-folder auto-mkdir): %u\n", perm_denied);
    return 0;
}

/* ── Subcommand: sync ────────────────────────────────────────────────────── */

static int cmd_sync(vw_ipc_conn_t *conn) {
    uint8_t resp[4];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_SYNC_NOW_REQ, NULL, 0,
                             VW_IPC_SYNC_NOW_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) {
        fprintf(stderr, "sync: IPC error %d\n", (int)err);
        return 1;
    }
    if (check_u32_resp(resp, rlen, "sync")) return 1;
    printf("sync queued\n");
    return 0;
}

/* ── Subcommands: pause / resume ─────────────────────────────────────────── */

/*
 * PAUSE_REQ / RESUME_REQ payload: string local_root (empty = all folders).
 */
static int cmd_pause(vw_ipc_conn_t *conn, uint32_t account_id, const char *folder) {
    uint8_t payload[520];
    uint32_t off = 0;
    vw_write_u32le(payload + off, account_id); off += 4u;
    const char *f = folder ? folder : "";
    vw_ipc_write_str(payload, sizeof(payload), &off, f, (uint16_t)strlen(f));

    uint8_t resp[4];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_PAUSE_REQ, payload, off,
                             VW_IPC_PAUSE_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "pause: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "pause")) return 1;
    if (folder)
        printf("paused: %s\n", folder);
    else
        printf("paused (all folders)\n");
    return 0;
}

static int cmd_resume(vw_ipc_conn_t *conn, uint32_t account_id, const char *folder) {
    uint8_t payload[520];
    uint32_t off = 0;
    vw_write_u32le(payload + off, account_id); off += 4u;
    const char *f = folder ? folder : "";
    vw_ipc_write_str(payload, sizeof(payload), &off, f, (uint16_t)strlen(f));

    uint8_t resp[4];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_RESUME_REQ, payload, off,
                             VW_IPC_RESUME_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "resume: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "resume")) return 1;
    if (folder)
        printf("resumed: %s\n", folder);
    else
        printf("resumed (all folders)\n");
    return 0;
}

/* ── Subcommand: add-folder ──────────────────────────────────────────────── */

/* FOLDER_ADD_REQ payload: u32 account_id, string local_root, string virtual_root. */
static int cmd_add_folder(vw_ipc_conn_t *conn, uint32_t account_id,
                            const char *local, const char *virt) {
    uint8_t payload[1044];
    uint32_t off = 0;
    vw_write_u32le(payload + off, account_id); off += 4u;
    vw_ipc_write_str(payload, sizeof(payload), &off,
                      local, (uint16_t)strnlen(local, 511));
    vw_ipc_write_str(payload, sizeof(payload), &off,
                      virt,  (uint16_t)strnlen(virt,  511));

    uint8_t resp[4];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_FOLDER_ADD_REQ, payload, off,
                             VW_IPC_FOLDER_ADD_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "add-folder: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "add-folder")) return 1;
    printf("folder added: %s -> %s\n", local, virt);
    return 0;
}

/* ── Subcommand: remove-folder ───────────────────────────────────────────── */

/* FOLDER_REMOVE_REQ payload: u32 account_id, string local_root. */
static int cmd_remove_folder(vw_ipc_conn_t *conn, uint32_t account_id, const char *local) {
    uint8_t payload[520];
    uint32_t off = 0;
    vw_write_u32le(payload + off, account_id); off += 4u;
    vw_ipc_write_str(payload, sizeof(payload), &off,
                      local, (uint16_t)strnlen(local, 511));

    uint8_t resp[4];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_FOLDER_REMOVE_REQ, payload, off,
                             VW_IPC_FOLDER_REMOVE_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "remove-folder: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "remove-folder")) return 1;
    printf("folder removed: %s\n", local);
    return 0;
}

/* ── Subcommand: add-shared-folder (TASK-106) ────────────────────────────── */

/* FOLDER_ADD_SHARED_REQ payload: u32 account_id, string local_root, string
 * virtual_root, u64 remote_dir_id. */
static int cmd_add_shared_folder(vw_ipc_conn_t *conn, uint32_t account_id, const char *local,
                                   const char *virt, uint64_t remote_dir_id) {
    uint8_t payload[1052];
    uint32_t off = 0;
    vw_write_u32le(payload + off, account_id); off += 4u;
    vw_ipc_write_str(payload, sizeof(payload), &off,
                      local, (uint16_t)strnlen(local, 511));
    vw_ipc_write_str(payload, sizeof(payload), &off,
                      virt,  (uint16_t)strnlen(virt,  511));
    vw_write_u64le(payload + off, remote_dir_id); off += 8u;

    uint8_t resp[4];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_FOLDER_ADD_SHARED_REQ, payload, off,
                             VW_IPC_FOLDER_ADD_SHARED_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "add-shared-folder: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "add-shared-folder")) return 1;
    printf("shared folder added: %s -> %s (remote_dir_id=%llu)\n",
           local, virt, (unsigned long long)remote_dir_id);
    return 0;
}

/* ── Subcommand: list-folders (TASK-106) ─────────────────────────────────── */

/* FOLDER_LIST_REQ payload: u32 account_id. FOLDER_LIST_RESP: u32 count +
 * per-entry (str local_root, str virtual_root, u8 paused, u8 pause_reason
 * [TASK-111], u64 remote_dir_id). */
static int cmd_list_folders(vw_ipc_conn_t *conn, uint32_t account_id) {
    uint8_t *resp = malloc(65536);
    if (!resp) { fprintf(stderr, "list-folders: out of memory\n"); return 1; }

    uint8_t req[4];
    vw_write_u32le(req, account_id);
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_FOLDER_LIST_REQ, req, sizeof(req),
                             VW_IPC_FOLDER_LIST_RESP, resp, 65536, &rlen);
    if (err != VW_OK) {
        fprintf(stderr, "list-folders: IPC error %d\n", (int)err);
        free(resp);
        return 1;
    }
    if (rlen < 4u) { free(resp); return 0; }

    uint32_t count = vw_read_u32le(resp);
    uint32_t off = 4u;

    printf("%-8s  %-10s  %-12s  %-30s  %s\n",
           "PAUSED", "REASON", "KIND", "LOCAL_ROOT", "VIRTUAL_ROOT");

    for (uint32_t i = 0; i < count; i++) {
        const char *lroot = NULL, *vroot = NULL;
        uint16_t ll = 0, vl = 0;
        if (vw_ipc_read_str(resp, rlen, &off, &lroot, &ll) != VW_OK) break;
        if (vw_ipc_read_str(resp, rlen, &off, &vroot, &vl) != VW_OK) break;
        if (off + 2u + 8u > rlen) break;
        uint8_t  paused        = resp[off++];
        uint8_t  pause_reason  = resp[off++];
        uint64_t remote_dir_id = vw_read_u64le(resp + off); off += 8u;

        char lbuf[512]; size_t lc = ll < sizeof(lbuf)-1u ? ll : sizeof(lbuf)-1u;
        memcpy(lbuf, lroot, lc); lbuf[lc] = '\0';
        char vbuf[512]; size_t vc = vl < sizeof(vbuf)-1u ? vl : sizeof(vbuf)-1u;
        memcpy(vbuf, vroot, vc); vbuf[vc] = '\0';

        char kind_buf[32];
        if (remote_dir_id != 0)
            snprintf(kind_buf, sizeof(kind_buf), "shared(%llu)", (unsigned long long)remote_dir_id);
        else
            snprintf(kind_buf, sizeof(kind_buf), "owned");

        const char *reason_str = "-";
        if (paused) {
            switch (pause_reason) {
            case VW_PAUSE_REASON_REVOKED:        reason_str = "revoked";   break;
            case VW_PAUSE_REASON_TREE_TOO_LARGE: reason_str = "too_large"; break;
            default:                             reason_str = "manual";   break;
            }
        }

        printf("%-8s  %-10s  %-12s  %-30s  %s\n",
               paused ? "yes" : "no", reason_str, kind_buf, lbuf, vbuf);
    }

    free(resp);
    return 0;
}

/* ── Subcommand: ls / conflicts ──────────────────────────────────────────── */

/*
 * FILE_LIST_REQ payload: u32 account_id, string virtual_prefix (empty =
 * all), u8 filter.
 *
 * FILE_LIST_RESP layout per entry:
 *   string virtual_path, string local_path,
 *   u32 sync_state, u8 entry_type,
 *   i64 server_mtime, i64 local_mtime, u64 server_size, u64 file_id,
 *   u64 vault_id (TASK-158)
 */
static int cmd_ls(vw_ipc_conn_t *conn, uint32_t account_id, const char *prefix, uint8_t filter) {
    uint8_t req[522];
    uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    const char *p = prefix ? prefix : "";
    vw_ipc_write_str(req, sizeof(req), &off, p, (uint16_t)strlen(p));
    req[off++] = filter;

    uint8_t *resp = malloc(65536);
    if (!resp) { fprintf(stderr, "ls: out of memory\n"); return 1; }

    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_FILE_LIST_REQ, req, off,
                             VW_IPC_FILE_LIST_RESP, resp, 65536, &rlen);
    if (err != VW_OK) {
        fprintf(stderr, "ls: IPC error %d\n", (int)err);
        free(resp);
        return 1;
    }
    if (rlen < 4) { free(resp); return 0; }

    uint32_t count = vw_read_u32le(resp);
    uint32_t roff  = 4;

    printf("%-12s  %-4s  %-10s  %-19s  %s\n",
           "SYNC STATE", "TYPE", "SIZE", "MTIME (UTC)", "NAME");

    for (uint32_t i = 0; i < count; i++) {
        const char *vpath = NULL, *lpath_unused = NULL;
        uint16_t vplen = 0, lplen = 0;

        if (vw_ipc_read_str(resp, rlen, &roff, &vpath, &vplen) != VW_OK) break;
        if (vw_ipc_read_str(resp, rlen, &roff, &lpath_unused, &lplen) != VW_OK) break;
        if (roff + 4u + 1u + 8u + 8u + 8u + 8u + 8u > rlen) break;

        uint32_t sync_state  = vw_read_u32le(resp + roff); roff += 4;
        uint8_t  entry_type  = resp[roff++];
        int64_t  server_mt   = (int64_t)vw_read_u64le(resp + roff); roff += 8;
        int64_t  local_mt    = (int64_t)vw_read_u64le(resp + roff); roff += 8;
        uint64_t server_size = vw_read_u64le(resp + roff);           roff += 8;
        /* file_id, vault_id: not printed by `ls` today; consumed to stay
         * aligned with the next entry (TASK-096 added file_id, TASK-158
         * added vault_id, to the wire format). */
        roff += 8; /* file_id */
        roff += 8; /* vault_id */

        int64_t mtime = server_mt ? server_mt : local_mt;
        char ts_buf[24]; format_ts(mtime, ts_buf, sizeof(ts_buf), 0);
        char sz_buf[16];
        if (entry_type == VW_ENTRY_DIR)
            snprintf(sz_buf, sizeof(sz_buf), "--");
        else
            human_size(server_size, sz_buf, sizeof(sz_buf));

        char name_buf[512];
        size_t nc = vplen < sizeof(name_buf) - 1 ? vplen : sizeof(name_buf) - 1;
        memcpy(name_buf, vpath, nc);
        name_buf[nc] = '\0';

        printf("%-12s  %-4s  %-10s  %-19s  %s\n",
               sync_state_str(sync_state),
               entry_type == VW_ENTRY_DIR ? "dir" : "file",
               sz_buf, ts_buf, name_buf);
    }

    free(resp);
    return 0;
}

/* ── Subcommand: account add / list / remove (TASK-162) ──────────────────── */

/*
 * ACCOUNT_ADD_REQ payload (TASK-161): u32 account_id (0 = new), string label,
 * string server_host, u16 server_port, string ca_cert_pem_path, string
 * username, string password, string otp.
 *
 * Host/port/CA-cert are per-account, not defaulted from any other
 * configured account — accounts are per-server, not just per-user
 * (ARCHITECTURE.md's "Accounts are per-server, not just per-user",
 * settled 2026-08-13): this is how a user adds a second account on a
 * completely unrelated server (e.g. a family server and a separate
 * friends server), not just a second user on the same one.
 */
static int cmd_account_add(vw_ipc_conn_t *conn, const char *server_host, uint16_t server_port,
                            const char *ca_cert_path, const char *label,
                            const char *username, const char *password, const char *otp) {
    /* Worst case: 4 (account_id) + (2+63) label + (2+255) host + 2 (port) +
     * (2+511) ca_cert_path + (2+63) username + (2+255) password +
     * (2+16) otp = 1181 bytes — sized with headroom, and every
     * vw_ipc_write_str call below is still checked rather than trusted,
     * since a silently-skipped write (VW_ERR_PROTO_TOO_LARGE) would
     * desync every field after it into the wrong byte offset instead of
     * just failing cleanly. */
    uint8_t payload[1536];
    uint32_t off = 0;
    vw_write_u32le(payload + off, 0u); off += 4u; /* account_id: 0 = new account */
    const char *lbl = (label && label[0]) ? label : username;
    vw_err_t werr = vw_ipc_write_str(payload, sizeof(payload), &off, lbl, (uint16_t)strnlen(lbl, 63));
    if (werr == VW_OK)
        werr = vw_ipc_write_str(payload, sizeof(payload), &off,
                                 server_host, (uint16_t)strnlen(server_host, 255));
    if (werr == VW_OK && off + 2u <= sizeof(payload)) { vw_write_u16le(payload + off, server_port); off += 2u; }
    else if (werr == VW_OK) werr = VW_ERR_PROTO_TOO_LARGE;
    const char *ca = ca_cert_path ? ca_cert_path : "";
    if (werr == VW_OK)
        werr = vw_ipc_write_str(payload, sizeof(payload), &off, ca, (uint16_t)strnlen(ca, 511));
    if (werr == VW_OK)
        werr = vw_ipc_write_str(payload, sizeof(payload), &off,
                                 username, (uint16_t)strnlen(username, 63));
    if (werr == VW_OK)
        werr = vw_ipc_write_str(payload, sizeof(payload), &off,
                                 password, (uint16_t)strnlen(password, 255));
    const char *o = otp ? otp : "";
    if (werr == VW_OK)
        werr = vw_ipc_write_str(payload, sizeof(payload), &off, o, (uint16_t)strnlen(o, 16));

    if (werr != VW_OK) {
        memset(payload, 0, sizeof(payload));
        fprintf(stderr, "account add: internal error building request (%d)\n", (int)werr);
        return 1;
    }

    uint8_t resp[8];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_ACCOUNT_ADD_REQ, payload, off,
                             VW_IPC_ACCOUNT_ADD_RESP, resp, sizeof(resp), &rlen);
    memset(payload, 0, sizeof(payload)); /* payload held the raw password */
    if (err != VW_OK) { fprintf(stderr, "account add: IPC error %d\n", (int)err); return 1; }

    if (rlen < 8) { fprintf(stderr, "account add: truncated response\n"); return 1; }
    uint32_t code = vw_read_u32le(resp);
    if (code == (uint32_t)VW_ERR_AUTH_2FA_REQUIRED) {
        fprintf(stderr, "account add: this account requires a 2FA code — re-run:\n"
                        "  %s account add %s %u %s <password> <otp-code>\n",
                        "vapourwault-cli", server_host, (unsigned)server_port, username);
        return 1;
    }
    if (code != 0) {
        fprintf(stderr, "account add: failed (code %u)\n", code);
        return 1;
    }
    uint32_t account_id = vw_read_u32le(resp + 4u);
    printf("account added: id=%u label=%s username=%s server=%s:%u\n",
           (unsigned)account_id, lbl, username, server_host, (unsigned)server_port);
    return 0;
}

/* ACCOUNT_LIST_REQ: no payload. Reuses fetch_account_list()'s decode. */
static int cmd_account_list(vw_ipc_conn_t *conn) {
    account_list_entry_t accts[64];
    int n = fetch_account_list(conn, accts, 64);
    if (n < 0) return 1;
    if (n == 0) { printf("no accounts configured\n"); return 0; }
    printf("%-4s  %-16s  %-20s  %-24s  %s\n", "ID", "LABEL", "USERNAME", "SERVER", "STATUS");
    for (int i = 0; i < n && i < 64; i++) {
        printf("%-4u  %-16s  %-20s  %-24s  %s\n",
               (unsigned)accts[i].account_id, accts[i].label, accts[i].username,
               accts[i].server_host, accts[i].connected ? "connected" : "offline");
    }
    if (n > 64) fprintf(stderr, "(%d more accounts not shown)\n", n - 64);
    return 0;
}

/* ACCOUNT_REMOVE_REQ payload: u32 account_id. RESP: u32 error_code. */
static int cmd_account_remove(vw_ipc_conn_t *conn, uint32_t account_id) {
    uint8_t req[4];
    vw_write_u32le(req, account_id);
    uint8_t resp[4];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_ACCOUNT_REMOVE_REQ, req, sizeof(req),
                             VW_IPC_ACCOUNT_REMOVE_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "account remove: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "account remove")) return 1;
    printf("account removed: id=%u\n", (unsigned)account_id);
    return 0;
}

/* ── Subcommand: shutdown ────────────────────────────────────────────────── */

static int cmd_shutdown(vw_ipc_conn_t *conn) {
    uint8_t resp[4];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_SHUTDOWN_REQ, NULL, 0,
                             VW_IPC_SHUTDOWN_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "shutdown: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "shutdown")) return 1;
    printf("daemon shutting down\n");
    return 0;
}

/* ── Sharing (TASK-095; server side: TASK-094, docs/PROTOCOL.md §7.5) ────── */

static int parse_permission(const char *s, uint8_t *out) {
    if (strcmp(s, "view") == 0)      { *out = (uint8_t)VW_PERM_VIEW; return 0; }
    if (strcmp(s, "edit") == 0)      { *out = (uint8_t)VW_PERM_EDIT; return 0; }
    fprintf(stderr, "error: permission must be 'view' or 'edit', got '%s'\n", s);
    return 1;
}

/* SHARE_GRANT_REQ: u32 account_id, string path, string target_username,
 * u8 permission, i64 expires_at. SHARE_GRANT_RESP: u32 error_code, u64 share_id. */
static int cmd_share(vw_ipc_conn_t *conn, uint32_t account_id, const char *path, const char *username,
                      uint8_t permission, int64_t expires_at) {
    uint8_t req[4u + 2u + VW_MAX_PATH_BYTES + 2u + VW_MAX_USERNAME_BYTES + 1u + 8u];
    uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    vw_ipc_write_str(req, sizeof(req), &off, path, (uint16_t)strlen(path));
    vw_ipc_write_str(req, sizeof(req), &off, username, (uint16_t)strlen(username));
    req[off++] = permission;
    vw_write_u64le(req + off, (uint64_t)expires_at); off += 8;

    uint8_t resp[12];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_SHARE_GRANT_REQ, req, off,
                             VW_IPC_SHARE_GRANT_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "share: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "share")) return 1;
    printf("shared: share_id=%llu\n", (unsigned long long)vw_read_u64le(resp + 4u));
    return 0;
}

/* SHARE_REVOKE_REQ / LINK_REVOKE_REQ: u32 account_id, u64 share_id.
 * RESP: u32 error_code. */
static int cmd_revoke(vw_ipc_conn_t *conn, uint32_t account_id, uint64_t share_id,
                       vw_ipc_msg_t req_type, vw_ipc_msg_t resp_type, const char *cmd_name) {
    uint8_t req[12];
    vw_write_u32le(req, account_id);
    vw_write_u64le(req + 4u, share_id);

    uint8_t resp[4];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, req_type, req, sizeof(req), resp_type, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "%s: IPC error %d\n", cmd_name, (int)err); return 1; }
    if (check_u32_resp(resp, rlen, cmd_name)) return 1;
    printf("revoked\n");
    return 0;
}

static const char *perm_str(uint8_t p) {
    switch ((vw_perm_t)p) {
    case VW_PERM_VIEW:  return "view";
    case VW_PERM_EDIT:  return "edit";
    case VW_PERM_OWNER: return "owner";
    default:            return "none";
    }
}

/* SHARE_LIST_REQ: u32 account_id, u8 mode. SHARE_LIST_RESP: u32 error_code, u32 count, entries. */
static int cmd_list_shares(vw_ipc_conn_t *conn, uint32_t account_id, uint8_t mode) {
    uint8_t req[5];
    vw_write_u32le(req, account_id);
    req[4] = mode;
    uint8_t *resp = malloc(65536);
    if (!resp) { fprintf(stderr, "list-shares: out of memory\n"); return 1; }

    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_SHARE_LIST_REQ, req, sizeof(req),
                             VW_IPC_SHARE_LIST_RESP, resp, 65536, &rlen);
    if (err != VW_OK) { fprintf(stderr, "list-shares: IPC error %d\n", (int)err); free(resp); return 1; }
    if (check_u32_resp(resp, rlen, "list-shares")) { free(resp); return 1; }
    if (rlen < 8u) { free(resp); return 0; }

    uint32_t count = vw_read_u32le(resp + 4u);
    uint32_t off = 8u;

    printf("%-10s  %-6s  %-10s  %-8s  %-20s  %-19s  %s\n",
           "SHARE_ID", "FILE", "TYPE", "PERM", "TARGET", "EXPIRES (UTC)", "NAME");

    for (uint32_t i = 0; i < count; i++) {
        if (off + 8u + 8u > rlen) break;
        uint64_t share_id = vw_read_u64le(resp + off); off += 8;
        uint64_t file_id  = vw_read_u64le(resp + off); off += 8;

        const char *name = NULL; uint16_t name_len = 0;
        if (vw_ipc_read_str(resp, rlen, &off, &name, &name_len) != VW_OK) break;
        if (off + 1u > rlen) break;
        uint8_t share_type = resp[off++];
        const char *tgt = NULL; uint16_t tgt_len = 0;
        if (vw_ipc_read_str(resp, rlen, &off, &tgt, &tgt_len) != VW_OK) break;
        if (off + 1u + 8u + 8u + 1u > rlen) break;
        uint8_t permission = resp[off++];
        off += 8u; /* created_at, unused here */
        int64_t expires_at = (int64_t)vw_read_u64le(resp + off); off += 8;
        off += 1u; /* revoked, unused here */

        char name_buf[65]; size_t nc = name_len < sizeof(name_buf) - 1u ? name_len : sizeof(name_buf) - 1u;
        memcpy(name_buf, name, nc); name_buf[nc] = '\0';
        char tgt_buf[66]; size_t tc = tgt_len < sizeof(tgt_buf) - 1u ? tgt_len : sizeof(tgt_buf) - 1u;
        memcpy(tgt_buf, tgt, tc); tgt_buf[tc] = '\0';
        char exp_buf[24]; format_ts(expires_at, exp_buf, sizeof(exp_buf), 1);

        printf("%-10llu  %-6llu  %-10s  %-8s  %-20s  %-19s  %s\n",
               (unsigned long long)share_id, (unsigned long long)file_id,
               share_type == 0 ? "grant" : "link",
               perm_str(permission), tgt_buf[0] ? tgt_buf : "-", exp_buf, name_buf);
    }

    free(resp);
    return 0;
}

/* LINK_CREATE_REQ: u32 account_id, string path, u8 permission, i64 expires_at.
 * LINK_CREATE_RESP: u32 error_code, u64 share_id, bytes[32] link_token. */
static int cmd_create_link(vw_ipc_conn_t *conn, uint32_t account_id, const char *path,
                            uint8_t permission, int64_t expires_at) {
    uint8_t req[4u + 2u + VW_MAX_PATH_BYTES + 1u + 8u];
    uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    vw_ipc_write_str(req, sizeof(req), &off, path, (uint16_t)strlen(path));
    req[off++] = permission;
    vw_write_u64le(req + off, (uint64_t)expires_at); off += 8;

    uint8_t resp[4u + 8u + 32u];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_LINK_CREATE_REQ, req, off,
                             VW_IPC_LINK_CREATE_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "create-link: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "create-link")) { memset(resp, 0, sizeof(resp)); return 1; }
    if (rlen < sizeof(resp)) { memset(resp, 0, sizeof(resp)); fprintf(stderr, "create-link: truncated response\n"); return 1; }

    uint64_t share_id = vw_read_u64le(resp + 4u);
    printf("link created: share_id=%llu\n", (unsigned long long)share_id);
    printf("token (save this now — it is never shown again): ");
    for (int i = 0; i < 32; i++) printf("%02x", resp[12u + (uint32_t)i]);
    printf("\n");
    memset(resp, 0, sizeof(resp));
    return 0;
}

/* LINK_LIST_REQ: u32 account_id, u64 file_id_filter (always 0 from the CLI —
 * no per-file filtering surfaced yet). LINK_LIST_RESP: u32 error_code,
 * u32 count, entries. */
static int cmd_list_links(vw_ipc_conn_t *conn, uint32_t account_id) {
    uint8_t req[12] = {0};
    vw_write_u32le(req, account_id);
    uint8_t *resp = malloc(65536);
    if (!resp) { fprintf(stderr, "list-links: out of memory\n"); return 1; }

    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_LINK_LIST_REQ, req, sizeof(req),
                             VW_IPC_LINK_LIST_RESP, resp, 65536, &rlen);
    if (err != VW_OK) { fprintf(stderr, "list-links: IPC error %d\n", (int)err); free(resp); return 1; }
    if (check_u32_resp(resp, rlen, "list-links")) { free(resp); return 1; }
    if (rlen < 8u) { free(resp); return 0; }

    uint32_t count = vw_read_u32le(resp + 4u);
    uint32_t off = 8u;

    printf("%-10s  %-6s  %-8s  %-19s  %-8s  %s\n",
           "SHARE_ID", "FILE", "PERM", "EXPIRES (UTC)", "REVOKED", "NAME");

    for (uint32_t i = 0; i < count; i++) {
        if (off + 8u + 8u > rlen) break;
        uint64_t share_id = vw_read_u64le(resp + off); off += 8;
        uint64_t file_id  = vw_read_u64le(resp + off); off += 8;

        const char *name = NULL; uint16_t name_len = 0;
        if (vw_ipc_read_str(resp, rlen, &off, &name, &name_len) != VW_OK) break;
        if (off + 1u + 8u + 8u + 1u > rlen) break;
        uint8_t permission = resp[off++];
        off += 8u; /* created_at, unused here */
        int64_t expires_at = (int64_t)vw_read_u64le(resp + off); off += 8;
        uint8_t revoked = resp[off++];

        char name_buf[65]; size_t nc = name_len < sizeof(name_buf) - 1u ? name_len : sizeof(name_buf) - 1u;
        memcpy(name_buf, name, nc); name_buf[nc] = '\0';
        char exp_buf[24]; format_ts(expires_at, exp_buf, sizeof(exp_buf), 1);

        printf("%-10llu  %-6llu  %-8s  %-19s  %-8s  %s\n",
               (unsigned long long)share_id, (unsigned long long)file_id,
               perm_str(permission), exp_buf, revoked ? "yes" : "no", name_buf);
    }

    free(resp);
    return 0;
}

/* ── Usage ───────────────────────────────────────────────────────────────── */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [--ipc-port <port>] [--account <label-or-id>] <command> [args]\n"
        "\n"
        "Account commands (TASK-161/162 — the daemon holds multiple accounts,\n"
        "each independently configured against its own server; see \"account add\"):\n"
        "  account add <host> <port> <username> <password|-|--stdin-password>\n"
        "              [otp-code] [--label <name>] [--ca-cert <path>]\n"
        "                                Add (or re-authenticate) an account. label\n"
        "                                defaults to <username>. Adding a second\n"
        "                                account against a different server is the\n"
        "                                normal way to use two unrelated self-hosted\n"
        "                                networks (e.g. family + friends) from one\n"
        "                                client — just give it a different host.\n"
        "  account list                  List configured accounts (id, label,\n"
        "                                username, server, connected)\n"
        "  account remove <label-or-id>  Log out and forget an account (local\n"
        "                                cache deleted; already-synced files on\n"
        "                                disk are untouched)\n"
        "\n"
        "Commands (account-scoped ones use --account, or the sole configured\n"
        "account if only one exists):\n"
        "  status                        Show daemon status (all accounts)\n"
        "  sync                          Trigger immediate sync (all accounts)\n"
        "  pause [<local_root>]          Pause sync (all or one folder)\n"
        "  resume [<local_root>]         Resume sync\n"
        "  add-folder <local> <virtual>  Add a sync folder\n"
        "  add-shared-folder <local> <virtual> <remote_dir_id>\n"
        "                                Add a sync folder rooted at a shared\n"
        "                                item's file_id (see list-shares)\n"
        "  remove-folder <local>         Remove a sync folder\n"
        "  list-folders                  List sync folders (owned + shared)\n"
        "  ls [<virtual_path>]           List synced files\n"
        "  conflicts                     List conflicted files only\n"
        "  share <path> <user> <view|edit> [expires_unix]\n"
        "                                Grant a user access to a file/folder\n"
        "  unshare <share_id>            Revoke a user-to-user grant\n"
        "  list-shares [--to-me]         List grants (created by me, or to me)\n"
        "  create-link <path> <view|edit> [expires_unix]\n"
        "                                Mint a public link; token shown once\n"
        "  revoke-link <share_id>        Revoke a public link\n"
        "  list-links                    List public links I've created\n"
        "  shutdown                      Ask the daemon to stop\n"
        "\n"
        "Options:\n"
        "  --ipc-port <port>          Override IPC port (default: %u)\n"
        "  --account <label-or-id>    Account to use for an account-scoped command\n"
        "  --help, -h                 Show this help\n",
        prog, (unsigned)VW_IPC_DEFAULT_PORT);
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int vw_client_cli_main(int argc, char *argv[], uint16_t ipc_port) {
#ifdef _WIN32
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);
#endif

    int argi = 1;
    const char *account_arg = NULL; /* --account <label-or-id>, or NULL */

    /* Global flags before the subcommand */
    while (argi < argc) {
        if (strcmp(argv[argi], "--ipc-port") == 0 && argi + 1 < argc) {
            argi++;
            int p = atoi(argv[argi]);
            if (p <= 0 || p > 65535) {
                fprintf(stderr, "error: invalid port: %s\n", argv[argi]);
                return 1;
            }
            ipc_port = (uint16_t)p;
            argi++;
        } else if (strcmp(argv[argi], "--account") == 0 && argi + 1 < argc) {
            argi++;
            account_arg = argv[argi];
            argi++;
        } else if (strcmp(argv[argi], "--help") == 0 ||
                   strcmp(argv[argi], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            break;
        }
    }

    if (argi >= argc) {
        print_usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[argi++];

    /* Help check helper — avoids repeating this inline per subcommand */
#define HELP_IF_REQUESTED() \
    do { if (argi < argc && (strcmp(argv[argi], "--help") == 0 || \
                              strcmp(argv[argi], "-h") == 0)) { \
        print_usage(argv[0]); return 0; } } while (0)

    if (strcmp(cmd, "status") == 0) {
        HELP_IF_REQUESTED();
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_status(c);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "sync") == 0) {
        HELP_IF_REQUESTED();
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_sync(c);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "pause") == 0) {
        HELP_IF_REQUESTED();
        const char *folder = (argi < argc) ? argv[argi++] : NULL;
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_pause(c, account_id, folder);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "resume") == 0) {
        HELP_IF_REQUESTED();
        const char *folder = (argi < argc) ? argv[argi++] : NULL;
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_resume(c, account_id, folder);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "add-folder") == 0) {
        HELP_IF_REQUESTED();
        if (argi + 1 >= argc) {
            fprintf(stderr, "Usage: %s add-folder <local_path> <virtual_path>\n",
                    argv[0]);
            return 1;
        }
        const char *local = argv[argi++];
        const char *virt  = argv[argi++];
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_add_folder(c, account_id, local, virt);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "add-shared-folder") == 0) {
        HELP_IF_REQUESTED();
        if (argi + 2 >= argc) {
            fprintf(stderr, "Usage: %s add-shared-folder <local_path> <virtual_path> <remote_dir_id>\n",
                    argv[0]);
            return 1;
        }
        const char *local = argv[argi++];
        const char *virt  = argv[argi++];
        const char *idstr = argv[argi++];
        unsigned long long remote_dir_id = strtoull(idstr, NULL, 10);
        if (remote_dir_id == 0) {
            fprintf(stderr, "error: remote_dir_id must be a nonzero file_id\n");
            return 1;
        }
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_add_shared_folder(c, account_id, local, virt, (uint64_t)remote_dir_id);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "remove-folder") == 0) {
        HELP_IF_REQUESTED();
        if (argi >= argc) {
            fprintf(stderr, "Usage: %s remove-folder <local_path>\n", argv[0]);
            return 1;
        }
        const char *local = argv[argi++];
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_remove_folder(c, account_id, local);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "list-folders") == 0) {
        HELP_IF_REQUESTED();
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_list_folders(c, account_id);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "ls") == 0) {
        HELP_IF_REQUESTED();
        const char *prefix = (argi < argc) ? argv[argi++] : NULL;
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_ls(c, account_id, prefix, VW_IPC_FILTER_ALL);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "conflicts") == 0) {
        HELP_IF_REQUESTED();
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_ls(c, account_id, NULL, (uint8_t)VW_SYNC_CONFLICT);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "account") == 0) {
        HELP_IF_REQUESTED();
        if (argi >= argc) {
            fprintf(stderr, "Usage: %s account add|list|remove ...\n", argv[0]);
            return 1;
        }
        const char *subcmd = argv[argi++];

        if (strcmp(subcmd, "add") == 0) {
            if (argi + 4 > argc) {
                fprintf(stderr,
                    "Usage: %s account add <host> <port> <username> "
                    "<password|-|--stdin-password> [otp-code] "
                    "[--label <name>] [--ca-cert <path>]\n"
                    "  Pass '-' or '--stdin-password' to read the password from stdin.\n",
                    argv[0]);
                return 1;
            }
            const char *host     = argv[argi++];
            uint16_t    port     = (uint16_t)strtoul(argv[argi++], NULL, 10);
            const char *username = argv[argi++];
            const char *pw_arg   = argv[argi++];
            const char *otp      = NULL;
            const char *label    = NULL;
            const char *ca_cert  = NULL;

            /* otp is the next bare token, if any, before the --flags start. */
            if (argi < argc && strncmp(argv[argi], "--", 2) != 0) {
                otp = argv[argi++];
            }
            while (argi < argc) {
                if (strcmp(argv[argi], "--label") == 0 && argi + 1 < argc) {
                    label = argv[argi + 1]; argi += 2;
                } else if (strcmp(argv[argi], "--ca-cert") == 0 && argi + 1 < argc) {
                    ca_cert = argv[argi + 1]; argi += 2;
                } else {
                    fprintf(stderr, "error: unrecognized argument: %s\n", argv[argi]);
                    return 1;
                }
            }

            /* Read password from stdin when '-' or '--stdin-password' is
             * specified, to avoid exposing it in /proc/<pid>/cmdline and ps
             * output — same convention as the server admin CLI's
             * user-create. */
            static char stdin_pw[256];
            const char *pw;
            if (strcmp(pw_arg, "-") == 0 || strcmp(pw_arg, "--stdin-password") == 0) {
                if (!fgets(stdin_pw, (int)sizeof(stdin_pw), stdin)) {
                    fprintf(stderr, "error: failed to read password from stdin\n");
                    return 1;
                }
                size_t plen = strlen(stdin_pw);
                if (plen > 0 && stdin_pw[plen - 1] == '\n') stdin_pw[--plen] = '\0';
                pw = stdin_pw;
            } else {
                pw = pw_arg;
            }
            vw_ipc_conn_t *c = cli_connect(ipc_port);
            if (!c) { memset(stdin_pw, 0, sizeof(stdin_pw)); return 1; }
            int rc = cmd_account_add(c, host, port, ca_cert, label, username, pw, otp);
            vw_ipc_conn_close(c);
            memset(stdin_pw, 0, sizeof(stdin_pw));
            return rc;
        }

        if (strcmp(subcmd, "list") == 0) {
            vw_ipc_conn_t *c = cli_connect(ipc_port);
            if (!c) return 1;
            int rc = cmd_account_list(c);
            vw_ipc_conn_close(c);
            return rc;
        }

        if (strcmp(subcmd, "remove") == 0) {
            if (argi >= argc) {
                fprintf(stderr, "Usage: %s account remove <label-or-id>\n", argv[0]);
                return 1;
            }
            const char *target = argv[argi++];
            uint32_t account_id = 0;
            if (resolve_account_id(ipc_port, target, &account_id)) return 1;
            vw_ipc_conn_t *c = cli_connect(ipc_port);
            if (!c) return 1;
            int rc = cmd_account_remove(c, account_id);
            vw_ipc_conn_close(c);
            return rc;
        }

        fprintf(stderr, "error: unknown account subcommand '%s' (expected add|list|remove)\n", subcmd);
        return 1;
    }

    if (strcmp(cmd, "share") == 0) {
        HELP_IF_REQUESTED();
        if (argi + 2 >= argc) {
            fprintf(stderr, "Usage: %s share <path> <username> <view|edit> [expires_unix]\n", argv[0]);
            return 1;
        }
        const char *path = argv[argi++];
        const char *username = argv[argi++];
        uint8_t permission;
        if (parse_permission(argv[argi++], &permission)) return 1;
        int64_t expires_at = (argi < argc) ? (int64_t)strtoll(argv[argi++], NULL, 10) : 0;
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_share(c, account_id, path, username, permission, expires_at);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "unshare") == 0) {
        HELP_IF_REQUESTED();
        if (argi >= argc) {
            fprintf(stderr, "Usage: %s unshare <share_id>\n", argv[0]);
            return 1;
        }
        uint64_t share_id = strtoull(argv[argi++], NULL, 10);
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_revoke(c, account_id, share_id, VW_IPC_SHARE_REVOKE_REQ, VW_IPC_SHARE_REVOKE_RESP, "unshare");
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "list-shares") == 0) {
        HELP_IF_REQUESTED();
        uint8_t mode = 0;
        if (argi < argc && strcmp(argv[argi], "--to-me") == 0) { mode = 1; argi++; }
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_list_shares(c, account_id, mode);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "create-link") == 0) {
        HELP_IF_REQUESTED();
        if (argi + 1 >= argc) {
            fprintf(stderr, "Usage: %s create-link <path> <view|edit> [expires_unix]\n", argv[0]);
            return 1;
        }
        const char *path = argv[argi++];
        uint8_t permission;
        if (parse_permission(argv[argi++], &permission)) return 1;
        int64_t expires_at = (argi < argc) ? (int64_t)strtoll(argv[argi++], NULL, 10) : 0;
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_create_link(c, account_id, path, permission, expires_at);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "revoke-link") == 0) {
        HELP_IF_REQUESTED();
        if (argi >= argc) {
            fprintf(stderr, "Usage: %s revoke-link <share_id>\n", argv[0]);
            return 1;
        }
        uint64_t share_id = strtoull(argv[argi++], NULL, 10);
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_revoke(c, account_id, share_id, VW_IPC_LINK_REVOKE_REQ, VW_IPC_LINK_REVOKE_RESP, "revoke-link");
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "list-links") == 0) {
        HELP_IF_REQUESTED();
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_list_links(c, account_id);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "shutdown") == 0) {
        HELP_IF_REQUESTED();
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_shutdown(c);
        vw_ipc_conn_close(c);
        return rc;
    }

#undef HELP_IF_REQUESTED

    fprintf(stderr, "error: unknown command: %s\n", cmd);
    print_usage(argv[0]);
    return 1;
}
