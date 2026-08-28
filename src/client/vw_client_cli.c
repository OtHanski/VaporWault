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
#include "vw_version.h"

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
    uint8_t  conn_mode; /* TASK-173/174: 0=offline, 1=primary, 2=fallback (read-only) */
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
        /* TASK-173/174: trailing conn_mode byte (0=offline, 1=primary,
         * 2=fallback) — must always be consumed, or every subsequent
         * entry's offset desyncs by one byte per account already seen. */
        uint8_t conn_mode = 0;
        if (off + 1u > rlen) break;
        conn_mode = resp[off]; off += 1u;
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
            e->conn_mode = conn_mode;
        }
        written++;
    }
    free(resp);
    return written;
}

/* Defined below with cmd_account_list; forward-declared here since this
 * hint function is used earlier in the file (resolve_account_id). */
static const char *conn_mode_str(uint8_t conn_mode);

static void print_account_list_hint(const account_list_entry_t *accts, int n) {
    for (int i = 0; i < n; i++) {
        fprintf(stderr, "    id=%u  label=%s  username=%s  server=%s  %s\n",
                (unsigned)accts[i].account_id, accts[i].label, accts[i].username,
                accts[i].server_host, conn_mode_str(accts[i].conn_mode));
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
    /* TASK-173: trailing byte, same append convention as perm_denied above. */
    uint8_t  any_on_fallback = (rlen >= 29) ? resp[28] : 0;

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
    if (any_on_fallback)
        printf("  NOTE: at least one account is on its read-only fallback "
               "right now — run `account list` for details.\n");
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

        /* TASK-192/193: selective-sync exclude rules, trailing field. */
        if (off + 2u > rlen) continue;
        uint16_t ecount = vw_read_u16le(resp + off); off += 2u;
        for (uint16_t j = 0; j < ecount; j++) {
            const char *pat = NULL; uint16_t pl = 0;
            if (vw_ipc_read_str(resp, rlen, &off, &pat, &pl) != VW_OK) break;
            char pbuf[256]; size_t pc = pl < sizeof(pbuf)-1u ? pl : sizeof(pbuf)-1u;
            memcpy(pbuf, pat, pc); pbuf[pc] = '\0';
            printf("           exclude: %s\n", pbuf);
        }
    }

    free(resp);
    return 0;
}

/* ── Subcommand: set-folder-rules (TASK-192/193) ──────────────────────────
 * Wholesale replace, not incremental — passing zero --exclude flags
 * clears every existing rule for the folder. FOLDER_SET_EXCLUDES_REQ:
 * u32 account_id, string local_root, u16 count, count*string pattern.
 * FOLDER_SET_EXCLUDES_RESP: u32 error_code. */
static int cmd_set_folder_excludes(vw_ipc_conn_t *conn, uint32_t account_id,
                                    const char *local_root,
                                    const char **patterns, uint16_t count) {
    uint8_t req[4u + 2u + VW_MAX_PATH_BYTES + 2u + 64u * 258u];
    uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    vw_ipc_write_str(req, sizeof(req), &off, local_root, (uint16_t)strlen(local_root));
    vw_write_u16le(req + off, count); off += 2u;
    for (uint16_t i = 0; i < count; i++)
        vw_ipc_write_str(req, sizeof(req), &off, patterns[i], (uint16_t)strlen(patterns[i]));

    uint8_t resp[4];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_FOLDER_SET_EXCLUDES_REQ, req, off,
                             VW_IPC_FOLDER_SET_EXCLUDES_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "set-folder-rules: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "set-folder-rules")) return 1;

    if (count == 0)
        printf("cleared all exclude rules for %s\n", local_root);
    else
        printf("set %u exclude rule(s) for %s\n", (unsigned)count, local_root);
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
                            const char *username, const char *password, const char *otp,
                            const char *fallback_host, uint16_t fallback_port,
                            const char *fallback_ca_cert_path) {
    /* Worst case: 4 (account_id) + (2+63) label + (2+255) host + 2 (port) +
     * (2+511) ca_cert_path + (2+63) username + (2+255) password +
     * (2+16) otp + (2+255) fallback_host + 2 (fallback_port) +
     * (2+511) fallback_ca_cert_path = 1954 bytes — sized with headroom, and
     * every vw_ipc_write_str call below is still checked rather than
     * trusted, since a silently-skipped write (VW_ERR_PROTO_TOO_LARGE)
     * would desync every field after it into the wrong byte offset instead
     * of just failing cleanly. */
    uint8_t payload[2048];
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

    /* TASK-174: optional trailing fallback fields — omitted entirely (not
     * sent as empty strings) when the caller supplied none, so a
     * re-authentication that doesn't repeat --fallback-* leaves whatever
     * fallback config already exists untouched (vw_daemon.c's own
     * "absent means leave as-is" contract, see TASK-173). */
    if (werr == VW_OK && fallback_host && fallback_host[0]) {
        werr = vw_ipc_write_str(payload, sizeof(payload), &off,
                                 fallback_host, (uint16_t)strnlen(fallback_host, 255));
        if (werr == VW_OK && off + 2u <= sizeof(payload)) {
            vw_write_u16le(payload + off, fallback_port); off += 2u;
        } else if (werr == VW_OK) {
            werr = VW_ERR_PROTO_TOO_LARGE;
        }
        const char *fca = fallback_ca_cert_path ? fallback_ca_cert_path : "";
        if (werr == VW_OK)
            werr = vw_ipc_write_str(payload, sizeof(payload), &off, fca,
                                     (uint16_t)strnlen(fca, 511));
    }

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
    if (fallback_host && fallback_host[0])
        printf("account added: id=%u label=%s username=%s server=%s:%u fallback=%s:%u\n",
               (unsigned)account_id, lbl, username, server_host, (unsigned)server_port,
               fallback_host, (unsigned)fallback_port);
    else
        printf("account added: id=%u label=%s username=%s server=%s:%u\n",
               (unsigned)account_id, lbl, username, server_host, (unsigned)server_port);
    return 0;
}

/* ACCOUNT_LIST_REQ: no payload. Reuses fetch_account_list()'s decode. */
/* TASK-173/174: matches vw_account_conn_mode_t in vw_daemon.c. */
static const char *conn_mode_str(uint8_t conn_mode) {
    switch (conn_mode) {
    case 1:  return "primary";
    case 2:  return "fallback (read-only)";
    default: return "offline";
    }
}

static int cmd_account_list(vw_ipc_conn_t *conn) {
    account_list_entry_t accts[64];
    int n = fetch_account_list(conn, accts, 64);
    if (n < 0) return 1;
    if (n == 0) { printf("no accounts configured\n"); return 0; }
    printf("%-4s  %-16s  %-20s  %-24s  %s\n", "ID", "LABEL", "USERNAME", "SERVER", "STATUS");
    for (int i = 0; i < n && i < 64; i++) {
        printf("%-4u  %-16s  %-20s  %-24s  %s\n",
               (unsigned)accts[i].account_id, accts[i].label, accts[i].username,
               accts[i].server_host, conn_mode_str(accts[i].conn_mode));
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
                            uint8_t permission, int64_t expires_at, const char *password) {
    uint8_t req[4u + 2u + VW_MAX_PATH_BYTES + 1u + 8u + 2u + 256u];
    uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    vw_ipc_write_str(req, sizeof(req), &off, path, (uint16_t)strlen(path));
    req[off++] = permission;
    vw_write_u64le(req + off, (uint64_t)expires_at); off += 8;
    vw_ipc_write_str(req, sizeof(req), &off, password ? password : "",
                      (uint16_t)(password ? strlen(password) : 0));

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

    printf("%-10s  %-6s  %-8s  %-19s  %-8s  %-9s  %s\n",
           "SHARE_ID", "FILE", "PERM", "EXPIRES (UTC)", "REVOKED", "PASSWORD", "NAME");

    for (uint32_t i = 0; i < count; i++) {
        if (off + 8u + 8u > rlen) break;
        uint64_t share_id = vw_read_u64le(resp + off); off += 8;
        uint64_t file_id  = vw_read_u64le(resp + off); off += 8;

        const char *name = NULL; uint16_t name_len = 0;
        if (vw_ipc_read_str(resp, rlen, &off, &name, &name_len) != VW_OK) break;
        if (off + 1u + 8u + 8u + 1u + 1u > rlen) break;
        uint8_t permission = resp[off++];
        off += 8u; /* created_at, unused here */
        int64_t expires_at = (int64_t)vw_read_u64le(resp + off); off += 8;
        uint8_t revoked = resp[off++];
        uint8_t has_password = resp[off++]; /* TASK-186/188 */

        char name_buf[65]; size_t nc = name_len < sizeof(name_buf) - 1u ? name_len : sizeof(name_buf) - 1u;
        memcpy(name_buf, name, nc); name_buf[nc] = '\0';
        char exp_buf[24]; format_ts(expires_at, exp_buf, sizeof(exp_buf), 1);

        printf("%-10llu  %-6llu  %-8s  %-19s  %-8s  %-9s  %s\n",
               (unsigned long long)share_id, (unsigned long long)file_id,
               perm_str(permission), exp_buf, revoked ? "yes" : "no",
               has_password ? "yes" : "no", name_buf);
    }

    free(resp);
    return 0;
}

/* ── Subcommands: version list / version restore (TASK-182) ─────────────── */

/* VERSION_LIST_REQ: u32 account_id, string virtual_path. VERSION_LIST_RESP:
 * u32 error_code, u32 count, count * { u64 version_id, i64 created_at,
 * u64 size_bytes }. */
static int cmd_version_list(vw_ipc_conn_t *conn, uint32_t account_id, const char *path) {
    uint8_t req[4u + 2u + VW_MAX_PATH_BYTES];
    uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    vw_ipc_write_str(req, sizeof(req), &off, path, (uint16_t)strlen(path));

    uint8_t *resp = malloc(65536);
    if (!resp) { fprintf(stderr, "version list: out of memory\n"); return 1; }
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_VERSION_LIST_REQ, req, off,
                             VW_IPC_VERSION_LIST_RESP, resp, 65536, &rlen);
    if (err != VW_OK) { fprintf(stderr, "version list: IPC error %d\n", (int)err); free(resp); return 1; }
    if (check_u32_resp(resp, rlen, "version list")) { free(resp); return 1; }
    if (rlen < 8u) { free(resp); return 0; }

    uint32_t count = vw_read_u32le(resp + 4u);
    uint32_t roff = 8u;

    printf("%-12s  %-19s  %s\n", "VERSION_ID", "CREATED (UTC)", "SIZE");
    for (uint32_t i = 0; i < count; i++) {
        if (roff + 24u > rlen) break;
        uint64_t version_id  = vw_read_u64le(resp + roff); roff += 8;
        int64_t  created_at  = (int64_t)vw_read_u64le(resp + roff); roff += 8;
        uint64_t size_bytes  = vw_read_u64le(resp + roff); roff += 8;

        char ts_buf[24]; format_ts(created_at, ts_buf, sizeof(ts_buf), 0);
        printf("%-12llu  %-19s  %llu\n",
               (unsigned long long)version_id, ts_buf, (unsigned long long)size_bytes);
    }

    free(resp);
    return 0;
}

/* VERSION_RESTORE_REQ: u32 account_id, string virtual_path, u64 version_id.
 * VERSION_RESTORE_RESP: u32 error_code. */
static int cmd_version_restore(vw_ipc_conn_t *conn, uint32_t account_id,
                                 const char *path, uint64_t version_id) {
    uint8_t req[4u + 2u + VW_MAX_PATH_BYTES + 8u];
    uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    vw_ipc_write_str(req, sizeof(req), &off, path, (uint16_t)strlen(path));
    vw_write_u64le(req + off, version_id); off += 8u;

    uint8_t resp[4];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_VERSION_RESTORE_REQ, req, off,
                             VW_IPC_VERSION_RESTORE_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "version restore: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "version restore")) return 1;

    printf("restored version %llu\n", (unsigned long long)version_id);
    return 0;
}

/* ── version --file-id (TASK-223): shared-file version history ───────────── */
/* Lets a grantee use version history on a file shared with them, which
 * they have no owner-namespaced path to give the commands above — see
 * "list-shares" for the file_id, docs/PROTOCOL.md §7.14/§7.3 background. */

/* VERSION_LIST_BY_ID_REQ: u32 account_id, u64 file_id.
 * _RESP: same shape as VERSION_LIST_RESP. */
static int cmd_version_list_by_id(vw_ipc_conn_t *conn, uint32_t account_id, uint64_t file_id) {
    uint8_t req[12];
    vw_write_u32le(req, account_id);
    vw_write_u64le(req + 4, file_id);

    uint8_t *resp = malloc(65536);
    if (!resp) { fprintf(stderr, "version list: out of memory\n"); return 1; }
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_VERSION_LIST_BY_ID_REQ, req, sizeof(req),
                             VW_IPC_VERSION_LIST_BY_ID_RESP, resp, 65536, &rlen);
    if (err != VW_OK) { fprintf(stderr, "version list: IPC error %d\n", (int)err); free(resp); return 1; }
    if (check_u32_resp(resp, rlen, "version list")) { free(resp); return 1; }
    if (rlen < 8u) { free(resp); return 0; }

    uint32_t count = vw_read_u32le(resp + 4u);
    uint32_t roff = 8u;

    printf("%-12s  %-19s  %s\n", "VERSION_ID", "CREATED (UTC)", "SIZE");
    for (uint32_t i = 0; i < count; i++) {
        if (roff + 24u > rlen) break;
        uint64_t version_id  = vw_read_u64le(resp + roff); roff += 8;
        int64_t  created_at  = (int64_t)vw_read_u64le(resp + roff); roff += 8;
        uint64_t size_bytes  = vw_read_u64le(resp + roff); roff += 8;

        char ts_buf[24]; format_ts(created_at, ts_buf, sizeof(ts_buf), 0);
        printf("%-12llu  %-19s  %llu\n",
               (unsigned long long)version_id, ts_buf, (unsigned long long)size_bytes);
    }

    free(resp);
    return 0;
}

/* VERSION_RESTORE_BY_ID_REQ: u32 account_id, u64 version_id.
 * _RESP: u32 error_code. */
static int cmd_version_restore_by_id(vw_ipc_conn_t *conn, uint32_t account_id,
                                      uint64_t version_id) {
    uint8_t req[12];
    vw_write_u32le(req, account_id);
    vw_write_u64le(req + 4, version_id);

    uint8_t resp[4];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_VERSION_RESTORE_BY_ID_REQ, req, sizeof(req),
                             VW_IPC_VERSION_RESTORE_BY_ID_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "version restore: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "version restore")) return 1;

    printf("restored version %llu\n", (unsigned long long)version_id);
    return 0;
}

/* ── Subcommand: search (TASK-199; docs/PROTOCOL.md §7.12) ───────────────── */

/* SEARCH_REQ: u32 account_id, string query. SEARCH_RESP: u32 error_code,
 * u32 count, u8 truncated, count * { u64 file_id, string name, u8 is_dir,
 * u64 size_bytes, i64 mtime_unix, u64 vault_id, u8 is_shared }. */
static int cmd_search(vw_ipc_conn_t *conn, uint32_t account_id, const char *query) {
    uint8_t req[4u + 2u + 256u];
    uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    vw_ipc_write_str(req, sizeof(req), &off, query, (uint16_t)strlen(query));

    uint8_t *resp = malloc(65536);
    if (!resp) { fprintf(stderr, "search: out of memory\n"); return 1; }
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_SEARCH_REQ, req, off,
                             VW_IPC_SEARCH_RESP, resp, 65536, &rlen);
    if (err != VW_OK) { fprintf(stderr, "search: IPC error %d\n", (int)err); free(resp); return 1; }
    if (check_u32_resp(resp, rlen, "search")) { free(resp); return 1; }
    if (rlen < 9u) { free(resp); return 0; }

    uint32_t count     = vw_read_u32le(resp + 4u);
    uint8_t  truncated = resp[8];
    uint32_t roff      = 9u;

    printf("%-10s  %-4s  %-8s  %-19s  %s\n", "FILE_ID", "TYPE", "SHARED", "MODIFIED (UTC)", "NAME");
    for (uint32_t i = 0; i < count; i++) {
        if (roff + 8u > rlen) break;
        uint64_t file_id = vw_read_u64le(resp + roff); roff += 8u;

        const char *name; uint16_t name_len;
        if (vw_ipc_read_str(resp, rlen, &roff, &name, &name_len) != VW_OK) break;
        char name_buf[64];
        uint16_t nc = name_len < sizeof(name_buf) - 1u ? name_len : (uint16_t)(sizeof(name_buf) - 1u);
        memcpy(name_buf, name, nc); name_buf[nc] = '\0';

        if (roff + 1u + 8u + 8u + 8u + 1u > rlen) break;
        uint8_t  is_dir     = resp[roff++];
        roff += 8u; /* size_bytes: not shown in this column layout */
        int64_t  mtime_unix = (int64_t)vw_read_u64le(resp + roff); roff += 8u;
        roff += 8u; /* vault_id: not shown here; `stat`/`list-folders` surface encryption status */
        uint8_t  is_shared  = resp[roff++];

        char ts_buf[24]; format_ts(mtime_unix, ts_buf, sizeof(ts_buf), 0);
        printf("%-10llu  %-4s  %-8s  %-19s  %s\n",
               (unsigned long long)file_id, is_dir ? "dir" : "file",
               is_shared ? "yes" : "no", ts_buf, name_buf);
    }

    if (truncated)
        printf("(results truncated at the server's cap — narrow the query to see more)\n");

    free(resp);
    return 0;
}

/* ── Subcommand: notify (TASK-206/207/209; docs/PROTOCOL.md §7.13) ───────── */

/* Human-readable category table — single source of truth for both `notify
 * list`'s display names and `notify set <category>`'s name lookup, so the
 * two can never drift apart. */
static const struct { const char *name; uint32_t bit; const char *desc; } NOTIFY_CATEGORIES[] = {
    { "share_received",         VW_NOTIFY_SHARE_RECEIVED,          "Someone shared a file or folder with you" },
    { "quota_warning",          VW_NOTIFY_QUOTA_WARNING,           "Your storage usage crossed 90% of your quota" },
    { "new_login",              VW_NOTIFY_NEW_LOGIN,               "A new (non-reconnect) login succeeded on your account" },
    { "account_security_change", VW_NOTIFY_ACCOUNT_SECURITY_CHANGE, "Your password changed or 2FA was enabled/disabled" },
};
#define NOTIFY_CATEGORIES_COUNT (sizeof(NOTIFY_CATEGORIES) / sizeof(NOTIFY_CATEGORIES[0]))

/* NOTIFY_PREFS_GET_REQ: u32 account_id. _GET_RESP: u32 error_code, u32 prefs_bitmask. */
static int cmd_notify_list(vw_ipc_conn_t *conn, uint32_t account_id) {
    uint8_t req[4];
    vw_write_u32le(req, account_id);

    uint8_t resp[8];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_NOTIFY_PREFS_GET_REQ, req, sizeof(req),
                             VW_IPC_NOTIFY_PREFS_GET_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "notify list: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "notify list")) return 1;
    if (rlen < 8u) { fprintf(stderr, "notify list: truncated response\n"); return 1; }

    uint32_t prefs = vw_read_u32le(resp + 4);
    printf("%-24s  %-4s  %s\n", "CATEGORY", "ON", "DESCRIPTION");
    for (size_t i = 0; i < NOTIFY_CATEGORIES_COUNT; i++) {
        printf("%-24s  %-4s  %s\n", NOTIFY_CATEGORIES[i].name,
               (prefs & NOTIFY_CATEGORIES[i].bit) ? "yes" : "no",
               NOTIFY_CATEGORIES[i].desc);
    }
    return 0;
}

/* NOTIFY_PREFS_SET_REQ: u32 account_id, u32 prefs_bitmask (the COMPLETE new
 * value, per §7.13 — this reads the current value via GET first, flips
 * only the one requested bit, then sends the full result). _SET_ACK:
 * u32 error_code, u32 prefs_bitmask (stored value after the call).
 *
 * Takes ipc_port rather than a pre-opened conn (unlike every other
 * cmd_* in this file) because it needs two separate request/response
 * round trips (GET then SET) and this codebase's daemon IPC is strictly
 * one-request-per-connection (vw_daemon.c's handle_ipc_client reads and
 * dispatches exactly one message, then the connection is done) — reusing
 * a single conn for a second request just hangs/errors on the daemon
 * having already moved on. Two short-lived connections, same as two
 * separate CLI invocations would each get. */
static int cmd_notify_set(uint16_t ipc_port, uint32_t account_id,
                           const char *category, const char *on_off) {
    uint32_t bit = 0;
    for (size_t i = 0; i < NOTIFY_CATEGORIES_COUNT; i++) {
        if (strcmp(category, NOTIFY_CATEGORIES[i].name) == 0) { bit = NOTIFY_CATEGORIES[i].bit; break; }
    }
    if (bit == 0) {
        fprintf(stderr, "notify set: unknown category '%s'\n", category);
        fprintf(stderr, "Known categories:");
        for (size_t i = 0; i < NOTIFY_CATEGORIES_COUNT; i++)
            fprintf(stderr, " %s", NOTIFY_CATEGORIES[i].name);
        fprintf(stderr, "\n");
        return 1;
    }
    int turn_on;
    if      (strcmp(on_off, "on")  == 0) turn_on = 1;
    else if (strcmp(on_off, "off") == 0) turn_on = 0;
    else { fprintf(stderr, "notify set: expected 'on' or 'off', got '%s'\n", on_off); return 1; }

    vw_ipc_conn_t *c1 = cli_connect(ipc_port);
    if (!c1) return 1;

    uint8_t greq[4];
    vw_write_u32le(greq, account_id);
    uint8_t gresp[8];
    uint32_t grlen = 0;
    vw_err_t err = ipc_rpc(c1, VW_IPC_NOTIFY_PREFS_GET_REQ, greq, sizeof(greq),
                             VW_IPC_NOTIFY_PREFS_GET_RESP, gresp, sizeof(gresp), &grlen);
    vw_ipc_conn_close(c1);
    if (err != VW_OK) { fprintf(stderr, "notify set: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(gresp, grlen, "notify set")) return 1;
    if (grlen < 8u) { fprintf(stderr, "notify set: truncated response\n"); return 1; }

    uint32_t prefs = vw_read_u32le(gresp + 4);
    if (turn_on) prefs |= bit; else prefs &= ~bit;

    vw_ipc_conn_t *c2 = cli_connect(ipc_port);
    if (!c2) return 1;

    uint8_t sreq[8];
    vw_write_u32le(sreq, account_id);
    vw_write_u32le(sreq + 4, prefs);
    uint8_t sresp[8];
    uint32_t srlen = 0;
    err = ipc_rpc(c2, VW_IPC_NOTIFY_PREFS_SET_REQ, sreq, sizeof(sreq),
                    VW_IPC_NOTIFY_PREFS_SET_ACK, sresp, sizeof(sresp), &srlen);
    vw_ipc_conn_close(c2);
    if (err != VW_OK) { fprintf(stderr, "notify set: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(sresp, srlen, "notify set")) return 1;

    printf("%s: %s\n", category, turn_on ? "on" : "off");
    return 0;
}

/* ── Subcommand: account email (TASK-222; docs/PROTOCOL.md §7.14) ────────── */

/* ACCOUNT_EMAIL_GET_REQ: u32 account_id. _GET_RESP: u32 error_code, string email. */
static int cmd_account_email_get(vw_ipc_conn_t *conn, uint32_t account_id) {
    uint8_t req[4];
    vw_write_u32le(req, account_id);

    uint8_t resp[4u + 2u + 128u];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_ACCOUNT_EMAIL_GET_REQ, req, sizeof(req),
                             VW_IPC_ACCOUNT_EMAIL_GET_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "account email: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "account email")) return 1;

    uint32_t off = 4u;
    const char *email; uint16_t email_len;
    if (vw_ipc_read_str(resp, rlen, &off, &email, &email_len) != VW_OK) {
        fprintf(stderr, "account email: truncated response\n");
        return 1;
    }
    if (email_len == 0) {
        printf("(no email on file — set one with: account email set <address>)\n");
    } else {
        printf("%.*s\n", (int)email_len, email);
    }
    return 0;
}

/* ACCOUNT_EMAIL_SET_REQ: u32 account_id, string email (""=clear).
 * _SET_ACK: u32 error_code, string email (stored value after the call). */
static int cmd_account_email_set(vw_ipc_conn_t *conn, uint32_t account_id, const char *address) {
    uint8_t req[4u + 2u + 128u];
    uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    if (vw_ipc_write_str(req, sizeof(req), &off, address, (uint16_t)strlen(address)) != VW_OK) {
        fprintf(stderr, "account email set: address too long\n");
        return 1;
    }

    uint8_t resp[4u + 2u + 128u];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_ACCOUNT_EMAIL_SET_REQ, req, off,
                             VW_IPC_ACCOUNT_EMAIL_SET_ACK, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "account email set: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "account email set")) return 1;

    printf("email set: %s\n", address);
    return 0;
}

/* ── Subcommand: account 2fa (TASK-219; docs/PROTOCOL.md §7.15) ──────────── */

/* ACCOUNT_2FA_GET_REQ: u32 account_id. _GET_RESP: u32 error_code, u8 otp_enabled. */
static int cmd_account_2fa_get(vw_ipc_conn_t *conn, uint32_t account_id) {
    uint8_t req[4];
    vw_write_u32le(req, account_id);

    uint8_t resp[5];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_ACCOUNT_2FA_GET_REQ, req, sizeof(req),
                             VW_IPC_ACCOUNT_2FA_GET_RESP, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "account 2fa: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "account 2fa")) return 1;

    printf("%s\n", (rlen >= 5u && resp[4]) ? "on" : "off");
    return 0;
}

/* ACCOUNT_2FA_SET_REQ: u32 account_id, string password, u8 enable.
 * _SET_ACK: u32 error_code, u8 otp_enabled (stored value after the call). */
static int cmd_account_2fa_set(vw_ipc_conn_t *conn, uint32_t account_id,
                                const char *password, int enable) {
    uint8_t req[4u + 2u + 256u + 1u];
    uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    if (vw_ipc_write_str(req, sizeof(req), &off, password, (uint16_t)strlen(password)) != VW_OK) {
        fprintf(stderr, "account 2fa: password too long\n");
        return 1;
    }
    req[off++] = (uint8_t)(enable ? 1 : 0);

    uint8_t resp[5];
    uint32_t rlen = 0;
    vw_err_t err = ipc_rpc(conn, VW_IPC_ACCOUNT_2FA_SET_REQ, req, off,
                             VW_IPC_ACCOUNT_2FA_SET_ACK, resp, sizeof(resp), &rlen);
    if (err != VW_OK) { fprintf(stderr, "account 2fa: IPC error %d\n", (int)err); return 1; }
    if (check_u32_resp(resp, rlen, "account 2fa")) return 1;

    printf("2fa: %s\n", (rlen >= 5u && resp[4]) ? "on" : "off");
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
        "              [--fallback-host <host>] [--fallback-port <port>]\n"
        "              [--fallback-ca-cert <path>]\n"
        "                                Add (or re-authenticate) an account. label\n"
        "                                defaults to <username>. Adding a second\n"
        "                                account against a different server is the\n"
        "                                normal way to use two unrelated self-hosted\n"
        "                                networks (e.g. family + friends) from one\n"
        "                                client — just give it a different host.\n"
        "                                --fallback-host/--fallback-port (TASK-173)\n"
        "                                configure an optional read-only replica the\n"
        "                                daemon automatically connects to if the\n"
        "                                primary becomes unreachable; both required\n"
        "                                together, --fallback-ca-cert optional.\n"
        "  account list                  List configured accounts (id, label,\n"
        "                                username, server, connection state:\n"
        "                                primary / fallback (read-only) / offline)\n"
        "  account remove <label-or-id>  Log out and forget an account (local\n"
        "                                cache deleted; already-synced files on\n"
        "                                disk are untouched)\n"
        "  account email                 Show the current account's email address\n"
        "                                (use --account to pick which one)\n"
        "  account email set <address>   Set (or change) the current account's\n"
        "                                email address — required for password\n"
        "                                recovery and email alerts (see \"notify\")\n"
        "  account 2fa                   Show whether 2FA is currently on\n"
        "  account 2fa on|off <password|-|--stdin-password>\n"
        "                                Enable/disable email-OTP two-factor login\n"
        "                                (requires your current password; \"on\"\n"
        "                                requires an account email already set)\n"
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
        "  set-folder-rules <local> [--exclude <glob> ...]\n"
        "                                Replace a folder's selective-sync\n"
        "                                exclude rules (no flags = clear all)\n"
        "  ls [<virtual_path>]           List synced files\n"
        "  conflicts                     List conflicted files only\n"
        "  share <path> <user> <view|edit> [expires_unix]\n"
        "                                Grant a user access to a file/folder\n"
        "  unshare <share_id>            Revoke a user-to-user grant\n"
        "  list-shares [--to-me]         List grants (created by me, or to me)\n"
        "  create-link <path> <view|edit> [expires_unix] [--password <pw>]\n"
        "                                Mint a public link; token shown once\n"
        "  revoke-link <share_id>        Revoke a public link\n"
        "  list-links                    List public links I've created\n"
        "  version list <path>           List all versions of a file\n"
        "  version restore <path> <version_id>\n"
        "                                Restore an older version as HEAD\n"
        "  version list --file-id <id>  List versions of a file shared with you\n"
        "                                (get <id> from list-shares — you have no\n"
        "                                path for content you don't own)\n"
        "  version restore --file-id <id> <version_id>\n"
        "                                Restore an older version of a shared file\n"
        "                                (requires an EDIT grant, not just VIEW)\n"
        "  search <query>                Search filenames across everything visible\n"
        "                                (owned + shared); case-insensitive substring\n"
        "  notify list                   Show your email notification preferences\n"
        "  notify set <category> on|off  Toggle one notification category\n"
        "  shutdown                      Ask the daemon to stop\n"
        "\n"
        "Options:\n"
        "  --ipc-port <port>          Override IPC port (default: %u)\n"
        "  --account <label-or-id>    Account to use for an account-scoped command\n"
        "  --version                  Print version and exit\n"
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
        } else if (strcmp(argv[argi], "--version") == 0) {
            printf("vapourwault-cli %s\n", VW_VERSION_STRING);
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

    if (strcmp(cmd, "set-folder-rules") == 0) {
        HELP_IF_REQUESTED();
        if (argi >= argc) {
            fprintf(stderr, "Usage: %s set-folder-rules <local_root> [--exclude <glob> ...]\n"
                            "  Replaces the whole rule set for this folder — pass no\n"
                            "  --exclude flags to clear all existing rules.\n", argv[0]);
            return 1;
        }
        const char *local_root = argv[argi++];
        const char *patterns[64];
        uint16_t npatterns = 0;
        while (argi < argc) {
            if (strcmp(argv[argi], "--exclude") == 0 && argi + 1 < argc) {
                if (npatterns >= 64) {
                    fprintf(stderr, "set-folder-rules: too many --exclude flags (max 64)\n");
                    return 1;
                }
                patterns[npatterns++] = argv[argi + 1];
                argi += 2;
            } else {
                fprintf(stderr, "set-folder-rules: unexpected argument '%s'\n", argv[argi]);
                return 1;
            }
        }
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_set_folder_excludes(c, account_id, local_root, patterns, npatterns);
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
                    "  [--fallback-host <host>] [--fallback-port <port>] "
                    "[--fallback-ca-cert <path>]\n"
                    "  Pass '-' or '--stdin-password' to read the password from stdin.\n"
                    "  --fallback-host and --fallback-port must be given together\n"
                    "  (--fallback-ca-cert is optional, like --ca-cert for the primary).\n"
                    "  Omit all fallback flags on a re-authentication to leave an\n"
                    "  already-configured fallback untouched.\n",
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
            const char *fb_host  = NULL;
            const char *fb_port_str = NULL;
            const char *fb_ca    = NULL;

            /* otp is the next bare token, if any, before the --flags start. */
            if (argi < argc && strncmp(argv[argi], "--", 2) != 0) {
                otp = argv[argi++];
            }
            while (argi < argc) {
                if (strcmp(argv[argi], "--label") == 0 && argi + 1 < argc) {
                    label = argv[argi + 1]; argi += 2;
                } else if (strcmp(argv[argi], "--ca-cert") == 0 && argi + 1 < argc) {
                    ca_cert = argv[argi + 1]; argi += 2;
                } else if (strcmp(argv[argi], "--fallback-host") == 0 && argi + 1 < argc) {
                    fb_host = argv[argi + 1]; argi += 2;
                } else if (strcmp(argv[argi], "--fallback-port") == 0 && argi + 1 < argc) {
                    fb_port_str = argv[argi + 1]; argi += 2;
                } else if (strcmp(argv[argi], "--fallback-ca-cert") == 0 && argi + 1 < argc) {
                    fb_ca = argv[argi + 1]; argi += 2;
                } else {
                    fprintf(stderr, "error: unrecognized argument: %s\n", argv[argi]);
                    return 1;
                }
            }
            /* TASK-174: --fallback-host and --fallback-port must be given
             * together — a partial set is a user error, never silently
             * treated as "no fallback" (this task's own acceptance
             * criterion). --fallback-ca-cert on its own without the other
             * two is equally nonsensical and rejected the same way. */
            if ((fb_host != NULL) != (fb_port_str != NULL) ||
                (fb_ca != NULL && fb_host == NULL)) {
                fprintf(stderr,
                    "error: --fallback-host and --fallback-port must be given "
                    "together (--fallback-ca-cert requires both too)\n");
                return 1;
            }
            uint16_t fb_port = fb_port_str ? (uint16_t)strtoul(fb_port_str, NULL, 10) : 0;

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
            int rc = cmd_account_add(c, host, port, ca_cert, label, username, pw, otp,
                                      fb_host, fb_port, fb_ca);
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

        if (strcmp(subcmd, "email") == 0) {
            uint32_t account_id = 0;
            if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;

            if (argi >= argc) {
                vw_ipc_conn_t *c = cli_connect(ipc_port);
                if (!c) return 1;
                int rc = cmd_account_email_get(c, account_id);
                vw_ipc_conn_close(c);
                return rc;
            }
            if (strcmp(argv[argi], "set") == 0) {
                argi++;
                if (argi >= argc) {
                    fprintf(stderr, "Usage: %s account email set <address>\n", argv[0]);
                    return 1;
                }
                const char *address = argv[argi++];
                vw_ipc_conn_t *c = cli_connect(ipc_port);
                if (!c) return 1;
                int rc = cmd_account_email_set(c, account_id, address);
                vw_ipc_conn_close(c);
                return rc;
            }
            fprintf(stderr, "Usage: %s account email | account email set <address>\n", argv[0]);
            return 1;
        }

        if (strcmp(subcmd, "2fa") == 0) {
            uint32_t status_account_id = 0;
            if (argi >= argc) {
                if (resolve_account_id(ipc_port, account_arg, &status_account_id)) return 1;
                vw_ipc_conn_t *c = cli_connect(ipc_port);
                if (!c) return 1;
                int rc = cmd_account_2fa_get(c, status_account_id);
                vw_ipc_conn_close(c);
                return rc;
            }
            if (argi + 1 >= argc) {
                fprintf(stderr,
                    "Usage: %s account 2fa | account 2fa on|off <password|-|--stdin-password>\n"
                    "  Requires your current password — same bar a real password\n"
                    "  change should have. 'on' requires an account email to already\n"
                    "  be set (account email set <address>) — 2FA codes are emailed,\n"
                    "  so enabling it without one would lock you out of every future\n"
                    "  login.\n",
                    argv[0]);
                return 1;
            }
            int enable;
            if      (strcmp(argv[argi], "on")  == 0) enable = 1;
            else if (strcmp(argv[argi], "off") == 0) enable = 0;
            else { fprintf(stderr, "account 2fa: expected 'on' or 'off', got '%s'\n", argv[argi]); return 1; }
            argi++;
            const char *pw_arg = argv[argi++];

            static char stdin_pw[256];
            const char *pw;
            if (strcmp(pw_arg, "-") == 0 || strcmp(pw_arg, "--stdin-password") == 0) {
                if (!fgets(stdin_pw, (int)sizeof(stdin_pw), stdin)) {
                    fprintf(stderr, "error: failed to read password from stdin\n");
                    return 1;
                }
                size_t slen = strlen(stdin_pw);
                if (slen > 0 && stdin_pw[slen - 1] == '\n') stdin_pw[--slen] = '\0';
                pw = stdin_pw;
            } else {
                pw = pw_arg;
            }

            uint32_t account_id = 0;
            if (resolve_account_id(ipc_port, account_arg, &account_id)) {
                memset(stdin_pw, 0, sizeof(stdin_pw));
                return 1;
            }
            vw_ipc_conn_t *c = cli_connect(ipc_port);
            if (!c) { memset(stdin_pw, 0, sizeof(stdin_pw)); return 1; }
            int rc = cmd_account_2fa_set(c, account_id, pw, enable);
            vw_ipc_conn_close(c);
            memset(stdin_pw, 0, sizeof(stdin_pw));
            return rc;
        }

        fprintf(stderr, "error: unknown account subcommand '%s' (expected add|list|remove|email|2fa)\n", subcmd);
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
            fprintf(stderr, "Usage: %s create-link <path> <view|edit> [expires_unix] [--password <pw>]\n", argv[0]);
            return 1;
        }
        const char *path = argv[argi++];
        uint8_t permission;
        if (parse_permission(argv[argi++], &permission)) return 1;
        int64_t expires_at = 0;
        const char *password = NULL;
        while (argi < argc) {
            if (strcmp(argv[argi], "--password") == 0 && argi + 1 < argc) {
                password = argv[argi + 1]; argi += 2;
            } else {
                expires_at = (int64_t)strtoll(argv[argi++], NULL, 10);
            }
        }
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_create_link(c, account_id, path, permission, expires_at, password);
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

    if (strcmp(cmd, "search") == 0) {
        HELP_IF_REQUESTED();
        if (argi >= argc) {
            fprintf(stderr, "Usage: %s search <query>\n", argv[0]);
            return 1;
        }
        const char *query = argv[argi++];
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_search(c, account_id, query);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "notify") == 0) {
        HELP_IF_REQUESTED();
        if (argi >= argc) {
            fprintf(stderr, "Usage: %s notify list | notify set <category> on|off\n", argv[0]);
            return 1;
        }
        const char *subcmd = argv[argi++];
        uint32_t account_id = 0;
        if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;

        if (strcmp(subcmd, "list") == 0) {
            vw_ipc_conn_t *c = cli_connect(ipc_port);
            if (!c) return 1;
            int rc = cmd_notify_list(c, account_id);
            vw_ipc_conn_close(c);
            return rc;
        }
        if (strcmp(subcmd, "set") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "Usage: %s notify set <category> on|off\n", argv[0]);
                return 1;
            }
            const char *category = argv[argi++];
            const char *on_off   = argv[argi++];
            return cmd_notify_set(ipc_port, account_id, category, on_off);
        }
        fprintf(stderr, "Usage: %s notify list | notify set <category> on|off\n", argv[0]);
        return 1;
    }

    if (strcmp(cmd, "version") == 0) {
        HELP_IF_REQUESTED();
        if (argi >= argc) {
            fprintf(stderr, "Usage: %s version list <path>|--file-id <id> | "
                            "version restore <path>|--file-id <id> <version_id>\n", argv[0]);
            return 1;
        }
        const char *subcmd = argv[argi++];

        if (strcmp(subcmd, "list") == 0) {
            if (argi >= argc) {
                fprintf(stderr, "Usage: %s version list <path>|--file-id <id>\n", argv[0]);
                return 1;
            }
            uint32_t account_id = 0;
            if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
            vw_ipc_conn_t *c = cli_connect(ipc_port);
            if (!c) return 1;
            int rc;
            /* --file-id (TASK-223): for a file shared with this account,
             * which has no owner-namespaced path to give the path-based
             * form above — see "list-shares" for the file_id to pass. */
            if (strcmp(argv[argi], "--file-id") == 0) {
                if (argi + 1 >= argc) {
                    fprintf(stderr, "Usage: %s version list --file-id <id>\n", argv[0]);
                    vw_ipc_conn_close(c);
                    return 1;
                }
                uint64_t file_id = strtoull(argv[argi + 1], NULL, 10);
                rc = cmd_version_list_by_id(c, account_id, file_id);
            } else {
                rc = cmd_version_list(c, account_id, argv[argi]);
            }
            vw_ipc_conn_close(c);
            return rc;
        }

        if (strcmp(subcmd, "restore") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "Usage: %s version restore <path>|--file-id <id> <version_id>\n", argv[0]);
                return 1;
            }
            uint32_t account_id = 0;
            if (resolve_account_id(ipc_port, account_arg, &account_id)) return 1;
            vw_ipc_conn_t *c = cli_connect(ipc_port);
            if (!c) return 1;
            int rc;
            if (strcmp(argv[argi], "--file-id") == 0) {
                if (argi + 2 >= argc) {
                    fprintf(stderr, "Usage: %s version restore --file-id <id> <version_id>\n", argv[0]);
                    vw_ipc_conn_close(c);
                    return 1;
                }
                /* file_id itself is unused here (VERSION_RESTORE resolves
                 * entirely by version_id server-side — see TASK-214,
                 * docs/PROTOCOL.md §7.3 rev 25); required on the command
                 * line anyway so `version restore --file-id <id> <vid>`
                 * mirrors `version list --file-id <id>` symmetrically and
                 * a caller doesn't need to know that asymmetry exists. */
                uint64_t version_id = strtoull(argv[argi + 2], NULL, 10);
                rc = cmd_version_restore_by_id(c, account_id, version_id);
            } else {
                uint64_t version_id = strtoull(argv[argi + 1], NULL, 10);
                rc = cmd_version_restore(c, account_id, argv[argi], version_id);
            }
            vw_ipc_conn_close(c);
            return rc;
        }

        fprintf(stderr, "error: unknown version subcommand '%s' (expected list|restore)\n", subcmd);
        return 1;
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
