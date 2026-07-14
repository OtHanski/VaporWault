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

/* ── Subcommand: status ───────────────────────────────────────────────────── */

/*
 * STATUS_RESP layout (24 bytes):
 *   u8  connected, u8 syncing, u8 paused, u8 _pad,
 *   i64 last_sync_at, u32 pending_uploads, u32 pending_downloads, u32 error_count
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

    char ts_buf[32];
    format_ts(last_sync, ts_buf, sizeof(ts_buf), 1);

    printf("VaporWault daemon status\n");
    printf("  Server:    %s\n", connected ? "connected" : "offline");
    printf("  Syncing:   %s\n", syncing   ? "yes" : "no");
    printf("  Paused:    %s\n", paused    ? "yes" : "no");
    printf("  Last sync: %s\n", ts_buf);
    printf("  Pending:   %u uploads, %u downloads, %u errors\n",
           uploads, downloads, errors);
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
static int cmd_pause(vw_ipc_conn_t *conn, const char *folder) {
    uint8_t payload[516];
    uint32_t off = 0;
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

static int cmd_resume(vw_ipc_conn_t *conn, const char *folder) {
    uint8_t payload[516];
    uint32_t off = 0;
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

/* FOLDER_ADD_REQ payload: string local_root, string virtual_root. */
static int cmd_add_folder(vw_ipc_conn_t *conn,
                            const char *local, const char *virt) {
    uint8_t payload[1040];
    uint32_t off = 0;
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

/* FOLDER_REMOVE_REQ payload: string local_root. */
static int cmd_remove_folder(vw_ipc_conn_t *conn, const char *local) {
    uint8_t payload[516];
    uint32_t off = 0;
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

/* ── Subcommand: ls / conflicts ──────────────────────────────────────────── */

/*
 * FILE_LIST_REQ payload: string virtual_prefix (empty = all), u8 filter.
 *
 * FILE_LIST_RESP layout per entry:
 *   string virtual_path, string local_path,
 *   u32 sync_state, u8 entry_type,
 *   i64 server_mtime, i64 local_mtime, u64 server_size
 */
static int cmd_ls(vw_ipc_conn_t *conn, const char *prefix, uint8_t filter) {
    uint8_t req[518];
    uint32_t off = 0;
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
        if (roff + 4u + 1u + 8u + 8u + 8u > rlen) break;

        uint32_t sync_state  = vw_read_u32le(resp + roff); roff += 4;
        uint8_t  entry_type  = resp[roff++];
        int64_t  server_mt   = (int64_t)vw_read_u64le(resp + roff); roff += 8;
        int64_t  local_mt    = (int64_t)vw_read_u64le(resp + roff); roff += 8;
        uint64_t server_size = vw_read_u64le(resp + roff);           roff += 8;

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

/* ── Usage ───────────────────────────────────────────────────────────────── */

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [--ipc-port <port>] <command> [args]\n"
        "\n"
        "Commands:\n"
        "  status                        Show daemon status\n"
        "  sync                          Trigger immediate sync\n"
        "  pause [<local_root>]          Pause sync (all or one folder)\n"
        "  resume [<local_root>]         Resume sync\n"
        "  add-folder <local> <virtual>  Add a sync folder\n"
        "  remove-folder <local>         Remove a sync folder\n"
        "  ls [<virtual_path>]           List synced files\n"
        "  conflicts                     List conflicted files only\n"
        "  shutdown                      Ask the daemon to stop\n"
        "\n"
        "Options:\n"
        "  --ipc-port <port>  Override IPC port (default: %u)\n"
        "  --help, -h         Show this help\n",
        prog, (unsigned)VW_IPC_DEFAULT_PORT);
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int vw_client_cli_main(int argc, char *argv[], uint16_t ipc_port) {
#ifdef _WIN32
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);
#endif

    int argi = 1;

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
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_pause(c, folder);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "resume") == 0) {
        HELP_IF_REQUESTED();
        const char *folder = (argi < argc) ? argv[argi++] : NULL;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_resume(c, folder);
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
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_add_folder(c, local, virt);
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
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_remove_folder(c, local);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "ls") == 0) {
        HELP_IF_REQUESTED();
        const char *prefix = (argi < argc) ? argv[argi++] : NULL;
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_ls(c, prefix, VW_IPC_FILTER_ALL);
        vw_ipc_conn_close(c);
        return rc;
    }

    if (strcmp(cmd, "conflicts") == 0) {
        HELP_IF_REQUESTED();
        vw_ipc_conn_t *c = cli_connect(ipc_port);
        if (!c) return 1;
        int rc = cmd_ls(c, NULL, (uint8_t)VW_SYNC_CONFLICT);
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
