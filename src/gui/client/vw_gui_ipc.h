#pragma once

/*
 * vw_gui_ipc — thin C++ wrapper around vw_ipc_conn_t for use in the render loop.
 *
 * Owned by ClientApp. All methods are called from the render thread; the
 * background poll thread holds the same mutex — callers must acquire it
 * before calling any method.
 *
 * TASK-108 finding: the daemon closes every IPC connection after handling
 * exactly one request (mirroring how vapourwault-cli opens a fresh
 * connection per subcommand — see handle_ipc_client's caller in
 * vw_daemon.c, which calls vw_ipc_conn_close() immediately after each
 * dispatch). This class used to hold one persistent connection reused
 * across calls, which "worked" for periodic status-only polling only by
 * accident: every other poll silently failed (send on an already-closed
 * socket), triggered disconnect(), and the following poll transparently
 * reconnected — invisible for a single repeated call, but broke outright
 * for any back-to-back sequence of different calls (e.g. login() then
 * file_list()). Every method below now opens its own short-lived
 * connection via one_shot() instead.
 */

#include "vw_ipc.h"
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

struct VwIpcStatus {
    uint8_t  connected        = 0;
    uint8_t  syncing          = 0;
    uint8_t  paused           = 0;
    int64_t  last_sync_at     = 0;
    uint32_t pending_uploads  = 0;
    uint32_t pending_downloads = 0;
    uint32_t error_count      = 0;
};

/* One VW_IPC_FILE_LIST_RESP entry (TASK-108) — mirrors vw_cache_entry_t's
 * fields as exposed over that IPC message, same set vapourwault-cli's
 * `ls` command decodes. */
struct VwGuiFileEntry {
    std::string virtual_path;
    std::string local_path;
    uint32_t    sync_state  = 0;  /* vw_sync_state_t */
    uint8_t     entry_type  = 0;  /* 0 = file, 1 = dir (VW_ENTRY_FILE/_DIR) */
    int64_t     server_mtime = 0;
    int64_t     local_mtime  = 0;
    uint64_t    server_size  = 0;
    uint64_t    file_id      = 0; /* 0 = not yet uploaded */
};

/* Sharing (TASK-096; library: TASK-095, docs/PROTOCOL.md §7.5). Mirrors
 * VW_IPC_SHARE_LIST_RESP / VW_IPC_LINK_LIST_RESP per-entry fields exactly
 * (see vw_ipc.h's payload doc comments), field-for-field the same shape
 * vapourwault-cli's `list-shares`/`list-links` decode. */
struct VwGuiShareEntry {
    uint64_t    share_id = 0;
    uint64_t    file_id = 0;
    std::string name;             /* shared item's leaf name; display-only */
    uint8_t     share_type = 0;   /* 0 = user grant, 1 = public link */
    std::string target_username;  /* empty for links */
    uint8_t     permission = 0;   /* vw_perm_t */
    int64_t     created_at = 0;
    int64_t     expires_at = 0;   /* 0 = never */
    uint8_t     revoked = 0;
};

struct VwGuiLinkEntry {
    uint64_t    share_id = 0;
    uint64_t    file_id = 0;
    std::string name;
    uint8_t     permission = 0;
    int64_t     created_at = 0;
    int64_t     expires_at = 0;
    uint8_t     revoked = 0;
};

class VwGuiIpc {
public:
    VwGuiIpc() = default;
    ~VwGuiIpc() = default;

    VwGuiIpc(const VwGuiIpc &) = delete;
    VwGuiIpc &operator=(const VwGuiIpc &) = delete;

    /* Probe the daemon (one-shot connect + close) and remember port for
     * subsequent calls. Returns true if the daemon accepted the connection. */
    bool connect(uint16_t port = VW_IPC_DEFAULT_PORT);

    /* Clears the "reachable" flag; does not hold any socket to close. */
    void disconnect();

    bool is_connected() const { return connected_; }

    /* Send STATUS_REQ and decode STATUS_RESP into *out. Returns false on error. */
    bool fetch_status(VwIpcStatus *out);

    /* Simple fire-and-forget requests that return an error_code response. */
    bool send_sync_now();
    bool send_pause(const char *folder_root);   /* nullptr = all folders */
    bool send_resume(const char *folder_root);
    bool send_shutdown();

    /* Send FOLDER_ADD_REQ; returns vw_err_t encoded as int. */
    int send_folder_add(const char *local_root, const char *virtual_root);

    /* Send FOLDER_REMOVE_REQ. */
    int send_folder_remove(const char *local_root);

    /*
     * Authenticate with the server, via the daemon (TASK-107). password is
     * zeroed by this call before returning, regardless of outcome — same
     * raw-password-handling convention as vw_client_cli.c's cmd_login.
     * otp may be nullptr/empty on the first attempt; returns
     * VW_ERR_AUTH_2FA_REQUIRED (encoded as int) if the account needs one.
     */
    int login(char *password, const char *otp);

    /*
     * List synced-cache entries under virtual path prefix (TASK-108) —
     * same VW_IPC_FILE_LIST_REQ/_RESP exchange vapourwault-cli's `ls` uses.
     * Returns true on success (out is cleared and repopulated); false on
     * IPC failure (out is left unchanged).
     */
    bool file_list(const char *prefix, std::vector<VwGuiFileEntry> *out);

    /*
     * Sharing (TASK-096). All take a virtual_path — the daemon resolves it
     * to a file_id via vw_client_file_stat before calling through (same
     * as vapourwault-cli's share/create-link commands). Return an int
     * error_code (0 = VW_OK) unless noted.
     */
    int share_grant(const char *virtual_path, const char *target_username,
                     uint8_t permission, int64_t expires_at, uint64_t *out_share_id);
    int share_revoke(uint64_t share_id);
    bool share_list(uint8_t mode, std::vector<VwGuiShareEntry> *out, int *out_error_code);

    /* out_token receives the raw 32-byte link token — meaningful only when
     * the return value is 0; never re-fetchable afterward (server never
     * re-discloses it), matching the CLI's own one-time-display handling. */
    int link_create(const char *virtual_path, uint8_t permission, int64_t expires_at,
                     uint64_t *out_share_id, uint8_t out_token[32]);
    int link_revoke(uint64_t share_id);
    bool link_list(std::vector<VwGuiLinkEntry> *out, int *out_error_code);

private:
    uint16_t port_      = VW_IPC_DEFAULT_PORT;
    bool     connected_ = false;

    /*
     * Open a fresh connection to port_, send one request, read exactly one
     * response, then close — see the class comment for why this replaced
     * a persistent connection. Updates connected_ as a side effect.
     */
    vw_err_t one_shot(vw_ipc_msg_t req_type, const uint8_t *req, uint32_t req_len,
                       vw_ipc_msg_t expect_resp_type,
                       uint8_t *resp_buf, uint32_t resp_bufsz, uint32_t *out_resp_len);

    /* Send a request with an optional string payload and read a u32 error_code resp. */
    int simple_req_resp(vw_ipc_msg_t req_type, vw_ipc_msg_t resp_type,
                        const uint8_t *payload, uint32_t payload_len);
};
