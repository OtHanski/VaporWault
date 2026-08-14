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
    uint64_t    vault_id     = 0; /* TASK-158: 0 = unencrypted or unknown */
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

/* Vault / E2EE (TASK-100; library: TASK-099, docs/PROTOCOL.md §7.11).
 * Mirrors VW_IPC_VAULT_LIST_RESP's per-entry fields exactly. */
struct VwGuiVaultEntry {
    uint64_t vault_id = 0;
    uint64_t folder_file_id = 0;
    int64_t  created_at = 0;
};

/* Multi-account (TASK-161/163). Mirrors VW_IPC_ACCOUNT_LIST_RESP's
 * per-entry fields exactly, same shape vapourwault-cli's `account list`
 * decodes (vw_client_cli.c's account_list_entry_t). */
struct VwGuiAccountEntry {
    uint32_t    account_id = 0;
    std::string label;
    std::string username;
    std::string server_host;
    uint8_t     connected = 0;
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

    /* Simple fire-and-forget requests that return an error_code response.
     * send_pause/send_resume are account-scoped (TASK-161); send_sync_now/
     * send_shutdown act on the whole daemon (every configured account). */
    bool send_sync_now();
    bool send_pause(uint32_t account_id, const char *folder_root);   /* nullptr = all folders */
    bool send_resume(uint32_t account_id, const char *folder_root);
    bool send_shutdown();

    /* Send FOLDER_ADD_REQ; returns vw_err_t encoded as int. Account-scoped
     * (TASK-161) — same wire payload vapourwault-cli's add-folder sends. */
    int send_folder_add(uint32_t account_id, const char *local_root, const char *virtual_root);

    /* Send FOLDER_REMOVE_REQ. Account-scoped (TASK-161). */
    int send_folder_remove(uint32_t account_id, const char *local_root);

    /*
     * Multi-account (TASK-161/163).
     */
    /* List configured accounts. Returns true on success (out is cleared
     * and repopulated); false on IPC failure (out is left unchanged). */
    bool account_list(std::vector<VwGuiAccountEntry> *out);

    /*
     * Add a new account (account_id_hint == 0) or re-authenticate an
     * existing one (account_id_hint != 0) — same ACCOUNT_ADD_REQ semantics
     * as vapourwault-cli's `account add` (vw_client_cli.c's
     * cmd_account_add). label may be nullptr/empty (defaults to username,
     * decided daemon-side). password is zeroed by this call before
     * returning, regardless of outcome — same raw-password-handling
     * convention as the old login(). otp may be nullptr/empty on the
     * first attempt; returns VW_ERR_AUTH_2FA_REQUIRED (encoded as int) if
     * the account needs one. *out_account_id is only meaningful on success
     * (0 return).
     */
    int account_add(uint32_t account_id_hint, const char *label,
                     const char *server_host, uint16_t server_port, const char *ca_cert_path,
                     const char *username, char *password, const char *otp,
                     uint32_t *out_account_id);

    /* Log out and forget an account (ACCOUNT_REMOVE_REQ). Already-synced
     * local files are untouched — see vw_ipc.h's own payload doc. */
    int account_remove(uint32_t account_id);

    /*
     * List synced-cache entries under virtual path prefix (TASK-108) —
     * same VW_IPC_FILE_LIST_REQ/_RESP exchange vapourwault-cli's `ls` uses.
     * Account-scoped (TASK-161). Returns true on success (out is cleared
     * and repopulated); false on IPC failure (out is left unchanged).
     */
    bool file_list(uint32_t account_id, const char *prefix, std::vector<VwGuiFileEntry> *out);

    /*
     * Sharing (TASK-096). All take a virtual_path — the daemon resolves it
     * to a file_id via vw_client_file_stat before calling through (same
     * as vapourwault-cli's share/create-link commands). Account-scoped
     * (TASK-161). Return an int error_code (0 = VW_OK) unless noted.
     */
    int share_grant(uint32_t account_id, const char *virtual_path, const char *target_username,
                     uint8_t permission, int64_t expires_at, uint64_t *out_share_id);
    int share_revoke(uint32_t account_id, uint64_t share_id);
    bool share_list(uint32_t account_id, uint8_t mode, std::vector<VwGuiShareEntry> *out, int *out_error_code);

    /* out_token receives the raw 32-byte link token — meaningful only when
     * the return value is 0; never re-fetchable afterward (server never
     * re-discloses it), matching the CLI's own one-time-display handling. */
    int link_create(uint32_t account_id, const char *virtual_path, uint8_t permission, int64_t expires_at,
                     uint64_t *out_share_id, uint8_t out_token[32]);
    int link_revoke(uint32_t account_id, uint64_t share_id);
    bool link_list(uint32_t account_id, std::vector<VwGuiLinkEntry> *out, int *out_error_code);

    /*
     * Vault / E2EE (TASK-100). Create a real server-side directory — a
     * vault's folder_file_id must already be one (see docs/PROTOCOL.md
     * §7.2's FILE_STAT_RESP note). new_parent_dir_id == 0 means the
     * caller's own root. Account-scoped (TASK-161).
     */
    int file_mkdir(uint32_t account_id, uint64_t new_parent_dir_id, const char *name, uint64_t *out_dir_id);

    /*
     * Create a new vault under folder_file_id, deriving its KEK from
     * passphrase. passphrase is zeroed by this call before returning,
     * regardless of outcome — same convention as account_add(). On
     * success the new vault is unlocked in the daemon's registry
     * immediately (no separate vault_unlock() call needed right after).
     */
    int vault_create(uint32_t account_id, uint64_t folder_file_id, char *passphrase, uint64_t *out_vault_id);

    /*
     * Unlock an existing vault (new-device case). passphrase is zeroed
     * before returning. Returns VW_ERR_AUTH_BAD_CREDS (encoded as int) for
     * a wrong passphrase.
     */
    int vault_unlock(uint32_t account_id, uint64_t vault_id, char *passphrase);

    /* List vaults owned by the caller. Never includes key material. */
    bool vault_list(uint32_t account_id, std::vector<VwGuiVaultEntry> *out, int *out_error_code);

    /*
     * Encrypt local_path and upload it into vault_id (which must already
     * be unlocked — vault_create or vault_unlock first). file_id == 0
     * creates a new file named leaf_name inside the vault's folder;
     * file_id != 0 uploads a new version of that existing file (leaf_name
     * ignored). Returns VW_ERR_AUTH_REQUIRED (encoded as int) if vault_id
     * is not currently unlocked in the daemon.
     */
    int vault_upload(uint32_t account_id, uint64_t vault_id, uint64_t file_id,
                      const char *leaf_name, const char *local_path,
                      uint64_t *out_file_id, uint64_t *out_version_id);

    /* Download and decrypt file_id's current version to local_path. */
    int vault_download(uint32_t account_id, uint64_t vault_id, uint64_t file_id, const char *local_path);

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
