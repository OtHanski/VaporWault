#pragma once

/*
 * ClientApp — top-level application state for the VaporWault client GUI.
 *
 * Owns the IPC connection and view dispatch. A background thread polls the
 * daemon status every 2 seconds. All shared state is guarded by status_mutex_.
 * The render thread may read cached_status_ without a lock only for display;
 * it must hold the lock to call any VwGuiIpc method.
 */

#include "vw_gui_ipc.h"
#include <SDL.h>
#include <mutex>
#include <atomic>
#include <cstdint>

enum class AppView { Login, Browser, Shared, Vault, Queue, Settings };

class ClientApp {
public:
    ClientApp();
    ~ClientApp();

    ClientApp(const ClientApp &) = delete;
    ClientApp &operator=(const ClientApp &) = delete;

    /* Call once after SDL/ImGui are initialised. Starts the background thread. */
    void start();

    /* Call once per frame — renders the active view. */
    void render_frame();

    /* Call before ImGui/SDL shutdown. Stops the background thread. */
    void stop();

    AppView active_view() const { return active_view_; }

    /* Snapshot of the last status received from the daemon (background-thread updated). */
    VwIpcStatus status_snapshot() {
        std::lock_guard<std::mutex> lk(status_mutex_);
        return cached_status_;
    }

    /*
     * Multi-account (TASK-161/163). Every other ipc_* method below is
     * implicitly scoped to active_account_id() internally — it is NOT
     * threaded through each method's own signature as an extra parameter,
     * because "only the active account is ever displayed" (this class's
     * whole design) means no view ever needs to address a *different*
     * account than whichever one is active; adding a parameter every call
     * site would have to pass identically everywhere would be pure
     * boilerplate with a real chance of one call site quietly using a
     * stale id. Background sync for every account regardless of which is
     * active remains entirely the daemon's concern (TASK-161's round-robin
     * loop) — this active-account notion is purely a GUI display/action
     * scope, not a daemon-visible concept.
     */
    uint32_t active_account_id() {
        std::lock_guard<std::mutex> lk(status_mutex_);
        return active_account_id_;
    }
    void set_active_account(uint32_t account_id) {
        std::lock_guard<std::mutex> lk(status_mutex_);
        active_account_id_ = account_id;
    }

    /* Render-thread-only: set the active account AND force every open
     * view (browser/shared/vault) to refetch for it. Unlike
     * set_active_account() above (also used by the background poll
     * thread's zero-config auto-select, where no view has fetched
     * anything yet so no invalidation is needed), this one reaches into
     * per-view static state that is only safe to touch from the render
     * thread — call this, not set_active_account(), from any UI code
     * (the switcher, "add account") that runs on the render thread. */
    void switch_active_account(uint32_t account_id);

    /* Snapshot of the accounts list, refreshed by the background poll
     * thread every ~2s (same cadence as cached_status_) — the switcher UI
     * reads this instead of issuing its own IPC call every frame. */
    std::vector<VwGuiAccountEntry> cached_accounts() {
        std::lock_guard<std::mutex> lk(status_mutex_);
        return cached_accounts_;
    }

    bool ipc_account_list(std::vector<VwGuiAccountEntry> *out);
    int  ipc_account_add(uint32_t account_id_hint, const char *label,
                          const char *server_host, uint16_t server_port, const char *ca_cert_path,
                          const char *username, char *password, const char *otp,
                          uint32_t *out_account_id);
    int  ipc_account_remove(uint32_t account_id);

    /* Called by views to request an IPC operation on the render thread.
     * The caller must NOT hold status_mutex_. Account-scoped ones
     * (everything except sync_now/shutdown, which act on the whole
     * daemon) implicitly use active_account_id() — see the note above. */
    bool ipc_sync_now();
    bool ipc_pause(const char *folder_root = nullptr);
    bool ipc_resume(const char *folder_root = nullptr);
    bool ipc_shutdown();
    int  ipc_folder_add(const char *local, const char *virt);
    int  ipc_folder_remove(const char *local);
    bool ipc_file_list(const char *prefix, std::vector<VwGuiFileEntry> *out);

    int  ipc_share_grant(const char *virtual_path, const char *target_username,
                          uint8_t permission, int64_t expires_at, uint64_t *out_share_id);
    int  ipc_share_revoke(uint64_t share_id);
    bool ipc_share_list(uint8_t mode, std::vector<VwGuiShareEntry> *out, int *out_error_code);
    int  ipc_link_create(const char *virtual_path, uint8_t permission, int64_t expires_at,
                          uint64_t *out_share_id, uint8_t out_token[32]);
    int  ipc_link_revoke(uint64_t share_id);
    bool ipc_link_list(std::vector<VwGuiLinkEntry> *out, int *out_error_code);

    int  ipc_file_mkdir(uint64_t new_parent_dir_id, const char *name, uint64_t *out_dir_id);
    int  ipc_vault_create(uint64_t folder_file_id, char *passphrase, uint64_t *out_vault_id);
    int  ipc_vault_unlock(uint64_t vault_id, char *passphrase);
    bool ipc_vault_list(std::vector<VwGuiVaultEntry> *out, int *out_error_code);
    int  ipc_vault_upload(uint64_t vault_id, uint64_t file_id,
                           const char *leaf_name, const char *local_path,
                           uint64_t *out_file_id, uint64_t *out_version_id);
    int  ipc_vault_download(uint64_t vault_id, uint64_t file_id, const char *local_path);

    uint16_t ipc_port = VW_IPC_DEFAULT_PORT;

private:
    VwGuiIpc    ipc_;
    AppView     active_view_ = AppView::Login;

    std::mutex      status_mutex_;
    VwIpcStatus     cached_status_;
    std::vector<VwGuiAccountEntry> cached_accounts_;
    std::atomic_bool poll_running_{false};
    SDL_Thread     *poll_thread_ = nullptr;

    /* 0 = no account selected yet (also account_registry_t's reserved
     * "create new" sentinel daemon-side — vw_daemon.c — so never a real
     * account_id). Guarded by status_mutex_ like every other field here;
     * methods that already hold the lock must read/write this member
     * directly, never through the public active_account_id()/
     * set_active_account() accessors (which lock themselves — not
     * reentrant). Auto-selected in poll_loop() when exactly one account
     * is configured and none is active yet. */
    uint32_t active_account_id_ = 0;

    /* Seconds until the next reconnect attempt. */
    float reconnect_timer_ = 0.0f;

    static int poll_thread_func(void *self);
    void poll_loop();
    void try_connect();
    void render_offline_banner();
    void render_account_switcher();
};
