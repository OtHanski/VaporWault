#include "ClientApp.h"
#include "views/vw_view_login.h"
#include "views/vw_view_browser.h"
#include "views/vw_view_shared.h"
#include "views/vw_view_vault.h"
#include "views/vw_view_queue.h"
#include "views/vw_view_settings.h"
#include "imgui.h"
#include <SDL.h>

ClientApp::ClientApp() = default;
ClientApp::~ClientApp() { stop(); }

void ClientApp::start() {
    try_connect();
    poll_running_ = true;
    poll_thread_ = SDL_CreateThread(poll_thread_func, "vw_ipc_poll", this);
}

void ClientApp::stop() {
    poll_running_ = false;
    if (poll_thread_) { SDL_WaitThread(poll_thread_, nullptr); poll_thread_ = nullptr; }
    std::lock_guard<std::mutex> lk(status_mutex_);
    ipc_.disconnect();
}

void ClientApp::try_connect() {
    std::lock_guard<std::mutex> lk(status_mutex_);
    ipc_.connect(ipc_port);
}

int ClientApp::poll_thread_func(void *self) {
    static_cast<ClientApp *>(self)->poll_loop();
    return 0;
}

void ClientApp::poll_loop() {
    while (poll_running_) {
        {
            std::lock_guard<std::mutex> lk(status_mutex_);
            if (!ipc_.is_connected()) {
                ipc_.connect(ipc_port);
            }
            if (ipc_.is_connected()) {
                ipc_.fetch_status(&cached_status_);

                /* Refresh the switcher's account list every tick (cheap,
                 * bounded IPC call — same cadence as the status poll
                 * above), and auto-select the sole configured account,
                 * exactly like vapourwault-cli's resolve_account_id() does
                 * for its own zero-config single-account case — a user
                 * with only one account should never have to touch the
                 * switcher. Auto-select never overrides a selection the
                 * user (or a just-completed "add account") already made —
                 * including a deliberate "no account" state after the
                 * last one was removed — since it only fires while
                 * active_account_id_ is still the sentinel. */
                std::vector<VwGuiAccountEntry> accts;
                if (ipc_.account_list(&accts)) {
                    cached_accounts_ = std::move(accts);
                    if (active_account_id_ == 0 && cached_accounts_.size() == 1)
                        active_account_id_ = cached_accounts_[0].account_id;
                }
            }
        }
        /* Poll every 2 seconds. Sleep in 100 ms slices to stay responsive to stop(). */
        for (int i = 0; i < 20 && poll_running_; i++)
            SDL_Delay(100);
    }
}

void ClientApp::render_frame() {
    VwIpcStatus snap = status_snapshot();
    bool connected_to_daemon;
    { std::lock_guard<std::mutex> lk(status_mutex_); connected_to_daemon = ipc_.is_connected(); }

    if (!connected_to_daemon) {
        render_offline_banner();
        vw_view_login_render(snap, *this);
        return;
    }

    /* Navigation menu bar */
    if (ImGui::BeginMainMenuBar()) {
        render_account_switcher();
        ImGui::Separator();
        if (ImGui::MenuItem("Files",    nullptr, active_view_ == AppView::Browser))
            active_view_ = AppView::Browser;
        if (ImGui::MenuItem("Shared",   nullptr, active_view_ == AppView::Shared))
            active_view_ = AppView::Shared;
        if (ImGui::MenuItem("Vault",    nullptr, active_view_ == AppView::Vault))
            active_view_ = AppView::Vault;
        if (ImGui::MenuItem("Queue",    nullptr, active_view_ == AppView::Queue))
            active_view_ = AppView::Queue;
        if (ImGui::MenuItem("Settings", nullptr, active_view_ == AppView::Settings))
            active_view_ = AppView::Settings;
        ImGui::EndMainMenuBar();
    }

    if (!snap.connected) {
        /* Daemon is running but not connected to server */
        active_view_ = AppView::Login;
        vw_view_login_render(snap, *this);
        return;
    }

    switch (active_view_) {
    case AppView::Browser:  vw_view_browser_render(snap, *this);  break;
    case AppView::Shared:   vw_view_shared_render(snap, *this);   break;
    case AppView::Vault:    vw_view_vault_render(snap, *this);    break;
    case AppView::Queue:    vw_view_queue_render(snap, *this);    break;
    case AppView::Settings: vw_view_settings_render(snap, *this); break;
    case AppView::Login:    vw_view_login_render(snap, *this);    break;
    default:
        active_view_ = AppView::Browser;
        vw_view_browser_render(snap, *this);
        break;
    }
}

void ClientApp::render_offline_banner() {
    ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, 28));
    ImGui::SetNextWindowBgAlpha(0.85f);
    ImGui::Begin("##offline_banner", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoInputs |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);
    ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f),
        "Daemon offline — retrying every 2 s");
    ImGui::End();
}

/* Multi-account (TASK-163): tab/dropdown near the top of the main window,
 * per the task's own UI requirement. A no-op-looking single entry for the
 * common single-account case (acceptance criteria: "no behavior change
 * for a single-account setup"), but still lets that one account be
 * removed or a second one added. */
void ClientApp::render_account_switcher() {
    std::vector<VwGuiAccountEntry> accounts = cached_accounts();
    uint32_t active_id = active_account_id();

    std::string current_label = "(no account)";
    for (auto &a : accounts) {
        if (a.account_id == active_id) {
            current_label = a.label.empty() ? a.username : a.label;
            break;
        }
    }

    if (ImGui::BeginMenu(current_label.c_str())) {
        for (auto &a : accounts) {
            bool selected = (a.account_id == active_id);
            std::string item = a.label.empty() ? a.username : a.label;
            if (!a.connected) item += "  [offline]";
            if (ImGui::MenuItem(item.c_str(), nullptr, selected) && !selected)
                switch_active_account(a.account_id);
        }
        if (!accounts.empty()) ImGui::Separator();
        if (ImGui::MenuItem("+ Add account..."))
            active_view_ = AppView::Login;
        if (active_id != 0 && ImGui::MenuItem("Remove current account..."))
            ImGui::OpenPopup("Remove account?##confirm");
        ImGui::EndMenu();
    }

    if (ImGui::BeginPopupModal("Remove account?##confirm", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Remove this account? Already-synced local files are kept;\n"
                    "the account's own cache/session are deleted from the daemon.");
        if (ImGui::Button("Remove")) {
            ipc_account_remove(active_id);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel"))
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

/* ── IPC passthrough (render thread, no lock held by caller) ──────────────── */

bool ClientApp::ipc_sync_now() {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.send_sync_now();
}
bool ClientApp::ipc_pause(const char *folder) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.send_pause(active_account_id_, folder);
}
bool ClientApp::ipc_resume(const char *folder) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.send_resume(active_account_id_, folder);
}
bool ClientApp::ipc_shutdown() {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.send_shutdown();
}

void ClientApp::switch_active_account(uint32_t account_id) {
    set_active_account(account_id);
    vw_view_browser_invalidate();
    vw_view_shared_invalidate();
    vw_view_vault_invalidate();
}

bool ClientApp::ipc_account_list(std::vector<VwGuiAccountEntry> *out) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.account_list(out);
}
int ClientApp::ipc_account_add(uint32_t account_id_hint, const char *label,
                                const char *server_host, uint16_t server_port, const char *ca_cert_path,
                                const char *username, char *password, const char *otp,
                                uint32_t *out_account_id) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.account_add(account_id_hint, label, server_host, server_port, ca_cert_path,
                             username, password, otp, out_account_id);
}
int ClientApp::ipc_account_remove(uint32_t account_id) {
    bool need_invalidate = false;
    int rc;
    {
        std::lock_guard<std::mutex> lk(status_mutex_);
        rc = ipc_.account_remove(account_id);
        /* If the removed account was active, clear the selection — the
         * next poll_loop() tick auto-selects again if exactly one account
         * remains, or the switcher/login view shows "no account" if none
         * do. Invalidation itself must happen AFTER the lock above is
         * released (see switch_active_account()'s doc comment: it's
         * render-thread-only, unguarded static view state), which is also
         * why this doesn't just call switch_active_account(0) here. */
        if (rc == 0 && active_account_id_ == account_id) {
            active_account_id_ = 0;
            need_invalidate = true;
        }
    }
    if (need_invalidate) {
        vw_view_browser_invalidate();
        vw_view_shared_invalidate();
        vw_view_vault_invalidate();
    }
    return rc;
}

int ClientApp::ipc_folder_add(const char *local, const char *virt) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.send_folder_add(active_account_id_, local, virt);
}
int ClientApp::ipc_folder_remove(const char *local) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.send_folder_remove(active_account_id_, local);
}
bool ClientApp::ipc_file_list(const char *prefix, std::vector<VwGuiFileEntry> *out) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.file_list(active_account_id_, prefix, out);
}
int ClientApp::ipc_share_grant(const char *virtual_path, const char *target_username,
                                uint8_t permission, int64_t expires_at, uint64_t *out_share_id) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.share_grant(active_account_id_, virtual_path, target_username, permission, expires_at, out_share_id);
}
int ClientApp::ipc_share_revoke(uint64_t share_id) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.share_revoke(active_account_id_, share_id);
}
bool ClientApp::ipc_share_list(uint8_t mode, std::vector<VwGuiShareEntry> *out, int *out_error_code) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.share_list(active_account_id_, mode, out, out_error_code);
}
int ClientApp::ipc_link_create(const char *virtual_path, uint8_t permission, int64_t expires_at,
                                uint64_t *out_share_id, uint8_t out_token[32]) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.link_create(active_account_id_, virtual_path, permission, expires_at, out_share_id, out_token);
}
int ClientApp::ipc_link_revoke(uint64_t share_id) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.link_revoke(active_account_id_, share_id);
}
bool ClientApp::ipc_link_list(std::vector<VwGuiLinkEntry> *out, int *out_error_code) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.link_list(active_account_id_, out, out_error_code);
}

int ClientApp::ipc_file_mkdir(uint64_t new_parent_dir_id, const char *name, uint64_t *out_dir_id) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.file_mkdir(active_account_id_, new_parent_dir_id, name, out_dir_id);
}
int ClientApp::ipc_vault_create(uint64_t folder_file_id, char *passphrase, uint64_t *out_vault_id) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.vault_create(active_account_id_, folder_file_id, passphrase, out_vault_id);
}
int ClientApp::ipc_vault_unlock(uint64_t vault_id, char *passphrase) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.vault_unlock(active_account_id_, vault_id, passphrase);
}
bool ClientApp::ipc_vault_list(std::vector<VwGuiVaultEntry> *out, int *out_error_code) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.vault_list(active_account_id_, out, out_error_code);
}
int ClientApp::ipc_vault_upload(uint64_t vault_id, uint64_t file_id,
                                 const char *leaf_name, const char *local_path,
                                 uint64_t *out_file_id, uint64_t *out_version_id) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.vault_upload(active_account_id_, vault_id, file_id, leaf_name, local_path, out_file_id, out_version_id);
}
int ClientApp::ipc_vault_download(uint64_t vault_id, uint64_t file_id, const char *local_path) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.vault_download(active_account_id_, vault_id, file_id, local_path);
}
