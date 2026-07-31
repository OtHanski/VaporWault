#include "ClientApp.h"
#include "views/vw_view_login.h"
#include "views/vw_view_browser.h"
#include "views/vw_view_shared.h"
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
        if (ImGui::MenuItem("Files",    nullptr, active_view_ == AppView::Browser))
            active_view_ = AppView::Browser;
        if (ImGui::MenuItem("Shared",   nullptr, active_view_ == AppView::Shared))
            active_view_ = AppView::Shared;
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
    case AppView::Queue:    vw_view_queue_render(snap, *this);    break;
    case AppView::Settings: vw_view_settings_render(snap, *this); break;
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

/* ── IPC passthrough (render thread, no lock held by caller) ──────────────── */

bool ClientApp::ipc_sync_now() {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.send_sync_now();
}
bool ClientApp::ipc_pause(const char *folder) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.send_pause(folder);
}
bool ClientApp::ipc_resume(const char *folder) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.send_resume(folder);
}
bool ClientApp::ipc_shutdown() {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.send_shutdown();
}
int ClientApp::ipc_folder_add(const char *local, const char *virt) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.send_folder_add(local, virt);
}
int ClientApp::ipc_folder_remove(const char *local) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.send_folder_remove(local);
}
int ClientApp::ipc_login(char *password, const char *otp) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.login(password, otp);
}
bool ClientApp::ipc_file_list(const char *prefix, std::vector<VwGuiFileEntry> *out) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.file_list(prefix, out);
}
int ClientApp::ipc_share_grant(const char *virtual_path, const char *target_username,
                                uint8_t permission, int64_t expires_at, uint64_t *out_share_id) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.share_grant(virtual_path, target_username, permission, expires_at, out_share_id);
}
int ClientApp::ipc_share_revoke(uint64_t share_id) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.share_revoke(share_id);
}
bool ClientApp::ipc_share_list(uint8_t mode, std::vector<VwGuiShareEntry> *out, int *out_error_code) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.share_list(mode, out, out_error_code);
}
int ClientApp::ipc_link_create(const char *virtual_path, uint8_t permission, int64_t expires_at,
                                uint64_t *out_share_id, uint8_t out_token[32]) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.link_create(virtual_path, permission, expires_at, out_share_id, out_token);
}
int ClientApp::ipc_link_revoke(uint64_t share_id) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.link_revoke(share_id);
}
bool ClientApp::ipc_link_list(std::vector<VwGuiLinkEntry> *out, int *out_error_code) {
    std::lock_guard<std::mutex> lk(status_mutex_);
    return ipc_.link_list(out, out_error_code);
}
