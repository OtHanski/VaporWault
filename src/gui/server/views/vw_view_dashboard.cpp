#include "vw_view_dashboard.h"
#include "../ServerApp.h"
#include "imgui.h"
#include <cstring>
#include <cstdio>

void VwViewDashboard::on_connected(const char *host, uint16_t port,
                                    const char *username,
                                    const uint8_t session_token[32])
{
    snprintf(host_,     sizeof(host_),     "%s", host);
    snprintf(username_, sizeof(username_), "%s", username);
    port_ = port;
    memcpy(session_token_, session_token, 32);

    cluster_view_.on_connected();
    users_view_.on_connected();
    audit_view_.on_connected();
}

DashboardAction VwViewDashboard::render(ServerApp &app)
{
    /* Status bar at the top */
    ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, 28));
    ImGui::SetNextWindowBgAlpha(0.9f);
    ImGui::Begin("##status_bar", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::Text("Connected to %s:%u  |  %s", host_, (unsigned)port_, username_);
    ImGui::SameLine(io.DisplaySize.x - 80);
    if (ImGui::SmallButton("Logout")) {
        ImGui::End();
        return DashboardAction::Logout;
    }
    ImGui::End();

    /* Main content area below the status bar */
    ImGui::SetNextWindowPos(ImVec2(0, 30));
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, io.DisplaySize.y - 30));
    ImGui::Begin("##main_panel", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings);

    bool session_expired = false;

    if (ImGui::BeginTabBar("##tabs")) {
        if (ImGui::BeginTabItem("Users")) {
            active_tab_ = Tab::Users;
            session_expired |= users_view_.render(app);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Cluster")) {
            active_tab_ = Tab::Cluster;
            session_expired |= cluster_view_.render(app);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Audit Log")) {
            active_tab_ = Tab::AuditLog;
            session_expired |= audit_view_.render(app);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    ImGui::End();

    if (session_expired)
        return DashboardAction::Logout;

    return DashboardAction::None;
}
