#include "vw_view_settings.h"
#include "../ClientApp.h"
#include "imgui.h"
#include <cstring>
#include <cstdio>

/* Per-frame local state — persists via static (single window, always-open). */
static char s_local_root[512]   = "";
static char s_virtual_root[256] = "";
static char s_status_msg[128]   = "";
static bool s_confirm_shutdown  = false;

void vw_view_settings_render(const VwIpcStatus & /*status*/, ClientApp &app) {
    ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 28));
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, io.DisplaySize.y - 28));
    ImGui::Begin("##settings", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

    /* IPC port */
    ImGui::SeparatorText("Connection");
    int port = (int)app.ipc_port;
    if (ImGui::InputInt("IPC port##settings", &port, 0, 0)) {
        if (port > 0 && port < 65536) app.ipc_port = (uint16_t)port;
    }
    ImGui::TextDisabled("Change takes effect on next reconnect.");

    /* Folder management */
    ImGui::Spacing();
    ImGui::SeparatorText("Sync folders");
    ImGui::InputText("Local path##settings",   s_local_root,   sizeof(s_local_root));
    ImGui::InputText("Virtual path##settings", s_virtual_root, sizeof(s_virtual_root));

    if (ImGui::Button("Add folder##settings")) {
        if (s_local_root[0] && s_virtual_root[0]) {
            int rc = app.ipc_folder_add(s_local_root, s_virtual_root);
            snprintf(s_status_msg, sizeof(s_status_msg),
                     rc == 0 ? "Folder added." : "Add failed (err %d).", rc);
        } else {
            snprintf(s_status_msg, sizeof(s_status_msg), "Both paths required.");
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Remove folder##settings")) {
        if (s_local_root[0]) {
            int rc = app.ipc_folder_remove(s_local_root);
            snprintf(s_status_msg, sizeof(s_status_msg),
                     rc == 0 ? "Folder removed." : "Remove failed (err %d).", rc);
        } else {
            snprintf(s_status_msg, sizeof(s_status_msg), "Enter local path to remove.");
        }
    }
    if (s_status_msg[0])
        ImGui::TextUnformatted(s_status_msg);

    /* Shutdown */
    ImGui::Spacing();
    ImGui::SeparatorText("Daemon");
    if (ImGui::Button("Shutdown daemon##settings"))
        s_confirm_shutdown = true;

    if (s_confirm_shutdown) {
        ImGui::OpenPopup("Confirm shutdown##settings");
        s_confirm_shutdown = false;
    }
    if (ImGui::BeginPopupModal("Confirm shutdown##settings", nullptr,
            ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("Stop the VaporWault daemon?\nSync will halt until it is restarted.");
        ImGui::Spacing();
        if (ImGui::Button("Shutdown##confirm", ImVec2(110, 0))) {
            app.ipc_shutdown();
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel##confirm", ImVec2(110, 0)))
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    ImGui::End();
}
