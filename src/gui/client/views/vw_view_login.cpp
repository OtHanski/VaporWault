#include "vw_view_login.h"
#include "../ClientApp.h"
#include "imgui.h"

void vw_view_login_render(const VwIpcStatus &status, ClientApp & /*app*/) {
    ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f),
                            ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(360, 0), ImGuiCond_Always);
    ImGui::Begin("VaporWault##login",  nullptr,
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove);

    if (!status.connected) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f),
            "Offline — daemon not connected to server");
        ImGui::Spacing();
    }

    ImGui::TextWrapped(
        "Login via CLI:  vapourwault-cli login\n\n"
        "Credential management is not yet available in the GUI.\n"
        "Once logged in through the CLI the GUI will connect automatically.");

    ImGui::End();
}
