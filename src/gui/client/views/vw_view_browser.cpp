#include "vw_view_browser.h"
#include "../ClientApp.h"
#include "imgui.h"
#include <cstring>

/* Sync state colours — used when file rows are populated (Phase 5) */
[[maybe_unused]] static ImVec4 sync_colour(uint32_t state) {
    /* vw_sync_state_t: 0=synced, 1=local_mod, 2=conflict, 3=error */
    switch (state) {
    case 0:  return ImVec4(0.2f, 0.9f, 0.2f, 1.0f); /* green  — synced     */
    case 1:  return ImVec4(0.9f, 0.8f, 0.1f, 1.0f); /* yellow — local mod  */
    case 2:  return ImVec4(0.9f, 0.2f, 0.2f, 1.0f); /* red    — conflict   */
    default: return ImVec4(0.7f, 0.7f, 0.7f, 1.0f); /* grey   — unknown    */
    }
}

[[maybe_unused]] static const char *sync_label(uint32_t state) {
    switch (state) {
    case 0: return "Synced";
    case 1: return "Modified";
    case 2: return "Conflict";
    default: return "Error";
    }
}

void vw_view_browser_render(const VwIpcStatus &status, ClientApp &app) {
    ImGuiIO &io = ImGui::GetIO();
    /* Full-screen content area below the menu bar (28 px) */
    ImGui::SetNextWindowPos(ImVec2(0, 28));
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, io.DisplaySize.y - 28));
    ImGui::Begin("##browser", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

    /* Toolbar */
    if (ImGui::Button("Sync Now##browser")) app.ipc_sync_now();
    ImGui::SameLine();
    const char *pause_label = status.paused ? "Resume##browser" : "Pause##browser";
    if (ImGui::Button(pause_label)) {
        if (status.paused) app.ipc_resume(); else app.ipc_pause();
    }
    ImGui::Separator();

    float left_w = ImGui::GetContentRegionAvail().x * 0.25f;

    /* Left: folder tree (placeholder — full implementation in Phase 5) */
    ImGui::BeginChild("##folder_tree", ImVec2(left_w, 0), true);
    ImGui::Text("/ (root)");
    ImGui::EndChild();

    ImGui::SameLine();

    /* Right: file list table */
    ImGui::BeginChild("##file_list", ImVec2(0, 0), false);
    if (ImGui::BeginTable("##files", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name",       ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Size",       ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Modified",   ImGuiTableColumnFlags_WidthFixed, 120.0f);
        ImGui::TableSetupColumn("Sync State", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableHeadersRow();

        /* File rows are populated by the daemon via IPC FILE_LIST_REQ.
         * Phase 4: show a placeholder until the daemon populates the list. */
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        ImGui::TextDisabled("(select a folder to list files)");

        ImGui::EndTable();
    }
    ImGui::EndChild();

    /* Conflict modal */
    if (ImGui::BeginPopupModal("Conflict##browser", nullptr,
            ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("A conflict copy exists for this file.");
        ImGui::Text("Resolve via CLI: vapourwault-cli resolve <path>");
        if (ImGui::Button("Close##conflict")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    ImGui::End();
}
