#include "vw_view_queue.h"
#include "../ClientApp.h"
#include "imgui.h"
#include <ctime>
#include <cstdio>

static void format_utc(char *buf, size_t n, int64_t unix_ts) {
    if (unix_ts == 0) { snprintf(buf, n, "Never"); return; }
    time_t t = (time_t)unix_ts;
    struct tm tm;
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    snprintf(buf, n, "%04d-%02d-%02d %02d:%02d UTC",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min);
}

void vw_view_queue_render(const VwIpcStatus &status, ClientApp &app) {
    ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 28));
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, io.DisplaySize.y - 28));
    ImGui::Begin("##queue", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

    char ts_buf[32];
    format_utc(ts_buf, sizeof(ts_buf), status.last_sync_at);
    ImGui::Text("Last sync: %s", ts_buf);
    ImGui::SameLine(0, 20);
    if (ImGui::Button("Sync Now##queue")) app.ipc_sync_now();

    ImGui::Separator();
    ImGui::Spacing();

    if (ImGui::BeginTable("##queue_stats", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupColumn("Uploads pending");
        ImGui::TableSetupColumn("Downloads pending");
        ImGui::TableSetupColumn("Errors");
        ImGui::TableHeadersRow();
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0); ImGui::Text("%u", status.pending_uploads);
        ImGui::TableSetColumnIndex(1); ImGui::Text("%u", status.pending_downloads);
        ImGui::TableSetColumnIndex(2);
        if (status.error_count > 0)
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%u", status.error_count);
        else
            ImGui::Text("0");
        ImGui::EndTable();
    }

    ImGui::Spacing();
    if (status.syncing)
        ImGui::TextColored(ImVec4(0.3f, 0.8f, 1.0f, 1.0f), "Sync in progress...");
    else if (status.paused)
        ImGui::TextColored(ImVec4(0.9f, 0.7f, 0.2f, 1.0f), "Sync paused");

    ImGui::End();
}
