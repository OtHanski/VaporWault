#include "vw_view_shared.h"
#include "../ClientApp.h"
#include "imgui.h"
#include <cstdio>
#include <ctime>
#include <vector>

static void format_ts(int64_t unix_ts, char *buf, size_t bufsz) {
    if (unix_ts == 0) { snprintf(buf, bufsz, "never"); return; }
    time_t t = (time_t)unix_ts;
    struct tm tm_val;
#ifdef _WIN32
    gmtime_s(&tm_val, &t);
#else
    gmtime_r(&t, &tm_val);
#endif
    strftime(buf, bufsz, "%Y-%m-%d %H:%M", &tm_val);
}

static const char *perm_label(uint8_t perm) {
    switch (perm) {
    case 1: return "View";
    case 2: return "Edit";
    case 3: return "Owner";
    default: return "None";
    }
}

/* Per-frame local state, matching this GUI's established convention. */
static std::vector<VwGuiShareEntry> s_shared_by_me;
static std::vector<VwGuiLinkEntry>  s_my_links;
static std::vector<VwGuiShareEntry> s_shared_with_me;
static bool s_needs_refresh = true;
static char s_error_msg[160] = "";

static void refresh(ClientApp &app) {
    int ec1 = 0, ec2 = 0, ec3 = 0;
    bool ok1 = app.ipc_share_list(0, &s_shared_by_me, &ec1);
    bool ok2 = app.ipc_link_list(&s_my_links, &ec2);
    bool ok3 = app.ipc_share_list(1, &s_shared_with_me, &ec3);
    if (!ok1 || !ok2 || !ok3)
        snprintf(s_error_msg, sizeof(s_error_msg),
                 "Failed to fetch sharing info (codes %d/%d/%d).", ec1, ec2, ec3);
    else
        s_error_msg[0] = '\0';
    s_needs_refresh = false;
}

void vw_view_shared_invalidate() {
    s_needs_refresh = true;
    s_shared_by_me.clear();
    s_my_links.clear();
    s_shared_with_me.clear();
}

void vw_view_shared_render(const VwIpcStatus & /*status*/, ClientApp &app) {
    ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 28));
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, io.DisplaySize.y - 28));
    ImGui::Begin("##shared", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

    if (s_needs_refresh) refresh(app);

    if (ImGui::Button("Refresh##shared")) refresh(app);
    ImGui::Separator();

    if (s_error_msg[0]) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f), "%s", s_error_msg);
        ImGui::Separator();
    }

    ImGui::SeparatorText("Shared by me — user grants");
    if (ImGui::BeginTable("##by_me_grants", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Shared with");
        ImGui::TableSetupColumn("Permission");
        ImGui::TableSetupColumn("Expires");
        ImGui::TableSetupColumn("");
        ImGui::TableHeadersRow();
        for (auto &s : s_shared_by_me) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(s.name.c_str());
            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(s.target_username.c_str());
            ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(perm_label(s.permission));
            ImGui::TableSetColumnIndex(3);
            char ts[24]; format_ts(s.expires_at, ts, sizeof(ts));
            ImGui::TextUnformatted(ts);
            ImGui::TableSetColumnIndex(4);
            if (s.revoked) {
                ImGui::TextDisabled("revoked");
            } else {
                ImGui::PushID((int)s.share_id);
                if (ImGui::SmallButton("Revoke")) { app.ipc_share_revoke(s.share_id); refresh(app); }
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }

    ImGui::Spacing();
    ImGui::SeparatorText("Shared by me — public links");
    if (ImGui::BeginTable("##by_me_links", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Permission");
        ImGui::TableSetupColumn("Expires");
        ImGui::TableSetupColumn("");
        ImGui::TableHeadersRow();
        for (auto &l : s_my_links) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(l.name.c_str());
            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(perm_label(l.permission));
            ImGui::TableSetColumnIndex(2);
            char ts[24]; format_ts(l.expires_at, ts, sizeof(ts));
            ImGui::TextUnformatted(ts);
            ImGui::TableSetColumnIndex(3);
            if (l.revoked) {
                ImGui::TextDisabled("revoked");
            } else {
                ImGui::PushID((int)l.share_id);
                if (ImGui::SmallButton("Revoke")) { app.ipc_link_revoke(l.share_id); refresh(app); }
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }

    ImGui::Spacing();
    ImGui::SeparatorText("Shared with me");
    ImGui::TextDisabled(
        "Metadata only — this view cannot browse into a shared folder's\n"
        "contents yet (no IPC message lists a folder's children by id).");
    if (ImGui::BeginTable("##with_me", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Permission");
        ImGui::TableSetupColumn("Expires");
        ImGui::TableSetupColumn("Revoked");
        ImGui::TableHeadersRow();
        for (auto &s : s_shared_with_me) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(s.name.c_str());
            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(perm_label(s.permission));
            ImGui::TableSetColumnIndex(2);
            char ts[24]; format_ts(s.expires_at, ts, sizeof(ts));
            ImGui::TextUnformatted(ts);
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(s.revoked ? "yes" : "no");
        }
        ImGui::EndTable();
    }

    ImGui::End();
}
