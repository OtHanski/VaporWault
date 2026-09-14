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

static void human_size(uint64_t bytes, char *buf, size_t bufsz) {
    if (bytes < 1024ull)
        snprintf(buf, bufsz, "%llu B", (unsigned long long)bytes);
    else if (bytes < 1024ull * 1024)
        snprintf(buf, bufsz, "%.1f KB", (double)bytes / 1024.0);
    else if (bytes < 1024ull * 1024 * 1024)
        snprintf(buf, bufsz, "%.1f MB", (double)bytes / (1024.0 * 1024.0));
    else
        snprintf(buf, bufsz, "%.1f GB", (double)bytes / (1024.0 * 1024.0 * 1024.0));
}

/* Per-frame local state, matching this GUI's established convention. */
static std::vector<VwGuiShareEntry> s_shared_by_me;
static std::vector<VwGuiLinkEntry>  s_my_links;
static std::vector<VwGuiShareEntry> s_shared_with_me;
static bool s_needs_refresh = true;
static char s_error_msg[160] = "";

/*
 * TASK-00282: nested browsing into a "shared with me" folder, via
 * TASK-00281's VW_IPC_SHARED_FOLDER_LIST_REQ. A separate, file_id-based
 * breadcrumb stack rather than reusing vw_view_browser.cpp's path-based
 * s_current_path — there is no owner-namespaced path into content the
 * caller doesn't own, the whole reason that IPC message exists. Empty
 * stack means "not currently browsing" (showing the flat share lists
 * above instead).
 */
struct VwSharedBrowseCrumb {
    uint64_t    file_id;
    std::string name;
};
static std::vector<VwSharedBrowseCrumb>    s_browse_stack;
static std::vector<VwGuiRemoteFileEntry>   s_browse_entries;
static char s_browse_error[160] = "";

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

static void refresh_browse(ClientApp &app) {
    if (s_browse_stack.empty()) return;
    int ec = 0;
    if (app.ipc_shared_folder_list(s_browse_stack.back().file_id, 0, &s_browse_entries, &ec)) {
        s_browse_error[0] = '\0';
    } else {
        s_browse_entries.clear();
        char reason[160];
        vw_gui_format_action_error(reason, sizeof(reason), "Browsing this folder", ec);
        snprintf(s_browse_error, sizeof(s_browse_error), "%s", reason);
    }
}

/* Entry point from a "shared with me" row's Browse button. dir_file_id
 * might name a file, not a folder (share lists carry no entry_type — see
 * TASK-00281's own note on why) — on VW_ERR_INVALID_ARG, surface that on
 * the flat list rather than switching into an empty browse view. */
static void start_browsing(ClientApp &app, uint64_t dir_file_id, const std::string &name) {
    s_browse_stack.clear();
    s_browse_stack.push_back({dir_file_id, name});
    refresh_browse(app);
    if (s_browse_error[0]) {
        /* Failed outright (e.g. this share is a file, not a folder) —
         * don't leave the user stuck in an empty browse view for it.
         * Built via std::string, then copied through a single %s: gcc's
         * -Wformat-truncation flags a fixed destination fed by two
         * combined %s sources whose statically-provable worst case
         * exceeds it (even when each source is itself bounded), but not
         * a single already-combined, runtime-sized source — the actual
         * truncation behavior (silently drop the tail) is identical and
         * fine here, this only avoids the false-positive warning. */
        std::string msg = "Can't browse \"" + name + "\": " + s_browse_error;
        snprintf(s_error_msg, sizeof(s_error_msg), "%s", msg.c_str());
        s_browse_stack.clear();
        s_browse_error[0] = '\0';
    }
}

static void browse_into(ClientApp &app, uint64_t dir_file_id, const std::string &name) {
    s_browse_stack.push_back({dir_file_id, name});
    refresh_browse(app);
}

static void browse_up(ClientApp &app) {
    if (s_browse_stack.empty()) return;
    s_browse_stack.pop_back();
    if (s_browse_stack.empty()) {
        s_browse_entries.clear();
        s_browse_error[0] = '\0';
    } else {
        refresh_browse(app);
    }
}

void vw_view_shared_invalidate() {
    s_needs_refresh = true;
    s_shared_by_me.clear();
    s_my_links.clear();
    s_shared_with_me.clear();
    s_browse_stack.clear();
    s_browse_entries.clear();
    s_browse_error[0] = '\0';
}

static void render_browse(ClientApp &app) {
    ImGui::SeparatorText("Shared with me — browsing");

    if (ImGui::Button("Up##shared_browse")) browse_up(app);
    ImGui::SameLine();
    /* Breadcrumb: click any earlier crumb to jump straight back to it. */
    for (size_t i = 0; i < s_browse_stack.size(); i++) {
        if (i > 0) { ImGui::SameLine(); ImGui::TextUnformatted("/"); ImGui::SameLine(); }
        ImGui::PushID((int)i);
        if (ImGui::SmallButton(s_browse_stack[i].name.c_str())) {
            s_browse_stack.resize(i + 1);
            refresh_browse(app);
        }
        ImGui::PopID();
    }

    if (s_browse_error[0]) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f), "%s", s_browse_error);
    }

    /* "Open" is deferred until after the loop below rather than called
     * directly from inside it: browse_into() -> refresh_browse() replaces
     * s_browse_entries (the very container being iterated), which would
     * invalidate the range-based for loop's iterator mid-iteration. */
    uint64_t pending_open_id = 0;
    std::string pending_open_name;

    if (ImGui::BeginTable("##browse_entries", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Size");
        ImGui::TableSetupColumn("Modified");
        ImGui::TableSetupColumn("");
        ImGui::TableHeadersRow();
        for (auto &e : s_browse_entries) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(e.entry_type == 1 ? "[dir] " : "");
            ImGui::SameLine(0.0f, 0.0f);
            ImGui::TextUnformatted(e.name.c_str());
            ImGui::TableSetColumnIndex(1);
            if (e.entry_type == 1) {
                ImGui::TextDisabled("--");
            } else {
                char sz[24]; human_size(e.size_bytes, sz, sizeof(sz));
                ImGui::TextUnformatted(sz);
            }
            ImGui::TableSetColumnIndex(2);
            char ts[24]; format_ts(e.mtime_unix, ts, sizeof(ts));
            ImGui::TextUnformatted(ts);
            ImGui::TableSetColumnIndex(3);
            if (e.entry_type == 1) {
                ImGui::PushID((int)e.file_id);
                if (ImGui::SmallButton("Open")) { pending_open_id = e.file_id; pending_open_name = e.name; }
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }

    if (pending_open_id != 0) browse_into(app, pending_open_id, pending_open_name);
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

    /* TASK-00282 (found while adding the same-shaped bug in render_browse
     * below, then checked here too since it's the exact same pattern):
     * both Revoke buttons below used to call refresh(app) directly from
     * inside the loop iterating the vector refresh() reassigns
     * (s_shared_by_me / s_my_links) — undefined behavior via iterator
     * invalidation on the range-based for loop, usually silently
     * harmless (std::vector::operator= often reuses the old buffer when
     * the new size doesn't exceed capacity) but a real, waiting crash
     * risk. Deferred to after each table, same as render_browse's own
     * "Open" button. */
    uint64_t pending_revoke_share_id = 0;
    uint64_t pending_revoke_link_id  = 0;

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
                if (ImGui::SmallButton("Revoke")) pending_revoke_share_id = s.share_id;
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
    if (pending_revoke_share_id != 0) { app.ipc_share_revoke(pending_revoke_share_id); refresh(app); }

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
                if (ImGui::SmallButton("Revoke")) pending_revoke_link_id = l.share_id;
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
    if (pending_revoke_link_id != 0) { app.ipc_link_revoke(pending_revoke_link_id); refresh(app); }

    ImGui::Spacing();

    if (!s_browse_stack.empty()) {
        render_browse(app);
        ImGui::End();
        return;
    }

    ImGui::SeparatorText("Shared with me");
    if (ImGui::BeginTable("##with_me", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Permission");
        ImGui::TableSetupColumn("Expires");
        ImGui::TableSetupColumn("Revoked");
        ImGui::TableSetupColumn("");
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
            ImGui::TableSetColumnIndex(4);
            /* A share's own entry may be a file, not a folder — share
             * lists carry no entry_type (TASK-00281's own note on why),
             * so this button is offered unconditionally and start_
             * browsing falls back to an inline error rather than an
             * empty browse view when the target turns out not to be one. */
            if (!s.revoked) {
                ImGui::PushID((int)s.share_id);
                if (ImGui::SmallButton("Browse")) start_browsing(app, s.file_id, s.name);
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }

    ImGui::End();
}
