#include "vw_view_browser.h"
#include "../ClientApp.h"
#include "imgui.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <set>
#include <vector>

/* Sync state colours/labels (vw_sync_state_t: 0=synced, 1=local_mod,
 * 2=remote_mod, 3=conflict, 4=local_del, 5=remote_del, 6=new_local). */
static ImVec4 sync_colour(uint32_t state) {
    switch (state) {
    case 0: return ImVec4(0.2f, 0.9f, 0.2f, 1.0f); /* green  — synced     */
    case 3: return ImVec4(0.9f, 0.2f, 0.2f, 1.0f); /* red    — conflict   */
    case 1: case 2: case 6:
        return ImVec4(0.9f, 0.8f, 0.1f, 1.0f);      /* yellow — pending    */
    default:
        return ImVec4(0.7f, 0.7f, 0.7f, 1.0f);      /* grey   — deleted/other */
    }
}

static const char *sync_label(uint32_t state) {
    switch (state) {
    case 0: return "Synced";
    case 1: return "Local mod";
    case 2: return "Remote mod";
    case 3: return "Conflict";
    case 4: return "Local del";
    case 5: return "Remote del";
    case 6: return "New";
    default: return "Unknown";
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

static void format_ts(int64_t unix_ts, char *buf, size_t bufsz) {
    if (unix_ts == 0) { snprintf(buf, bufsz, "--"); return; }
    time_t t = (time_t)unix_ts;
    struct tm tm_val;
#ifdef _WIN32
    gmtime_s(&tm_val, &t);
#else
    gmtime_r(&t, &tm_val);
#endif
    strftime(buf, bufsz, "%Y-%m-%d %H:%M", &tm_val);
}

/* A row as displayed at the current path — either a real synced file, or a
 * synthetic directory derived from a deeper file's path (the local sync
 * cache backing VW_IPC_FILE_LIST_REQ never contains directory entries at
 * all — vw_sync.c's own sync engine skips them, see TASK-104's notes — so
 * "folders" here are inferred from path components, not real objects). */
struct DisplayRow {
    std::string name;
    bool        is_dir = false;
    uint64_t    size = 0;
    int64_t     mtime = 0;
    uint32_t    sync_state = 0;
};

static constexpr uint8_t kEntryTypeDir = 1; /* VW_ENTRY_DIR, see vw_store.h */

static std::vector<DisplayRow> compute_rows(const std::vector<VwGuiFileEntry> &entries,
                                             const std::string &current_path) {
    std::string prefix = current_path;
    if (prefix.empty() || prefix.back() != '/') prefix += '/';

    std::vector<DisplayRow> rows;
    std::set<std::string> seen_dirs;

    for (const auto &e : entries) {
        if (e.virtual_path.size() <= prefix.size()) continue;
        if (e.virtual_path.compare(0, prefix.size(), prefix) != 0) continue;

        std::string rel = e.virtual_path.substr(prefix.size());
        size_t slash = rel.find('/');
        if (slash == std::string::npos) {
            /* Direct child — a real cache entry, which may itself be a
             * directory record (the local walk does create those, even
             * though nothing has uploaded them remotely yet — see
             * TASK-104's notes) or a plain file. */
            if (e.entry_type == kEntryTypeDir) {
                if (seen_dirs.insert(rel).second) {
                    DisplayRow r; r.name = rel; r.is_dir = true;
                    rows.push_back(std::move(r));
                }
            } else {
                DisplayRow r;
                r.name       = rel;
                r.is_dir     = false;
                r.size       = e.server_size;
                r.mtime      = e.server_mtime ? e.server_mtime : e.local_mtime;
                r.sync_state = e.sync_state;
                rows.push_back(std::move(r));
            }
        } else {
            /* Deeper descendant — implies an intermediate directory even
             * if that directory has no cache entry of its own. */
            std::string dirname = rel.substr(0, slash);
            if (seen_dirs.insert(dirname).second) {
                DisplayRow r;
                r.name   = dirname;
                r.is_dir = true;
                rows.push_back(std::move(r));
            }
        }
    }

    std::sort(rows.begin(), rows.end(), [](const DisplayRow &a, const DisplayRow &b) {
        if (a.is_dir != b.is_dir) return a.is_dir;
        return a.name < b.name;
    });
    return rows;
}

/* Per-frame local state — persists via static, matching this GUI's
 * established convention (vw_view_settings.cpp). */
static std::vector<VwGuiFileEntry> s_entries;
static std::string s_current_path = "/";
static bool        s_needs_refresh = true;
static char         s_error_msg[128] = "";

static void refresh(ClientApp &app) {
    if (app.ipc_file_list("", &s_entries)) {
        s_error_msg[0] = '\0';
    } else {
        snprintf(s_error_msg, sizeof(s_error_msg), "Failed to fetch file list from daemon.");
    }
    s_needs_refresh = false;
}

static void navigate_up() {
    if (s_current_path == "/") return;
    size_t pos = s_current_path.find_last_of('/');
    s_current_path = (pos == 0) ? "/" : s_current_path.substr(0, pos);
}

void vw_view_browser_render(const VwIpcStatus &status, ClientApp &app) {
    ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 28));
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, io.DisplaySize.y - 28));
    ImGui::Begin("##browser", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

    if (s_needs_refresh) refresh(app);

    /* Toolbar */
    if (ImGui::Button("Sync Now##browser")) app.ipc_sync_now();
    ImGui::SameLine();
    const char *pause_label = status.paused ? "Resume##browser" : "Pause##browser";
    if (ImGui::Button(pause_label)) {
        if (status.paused) app.ipc_resume(); else app.ipc_pause();
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh##browser")) refresh(app);
    ImGui::SameLine();
    if (ImGui::Button("Up##browser")) navigate_up();
    ImGui::SameLine();
    ImGui::TextDisabled("%s", s_current_path.c_str());
    ImGui::Separator();

    if (s_error_msg[0]) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f), "%s", s_error_msg);
        ImGui::Separator();
    }

    std::vector<DisplayRow> rows = compute_rows(s_entries, s_current_path);

    if (ImGui::BeginTable("##files", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Name",       ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Size",       ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Modified",   ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Sync State", ImGuiTableColumnFlags_WidthFixed, 90.0f);
        ImGui::TableHeadersRow();

        if (rows.empty()) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextDisabled("(empty — add a sync folder in Settings)");
        }

        for (const auto &row : rows) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            const char *icon = row.is_dir ? "[dir] " : "";
            bool clicked = ImGui::Selectable((std::string(icon) + row.name).c_str(),
                                              false, ImGuiSelectableFlags_SpanAllColumns |
                                              (row.is_dir ? ImGuiSelectableFlags_AllowDoubleClick : 0));
            if (row.is_dir && clicked && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                s_current_path = (s_current_path == "/" ? "" : s_current_path) + "/" + row.name;
            }

            ImGui::TableSetColumnIndex(1);
            if (row.is_dir) {
                ImGui::TextUnformatted("--");
            } else {
                char sz[16]; human_size(row.size, sz, sizeof(sz));
                ImGui::TextUnformatted(sz);
            }

            ImGui::TableSetColumnIndex(2);
            if (row.is_dir) {
                ImGui::TextUnformatted("--");
            } else {
                char ts[24]; format_ts(row.mtime, ts, sizeof(ts));
                ImGui::TextUnformatted(ts);
            }

            ImGui::TableSetColumnIndex(3);
            if (!row.is_dir) {
                ImGui::TextColored(sync_colour(row.sync_state), "%s", sync_label(row.sync_state));
            } else {
                ImGui::TextUnformatted("--");
            }
        }

        ImGui::EndTable();
    }

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
