#include "vw_view_browser.h"
#include "../ClientApp.h"
#include "vw_view_vault.h"
#include "imgui.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <map>
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
    std::string virtual_path;
    uint64_t    file_id = 0;    /* 0 for a synthetic dir / not-yet-uploaded file */
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
                    DisplayRow r;
                    r.name         = rel;
                    r.virtual_path = e.virtual_path;
                    r.file_id      = e.file_id;
                    r.is_dir       = true;
                    rows.push_back(std::move(r));
                }
            } else {
                DisplayRow r;
                r.name         = rel;
                r.virtual_path = e.virtual_path;
                r.file_id      = e.file_id;
                r.is_dir       = false;
                r.size         = e.server_size;
                r.mtime        = e.server_mtime ? e.server_mtime : e.local_mtime;
                r.sync_state   = e.sync_state;
                rows.push_back(std::move(r));
            }
        } else {
            /* Deeper descendant — implies an intermediate directory even
             * if that directory has no cache entry of its own (no real
             * file_id to attach — sharing a synthetic directory isn't
             * possible until it has one, i.e. until something uploads
             * through it or FILE_MKDIR creates it explicitly). */
            std::string dirname = rel.substr(0, slash);
            if (seen_dirs.insert(dirname).second) {
                DisplayRow r;
                r.name         = dirname;
                r.virtual_path = prefix + dirname;
                r.is_dir       = true;
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

/* ── Browser state (static, matching this GUI's established convention) ── */

static std::vector<VwGuiFileEntry> s_entries;
static std::string s_current_path = "/";
static bool        s_needs_refresh = true;
static char        s_error_msg[128] = "";
static std::set<uint64_t> s_shared_file_ids; /* file_ids with an active grant or link */
static std::map<uint64_t, uint64_t> s_vault_ids; /* file_id -> vault_id (0 = unencrypted) */

/* Decrypt & Download dialog (TASK-100) */
static bool     s_decrypt_open = false;
static uint64_t s_decrypt_vault_id = 0;
static uint64_t s_decrypt_file_id = 0;
static std::string s_decrypt_name;
static char     s_decrypt_local_path[600] = "";
static char     s_decrypt_status[220] = "";

/* ── Share dialog state (TASK-096) ────────────────────────────────────────
 * Opened per-row via a right-click context menu; operates on whichever
 * file/folder was clicked (by virtual_path — share_grant/link_create
 * resolve file_id themselves, mirroring vapourwault-cli's share/create-link
 * commands, which also only ever take a path). */
static bool        s_share_open = false;
static std::string s_share_path;
static uint64_t    s_share_file_id = 0;

static char s_grant_username[65] = "";
static int  s_grant_perm_idx = 0;   /* 0 = View, 1 = Edit */
static bool s_grant_has_expiry = false;
static int  s_grant_expiry_days = 30;
static char s_grant_status[160] = "";

static int  s_link_perm_idx = 0;
static bool s_link_has_expiry = false;
static int  s_link_expiry_days = 30;
static char s_link_status[160] = "";
static bool s_link_token_valid = false;
static char s_link_token_hex[65] = "";

static std::vector<VwGuiShareEntry> s_dialog_shares;
static std::vector<VwGuiLinkEntry>  s_dialog_links;

static const char *perm_label(uint8_t perm) {
    switch (perm) {
    case 1: return "View";
    case 2: return "Edit";
    case 3: return "Owner";
    default: return "None";
    }
}

static void refresh_shared_badges(ClientApp &app) {
    s_shared_file_ids.clear();
    std::vector<VwGuiShareEntry> shares; int ec1 = 0;
    if (app.ipc_share_list(0, &shares, &ec1))
        for (auto &s : shares) if (!s.revoked) s_shared_file_ids.insert(s.file_id);
    std::vector<VwGuiLinkEntry> links; int ec2 = 0;
    if (app.ipc_link_list(&links, &ec2))
        for (auto &l : links) if (!l.revoked) s_shared_file_ids.insert(l.file_id);
}

/* TASK-158: VW_IPC_FILE_LIST_RESP now carries each entry's vault_id
 * directly (vw_cache_entry_t.vault_id, populated from FILE_LIST_RESP's own
 * per-entry vault_id — TASK-156). This just reshapes s_entries' already-
 * fetched field into the file_id -> vault_id map the row-render code
 * looks up by; no extra IPC round trip and no cap on listing size. */
static void refresh_vault_badges() {
    s_vault_ids.clear();
    for (auto &e : s_entries) {
        if (e.entry_type != 0 || e.file_id == 0) continue; /* dirs / not-yet-uploaded */
        if (e.vault_id != 0) s_vault_ids[e.file_id] = e.vault_id;
    }
}

static void refresh(ClientApp &app) {
    if (app.ipc_file_list("", &s_entries)) {
        s_error_msg[0] = '\0';
    } else {
        snprintf(s_error_msg, sizeof(s_error_msg), "Failed to fetch file list from daemon.");
    }
    refresh_shared_badges(app);
    refresh_vault_badges();
    s_needs_refresh = false;
}

void vw_view_browser_invalidate() {
    s_needs_refresh = true;
    s_current_path = "/";
    s_entries.clear();
    s_shared_file_ids.clear();
    s_vault_ids.clear();
}

static void navigate_up() {
    if (s_current_path == "/") return;
    size_t pos = s_current_path.find_last_of('/');
    s_current_path = (pos == 0) ? "/" : s_current_path.substr(0, pos);
}

static void refresh_dialog_lists(ClientApp &app) {
    int ec = 0;
    app.ipc_share_list(0, &s_dialog_shares, &ec);
    app.ipc_link_list(&s_dialog_links, &ec);
}

static void open_share_dialog(const DisplayRow &row, ClientApp &app) {
    s_share_path    = row.virtual_path;
    s_share_file_id = row.file_id;
    s_grant_username[0] = '\0';
    s_grant_status[0]   = '\0';
    s_link_status[0]    = '\0';
    s_link_token_valid  = false;
    s_link_token_hex[0] = '\0';
    refresh_dialog_lists(app);
    s_share_open = true;
    ImGui::OpenPopup("Share##dialog");
}

static void render_decrypt_dialog(ClientApp &app) {
    if (!s_decrypt_open) return;
    ImGui::SetNextWindowSize(ImVec2(520, 0), ImGuiCond_Always);
    if (!ImGui::BeginPopupModal("Decrypt & Download##dialog", &s_decrypt_open,
                                 ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }

    ImGui::TextWrapped("%s", s_decrypt_name.c_str());

    if (!vw_view_vault_is_unlocked(s_decrypt_vault_id)) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f),
            "Vault #%llu is locked in this session. Unlock it from the "
            "Vault tab first, then try again.",
            (unsigned long long)s_decrypt_vault_id);
        ImGui::Separator();
        if (ImGui::Button("Close##decrypt")) { s_decrypt_open = false; ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
        return;
    }

    ImGui::Separator();
    ImGui::InputText("Save to local path", s_decrypt_local_path, sizeof(s_decrypt_local_path));

    if (ImGui::Button("Decrypt & Download##confirm")) {
        if (!s_decrypt_local_path[0]) {
            snprintf(s_decrypt_status, sizeof(s_decrypt_status), "Enter a destination path.");
        } else {
            int rc = app.ipc_vault_download(s_decrypt_vault_id, s_decrypt_file_id,
                                             s_decrypt_local_path);
            if (rc == 0) {
                snprintf(s_decrypt_status, sizeof(s_decrypt_status), "Downloaded and decrypted.");
            } else {
                snprintf(s_decrypt_status, sizeof(s_decrypt_status),
                         "Download failed (code %d).", rc);
            }
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Close##decrypt2")) { s_decrypt_open = false; ImGui::CloseCurrentPopup(); }
    if (s_decrypt_status[0]) ImGui::TextUnformatted(s_decrypt_status);

    ImGui::EndPopup();
}

static void render_share_dialog(ClientApp &app) {
    if (!s_share_open) return;

    ImGui::SetNextWindowSize(ImVec2(480, 0), ImGuiCond_Always);
    if (!ImGui::BeginPopupModal("Share##dialog", &s_share_open, ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }

    ImGui::TextWrapped("%s", s_share_path.c_str());
    if (s_share_file_id == 0) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f),
            "This item hasn't finished uploading yet — sharing needs a server file_id.");
        ImGui::Separator();
        if (ImGui::Button("Close##share")) { s_share_open = false; ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
        return;
    }

    ImGui::Separator();
    ImGui::SeparatorText("Grant to a user");
    ImGui::InputText("Username##grant", s_grant_username, sizeof(s_grant_username));
    ImGui::RadioButton("View##grant", &s_grant_perm_idx, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Edit##grant", &s_grant_perm_idx, 1);
    ImGui::Checkbox("Expires##grant", &s_grant_has_expiry);
    if (s_grant_has_expiry) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(80);
        ImGui::InputInt("days from now##grant", &s_grant_expiry_days);
        if (s_grant_expiry_days < 1) s_grant_expiry_days = 1;
    }
    if (ImGui::Button("Grant access##grant")) {
        if (!s_grant_username[0]) {
            snprintf(s_grant_status, sizeof(s_grant_status), "Enter a username.");
        } else {
            int64_t expires_at = s_grant_has_expiry
                ? (int64_t)std::time(nullptr) + (int64_t)s_grant_expiry_days * 86400
                : 0;
            uint8_t perm = (uint8_t)(s_grant_perm_idx == 1 ? 2 : 1); /* VW_PERM_EDIT/VIEW */
            uint64_t share_id = 0;
            int rc = app.ipc_share_grant(s_share_path.c_str(), s_grant_username, perm,
                                          expires_at, &share_id);
            if (rc == 0) {
                snprintf(s_grant_status, sizeof(s_grant_status),
                         "Granted %s access to %s.", perm_label(perm), s_grant_username);
                s_grant_username[0] = '\0';
                refresh_dialog_lists(app);
                refresh_shared_badges(app);
            } else {
                vw_gui_format_action_error(s_grant_status, sizeof(s_grant_status), "Grant", rc);
            }
        }
    }
    if (s_grant_status[0]) ImGui::TextUnformatted(s_grant_status);

    ImGui::Separator();
    ImGui::SeparatorText("Public link");
    ImGui::TextWrapped(
        "Anyone with this link can access this item — no account needed. "
        "The token is shown only once; save it now.");
    ImGui::RadioButton("View##link", &s_link_perm_idx, 0);
    ImGui::SameLine();
    ImGui::RadioButton("Edit##link", &s_link_perm_idx, 1);
    ImGui::Checkbox("Expires##link", &s_link_has_expiry);
    if (s_link_has_expiry) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(80);
        ImGui::InputInt("days from now##link", &s_link_expiry_days);
        if (s_link_expiry_days < 1) s_link_expiry_days = 1;
    }
    if (ImGui::Button("Create link##link")) {
        int64_t expires_at = s_link_has_expiry
            ? (int64_t)std::time(nullptr) + (int64_t)s_link_expiry_days * 86400
            : 0;
        uint8_t perm = (uint8_t)(s_link_perm_idx == 1 ? 2 : 1);
        uint64_t share_id = 0; uint8_t token[32];
        int rc = app.ipc_link_create(s_share_path.c_str(), perm, expires_at, &share_id, token);
        if (rc == 0) {
            static const char hex[] = "0123456789abcdef";
            for (int i = 0; i < 32; i++) {
                s_link_token_hex[i * 2]     = hex[(token[i] >> 4) & 0xF];
                s_link_token_hex[i * 2 + 1] = hex[token[i] & 0xF];
            }
            s_link_token_hex[64] = '\0';
            s_link_token_valid = true;
            snprintf(s_link_status, sizeof(s_link_status), "Link created.");
            memset(token, 0, sizeof(token));
            refresh_dialog_lists(app);
            refresh_shared_badges(app);
        } else {
            vw_gui_format_action_error(s_link_status, sizeof(s_link_status), "Link creation", rc);
        }
    }
    if (s_link_token_valid) {
        ImGui::InputText("##token", s_link_token_hex, sizeof(s_link_token_hex),
                          ImGuiInputTextFlags_ReadOnly);
        ImGui::SameLine();
        if (ImGui::Button("Copy##token")) ImGui::SetClipboardText(s_link_token_hex);
    }
    if (s_link_status[0]) ImGui::TextUnformatted(s_link_status);

    ImGui::Separator();
    ImGui::SeparatorText("Existing shares & links for this item");
    if (ImGui::BeginTable("##dialog_shares", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Type");
        ImGui::TableSetupColumn("With / Permission");
        ImGui::TableSetupColumn("Expires");
        ImGui::TableSetupColumn("");
        ImGui::TableHeadersRow();

        for (auto &s : s_dialog_shares) {
            if (s.file_id != s_share_file_id || s.revoked) continue;
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted("Grant");
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%s (%s)", s.target_username.c_str(), perm_label(s.permission));
            ImGui::TableSetColumnIndex(2);
            char ts[24]; format_ts(s.expires_at, ts, sizeof(ts));
            ImGui::TextUnformatted(ts);
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID((int)s.share_id);
            if (ImGui::SmallButton("Revoke")) {
                if (app.ipc_share_revoke(s.share_id) == 0) {
                    refresh_dialog_lists(app);
                    refresh_shared_badges(app);
                }
            }
            ImGui::PopID();
        }
        for (auto &l : s_dialog_links) {
            if (l.file_id != s_share_file_id || l.revoked) continue;
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted("Link");
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("(anyone) (%s)", perm_label(l.permission));
            ImGui::TableSetColumnIndex(2);
            char ts[24]; format_ts(l.expires_at, ts, sizeof(ts));
            ImGui::TextUnformatted(ts);
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID((int)(l.share_id | 0x8000000000000000ull));
            if (ImGui::SmallButton("Revoke")) {
                if (app.ipc_link_revoke(l.share_id) == 0) {
                    refresh_dialog_lists(app);
                    refresh_shared_badges(app);
                }
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    ImGui::Separator();
    if (ImGui::Button("Close##share")) { s_share_open = false; ImGui::CloseCurrentPopup(); }
    ImGui::EndPopup();
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
            bool shared = row.file_id != 0 && s_shared_file_ids.count(row.file_id) > 0;
            auto vault_it = row.file_id != 0 ? s_vault_ids.find(row.file_id) : s_vault_ids.end();
            bool encrypted = vault_it != s_vault_ids.end();
            std::string label = std::string(icon) + row.name +
                                 (encrypted ? "  [encrypted]" : "") +
                                 (shared ? "  [shared]" : "");
            ImGui::PushID(row.virtual_path.c_str());
            bool clicked = ImGui::Selectable(label.c_str(), false,
                                              ImGuiSelectableFlags_SpanAllColumns |
                                              (row.is_dir ? ImGuiSelectableFlags_AllowDoubleClick : 0));
            if (row.is_dir && clicked && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                s_current_path = (s_current_path == "/" ? "" : s_current_path) + "/" + row.name;
            }
            if (ImGui::BeginPopupContextItem("##ctx")) {
                if (ImGui::MenuItem("Share...")) open_share_dialog(row, app);
                if (encrypted && ImGui::MenuItem("Decrypt & Download...")) {
                    s_decrypt_vault_id = vault_it->second;
                    s_decrypt_file_id  = row.file_id;
                    s_decrypt_name     = row.name;
                    s_decrypt_local_path[0] = '\0';
                    s_decrypt_status[0]     = '\0';
                    s_decrypt_open = true;
                    ImGui::OpenPopup("Decrypt & Download##dialog");
                }
                ImGui::EndPopup();
            }
            ImGui::PopID();

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

    render_share_dialog(app);
    render_decrypt_dialog(app);

    ImGui::End();
}
