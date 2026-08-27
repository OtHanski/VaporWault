#include "vw_view_settings.h"
#include "../ClientApp.h"
#include "imgui.h"
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>

/* Per-frame local state — persists via static (single window, always-open). */
static char s_local_root[512]   = "";
static char s_virtual_root[256] = "";
static char s_status_msg[128]   = "";
static bool s_confirm_shutdown  = false;

/* Sync-folder listing + selective-sync rule editor (TASK-194). */
static std::vector<VwGuiFolderEntry> s_folders;
static bool        s_folders_loaded = false;
static int         s_selected_folder = -1; /* index into s_folders, or -1 */
static char        s_new_pattern[256] = "";
static char        s_folder_rules_status[160] = "";

static void refresh_folders(ClientApp &app) {
    app.ipc_folder_list(&s_folders);
    s_folders_loaded = true;
    if (s_selected_folder >= (int)s_folders.size()) s_selected_folder = -1;
}

static void apply_excludes(ClientApp &app, int idx, const std::vector<std::string> &patterns) {
    if (idx < 0 || idx >= (int)s_folders.size()) return;
    int rc = app.ipc_folder_set_excludes(s_folders[idx].local_root.c_str(), patterns);
    if (rc == 0) {
        s_folder_rules_status[0] = '\0';
        refresh_folders(app);
    } else {
        snprintf(s_folder_rules_status, sizeof(s_folder_rules_status),
                 "Failed to update rules (err %d).", rc);
    }
}

/* Notification preferences (TASK-206/207/209/210; docs/PROTOCOL.md §7.13).
 * Single source of truth for name/bit/description, mirroring
 * vapourwault-cli's own NOTIFY_CATEGORIES[] table so the two surfaces
 * can't describe the categories differently. */
static const struct { const char *label; uint32_t bit; const char *desc; } NOTIFY_CATEGORIES[] = {
    { "Someone shares something with me",        VW_NOTIFY_SHARE_RECEIVED,          "A grant or link naming you was created" },
    { "My storage usage crosses 90% of quota",   VW_NOTIFY_QUOTA_WARNING,            "Re-arms once usage drops back under the threshold" },
    { "A new login succeeds on my account",      VW_NOTIFY_NEW_LOGIN,                "Never fires for a normal daemon reconnect" },
    { "My password or 2FA setting changes",      VW_NOTIFY_ACCOUNT_SECURITY_CHANGE,  "Password change or 2FA enable/disable" },
};
#define NOTIFY_CATEGORIES_COUNT (sizeof(NOTIFY_CATEGORIES) / sizeof(NOTIFY_CATEGORIES[0]))

static bool     s_notify_loaded = false;
static uint32_t s_notify_prefs  = 0;
static char     s_notify_status[128] = "";

static void refresh_notify_prefs(ClientApp &app) {
    uint32_t prefs = 0;
    if (app.ipc_notify_prefs_get(&prefs)) {
        s_notify_prefs = prefs;
        s_notify_loaded = true;
    } else {
        snprintf(s_notify_status, sizeof(s_notify_status), "Failed to fetch notification preferences.");
    }
}

/* Account email (TASK-222; docs/PROTOCOL.md §7.14) — the first real path
 * that can put an email on an account, so this section sits above
 * "Email notifications", which is silently a no-op without one. */
static bool s_email_loaded  = false;
static char s_email_current[129] = "";
static char s_email_input[129]   = "";
static char s_email_status[160]  = "";

static void refresh_account_email(ClientApp &app) {
    std::string email;
    if (app.ipc_account_email_get(&email)) {
        snprintf(s_email_current, sizeof(s_email_current), "%s", email.c_str());
        snprintf(s_email_input,   sizeof(s_email_input),   "%s", email.c_str());
        s_email_loaded = true;
    } else {
        snprintf(s_email_status, sizeof(s_email_status), "Failed to fetch account email.");
    }
}

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

    /* Sync-folder listing + selective-sync rule editor (TASK-192/194). */
    ImGui::Spacing();
    ImGui::SeparatorText("Configured folders");
    if (!s_folders_loaded) refresh_folders(app);
    if (ImGui::Button("Refresh##folders")) refresh_folders(app);

    if (ImGui::BeginTable("##folders_table", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Local root");
        ImGui::TableSetupColumn("Virtual root");
        ImGui::TableSetupColumn("Paused");
        ImGui::TableSetupColumn("Exclude rules");
        ImGui::TableHeadersRow();

        for (int i = 0; i < (int)s_folders.size(); i++) {
            const VwGuiFolderEntry &f = s_folders[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            bool selected = (i == s_selected_folder);
            ImGui::PushID(i);
            if (ImGui::Selectable(f.local_root.c_str(), selected,
                                   ImGuiSelectableFlags_SpanAllColumns)) {
                s_selected_folder = selected ? -1 : i;
                s_new_pattern[0] = '\0';
                s_folder_rules_status[0] = '\0';
            }
            ImGui::PopID();
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(f.virtual_root.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(f.paused ? "yes" : "no");
            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%d rule(s)", (int)f.excludes.size());
        }
        ImGui::EndTable();
    }

    if (s_selected_folder >= 0 && s_selected_folder < (int)s_folders.size()) {
        const VwGuiFolderEntry &sel = s_folders[s_selected_folder];
        ImGui::Spacing();
        ImGui::Text("Selective sync rules for: %s", sel.local_root.c_str());
        ImGui::TextDisabled(
            "Files matching a rule are never uploaded or downloaded by this "
            "folder. Already-synced local files are left alone — a rule only "
            "stops further changes from syncing.");

        for (size_t i = 0; i < sel.excludes.size(); i++) {
            ImGui::PushID((int)i);
            ImGui::BulletText("%s", sel.excludes[i].c_str());
            ImGui::SameLine();
            if (ImGui::SmallButton("Remove##rule")) {
                std::vector<std::string> updated = sel.excludes;
                updated.erase(updated.begin() + (long)i);
                apply_excludes(app, s_selected_folder, updated);
                ImGui::PopID();
                break; /* s_folders was just refreshed/invalidated */
            }
            ImGui::PopID();
        }

        ImGui::SetNextItemWidth(300);
        ImGui::InputText("##new_pattern", s_new_pattern, sizeof(s_new_pattern));
        ImGui::SameLine();
        if (ImGui::Button("Add pattern##rule")) {
            if (s_new_pattern[0]) {
                std::vector<std::string> updated = sel.excludes;
                updated.push_back(s_new_pattern);
                apply_excludes(app, s_selected_folder, updated);
                s_new_pattern[0] = '\0';
            }
        }
        if (s_folder_rules_status[0]) ImGui::TextUnformatted(s_folder_rules_status);
    }

    /* Account email (TASK-222; docs/PROTOCOL.md §7.14). */
    ImGui::Spacing();
    ImGui::SeparatorText("Account email");
    if (!s_email_loaded) refresh_account_email(app);
    ImGui::TextDisabled(
        "Used for password recovery and the email notifications below. "
        "Not set by account creation or invites — set it here.");
    ImGui::SetNextItemWidth(320);
    ImGui::InputText("##account_email", s_email_input, sizeof(s_email_input));
    ImGui::SameLine();
    if (ImGui::Button("Save##account_email")) {
        std::string stored;
        int rc = app.ipc_account_email_set(s_email_input, &stored);
        if (rc == 0) {
            snprintf(s_email_current, sizeof(s_email_current), "%s", stored.c_str());
            snprintf(s_email_input,   sizeof(s_email_input),   "%s", stored.c_str());
            s_email_status[0] = '\0';
        } else if (rc == (int)VW_ERR_ALREADY_EXISTS) {
            snprintf(s_email_status, sizeof(s_email_status),
                     "That address is already in use by another account.");
            refresh_account_email(app); /* re-sync input with real server state */
        } else {
            snprintf(s_email_status, sizeof(s_email_status),
                     "Invalid email address (err %d).", rc);
            refresh_account_email(app); /* re-sync input with real server state */
        }
    }
    ImGui::TextDisabled("Current: %s", s_email_current[0] ? s_email_current : "(none)");
    if (s_email_status[0]) ImGui::TextUnformatted(s_email_status);

    /* Notification preferences (TASK-206/207/209/210). */
    ImGui::Spacing();
    ImGui::SeparatorText("Email notifications");
    if (!s_notify_loaded) refresh_notify_prefs(app);
    ImGui::TextDisabled("Sent to your account's on-file email address. Off by default.");
    for (size_t i = 0; i < NOTIFY_CATEGORIES_COUNT; i++) {
        bool on = (s_notify_prefs & NOTIFY_CATEGORIES[i].bit) != 0;
        ImGui::PushID((int)i);
        if (ImGui::Checkbox(NOTIFY_CATEGORIES[i].label, &on)) {
            uint32_t requested = on ? (s_notify_prefs | NOTIFY_CATEGORIES[i].bit)
                                     : (s_notify_prefs & ~NOTIFY_CATEGORIES[i].bit);
            uint32_t stored = 0;
            int rc = app.ipc_notify_prefs_set(requested, &stored);
            if (rc == 0) {
                s_notify_prefs = stored;
                s_notify_status[0] = '\0';
            } else {
                snprintf(s_notify_status, sizeof(s_notify_status),
                         "Failed to update notification setting (err %d).", rc);
                refresh_notify_prefs(app); /* re-sync with real server state */
            }
        }
        ImGui::SameLine();
        ImGui::TextDisabled("(%s)", NOTIFY_CATEGORIES[i].desc);
        ImGui::PopID();
    }
    if (s_notify_status[0]) ImGui::TextUnformatted(s_notify_status);

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
