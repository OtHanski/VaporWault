#include "vw_view_vault.h"
#include "../ClientApp.h"
#include "imgui.h"
#include <cstdio>
#include <cstring>
#include <ctime>
#include <set>
#include <vector>

/*
 * Vault / E2EE UI (TASK-100; library: TASK-099, docs/PROTOCOL.md §7.11).
 *
 * There is deliberately no automatic vault-aware sync yet (that's
 * TASK-106's job — the sync engine has no notion of vaults at all today),
 * so this view's "Encrypt & Upload..."/"Decrypt & Download..." actions are
 * manual, one-file-at-a-time operations, not a background process. This
 * is stated plainly in the UI (see the "Manual only" note in the render
 * function) rather than implied by omission.
 */

/* ── State (static, matching this GUI's established convention) ── */

static std::vector<VwGuiVaultEntry> s_vaults;
static bool        s_needs_refresh = true;
static char        s_error_msg[160] = "";
static std::set<uint64_t> s_unlocked_vaults; /* see vw_view_vault.h's doc comment */

/* Setup wizard */
static bool s_setup_open = false;
static char s_setup_dirname[64]  = "";
static char s_setup_pass1[256]   = "";
static char s_setup_pass2[256]   = "";
static char s_setup_status[220]  = "";

/* Unlock modal */
static bool     s_unlock_open = false;
static uint64_t s_unlock_vault_id = 0;
static char     s_unlock_pass[256]  = "";
static char     s_unlock_status[200] = "";

/* Encrypt & Upload dialog */
static bool     s_upload_open = false;
static uint64_t s_upload_vault_id = 0;
static char     s_upload_local_path[600] = "";
static char     s_upload_leaf_name[256]  = "";
static char     s_upload_status[220] = "";

bool vw_view_vault_is_unlocked(uint64_t vault_id) {
    return s_unlocked_vaults.count(vault_id) != 0;
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

static void refresh(ClientApp &app) {
    int ec = 0;
    if (app.ipc_vault_list(&s_vaults, &ec)) {
        s_error_msg[0] = '\0';
    } else {
        snprintf(s_error_msg, sizeof(s_error_msg), "Failed to list vaults (code %d).", ec);
    }
    s_needs_refresh = false;
}

void vw_view_vault_invalidate() {
    s_needs_refresh = true;
    s_vaults.clear();
    s_unlocked_vaults.clear();
}

/* ── Warnings block — shared verbatim by the setup wizard; do not soften
 * or shorten any of these three, per TASK-100's explicit instruction. ── */
static void render_vault_warnings() {
    ImGui::PushStyleColor(ImGuiCol_Border, ImVec4(0.9f, 0.6f, 0.1f, 1.0f));
    ImGui::BeginChild("##vault_warnings", ImVec2(0, 0),
                       ImGuiChildFlags_Borders | ImGuiChildFlags_AutoResizeY);

    ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.2f, 1.0f), "Before you continue:");

    ImGui::TextWrapped(
        "%s", "- Passphrase loss is permanent. This passphrase is separate from your "
        "account password and is never sent to the server. If you lose it, the files "
        "in this vault are permanently and unrecoverably lost -- there is no password "
        "reset, no admin override, and no way for VaporWault to recover them.");
    ImGui::Spacing();
    ImGui::TextWrapped(
        "%s", "- Metadata is NOT encrypted. Filenames, folder structure, and file sizes "
        "remain visible to the server. Only the contents of your files are protected.");
    ImGui::Spacing();
    ImGui::TextWrapped(
        "%s", "- Every edit re-uploads the whole file. Encrypted files cannot use "
        "incremental/delta sync, because each new version gets a fresh encryption key. "
        "Avoid vaults for large files you edit often (e.g. databases or VM disk images) "
        "unless you accept this bandwidth cost.");

    ImGui::EndChild();
    ImGui::PopStyleColor();
}

static void render_setup_wizard(ClientApp &app) {
    /* TASK-106 review finding: closing this modal via the window's native
     * "X" (which ImGui::BeginPopupModal handles internally by flipping
     * s_setup_open to false as a side effect, bypassing the Cancel/Create
     * button handlers below that used to be the only places these buffers
     * got zeroed) previously left a just-typed real passphrase sitting in
     * these long-lived static buffers indefinitely. Detecting the
     * open->closed transition here catches every closing path uniformly,
     * at the cost of a one-frame delay after an X-close (buffers are
     * still zeroed well before any plausible attacker could act on
     * process memory). */
    static bool was_open = false;
    if (was_open && !s_setup_open) {
        memset(s_setup_pass1, 0, sizeof(s_setup_pass1));
        memset(s_setup_pass2, 0, sizeof(s_setup_pass2));
    }
    was_open = s_setup_open;

    if (!s_setup_open) return;
    ImGui::SetNextWindowSize(ImVec2(520, 0), ImGuiCond_Always);
    if (!ImGui::BeginPopupModal("Create Vault##dialog", &s_setup_open,
                                 ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }

    ImGui::TextWrapped(
        "A vault is a server folder whose file contents are end-to-end "
        "encrypted with a passphrase only you know.");
    ImGui::Separator();

    ImGui::InputText("Vault folder name", s_setup_dirname, sizeof(s_setup_dirname));
    ImGui::InputText("Encryption passphrase", s_setup_pass1, sizeof(s_setup_pass1),
                      ImGuiInputTextFlags_Password);
    ImGui::InputText("Confirm passphrase", s_setup_pass2, sizeof(s_setup_pass2),
                      ImGuiInputTextFlags_Password);

    ImGui::Spacing();
    render_vault_warnings();
    ImGui::Spacing();

    if (ImGui::Button("Create Vault##confirm")) {
        if (!s_setup_dirname[0]) {
            snprintf(s_setup_status, sizeof(s_setup_status), "Enter a folder name.");
        } else if (!s_setup_pass1[0]) {
            snprintf(s_setup_status, sizeof(s_setup_status), "Enter a passphrase.");
        } else if (strcmp(s_setup_pass1, s_setup_pass2) != 0) {
            snprintf(s_setup_status, sizeof(s_setup_status), "Passphrases do not match.");
        } else {
            uint64_t dir_id = 0;
            int rc = app.ipc_file_mkdir(0, s_setup_dirname, &dir_id);
            if (rc != 0) {
                snprintf(s_setup_status, sizeof(s_setup_status),
                         "Could not create folder (code %d).", rc);
            } else {
                uint64_t vault_id = 0;
                rc = app.ipc_vault_create(dir_id, s_setup_pass1, &vault_id);
                /* ipc_vault_create zeroes s_setup_pass1 itself; zero the
                 * confirm field here since nothing else will. */
                memset(s_setup_pass2, 0, sizeof(s_setup_pass2));
                if (rc == 0) {
                    s_unlocked_vaults.insert(vault_id);
                    s_setup_dirname[0] = '\0';
                    s_setup_open = false;
                    ImGui::CloseCurrentPopup();
                    refresh(app);
                } else {
                    snprintf(s_setup_status, sizeof(s_setup_status),
                             "Vault creation failed (code %d).", rc);
                }
            }
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel##setup")) {
        memset(s_setup_pass1, 0, sizeof(s_setup_pass1));
        memset(s_setup_pass2, 0, sizeof(s_setup_pass2));
        s_setup_open = false;
        ImGui::CloseCurrentPopup();
    }
    if (s_setup_status[0])
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f), "%s", s_setup_status);

    ImGui::EndPopup();
}

static void open_unlock_modal(uint64_t vault_id) {
    s_unlock_vault_id = vault_id;
    s_unlock_pass[0] = '\0';
    s_unlock_status[0] = '\0';
    s_unlock_open = true;
    ImGui::OpenPopup("Unlock Vault##dialog");
}

static void render_unlock_modal(ClientApp &app) {
    /* Same X-close zeroing fix as render_setup_wizard above. */
    static bool was_open = false;
    if (was_open && !s_unlock_open) {
        memset(s_unlock_pass, 0, sizeof(s_unlock_pass));
    }
    was_open = s_unlock_open;

    if (!s_unlock_open) return;
    ImGui::SetNextWindowSize(ImVec2(420, 0), ImGuiCond_Always);
    if (!ImGui::BeginPopupModal("Unlock Vault##dialog", &s_unlock_open,
                                 ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }

    ImGui::Text("Vault #%llu", (unsigned long long)s_unlock_vault_id);
    ImGui::InputText("Encryption passphrase", s_unlock_pass, sizeof(s_unlock_pass),
                      ImGuiInputTextFlags_Password);

    if (ImGui::Button("Unlock##confirm")) {
        int rc = app.ipc_vault_unlock(s_unlock_vault_id, s_unlock_pass);
        if (rc == 0) {
            s_unlocked_vaults.insert(s_unlock_vault_id);
            s_unlock_open = false;
            ImGui::CloseCurrentPopup();
        } else if (rc == (int)VW_ERR_AUTH_BAD_CREDS) {
            snprintf(s_unlock_status, sizeof(s_unlock_status), "Wrong passphrase.");
        } else {
            snprintf(s_unlock_status, sizeof(s_unlock_status), "Unlock failed (code %d).", rc);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel##unlock")) {
        memset(s_unlock_pass, 0, sizeof(s_unlock_pass));
        s_unlock_open = false;
        ImGui::CloseCurrentPopup();
    }
    if (s_unlock_status[0])
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f), "%s", s_unlock_status);

    ImGui::EndPopup();
}

static void open_upload_dialog(uint64_t vault_id) {
    s_upload_vault_id = vault_id;
    s_upload_local_path[0] = '\0';
    s_upload_leaf_name[0]  = '\0';
    s_upload_status[0]     = '\0';
    s_upload_open = true;
    ImGui::OpenPopup("Encrypt & Upload##dialog");
}

static void render_upload_dialog(ClientApp &app) {
    if (!s_upload_open) return;
    ImGui::SetNextWindowSize(ImVec2(520, 0), ImGuiCond_Always);
    if (!ImGui::BeginPopupModal("Encrypt & Upload##dialog", &s_upload_open,
                                 ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }

    ImGui::TextWrapped(
        "Encrypts a local file and uploads it into vault #%llu. This is a "
        "one-time, manual operation -- it does not add the file to ongoing "
        "background sync.",
        (unsigned long long)s_upload_vault_id);
    ImGui::Separator();
    ImGui::InputText("Local file path", s_upload_local_path, sizeof(s_upload_local_path));
    ImGui::InputText("Name in vault", s_upload_leaf_name, sizeof(s_upload_leaf_name));

    if (ImGui::Button("Encrypt & Upload##confirm")) {
        if (!s_upload_local_path[0] || !s_upload_leaf_name[0]) {
            snprintf(s_upload_status, sizeof(s_upload_status),
                     "Enter both a local path and a name.");
        } else {
            uint64_t out_file_id = 0, out_version_id = 0;
            int rc = app.ipc_vault_upload(s_upload_vault_id, 0, s_upload_leaf_name,
                                           s_upload_local_path, &out_file_id, &out_version_id);
            if (rc == 0) {
                snprintf(s_upload_status, sizeof(s_upload_status),
                         "Uploaded as file #%llu.", (unsigned long long)out_file_id);
            } else {
                snprintf(s_upload_status, sizeof(s_upload_status),
                         "Upload failed (code %d).", rc);
            }
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Close##upload")) { s_upload_open = false; ImGui::CloseCurrentPopup(); }
    if (s_upload_status[0]) ImGui::TextUnformatted(s_upload_status);

    ImGui::EndPopup();
}

void vw_view_vault_render(const VwIpcStatus & /*status*/, ClientApp &app) {
    ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 28));
    ImGui::SetNextWindowSize(ImVec2(io.DisplaySize.x, io.DisplaySize.y - 28));
    ImGui::Begin("##vault", nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus);

    if (s_needs_refresh) refresh(app);

    if (ImGui::Button("Refresh##vault")) refresh(app);
    ImGui::SameLine();
    if (ImGui::Button("Create New Vault...")) {
        s_setup_dirname[0] = '\0';
        memset(s_setup_pass1, 0, sizeof(s_setup_pass1));
        memset(s_setup_pass2, 0, sizeof(s_setup_pass2));
        s_setup_status[0] = '\0';
        s_setup_open = true;
        ImGui::OpenPopup("Create Vault##dialog");
    }
    ImGui::SameLine();
    ImGui::TextDisabled("(manual encrypt/upload only -- see TASK-106 for automatic sync)");
    ImGui::Separator();

    if (s_error_msg[0]) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f), "%s", s_error_msg);
        ImGui::Separator();
    }

    if (ImGui::BeginTable("##vaults", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Vault ID");
        ImGui::TableSetupColumn("Folder file_id");
        ImGui::TableSetupColumn("Created");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("");
        ImGui::TableHeadersRow();
        for (auto &v : s_vaults) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%llu", (unsigned long long)v.vault_id);
            ImGui::TableSetColumnIndex(1);
            ImGui::Text("%llu", (unsigned long long)v.folder_file_id);
            ImGui::TableSetColumnIndex(2);
            char ts[24]; format_ts(v.created_at, ts, sizeof(ts));
            ImGui::TextUnformatted(ts);
            ImGui::TableSetColumnIndex(3);
            bool unlocked = vw_view_vault_is_unlocked(v.vault_id);
            if (unlocked) ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "Unlocked");
            else ImGui::TextDisabled("Locked");
            ImGui::TableSetColumnIndex(4);
            ImGui::PushID((int)v.vault_id);
            if (unlocked) {
                if (ImGui::SmallButton("Encrypt & Upload...")) open_upload_dialog(v.vault_id);
            } else {
                if (ImGui::SmallButton("Unlock")) open_unlock_modal(v.vault_id);
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    render_setup_wizard(app);
    render_unlock_modal(app);
    render_upload_dialog(app);

    ImGui::End();
}
