#include "vw_view_login.h"
#include "../ClientApp.h"
#include "imgui.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>

/* Per-frame local state — persists via static (single window, always-open),
 * matching vw_view_settings.cpp's established convention for this GUI.
 *
 * TASK-163: this is the "no account reachable yet" view (shown whenever
 * ClientApp::render_frame() sees zero live server connections across every
 * configured account) and doubles as the body of the switcher's "+ Add
 * account" modal (see ClientApp.cpp) — both cases are "collect one
 * account's connection details and send ACCOUNT_ADD_REQ", just reached from
 * different places. Host/port/CA-cert/label are per-account fields, never
 * defaulted from another already-configured account
 * (ARCHITECTURE.md's "Accounts are per-server, not just per-user"). */
static char s_label[64]     = "";
static char s_host[256]     = "";
static char s_port[8]       = "4430";
static char s_ca_cert[512]  = "";
static char s_username[64]  = "";
static char s_password[256] = "";
static char s_otp[16]       = "";
static char s_status_msg[160] = "";
static bool s_need_otp       = false;

void vw_view_login_render(const VwIpcStatus &status, ClientApp &app) {
    ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f),
                            ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(400, 0), ImGuiCond_Always);
    ImGui::Begin("VaporWault##login",  nullptr,
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove);

    if (!status.connected) {
        ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.2f, 1.0f),
            "Offline — no account currently connected to a server");
        ImGui::Spacing();
    }

    ImGui::InputText("Label (optional)##login", s_label, sizeof(s_label));
    ImGui::InputText("Server host##login", s_host, sizeof(s_host));
    ImGui::InputText("Server port##login", s_port, sizeof(s_port), ImGuiInputTextFlags_CharsDecimal);
    ImGui::InputText("CA cert path##login", s_ca_cert, sizeof(s_ca_cert));
    ImGui::InputText("Username##login", s_username, sizeof(s_username));
    bool submit = ImGui::InputText("Password##login", s_password, sizeof(s_password),
                      ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);

    if (s_need_otp)
        submit = ImGui::InputText("2FA code##login", s_otp, sizeof(s_otp),
                      ImGuiInputTextFlags_EnterReturnsTrue) || submit;

    submit = ImGui::Button("Add account##login") || submit;

    if (submit && s_password[0] && s_host[0] && s_username[0]) {
        uint16_t port = (uint16_t)strtoul(s_port, nullptr, 10);
        uint32_t new_account_id = 0;
        int rc = app.ipc_account_add(0, s_label, s_host, port, s_ca_cert,
                                      s_username, s_password, s_otp, &new_account_id);
        /* app.ipc_account_add() zeroes s_password in place regardless of
         * outcome (raw-password-handling convention, see vw_gui_ipc.cpp). */
        if (rc == 0) {
            s_status_msg[0] = '\0';
            s_need_otp = false;
            s_otp[0] = '\0';
            s_label[0] = '\0';
            s_username[0] = '\0';
            /* Render-thread-only — see ClientApp.h's doc comment. Safe
             * here: this render call and the switch happen on the same
             * (render) thread. */
            app.switch_active_account(new_account_id);
        } else if (rc == (int)VW_ERR_AUTH_2FA_REQUIRED) {
            s_need_otp = true;
            snprintf(s_status_msg, sizeof(s_status_msg),
                     "This account requires a 2FA code — enter it above and add it again.");
        } else {
            snprintf(s_status_msg, sizeof(s_status_msg),
                     "Add account failed (code %d).", rc);
        }
    }

    if (s_status_msg[0]) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.3f, 1.0f), "%s", s_status_msg);
    }

    ImGui::End();
}
