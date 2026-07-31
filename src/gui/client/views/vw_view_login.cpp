#include "vw_view_login.h"
#include "../ClientApp.h"
#include "imgui.h"
#include <cstring>
#include <cstdio>

/* Per-frame local state — persists via static (single window, always-open),
 * matching vw_view_settings.cpp's established convention for this GUI. */
static char s_password[256] = "";
static char s_otp[16]       = "";
static char s_status_msg[160] = "";
static bool s_need_otp       = false;

void vw_view_login_render(const VwIpcStatus &status, ClientApp &app) {
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

    bool submit = ImGui::InputText("Password##login", s_password, sizeof(s_password),
                      ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);

    if (s_need_otp)
        submit = ImGui::InputText("2FA code##login", s_otp, sizeof(s_otp),
                      ImGuiInputTextFlags_EnterReturnsTrue) || submit;

    submit = ImGui::Button("Login##login") || submit;

    if (submit && s_password[0]) {
        int rc = app.ipc_login(s_password, s_otp);
        /* app.ipc_login() zeroes s_password in place regardless of outcome
         * (raw-password-handling convention, see vw_gui_ipc.cpp). */
        if (rc == 0) {
            s_status_msg[0] = '\0';
            s_need_otp = false;
            s_otp[0] = '\0';
            /* No explicit view transition here — ClientApp::render_frame
             * switches to Browser once the next status poll reports
             * connected == true. */
        } else if (rc == (int)VW_ERR_AUTH_2FA_REQUIRED) {
            s_need_otp = true;
            snprintf(s_status_msg, sizeof(s_status_msg),
                     "This account requires a 2FA code — enter it above and log in again.");
        } else {
            snprintf(s_status_msg, sizeof(s_status_msg),
                     "Login failed (code %d).", rc);
        }
    }

    if (s_status_msg[0]) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.3f, 1.0f), "%s", s_status_msg);
    }

    ImGui::End();
}
