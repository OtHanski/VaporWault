#include "vw_view_login.h"
#include "../ServerApp.h"
#include "imgui.h"
#include "vw_crypto.h"

#include <cstring>
#include <cstdio>

void VwViewLogin::render(ServerApp &app)
{
    ImGuiIO &io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f),
                            ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(420, 0), ImGuiCond_Always);
    ImGui::Begin("VaporWault Server##login", nullptr,
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove);

    ImGui::Text("Server connection");
    ImGui::Separator();
    ImGui::Spacing();

    bool disabled = (state_ == LoginState::Connecting || state_ == LoginState::AwaitingOtp);
    if (disabled) ImGui::BeginDisabled();

    ImGui::InputText("Host",    host_,    sizeof(host_));
    ImGui::InputInt ("Port",    &port_);
    if (port_ < 1) port_ = 1;
    if (port_ > 65535) port_ = 65535;
    ImGui::InputText("CA cert", ca_cert_, sizeof(ca_cert_));

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::InputText("Username", username_, sizeof(username_));
    ImGui::InputText("Password", password_, sizeof(password_),
                     ImGuiInputTextFlags_Password);

    if (disabled) ImGui::EndDisabled();

    if (needs_otp_) {
        ImGui::Spacing();
        ImGui::Text("Two-factor authentication:");
        ImGui::InputText("OTP code", otp_code_, sizeof(otp_code_));

        if (ImGui::Button("Submit OTP", ImVec2(200, 0)))
            do_otp(app);
    } else {
        ImGui::Spacing();
        if (ImGui::Button("Connect", ImVec2(200, 0)))
            do_connect(app);
    }

    if (state_ == LoginState::Error && error_msg_[0] != '\0') {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "%s", error_msg_);
    }

    ImGui::End();
}

void VwViewLogin::do_connect(ServerApp &app)
{
    state_ = LoginState::Connecting;
    error_msg_[0] = '\0';

    const char *ca = (ca_cert_[0] != '\0') ? ca_cert_ : nullptr;
    vw_err_t rc = app.conn().connect(host_, (uint16_t)port_, ca);
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_),
                 "Connection failed (err %d)", (int)rc);
        state_ = LoginState::Error;
        return;
    }

    /* Derive auth token: SHA-256(password) as the wire credential. */
    uint8_t auth_token[32];
    vw_crypto_sha256((const uint8_t *)password_, strlen(password_), auth_token);

    /* Build AUTH_REQUEST payload */
    vw_payload_auth_request_t req{};
    req.username     = username_;
    req.username_len = (uint16_t)strlen(username_);
    memcpy(req.auth_token, auth_token, 32);

    uint8_t  payload_buf[512];
    uint32_t payload_len = 0;
    rc = vw_proto_encode_auth_request(&req, payload_buf, sizeof(payload_buf), &payload_len);
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_), "Encode error %d", (int)rc);
        state_ = LoginState::Error;
        app.conn().disconnect();
        return;
    }

    rc = app.conn().send_msg(VW_MSG_AUTH_REQUEST, payload_buf, payload_len);
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_), "Send error %d", (int)rc);
        state_ = LoginState::Error;
        app.conn().disconnect();
        return;
    }

    /* Receive AUTH_OK, AUTH_FAIL, or AUTH_CHALLENGE */
    vw_msg_type_t resp_type;
    void *resp_payload   = nullptr;
    uint32_t resp_len    = 0;
    rc = app.conn().recv_msg(&resp_type, &resp_payload, &resp_len);
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_), "Recv error %d", (int)rc);
        state_ = LoginState::Error;
        app.conn().disconnect();
        return;
    }

    if (resp_type == VW_MSG_AUTH_CHALLENGE) {
        free(resp_payload);
        needs_otp_ = true;
        state_     = LoginState::AwaitingOtp;
        return;
    }

    if (resp_type == VW_MSG_AUTH_OK) {
        vw_payload_auth_ok_t auth_ok{};
        vw_err_t decode_rc = vw_proto_decode_auth_ok(
            (const uint8_t *)resp_payload, resp_len, &auth_ok);
        free(resp_payload);
        if (decode_rc != VW_OK) {
            snprintf(error_msg_, sizeof(error_msg_),
                     "Server sent malformed AUTH_OK (err %d). Please retry.", (int)decode_rc);
            state_ = LoginState::Error;
            app.conn().disconnect();
            return;
        }
        if (!auth_ok.is_admin) {
            snprintf(error_msg_, sizeof(error_msg_),
                     "Account '%s' is not an admin account.", username_);
            state_ = LoginState::Error;
            app.conn().disconnect();
            return;
        }
        /* Clear password from stack immediately */
        memset(password_, 0, sizeof(password_));
        state_     = LoginState::Idle;
        needs_otp_ = false;
        app.on_login_success(host_, (uint16_t)port_, username_, auth_ok);
        return;
    } else if (resp_type == VW_MSG_AUTH_FAIL) {
        vw_payload_auth_fail_t fail{};
        vw_proto_decode_auth_fail((const uint8_t *)resp_payload, resp_len, &fail);
        free(resp_payload);
        if (fail.lockout_remaining_secs > 0)
            snprintf(error_msg_, sizeof(error_msg_),
                     "Account locked — retry in %u seconds.",
                     (unsigned)fail.lockout_remaining_secs);
        else
            snprintf(error_msg_, sizeof(error_msg_), "Invalid credentials.");
    } else {
        free(resp_payload);
        snprintf(error_msg_, sizeof(error_msg_),
                 "Unexpected response type 0x%04X.", (unsigned)resp_type);
    }

    state_ = LoginState::Error;
    app.conn().disconnect();
}

void VwViewLogin::do_otp(ServerApp &app)
{
    vw_payload_auth_otp_t otp{};
    otp.otp_code = otp_code_;
    otp.otp_len  = (uint16_t)strlen(otp_code_);

    uint8_t  payload_buf[64];
    uint32_t payload_len = 0;
    vw_err_t rc = vw_proto_encode_auth_otp(&otp, payload_buf, sizeof(payload_buf), &payload_len);
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_), "OTP encode error %d", (int)rc);
        state_ = LoginState::Error;
        app.conn().disconnect();
        needs_otp_ = false;
        return;
    }

    rc = app.conn().send_msg(VW_MSG_AUTH_OTP, payload_buf, payload_len);
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_), "OTP send error %d", (int)rc);
        state_ = LoginState::Error;
        app.conn().disconnect();
        needs_otp_ = false;
        return;
    }

    vw_msg_type_t resp_type;
    void *resp_payload = nullptr;
    uint32_t resp_len  = 0;
    rc = app.conn().recv_msg(&resp_type, &resp_payload, &resp_len);
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_), "OTP recv error %d", (int)rc);
        state_ = LoginState::Error;
        app.conn().disconnect();
        needs_otp_ = false;
        return;
    }

    if (resp_type == VW_MSG_AUTH_OK) {
        vw_payload_auth_ok_t auth_ok{};
        vw_err_t decode_rc = vw_proto_decode_auth_ok(
            (const uint8_t *)resp_payload, resp_len, &auth_ok);
        free(resp_payload);
        if (decode_rc != VW_OK) {
            snprintf(error_msg_, sizeof(error_msg_),
                     "Server sent malformed AUTH_OK (err %d). Please retry.", (int)decode_rc);
            state_     = LoginState::Error;
            needs_otp_ = false;
            app.conn().disconnect();
            return;
        }
        if (!auth_ok.is_admin) {
            snprintf(error_msg_, sizeof(error_msg_),
                     "Account '%s' is not an admin account.", username_);
            state_     = LoginState::Error;
            needs_otp_ = false;
            app.conn().disconnect();
            return;
        }
        memset(password_, 0, sizeof(password_));
        memset(otp_code_, 0, sizeof(otp_code_));
        state_     = LoginState::Idle;
        needs_otp_ = false;
        app.on_login_success(host_, (uint16_t)port_, username_, auth_ok);
        return;
    } else if (resp_type == VW_MSG_AUTH_FAIL) {
        vw_payload_auth_fail_t fail{};
        vw_proto_decode_auth_fail((const uint8_t *)resp_payload, resp_len, &fail);
        free(resp_payload);
        if (fail.lockout_remaining_secs > 0)
            snprintf(error_msg_, sizeof(error_msg_),
                     "2FA locked — retry in %u seconds.",
                     (unsigned)fail.lockout_remaining_secs);
        else
            snprintf(error_msg_, sizeof(error_msg_), "Invalid OTP code.");
    } else {
        free(resp_payload);
        snprintf(error_msg_, sizeof(error_msg_),
                 "Unexpected OTP response 0x%04X.", (unsigned)resp_type);
    }

    state_     = LoginState::Error;
    needs_otp_ = false;
    app.conn().disconnect();
}
