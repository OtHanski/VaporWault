#pragma once

extern "C" {
#include "vw_proto.h"
}

class ServerApp;

class VwViewLogin {
public:
    VwViewLogin() = default;

    /* Renders the login form. Calls app.on_login_success() on success. */
    void render(ServerApp &app);

private:
    char    host_[256]     = "localhost";
    int     port_          = 9000;
    char    ca_cert_[512]  = "";
    char    username_[128] = "";
    char    password_[256] = "";
    char    otp_code_[16]  = "";

    enum class LoginState { Idle, Connecting, AwaitingOtp, Error };
    LoginState state_       = LoginState::Idle;
    bool       needs_otp_   = false;
    char       error_msg_[256] = "";

    void do_connect(ServerApp &app);
    void do_otp(ServerApp &app);
};
