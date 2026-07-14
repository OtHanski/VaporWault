#include "ServerApp.h"
#include "imgui.h"
#include <cstring>
#include <cstdio>

ServerApp::ServerApp() = default;

void ServerApp::render_frame()
{
    switch (state_) {
    case ServerAppView::Disconnected:
        login_view_.render(*this);
        break;

    case ServerAppView::Connected:
        if (dashboard_view_.render(*this) == DashboardAction::Logout) {
            on_session_expired();
        }
        break;
    }
}

void ServerApp::on_login_success(const char *host, uint16_t port,
                                  const char *username,
                                  const vw_payload_auth_ok_t &auth_ok)
{
    snprintf(connected_host_, sizeof(connected_host_), "%s", host);
    connected_port_ = port;
    snprintf(connected_username_, sizeof(connected_username_), "%s", username);
    memcpy(session_token_, auth_ok.session_token, 32);
    user_id_ = auth_ok.user_id;

    dashboard_view_.on_connected(connected_host_, connected_port_,
                                 connected_username_, session_token_);
    state_ = ServerAppView::Connected;
}

void ServerApp::on_session_expired()
{
    conn_.disconnect();
    memset(session_token_, 0, sizeof(session_token_));
    user_id_ = 0;
    state_   = ServerAppView::Disconnected;
}
