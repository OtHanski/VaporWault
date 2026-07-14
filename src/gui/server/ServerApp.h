#pragma once

/*
 * ServerApp — top-level application state for the VaporWault server GUI.
 *
 * Two states:
 *   DISCONNECTED — shows the login view (connect + authenticate as admin).
 *   CONNECTED    — shows the dashboard (user management, cluster, audit log).
 *
 * All server communication goes through conn_; no protocol logic in views.
 */

#include "vw_server_conn.h"
#include "views/vw_view_login.h"
#include "views/vw_view_dashboard.h"

enum class ServerAppView { Disconnected, Connected };

class ServerApp {
public:
    ServerApp();
    ~ServerApp() = default;

    ServerApp(const ServerApp &) = delete;
    ServerApp &operator=(const ServerApp &) = delete;

    /* Call once per frame — renders the active view. */
    void render_frame();

    /* Called by the login view on successful admin authentication. */
    void on_login_success(const char *host, uint16_t port,
                          const char *username,
                          const vw_payload_auth_ok_t &auth_ok);

    /* Called by any view when the session expires or connection drops. */
    void on_session_expired();

    VwServerConn &conn() { return conn_; }

    /* Returns the current session token (32 bytes). Valid only when Connected. */
    const uint8_t *session_token() const { return session_token_; }

private:
    VwServerConn    conn_;
    ServerAppView   state_    = ServerAppView::Disconnected;

    VwViewLogin     login_view_;
    VwViewDashboard dashboard_view_;

    /* Connected-session info (cleared on disconnect). */
    char     connected_host_[256]     = {};
    uint16_t connected_port_          = 0;
    char     connected_username_[128] = {};
    uint8_t  session_token_[32]       = {};
    uint64_t user_id_                 = 0;
};
