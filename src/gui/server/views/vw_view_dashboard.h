#pragma once

#include <cstdint>
#include <cstring>

#include "vw_view_cluster.h"
#include "vw_view_users.h"
#include "vw_view_audit.h"

class ServerApp;

enum class DashboardAction { None, Logout };

class VwViewDashboard {
public:
    VwViewDashboard() = default;

    /* Called by ServerApp immediately after a successful login. */
    void on_connected(const char *host, uint16_t port,
                      const char *username,
                      const uint8_t session_token[32]);

    /* Renders the dashboard. Returns DashboardAction::Logout if the user
     * requests logout or the session expires. */
    DashboardAction render(ServerApp &app);

private:
    char    host_[256]     = {};
    uint16_t port_         = 0;
    char    username_[128] = {};
    uint8_t session_token_[32] = {};

    enum class Tab { Users, Cluster, AuditLog };
    Tab active_tab_ = Tab::Users;

    VwViewCluster cluster_view_;
    VwViewUsers   users_view_;
    VwViewAudit   audit_view_;
};
