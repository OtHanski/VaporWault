#pragma once

#include <cstdint>
#include <vector>
#include <string>

class ServerApp;

struct ClusterNodeEntry {
    uint64_t    node_id;
    uint8_t     is_active;
    uint8_t     role;           /* 0=replica, 1=primary */
    uint64_t    sync_watermark;
    uint64_t    lag_entries;
    char        hostname[129];  /* 128-byte NUL-padded field + NUL */
};

class VwViewCluster {
public:
    VwViewCluster() = default;

    void on_connected();
    /* Returns true if the session expired. */
    bool render(ServerApp &app);

private:
    enum class State { Idle, Fetching, Ready, Error };

    void do_fetch(ServerApp &app);
    bool parse_resp(const uint8_t *buf, uint32_t len);

    State    state_            = State::Idle;
    uint8_t  our_role_         = 0;       /* 0=replica, 1=primary */
    std::vector<ClusterNodeEntry> nodes_;

    bool     auto_refresh_     = true;
    int      refresh_interval_ = 5;      /* seconds */
    double   last_fetch_time_  = 0.0;    /* ImGui time of last fetch */

    char     error_msg_[256]   = {};
};
