#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

class ServerApp;

struct UserEntry {
    uint64_t    user_id      = 0;
    bool        is_admin     = false;
    bool        is_active    = true;
    char        username[65] = {};
    char        email[129]   = {};
    uint64_t    quota_bytes  = 0;
    uint64_t    used_bytes   = 0;
};

class VwViewUsers {
public:
    VwViewUsers() = default;

    /* Call once when the dashboard connects (reset cached state). */
    void on_connected();

    /* Renders the Users tab. Returns true if the session expired and the
     * dashboard should transition back to the login view. */
    bool render(ServerApp &app);

private:
    enum class State {
        Idle,
        FetchingList,
        ListReady,
        SuspendPending,
        QuotaModalOpen,
        Error,
    };

    void do_fetch(ServerApp &app);
    void do_suspend(ServerApp &app, uint64_t uid, bool active);
    void do_set_quota(ServerApp &app, uint64_t uid, uint64_t quota);

    bool parse_list_resp(const uint8_t *buf, uint32_t len);

    State                state_          = State::Idle;
    char                 filter_[128]    = {};
    std::vector<UserEntry> users_;
    uint32_t             page_offset_    = 0;
    static constexpr uint32_t kPageSize  = 50;

    /* Quota modal state */
    uint64_t             quota_modal_uid_ = 0;
    char                 quota_input_[32] = {};

    /* Error / status display */
    char                 error_msg_[256]  = {};
};
