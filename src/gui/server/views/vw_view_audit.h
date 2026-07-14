#pragma once

#include <cstdint>
#include <vector>
#include <string>

class ServerApp;

struct AuditEntry {
    uint64_t    entry_id   = 0;
    uint8_t     op_type    = 0;
    std::string detail;   /* human-readable description */
};

class VwViewAudit {
public:
    VwViewAudit() = default;

    /* Call once when the dashboard connects (reset cached state). */
    void on_connected();

    /* Renders the Audit Log tab.
     * Returns true if the session has expired. */
    bool render(ServerApp &app);

private:
    void do_query(ServerApp &app);
    bool parse_audit_resp(const uint8_t *buf, uint32_t len);
    void export_csv() const;

    static const char *op_type_name(uint8_t op_type);

    enum class State { Idle, Ready, Error };

    State                    state_          = State::Idle;
    uint32_t                 max_entries_    = 100;
    std::vector<AuditEntry>  entries_;
    char                     error_msg_[256] = {};
};
