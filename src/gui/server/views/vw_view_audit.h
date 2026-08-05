#pragma once

#include <cstdint>
#include <vector>
#include <string>

class ServerApp;

struct AuditEntry {
    uint64_t    entry_id     = 0;
    uint8_t     op_type      = 0;
    uint64_t    ts_unix_secs = 0;      /* append time (protocol v17, TASK-121); advisory only */
    uint64_t    subject_id   = 0;      /* user/owner id, when op_type carries one */
    bool        has_subject  = false;
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
    void export_csv(const std::vector<const AuditEntry *> &rows);
    bool passes_filters(const AuditEntry &e) const;
    std::vector<const AuditEntry *> filtered_entries() const;

    static const char *op_type_name(uint8_t op_type);

    enum class State { Idle, Ready, Error };

    State                    state_          = State::Idle;
    uint32_t                 max_entries_    = 100;
    std::vector<AuditEntry>  entries_;
    char                     error_msg_[256] = {};
    std::string              last_export_path_;
    std::string              last_export_error_;

    /* Client-side filters, applied over the currently-loaded page of
     * entries_. AUDIT_QUERY only takes a max_entries count server-side
     * (see docs/PROTOCOL.md), so filtering by user/type/text happens here
     * rather than round-tripping to the server. */
    int                      filter_op_type_  = -1;   /* -1 = all types */
    char                     filter_user_[32] = {};   /* decimal user/owner id, empty = any */
    char                     filter_text_[128] = {};  /* substring match against detail/type */

    /* Date/time-range filter (TASK-121/TASK-124), matched against
     * AuditEntry::ts_unix_secs. Accepts "YYYY-MM-DD" or "YYYY-MM-DD HH:MM[:SS]"
     * in local time; empty = unbounded on that side. */
    char                     filter_ts_from_[32] = {};
    char                     filter_ts_to_[32]   = {};
};
