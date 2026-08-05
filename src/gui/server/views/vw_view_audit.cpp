#include "vw_view_audit.h"
#include "../ServerApp.h"
#include "imgui.h"

extern "C" {
#include "vw_proto.h"
#include "vw_oplog.h"
}

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <cerrno>
#include <cctype>

#ifdef _WIN32
#  include <direct.h>   /* _fullpath */
#else
#  include <limits.h>
#  include <stdlib.h>   /* realpath */
#endif

/* Oplog on-disk entry header size (protocol v17, docs/PROTOCOL.md §7.7):
 * crc32(4)+payload_len(4)+entry_id(8)+ts_unix_secs(8)+confirmed(1) = 25 bytes.
 * op_type is the first byte of the payload, not part of the header.
 * Use vw_oplog.h's public VW_OPLOG_ENTRY_HDR_BYTES here rather than a private
 * copy — TASK-121/TASK-122's v17 migration found three divergent hardcoded
 * copies of this constant across the codebase, one of which had silently
 * gone stale; this file was one of them. */

/* Formats an advisory oplog ts_unix_secs (TASK-121) as local time for display
 * and CSV export. 0 means "not present" (defensive — every v17 entry carries
 * one, but a malformed/legacy entry could not). */
static std::string format_ts_local(uint64_t ts_unix_secs)
{
    if (ts_unix_secs == 0) return "-";
    time_t     t  = (time_t)ts_unix_secs;
    struct tm *tm_info = localtime(&t);
    if (!tm_info) return "-";
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
    return buf;
}

/* Parses "YYYY-MM-DD" or "YYYY-MM-DD HH:MM[:SS]" (local time) into a unix
 * timestamp. Returns false (leaving *out untouched) for an empty or
 * unparsable string, so callers can treat that side of the range as
 * unbounded. */
static bool parse_ts_local(const char *s, uint64_t *out)
{
    if (!s || !*s) return false;
    struct tm tmv;
    memset(&tmv, 0, sizeof(tmv));
    tmv.tm_isdst = -1;
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, se = 0;
    int n = sscanf(s, "%d-%d-%d %d:%d:%d", &y, &mo, &d, &h, &mi, &se);
    if (n < 3) return false;  /* need at least a full date */
    tmv.tm_year = y - 1900;
    tmv.tm_mon  = mo - 1;
    tmv.tm_mday = d;
    tmv.tm_hour = h;
    tmv.tm_min  = mi;
    tmv.tm_sec  = se;
    time_t t = mktime(&tmv);
    if (t == (time_t)-1) return false;
    *out = (uint64_t)t;
    return true;
}

const char *VwViewAudit::op_type_name(uint8_t op_type)
{
    switch (op_type) {
    case VW_OPLOG_USER_WRITE:    return "User Write";
    case VW_OPLOG_FILE_WRITE:    return "File Write (legacy)"; /* retired 0x02, pre-v17 only */
    case VW_OPLOG_FILE_DELETE:   return "File Delete";
    case VW_OPLOG_PERM_WRITE:    return "Perm Write";
    case VW_OPLOG_SESSION_WRITE: return "Session Write";
    case VW_OPLOG_CHUNK_WRITE:   return "Chunk Write";
    case VW_OPLOG_VAULT_WRITE:   return "Vault Write";
    case VW_OPLOG_FILE_CREATE:   return "File Create";
    case VW_OPLOG_FILE_UPDATE:   return "File Update";
    case VW_OPLOG_FILE_VERSION:  return "File Version";
    default:                     return "Unknown";
    }
}

void VwViewAudit::on_connected()
{
    state_            = State::Idle;
    error_msg_[0]     = '\0';
    last_export_path_.clear();
    last_export_error_.clear();
    entries_.clear();
    filter_op_type_   = -1;
    filter_user_[0]   = '\0';
    filter_text_[0]   = '\0';
    filter_ts_from_[0] = '\0';
    filter_ts_to_[0]   = '\0';
}

bool VwViewAudit::render(ServerApp &app)
{
    if (state_ == State::Idle)
        do_query(app);

    ImGui::Spacing();
    ImGui::Text("Last entries:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(80);
    int max_e = (int)max_entries_;
    if (ImGui::InputInt("##max_entries", &max_e, 0, 0)) {
        if (max_e < 1) max_e = 1;
        if (max_e > 256) max_e = 256;
        max_entries_ = (uint32_t)max_e;
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh##audit"))
        do_query(app);

    /* Client-side filters over the currently-loaded page. AUDIT_QUERY has no
     * server-side filtering beyond max_entries (see docs/PROTOCOL.md), so
     * narrowing by type/user/text happens here rather than re-querying. */
    static const char *kTypeNames[] = {
        "All types", "User Write", "File Create", "File Update", "File Version",
        "File Delete", "Perm Write", "Session Write", "Chunk Write", "Vault Write",
    };
    static const uint8_t kTypeValues[] = {
        0, VW_OPLOG_USER_WRITE, VW_OPLOG_FILE_CREATE, VW_OPLOG_FILE_UPDATE,
        VW_OPLOG_FILE_VERSION, VW_OPLOG_FILE_DELETE, VW_OPLOG_PERM_WRITE,
        VW_OPLOG_SESSION_WRITE, VW_OPLOG_CHUNK_WRITE, VW_OPLOG_VAULT_WRITE,
    };
    int type_idx = 0;
    if (filter_op_type_ >= 0) {
        for (int i = 1; i < (int)(sizeof(kTypeValues) / sizeof(kTypeValues[0])); i++) {
            if (kTypeValues[i] == filter_op_type_) { type_idx = i; break; }
        }
    }
    ImGui::SetNextItemWidth(140);
    if (ImGui::Combo("##filter_type", &type_idx, kTypeNames, (int)(sizeof(kTypeNames) / sizeof(kTypeNames[0]))))
        filter_op_type_ = (type_idx == 0) ? -1 : (int)kTypeValues[type_idx];

    ImGui::SameLine();
    ImGui::SetNextItemWidth(100);
    ImGui::InputTextWithHint("##filter_user", "User/owner id", filter_user_, sizeof(filter_user_),
                              ImGuiInputTextFlags_CharsDecimal);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Matches entries with an attributable user/owner id\n"
                           "(User Write, File Create, Perm/Vault Write). File\n"
                           "Update/Version and File Delete carry a file id, not a\n"
                           "user id; Session Write carries a session slot — all\n"
                           "three are excluded from this filter when it's set.");

    ImGui::SameLine();
    ImGui::SetNextItemWidth(200);
    ImGui::InputTextWithHint("##filter_text", "Search detail / event type", filter_text_, sizeof(filter_text_));

    ImGui::Text("From:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(150);
    ImGui::InputTextWithHint("##filter_ts_from", "YYYY-MM-DD [HH:MM]",
                              filter_ts_from_, sizeof(filter_ts_from_));
    ImGui::SameLine();
    ImGui::Text("To:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(150);
    ImGui::InputTextWithHint("##filter_ts_to", "YYYY-MM-DD [HH:MM]",
                              filter_ts_to_, sizeof(filter_ts_to_));
    if (ImGui::IsItemHovered() || ImGui::IsItemActive())
        ImGui::SetTooltip("Local time, inclusive. Filters on the oplog's advisory\n"
                           "append timestamp (TASK-121) — not authoritative for\n"
                           "ordering, just for narrowing this view.");

    ImGui::SameLine();
    if (ImGui::Button("Export CSV##audit")) {
        last_export_path_.clear();
        last_export_error_.clear();
        export_csv(filtered_entries());
    }
    if (!last_export_path_.empty())
        ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f),
                           "Exported: %s", last_export_path_.c_str());
    if (!last_export_error_.empty())
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f),
                           "%s", last_export_error_.c_str());

    if (state_ == State::Error) {
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Error: %s", error_msg_);
        return false;
    }

    ImGui::Spacing();

    std::vector<const AuditEntry *> visible = filtered_entries();

    ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##audit_table", 4, flags, ImVec2(0, -40))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Entry ID",   ImGuiTableColumnFlags_WidthFixed,  90);
        ImGui::TableSetupColumn("Time",       ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Event Type", ImGuiTableColumnFlags_WidthFixed, 120);
        ImGui::TableSetupColumn("Detail",     ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto *e : visible) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%llu", (unsigned long long)e->entry_id);
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(format_ts_local(e->ts_unix_secs).c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(op_type_name(e->op_type));
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(e->detail.c_str());
        }
        ImGui::EndTable();
    }

    ImGui::Text("%zu of %zu entries shown", visible.size(), entries_.size());
    return false;
}

bool VwViewAudit::parse_audit_resp(const uint8_t *buf, uint32_t len)
{
    if (len < 4) return false;
    uint32_t count = vw_read_u32le(buf);

    entries_.clear();
    const uint8_t *p         = buf + 4;
    uint32_t       remaining = len - 4;

    for (uint32_t i = 0; i < count; i++) {
        if (remaining < VW_OPLOG_ENTRY_HDR_BYTES) break;

        uint32_t stored_plen = vw_read_u32le(p + 4);
        uint64_t entry_id    = vw_read_u64le(p + 8);
        uint64_t ts_secs     = vw_read_u64le(p + 16);       /* ts_unix_secs, offset 16 */
        uint8_t  op_type     = p[VW_OPLOG_ENTRY_HDR_BYTES]; /* confirmed byte at [24], op_type at [25] */

        /* Guard against uint32_t overflow: remaining >= VW_OPLOG_ENTRY_HDR_BYTES is
         * already checked above, so the subtraction is safe. This also replaces the
         * old post-addition bounds check, which was bypassed on overflow. */
        if (stored_plen > remaining - VW_OPLOG_ENTRY_HDR_BYTES) break;
        uint32_t entry_total = VW_OPLOG_ENTRY_HDR_BYTES + stored_plen;

        AuditEntry e;
        e.entry_id     = entry_id;
        e.op_type      = op_type;
        e.ts_unix_secs = ts_secs;

        /* Build a human-readable detail line from the raw payload. */
        const uint8_t *payload = p + VW_OPLOG_ENTRY_HDR_BYTES + 1;  /* after op_type byte */
        uint32_t       plen    = stored_plen > 1u ? stored_plen - 1u : 0u;

        char detail_buf[256] = {};
        if (op_type == VW_OPLOG_USER_WRITE && plen >= 8) {
            uint64_t uid = vw_read_u64le(payload);
            snprintf(detail_buf, sizeof(detail_buf), "user_id=%llu",
                     (unsigned long long)uid);
            e.subject_id = uid;
            e.has_subject = true;
        } else if (op_type == VW_OPLOG_SESSION_WRITE && plen >= 8) {
            uint64_t slot = vw_read_u64le(payload);
            snprintf(detail_buf, sizeof(detail_buf), "session_slot=%llu",
                     (unsigned long long)slot);
            /* Not a user id — a session slot index — so left unattributed
             * for the purposes of the user filter. */
        } else if ((op_type == VW_OPLOG_PERM_WRITE || op_type == VW_OPLOG_VAULT_WRITE) &&
                   plen >= 8) {
            uint64_t owner = vw_read_u64le(payload);
            snprintf(detail_buf, sizeof(detail_buf), "owner_id=%llu",
                     (unsigned long long)owner);
            e.subject_id = owner;
            e.has_subject = true;
        } else if (op_type == VW_OPLOG_FILE_CREATE && plen >= 8) {
            /* Unambiguous as of protocol v17 (TASK-122) — payload is owner_id.
             * Restores the "did user X create file Y" capability that was
             * lost when FILE_WRITE's ambiguity forced this to be unattributed. */
            uint64_t owner = vw_read_u64le(payload);
            snprintf(detail_buf, sizeof(detail_buf), "owner_id=%llu",
                     (unsigned long long)owner);
            e.subject_id = owner;
            e.has_subject = true;
        } else if ((op_type == VW_OPLOG_FILE_UPDATE || op_type == VW_OPLOG_FILE_VERSION) &&
                   plen >= 8) {
            /* Payload is file_id, not a user/owner id — same treatment as
             * FILE_DELETE below: shown, but excluded from the user filter. */
            uint64_t fid = vw_read_u64le(payload);
            snprintf(detail_buf, sizeof(detail_buf), "file_id=%llu",
                     (unsigned long long)fid);
        } else if (op_type == VW_OPLOG_FILE_WRITE && plen >= 8) {
            /* Retired pre-v17 op_type (TASK-122) — only reachable from an
             * entry written before this cluster's oplog-format cutover.
             * Payload meaning is still ambiguous for these, so left
             * unattributed rather than mislabeled. */
            uint64_t ref = vw_read_u64le(payload);
            snprintf(detail_buf, sizeof(detail_buf), "ref_id=%llu",
                     (unsigned long long)ref);
        } else if (op_type == VW_OPLOG_FILE_DELETE && plen >= 8) {
            uint64_t fid = vw_read_u64le(payload);
            snprintf(detail_buf, sizeof(detail_buf), "file_id=%llu",
                     (unsigned long long)fid);
        } else if (plen > 0) {
            /* Hex dump first 16 bytes. */
            uint32_t show = plen < 16u ? plen : 16u;
            int off = 0;
            for (uint32_t b = 0; b < show && off < (int)sizeof(detail_buf) - 3; b++)
                off += snprintf(detail_buf + off, sizeof(detail_buf) - (size_t)off,
                                "%02x ", payload[b]);
        } else {
            snprintf(detail_buf, sizeof(detail_buf), "(no payload)");
        }
        e.detail = detail_buf;

        entries_.push_back(e);
        p         += entry_total;
        remaining -= entry_total;
    }
    return true;
}

void VwViewAudit::do_query(ServerApp &app)
{
    error_msg_[0] = '\0';

    uint8_t req[36];
    const uint8_t *tok = app.session_token();
    memcpy(req, tok, 32);
    vw_write_u32le(req + 32, max_entries_);

    vw_err_t rc = app.conn().send_msg(VW_MSG_AUDIT_QUERY, req, sizeof(req));
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_), "send failed: %d", (int)rc);
        state_ = State::Error;
        return;
    }

    vw_msg_type_t rtype;
    void         *rbuf = nullptr;
    uint32_t      rlen = 0;
    rc = app.conn().recv_msg(&rtype, &rbuf, &rlen);
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_), "recv failed: %d", (int)rc);
        state_ = State::Error;
        return;
    }

    if (rtype == VW_MSG_ERROR) {
        uint32_t code = (rlen >= 4) ? vw_read_u32le((const uint8_t *)rbuf) : 0;
        free(rbuf);
        snprintf(error_msg_, sizeof(error_msg_), "server error: %u", code);
        state_ = State::Error;
        return;
    }

    if (rtype != VW_MSG_AUDIT_RESP) {
        free(rbuf);
        snprintf(error_msg_, sizeof(error_msg_), "unexpected response 0x%04x", (unsigned)rtype);
        state_ = State::Error;
        return;
    }

    bool ok = parse_audit_resp((const uint8_t *)rbuf, rlen);
    free(rbuf);
    if (!ok) {
        snprintf(error_msg_, sizeof(error_msg_), "malformed AUDIT_RESP");
        state_ = State::Error;
        return;
    }
    state_ = State::Ready;
}

static bool ci_contains(const char *haystack, const char *needle)
{
    if (!needle || !*needle) return true;
    size_t hlen = strlen(haystack), nlen = strlen(needle);
    if (nlen > hlen) return false;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        size_t j = 0;
        for (; j < nlen; j++) {
            if (tolower((unsigned char)haystack[i + j]) != tolower((unsigned char)needle[j]))
                break;
        }
        if (j == nlen) return true;
    }
    return false;
}

bool VwViewAudit::passes_filters(const AuditEntry &e) const
{
    if (filter_op_type_ >= 0 && e.op_type != (uint8_t)filter_op_type_)
        return false;

    if (filter_user_[0] != '\0') {
        if (!e.has_subject) return false;
        char *endp = nullptr;
        uint64_t want = strtoull(filter_user_, &endp, 10);
        if (endp == filter_user_ || e.subject_id != want)
            return false;
    }

    if (filter_text_[0] != '\0') {
        bool in_detail = ci_contains(e.detail.c_str(), filter_text_);
        bool in_type    = ci_contains(op_type_name(e.op_type), filter_text_);
        if (!in_detail && !in_type)
            return false;
    }

    uint64_t ts_from = 0, ts_to = 0;
    if (parse_ts_local(filter_ts_from_, &ts_from) && e.ts_unix_secs < ts_from)
        return false;
    if (parse_ts_local(filter_ts_to_, &ts_to) && e.ts_unix_secs > ts_to)
        return false;

    return true;
}

std::vector<const AuditEntry *> VwViewAudit::filtered_entries() const
{
    std::vector<const AuditEntry *> out;
    out.reserve(entries_.size());
    for (const auto &e : entries_) {
        if (passes_filters(e))
            out.push_back(&e);
    }
    return out;
}

void VwViewAudit::export_csv(const std::vector<const AuditEntry *> &rows)
{
    /* Build a timestamped filename in the current working directory. */
    char filename[64];
    time_t now = time(nullptr);
    struct tm *tm_info = localtime(&now);
    if (tm_info)
        strftime(filename, sizeof(filename), "audit_export_%Y%m%d_%H%M%S.csv", tm_info);
    else
        snprintf(filename, sizeof(filename), "audit_export_%llu.csv",
                 (unsigned long long)(uint64_t)rows.size());

    FILE *f = fopen(filename, "w");
    if (!f) {
        last_export_error_ = std::string("Export failed: ") + strerror(errno);
        return;
    }

    fprintf(f, "EntryID,Time,EventType,Detail\n");
    for (const auto *e : rows) {
        fprintf(f, "%llu,%s,%s,\"%s\"\n",
                (unsigned long long)e->entry_id,
                format_ts_local(e->ts_unix_secs).c_str(),
                op_type_name(e->op_type),
                e->detail.c_str());
    }
    fclose(f);

    /* Resolve and store the full path for display in the UI. */
#ifdef _WIN32
    char full_path[4096] = {};
    if (_fullpath(full_path, filename, sizeof(full_path)))
        last_export_path_ = full_path;
    else
        last_export_path_ = filename;
#else
    char full_path[PATH_MAX] = {};
    if (realpath(filename, full_path))
        last_export_path_ = full_path;
    else
        last_export_path_ = filename;
#endif
}
