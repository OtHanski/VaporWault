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

#ifdef _WIN32
#  include <direct.h>   /* _fullpath */
#else
#  include <limits.h>
#  include <stdlib.h>   /* realpath */
#endif

/* Oplog on-disk entry header size: crc32(4)+payload_len(4)+entry_id(8)+confirmed(1) = 17 bytes.
 * op_type is the first byte of the payload, not part of the header. */
static constexpr uint32_t OPLOG_ENTRY_HDR = 17u;

const char *VwViewAudit::op_type_name(uint8_t op_type)
{
    switch (op_type) {
    case VW_OPLOG_USER_WRITE:    return "User Write";
    case VW_OPLOG_FILE_WRITE:    return "File Write";
    case VW_OPLOG_FILE_DELETE:   return "File Delete";
    case VW_OPLOG_PERM_WRITE:    return "Perm Write";
    case VW_OPLOG_SESSION_WRITE: return "Session Write";
    case VW_OPLOG_CHUNK_WRITE:   return "Chunk Write";
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
    if (ImGui::Button("Search##audit"))
        do_query(app);
    ImGui::SameLine();
    if (ImGui::Button("Export CSV##audit")) {
        last_export_path_.clear();
        last_export_error_.clear();
        export_csv();
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

    ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##audit_table", 3, flags, ImVec2(0, -40))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Entry ID",   ImGuiTableColumnFlags_WidthFixed,  90);
        ImGui::TableSetupColumn("Event Type", ImGuiTableColumnFlags_WidthFixed, 120);
        ImGui::TableSetupColumn("Detail",     ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto &e : entries_) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%llu", (unsigned long long)e.entry_id);
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(op_type_name(e.op_type));
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(e.detail.c_str());
        }
        ImGui::EndTable();
    }

    ImGui::Text("%zu entries shown", entries_.size());
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
        if (remaining < OPLOG_ENTRY_HDR) break;

        uint32_t stored_plen = vw_read_u32le(p + 4);
        uint64_t entry_id    = vw_read_u64le(p + 8);
        uint8_t  op_type     = p[17];  /* confirmed byte at [16], op_type at [17] */

        /* Guard against uint32_t overflow: remaining >= OPLOG_ENTRY_HDR is already
         * checked above, so the subtraction is safe. This also replaces the old
         * post-addition bounds check, which was bypassed on overflow. */
        if (stored_plen > remaining - OPLOG_ENTRY_HDR) break;
        uint32_t entry_total = OPLOG_ENTRY_HDR + stored_plen;

        AuditEntry e;
        e.entry_id = entry_id;
        e.op_type  = op_type;

        /* Build a human-readable detail line from the raw payload. */
        const uint8_t *payload = p + 17 + 1;  /* after op_type byte */
        uint32_t       plen    = stored_plen > 1u ? stored_plen - 1u : 0u;

        char detail_buf[256] = {};
        if (op_type == VW_OPLOG_USER_WRITE && plen >= 8) {
            uint64_t uid = vw_read_u64le(payload);
            snprintf(detail_buf, sizeof(detail_buf), "user_id=%llu",
                     (unsigned long long)uid);
        } else if (op_type == VW_OPLOG_SESSION_WRITE && plen >= 8) {
            uint64_t slot = vw_read_u64le(payload);
            snprintf(detail_buf, sizeof(detail_buf), "session_slot=%llu",
                     (unsigned long long)slot);
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

void VwViewAudit::export_csv()
{
    /* Build a timestamped filename in the current working directory. */
    char filename[64];
    time_t now = time(nullptr);
    struct tm *tm_info = localtime(&now);
    if (tm_info)
        strftime(filename, sizeof(filename), "audit_export_%Y%m%d_%H%M%S.csv", tm_info);
    else
        snprintf(filename, sizeof(filename), "audit_export_%llu.csv",
                 (unsigned long long)(uint64_t)entries_.size());

    FILE *f = fopen(filename, "w");
    if (!f) {
        last_export_error_ = std::string("Export failed: ") + strerror(errno);
        return;
    }

    fprintf(f, "EntryID,EventType,Detail\n");
    for (const auto &e : entries_) {
        fprintf(f, "%llu,%s,\"%s\"\n",
                (unsigned long long)e.entry_id,
                op_type_name(e.op_type),
                e.detail.c_str());
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
