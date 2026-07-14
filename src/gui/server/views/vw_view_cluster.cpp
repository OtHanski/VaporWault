#include "vw_view_cluster.h"
#include "../ServerApp.h"
#include "imgui.h"

extern "C" {
#include "vw_proto.h"
}

#include <cstring>
#include <cstdio>
#include <cstdlib>

/* Per-node entry wire size: node_id(8)+is_active(1)+role(1)+swm(8)+lag(8)+hostname(128) = 154 */
static constexpr uint32_t CLUSTER_NODE_ENTRY = 154u;

void VwViewCluster::on_connected()
{
    state_           = State::Idle;
    our_role_        = 0;
    last_fetch_time_ = 0.0;
    error_msg_[0]    = '\0';
    nodes_.clear();
}

bool VwViewCluster::parse_resp(const uint8_t *buf, uint32_t len)
{
    /* Minimum: role(1) + count(4) = 5 bytes. */
    if (len < 5u) return false;

    our_role_ = buf[0];
    uint32_t count = vw_read_u32le(buf + 1);

    if (len < 5u + count * CLUSTER_NODE_ENTRY) return false;

    nodes_.clear();
    const uint8_t *p = buf + 5;
    for (uint32_t i = 0; i < count; i++) {
        ClusterNodeEntry e;
        e.node_id        = vw_read_u64le(p);
        e.is_active      = p[8];
        e.role           = p[9];
        e.sync_watermark = vw_read_u64le(p + 10);
        e.lag_entries    = vw_read_u64le(p + 18);
        memcpy(e.hostname, p + 26, 128);
        e.hostname[128]  = '\0';
        nodes_.push_back(e);
        p += CLUSTER_NODE_ENTRY;
    }
    return true;
}

void VwViewCluster::do_fetch(ServerApp &app)
{
    error_msg_[0] = '\0';
    state_         = State::Fetching;

    /* Request: session_token(32) only. */
    uint8_t req[32];
    memcpy(req, app.session_token(), 32);

    vw_err_t rc = app.conn().send_msg(VW_MSG_CLUSTER_STATUS, req, sizeof(req));
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

    if (rtype != VW_MSG_CLUSTER_STATUS_RESP) {
        free(rbuf);
        snprintf(error_msg_, sizeof(error_msg_), "unexpected response 0x%04x", (unsigned)rtype);
        state_ = State::Error;
        return;
    }

    bool ok = parse_resp((const uint8_t *)rbuf, rlen);
    free(rbuf);
    if (!ok) {
        snprintf(error_msg_, sizeof(error_msg_), "malformed CLUSTER_STATUS_RESP");
        state_ = State::Error;
        return;
    }

    last_fetch_time_ = ImGui::GetTime();
    state_ = State::Ready;
}

bool VwViewCluster::render(ServerApp &app)
{
    /* Auto-fetch on first render or when auto-refresh fires. */
    double now = ImGui::GetTime();
    bool should_fetch = (state_ == State::Idle);
    if (!should_fetch && auto_refresh_ && state_ == State::Ready) {
        if (now - last_fetch_time_ >= (double)refresh_interval_)
            should_fetch = true;
    }
    if (should_fetch)
        do_fetch(app);

    /* ── Role banner ──────────────────────────────────────────────────── */
    ImGui::Spacing();
    if (our_role_ == 1) {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.2f, 0.9f, 0.2f, 1.0f));
        ImGui::Text("  PRIMARY");
        ImGui::PopStyleColor();
    } else {
        ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.3f, 0.6f, 1.0f, 1.0f));
        ImGui::Text("  REPLICA");
        ImGui::PopStyleColor();
    }

    /* ── Controls ─────────────────────────────────────────────────────── */
    ImGui::SameLine(120);
    if (ImGui::Button("Refresh##cluster"))
        do_fetch(app);
    ImGui::SameLine();
    ImGui::Checkbox("Auto-refresh (5 s)##cluster", &auto_refresh_);

    if (state_ == State::Error) {
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Error: %s", error_msg_);
        return false;
    }

    if (state_ == State::Fetching) {
        ImGui::Text("Loading...");
        return false;
    }

    /* ── Node table ───────────────────────────────────────────────────── */
    ImGui::Spacing();

    ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##cluster_table", 6, flags, ImVec2(0, -40))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Node ID",        ImGuiTableColumnFlags_WidthFixed,   90);
        ImGui::TableSetupColumn("Hostname",        ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Role",            ImGuiTableColumnFlags_WidthFixed,   60);
        ImGui::TableSetupColumn("Status",          ImGuiTableColumnFlags_WidthFixed,   70);
        ImGui::TableSetupColumn("Sync Watermark",  ImGuiTableColumnFlags_WidthFixed,  120);
        ImGui::TableSetupColumn("Lag (entries)",   ImGuiTableColumnFlags_WidthFixed,  100);
        ImGui::TableHeadersRow();

        for (const auto &n : nodes_) {
            ImGui::TableNextRow();

            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%016llx", (unsigned long long)n.node_id);

            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(n.hostname);

            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(n.role == 1 ? "Primary" : "Replica");

            ImGui::TableSetColumnIndex(3);
            if (n.is_active) {
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.2f, 0.9f, 0.2f, 1.0f));
                ImGui::TextUnformatted("Active");
                ImGui::PopStyleColor();
            } else {
                ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "Inactive");
            }

            ImGui::TableSetColumnIndex(4);
            ImGui::Text("%llu", (unsigned long long)n.sync_watermark);

            ImGui::TableSetColumnIndex(5);
            ImVec4 lag_colour;
            if (n.lag_entries == 0)
                lag_colour = ImVec4(0.2f, 0.9f, 0.2f, 1.0f);   /* green */
            else if (n.lag_entries < 1000)
                lag_colour = ImVec4(1.0f, 0.85f, 0.0f, 1.0f);  /* yellow */
            else
                lag_colour = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);   /* red */
            ImGui::PushStyleColor(ImGuiCol_Text, lag_colour);
            ImGui::Text("%llu entries", (unsigned long long)n.lag_entries);
            ImGui::PopStyleColor();
        }
        ImGui::EndTable();
    }

    ImGui::Text("%zu node(s)", nodes_.size());
    return false;
}
