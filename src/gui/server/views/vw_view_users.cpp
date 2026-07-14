#include "vw_view_users.h"
#include "../ServerApp.h"
#include "imgui.h"

extern "C" {
#include "vw_proto.h"
}

#include <cstring>
#include <cstdio>
#include <cstdlib>

static constexpr uint32_t ULIST_ENTRY_WIRE = 220u;

void VwViewUsers::on_connected()
{
    state_            = State::Idle;
    page_offset_      = 0;
    filter_[0]        = '\0';
    error_msg_[0]     = '\0';
    session_expired_  = false;
    users_.clear();
}

bool VwViewUsers::render(ServerApp &app)
{
    if (session_expired_) return true;

    if (state_ == State::Idle) {
        /* Auto-fetch on first render. */
        do_fetch(app);
    }
    if (session_expired_) return true;

    ImGui::Spacing();

    /* Filter input + Refresh */
    ImGui::SetNextItemWidth(250.0f);
    ImGui::InputText("Filter##users", filter_, sizeof(filter_));
    ImGui::SameLine();
    if (ImGui::Button("Refresh##users"))
        do_fetch(app);

    if (state_ == State::Error) {
        ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Error: %s", error_msg_);
        return false;
    }

    ImGui::Spacing();

    /* Pagination controls */
    ImGui::Text("Page offset: %u", page_offset_);
    ImGui::SameLine();
    if (page_offset_ > 0) {
        if (ImGui::Button("<< Prev##users")) {
            page_offset_ = (page_offset_ >= kPageSize) ? page_offset_ - kPageSize : 0;
            do_fetch(app);
        }
        ImGui::SameLine();
    }
    if ((uint32_t)users_.size() == kPageSize) {
        if (ImGui::Button("Next >>##users")) {
            page_offset_ += kPageSize;
            do_fetch(app);
        }
    }

    ImGui::Spacing();

    /* User table */
    ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;
    if (ImGui::BeginTable("##user_table", 8, flags, ImVec2(0, -60))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("ID",       ImGuiTableColumnFlags_WidthFixed,  60);
        ImGui::TableSetupColumn("Username", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Email",    ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Quota",    ImGuiTableColumnFlags_WidthFixed,  80);
        ImGui::TableSetupColumn("Used",     ImGuiTableColumnFlags_WidthFixed,  80);
        ImGui::TableSetupColumn("% Used",   ImGuiTableColumnFlags_WidthFixed, 100);
        ImGui::TableSetupColumn("Status",   ImGuiTableColumnFlags_WidthFixed,  80);
        ImGui::TableSetupColumn("Actions",  ImGuiTableColumnFlags_WidthFixed, 160);
        ImGui::TableHeadersRow();

        for (auto &u : users_) {
            /* Client-side filter */
            if (filter_[0] != '\0') {
                if (!strstr(u.username, filter_) && !strstr(u.email, filter_))
                    continue;
            }

            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%llu", (unsigned long long)u.user_id);

            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(u.username);

            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(u.email);

            ImGui::TableSetColumnIndex(3);
            if (u.quota_bytes == 0)
                ImGui::TextUnformatted("Unlimited");
            else
                ImGui::Text("%.1f MB", (double)u.quota_bytes / (1024.0 * 1024.0));

            ImGui::TableSetColumnIndex(4);
            ImGui::Text("%.1f MB", (double)u.used_bytes / (1024.0 * 1024.0));

            ImGui::TableSetColumnIndex(5);
            if (u.quota_bytes > 0) {
                float pct = (float)u.used_bytes / (float)u.quota_bytes;
                ImVec4 color = (pct < 0.75f) ? ImVec4(0.2f, 0.8f, 0.2f, 1.0f)
                             : (pct < 0.90f) ? ImVec4(1.0f, 0.8f, 0.0f, 1.0f)
                                             : ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
                ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color);
                char label[16];
                snprintf(label, sizeof(label), "%.0f%%", pct * 100.0f);
                ImGui::ProgressBar(pct, ImVec2(-1, 0), label);
                ImGui::PopStyleColor();
            } else {
                ImGui::TextUnformatted("—");
            }

            ImGui::TableSetColumnIndex(6);
            if (u.is_active)
                ImGui::TextColored(ImVec4(0.2f, 0.9f, 0.2f, 1.0f), "Active");
            else
                ImGui::TextColored(ImVec4(1.0f, 0.3f, 0.3f, 1.0f), "Suspended");

            ImGui::TableSetColumnIndex(7);
            ImGui::PushID((int)(int64_t)u.user_id);

            const char *toggle_label = u.is_active ? "Suspend" : "Unsuspend";
            if (ImGui::SmallButton(toggle_label))
                do_suspend(app, u.user_id, !u.is_active);

            ImGui::SameLine();
            if (ImGui::SmallButton("Set Quota")) {
                quota_modal_uid_ = u.user_id;
                if (u.quota_bytes > 0)
                    snprintf(quota_input_, sizeof(quota_input_), "%llu",
                             (unsigned long long)u.quota_bytes);
                else
                    quota_input_[0] = '\0';
                state_ = State::QuotaModalOpen;
                ImGui::OpenPopup("##quota_modal");
            }

            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    /* Quota modal */
    bool modal_open = true;
    if (ImGui::BeginPopupModal("##quota_modal", &modal_open,
                               ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Set quota for user #%llu", (unsigned long long)quota_modal_uid_);
        ImGui::Text("Enter quota in bytes (0 = unlimited):");
        ImGui::SetNextItemWidth(200);
        ImGui::InputText("##quota_input", quota_input_, sizeof(quota_input_));

        if (ImGui::Button("Save", ImVec2(90, 0))) {
            uint64_t q = (uint64_t)strtoull(quota_input_, nullptr, 10);
            do_set_quota(app, quota_modal_uid_, q);
            ImGui::CloseCurrentPopup();
            state_ = State::ListReady;
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(90, 0))) {
            ImGui::CloseCurrentPopup();
            state_ = State::ListReady;
        }
        ImGui::EndPopup();
    } else if (state_ == State::QuotaModalOpen) {
        state_ = State::ListReady;
    }

    if (error_msg_[0] != '\0') {
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", error_msg_);
    }

    return false;  /* no session expiry */
}

bool VwViewUsers::parse_list_resp(const uint8_t *buf, uint32_t len)
{
    if (len < 4) return false;
    uint32_t count = vw_read_u32le(buf);

    const uint8_t *p = buf + 4;
    uint32_t remaining = len - 4;

    users_.clear();
    for (uint32_t i = 0; i < count; i++) {
        if (remaining < ULIST_ENTRY_WIRE) break;
        UserEntry u;
        u.user_id    = vw_read_u64le(p + 0);
        u.is_admin   = p[8] != 0;
        u.is_active  = p[9] != 0;
        memcpy(u.username, p + 12,  64); u.username[64] = '\0';
        memcpy(u.email,    p + 76, 128); u.email[128]   = '\0';
        u.quota_bytes = vw_read_u64le(p + 204);
        u.used_bytes  = vw_read_u64le(p + 212);
        users_.push_back(u);
        p         += ULIST_ENTRY_WIRE;
        remaining -= ULIST_ENTRY_WIRE;
    }
    return true;
}

void VwViewUsers::do_fetch(ServerApp &app)
{
    error_msg_[0] = '\0';

    uint8_t req[40];
    const uint8_t *tok = app.session_token();
    memcpy(req, tok, 32);
    vw_write_u32le(req + 32, page_offset_);
    vw_write_u32le(req + 36, kPageSize);

    vw_err_t rc = app.conn().send_msg(VW_MSG_USER_LIST, req, sizeof(req));
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_), "send failed: %d", (int)rc);
        state_ = State::Error;
        return;
    }

    vw_msg_type_t rtype;
    void         *rbuf  = nullptr;
    uint32_t      rlen  = 0;
    rc = app.conn().recv_msg(&rtype, &rbuf, &rlen);
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_), "recv failed: %d", (int)rc);
        state_ = State::Error;
        return;
    }

    if (rtype == VW_MSG_ERROR) {
        uint32_t code = (rlen >= 4) ? vw_read_u32le((const uint8_t *)rbuf) : 0;
        free(rbuf);
        if (code == (uint32_t)VW_ERR_AUTH_REQUIRED ||
            code == (uint32_t)VW_ERR_AUTH_SESSION_EXPIRED) {
            session_expired_ = true;
            return;
        }
        snprintf(error_msg_, sizeof(error_msg_), "server error: %u", code);
        state_ = State::Error;
        return;
    }

    if (rtype != VW_MSG_USER_LIST_RESP) {
        free(rbuf);
        snprintf(error_msg_, sizeof(error_msg_), "unexpected response 0x%04x", (unsigned)rtype);
        state_ = State::Error;
        return;
    }

    bool ok = parse_list_resp((const uint8_t *)rbuf, rlen);
    free(rbuf);
    if (!ok) {
        snprintf(error_msg_, sizeof(error_msg_), "malformed USER_LIST_RESP");
        state_ = State::Error;
        return;
    }
    state_ = State::ListReady;
}

void VwViewUsers::do_suspend(ServerApp &app, uint64_t uid, bool active)
{
    error_msg_[0] = '\0';

    uint8_t req[41];
    const uint8_t *tok = app.session_token();
    memcpy(req, tok, 32);
    vw_write_u64le(req + 32, uid);
    req[40] = active ? 1 : 0;

    vw_err_t rc = app.conn().send_msg(VW_MSG_USER_SUSPEND, req, sizeof(req));
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_), "send failed: %d", (int)rc);
        return;
    }

    vw_msg_type_t rtype;
    void         *rbuf = nullptr;
    uint32_t      rlen = 0;
    rc = app.conn().recv_msg(&rtype, &rbuf, &rlen);
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_), "recv failed: %d", (int)rc);
        return;
    }

    if (rtype == VW_MSG_USER_SUSPEND_ACK && rlen >= 4) {
        uint32_t code = vw_read_u32le((const uint8_t *)rbuf);
        free(rbuf);
        if (code != 0) {
            snprintf(error_msg_, sizeof(error_msg_), "suspend error: %u", code);
            return;
        }
    } else {
        free(rbuf);
    }

    do_fetch(app);  /* refresh the list */
}

void VwViewUsers::do_set_quota(ServerApp &app, uint64_t uid, uint64_t quota)
{
    error_msg_[0] = '\0';

    uint8_t req[48];
    const uint8_t *tok = app.session_token();
    memcpy(req, tok, 32);
    vw_write_u64le(req + 32, uid);
    vw_write_u64le(req + 40, quota);

    vw_err_t rc = app.conn().send_msg(VW_MSG_QUOTA_ADJUST, req, sizeof(req));
    if (rc != VW_OK) {
        snprintf(error_msg_, sizeof(error_msg_), "send failed: %d", (int)rc);
        return;
    }

    vw_msg_type_t rtype;
    void         *rbuf = nullptr;
    uint32_t      rlen = 0;
    rc = app.conn().recv_msg(&rtype, &rbuf, &rlen);
    free(rbuf);
    if (rc != VW_OK)
        snprintf(error_msg_, sizeof(error_msg_), "recv failed: %d", (int)rc);
    else
        do_fetch(app);
}
