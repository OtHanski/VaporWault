#include "vw_gui_ipc.h"
#include "../core/vw_proto.h"
#include <cstring>
#include <cstdio>

static uint32_t read_u32_le(const uint8_t *buf) {
    return (uint32_t)buf[0] | ((uint32_t)buf[1] << 8)
         | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}
static int64_t read_i64_le(const uint8_t *buf) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)buf[i] << (8 * i));
    return (int64_t)v;
}

bool VwGuiIpc::connect(uint16_t port) {
    port_ = port;
    vw_ipc_conn_t *probe = nullptr;
    connected_ = (vw_ipc_connect(port, &probe) == VW_OK);
    if (probe) vw_ipc_conn_close(probe);
    return connected_;
}

void VwGuiIpc::disconnect() {
    connected_ = false;
}

vw_err_t VwGuiIpc::one_shot(vw_ipc_msg_t req_type, const uint8_t *req, uint32_t req_len,
                             vw_ipc_msg_t expect_resp_type,
                             uint8_t *resp_buf, uint32_t resp_bufsz, uint32_t *out_resp_len) {
    vw_ipc_conn_t *conn = nullptr;
    vw_err_t err = vw_ipc_connect(port_, &conn);
    if (err != VW_OK) { connected_ = false; return err; }

    err = vw_ipc_send(conn, req_type, req, req_len);
    if (err != VW_OK) { vw_ipc_conn_close(conn); connected_ = false; return err; }

    vw_ipc_msg_t type;
    err = vw_ipc_recv(conn, &type, resp_buf, resp_bufsz, out_resp_len);
    vw_ipc_conn_close(conn);
    if (err != VW_OK) { connected_ = false; return err; }
    if (type != expect_resp_type) { connected_ = false; return VW_ERR_PROTO_INVALID; }

    connected_ = true;
    return VW_OK;
}

bool VwGuiIpc::fetch_status(VwIpcStatus *out) {
    uint8_t buf[64]; uint32_t plen;
    if (one_shot(VW_IPC_STATUS_REQ, nullptr, 0, VW_IPC_STATUS_RESP,
                 buf, sizeof(buf), &plen) != VW_OK || plen < 20)
        return false;

    out->connected         = buf[0];
    out->syncing           = buf[1];
    out->paused            = buf[2];
    out->last_sync_at      = read_i64_le(buf + 4);
    out->pending_uploads   = read_u32_le(buf + 12);
    out->pending_downloads = read_u32_le(buf + 16);
    out->error_count       = (plen >= 24) ? read_u32_le(buf + 20) : 0;
    /* TASK-173/175: trailing byte, same append convention as error_count
     * (which itself was appended after connected/syncing/paused). */
    out->any_on_fallback   = (plen >= 29) ? buf[28] : 0;
    return true;
}

int VwGuiIpc::simple_req_resp(vw_ipc_msg_t req_type, vw_ipc_msg_t resp_type,
                               const uint8_t *payload, uint32_t payload_len) {
    uint8_t buf[8]; uint32_t plen;
    vw_err_t err = one_shot(req_type, payload, payload_len, resp_type, buf, sizeof(buf), &plen);
    if (err != VW_OK) return (int)err;
    if (plen < 4) return (int)VW_ERR_IO;
    return (int)read_u32_le(buf);
}

bool VwGuiIpc::send_sync_now() {
    return simple_req_resp(VW_IPC_SYNC_NOW_REQ, VW_IPC_SYNC_NOW_RESP, nullptr, 0) == 0;
}

bool VwGuiIpc::send_pause(uint32_t account_id, const char *folder_root) {
    uint8_t buf[520]; uint32_t off = 0;
    vw_write_u32le(buf + off, account_id); off += 4u;
    const char *s = folder_root ? folder_root : "";
    vw_ipc_write_str(buf, sizeof(buf), &off, s, (uint16_t)strlen(s));
    return simple_req_resp(VW_IPC_PAUSE_REQ, VW_IPC_PAUSE_RESP, buf, off) == 0;
}

bool VwGuiIpc::send_resume(uint32_t account_id, const char *folder_root) {
    uint8_t buf[520]; uint32_t off = 0;
    vw_write_u32le(buf + off, account_id); off += 4u;
    const char *s = folder_root ? folder_root : "";
    vw_ipc_write_str(buf, sizeof(buf), &off, s, (uint16_t)strlen(s));
    return simple_req_resp(VW_IPC_RESUME_REQ, VW_IPC_RESUME_RESP, buf, off) == 0;
}

bool VwGuiIpc::send_shutdown() {
    return simple_req_resp(VW_IPC_SHUTDOWN_REQ, VW_IPC_SHUTDOWN_RESP, nullptr, 0) == 0;
}

int VwGuiIpc::send_folder_add(uint32_t account_id, const char *local_root, const char *virtual_root) {
    uint8_t buf[1032]; uint32_t off = 0;
    vw_write_u32le(buf + off, account_id); off += 4u;
    vw_ipc_write_str(buf, sizeof(buf), &off, local_root,   (uint16_t)strnlen(local_root, 511));
    vw_ipc_write_str(buf, sizeof(buf), &off, virtual_root, (uint16_t)strnlen(virtual_root, 511));
    return simple_req_resp(VW_IPC_FOLDER_ADD_REQ, VW_IPC_FOLDER_ADD_RESP, buf, off);
}

int VwGuiIpc::send_folder_remove(uint32_t account_id, const char *local_root) {
    uint8_t buf[518]; uint32_t off = 0;
    vw_write_u32le(buf + off, account_id); off += 4u;
    vw_ipc_write_str(buf, sizeof(buf), &off, local_root, (uint16_t)strnlen(local_root, 511));
    return simple_req_resp(VW_IPC_FOLDER_REMOVE_REQ, VW_IPC_FOLDER_REMOVE_RESP, buf, off);
}

bool VwGuiIpc::folder_list(uint32_t account_id, std::vector<VwGuiFolderEntry> *out) {
    uint8_t req[4]; vw_write_u32le(req, account_id);
    static const uint32_t kRespCap = 65536;
    std::vector<uint8_t> resp(kRespCap);
    uint32_t rlen;
    if (one_shot(VW_IPC_FOLDER_LIST_REQ, req, sizeof(req), VW_IPC_FOLDER_LIST_RESP,
                 resp.data(), kRespCap, &rlen) != VW_OK)
        return false;
    if (rlen < 4) { out->clear(); return true; }

    uint32_t count = read_u32_le(resp.data());
    uint32_t off = 4;
    std::vector<VwGuiFolderEntry> entries;
    entries.reserve(count);

    for (uint32_t i = 0; i < count; i++) {
        VwGuiFolderEntry e;
        const char *lroot = nullptr; uint16_t llen = 0;
        if (vw_ipc_read_str(resp.data(), rlen, &off, &lroot, &llen) != VW_OK) break;
        e.local_root.assign(lroot, llen);
        const char *vroot = nullptr; uint16_t vlen = 0;
        if (vw_ipc_read_str(resp.data(), rlen, &off, &vroot, &vlen) != VW_OK) break;
        e.virtual_root.assign(vroot, vlen);

        if (off + 1u + 1u + 8u + 2u > rlen) break;
        e.paused        = resp[off++];
        e.pause_reason  = resp[off++];
        e.remote_dir_id = (uint64_t)read_i64_le(resp.data() + off); off += 8;

        uint16_t ecount = vw_read_u16le(resp.data() + off); off += 2;
        for (uint16_t j = 0; j < ecount; j++) {
            const char *pat = nullptr; uint16_t plen = 0;
            if (vw_ipc_read_str(resp.data(), rlen, &off, &pat, &plen) != VW_OK) break;
            e.excludes.emplace_back(pat, plen);
        }
        entries.push_back(std::move(e));
    }

    *out = std::move(entries);
    return true;
}

int VwGuiIpc::folder_set_excludes(uint32_t account_id, const char *local_root,
                                   const std::vector<std::string> &patterns) {
    std::vector<uint8_t> buf(4u + 2u + 512u + 2u + 64u * 258u);
    uint32_t off = 0;
    vw_write_u32le(buf.data() + off, account_id); off += 4u;
    vw_ipc_write_str(buf.data(), (uint32_t)buf.size(), &off, local_root,
                      (uint16_t)strnlen(local_root, 511));
    uint16_t count = (uint16_t)(patterns.size() < 64 ? patterns.size() : 64);
    vw_write_u16le(buf.data() + off, count); off += 2u;
    for (uint16_t i = 0; i < count; i++)
        vw_ipc_write_str(buf.data(), (uint32_t)buf.size(), &off,
                          patterns[i].c_str(), (uint16_t)patterns[i].size());
    return simple_req_resp(VW_IPC_FOLDER_SET_EXCLUDES_REQ, VW_IPC_FOLDER_SET_EXCLUDES_RESP,
                            buf.data(), off);
}

bool VwGuiIpc::notify_prefs_get(uint32_t account_id, uint32_t *out_prefs) {
    uint8_t req[4]; vw_write_u32le(req, account_id);
    uint8_t resp[8]; uint32_t plen;
    if (one_shot(VW_IPC_NOTIFY_PREFS_GET_REQ, req, sizeof(req), VW_IPC_NOTIFY_PREFS_GET_RESP,
                 resp, sizeof(resp), &plen) != VW_OK || plen < 8)
        return false;
    if (read_u32_le(resp) != 0) return false; /* error_code */
    *out_prefs = read_u32_le(resp + 4);
    return true;
}

int VwGuiIpc::notify_prefs_set(uint32_t account_id, uint32_t prefs, uint32_t *out_prefs) {
    uint8_t req[8]; vw_write_u32le(req, account_id); vw_write_u32le(req + 4, prefs);
    uint8_t resp[8]; uint32_t plen;
    vw_err_t err = one_shot(VW_IPC_NOTIFY_PREFS_SET_REQ, req, sizeof(req),
                             VW_IPC_NOTIFY_PREFS_SET_ACK, resp, sizeof(resp), &plen);
    if (err != VW_OK) return (int)err;
    if (plen < 8) return (int)VW_ERR_IO;
    uint32_t code = read_u32_le(resp);
    if (code == 0 && out_prefs) *out_prefs = read_u32_le(resp + 4);
    return (int)code;
}

bool VwGuiIpc::account_email_get(uint32_t account_id, std::string *out_email) {
    uint8_t req[4]; vw_write_u32le(req, account_id);
    uint8_t resp[4 + 2 + 128]; uint32_t plen;
    if (one_shot(VW_IPC_ACCOUNT_EMAIL_GET_REQ, req, sizeof(req), VW_IPC_ACCOUNT_EMAIL_GET_RESP,
                 resp, sizeof(resp), &plen) != VW_OK || plen < 4)
        return false;
    if (read_u32_le(resp) != 0) return false; /* error_code */
    uint32_t off = 4;
    const char *email = nullptr; uint16_t email_len = 0;
    if (vw_ipc_read_str(resp, plen, &off, &email, &email_len) != VW_OK) return false;
    *out_email = std::string(email, email_len);
    return true;
}

int VwGuiIpc::account_email_set(uint32_t account_id, const std::string &email,
                                 std::string *out_email) {
    uint8_t req[4 + 2 + 128];
    uint32_t off = 0;
    vw_write_u32le(req, account_id); off += 4;
    if (vw_ipc_write_str(req, sizeof(req), &off, email.c_str(),
                          (uint16_t)email.size()) != VW_OK)
        return (int)VW_ERR_INVALID_ARG;

    uint8_t resp[4 + 2 + 128]; uint32_t plen;
    vw_err_t err = one_shot(VW_IPC_ACCOUNT_EMAIL_SET_REQ, req, off,
                             VW_IPC_ACCOUNT_EMAIL_SET_ACK, resp, sizeof(resp), &plen);
    if (err != VW_OK) return (int)err;
    if (plen < 4) return (int)VW_ERR_IO;
    uint32_t code = read_u32_le(resp);
    if (code == 0 && out_email) {
        uint32_t roff = 4;
        const char *stored = nullptr; uint16_t stored_len = 0;
        if (vw_ipc_read_str(resp, plen, &roff, &stored, &stored_len) == VW_OK)
            *out_email = std::string(stored, stored_len);
    }
    return (int)code;
}

bool VwGuiIpc::account_2fa_get(uint32_t account_id, uint8_t *out_enabled) {
    uint8_t req[4]; vw_write_u32le(req, account_id);
    uint8_t resp[5]; uint32_t plen;
    if (one_shot(VW_IPC_ACCOUNT_2FA_GET_REQ, req, sizeof(req), VW_IPC_ACCOUNT_2FA_GET_RESP,
                 resp, sizeof(resp), &plen) != VW_OK || plen < 5)
        return false;
    if (read_u32_le(resp) != 0) return false; /* error_code */
    *out_enabled = resp[4];
    return true;
}

int VwGuiIpc::account_2fa_set(uint32_t account_id, const std::string &password,
                               bool enable, uint8_t *out_enabled) {
    uint8_t req[4 + 2 + 256 + 1];
    uint32_t off = 0;
    vw_write_u32le(req, account_id); off += 4;
    if (vw_ipc_write_str(req, sizeof(req), &off, password.c_str(),
                          (uint16_t)password.size()) != VW_OK)
        return (int)VW_ERR_INVALID_ARG;
    req[off++] = enable ? 1 : 0;

    uint8_t resp[5]; uint32_t plen;
    vw_err_t err = one_shot(VW_IPC_ACCOUNT_2FA_SET_REQ, req, off,
                             VW_IPC_ACCOUNT_2FA_SET_ACK, resp, sizeof(resp), &plen);
    if (err != VW_OK) return (int)err;
    if (plen < 5) return (int)VW_ERR_IO;
    uint32_t code = read_u32_le(resp);
    if (code == 0 && out_enabled) *out_enabled = resp[4];
    return (int)code;
}

bool VwGuiIpc::account_list(std::vector<VwGuiAccountEntry> *out) {
    static const uint32_t kRespCap = 65536;
    std::vector<uint8_t> resp(kRespCap);
    uint32_t rlen;
    if (one_shot(VW_IPC_ACCOUNT_LIST_REQ, nullptr, 0, VW_IPC_ACCOUNT_LIST_RESP,
                 resp.data(), kRespCap, &rlen) != VW_OK)
        return false;
    if (rlen < 4) { out->clear(); return true; }

    uint32_t count = read_u32_le(resp.data());
    uint32_t off = 4;
    std::vector<VwGuiAccountEntry> entries;
    entries.reserve(count);

    for (uint32_t i = 0; i < count; i++) {
        if (off + 4u > rlen) break;
        VwGuiAccountEntry e;
        e.account_id = read_u32_le(resp.data() + off); off += 4;

        const char *label = nullptr, *username = nullptr, *host = nullptr;
        uint16_t label_len = 0, user_len = 0, host_len = 0;
        if (vw_ipc_read_str(resp.data(), rlen, &off, &label, &label_len) != VW_OK) break;
        if (vw_ipc_read_str(resp.data(), rlen, &off, &username, &user_len) != VW_OK) break;
        if (vw_ipc_read_str(resp.data(), rlen, &off, &host, &host_len) != VW_OK) break;
        if (off + 1u + 8u > rlen) break;
        e.label.assign(label, label_len);
        e.username.assign(username, user_len);
        e.server_host.assign(host, host_len);
        e.connected = resp[off]; off += 1u;
        off += 8u; /* pending_uploads (u32) + pending_downloads (u32) */
        /* TASK-173/175: trailing conn_mode byte (0=offline, 1=primary,
         * 2=fallback) — must always be consumed, or every subsequent
         * entry's offset desyncs by one byte per account already seen. */
        if (off + 1u > rlen) break;
        e.conn_mode = resp[off]; off += 1u;
        entries.push_back(std::move(e));
    }

    *out = std::move(entries);
    return true;
}

int VwGuiIpc::account_add(uint32_t account_id_hint, const char *label,
                           const char *server_host, uint16_t server_port, const char *ca_cert_path,
                           const char *username, char *password, const char *otp,
                           const char *fallback_host, uint16_t fallback_port,
                           const char *fallback_ca_cert_path,
                           uint32_t *out_account_id) {
    /* Worst case: 4 (account_id) + (2+63) label + (2+255) host + 2 (port) +
     * (2+511) ca_cert_path + (2+63) username + (2+255) password +
     * (2+16) otp + (2+255) fallback_host + 2 (fallback_port) +
     * (2+511) fallback_ca_cert_path = 1954 bytes — sized with headroom.
     * Every write is checked (TASK-162's CQR review found the CLI's
     * equivalent function unchecked against this exact buffer's worst
     * case — same fix here). */
    uint8_t buf[2048]; uint32_t off = 0;
    vw_write_u32le(buf + off, account_id_hint); off += 4u;
    const char *lbl = (label && label[0]) ? label : username;
    vw_err_t werr = vw_ipc_write_str(buf, sizeof(buf), &off, lbl, (uint16_t)strnlen(lbl, 63));
    if (werr == VW_OK)
        werr = vw_ipc_write_str(buf, sizeof(buf), &off, server_host, (uint16_t)strnlen(server_host, 255));
    if (werr == VW_OK && off + 2u <= sizeof(buf)) { vw_write_u16le(buf + off, server_port); off += 2u; }
    else if (werr == VW_OK) werr = VW_ERR_PROTO_TOO_LARGE;
    const char *ca = ca_cert_path ? ca_cert_path : "";
    if (werr == VW_OK)
        werr = vw_ipc_write_str(buf, sizeof(buf), &off, ca, (uint16_t)strnlen(ca, 511));
    if (werr == VW_OK)
        werr = vw_ipc_write_str(buf, sizeof(buf), &off, username, (uint16_t)strnlen(username, 63));
    if (werr == VW_OK)
        werr = vw_ipc_write_str(buf, sizeof(buf), &off, password, (uint16_t)strnlen(password, 255));
    const char *o = otp ? otp : "";
    if (werr == VW_OK)
        werr = vw_ipc_write_str(buf, sizeof(buf), &off, o, (uint16_t)strnlen(o, 16));

    /* TASK-173/175: optional trailing fallback fields — omitted entirely
     * (not sent as empty strings) when the caller passed no fallback_host,
     * so a re-authentication that doesn't repeat it leaves an already-
     * configured fallback untouched (vw_daemon.c's "absent means leave
     * as-is" contract). */
    if (werr == VW_OK && fallback_host && fallback_host[0]) {
        werr = vw_ipc_write_str(buf, sizeof(buf), &off,
                                 fallback_host, (uint16_t)strnlen(fallback_host, 255));
        if (werr == VW_OK && off + 2u <= sizeof(buf)) {
            vw_write_u16le(buf + off, fallback_port); off += 2u;
        } else if (werr == VW_OK) {
            werr = VW_ERR_PROTO_TOO_LARGE;
        }
        const char *fca = fallback_ca_cert_path ? fallback_ca_cert_path : "";
        if (werr == VW_OK)
            werr = vw_ipc_write_str(buf, sizeof(buf), &off, fca, (uint16_t)strnlen(fca, 511));
    }

    if (werr != VW_OK) {
        memset(buf, 0, sizeof(buf));
        memset(password, 0, strlen(password));
        return (int)werr;
    }

    uint8_t resp[8]; uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_ACCOUNT_ADD_REQ, buf, off, VW_IPC_ACCOUNT_ADD_RESP, resp, sizeof(resp), &rlen);

    /* Zero both the wire-form request buffer and the caller's own field in
     * place (password is the caller's actual input buffer, passed by
     * pointer) — the caller does not need to zero it again. */
    memset(buf, 0, sizeof(buf));
    memset(password, 0, strlen(password));

    if (err != VW_OK) return (int)err;
    if (rlen < 8) return (int)VW_ERR_IO;
    uint32_t ec = read_u32_le(resp);
    if (ec == 0 && out_account_id) *out_account_id = read_u32_le(resp + 4);
    return (int)ec;
}

int VwGuiIpc::account_remove(uint32_t account_id) {
    uint8_t req[4]; vw_write_u32le(req, account_id);
    return simple_req_resp(VW_IPC_ACCOUNT_REMOVE_REQ, VW_IPC_ACCOUNT_REMOVE_RESP, req, sizeof(req));
}

bool VwGuiIpc::file_list(uint32_t account_id, const char *prefix, std::vector<VwGuiFileEntry> *out) {
    uint8_t req[522]; uint32_t roff = 0;
    vw_write_u32le(req + roff, account_id); roff += 4u;
    const char *p = prefix ? prefix : "";
    vw_ipc_write_str(req, sizeof(req), &roff, p, (uint16_t)strlen(p));
    req[roff++] = VW_IPC_FILTER_ALL;

    static const uint32_t kRespCap = 65536;
    std::vector<uint8_t> resp(kRespCap);
    uint32_t rlen;
    if (one_shot(VW_IPC_FILE_LIST_REQ, req, roff, VW_IPC_FILE_LIST_RESP,
                 resp.data(), kRespCap, &rlen) != VW_OK)
        return false;
    if (rlen < 4) { out->clear(); return true; }

    uint32_t count = read_u32_le(resp.data());
    uint32_t off = 4;
    std::vector<VwGuiFileEntry> entries;
    entries.reserve(count);

    for (uint32_t i = 0; i < count; i++) {
        const char *vpath = nullptr, *lpath = nullptr;
        uint16_t vplen = 0, lplen = 0;
        if (vw_ipc_read_str(resp.data(), rlen, &off, &vpath, &vplen) != VW_OK) break;
        if (vw_ipc_read_str(resp.data(), rlen, &off, &lpath, &lplen) != VW_OK) break;
        if (off + 4u + 1u + 8u + 8u + 8u + 8u + 8u > rlen) break;

        VwGuiFileEntry e;
        e.virtual_path.assign(vpath, vplen);
        e.local_path.assign(lpath, lplen);
        e.sync_state   = read_u32_le(resp.data() + off); off += 4;
        e.entry_type   = resp[off++];
        e.server_mtime = read_i64_le(resp.data() + off); off += 8;
        e.local_mtime  = read_i64_le(resp.data() + off); off += 8;
        e.server_size  = (uint64_t)read_i64_le(resp.data() + off); off += 8;
        e.file_id      = (uint64_t)read_i64_le(resp.data() + off); off += 8;
        e.vault_id     = (uint64_t)read_i64_le(resp.data() + off); off += 8;
        entries.push_back(std::move(e));
    }

    *out = std::move(entries);
    return true;
}

bool VwGuiIpc::search(uint32_t account_id, const char *query, std::vector<VwGuiSearchEntry> *out,
                       uint8_t *out_truncated, int *out_error_code) {
    uint8_t req[4u + 2u + 256u]; uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    const char *q = query ? query : "";
    vw_ipc_write_str(req, sizeof(req), &off, q, (uint16_t)strlen(q));

    static const uint32_t kRespCap = 65536;
    std::vector<uint8_t> resp(kRespCap);
    uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_SEARCH_REQ, req, off, VW_IPC_SEARCH_RESP,
                             resp.data(), kRespCap, &rlen);
    if (err != VW_OK) { if (out_error_code) *out_error_code = (int)err; return false; }
    if (rlen < 9) { if (out_error_code) *out_error_code = (int)VW_ERR_IO; return false; }

    uint32_t ec = read_u32_le(resp.data());
    if (out_error_code) *out_error_code = (int)ec;
    if (ec != 0) return false;

    uint32_t count = read_u32_le(resp.data() + 4);
    uint8_t  truncated = resp[8];
    if (out_truncated) *out_truncated = truncated;
    uint32_t roff = 9;

    std::vector<VwGuiSearchEntry> entries;
    entries.reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        if (roff + 8u > rlen) break;
        VwGuiSearchEntry e;
        e.file_id = (uint64_t)read_i64_le(resp.data() + roff); roff += 8;

        const char *name = nullptr; uint16_t nlen = 0;
        if (vw_ipc_read_str(resp.data(), rlen, &roff, &name, &nlen) != VW_OK) break;
        e.name.assign(name, nlen);

        if (roff + 1u + 8u + 8u + 8u + 1u > rlen) break;
        e.is_dir     = resp[roff++];
        e.size_bytes = (uint64_t)read_i64_le(resp.data() + roff); roff += 8;
        e.mtime_unix = read_i64_le(resp.data() + roff); roff += 8;
        e.vault_id   = (uint64_t)read_i64_le(resp.data() + roff); roff += 8;
        e.is_shared  = resp[roff++];
        entries.push_back(std::move(e));
    }

    *out = std::move(entries);
    return true;
}

int VwGuiIpc::share_grant(uint32_t account_id, const char *virtual_path, const char *target_username,
                           uint8_t permission, int64_t expires_at, uint64_t *out_share_id) {
    uint8_t req[4u + 2u + 4096u + 2u + 65u + 1u + 8u]; uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    vw_ipc_write_str(req, sizeof(req), &off, virtual_path, (uint16_t)strlen(virtual_path));
    vw_ipc_write_str(req, sizeof(req), &off, target_username, (uint16_t)strlen(target_username));
    req[off++] = permission;
    vw_write_u64le(req + off, (uint64_t)expires_at); off += 8;

    uint8_t resp[12]; uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_SHARE_GRANT_REQ, req, off, VW_IPC_SHARE_GRANT_RESP,
                             resp, sizeof(resp), &rlen);
    if (err != VW_OK) return (int)err;
    if (rlen < 12) return (int)VW_ERR_IO;
    uint32_t ec = read_u32_le(resp);
    if (ec == 0 && out_share_id) *out_share_id = (uint64_t)read_i64_le(resp + 4);
    return (int)ec;
}

int VwGuiIpc::share_revoke(uint32_t account_id, uint64_t share_id) {
    uint8_t req[12]; vw_write_u32le(req, account_id); vw_write_u64le(req + 4u, share_id);
    return simple_req_resp(VW_IPC_SHARE_REVOKE_REQ, VW_IPC_SHARE_REVOKE_RESP, req, sizeof(req));
}

int VwGuiIpc::link_revoke(uint32_t account_id, uint64_t share_id) {
    uint8_t req[12]; vw_write_u32le(req, account_id); vw_write_u64le(req + 4u, share_id);
    return simple_req_resp(VW_IPC_LINK_REVOKE_REQ, VW_IPC_LINK_REVOKE_RESP, req, sizeof(req));
}

bool VwGuiIpc::share_list(uint32_t account_id, uint8_t mode, std::vector<VwGuiShareEntry> *out, int *out_error_code) {
    uint8_t req[5]; vw_write_u32le(req, account_id); req[4] = mode;
    static const uint32_t kRespCap = 65536;
    std::vector<uint8_t> resp(kRespCap);
    uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_SHARE_LIST_REQ, req, sizeof(req), VW_IPC_SHARE_LIST_RESP,
                             resp.data(), kRespCap, &rlen);
    if (err != VW_OK) { if (out_error_code) *out_error_code = (int)err; return false; }
    if (rlen < 8) { if (out_error_code) *out_error_code = (int)VW_ERR_IO; return false; }

    uint32_t ec = read_u32_le(resp.data());
    if (out_error_code) *out_error_code = (int)ec;
    if (ec != 0) return false;

    uint32_t count = read_u32_le(resp.data() + 4);
    uint32_t off = 8;
    std::vector<VwGuiShareEntry> entries;
    entries.reserve(count);

    for (uint32_t i = 0; i < count; i++) {
        if (off + 16u > rlen) break;
        VwGuiShareEntry e;
        e.share_id = (uint64_t)read_i64_le(resp.data() + off); off += 8;
        e.file_id  = (uint64_t)read_i64_le(resp.data() + off); off += 8;

        const char *name = nullptr; uint16_t nlen = 0;
        if (vw_ipc_read_str(resp.data(), rlen, &off, &name, &nlen) != VW_OK) break;
        e.name.assign(name, nlen);
        if (off + 1u > rlen) break;
        e.share_type = resp[off++];

        const char *tgt = nullptr; uint16_t tlen = 0;
        if (vw_ipc_read_str(resp.data(), rlen, &off, &tgt, &tlen) != VW_OK) break;
        e.target_username.assign(tgt, tlen);

        if (off + 1u + 8u + 8u + 1u > rlen) break;
        e.permission = resp[off++];
        e.created_at = read_i64_le(resp.data() + off); off += 8;
        e.expires_at = read_i64_le(resp.data() + off); off += 8;
        e.revoked    = resp[off++];
        entries.push_back(std::move(e));
    }

    *out = std::move(entries);
    return true;
}

int VwGuiIpc::link_create(uint32_t account_id, const char *virtual_path, uint8_t permission, int64_t expires_at,
                           const char *password, uint64_t *out_share_id, uint8_t out_token[32]) {
    uint8_t req[4u + 2u + 4096u + 1u + 8u + 2u + 256u]; uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    vw_ipc_write_str(req, sizeof(req), &off, virtual_path, (uint16_t)strlen(virtual_path));
    req[off++] = permission;
    vw_write_u64le(req + off, (uint64_t)expires_at); off += 8;
    vw_ipc_write_str(req, sizeof(req), &off, password ? password : "",
                      (uint16_t)(password ? strlen(password) : 0));

    uint8_t resp[4u + 8u + 32u]; uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_LINK_CREATE_REQ, req, off, VW_IPC_LINK_CREATE_RESP,
                             resp, sizeof(resp), &rlen);
    if (err != VW_OK) return (int)err;
    if (rlen < sizeof(resp)) { memset(resp, 0, sizeof(resp)); return (int)VW_ERR_IO; }

    uint32_t ec = read_u32_le(resp);
    if (ec == 0) {
        if (out_share_id) *out_share_id = (uint64_t)read_i64_le(resp + 4);
        if (out_token) memcpy(out_token, resp + 12, 32);
    }
    memset(resp, 0, sizeof(resp)); /* never let the raw token linger */
    return (int)ec;
}

bool VwGuiIpc::link_list(uint32_t account_id, std::vector<VwGuiLinkEntry> *out, int *out_error_code) {
    uint8_t req[12] = {0}; /* file_id_filter=0 — all my links, matching the CLI */
    vw_write_u32le(req, account_id);
    static const uint32_t kRespCap = 65536;
    std::vector<uint8_t> resp(kRespCap);
    uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_LINK_LIST_REQ, req, sizeof(req), VW_IPC_LINK_LIST_RESP,
                             resp.data(), kRespCap, &rlen);
    if (err != VW_OK) { if (out_error_code) *out_error_code = (int)err; return false; }
    if (rlen < 8) { if (out_error_code) *out_error_code = (int)VW_ERR_IO; return false; }

    uint32_t ec = read_u32_le(resp.data());
    if (out_error_code) *out_error_code = (int)ec;
    if (ec != 0) return false;

    uint32_t count = read_u32_le(resp.data() + 4);
    uint32_t off = 8;
    std::vector<VwGuiLinkEntry> entries;
    entries.reserve(count);

    for (uint32_t i = 0; i < count; i++) {
        if (off + 16u > rlen) break;
        VwGuiLinkEntry e;
        e.share_id = (uint64_t)read_i64_le(resp.data() + off); off += 8;
        e.file_id  = (uint64_t)read_i64_le(resp.data() + off); off += 8;

        const char *name = nullptr; uint16_t nlen = 0;
        if (vw_ipc_read_str(resp.data(), rlen, &off, &name, &nlen) != VW_OK) break;
        e.name.assign(name, nlen);

        if (off + 1u + 8u + 8u + 1u + 1u > rlen) break;
        e.permission = resp[off++];
        e.created_at = read_i64_le(resp.data() + off); off += 8;
        e.expires_at = read_i64_le(resp.data() + off); off += 8;
        e.revoked    = resp[off++];
        e.has_password = resp[off++]; /* TASK-186/189 */
        entries.push_back(std::move(e));
    }

    *out = std::move(entries);
    return true;
}

bool VwGuiIpc::version_list(uint32_t account_id, const char *virtual_path,
                             std::vector<VwGuiVersionEntry> *out, int *out_error_code) {
    uint8_t req[4u + 2u + 4096u]; uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    vw_ipc_write_str(req, sizeof(req), &off, virtual_path, (uint16_t)strlen(virtual_path));

    static const uint32_t kRespCap = 65536;
    std::vector<uint8_t> resp(kRespCap);
    uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_VERSION_LIST_REQ, req, off, VW_IPC_VERSION_LIST_RESP,
                             resp.data(), kRespCap, &rlen);
    if (err != VW_OK) { if (out_error_code) *out_error_code = (int)err; return false; }
    if (rlen < 8) { if (out_error_code) *out_error_code = (int)VW_ERR_IO; return false; }

    uint32_t ec = read_u32_le(resp.data());
    if (out_error_code) *out_error_code = (int)ec;
    if (ec != 0) return false;

    uint32_t count = read_u32_le(resp.data() + 4);
    uint32_t roff = 8;
    std::vector<VwGuiVersionEntry> entries;
    entries.reserve(count);

    for (uint32_t i = 0; i < count; i++) {
        if (roff + 24u > rlen) break;
        VwGuiVersionEntry e;
        e.version_id = (uint64_t)read_i64_le(resp.data() + roff); roff += 8;
        e.created_at = read_i64_le(resp.data() + roff); roff += 8;
        e.size_bytes = (uint64_t)read_i64_le(resp.data() + roff); roff += 8;
        entries.push_back(e);
    }

    *out = std::move(entries);
    return true;
}

int VwGuiIpc::version_restore(uint32_t account_id, const char *virtual_path, uint64_t version_id) {
    uint8_t req[4u + 2u + 4096u + 8u]; uint32_t off = 0;
    vw_write_u32le(req + off, account_id); off += 4u;
    vw_ipc_write_str(req, sizeof(req), &off, virtual_path, (uint16_t)strlen(virtual_path));
    vw_write_u64le(req + off, version_id); off += 8u;

    return simple_req_resp(VW_IPC_VERSION_RESTORE_REQ, VW_IPC_VERSION_RESTORE_RESP, req, off);
}

int VwGuiIpc::file_mkdir(uint32_t account_id, uint64_t new_parent_dir_id, const char *name, uint64_t *out_dir_id) {
    uint8_t req[4u + 8u + 2u + 256u]; uint32_t off = 0;
    vw_write_u32le(req, account_id); off += 4u;
    vw_write_u64le(req + off, new_parent_dir_id); off += 8u;
    vw_ipc_write_str(req, sizeof(req), &off, name, (uint16_t)strlen(name));

    uint8_t resp[12]; uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_FILE_MKDIR_REQ, req, off, VW_IPC_FILE_MKDIR_RESP,
                             resp, sizeof(resp), &rlen);
    if (err != VW_OK) return (int)err;
    if (rlen < 12) return (int)VW_ERR_IO;
    uint32_t ec = read_u32_le(resp);
    if (ec == 0 && out_dir_id) *out_dir_id = (uint64_t)read_i64_le(resp + 4);
    return (int)ec;
}

int VwGuiIpc::vault_create(uint32_t account_id, uint64_t folder_file_id, char *passphrase, uint64_t *out_vault_id) {
    uint8_t req[4u + 8u + 2u + 512u]; uint32_t off = 0;
    vw_write_u32le(req, account_id); off += 4u;
    vw_write_u64le(req + off, folder_file_id); off += 8u;
    vw_ipc_write_str(req, sizeof(req), &off, passphrase, (uint16_t)strnlen(passphrase, 511));

    uint8_t resp[12]; uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_VAULT_CREATE_REQ, req, off, VW_IPC_VAULT_CREATE_RESP,
                             resp, sizeof(resp), &rlen);

    /* Zero both the wire-form request buffer and the caller's own field —
     * same convention as account_add(). */
    memset(req, 0, sizeof(req));
    memset(passphrase, 0, strlen(passphrase));

    if (err != VW_OK) return (int)err;
    if (rlen < 12) return (int)VW_ERR_IO;
    uint32_t ec = read_u32_le(resp);
    if (ec == 0 && out_vault_id) *out_vault_id = (uint64_t)read_i64_le(resp + 4);
    return (int)ec;
}

int VwGuiIpc::vault_unlock(uint32_t account_id, uint64_t vault_id, char *passphrase) {
    uint8_t req[4u + 8u + 2u + 512u]; uint32_t off = 0;
    vw_write_u32le(req, account_id); off += 4u;
    vw_write_u64le(req + off, vault_id); off += 8u;
    vw_ipc_write_str(req, sizeof(req), &off, passphrase, (uint16_t)strnlen(passphrase, 511));

    uint8_t resp[4]; uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_VAULT_UNLOCK_REQ, req, off, VW_IPC_VAULT_UNLOCK_RESP,
                             resp, sizeof(resp), &rlen);

    memset(req, 0, sizeof(req));
    memset(passphrase, 0, strlen(passphrase));

    if (err != VW_OK) return (int)err;
    if (rlen < 4) return (int)VW_ERR_IO;
    return (int)read_u32_le(resp);
}

bool VwGuiIpc::vault_list(uint32_t account_id, std::vector<VwGuiVaultEntry> *out, int *out_error_code) {
    uint8_t req[4]; vw_write_u32le(req, account_id);
    static const uint32_t kRespCap = 65536;
    std::vector<uint8_t> resp(kRespCap);
    uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_VAULT_LIST_REQ, req, sizeof(req), VW_IPC_VAULT_LIST_RESP,
                             resp.data(), kRespCap, &rlen);
    if (err != VW_OK) { if (out_error_code) *out_error_code = (int)err; return false; }
    if (rlen < 8) { if (out_error_code) *out_error_code = (int)VW_ERR_IO; return false; }

    uint32_t ec = read_u32_le(resp.data());
    if (out_error_code) *out_error_code = (int)ec;
    if (ec != 0) return false;

    uint32_t count = read_u32_le(resp.data() + 4);
    uint32_t off = 8;
    std::vector<VwGuiVaultEntry> entries;
    entries.reserve(count);

    for (uint32_t i = 0; i < count; i++) {
        if (off + 24u > rlen) break;
        VwGuiVaultEntry e;
        e.vault_id       = (uint64_t)read_i64_le(resp.data() + off); off += 8;
        e.folder_file_id = (uint64_t)read_i64_le(resp.data() + off); off += 8;
        e.created_at     = read_i64_le(resp.data() + off);           off += 8;
        entries.push_back(e);
    }

    *out = std::move(entries);
    return true;
}

int VwGuiIpc::vault_delete(uint32_t account_id, uint64_t vault_id) {
    /* CQR.08 finding: this used to hand-roll one_shot() + response
     * decoding — same u32 account_id + u64 id request, u32 error_code
     * response shape share_revoke/link_revoke already share via
     * simple_req_resp() above. */
    uint8_t req[12]; vw_write_u32le(req, account_id); vw_write_u64le(req + 4u, vault_id);
    return simple_req_resp(VW_IPC_VAULT_DELETE_REQ, VW_IPC_VAULT_DELETE_RESP, req, sizeof(req));
}

int VwGuiIpc::vault_upload(uint32_t account_id, uint64_t vault_id, uint64_t file_id,
                            const char *leaf_name, const char *local_path,
                            uint64_t *out_file_id, uint64_t *out_version_id) {
    uint8_t req[4u + 16u + 2u + 256u + 2u + 1024u]; uint32_t off = 0;
    vw_write_u32le(req, account_id);   off += 4u;
    vw_write_u64le(req + off, vault_id);      off += 8u;
    vw_write_u64le(req + off, file_id); off += 8u;
    const char *leaf = leaf_name ? leaf_name : "";
    vw_ipc_write_str(req, sizeof(req), &off, leaf, (uint16_t)strlen(leaf));
    vw_ipc_write_str(req, sizeof(req), &off, local_path, (uint16_t)strlen(local_path));

    uint8_t resp[20]; uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_VAULT_UPLOAD_REQ, req, off, VW_IPC_VAULT_UPLOAD_RESP,
                             resp, sizeof(resp), &rlen);
    if (err != VW_OK) return (int)err;
    if (rlen < 20) return (int)VW_ERR_IO;
    uint32_t ec = read_u32_le(resp);
    if (ec == 0) {
        if (out_file_id)    *out_file_id    = (uint64_t)read_i64_le(resp + 4);
        if (out_version_id) *out_version_id = (uint64_t)read_i64_le(resp + 12);
    }
    return (int)ec;
}

int VwGuiIpc::vault_download(uint32_t account_id, uint64_t vault_id, uint64_t file_id, const char *local_path) {
    uint8_t req[4u + 16u + 2u + 1024u]; uint32_t off = 0;
    vw_write_u32le(req, account_id);   off += 4u;
    vw_write_u64le(req + off, vault_id);      off += 8u;
    vw_write_u64le(req + off, file_id); off += 8u;
    vw_ipc_write_str(req, sizeof(req), &off, local_path, (uint16_t)strlen(local_path));

    uint8_t resp[4]; uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_VAULT_DOWNLOAD_REQ, req, off, VW_IPC_VAULT_DOWNLOAD_RESP,
                             resp, sizeof(resp), &rlen);
    if (err != VW_OK) return (int)err;
    if (rlen < 4) return (int)VW_ERR_IO;
    return (int)read_u32_le(resp);
}

