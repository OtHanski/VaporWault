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

bool VwGuiIpc::send_pause(const char *folder_root) {
    uint8_t buf[514]; uint32_t off = 0;
    const char *s = folder_root ? folder_root : "";
    vw_ipc_write_str(buf, sizeof(buf), &off, s, (uint16_t)strlen(s));
    return simple_req_resp(VW_IPC_PAUSE_REQ, VW_IPC_PAUSE_RESP, buf, off) == 0;
}

bool VwGuiIpc::send_resume(const char *folder_root) {
    uint8_t buf[514]; uint32_t off = 0;
    const char *s = folder_root ? folder_root : "";
    vw_ipc_write_str(buf, sizeof(buf), &off, s, (uint16_t)strlen(s));
    return simple_req_resp(VW_IPC_RESUME_REQ, VW_IPC_RESUME_RESP, buf, off) == 0;
}

bool VwGuiIpc::send_shutdown() {
    return simple_req_resp(VW_IPC_SHUTDOWN_REQ, VW_IPC_SHUTDOWN_RESP, nullptr, 0) == 0;
}

int VwGuiIpc::send_folder_add(const char *local_root, const char *virtual_root) {
    uint8_t buf[1028]; uint32_t off = 0;
    vw_ipc_write_str(buf, sizeof(buf), &off, local_root,   (uint16_t)strlen(local_root));
    vw_ipc_write_str(buf, sizeof(buf), &off, virtual_root, (uint16_t)strlen(virtual_root));
    return simple_req_resp(VW_IPC_FOLDER_ADD_REQ, VW_IPC_FOLDER_ADD_RESP, buf, off);
}

int VwGuiIpc::send_folder_remove(const char *local_root) {
    uint8_t buf[514]; uint32_t off = 0;
    vw_ipc_write_str(buf, sizeof(buf), &off, local_root, (uint16_t)strlen(local_root));
    /* filter byte not needed for folder remove */
    return simple_req_resp(VW_IPC_FOLDER_REMOVE_REQ, VW_IPC_FOLDER_REMOVE_RESP, buf, off);
}

int VwGuiIpc::login(char *password, const char *otp) {
    uint8_t buf[600]; uint32_t off = 0;
    vw_ipc_write_str(buf, sizeof(buf), &off, password, (uint16_t)strnlen(password, 255));
    const char *o = otp ? otp : "";
    vw_ipc_write_str(buf, sizeof(buf), &off, o, (uint16_t)strnlen(o, 16));

    uint8_t resp[4]; uint32_t rlen;
    vw_err_t err = one_shot(VW_IPC_LOGIN_REQ, buf, off, VW_IPC_LOGIN_RESP, resp, sizeof(resp), &rlen);

    /* Zero both the wire-form request buffer and the caller's own field in
     * place (password is the caller's actual input buffer, passed by
     * pointer) — the caller does not need to zero it again. */
    memset(buf, 0, sizeof(buf));
    memset(password, 0, strlen(password));

    if (err != VW_OK) return (int)err;
    if (rlen < 4) return (int)VW_ERR_IO;
    return (int)read_u32_le(resp);
}

bool VwGuiIpc::file_list(const char *prefix, std::vector<VwGuiFileEntry> *out) {
    uint8_t req[518]; uint32_t roff = 0;
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
        if (off + 4u + 1u + 8u + 8u + 8u > rlen) break;

        VwGuiFileEntry e;
        e.virtual_path.assign(vpath, vplen);
        e.local_path.assign(lpath, lplen);
        e.sync_state   = read_u32_le(resp.data() + off); off += 4;
        e.entry_type   = resp[off++];
        e.server_mtime = read_i64_le(resp.data() + off); off += 8;
        e.local_mtime  = read_i64_le(resp.data() + off); off += 8;
        e.server_size  = (uint64_t)read_i64_le(resp.data() + off); off += 8;
        entries.push_back(std::move(e));
    }

    *out = std::move(entries);
    return true;
}
