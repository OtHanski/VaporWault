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
    disconnect();
    return vw_ipc_connect(port, &conn_) == VW_OK;
}

void VwGuiIpc::disconnect() {
    if (conn_) { vw_ipc_conn_close(conn_); conn_ = nullptr; }
}

bool VwGuiIpc::fetch_status(VwIpcStatus *out) {
    if (!conn_) return false;
    if (vw_ipc_send(conn_, VW_IPC_STATUS_REQ, nullptr, 0) != VW_OK) {
        disconnect(); return false;
    }
    uint8_t buf[64];
    vw_ipc_msg_t type; uint32_t plen;
    if (vw_ipc_recv(conn_, &type, buf, sizeof(buf), &plen) != VW_OK
            || type != VW_IPC_STATUS_RESP || plen < 20) {
        disconnect(); return false;
    }
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
    if (!conn_) return (int)VW_ERR_IPC_NOT_RUNNING;
    if (vw_ipc_send(conn_, req_type, payload, payload_len) != VW_OK) {
        disconnect(); return (int)VW_ERR_IO;
    }
    uint8_t buf[8]; vw_ipc_msg_t type; uint32_t plen;
    if (vw_ipc_recv(conn_, &type, buf, sizeof(buf), &plen) != VW_OK
            || type != resp_type || plen < 4) {
        disconnect(); return (int)VW_ERR_IO;
    }
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
