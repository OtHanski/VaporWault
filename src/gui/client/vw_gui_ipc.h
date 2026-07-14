#pragma once

/*
 * vw_gui_ipc — thin C++ wrapper around vw_ipc_conn_t for use in the render loop.
 *
 * Owned by ClientApp. One connection attempt at a time; callers check is_connected()
 * before sending. All methods are called from the render thread; the background poll
 * thread holds the same mutex — callers must acquire it before calling any method.
 */

#include "vw_ipc.h"
#include <cstdint>
#include <cstring>

struct VwIpcStatus {
    uint8_t  connected        = 0;
    uint8_t  syncing          = 0;
    uint8_t  paused           = 0;
    int64_t  last_sync_at     = 0;
    uint32_t pending_uploads  = 0;
    uint32_t pending_downloads = 0;
    uint32_t error_count      = 0;
};

class VwGuiIpc {
public:
    VwGuiIpc() = default;
    ~VwGuiIpc() { disconnect(); }

    VwGuiIpc(const VwGuiIpc &) = delete;
    VwGuiIpc &operator=(const VwGuiIpc &) = delete;

    /* Attempt to connect. Returns true on success. */
    bool connect(uint16_t port = VW_IPC_DEFAULT_PORT);

    /* Close the connection. Safe to call when already disconnected. */
    void disconnect();

    bool is_connected() const { return conn_ != nullptr; }

    /* Send STATUS_REQ and decode STATUS_RESP into *out. Returns false on error. */
    bool fetch_status(VwIpcStatus *out);

    /* Simple fire-and-forget requests that return an error_code response. */
    bool send_sync_now();
    bool send_pause(const char *folder_root);   /* nullptr = all folders */
    bool send_resume(const char *folder_root);
    bool send_shutdown();

    /* Send FOLDER_ADD_REQ; returns vw_err_t encoded as int. */
    int send_folder_add(const char *local_root, const char *virtual_root);

    /* Send FOLDER_REMOVE_REQ. */
    int send_folder_remove(const char *local_root);

private:
    vw_ipc_conn_t *conn_  = nullptr;

    /* Send a request with an optional string payload and read a u32 error_code resp. */
    int simple_req_resp(vw_ipc_msg_t req_type, vw_ipc_msg_t resp_type,
                        const uint8_t *payload, uint32_t payload_len);
};
