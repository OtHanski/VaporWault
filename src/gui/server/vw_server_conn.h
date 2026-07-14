#pragma once

/*
 * vw_server_conn — thin C++ wrapper around vw_net + vw_proto for the server GUI.
 *
 * Manages the TLS connection to the server and provides typed send/recv of
 * framed protocol messages. No protocol logic lives here — callers encode
 * and decode payloads themselves using vw_proto helpers.
 *
 * Thread safety: not thread-safe. All methods must be called from the render
 * thread (or with external locking).
 */

extern "C" {
#include "vw_net.h"
#include "vw_proto.h"
}

#include <cstdint>
#include <cstdlib>

class VwServerConn {
public:
    VwServerConn() = default;
    ~VwServerConn() { disconnect(); }

    VwServerConn(const VwServerConn &) = delete;
    VwServerConn &operator=(const VwServerConn &) = delete;

    /* Connect and perform TLS handshake. ca_cert_path == nullptr uses NONE
     * verification (test mode only). Returns VW_OK on success. */
    vw_err_t connect(const char *host, uint16_t port,
                     const char *ca_cert_path,
                     uint32_t connect_timeout_ms = 5000,
                     uint32_t recv_timeout_ms    = 10000);

    /* Send one framed message. payload may be nullptr if payload_len == 0. */
    vw_err_t send_msg(vw_msg_type_t type,
                      const void *payload, uint32_t payload_len);

    /* Receive one framed message. Caller frees *out_payload (malloc'd).
     * Returns VW_ERR_PROTO_TOO_LARGE if the message exceeds 1 MiB admin limit. */
    vw_err_t recv_msg(vw_msg_type_t *out_type,
                      void **out_payload, uint32_t *out_payload_len);

    /* Close the TLS connection gracefully. Safe to call when disconnected. */
    void disconnect();

    bool is_connected() const { return conn_ != nullptr; }

    /* Negotiated protocol version (valid after a successful HELLO exchange). */
    uint16_t proto_version() const { return proto_version_; }

private:
    vw_conn_t *conn_         = nullptr;
    uint16_t   proto_version_ = 0;

    /* Recv buffer large enough for any admin response (1 MiB). */
    static constexpr uint32_t kRecvBufSize = 1u * 1024u * 1024u;
    uint8_t recv_buf_[kRecvBufSize];
};
