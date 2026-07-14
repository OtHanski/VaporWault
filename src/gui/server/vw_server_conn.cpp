#include "vw_server_conn.h"
#include <cstdlib>
#include <cstring>

vw_err_t VwServerConn::connect(const char *host, uint16_t port,
                                const char *ca_cert_path,
                                uint32_t connect_timeout_ms,
                                uint32_t recv_timeout_ms)
{
    disconnect();

    vw_conn_opts_t opts{};
    opts.connect_timeout_ms = connect_timeout_ms;
    opts.recv_timeout_ms    = recv_timeout_ms;

    vw_cert_verify_t verify = (ca_cert_path != nullptr)
        ? VW_CERT_VERIFY_REQUIRED
        : VW_CERT_VERIFY_NONE;

    vw_err_t rc = vw_net_connect(host, port, verify, ca_cert_path, &opts, &conn_);
    if (rc != VW_OK)
        return rc;

    /* Version negotiation: client side */
    rc = vw_proto_negotiate(conn_, /*is_server=*/0, &proto_version_);
    if (rc != VW_OK) {
        vw_net_close(conn_);
        conn_ = nullptr;
        return rc;
    }

    return VW_OK;
}

vw_err_t VwServerConn::send_msg(vw_msg_type_t type,
                                  const void *payload, uint32_t payload_len)
{
    if (!conn_) return VW_ERR_NET_CLOSED;
    return vw_proto_send(conn_, type, payload, payload_len);
}

vw_err_t VwServerConn::recv_msg(vw_msg_type_t *out_type,
                                  void **out_payload, uint32_t *out_payload_len)
{
    if (!conn_) return VW_ERR_NET_CLOSED;

    uint32_t payload_len = 0;
    vw_err_t rc = vw_proto_recv(conn_, out_type,
                                 recv_buf_, kRecvBufSize, &payload_len);
    if (rc != VW_OK)
        return rc;

    if (payload_len > 0) {
        void *buf = malloc(payload_len);
        if (!buf) return VW_ERR_OOM;
        memcpy(buf, recv_buf_, payload_len);
        *out_payload     = buf;
        *out_payload_len = payload_len;
    } else {
        *out_payload     = nullptr;
        *out_payload_len = 0;
    }
    return VW_OK;
}

void VwServerConn::disconnect()
{
    if (conn_) {
        vw_net_close(conn_);
        conn_ = nullptr;
    }
    proto_version_ = 0;
}
