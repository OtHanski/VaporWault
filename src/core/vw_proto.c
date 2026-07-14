#include "vw_proto.h"
#include "vw_net.h"

#include <string.h>

/* ── Bounded read/write primitives ───────────────────────────────────────── */

static vw_err_t pw_u8(uint8_t *b, uint32_t sz, uint32_t *o, uint8_t v)
{
    if (*o + 1u > sz) return VW_ERR_PROTO_TOO_LARGE;
    b[(*o)++] = v;
    return VW_OK;
}
static vw_err_t pw_u16(uint8_t *b, uint32_t sz, uint32_t *o, uint16_t v)
{
    if (*o + 2u > sz) return VW_ERR_PROTO_TOO_LARGE;
    vw_write_u16le(b + *o, v); *o += 2;
    return VW_OK;
}
static vw_err_t pw_u32(uint8_t *b, uint32_t sz, uint32_t *o, uint32_t v)
{
    if (*o + 4u > sz) return VW_ERR_PROTO_TOO_LARGE;
    vw_write_u32le(b + *o, v); *o += 4;
    return VW_OK;
}
static vw_err_t pw_u64(uint8_t *b, uint32_t sz, uint32_t *o, uint64_t v)
{
    if (*o + 8u > sz) return VW_ERR_PROTO_TOO_LARGE;
    vw_write_u64le(b + *o, v); *o += 8;
    return VW_OK;
}
static vw_err_t pw_raw(uint8_t *b, uint32_t sz, uint32_t *o, const void *src, uint32_t n)
{
    if (*o + n > sz) return VW_ERR_PROTO_TOO_LARGE;
    memcpy(b + *o, src, n); *o += n;
    return VW_OK;
}
static vw_err_t pr_u8(const uint8_t *b, uint32_t sz, uint32_t *o, uint8_t *v)
{
    if (*o + 1u > sz) return VW_ERR_PROTO_TRUNCATED;
    *v = b[(*o)++];
    return VW_OK;
}
static vw_err_t pr_u16(const uint8_t *b, uint32_t sz, uint32_t *o, uint16_t *v)
{
    if (*o + 2u > sz) return VW_ERR_PROTO_TRUNCATED;
    *v = vw_read_u16le(b + *o); *o += 2;
    return VW_OK;
}
static vw_err_t pr_u32(const uint8_t *b, uint32_t sz, uint32_t *o, uint32_t *v)
{
    if (*o + 4u > sz) return VW_ERR_PROTO_TRUNCATED;
    *v = vw_read_u32le(b + *o); *o += 4;
    return VW_OK;
}
static vw_err_t pr_u64(const uint8_t *b, uint32_t sz, uint32_t *o, uint64_t *v)
{
    if (*o + 8u > sz) return VW_ERR_PROTO_TRUNCATED;
    *v = vw_read_u64le(b + *o); *o += 8;
    return VW_OK;
}
static vw_err_t pr_raw(const uint8_t *b, uint32_t sz, uint32_t *o, void *dst, uint32_t n)
{
    if (*o + n > sz) return VW_ERR_PROTO_TRUNCATED;
    memcpy(dst, b + *o, n); *o += n;
    return VW_OK;
}

/* ── Send ────────────────────────────────────────────────────────────────── */

vw_err_t vw_proto_send(vw_conn_t *conn, vw_msg_type_t type,
                        const void *payload, uint32_t payload_len) {
    uint32_t total_len = VW_PROTO_HEADER_SIZE + payload_len;
    if (total_len < VW_PROTO_HEADER_SIZE) return VW_ERR_PROTO_TOO_LARGE; /* overflow */
    if (total_len > VW_MAX_MSG_BYTES)     return VW_ERR_PROTO_TOO_LARGE;

    uint8_t hdr[VW_PROTO_HEADER_SIZE];
    vw_write_u32le(hdr + 0, total_len);
    vw_write_u16le(hdr + 4, (uint16_t)type);
    vw_write_u16le(hdr + 6, VW_PROTO_VERSION_CURRENT);

    vw_err_t err = vw_net_send(conn, hdr, VW_PROTO_HEADER_SIZE);
    if (err != VW_OK) return err;

    if (payload_len > 0) {
        err = vw_net_send(conn, payload, payload_len);
        if (err != VW_OK) return err;
    }
    return VW_OK;
}

/* ── Recv ────────────────────────────────────────────────────────────────── */

vw_err_t vw_proto_recv(vw_conn_t *conn, vw_msg_type_t *out_type,
                        void *out_buf, uint32_t buf_size,
                        uint32_t *out_payload_len) {
    uint8_t hdr[VW_PROTO_HEADER_SIZE];
    vw_err_t err = vw_net_recv(conn, hdr, VW_PROTO_HEADER_SIZE);
    if (err != VW_OK) return err;

    uint32_t total_len = vw_read_u32le(hdr + 0);

    /* Enforce maximum message size before any allocation or further reads */
    if (total_len < VW_PROTO_HEADER_SIZE) return VW_ERR_PROTO_INVALID;
    if (total_len > VW_MAX_MSG_BYTES)     return VW_ERR_PROTO_TOO_LARGE;

    uint32_t payload_len = total_len - VW_PROTO_HEADER_SIZE;

    /* Ensure caller buffer is large enough */
    if (payload_len > buf_size) return VW_ERR_PROTO_TOO_LARGE;

    *out_type = (vw_msg_type_t)vw_read_u16le(hdr + 4);
    /* proto_version at hdr+6 is informational; checked in negotiate() */

    if (payload_len > 0) {
        err = vw_net_recv(conn, out_buf, payload_len);
        if (err != VW_OK) return err;
    }

    *out_payload_len = payload_len;
    return VW_OK;
}

/* ── Version negotiation ─────────────────────────────────────────────────── */

vw_err_t vw_proto_negotiate(vw_conn_t *conn, int is_server,
                             uint16_t *out_version) {
    if (is_server) {
        /* Server: wait for HELLO, then send HELLO_OK or VERSION_REJECT */
        vw_msg_type_t type;
        uint8_t payload[VW_PROTO_HEADER_SIZE + 4];  /* hello payload is tiny */
        uint32_t plen;

        vw_err_t err = vw_proto_recv(conn, &type, payload, sizeof(payload), &plen);
        if (err != VW_OK) return err;
        if (type != VW_MSG_HELLO) return VW_ERR_PROTO_INVALID;
        if (plen < 2)             return VW_ERR_PROTO_INVALID;

        uint16_t client_max = vw_read_u16le(payload);

        /* We only support VW_PROTO_VERSION_CURRENT */
        if (client_max < VW_PROTO_VERSION_CURRENT) {
            uint8_t reject[4];
            vw_write_u16le(reject + 0, VW_PROTO_VERSION_CURRENT);  /* our min */
            vw_write_u16le(reject + 2, VW_PROTO_VERSION_CURRENT);  /* our max */
            /* ignore send error — we're closing the connection immediately after */
            (void)vw_proto_send(conn, VW_MSG_VERSION_REJECT, reject, sizeof(reject));
            return VW_ERR_PROTO_VERSION;
        }

        /* HELLO_OK: negotiated_version (2 bytes) + server_id (16 bytes) */
        uint16_t negotiated = VW_PROTO_VERSION_CURRENT;
        uint8_t hello_ok[18];
        vw_write_u16le(hello_ok, negotiated);
        memset(hello_ok + 2, 0, 16);  /* server_id: zeroed (filled in by caller later) */

        err = vw_proto_send(conn, VW_MSG_HELLO_OK, hello_ok, sizeof(hello_ok));
        if (err != VW_OK) return err;

        *out_version = negotiated;
    } else {
        /* Client: send HELLO, receive HELLO_OK or VERSION_REJECT */
        uint8_t hello[2];
        vw_write_u16le(hello, VW_PROTO_VERSION_CURRENT);

        vw_err_t err = vw_proto_send(conn, VW_MSG_HELLO, hello, sizeof(hello));
        if (err != VW_OK) return err;

        vw_msg_type_t type;
        uint8_t payload[64];
        uint32_t plen;

        err = vw_proto_recv(conn, &type, payload, sizeof(payload), &plen);
        if (err != VW_OK) return err;

        if (type == VW_MSG_VERSION_REJECT) return VW_ERR_PROTO_VERSION;
        if (type != VW_MSG_HELLO_OK)       return VW_ERR_PROTO_INVALID;
        if (plen < 2)                      return VW_ERR_PROTO_INVALID;

        *out_version = vw_read_u16le(payload);
        if (*out_version != VW_PROTO_VERSION_CURRENT) return VW_ERR_PROTO_VERSION;
    }

    return VW_OK;
}

/* ── String serialisation helpers ────────────────────────────────────────── */

vw_err_t vw_proto_write_str(uint8_t *buf, uint32_t buf_size, uint32_t *offset,
                             const char *str, uint16_t str_len) {
    /* 2-byte length prefix + string bytes; guard written this way to prevent unsigned underflow */
    if (*offset > buf_size || (uint32_t)str_len + 2u > buf_size - *offset)
        return VW_ERR_PROTO_TOO_LARGE;
    vw_write_u16le(buf + *offset, str_len);
    *offset += 2;
    if (str_len > 0) {
        memcpy(buf + *offset, str, str_len);
        *offset += str_len;
    }
    return VW_OK;
}

vw_err_t vw_proto_read_str(const uint8_t *buf, uint32_t buf_size, uint32_t *offset,
                            const char **out_str, uint16_t *out_len) {
    if (*offset + 2u > buf_size) return VW_ERR_PROTO_TRUNCATED;
    uint16_t slen = vw_read_u16le(buf + *offset);
    *offset += 2;
    if (*offset + (uint32_t)slen > buf_size) return VW_ERR_PROTO_TRUNCATED;
    *out_str = (const char *)(buf + *offset);
    *out_len = slen;
    *offset += slen;
    return VW_OK;
}

/* ── Auth payload encode / decode ────────────────────────────────────────── */

vw_err_t vw_proto_encode_auth_request(
    const vw_payload_auth_request_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len)
{
    uint32_t o = 0;
    vw_err_t err;
    if ((err = vw_proto_write_str(buf, buf_size, &o, p->username, p->username_len)) != VW_OK) return err;
    if ((err = pw_raw(buf, buf_size, &o, p->auth_token, VW_TOKEN_BYTES)) != VW_OK) return err;
    *out_len = o;
    return VW_OK;
}

vw_err_t vw_proto_decode_auth_request(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_request_t *out)
{
    uint32_t o = 0;
    vw_err_t err;
    if ((err = vw_proto_read_str(buf, len, &o, &out->username, &out->username_len)) != VW_OK) return err;
    if (out->username_len == 0 || out->username_len > VW_MAX_USERNAME_BYTES) return VW_ERR_PROTO_TRUNCATED;
    if ((err = pr_raw(buf, len, &o, out->auth_token, VW_TOKEN_BYTES)) != VW_OK) return err;
    if (o != len) return VW_ERR_PROTO_TRUNCATED;
    return VW_OK;
}

vw_err_t vw_proto_encode_auth_challenge(
    const vw_payload_auth_challenge_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len)
{
    uint32_t o = 0;
    vw_err_t err;
    if ((err = pw_u8(buf, buf_size, &o, p->challenge_type)) != VW_OK) return err;
    if ((err = vw_proto_write_str(buf, buf_size, &o, p->hint, p->hint_len)) != VW_OK) return err;
    *out_len = o;
    return VW_OK;
}

vw_err_t vw_proto_decode_auth_challenge(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_challenge_t *out)
{
    uint32_t o = 0;
    vw_err_t err;
    if ((err = pr_u8(buf, len, &o, &out->challenge_type)) != VW_OK) return err;
    if ((err = vw_proto_read_str(buf, len, &o, &out->hint, &out->hint_len)) != VW_OK) return err;
    if (o != len) return VW_ERR_PROTO_TRUNCATED;
    return VW_OK;
}

vw_err_t vw_proto_encode_auth_otp(
    const vw_payload_auth_otp_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len)
{
    uint32_t o = 0;
    vw_err_t err;
    if ((err = vw_proto_write_str(buf, buf_size, &o, p->otp_code, p->otp_len)) != VW_OK) return err;
    *out_len = o;
    return VW_OK;
}

vw_err_t vw_proto_decode_auth_otp(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_otp_t *out)
{
    uint32_t o = 0;
    vw_err_t err;
    if ((err = vw_proto_read_str(buf, len, &o, &out->otp_code, &out->otp_len)) != VW_OK) return err;
    if (out->otp_len < 1 || out->otp_len > 8) return VW_ERR_PROTO_TRUNCATED;
    if (o != len) return VW_ERR_PROTO_TRUNCATED;
    return VW_OK;
}

vw_err_t vw_proto_encode_auth_ok(
    const vw_payload_auth_ok_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len)
{
    uint32_t o = 0;
    vw_err_t err;
    if ((err = pw_raw(buf, buf_size, &o, p->session_token, VW_TOKEN_BYTES)) != VW_OK) return err;
    if ((err = pw_u64(buf, buf_size, &o, (uint64_t)p->expires_at)) != VW_OK) return err;
    if ((err = pw_u8(buf, buf_size, &o, p->is_admin)) != VW_OK) return err;
    if ((err = pw_u64(buf, buf_size, &o, p->quota_bytes)) != VW_OK) return err;
    if ((err = pw_u64(buf, buf_size, &o, p->used_bytes)) != VW_OK) return err;
    if ((err = pw_u64(buf, buf_size, &o, p->user_id)) != VW_OK) return err;
    *out_len = o;
    return VW_OK;
}

vw_err_t vw_proto_decode_auth_ok(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_ok_t *out)
{
    uint32_t o = 0;
    uint64_t expires_raw;
    vw_err_t err;
    if ((err = pr_raw(buf, len, &o, out->session_token, VW_TOKEN_BYTES)) != VW_OK) return err;
    if ((err = pr_u64(buf, len, &o, &expires_raw)) != VW_OK) return err;
    out->expires_at = (int64_t)expires_raw;
    if ((err = pr_u8(buf, len, &o, &out->is_admin)) != VW_OK) return err;
    if ((err = pr_u64(buf, len, &o, &out->quota_bytes)) != VW_OK) return err;
    if ((err = pr_u64(buf, len, &o, &out->used_bytes)) != VW_OK) return err;
    if ((err = pr_u64(buf, len, &o, &out->user_id)) != VW_OK) return err;
    if (o != len) return VW_ERR_PROTO_TRUNCATED;
    return VW_OK;
}

vw_err_t vw_proto_encode_auth_fail(
    const vw_payload_auth_fail_t *p,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len)
{
    uint32_t o = 0;
    vw_err_t err;
    if ((err = pw_u32(buf, buf_size, &o, p->error_code)) != VW_OK) return err;
    if ((err = pw_u16(buf, buf_size, &o, p->lockout_remaining_secs)) != VW_OK) return err;
    *out_len = o;
    return VW_OK;
}

vw_err_t vw_proto_decode_auth_fail(
    const uint8_t *buf, uint32_t len,
    vw_payload_auth_fail_t *out)
{
    uint32_t o = 0;
    vw_err_t err;
    if ((err = pr_u32(buf, len, &o, &out->error_code)) != VW_OK) return err;
    if ((err = pr_u16(buf, len, &o, &out->lockout_remaining_secs)) != VW_OK) return err;
    if (o != len) return VW_ERR_PROTO_TRUNCATED;
    return VW_OK;
}

vw_err_t vw_proto_encode_error(
    uint32_t error_code, const char *msg, uint16_t msg_len,
    uint8_t *buf, uint32_t buf_size, uint32_t *out_len)
{
    uint32_t o = 0;
    vw_err_t err;
    if ((err = pw_u32(buf, buf_size, &o, error_code)) != VW_OK) return err;
    if ((err = vw_proto_write_str(buf, buf_size, &o, msg, msg_len)) != VW_OK) return err;
    *out_len = o;
    return VW_OK;
}

vw_err_t vw_proto_decode_error(
    const uint8_t *buf, uint32_t len,
    uint32_t *out_code, const char **out_msg, uint16_t *out_msg_len)
{
    uint32_t o = 0;
    vw_err_t err;
    if ((err = pr_u32(buf, len, &o, out_code)) != VW_OK) return err;
    if ((err = vw_proto_read_str(buf, len, &o, out_msg, out_msg_len)) != VW_OK) return err;
    if (o != len) return VW_ERR_PROTO_TRUNCATED;
    return VW_OK;
}
