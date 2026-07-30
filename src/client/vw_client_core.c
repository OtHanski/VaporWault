#include "vw_client_core.h"
#include "../core/vw_crypto.h"
#include "../core/vw_fs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void *(* volatile g_memset_fn)(void *, int, size_t) = memset;
#define secure_zero(p, n) ((void)g_memset_fn((p), 0, (n)))

struct vw_client_sess {
    vw_conn_t *conn;
    uint64_t   user_id;
    uint8_t    session_token[VW_TOKEN_BYTES];
    int64_t    expires_at;
    uint8_t    is_admin;
    uint64_t   quota_bytes;
    uint64_t   used_bytes;
};

/* ── Internal helpers ────────────────────────────────────────────────────── */

static vw_err_t do_connect(const vw_client_cfg_t *cfg, vw_conn_t **out_conn)
{
    return vw_net_connect(cfg->host, cfg->port, cfg->cert_verify,
                           cfg->ca_cert_pem_path, cfg->conn_opts, out_conn);
}

static void sess_destroy(vw_client_sess_t *sess)
{
    if (!sess) return;
    secure_zero(sess->session_token, VW_TOKEN_BYTES);
    vw_net_close(sess->conn);
    free(sess);
}

/*
 * Receive AUTH_OK or AUTH_FAIL and populate sess on success.
 * Returns the auth error code on AUTH_FAIL.
 */
static vw_err_t recv_auth_result(vw_conn_t *conn, vw_client_sess_t *sess)
{
    vw_msg_type_t type;
    uint8_t buf[128];
    uint32_t plen;
    vw_err_t err = vw_proto_recv(conn, &type, buf, sizeof(buf), &plen);
    if (err != VW_OK) return err;

    if (type == VW_MSG_AUTH_OK) {
        vw_payload_auth_ok_t ok;
        err = vw_proto_decode_auth_ok(buf, plen, &ok);
        if (err != VW_OK) {
            secure_zero(buf, sizeof(buf));
            return err;
        }
        memcpy(sess->session_token, ok.session_token, VW_TOKEN_BYTES);
        sess->expires_at  = ok.expires_at;
        sess->is_admin    = ok.is_admin;
        sess->quota_bytes = ok.quota_bytes;
        sess->used_bytes  = ok.used_bytes;
        sess->user_id     = ok.user_id;
        secure_zero(&ok, sizeof(ok));   /* wipe decoded session token */
        secure_zero(buf, sizeof(buf));  /* wipe wire form */
        return VW_OK;
    }

    if (type == VW_MSG_AUTH_FAIL) {
        vw_payload_auth_fail_t fail;
        if (vw_proto_decode_auth_fail(buf, plen, &fail) == VW_OK)
            return (vw_err_t)fail.error_code;
        return VW_ERR_AUTH_BAD_CREDS;
    }

    return VW_ERR_PROTO_INVALID;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

vw_err_t vw_client_connect(const vw_client_cfg_t *cfg,
                             const char *username, uint16_t username_len,
                             const void *password, size_t pw_len,
                             vw_otp_callback_t otp_cb, void *otp_userdata,
                             vw_client_sess_t **out_sess)
{
    if (!cfg || !username || !password || !out_sess) return VW_ERR_INVALID_ARG;
    if (!username_len || username_len > VW_MAX_USERNAME_BYTES)
        return VW_ERR_INVALID_ARG;

    vw_client_sess_t *sess = calloc(1, sizeof(*sess));
    if (!sess) return VW_ERR_OOM;

    vw_err_t err = do_connect(cfg, &sess->conn);
    if (err != VW_OK) { free(sess); return err; }

    uint16_t version;
    err = vw_proto_negotiate(sess->conn, 0 /*is_server*/, &version);
    if (err != VW_OK) { sess_destroy(sess); return err; }

    /* Derive auth_token = SHA-256(password) — PROTOCOL.md §8.1 Phase 1 */
    uint8_t auth_token[VW_TOKEN_BYTES];
    err = vw_crypto_sha256(password, pw_len, auth_token);
    if (err != VW_OK) { sess_destroy(sess); return err; }

    /* Encode AUTH_REQUEST */
    vw_payload_auth_request_t req;
    req.username     = username;
    req.username_len = username_len;
    memcpy(req.auth_token, auth_token, VW_TOKEN_BYTES);
    secure_zero(auth_token, VW_TOKEN_BYTES);  /* wipe local copy after memcpy */

    uint8_t req_buf[2u + VW_MAX_USERNAME_BYTES + VW_TOKEN_BYTES];
    uint32_t req_len;
    err = vw_proto_encode_auth_request(&req, req_buf, sizeof(req_buf), &req_len);
    if (err != VW_OK) {
        secure_zero(req.auth_token, VW_TOKEN_BYTES);
        secure_zero(req_buf, sizeof(req_buf));
        sess_destroy(sess);
        return err;
    }

    err = vw_proto_send(sess->conn, VW_MSG_AUTH_REQUEST, req_buf, req_len);
    secure_zero(req.auth_token, VW_TOKEN_BYTES);  /* wipe struct copy */
    secure_zero(req_buf, sizeof(req_buf));          /* wipe encoded wire form */
    if (err != VW_OK) { sess_destroy(sess); return err; }

    /* Receive AUTH_OK, AUTH_CHALLENGE, or AUTH_FAIL */
    vw_msg_type_t type;
    uint8_t resp[256];
    uint32_t resp_plen;
    err = vw_proto_recv(sess->conn, &type, resp, sizeof(resp), &resp_plen);
    if (err != VW_OK) { sess_destroy(sess); return err; }

    if (type == VW_MSG_AUTH_OK) {
        vw_payload_auth_ok_t ok;
        err = vw_proto_decode_auth_ok(resp, resp_plen, &ok);
        if (err != VW_OK) {
            secure_zero(resp, sizeof(resp));
            sess_destroy(sess);
            return err;
        }
        memcpy(sess->session_token, ok.session_token, VW_TOKEN_BYTES);
        sess->expires_at  = ok.expires_at;
        sess->is_admin    = ok.is_admin;
        sess->quota_bytes = ok.quota_bytes;
        sess->used_bytes  = ok.used_bytes;
        sess->user_id     = ok.user_id;
        secure_zero(&ok, sizeof(ok));    /* wipe decoded session token */
        secure_zero(resp, sizeof(resp)); /* wipe wire form */
        *out_sess = sess;
        return VW_OK;
    }

    if (type == VW_MSG_AUTH_CHALLENGE) {
        if (!otp_cb) { sess_destroy(sess); return VW_ERR_AUTH_2FA_REQUIRED; }

        char otp_buf[16] = {0};
        uint16_t otp_len = 0;
        err = otp_cb(otp_userdata, otp_buf, &otp_len);
        if (err != VW_OK) { sess_destroy(sess); return err; }

        vw_payload_auth_otp_t otp_payload;
        otp_payload.otp_code = otp_buf;
        otp_payload.otp_len  = otp_len;

        /* Encode: 2-byte length prefix + up to 8 digit bytes */
        uint8_t otp_wire[2u + 8u];
        uint32_t otp_wire_len;
        err = vw_proto_encode_auth_otp(&otp_payload, otp_wire,
                                        sizeof(otp_wire), &otp_wire_len);
        secure_zero(otp_buf, sizeof(otp_buf));  /* wipe OTP code after encoding */
        if (err != VW_OK) { sess_destroy(sess); return err; }

        err = vw_proto_send(sess->conn, VW_MSG_AUTH_OTP, otp_wire, otp_wire_len);
        if (err != VW_OK) { sess_destroy(sess); return err; }

        err = recv_auth_result(sess->conn, sess);
        if (err != VW_OK) { sess_destroy(sess); return err; }

        *out_sess = sess;
        return VW_OK;
    }

    if (type == VW_MSG_AUTH_FAIL) {
        vw_payload_auth_fail_t fail;
        if (vw_proto_decode_auth_fail(resp, resp_plen, &fail) == VW_OK)
            err = (vw_err_t)fail.error_code;
        else
            err = VW_ERR_AUTH_BAD_CREDS;
        sess_destroy(sess);
        return err;
    }

    sess_destroy(sess);
    return VW_ERR_PROTO_INVALID;
}

vw_err_t vw_client_resume(const vw_client_cfg_t *cfg,
                            const uint8_t saved_token[VW_TOKEN_BYTES],
                            vw_client_sess_t **out_sess)
{
    if (!cfg || !saved_token || !out_sess) return VW_ERR_INVALID_ARG;

    vw_client_sess_t *sess = calloc(1, sizeof(*sess));
    if (!sess) return VW_ERR_OOM;

    vw_err_t err = do_connect(cfg, &sess->conn);
    if (err != VW_OK) { free(sess); return err; }

    uint16_t version;
    err = vw_proto_negotiate(sess->conn, 0 /*is_server*/, &version);
    if (err != VW_OK) { sess_destroy(sess); return err; }

    err = vw_proto_send(sess->conn, VW_MSG_SESSION_RESUME,
                         saved_token, VW_TOKEN_BYTES);
    if (err != VW_OK) { sess_destroy(sess); return err; }

    err = recv_auth_result(sess->conn, sess);
    if (err != VW_OK) { sess_destroy(sess); return err; }

    *out_sess = sess;
    return VW_OK;
}

void vw_client_get_token(const vw_client_sess_t *sess,
                          uint8_t out_token[VW_TOKEN_BYTES])
{
    if (!sess || !out_token) return;
    memcpy(out_token, sess->session_token, VW_TOKEN_BYTES);
}

uint64_t vw_client_user_id_of(const vw_client_sess_t *sess)
{
    return sess ? sess->user_id : 0;
}

int64_t vw_client_expires_at_of(const vw_client_sess_t *sess)
{
    return sess ? sess->expires_at : 0;
}

uint8_t vw_client_is_admin_of(const vw_client_sess_t *sess)
{
    return sess ? sess->is_admin : 0;
}

void vw_client_logout(vw_client_sess_t *sess)
{
    if (!sess) return;
    (void)vw_proto_send(sess->conn, VW_MSG_AUTH_LOGOUT, NULL, 0);
    sess_destroy(sess);
}

void vw_client_close(vw_client_sess_t *sess)
{
    sess_destroy(sess);
}

vw_conn_t *vw_client_conn(vw_client_sess_t *sess)
{
    return sess ? sess->conn : NULL;
}

/* ── Phase 2: File Transfer ──────────────────────────────────────────────── */

#ifndef VW_MIN
#define VW_MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

/* Max hashes per CHUNK_QUERY round (PROTOCOL.md §7.2 — uint16, max 1024). */
#define CHUNK_QUERY_MAX 1024u

/*
 * Returns VW_ERR_AUTH_REQUIRED if sess is NULL or already expired,
 * VW_OK otherwise.
 */
static vw_err_t sess_check_valid(const vw_client_sess_t *sess)
{
    if (!sess) return VW_ERR_AUTH_REQUIRED;
    time_t now = time(NULL);
    if (sess->expires_at != 0 && (int64_t)now >= sess->expires_at)
        return VW_ERR_AUTH_REQUIRED;
    return VW_OK;
}

/*
 * Validate a virtual path per PROTOCOL.md §7.8.2.
 * Returns VW_ERR_PATH_INVALID if the path is bad.
 */
static vw_err_t path_validate_client(const char *path)
{
    if (!path || path[0] != '/')       return VW_ERR_PATH_INVALID;
    size_t len = strlen(path);
    if (len > VW_MAX_PATH_BYTES)       return VW_ERR_PATH_INVALID;
    for (size_t i = 0; i < len; i++) {
        if (path[i] == '\0' || path[i] == '\\')
            return VW_ERR_PATH_INVALID;
    }
    /* Reject ".." components and empty components */
    const char *p = path;
    while (*p) {
        if (*p == '/') {
            p++;
            if (*p == '/')             return VW_ERR_PATH_INVALID;
            if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0'))
                return VW_ERR_PATH_INVALID;
        } else {
            p++;
        }
    }
    return VW_OK;
}

/*
 * Receive a response. If the server sent VW_MSG_ERROR instead of
 * expected_type, extract and return the embedded error code.
 * On success, *out_plen is the payload byte count already written to buf.
 */
static vw_err_t recv_expect(vw_conn_t *conn, vw_msg_type_t expected_type,
                              void *buf, uint32_t buf_size, uint32_t *out_plen)
{
    vw_msg_type_t type;
    vw_err_t err = vw_proto_recv(conn, &type, buf, buf_size, out_plen);
    if (err != VW_OK) return err;
    if (type == expected_type) return VW_OK;
    if (type == VW_MSG_ERROR && *out_plen >= 4)
        return (vw_err_t)vw_read_u32le((const uint8_t *)buf);
    return VW_ERR_PROTO_INVALID;
}

/* ── vw_client_file_list ─────────────────────────────────────────────────── */

vw_err_t vw_client_file_list(vw_client_sess_t *sess,
                               const char *virtual_path,
                               uint8_t recursive,
                               vw_file_entry_t **out,
                               uint32_t *out_count)
{
    vw_err_t err;
    if (!sess || !virtual_path || !out || !out_count) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK) return err;
    if ((err = path_validate_client(virtual_path)) != VW_OK) return err;

    uint16_t path_len = (uint16_t)strlen(virtual_path);

    /* Build payload: token[32] + recursive(u8) + include_deleted(u8) +
     *                path_len(u16 LE) + path */
    uint32_t plen = VW_TOKEN_BYTES + 1u + 1u + 2u + (uint32_t)path_len;
    uint8_t *pbuf = malloc(plen);
    if (!pbuf) return VW_ERR_OOM;
    uint8_t *p = pbuf;
    memcpy(p, sess->session_token, VW_TOKEN_BYTES); p += VW_TOKEN_BYTES;
    *p++ = recursive;
    *p++ = 0; /* include_deleted=0 */
    vw_write_u16le(p, path_len); p += 2;
    memcpy(p, virtual_path, path_len);

    err = vw_proto_send(sess->conn, VW_MSG_FILE_LIST, pbuf, plen);
    free(pbuf);
    if (err != VW_OK) return err;

    /* Receive FILE_LIST_RESP. Max 65535 entries × ~300 bytes ≈ 20 MiB;
     * allocate a VW_MAX_MSG_BYTES receive buffer. */
    uint8_t *rbuf = malloc(VW_MAX_MSG_BYTES);
    if (!rbuf) return VW_ERR_OOM;
    uint32_t rplen;
    err = recv_expect(sess->conn, VW_MSG_FILE_LIST_RESP, rbuf, VW_MAX_MSG_BYTES, &rplen);
    if (err != VW_OK) { free(rbuf); return err; }

    /* Decode: count(u32) then repeated entries */
    if (rplen < 4) { free(rbuf); return VW_ERR_PROTO_TRUNCATED; }
    uint32_t count = vw_read_u32le(rbuf);
    uint32_t off = 4;

    vw_file_entry_t *entries = NULL;
    if (count > 0) {
        entries = calloc(count, sizeof(*entries));
        if (!entries) { free(rbuf); return VW_ERR_OOM; }
    }

    for (uint32_t i = 0; i < count; i++) {
        /* name (string: u16 len + bytes) */
        if (off + 2 > rplen) goto trunc;
        uint16_t nlen = vw_read_u16le(rbuf + off); off += 2;
        if (off + nlen > rplen) goto trunc;
        uint16_t copy_len = (uint16_t)VW_MIN(nlen, 255u);
        memcpy(entries[i].name, rbuf + off, copy_len);
        entries[i].name[copy_len] = '\0';
        off += nlen;
        /* file_id(u64) + size_bytes(u64) + mtime_unix(i64) + entry_type(u8) + perm(u8) */
        if (off + 8 + 8 + 8 + 1 + 1 > rplen) goto trunc;
        entries[i].file_id    = vw_read_u64le(rbuf + off); off += 8;
        entries[i].size_bytes = vw_read_u64le(rbuf + off); off += 8;
        entries[i].mtime_unix = (int64_t)vw_read_u64le(rbuf + off); off += 8;
        entries[i].entry_type = rbuf[off++];
        /* perm: consumed but not stored (vw_file_entry_t has no perm field) */
        off++;
    }
    free(rbuf);
    *out = entries;
    *out_count = count;
    return VW_OK;

trunc:
    free(entries);
    free(rbuf);
    return VW_ERR_PROTO_TRUNCATED;
}

/* ── vw_client_file_stat ─────────────────────────────────────────────────── */

/*
 * Shared by vw_client_file_stat (file_id=0, path lookup) and
 * vw_client_file_stat_by_id (file_id!=0, path ignored server-side).
 */
static vw_err_t stat_common(vw_client_sess_t *sess, uint64_t file_id,
                             const char *virtual_path, vw_file_entry_t *out)
{
    uint16_t path_len = virtual_path ? (uint16_t)strlen(virtual_path) : 0u;

    /* token[32] + file_id(u64) + path_len(u16) + path (path only meaningful
     * when file_id == 0) */
    uint32_t plen = VW_TOKEN_BYTES + 8u + 2u + (uint32_t)path_len;
    uint8_t *pbuf = malloc(plen);
    if (!pbuf) return VW_ERR_OOM;
    uint8_t *p = pbuf;
    memcpy(p, sess->session_token, VW_TOKEN_BYTES); p += VW_TOKEN_BYTES;
    vw_write_u64le(p, file_id); p += 8;
    vw_write_u16le(p, path_len); p += 2;
    if (path_len > 0) memcpy(p, virtual_path, path_len);

    vw_err_t err = vw_proto_send(sess->conn, VW_MSG_FILE_STAT, pbuf, plen);
    free(pbuf);
    if (err != VW_OK) return err;

    /* FILE_STAT_RESP: fixed fields (44 bytes) + path (up to 4096) → max 4140 bytes.
     * Allocate enough to satisfy vw_proto_recv's buf_size check. */
    uint8_t *rbuf = malloc(8192u);
    if (!rbuf) return VW_ERR_OOM;
    uint32_t rplen;
    err = recv_expect(sess->conn, VW_MSG_FILE_STAT_RESP, rbuf, 8192u, &rplen);
    if (err != VW_OK) { free(rbuf); return err; }

    /* entry_type(u8) + file_id(u64) + size_bytes(u64) + mtime_unix(i64) +
     * version_id(u64) + owner_id(u64) + perm(u8) + path_len(u16) + path */
    if (rplen < 1u + 8u + 8u + 8u + 8u + 8u + 1u + 2u) {
        free(rbuf);
        return VW_ERR_PROTO_TRUNCATED;
    }
    uint32_t off = 0;
    out->entry_type = rbuf[off++];
    out->file_id    = vw_read_u64le(rbuf + off); off += 8;
    out->size_bytes = vw_read_u64le(rbuf + off); off += 8;
    out->mtime_unix = (int64_t)vw_read_u64le(rbuf + off); off += 8;
    out->version_id = vw_read_u64le(rbuf + off); off += 8;
    /* owner_id: consumed, not returned */    off += 8;
    /* perm:     consumed, not returned */    off++;
    /* path string: not stored (caller already knows it) */
    free(rbuf);
    return VW_OK;
}

vw_err_t vw_client_file_stat(vw_client_sess_t *sess,
                               const char *virtual_path,
                               vw_file_entry_t *out)
{
    vw_err_t err;
    if (!sess || !virtual_path || !out) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK) return err;
    if ((err = path_validate_client(virtual_path)) != VW_OK) return err;
    return stat_common(sess, 0, virtual_path, out);
}

vw_err_t vw_client_file_stat_by_id(vw_client_sess_t *sess,
                                    uint64_t file_id,
                                    vw_file_entry_t *out)
{
    vw_err_t err;
    if (!sess || file_id == 0 || !out) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK) return err;
    return stat_common(sess, file_id, NULL, out);
}

/* ── Shared upload helper (hash + CHUNK_QUERY + CHUNK_UPLOAD passes) ─────── */

/*
 * Hashes local_path in VW_CHUNK_SIZE chunks, queries the server for which
 * are already present, and uploads the missing ones. *out_hashes receives
 * a malloc'd ordered chunk-hash array (caller frees); *out_chunk_count and
 * *out_logical_size receive the chunk count and total byte size.
 *
 * Factored out of vw_client_file_upload so the file_id-addressed variants
 * below (vw_client_file_upload_to_id/_into_folder) share the exact same
 * chunking/dedup/upload logic and only need to build their own FILE_COMMIT
 * payload afterward.
 */
static vw_err_t upload_chunks(vw_client_sess_t *sess, const char *local_path,
                               uint8_t **out_hashes, uint32_t *out_chunk_count,
                               uint64_t *out_logical_size,
                               vw_client_progress_cb_t progress_cb, void *userdata)
{
    vw_err_t err;

    /* ── Pass 1: read file and collect chunk hashes ── */

    vw_fs_chunk_ctx_t chunk_ctx;
    err = vw_fs_chunk_open(local_path, &chunk_ctx);
    if (err != VW_OK) return err;

    uint8_t *chunk_buf = malloc(VW_CHUNK_SIZE);
    if (!chunk_buf) { vw_fs_chunk_close(&chunk_ctx); return VW_ERR_OOM; }

    uint8_t  *hashes     = NULL;
    uint32_t  hash_cap   = 0;
    uint32_t  chunk_count = 0;
    uint64_t  logical_size = 0;

    for (;;) {
        size_t chunk_len;
        int is_last;
        err = vw_fs_chunk_next(&chunk_ctx, chunk_buf, &chunk_len, &is_last);
        if (err != VW_OK) goto cleanup_pass1;

        /* Grow hash array */
        if (chunk_count >= hash_cap) {
            uint32_t new_cap = hash_cap ? hash_cap * 2 : 64;
            uint8_t *new_hashes = realloc(hashes, (size_t)new_cap * VW_HASH_BYTES);
            if (!new_hashes) { err = VW_ERR_OOM; goto cleanup_pass1; }
            hashes   = new_hashes;
            hash_cap = new_cap;
        }

        err = vw_crypto_sha256(chunk_buf, chunk_len,
                                hashes + (size_t)chunk_count * VW_HASH_BYTES);
        if (err != VW_OK) goto cleanup_pass1;

        logical_size += chunk_len;
        chunk_count++;
        if (is_last) break;
    }

cleanup_pass1:
    vw_fs_chunk_close(&chunk_ctx);
    free(chunk_buf);
    if (err != VW_OK) { free(hashes); return err; }

    /* ── Pass 2: CHUNK_QUERY batches → upload missing chunks ── */

    /* Allocate bitmask for "need upload" flags, one bit per chunk. */
    size_t bitmask_bytes = ((size_t)chunk_count + 7u) / 8u;
    uint8_t *need_upload = calloc(1, bitmask_bytes ? bitmask_bytes : 1);
    if (!need_upload) { free(hashes); return VW_ERR_OOM; }

    /* Send CHUNK_QUERY rounds (up to 1024 hashes each). */
    for (uint32_t base = 0; base < chunk_count; base += CHUNK_QUERY_MAX) {
        uint16_t batch = (uint16_t)VW_MIN(CHUNK_QUERY_MAX, chunk_count - base);
        uint32_t qplen = VW_TOKEN_BYTES + 2u + (uint32_t)batch * VW_HASH_BYTES;
        uint8_t *qbuf  = malloc(qplen);
        if (!qbuf) { err = VW_ERR_OOM; goto cleanup_upload; }

        uint8_t *wp = qbuf;
        memcpy(wp, sess->session_token, VW_TOKEN_BYTES); wp += VW_TOKEN_BYTES;
        vw_write_u16le(wp, batch); wp += 2;
        memcpy(wp, hashes + (size_t)base * VW_HASH_BYTES,
               (size_t)batch * VW_HASH_BYTES);

        err = vw_proto_send(sess->conn, VW_MSG_CHUNK_QUERY, qbuf, qplen);
        free(qbuf);
        if (err != VW_OK) goto cleanup_upload;

        uint8_t rbuf[2u + ((CHUNK_QUERY_MAX + 7u) / 8u)];
        uint32_t rplen;
        err = recv_expect(sess->conn, VW_MSG_CHUNK_QUERY_RESP,
                           rbuf, sizeof(rbuf), &rplen);
        if (err != VW_OK) goto cleanup_upload;

        if (rplen < 2u) { err = VW_ERR_PROTO_TRUNCATED; goto cleanup_upload; }
        uint16_t resp_count = vw_read_u16le(rbuf);
        if (resp_count != batch) { err = VW_ERR_PROTO_INVALID; goto cleanup_upload; }

        uint16_t resp_bitmask_bytes = (uint16_t)((batch + 7u) / 8u);
        if (rplen < 2u + resp_bitmask_bytes) {
            err = VW_ERR_PROTO_TRUNCATED;
            goto cleanup_upload;
        }

        /* bit=0 → server does NOT have the chunk → we need to upload */
        for (uint16_t i = 0; i < batch; i++) {
            uint32_t global_i = base + i;
            uint8_t  byte_val = rbuf[2u + i / 8u];
            uint8_t  bit      = (uint8_t)(byte_val >> (7u - (i % 8u))) & 1u;
            if (!bit)
                need_upload[global_i / 8u] |= (uint8_t)(1u << (7u - (global_i % 8u)));
        }
    }

    /* Re-open local file and upload missing chunks. */
    chunk_buf = malloc(VW_CHUNK_SIZE);
    if (!chunk_buf) { err = VW_ERR_OOM; goto cleanup_upload; }

    err = vw_fs_chunk_open(local_path, &chunk_ctx);
    if (err != VW_OK) { free(chunk_buf); goto cleanup_upload; }

    /* Upload buffer: token[32] + hash[32] + len(u32) + data */
    uint8_t *ubuf = malloc(VW_TOKEN_BYTES + VW_HASH_BYTES + 4u + VW_CHUNK_SIZE);
    if (!ubuf) {
        vw_fs_chunk_close(&chunk_ctx);
        free(chunk_buf);
        err = VW_ERR_OOM;
        goto cleanup_upload;
    }

    uint64_t bytes_done = 0;
    for (uint32_t ci = 0; ci < chunk_count; ci++) {
        size_t chunk_len;
        int is_last;
        err = vw_fs_chunk_next(&chunk_ctx, chunk_buf, &chunk_len, &is_last);
        if (err != VW_OK) break;

        uint8_t need = (need_upload[ci / 8u] >> (7u - (ci % 8u))) & 1u;
        if (need) {
            const uint8_t *chash = hashes + (size_t)ci * VW_HASH_BYTES;
            uint8_t *wp = ubuf;
            memcpy(wp, sess->session_token, VW_TOKEN_BYTES); wp += VW_TOKEN_BYTES;
            memcpy(wp, chash, VW_HASH_BYTES); wp += VW_HASH_BYTES;
            vw_write_u32le(wp, (uint32_t)chunk_len); wp += 4;
            memcpy(wp, chunk_buf, chunk_len);
            uint32_t uplen = VW_TOKEN_BYTES + VW_HASH_BYTES + 4u + (uint32_t)chunk_len;

            err = vw_proto_send(sess->conn, VW_MSG_CHUNK_UPLOAD, ubuf, uplen);
            if (err != VW_OK) break;

            /* Receive CHUNK_UPLOAD_ACK: hash[32] + error_code(u32) */
            uint8_t ackbuf[VW_HASH_BYTES + 4u];
            uint32_t ackplen;
            err = recv_expect(sess->conn, VW_MSG_CHUNK_UPLOAD_ACK,
                               ackbuf, sizeof(ackbuf), &ackplen);
            if (err != VW_OK) break;
            if (ackplen >= VW_HASH_BYTES + 4u) {
                uint32_t ec = vw_read_u32le(ackbuf + VW_HASH_BYTES);
                if (ec != 0) { err = (vw_err_t)ec; break; }
            }
        }

        bytes_done += chunk_len;
        if (progress_cb) progress_cb(bytes_done, logical_size, userdata);
        (void)is_last;
    }

    free(ubuf);
    vw_fs_chunk_close(&chunk_ctx);
    free(chunk_buf);
    if (err != VW_OK) goto cleanup_upload;

    free(need_upload);
    *out_hashes       = hashes;
    *out_chunk_count  = chunk_count;
    *out_logical_size = logical_size;
    return VW_OK;

cleanup_upload:
    free(need_upload);
    free(hashes);
    return err;
}

/*
 * Sends FILE_COMMIT and decodes FILE_COMMIT_ACK. name_or_path is either a
 * full virtual path (file_id == 0: create-by-path or update-owned-path) or
 * a bare leaf name (file_id names an existing FILE: update; file_id names
 * a DIRECTORY the caller has EDIT on: create a new file under it — see
 * docs/PROTOCOL.md §7.5's FILE_COMMIT directory-file_id note, TASK-094).
 */
static vw_err_t send_file_commit(vw_client_sess_t *sess, uint64_t file_id,
                                  const char *name_or_path, uint16_t name_len,
                                  uint64_t logical_size, uint32_t chunk_count,
                                  const uint8_t *hashes,
                                  uint64_t *out_file_id, uint64_t *out_version_id)
{
    uint32_t cplen = VW_TOKEN_BYTES + 8u + 8u + 4u + 2u
                   + (uint32_t)name_len
                   + (uint32_t)chunk_count * VW_HASH_BYTES;
    uint8_t *cbuf = malloc(cplen);
    if (!cbuf) return VW_ERR_OOM;

    uint8_t *cp = cbuf;
    memcpy(cp, sess->session_token, VW_TOKEN_BYTES); cp += VW_TOKEN_BYTES;
    vw_write_u64le(cp, file_id);      cp += 8;
    vw_write_u64le(cp, logical_size); cp += 8;
    vw_write_u32le(cp, chunk_count);  cp += 4;
    vw_write_u16le(cp, name_len);     cp += 2;
    if (name_len > 0) { memcpy(cp, name_or_path, name_len); cp += name_len; }
    memcpy(cp, hashes, (size_t)chunk_count * VW_HASH_BYTES);

    vw_err_t err = vw_proto_send(sess->conn, VW_MSG_FILE_COMMIT, cbuf, cplen);
    free(cbuf);
    if (err != VW_OK) return err;

    /* FILE_COMMIT_ACK: file_id(u64) + version_id(u64) + error_code(u32) */
    uint8_t ackbuf[20];
    uint32_t ackplen;
    err = recv_expect(sess->conn, VW_MSG_FILE_COMMIT_ACK,
                       ackbuf, sizeof(ackbuf), &ackplen);
    if (err != VW_OK) return err;
    if (ackplen < 20u) return VW_ERR_PROTO_TRUNCATED;

    if (out_file_id)    *out_file_id    = vw_read_u64le(ackbuf);
    if (out_version_id) *out_version_id = vw_read_u64le(ackbuf + 8u);
    uint32_t ec = vw_read_u32le(ackbuf + 16u);
    return ec != 0 ? (vw_err_t)ec : VW_OK;
}

/* ── vw_client_file_upload ───────────────────────────────────────────────── */

vw_err_t vw_client_file_upload(vw_client_sess_t *sess,
                                 const char *virtual_path,
                                 const char *local_path,
                                 vw_client_progress_cb_t progress_cb,
                                 void *userdata)
{
    vw_err_t err;
    if (!sess || !virtual_path || !local_path) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK)     return err;
    if ((err = path_validate_client(virtual_path)) != VW_OK) return err;

    uint8_t  *hashes;
    uint32_t  chunk_count;
    uint64_t  logical_size;
    err = upload_chunks(sess, local_path, &hashes, &chunk_count, &logical_size,
                         progress_cb, userdata);
    if (err != VW_OK) return err;

    /* ── Send FILE_COMMIT (file_id=0, path=virtual_path: new-or-owned-path) ── */
    uint64_t new_file_id, new_version_id;
    err = send_file_commit(sess, 0, virtual_path, (uint16_t)strlen(virtual_path),
                            logical_size, chunk_count, hashes,
                            &new_file_id, &new_version_id);
    free(hashes);
    return err;
}

vw_err_t vw_client_file_upload_to_id(vw_client_sess_t *sess,
                                       uint64_t file_id,
                                       const char *local_path,
                                       vw_client_progress_cb_t progress_cb,
                                       void *userdata)
{
    vw_err_t err;
    if (!sess || file_id == 0 || !local_path) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK) return err;

    uint8_t  *hashes;
    uint32_t  chunk_count;
    uint64_t  logical_size;
    err = upload_chunks(sess, local_path, &hashes, &chunk_count, &logical_size,
                         progress_cb, userdata);
    if (err != VW_OK) return err;

    /* file_id names an existing file: path field is unused by the server
     * in this case (updates the file in place), so send it empty. */
    uint64_t new_file_id, new_version_id;
    err = send_file_commit(sess, file_id, NULL, 0,
                            logical_size, chunk_count, hashes,
                            &new_file_id, &new_version_id);
    free(hashes);
    return err;
}

vw_err_t vw_client_file_upload_into_folder(vw_client_sess_t *sess,
                                             uint64_t folder_file_id,
                                             const char *leaf_name,
                                             const char *local_path,
                                             vw_client_progress_cb_t progress_cb,
                                             void *userdata)
{
    vw_err_t err;
    if (!sess || folder_file_id == 0 || !leaf_name || !leaf_name[0] || !local_path)
        return VW_ERR_INVALID_ARG;
    if (strchr(leaf_name, '/') != NULL) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK) return err;

    uint8_t  *hashes;
    uint32_t  chunk_count;
    uint64_t  logical_size;
    err = upload_chunks(sess, local_path, &hashes, &chunk_count, &logical_size,
                         progress_cb, userdata);
    if (err != VW_OK) return err;

    /* file_id names the FOLDER here; path is the bare leaf name of the new
     * file created inside it (server-side reinterpretation, see
     * handle_file_commit's file_id-names-a-DIR branch). */
    uint64_t new_file_id, new_version_id;
    err = send_file_commit(sess, folder_file_id, leaf_name, (uint16_t)strlen(leaf_name),
                            logical_size, chunk_count, hashes,
                            &new_file_id, &new_version_id);
    free(hashes);
    return err;
}

/* ── vw_client_file_download ─────────────────────────────────────────────── */

/*
 * Shared by vw_client_file_download (resolves entry via path first) and
 * vw_client_file_download_by_id (entry already resolved via file_id).
 * Does steps 2-3: VERSION_CHUNKS, then per-chunk download/verify/assemble.
 */
static vw_err_t download_by_entry(vw_client_sess_t *sess,
                                   const vw_file_entry_t *entry,
                                   const char *local_path,
                                   vw_client_progress_cb_t progress_cb,
                                   void *userdata)
{
    vw_err_t err;

    /* ── Step 2: VERSION_CHUNKS {version_id} → chunk hash list ── */
    uint8_t vc_payload[VW_TOKEN_BYTES + 8u];
    memcpy(vc_payload, sess->session_token, VW_TOKEN_BYTES);
    vw_write_u64le(vc_payload + VW_TOKEN_BYTES, entry->version_id);

    err = vw_proto_send(sess->conn, VW_MSG_VERSION_CHUNKS,
                         vc_payload, sizeof(vc_payload));
    if (err != VW_OK) return err;

    uint8_t *vc_rbuf = malloc(VW_MAX_MSG_BYTES);
    if (!vc_rbuf) return VW_ERR_OOM;
    uint32_t vc_rplen;
    err = recv_expect(sess->conn, VW_MSG_VERSION_CHUNKS_RESP,
                       vc_rbuf, VW_MAX_MSG_BYTES, &vc_rplen);
    if (err != VW_OK) { free(vc_rbuf); return err; }

    if (vc_rplen < 4u) { free(vc_rbuf); return VW_ERR_PROTO_TRUNCATED; }
    uint32_t chunk_count = vw_read_u32le(vc_rbuf);
    if (vc_rplen < 4u + (uint64_t)chunk_count * VW_HASH_BYTES) {
        free(vc_rbuf);
        return VW_ERR_PROTO_TRUNCATED;
    }

    const uint8_t *remote_hashes = vc_rbuf + 4u;

    /* ── Step 3: download each chunk; assemble into temp file ── */

    /* Build temp path: local_path + ".tmp" */
    size_t tmp_len = strlen(local_path) + 5u;
    char *tmp_path = malloc(tmp_len);
    if (!tmp_path) { free(vc_rbuf); return VW_ERR_OOM; }
    snprintf(tmp_path, tmp_len, "%s.tmp", local_path);

    vw_fs_chunk_writer_ctx_t writer;
    err = vw_fs_chunk_writer_open(tmp_path, &writer);
    if (err != VW_OK) { free(tmp_path); free(vc_rbuf); return err; }

    /* Download request buffer: token[32] + hash[32] */
    uint8_t dreq[VW_TOKEN_BYTES + VW_HASH_BYTES];
    memcpy(dreq, sess->session_token, VW_TOKEN_BYTES);

    /* Chunk data receive buffer */
    uint8_t *data_rbuf = malloc(VW_HASH_BYTES + 4u + VW_CHUNK_SIZE);
    if (!data_rbuf) {
        vw_fs_chunk_writer_abort(&writer);
        free(tmp_path);
        free(vc_rbuf);
        return VW_ERR_OOM;
    }

    uint64_t bytes_done = 0;
    for (uint32_t ci = 0; ci < chunk_count; ci++) {
        const uint8_t *chash = remote_hashes + (size_t)ci * VW_HASH_BYTES;
        memcpy(dreq + VW_TOKEN_BYTES, chash, VW_HASH_BYTES);

        err = vw_proto_send(sess->conn, VW_MSG_CHUNK_DOWNLOAD_REQ,
                             dreq, sizeof(dreq));
        if (err != VW_OK) break;

        uint32_t drplen;
        err = recv_expect(sess->conn, VW_MSG_CHUNK_DATA,
                           data_rbuf, VW_HASH_BYTES + 4u + VW_CHUNK_SIZE, &drplen);
        if (err != VW_OK) break;

        /* CHUNK_DATA: hash[32] + chunk_len(u32) + data */
        if (drplen < VW_HASH_BYTES + 4u) { err = VW_ERR_PROTO_TRUNCATED; break; }
        uint32_t chunk_len = vw_read_u32le(data_rbuf + VW_HASH_BYTES);
        if (drplen < VW_HASH_BYTES + 4u + chunk_len) {
            err = VW_ERR_PROTO_TRUNCATED; break;
        }

        /* Verify SHA-256(data) == requested hash */
        uint8_t got_hash[VW_HASH_BYTES];
        vw_err_t herr = vw_crypto_sha256(data_rbuf + VW_HASH_BYTES + 4u,
                                          chunk_len, got_hash);
        if (herr != VW_OK || !vw_crypto_constant_time_eq(got_hash, chash, VW_HASH_BYTES)) {
            err = VW_ERR_PROTO_INVALID; break;
        }

        err = vw_fs_chunk_writer_append(&writer,
                                         data_rbuf + VW_HASH_BYTES + 4u,
                                         chunk_len);
        if (err != VW_OK) break;

        bytes_done += chunk_len;
        if (progress_cb) progress_cb(bytes_done, entry->size_bytes, userdata);
    }

    free(data_rbuf);

    if (err != VW_OK) {
        vw_fs_chunk_writer_abort(&writer);
        free(tmp_path);
        free(vc_rbuf);
        return err;
    }

    err = vw_fs_chunk_writer_close(&writer);
    if (err == VW_OK) err = vw_fs_rename(tmp_path, local_path);
    if (err != VW_OK) vw_fs_delete(tmp_path);

    free(tmp_path);
    free(vc_rbuf);
    return err;
}

vw_err_t vw_client_file_download(vw_client_sess_t *sess,
                                   const char *virtual_path,
                                   const char *local_path,
                                   vw_client_progress_cb_t progress_cb,
                                   void *userdata)
{
    vw_err_t err;
    if (!sess || !virtual_path || !local_path) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK)     return err;
    if ((err = path_validate_client(virtual_path)) != VW_OK) return err;

    vw_file_entry_t entry;
    err = vw_client_file_stat(sess, virtual_path, &entry);
    if (err != VW_OK) return err;

    return download_by_entry(sess, &entry, local_path, progress_cb, userdata);
}

vw_err_t vw_client_file_download_by_id(vw_client_sess_t *sess,
                                         uint64_t file_id,
                                         const char *local_path,
                                         vw_client_progress_cb_t progress_cb,
                                         void *userdata)
{
    vw_err_t err;
    if (!sess || file_id == 0 || !local_path) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK) return err;

    vw_file_entry_t entry;
    err = vw_client_file_stat_by_id(sess, file_id, &entry);
    if (err != VW_OK) return err;

    return download_by_entry(sess, &entry, local_path, progress_cb, userdata);
}

/* ── vw_client_file_delete ───────────────────────────────────────────────── */

vw_err_t vw_client_file_delete(vw_client_sess_t *sess,
                                 const char *virtual_path)
{
    vw_err_t err;
    if (!sess || !virtual_path) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK)     return err;
    if ((err = path_validate_client(virtual_path)) != VW_OK) return err;

    uint16_t path_len = (uint16_t)strlen(virtual_path);

    /* token[32] + file_id(u64)=0 + path_len(u16) + path */
    uint32_t plen = VW_TOKEN_BYTES + 8u + 2u + (uint32_t)path_len;
    uint8_t *pbuf = malloc(plen);
    if (!pbuf) return VW_ERR_OOM;
    uint8_t *p = pbuf;
    memcpy(p, sess->session_token, VW_TOKEN_BYTES); p += VW_TOKEN_BYTES;
    vw_write_u64le(p, 0); p += 8;
    vw_write_u16le(p, path_len); p += 2;
    memcpy(p, virtual_path, path_len);

    err = vw_proto_send(sess->conn, VW_MSG_FILE_DELETE, pbuf, plen);
    free(pbuf);
    if (err != VW_OK) return err;

    uint8_t rbuf[4];
    uint32_t rplen;
    err = recv_expect(sess->conn, VW_MSG_FILE_DELETE_ACK, rbuf, sizeof(rbuf), &rplen);
    if (err == VW_OK && rplen >= 4u) {
        uint32_t ec = vw_read_u32le(rbuf);
        if (ec != 0) err = (vw_err_t)ec;
    }
    return err;
}

/* ── vw_client_file_move ─────────────────────────────────────────────────── */

vw_err_t vw_client_file_move(vw_client_sess_t *sess,
                               uint64_t file_id,
                               uint64_t new_parent_dir_id,
                               const char *new_name)
{
    vw_err_t err;
    if (!sess || file_id == 0) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK) return err;

    uint16_t name_len = new_name ? (uint16_t)strlen(new_name) : 0u;

    /* token[32] + file_id(u64) + new_parent_dir_id(u64) + name_len(u16) + name */
    uint32_t plen = VW_TOKEN_BYTES + 8u + 8u + 2u + (uint32_t)name_len;
    uint8_t *pbuf = malloc(plen);
    if (!pbuf) return VW_ERR_OOM;
    uint8_t *p = pbuf;
    memcpy(p, sess->session_token, VW_TOKEN_BYTES); p += VW_TOKEN_BYTES;
    vw_write_u64le(p, file_id);           p += 8;
    vw_write_u64le(p, new_parent_dir_id); p += 8;
    vw_write_u16le(p, name_len);          p += 2;
    if (name_len > 0) memcpy(p, new_name, name_len);

    err = vw_proto_send(sess->conn, VW_MSG_FILE_MOVE, pbuf, plen);
    free(pbuf);
    if (err != VW_OK) return err;

    uint8_t rbuf[4];
    uint32_t rplen;
    err = recv_expect(sess->conn, VW_MSG_FILE_MOVE_ACK, rbuf, sizeof(rbuf), &rplen);
    if (err == VW_OK && rplen >= 4u) {
        uint32_t ec = vw_read_u32le(rbuf);
        if (ec != 0) err = (vw_err_t)ec;
    }
    return err;
}

/* ── vw_client_version_list ──────────────────────────────────────────────── */

vw_err_t vw_client_version_list(vw_client_sess_t *sess,
                                  const char *virtual_path,
                                  vw_version_entry_t **out,
                                  uint32_t *out_count)
{
    vw_err_t err;
    if (!sess || !virtual_path || !out || !out_count) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK)     return err;
    if ((err = path_validate_client(virtual_path)) != VW_OK) return err;

    /* Resolve file_id via FILE_STAT */
    vw_file_entry_t entry;
    err = vw_client_file_stat(sess, virtual_path, &entry);
    if (err != VW_OK) return err;

    /* VERSION_LIST payload: token[32] + file_id(u64) + offset(u32)=0 + limit(u32)=0 */
    uint8_t pbuf[VW_TOKEN_BYTES + 8u + 4u + 4u];
    uint8_t *p = pbuf;
    memcpy(p, sess->session_token, VW_TOKEN_BYTES); p += VW_TOKEN_BYTES;
    vw_write_u64le(p, entry.file_id); p += 8;
    vw_write_u32le(p, 0); p += 4;  /* offset */
    vw_write_u32le(p, 0);           /* limit = server default */

    err = vw_proto_send(sess->conn, VW_MSG_VERSION_LIST, pbuf, sizeof(pbuf));
    if (err != VW_OK) return err;

    uint8_t *rbuf = malloc(VW_MAX_MSG_BYTES);
    if (!rbuf) return VW_ERR_OOM;
    uint32_t rplen;
    err = recv_expect(sess->conn, VW_MSG_VERSION_LIST_RESP,
                       rbuf, VW_MAX_MSG_BYTES, &rplen);
    if (err != VW_OK) { free(rbuf); return err; }

    /* count(u32) + total(u32) + count × {version_id(u64)+created_at(i64)+size_bytes(u64)+creator(u64)} */
    if (rplen < 8u) { free(rbuf); return VW_ERR_PROTO_TRUNCATED; }
    uint32_t count = vw_read_u32le(rbuf);
    /* total (u32) is consumed but not returned */
    uint32_t off = 8u;

    vw_version_entry_t *entries = NULL;
    if (count > 0) {
        entries = calloc(count, sizeof(*entries));
        if (!entries) { free(rbuf); return VW_ERR_OOM; }
    }

    for (uint32_t i = 0; i < count; i++) {
        if (off + 32u > rplen) { free(entries); free(rbuf); return VW_ERR_PROTO_TRUNCATED; }
        entries[i].version_id  = vw_read_u64le(rbuf + off);       off += 8;
        entries[i].created_at  = (int64_t)vw_read_u64le(rbuf + off); off += 8;
        entries[i].size_bytes  = vw_read_u64le(rbuf + off);       off += 8;
        /* creator_user_id: consumed, not returned */               off += 8;
    }

    free(rbuf);
    *out = entries;
    *out_count = count;
    return VW_OK;
}

/* ── vw_client_version_restore ───────────────────────────────────────────── */

vw_err_t vw_client_version_restore(vw_client_sess_t *sess,
                                     const char *virtual_path,
                                     uint64_t version_id)
{
    vw_err_t err;
    if (!sess || !virtual_path) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK)     return err;
    if ((err = path_validate_client(virtual_path)) != VW_OK) return err;

    uint16_t path_len = (uint16_t)strlen(virtual_path);

    /* token[32] + version_id(u64) + path_len(u16) + path */
    uint32_t plen = VW_TOKEN_BYTES + 8u + 2u + (uint32_t)path_len;
    uint8_t *pbuf = malloc(plen);
    if (!pbuf) return VW_ERR_OOM;
    uint8_t *p = pbuf;
    memcpy(p, sess->session_token, VW_TOKEN_BYTES); p += VW_TOKEN_BYTES;
    vw_write_u64le(p, version_id); p += 8;
    vw_write_u16le(p, path_len); p += 2;
    memcpy(p, virtual_path, path_len);

    err = vw_proto_send(sess->conn, VW_MSG_VERSION_RESTORE, pbuf, plen);
    free(pbuf);
    if (err != VW_OK) return err;

    /* VERSION_RESTORE_ACK: version_id(u64) + error_code(u32) */
    uint8_t rbuf[12];
    uint32_t rplen;
    err = recv_expect(sess->conn, VW_MSG_VERSION_RESTORE_ACK,
                       rbuf, sizeof(rbuf), &rplen);
    if (err == VW_OK && rplen >= 12u) {
        uint32_t ec = vw_read_u32le(rbuf + 8u);
        if (ec != 0) err = (vw_err_t)ec;
    }
    return err;
}

/* ── Sharing (TASK-095; server side: TASK-094, docs/PROTOCOL.md §7.5) ────── */

vw_err_t vw_client_share_grant(vw_client_sess_t *sess,
                                 uint64_t file_id,
                                 const char *target_username,
                                 vw_perm_t permission,
                                 int64_t expires_at,
                                 uint64_t *out_share_id)
{
    vw_err_t err;
    if (!sess || file_id == 0 || !target_username || !target_username[0])
        return VW_ERR_INVALID_ARG;
    if (permission != VW_PERM_VIEW && permission != VW_PERM_EDIT)
        return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK) return err;

    uint16_t uname_len = (uint16_t)strlen(target_username);
    if (uname_len > VW_MAX_USERNAME_BYTES) return VW_ERR_INVALID_ARG;

    /* token[32] + file_id(u64) + target_username(str) + permission(u8) + expires_at(i64) */
    uint32_t plen = VW_TOKEN_BYTES + 8u + 2u + (uint32_t)uname_len + 1u + 8u;
    uint8_t *pbuf = malloc(plen);
    if (!pbuf) return VW_ERR_OOM;
    uint32_t off = 0;
    memcpy(pbuf + off, sess->session_token, VW_TOKEN_BYTES); off += VW_TOKEN_BYTES;
    vw_write_u64le(pbuf + off, file_id); off += 8;
    (void)vw_proto_write_str(pbuf, plen, &off, target_username, uname_len);
    pbuf[off++] = (uint8_t)permission;
    vw_write_u64le(pbuf + off, (uint64_t)expires_at); off += 8;

    err = vw_proto_send(sess->conn, VW_MSG_SHARE_GRANT, pbuf, off);
    free(pbuf);
    if (err != VW_OK) return err;

    /* SHARE_GRANT_ACK: error_code(u32) + share_id(u64) */
    uint8_t rbuf[12];
    uint32_t rplen;
    err = recv_expect(sess->conn, VW_MSG_SHARE_GRANT_ACK, rbuf, sizeof(rbuf), &rplen);
    if (err != VW_OK) return err;
    if (rplen < 12u) return VW_ERR_PROTO_TRUNCATED;
    uint32_t ec = vw_read_u32le(rbuf);
    if (ec != 0) return (vw_err_t)ec;
    if (out_share_id) *out_share_id = vw_read_u64le(rbuf + 4u);
    return VW_OK;
}

/*
 * Shared by vw_client_share_revoke and vw_client_link_revoke — identical
 * wire shape: token[32] + share_id(u64), ACK: error_code(u32).
 */
static vw_err_t revoke_common(vw_client_sess_t *sess, uint64_t share_id,
                               vw_msg_type_t req_type, vw_msg_type_t ack_type)
{
    vw_err_t err;
    if (!sess || share_id == 0) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK) return err;

    uint8_t pbuf[VW_TOKEN_BYTES + 8u];
    memcpy(pbuf, sess->session_token, VW_TOKEN_BYTES);
    vw_write_u64le(pbuf + VW_TOKEN_BYTES, share_id);

    err = vw_proto_send(sess->conn, req_type, pbuf, sizeof(pbuf));
    if (err != VW_OK) return err;

    uint8_t rbuf[4];
    uint32_t rplen;
    err = recv_expect(sess->conn, ack_type, rbuf, sizeof(rbuf), &rplen);
    if (err == VW_OK && rplen >= 4u) {
        uint32_t ec = vw_read_u32le(rbuf);
        if (ec != 0) err = (vw_err_t)ec;
    }
    return err;
}

vw_err_t vw_client_share_revoke(vw_client_sess_t *sess, uint64_t share_id)
{
    return revoke_common(sess, share_id, VW_MSG_SHARE_REVOKE, VW_MSG_SHARE_REVOKE_ACK);
}

vw_err_t vw_client_link_revoke(vw_client_sess_t *sess, uint64_t share_id)
{
    return revoke_common(sess, share_id, VW_MSG_LINK_REVOKE, VW_MSG_LINK_REVOKE_ACK);
}

vw_err_t vw_client_share_list(vw_client_sess_t *sess,
                                uint8_t mode,
                                vw_share_entry_t **out,
                                uint32_t *out_count)
{
    vw_err_t err;
    if (!sess || !out || !out_count) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK) return err;

    uint8_t pbuf[VW_TOKEN_BYTES + 1u];
    memcpy(pbuf, sess->session_token, VW_TOKEN_BYTES);
    pbuf[VW_TOKEN_BYTES] = mode;

    err = vw_proto_send(sess->conn, VW_MSG_SHARE_LIST, pbuf, sizeof(pbuf));
    if (err != VW_OK) return err;

    uint8_t *rbuf = malloc(VW_MAX_MSG_BYTES);
    if (!rbuf) return VW_ERR_OOM;
    uint32_t rplen;
    err = recv_expect(sess->conn, VW_MSG_SHARE_LIST_RESP, rbuf, VW_MAX_MSG_BYTES, &rplen);
    if (err != VW_OK) { free(rbuf); return err; }

    if (rplen < 4u) { free(rbuf); return VW_ERR_PROTO_TRUNCATED; }
    uint32_t count = vw_read_u32le(rbuf);
    uint32_t off = 4u;

    vw_share_entry_t *entries = NULL;
    if (count > 0) {
        entries = calloc(count, sizeof(*entries));
        if (!entries) { free(rbuf); return VW_ERR_OOM; }
    }

    for (uint32_t i = 0; i < count; i++) {
        if (off + 8u + 8u > rplen) goto trunc;
        entries[i].share_id = vw_read_u64le(rbuf + off); off += 8;
        entries[i].file_id  = vw_read_u64le(rbuf + off); off += 8;

        const char *name; uint16_t name_len;
        if (vw_proto_read_str(rbuf, rplen, &off, &name, &name_len) != VW_OK) goto trunc;
        uint16_t ncopy = (uint16_t)VW_MIN(name_len, (uint16_t)(sizeof(entries[i].name) - 1u));
        memcpy(entries[i].name, name, ncopy);
        entries[i].name[ncopy] = '\0';

        if (off + 1u > rplen) goto trunc;
        entries[i].share_type = rbuf[off++];

        const char *tgt; uint16_t tgt_len;
        if (vw_proto_read_str(rbuf, rplen, &off, &tgt, &tgt_len) != VW_OK) goto trunc;
        uint16_t tcopy = (uint16_t)VW_MIN(tgt_len, (uint16_t)(sizeof(entries[i].target_username) - 1u));
        memcpy(entries[i].target_username, tgt, tcopy);
        entries[i].target_username[tcopy] = '\0';

        if (off + 1u + 8u + 8u + 1u > rplen) goto trunc;
        entries[i].permission  = rbuf[off++];
        entries[i].created_at  = (int64_t)vw_read_u64le(rbuf + off); off += 8;
        entries[i].expires_at  = (int64_t)vw_read_u64le(rbuf + off); off += 8;
        entries[i].revoked     = rbuf[off++];
    }
    free(rbuf);
    *out = entries;
    *out_count = count;
    return VW_OK;

trunc:
    free(entries);
    free(rbuf);
    return VW_ERR_PROTO_TRUNCATED;
}

vw_err_t vw_client_link_create(vw_client_sess_t *sess,
                                 uint64_t file_id,
                                 vw_perm_t permission,
                                 int64_t expires_at,
                                 uint64_t *out_share_id,
                                 uint8_t out_link_token[32])
{
    vw_err_t err;
    if (!sess || file_id == 0 || !out_link_token) return VW_ERR_INVALID_ARG;
    if (permission != VW_PERM_VIEW && permission != VW_PERM_EDIT)
        return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK) return err;

    /* token[32] + file_id(u64) + permission(u8) + expires_at(i64) */
    uint8_t pbuf[VW_TOKEN_BYTES + 8u + 1u + 8u];
    uint8_t *p = pbuf;
    memcpy(p, sess->session_token, VW_TOKEN_BYTES); p += VW_TOKEN_BYTES;
    vw_write_u64le(p, file_id); p += 8;
    *p++ = (uint8_t)permission;
    vw_write_u64le(p, (uint64_t)expires_at);

    err = vw_proto_send(sess->conn, VW_MSG_LINK_CREATE, pbuf, sizeof(pbuf));
    if (err != VW_OK) return err;

    /* LINK_CREATE_ACK: error_code(u32) + share_id(u64) + link_token[32] */
    uint8_t rbuf[4u + 8u + 32u];
    uint32_t rplen;
    err = recv_expect(sess->conn, VW_MSG_LINK_CREATE_ACK, rbuf, sizeof(rbuf), &rplen);
    if (err != VW_OK) return err;
    if (rplen < sizeof(rbuf)) { secure_zero(rbuf, sizeof(rbuf)); return VW_ERR_PROTO_TRUNCATED; }

    uint32_t ec = vw_read_u32le(rbuf);
    if (ec != 0) { secure_zero(rbuf, sizeof(rbuf)); return (vw_err_t)ec; }

    if (out_share_id) *out_share_id = vw_read_u64le(rbuf + 4u);
    memcpy(out_link_token, rbuf + 12u, 32u);
    secure_zero(rbuf, sizeof(rbuf));
    return VW_OK;
}

vw_err_t vw_client_link_list(vw_client_sess_t *sess,
                               uint64_t file_id_filter,
                               vw_link_entry_t **out,
                               uint32_t *out_count)
{
    vw_err_t err;
    if (!sess || !out || !out_count) return VW_ERR_INVALID_ARG;
    if ((err = sess_check_valid(sess)) != VW_OK) return err;

    uint8_t pbuf[VW_TOKEN_BYTES + 8u];
    memcpy(pbuf, sess->session_token, VW_TOKEN_BYTES);
    vw_write_u64le(pbuf + VW_TOKEN_BYTES, file_id_filter);

    err = vw_proto_send(sess->conn, VW_MSG_LINK_LIST, pbuf, sizeof(pbuf));
    if (err != VW_OK) return err;

    uint8_t *rbuf = malloc(VW_MAX_MSG_BYTES);
    if (!rbuf) return VW_ERR_OOM;
    uint32_t rplen;
    err = recv_expect(sess->conn, VW_MSG_LINK_LIST_RESP, rbuf, VW_MAX_MSG_BYTES, &rplen);
    if (err != VW_OK) { free(rbuf); return err; }

    if (rplen < 4u) { free(rbuf); return VW_ERR_PROTO_TRUNCATED; }
    uint32_t count = vw_read_u32le(rbuf);
    uint32_t off = 4u;

    vw_link_entry_t *entries = NULL;
    if (count > 0) {
        entries = calloc(count, sizeof(*entries));
        if (!entries) { free(rbuf); return VW_ERR_OOM; }
    }

    for (uint32_t i = 0; i < count; i++) {
        if (off + 8u + 8u > rplen) goto trunc;
        entries[i].share_id = vw_read_u64le(rbuf + off); off += 8;
        entries[i].file_id  = vw_read_u64le(rbuf + off); off += 8;

        const char *name; uint16_t name_len;
        if (vw_proto_read_str(rbuf, rplen, &off, &name, &name_len) != VW_OK) goto trunc;
        uint16_t ncopy = (uint16_t)VW_MIN(name_len, (uint16_t)(sizeof(entries[i].name) - 1u));
        memcpy(entries[i].name, name, ncopy);
        entries[i].name[ncopy] = '\0';

        if (off + 1u + 8u + 8u + 1u > rplen) goto trunc;
        entries[i].permission = rbuf[off++];
        entries[i].created_at = (int64_t)vw_read_u64le(rbuf + off); off += 8;
        entries[i].expires_at = (int64_t)vw_read_u64le(rbuf + off); off += 8;
        entries[i].revoked    = rbuf[off++];
    }
    free(rbuf);
    *out = entries;
    *out_count = count;
    return VW_OK;

trunc:
    free(entries);
    free(rbuf);
    return VW_ERR_PROTO_TRUNCATED;
}

vw_err_t vw_client_link_access(const vw_client_cfg_t *cfg,
                                 const uint8_t link_token[32],
                                 vw_client_sess_t **out_sess)
{
    if (!cfg || !link_token || !out_sess) return VW_ERR_INVALID_ARG;

    vw_client_sess_t *sess = calloc(1, sizeof(*sess));
    if (!sess) return VW_ERR_OOM;

    vw_err_t err = do_connect(cfg, &sess->conn);
    if (err != VW_OK) { free(sess); return err; }

    uint16_t version;
    err = vw_proto_negotiate(sess->conn, 0 /*is_server*/, &version);
    if (err != VW_OK) { sess_destroy(sess); return err; }

    err = vw_proto_send(sess->conn, VW_MSG_LINK_ACCESS, link_token, 32u);
    if (err != VW_OK) { sess_destroy(sess); return err; }

    /* LINK_ACCESS_ACK has the same wire shape as AUTH_OK (§7.5): user_id=0,
     * is_admin=0, quota fields zeroed. Failure is AUTH_FAIL, same generic
     * bad-creds code for unknown/revoked/expired (anti-enumeration). */
    vw_msg_type_t type;
    uint8_t resp[128];
    uint32_t resp_plen;
    err = vw_proto_recv(sess->conn, &type, resp, sizeof(resp), &resp_plen);
    if (err != VW_OK) { sess_destroy(sess); return err; }

    if (type == VW_MSG_LINK_ACCESS_ACK) {
        vw_payload_auth_ok_t ok;
        err = vw_proto_decode_auth_ok(resp, resp_plen, &ok);
        if (err != VW_OK) {
            secure_zero(resp, sizeof(resp));
            sess_destroy(sess);
            return err;
        }
        memcpy(sess->session_token, ok.session_token, VW_TOKEN_BYTES);
        sess->expires_at  = ok.expires_at;
        sess->is_admin    = ok.is_admin;
        sess->quota_bytes = ok.quota_bytes;
        sess->used_bytes  = ok.used_bytes;
        sess->user_id     = ok.user_id;
        secure_zero(&ok, sizeof(ok));
        secure_zero(resp, sizeof(resp));
        *out_sess = sess;
        return VW_OK;
    }

    if (type == VW_MSG_AUTH_FAIL) {
        vw_payload_auth_fail_t fail;
        if (vw_proto_decode_auth_fail(resp, resp_plen, &fail) == VW_OK)
            err = (vw_err_t)fail.error_code;
        else
            err = VW_ERR_AUTH_BAD_CREDS;
        sess_destroy(sess);
        return err;
    }

    sess_destroy(sess);
    return VW_ERR_PROTO_INVALID;
}
