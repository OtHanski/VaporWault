#include "vw_gateway_api.h"
#include "vw_json.h"
#include "../core/vw_crypto.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define VW_GATEWAY_COOKIE_NAME "vw_session"
#define VW_GATEWAY_MAX_PASSWORD_BYTES 256u

/* ── Small shared helpers ─────────────────────────────────────────────────── */

static void send_json_status(vw_http_conn_t *conn, int http_status,
                              const char *status_str, const char *set_cookie) {
    char buf[256];
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, sizeof(buf));
    vw_json_write_object_start(&w);
    vw_json_write_key(&w, "status");
    vw_json_write_string(&w, status_str, strlen(status_str));
    vw_json_write_object_end(&w);
    size_t len = 0;
    vw_json_writer_result(&w, &len);
    vw_http_send_response(conn, http_status, "application/json", set_cookie, buf, (uint32_t)len);
}

static void send_error(vw_http_conn_t *conn, int http_status, const char *status_str) {
    send_json_status(conn, http_status, status_str, NULL);
}

/* Finds "name=value" in the request's Cookie header. Returns 1 and fills
 * out (NUL-terminated) on success, 0 if absent or too long for out_size. */
static int get_cookie_value(const vw_http_request_t *req, const char *name,
                             char *out, size_t out_size) {
    const char *cookie_header = vw_http_header_get(req, "Cookie");
    if (cookie_header == NULL) return 0;

    size_t name_len = strlen(name);
    const char *p = cookie_header;
    while (*p != '\0') {
        while (*p == ' ') p++;
        const char *eq = strchr(p, '=');
        if (eq == NULL) break;
        size_t key_len = (size_t)(eq - p);
        const char *val_start = eq + 1;
        const char *semi = strchr(val_start, ';');
        size_t val_len = semi ? (size_t)(semi - val_start) : strlen(val_start);

        if (key_len == name_len && memcmp(p, name, name_len) == 0) {
            if (val_len >= out_size) return 0;
            memcpy(out, val_start, val_len);
            out[val_len] = '\0';
            return 1;
        }
        if (semi == NULL) break;
        p = semi + 1;
    }
    return 0;
}

/*
 * Resolves the calling browser's session from its cookie. Returns VW_OK
 * with *out_sess set (and *out_cookie filled in - needed by
 * send_file_op_error below to evict this exact session if the connection
 * turns out to be desynced, TASK-155), or writes a 401 response itself
 * and returns VW_ERR_AUTH_REQUIRED (caller should just return in that
 * case). out_cookie must be at least VW_GATEWAY_COOKIE_HEX_LEN+1 bytes;
 * pass NULL if the caller doesn't need it (e.g. login/logout, which don't
 * call this at all).
 */
static vw_err_t require_session(vw_gateway_session_pool_t *pool,
                                 const vw_http_request_t *req,
                                 vw_http_conn_t *conn,
                                 vw_client_sess_t **out_sess,
                                 char *out_cookie) {
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (!get_cookie_value(req, VW_GATEWAY_COOKIE_NAME, cookie, sizeof(cookie))) {
        send_error(conn, 401, "auth_required");
        return VW_ERR_AUTH_REQUIRED;
    }
    vw_err_t err = vw_gateway_session_get(pool, cookie, out_sess);
    if (err != VW_OK) {
        send_error(conn, 401, "auth_required");
        return VW_ERR_AUTH_REQUIRED;
    }
    if (out_cookie != NULL) {
        memcpy(out_cookie, cookie, sizeof(cookie));
    }
    return VW_OK;
}

/* ── Auth endpoints (TASK-132) ────────────────────────────────────────────── */

typedef struct {
    const char *otp;      /* NULL if the browser hasn't supplied one yet */
    uint16_t    otp_len;
} login_otp_ctx_t;

/*
 * See vw_client_core.h's vw_otp_callback_t doc: returning anything other
 * than VW_OK aborts vw_client_connect with that exact code. Returning
 * VW_ERR_AUTH_2FA_REQUIRED here when no OTP was supplied lets the gateway
 * tell "need a code" (this path) apart from "wrong code"
 * (VW_ERR_AUTH_2FA_INVALID, the server's own AUTH_FAIL response to a
 * submitted-but-wrong code) using vw_client_connect's ordinary return
 * value — no gateway-side "pending login" state needed across the two
 * HTTP requests at all. The browser resubmits username+password+otp
 * together on the second call (TASK-137's login view keeps them in
 * memory between the two form steps, never persisted).
 */
static vw_err_t login_otp_cb(void *userdata, char *otp_buf, uint16_t *otp_len) {
    login_otp_ctx_t *ctx = (login_otp_ctx_t *)userdata;
    if (ctx->otp == NULL) return VW_ERR_AUTH_2FA_REQUIRED;
    memcpy(otp_buf, ctx->otp, ctx->otp_len);
    *otp_len = ctx->otp_len;
    return VW_OK;
}

static void handle_login(vw_gateway_session_pool_t *pool,
                          const vw_gateway_server_cfg_t *cfg,
                          const vw_http_request_t *req,
                          vw_http_conn_t *conn) {
    if (req->method != VW_HTTP_POST || req->body == NULL || req->body_len == 0) {
        send_error(conn, 400, "bad_request");
        return;
    }

    vw_json_value_t v;
    char username[VW_MAX_USERNAME_BYTES + 1];
    char password[VW_GATEWAY_MAX_PASSWORD_BYTES];
    char otp[16];
    size_t out_len = 0;

    if (vw_json_object_get((const char *)req->body, req->body_len, "username", &v) != VW_OK ||
        v.kind != VW_JSON_STRING ||
        vw_json_string_decode(v.start, v.len, username, sizeof(username), &out_len) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }
    uint16_t username_len = (uint16_t)out_len;

    if (vw_json_object_get((const char *)req->body, req->body_len, "password", &v) != VW_OK ||
        v.kind != VW_JSON_STRING ||
        vw_json_string_decode(v.start, v.len, password, sizeof(password), &out_len) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }
    size_t password_len = out_len;

    login_otp_ctx_t otp_ctx;
    otp_ctx.otp = NULL;
    otp_ctx.otp_len = 0;
    if (vw_json_object_get((const char *)req->body, req->body_len, "otp", &v) == VW_OK &&
        v.kind == VW_JSON_STRING &&
        vw_json_string_decode(v.start, v.len, otp, sizeof(otp), &out_len) == VW_OK &&
        out_len > 0) {
        otp_ctx.otp = otp;
        otp_ctx.otp_len = (uint16_t)out_len;
    }

    vw_client_cfg_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.host = cfg->server_host;
    client_cfg.port = cfg->server_port;
    client_cfg.cert_verify = VW_CERT_VERIFY_REQUIRED;
    client_cfg.ca_cert_pem_path = cfg->ca_cert_pem_path;

    vw_client_sess_t *sess = NULL;
    vw_err_t err = vw_client_connect(&client_cfg, username, username_len,
                                      password, password_len,
                                      login_otp_cb, &otp_ctx, &sess);

    vw_crypto_secure_zero(password, sizeof(password));
    vw_crypto_secure_zero(otp, sizeof(otp));

    if (err == VW_OK) {
        char cookie_hex[VW_GATEWAY_COOKIE_HEX_LEN + 1];
        if (vw_gateway_session_create(pool, sess, cookie_hex) != VW_OK) {
            vw_client_close(sess);
            send_error(conn, 503, "too_many_sessions");
            return;
        }
        char cookie_header[VW_GATEWAY_COOKIE_HEX_LEN + 96];
        snprintf(cookie_header, sizeof(cookie_header),
                 VW_GATEWAY_COOKIE_NAME "=%s; Path=/; HttpOnly; Secure; SameSite=Strict",
                 cookie_hex);
        send_json_status(conn, 200, "ok", cookie_header);
        return;
    }

    switch (err) {
        case VW_ERR_AUTH_2FA_REQUIRED:
            send_error(conn, 401, "otp_required");
            break;
        case VW_ERR_AUTH_2FA_INVALID:
        case VW_ERR_AUTH_2FA_LOCKED:
            send_error(conn, 401, "otp_invalid");
            break;
        case VW_ERR_AUTH_BAD_CREDS:
        case VW_ERR_AUTH_LOCKED:
            send_error(conn, 401, "bad_credentials");
            break;
        case VW_ERR_NET_CONNECT:
        case VW_ERR_NET_TLS:
            send_error(conn, 502, "server_unreachable");
            break;
        default:
            send_error(conn, 500, "error");
            break;
    }
}

static void handle_logout(vw_gateway_session_pool_t *pool,
                           const vw_http_request_t *req,
                           vw_http_conn_t *conn) {
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (get_cookie_value(req, VW_GATEWAY_COOKIE_NAME, cookie, sizeof(cookie))) {
        vw_gateway_session_remove(pool, cookie);
    }
    /* Idempotent either way - an unknown/absent cookie is not an error. */
    send_json_status(conn, 200, "ok",
                      VW_GATEWAY_COOKIE_NAME "=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0");
}

/* ── File endpoints (TASK-133) ────────────────────────────────────────────
 *
 * Metadata operations only in this pass (list/stat/mkdir/delete/move) -
 * upload/download (file content transfer) are NOT implemented yet; see
 * TASK-133's own notes for why (binary content doesn't fit cleanly into
 * this module's JSON-body convention without either a base64 layer or a
 * separate raw-body route, neither written yet) and file a follow-up
 * rather than rushing either approach.
 */

/*
 * Maps a vw_client_core error from a file operation to an HTTP response.
 * TASK-155: a pre-existing vw_proto_recv/vw_client_core bug leaves a
 * connection permanently desynced whenever one of these RPCs is rejected
 * via the server's generic error path (a very ordinary occurrence, not an
 * edge case - see TASK-155 for the full mechanism). This gateway can't
 * fix that bug (out of WEB.09's domain), but it can contain the damage:
 * any error OUTSIDE the small set of business-logic outcomes we
 * positively recognize is treated as "this connection might be broken
 * now" and the session is evicted, forcing the browser to log in again
 * (and get a fresh connection) rather than the gateway silently handing
 * a possibly-hung connection to the next request on this same cookie.
 */
static void send_file_op_error(vw_gateway_session_pool_t *pool, const char *cookie_hex,
                                vw_http_conn_t *conn, vw_err_t err) {
    switch (err) {
        case VW_ERR_NOT_FOUND:
            send_error(conn, 404, "not_found");
            return;
        case VW_ERR_DIR_NOT_EMPTY:
            send_error(conn, 409, "dir_not_empty");
            return;
        case VW_ERR_PERMISSION:
            send_error(conn, 403, "forbidden");
            return;
        case VW_ERR_PATH_INVALID:
        case VW_ERR_PATH_CONFLICT:
        case VW_ERR_INVALID_ARG:
            send_error(conn, 400, "bad_request");
            return;
        case VW_ERR_QUOTA_EXCEEDED:
            send_error(conn, 507, "quota_exceeded");
            return;
        case VW_ERR_AUTH_REQUIRED:
            /* A perfectly ordinary outcome, not a "connection might be
             * broken" signal - e.g. a scoped (link) session whose
             * underlying share/link was revoked after the session was
             * established (TASK-134's own acceptance criterion: the
             * server re-checks revocation live on every request, so this
             * is exactly how that shows up here). Evicting is still
             * correct (this session can never succeed again), but the
             * browser gets a clean 401 instead of a scary generic error. */
            if (cookie_hex != NULL) {
                vw_gateway_session_remove(pool, cookie_hex);
            }
            send_error(conn, 401, "auth_required");
            return;
        default:
            if (cookie_hex != NULL) {
                vw_gateway_session_remove(pool, cookie_hex);
            }
            send_error(conn, 500, "error");
            return;
    }
}

static void write_file_entry(vw_json_writer_t *w, const vw_file_entry_t *e) {
    vw_json_write_object_start(w);
    vw_json_write_key(w, "name");
    vw_json_write_string(w, e->name, strlen(e->name));
    vw_json_write_key(w, "entry_type");
    vw_json_write_uint(w, e->entry_type);
    vw_json_write_key(w, "file_id");
    vw_json_write_uint(w, e->file_id);
    vw_json_write_key(w, "size_bytes");
    vw_json_write_uint(w, e->size_bytes);
    vw_json_write_key(w, "mtime_unix");
    vw_json_write_int(w, e->mtime_unix);
    vw_json_write_key(w, "version_id");
    vw_json_write_uint(w, e->version_id);
    vw_json_write_key(w, "vault_id");
    vw_json_write_uint(w, e->vault_id);
    vw_json_write_object_end(w);
}

static vw_err_t get_json_string_field(const vw_http_request_t *req, const char *key,
                                       char *out, size_t out_size) {
    vw_json_value_t v;
    size_t out_len = 0;
    if (vw_json_object_get((const char *)req->body, req->body_len, key, &v) != VW_OK ||
        v.kind != VW_JSON_STRING) {
        return VW_ERR_PROTO_INVALID;
    }
    return vw_json_string_decode(v.start, v.len, out, out_size, &out_len);
}

static vw_err_t get_json_uint_field(const vw_http_request_t *req, const char *key,
                                     uint64_t *out) {
    vw_json_value_t v;
    if (vw_json_object_get((const char *)req->body, req->body_len, key, &v) != VW_OK ||
        v.kind != VW_JSON_NUMBER) {
        return VW_ERR_PROTO_INVALID;
    }
    *out = (uint64_t)v.number_val;
    return VW_OK;
}

static void handle_file_list(vw_gateway_session_pool_t *pool,
                              const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    char path[VW_MAX_PATH_BYTES];
    if (get_json_string_field(req, "path", path, sizeof(path)) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }
    vw_json_value_t v;
    uint8_t recursive = 0;
    if (vw_json_object_get((const char *)req->body, req->body_len, "recursive", &v) == VW_OK &&
        v.kind == VW_JSON_BOOL) {
        recursive = (uint8_t)v.bool_val;
    }

    vw_file_entry_t *entries = NULL;
    uint32_t count = 0;
    vw_err_t err = vw_client_file_list(sess, path, recursive, &entries, &count);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    char *buf = malloc(65536);
    if (buf == NULL) { free(entries); send_error(conn, 500, "error"); return; }
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, 65536);
    vw_json_write_array_start(&w);
    for (uint32_t i = 0; i < count; i++) write_file_entry(&w, &entries[i]);
    vw_json_write_array_end(&w);
    free(entries);

    size_t len = 0;
    if (vw_json_writer_result(&w, &len) != VW_OK) {
        free(buf);
        send_error(conn, 500, "response_too_large");
        return;
    }
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
    free(buf);
}

static void handle_file_stat(vw_gateway_session_pool_t *pool,
                              const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    char path[VW_MAX_PATH_BYTES];
    if (get_json_string_field(req, "path", path, sizeof(path)) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }

    vw_file_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    vw_err_t err = vw_client_file_stat(sess, path, &entry);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    char buf[1024];
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, sizeof(buf));
    write_file_entry(&w, &entry);
    size_t len = 0;
    vw_json_writer_result(&w, &len);
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
}

static void handle_file_mkdir(vw_gateway_session_pool_t *pool,
                               const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    char name[256];
    uint64_t parent_dir_id = 0;
    if (get_json_string_field(req, "name", name, sizeof(name)) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }
    /* parent_dir_id is optional; 0 (caller's own root) if absent. */
    (void)get_json_uint_field(req, "parent_dir_id", &parent_dir_id);

    uint64_t out_dir_id = 0;
    vw_err_t err = vw_client_file_mkdir(sess, parent_dir_id, name, &out_dir_id);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    char buf[128];
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, sizeof(buf));
    vw_json_write_object_start(&w);
    vw_json_write_key(&w, "dir_id");
    vw_json_write_uint(&w, out_dir_id);
    vw_json_write_object_end(&w);
    size_t len = 0;
    vw_json_writer_result(&w, &len);
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
}

static void handle_file_delete(vw_gateway_session_pool_t *pool,
                                const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    char path[VW_MAX_PATH_BYTES];
    if (get_json_string_field(req, "path", path, sizeof(path)) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }

    vw_err_t err = vw_client_file_delete(sess, path);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }
    send_json_status(conn, 200, "ok", NULL);
}

static void handle_file_move(vw_gateway_session_pool_t *pool,
                              const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    uint64_t file_id = 0, new_parent_dir_id = 0;
    char new_name[256];
    new_name[0] = '\0';

    if (get_json_uint_field(req, "file_id", &file_id) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }
    (void)get_json_uint_field(req, "new_parent_dir_id", &new_parent_dir_id);
    (void)get_json_string_field(req, "new_name", new_name, sizeof(new_name));

    vw_err_t err = vw_client_file_move(sess, file_id, new_parent_dir_id,
                                        new_name[0] ? new_name : NULL);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }
    send_json_status(conn, 200, "ok", NULL);
}

/* ── Version history endpoints (TASK-133's own scope, deferred to this
 * pass alongside chunk transfer below) ──────────────────────────────────── */

static void write_version_entry(vw_json_writer_t *w, const vw_version_entry_t *e) {
    vw_json_write_object_start(w);
    vw_json_write_key(w, "version_id");
    vw_json_write_uint(w, e->version_id);
    vw_json_write_key(w, "created_at");
    vw_json_write_int(w, e->created_at);
    vw_json_write_key(w, "size_bytes");
    vw_json_write_uint(w, e->size_bytes);
    vw_json_write_object_end(w);
}

static void handle_version_list(vw_gateway_session_pool_t *pool,
                                 const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    char path[VW_MAX_PATH_BYTES];
    if (get_json_string_field(req, "path", path, sizeof(path)) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }

    vw_version_entry_t *entries = NULL;
    uint32_t count = 0;
    vw_err_t err = vw_client_version_list(sess, path, &entries, &count);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    char *buf = malloc(65536);
    if (buf == NULL) { free(entries); send_error(conn, 500, "error"); return; }
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, 65536);
    vw_json_write_array_start(&w);
    for (uint32_t i = 0; i < count; i++) write_version_entry(&w, &entries[i]);
    vw_json_write_array_end(&w);
    free(entries);

    size_t len = 0;
    if (vw_json_writer_result(&w, &len) != VW_OK) {
        free(buf);
        send_error(conn, 500, "response_too_large");
        return;
    }
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
    free(buf);
}

static void handle_version_restore(vw_gateway_session_pool_t *pool,
                                    const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    char path[VW_MAX_PATH_BYTES];
    uint64_t version_id = 0;
    if (get_json_string_field(req, "path", path, sizeof(path)) != VW_OK ||
        get_json_uint_field(req, "version_id", &version_id) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }

    vw_err_t err = vw_client_version_restore(sess, path, version_id);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }
    send_json_status(conn, 200, "ok", NULL);
}

/* ── Chunk transfer endpoints (TASK-139's backend prerequisite) ───────────
 *
 * The browser drives CHUNK_QUERY/CHUNK_UPLOAD/FILE_COMMIT (upload) and
 * VERSION_CHUNKS/CHUNK_DOWNLOAD_REQ (download) directly, one HTTP request
 * per chunk step, per TASK-127/TASK-139's own design note - this is what
 * gives real per-file byte progress without inventing a status/polling
 * API. Chunk hashes are hex-encoded (matches this file's existing
 * convention for opaque binary fields); chunk BODIES are raw binary, not
 * JSON/base64-wrapped - vw_http_request_t.body is already a plain byte
 * buffer (TASK-129's own doc anticipated this: VW_HTTP_MAX_BODY_BYTES is
 * sized as "one VW_CHUNK_SIZE_DEFAULT chunk plus headroom"), so there is
 * no encoding overhead or new routing mechanism needed for the two
 * endpoints that carry chunk content itself.
 */

#define VW_GATEWAY_CHUNK_HASH_HEADER   "X-Vw-Chunk-Hash"
/* Sanity bound on chunk_hashes[] length in a single FILE_COMMIT request -
 * matches vw_client_file_list's own "max 65535 entries" precedent, not a
 * real expected size (65536 chunks * 4 MiB is a 256 GiB file). */
#define VW_GATEWAY_MAX_CHUNK_COUNT     65536u

static void handle_chunk_upload(vw_gateway_session_pool_t *pool,
                                 const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;

    const char *hash_hex = vw_http_header_get(req, VW_GATEWAY_CHUNK_HASH_HEADER);
    if (hash_hex == NULL || strlen(hash_hex) != VW_HASH_BYTES * 2u ||
        req->body == NULL || req->body_len == 0 ||
        req->body_len > VW_CHUNK_SIZE_DEFAULT) {
        send_error(conn, 400, "bad_request");
        return;
    }
    uint8_t hash[VW_HASH_BYTES];
    if (vw_crypto_hex_decode(hash_hex, VW_HASH_BYTES * 2u, hash) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }

    vw_err_t err = vw_client_chunk_upload_if_missing(sess, hash, req->body, req->body_len);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }
    send_json_status(conn, 200, "ok", NULL);
}

typedef struct {
    uint8_t *buf;
    uint32_t count;
    uint32_t cap;
    int      error;
} chunk_hash_decode_ctx_t;

static int count_array_elem_cb(void *ud, vw_json_value_t element) {
    (void)element;
    uint32_t *count = (uint32_t *)ud;
    (*count)++;
    return 0;
}

static int decode_chunk_hash_cb(void *ud, vw_json_value_t element) {
    chunk_hash_decode_ctx_t *ctx = (chunk_hash_decode_ctx_t *)ud;
    if (ctx->count >= ctx->cap || element.kind != VW_JSON_STRING) {
        ctx->error = 1;
        return 1;
    }
    char hex[VW_HASH_BYTES * 2u + 1u];
    size_t out_len = 0;
    if (vw_json_string_decode(element.start, element.len, hex, sizeof(hex), &out_len) != VW_OK ||
        out_len != VW_HASH_BYTES * 2u ||
        vw_crypto_hex_decode(hex, out_len, ctx->buf + (size_t)ctx->count * VW_HASH_BYTES) != VW_OK) {
        ctx->error = 1;
        return 1;
    }
    ctx->count++;
    return 0;
}

static void handle_file_commit(vw_gateway_session_pool_t *pool,
                                const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    char path[VW_MAX_PATH_BYTES];
    path[0] = '\0';
    uint64_t file_id = 0;
    char leaf_name[256];
    leaf_name[0] = '\0';
    uint64_t logical_size = 0;

    (void)get_json_string_field(req, "path", path, sizeof(path));
    (void)get_json_uint_field(req, "file_id", &file_id);
    (void)get_json_string_field(req, "leaf_name", leaf_name, sizeof(leaf_name));

    if (get_json_uint_field(req, "logical_size", &logical_size) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }

    const char *name_or_path = NULL;
    uint16_t name_len = 0;
    uint64_t commit_file_id = 0;
    if (path[0] != '\0') {
        name_or_path = path;
        name_len = (uint16_t)strlen(path);
        commit_file_id = 0;
    } else if (file_id != 0 && leaf_name[0] != '\0') {
        name_or_path = leaf_name;
        name_len = (uint16_t)strlen(leaf_name);
        commit_file_id = file_id;
    } else if (file_id != 0) {
        name_or_path = NULL;
        name_len = 0;
        commit_file_id = file_id;
    } else {
        send_error(conn, 400, "bad_request");
        return;
    }

    vw_json_value_t arr;
    if (vw_json_object_get((const char *)req->body, req->body_len, "chunk_hashes", &arr) != VW_OK ||
        arr.kind != VW_JSON_ARRAY) {
        send_error(conn, 400, "bad_request");
        return;
    }

    uint32_t chunk_count = 0;
    if (vw_json_array_foreach(arr.start, arr.len, count_array_elem_cb, &chunk_count) != VW_OK ||
        chunk_count == 0 || chunk_count > VW_GATEWAY_MAX_CHUNK_COUNT) {
        send_error(conn, 400, "bad_request");
        return;
    }

    uint8_t *hashes = malloc((size_t)chunk_count * VW_HASH_BYTES);
    if (hashes == NULL) { send_error(conn, 500, "error"); return; }

    chunk_hash_decode_ctx_t ctx = { hashes, 0, chunk_count, 0 };
    if (vw_json_array_foreach(arr.start, arr.len, decode_chunk_hash_cb, &ctx) != VW_OK ||
        ctx.error || ctx.count != chunk_count) {
        free(hashes);
        send_error(conn, 400, "bad_request");
        return;
    }

    uint64_t out_file_id = 0, out_version_id = 0;
    vw_err_t err = vw_client_file_commit_raw(sess, commit_file_id, name_or_path, name_len,
                                              logical_size, chunk_count, hashes,
                                              0, NULL, 0,
                                              &out_file_id, &out_version_id);
    free(hashes);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    char buf[192];
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, sizeof(buf));
    vw_json_write_object_start(&w);
    vw_json_write_key(&w, "file_id");
    vw_json_write_uint(&w, out_file_id);
    vw_json_write_key(&w, "version_id");
    vw_json_write_uint(&w, out_version_id);
    vw_json_write_object_end(&w);
    size_t len = 0;
    vw_json_writer_result(&w, &len);
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
}

static void handle_version_chunks(vw_gateway_session_pool_t *pool,
                                   const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    uint64_t version_id = 0;
    if (get_json_uint_field(req, "version_id", &version_id) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }

    uint8_t *hashes = NULL;
    uint32_t chunk_count = 0;
    uint64_t vault_id = 0;
    uint8_t *wrapped_dek = NULL;
    uint16_t wrapped_dek_len = 0;

    vw_err_t err = vw_client_version_chunks_raw(sess, version_id, &hashes, &chunk_count,
                                                 &vault_id, &wrapped_dek, &wrapped_dek_len);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    /* Every hex-encoded hash is 64 chars + 2 quotes + comma; generous
     * per-entry budget plus a fixed allowance for the object's other
     * fields and the wrapped_dek hex (bounded by
     * VW_GATEWAY_MAX_KDF_PARAMS_BYTES-scale content in practice). */
    size_t cap = (size_t)chunk_count * 72u + 4096u + (size_t)wrapped_dek_len * 2u;
    char *buf = malloc(cap);
    if (buf == NULL) {
        free(hashes); free(wrapped_dek);
        send_error(conn, 500, "error");
        return;
    }
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, cap);
    vw_json_write_object_start(&w);
    vw_json_write_key(&w, "chunk_hashes");
    vw_json_write_array_start(&w);
    for (uint32_t i = 0; i < chunk_count; i++) {
        char hex[VW_HASH_BYTES * 2u + 1u];
        vw_crypto_hex_encode(hashes + (size_t)i * VW_HASH_BYTES, VW_HASH_BYTES, hex);
        vw_json_write_string(&w, hex, VW_HASH_BYTES * 2u);
    }
    vw_json_write_array_end(&w);
    vw_json_write_key(&w, "vault_id");
    vw_json_write_uint(&w, vault_id);
    vw_json_write_key(&w, "wrapped_dek");
    if (wrapped_dek_len > 0) {
        char *dek_hex = malloc((size_t)wrapped_dek_len * 2u + 1u);
        if (dek_hex != NULL) {
            vw_crypto_hex_encode(wrapped_dek, wrapped_dek_len, dek_hex);
            vw_json_write_string(&w, dek_hex, strlen(dek_hex));
            free(dek_hex);
        } else {
            vw_json_write_null(&w);
        }
    } else {
        vw_json_write_null(&w);
    }
    vw_json_write_object_end(&w);
    free(hashes);
    free(wrapped_dek);

    size_t len = 0;
    if (vw_json_writer_result(&w, &len) != VW_OK) {
        free(buf);
        send_error(conn, 500, "response_too_large");
        return;
    }
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
    free(buf);
}

static void handle_chunk_download(vw_gateway_session_pool_t *pool,
                                   const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    char hex[VW_HASH_BYTES * 2u + 1u];
    if (get_json_string_field(req, "hash", hex, sizeof(hex)) != VW_OK ||
        strlen(hex) != VW_HASH_BYTES * 2u) {
        send_error(conn, 400, "bad_request");
        return;
    }
    uint8_t hash[VW_HASH_BYTES];
    if (vw_crypto_hex_decode(hex, VW_HASH_BYTES * 2u, hash) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }

    uint8_t *data = NULL;
    uint32_t data_len = 0;
    vw_err_t err = vw_client_chunk_download_raw(sess, hash, &data, &data_len);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    vw_http_send_response(conn, 200, "application/octet-stream", NULL, data, data_len);
    free(data);
}

/* ── Sharing endpoints (TASK-134) ─────────────────────────────────────────
 *
 * Thin translators over vw_client_share_grant/_revoke/_list and
 * vw_client_link_create/_revoke/_list/_access — the server remains the
 * sole authority on permission checks (ownership, effective
 * permission on file_id, creator-only revoke), matching this file's own
 * module doc.
 */

#define VW_GATEWAY_MAX_TARGET_USERNAME_BYTES (VW_MAX_USERNAME_BYTES + 1u)

static vw_err_t get_json_permission_field(const vw_http_request_t *req,
                                           vw_perm_t *out) {
    uint64_t raw = 0;
    if (get_json_uint_field(req, "permission", &raw) != VW_OK) return VW_ERR_PROTO_INVALID;
    if (raw > VW_PERM_OWNER) return VW_ERR_PROTO_INVALID;
    *out = (vw_perm_t)raw;
    return VW_OK;
}

static void write_share_entry(vw_json_writer_t *w, const vw_share_entry_t *e) {
    vw_json_write_object_start(w);
    vw_json_write_key(w, "share_id");
    vw_json_write_uint(w, e->share_id);
    vw_json_write_key(w, "file_id");
    vw_json_write_uint(w, e->file_id);
    vw_json_write_key(w, "share_type");
    vw_json_write_uint(w, e->share_type);
    vw_json_write_key(w, "target_username");
    vw_json_write_string(w, e->target_username, strlen(e->target_username));
    vw_json_write_key(w, "permission");
    vw_json_write_uint(w, e->permission);
    vw_json_write_key(w, "created_at");
    vw_json_write_int(w, e->created_at);
    vw_json_write_key(w, "expires_at");
    vw_json_write_int(w, e->expires_at);
    vw_json_write_key(w, "revoked");
    vw_json_write_bool(w, e->revoked);
    vw_json_write_object_end(w);
}

static void write_link_entry(vw_json_writer_t *w, const vw_link_entry_t *e) {
    vw_json_write_object_start(w);
    vw_json_write_key(w, "share_id");
    vw_json_write_uint(w, e->share_id);
    vw_json_write_key(w, "file_id");
    vw_json_write_uint(w, e->file_id);
    vw_json_write_key(w, "name");
    vw_json_write_string(w, e->name, strlen(e->name));
    vw_json_write_key(w, "permission");
    vw_json_write_uint(w, e->permission);
    vw_json_write_key(w, "created_at");
    vw_json_write_int(w, e->created_at);
    vw_json_write_key(w, "expires_at");
    vw_json_write_int(w, e->expires_at);
    vw_json_write_key(w, "revoked");
    vw_json_write_bool(w, e->revoked);
    vw_json_write_object_end(w);
}

static void handle_share_grant(vw_gateway_session_pool_t *pool,
                                const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    uint64_t file_id = 0;
    char target_username[VW_GATEWAY_MAX_TARGET_USERNAME_BYTES];
    vw_perm_t perm;
    uint64_t expires_at = 0;

    if (get_json_uint_field(req, "file_id", &file_id) != VW_OK ||
        get_json_string_field(req, "target_username", target_username, sizeof(target_username)) != VW_OK ||
        get_json_permission_field(req, &perm) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }
    (void)get_json_uint_field(req, "expires_at", &expires_at);

    uint64_t out_share_id = 0;
    vw_err_t err = vw_client_share_grant(sess, file_id, target_username, perm,
                                          (int64_t)expires_at, &out_share_id);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    char buf[128];
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, sizeof(buf));
    vw_json_write_object_start(&w);
    vw_json_write_key(&w, "share_id");
    vw_json_write_uint(&w, out_share_id);
    vw_json_write_object_end(&w);
    size_t len = 0;
    vw_json_writer_result(&w, &len);
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
}

static void handle_share_revoke(vw_gateway_session_pool_t *pool,
                                 const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    uint64_t share_id = 0;
    if (get_json_uint_field(req, "share_id", &share_id) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }

    vw_err_t err = vw_client_share_revoke(sess, share_id);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }
    send_json_status(conn, 200, "ok", NULL);
}

static void handle_share_list(vw_gateway_session_pool_t *pool,
                               const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    uint64_t mode = 0;
    if (get_json_uint_field(req, "mode", &mode) != VW_OK || mode > 1) {
        send_error(conn, 400, "bad_request");
        return;
    }

    vw_share_entry_t *entries = NULL;
    uint32_t count = 0;
    vw_err_t err = vw_client_share_list(sess, (uint8_t)mode, &entries, &count);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    char *buf = malloc(65536);
    if (buf == NULL) { free(entries); send_error(conn, 500, "error"); return; }
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, 65536);
    vw_json_write_array_start(&w);
    for (uint32_t i = 0; i < count; i++) write_share_entry(&w, &entries[i]);
    vw_json_write_array_end(&w);
    free(entries);

    size_t len = 0;
    if (vw_json_writer_result(&w, &len) != VW_OK) {
        free(buf);
        send_error(conn, 500, "response_too_large");
        return;
    }
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
    free(buf);
}

static void handle_link_create(vw_gateway_session_pool_t *pool,
                                const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    uint64_t file_id = 0;
    vw_perm_t perm;
    uint64_t expires_at = 0;

    if (get_json_uint_field(req, "file_id", &file_id) != VW_OK ||
        get_json_permission_field(req, &perm) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }
    (void)get_json_uint_field(req, "expires_at", &expires_at);

    uint64_t out_share_id = 0;
    uint8_t link_token[32];
    vw_err_t err = vw_client_link_create(sess, file_id, perm, (int64_t)expires_at,
                                          &out_share_id, link_token);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    /* link_token is the only time this raw bearer credential is ever
     * available (vw_client_link_create's own doc) - relayed once, never
     * persisted gateway-side beyond this response. */
    char token_hex[65];
    vw_crypto_hex_encode(link_token, sizeof(link_token), token_hex);

    char buf[192];
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, sizeof(buf));
    vw_json_write_object_start(&w);
    vw_json_write_key(&w, "share_id");
    vw_json_write_uint(&w, out_share_id);
    vw_json_write_key(&w, "link_token");
    vw_json_write_string(&w, token_hex, strlen(token_hex));
    vw_json_write_object_end(&w);
    size_t len = 0;
    vw_json_writer_result(&w, &len);
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
}

static void handle_link_revoke(vw_gateway_session_pool_t *pool,
                                const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    uint64_t share_id = 0;
    if (get_json_uint_field(req, "share_id", &share_id) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }

    vw_err_t err = vw_client_link_revoke(sess, share_id);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }
    send_json_status(conn, 200, "ok", NULL);
}

static void handle_link_list(vw_gateway_session_pool_t *pool,
                              const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    uint64_t file_id_filter = 0;
    (void)get_json_uint_field(req, "file_id_filter", &file_id_filter);

    vw_link_entry_t *entries = NULL;
    uint32_t count = 0;
    vw_err_t err = vw_client_link_list(sess, file_id_filter, &entries, &count);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    char *buf = malloc(65536);
    if (buf == NULL) { free(entries); send_error(conn, 500, "error"); return; }
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, 65536);
    vw_json_write_array_start(&w);
    for (uint32_t i = 0; i < count; i++) write_link_entry(&w, &entries[i]);
    vw_json_write_array_end(&w);
    free(entries);

    size_t len = 0;
    if (vw_json_writer_result(&w, &len) != VW_OK) {
        free(buf);
        send_error(conn, 500, "response_too_large");
        return;
    }
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
    free(buf);
}

/*
 * Redeems a public link - deliberately the ONLY endpoint besides
 * /api/login that runs without require_session, since a link is a
 * pre-auth, unauthenticated flow server-side too (LINK_ACCESS,
 * docs/PROTOCOL.md §7.10). Establishes a scoped gateway session exactly
 * like a normal login (same pool, same slot type, same idle-eviction
 * behavior; TASK-134's own acceptance criteria) - the resulting
 * vw_client_sess_t is scoped server-side to this one share_id, so every
 * subsequent request on this cookie is naturally re-checked against the
 * link's live revoked/expired state by the server itself on each call,
 * never cached gateway-side at redemption time.
 */
static void handle_link_access(vw_gateway_session_pool_t *pool,
                                const vw_gateway_server_cfg_t *cfg,
                                const vw_http_request_t *req, vw_http_conn_t *conn) {
    if (req->method != VW_HTTP_POST || req->body == NULL || req->body_len == 0) {
        send_error(conn, 400, "bad_request");
        return;
    }

    char token_hex[65];
    if (get_json_string_field(req, "link_token", token_hex, sizeof(token_hex)) != VW_OK ||
        strlen(token_hex) != 64) {
        send_error(conn, 400, "bad_request");
        return;
    }
    uint8_t link_token[32];
    if (vw_crypto_hex_decode(token_hex, 64, link_token) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }

    vw_client_cfg_t client_cfg;
    memset(&client_cfg, 0, sizeof(client_cfg));
    client_cfg.host = cfg->server_host;
    client_cfg.port = cfg->server_port;
    client_cfg.cert_verify = VW_CERT_VERIFY_REQUIRED;
    client_cfg.ca_cert_pem_path = cfg->ca_cert_pem_path;

    vw_client_sess_t *sess = NULL;
    vw_err_t err = vw_client_link_access(&client_cfg, link_token, &sess);
    if (err != VW_OK) {
        /* Anti-enumeration (vw_client_link_access's own doc): unknown,
         * revoked, and expired tokens are all indistinguishable here too. */
        send_error(conn, 401, "bad_credentials");
        return;
    }

    char cookie_hex[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (vw_gateway_session_create(pool, sess, cookie_hex) != VW_OK) {
        vw_client_close(sess);
        send_error(conn, 503, "too_many_sessions");
        return;
    }
    char cookie_header[VW_GATEWAY_COOKIE_HEX_LEN + 96];
    snprintf(cookie_header, sizeof(cookie_header),
             VW_GATEWAY_COOKIE_NAME "=%s; Path=/; HttpOnly; Secure; SameSite=Strict",
             cookie_hex);
    send_json_status(conn, 200, "ok", cookie_header);
}

/* ── Vault registry endpoints (TASK-135) ──────────────────────────────────
 *
 * Registry plumbing only - wrapped_vk/kdf_salt/kdf_params move as opaque
 * hex-encoded byte blobs between browser and server. Nothing in this
 * section deserializes, logs, or otherwise touches a passphrase or an
 * unwrapped key - there is no passphrase field in any of these endpoints'
 * JSON schemas by construction (this task's own acceptance criteria).
 */

#define VW_GATEWAY_MAX_WRAPPED_VK_BYTES 2048u
#define VW_GATEWAY_MAX_KDF_PARAMS_BYTES 512u

static vw_err_t get_json_hex_field(const vw_http_request_t *req, const char *key,
                                    uint8_t *out, size_t out_cap, size_t *out_len) {
    char hex[VW_GATEWAY_MAX_WRAPPED_VK_BYTES * 2u + 1u];
    if (get_json_string_field(req, key, hex, sizeof(hex)) != VW_OK) return VW_ERR_PROTO_INVALID;
    size_t hex_len = strlen(hex);
    if (hex_len % 2u != 0u) return VW_ERR_PROTO_INVALID;
    size_t raw_len = hex_len / 2u;
    if (raw_len > out_cap) return VW_ERR_PROTO_INVALID;
    if (vw_crypto_hex_decode(hex, hex_len, out) != VW_OK) return VW_ERR_PROTO_INVALID;
    *out_len = raw_len;
    return VW_OK;
}

static void handle_vault_create(vw_gateway_session_pool_t *pool,
                                 const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    uint64_t folder_file_id = 0;
    uint8_t wrapped_vk[VW_GATEWAY_MAX_WRAPPED_VK_BYTES];
    size_t wrapped_vk_len = 0;
    uint8_t kdf_salt_hex_raw[16];
    size_t kdf_salt_len = 0;
    uint8_t kdf_params[VW_GATEWAY_MAX_KDF_PARAMS_BYTES];
    size_t kdf_params_len = 0;

    if (get_json_uint_field(req, "folder_file_id", &folder_file_id) != VW_OK ||
        get_json_hex_field(req, "wrapped_vk", wrapped_vk, sizeof(wrapped_vk), &wrapped_vk_len) != VW_OK ||
        wrapped_vk_len == 0 ||
        get_json_hex_field(req, "kdf_salt", kdf_salt_hex_raw, sizeof(kdf_salt_hex_raw), &kdf_salt_len) != VW_OK ||
        kdf_salt_len != 16) {
        send_error(conn, 400, "bad_request");
        return;
    }
    /* kdf_params may legitimately be empty (vw_client_vault_key_fetch's own
     * doc: "may be set to NULL with *out_kdf_params_len == 0"). */
    if (get_json_hex_field(req, "kdf_params", kdf_params, sizeof(kdf_params), &kdf_params_len) != VW_OK) {
        kdf_params_len = 0;
    }

    uint64_t out_vault_id = 0;
    vw_err_t err = vw_client_vault_create(sess, folder_file_id,
                                           wrapped_vk, (uint16_t)wrapped_vk_len,
                                           kdf_salt_hex_raw,
                                           kdf_params_len > 0 ? kdf_params : NULL,
                                           (uint16_t)kdf_params_len,
                                           &out_vault_id);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    char buf[128];
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, sizeof(buf));
    vw_json_write_object_start(&w);
    vw_json_write_key(&w, "vault_id");
    vw_json_write_uint(&w, out_vault_id);
    vw_json_write_object_end(&w);
    size_t len = 0;
    vw_json_writer_result(&w, &len);
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
}

static void handle_vault_key_fetch(vw_gateway_session_pool_t *pool,
                                    const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    uint64_t vault_id = 0;
    if (get_json_uint_field(req, "vault_id", &vault_id) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }

    uint8_t *wrapped_vk = NULL;
    uint16_t wrapped_vk_len = 0;
    uint8_t kdf_salt[16];
    uint8_t *kdf_params = NULL;
    uint16_t kdf_params_len = 0;
    uint64_t folder_file_id = 0;

    vw_err_t err = vw_client_vault_key_fetch(sess, vault_id,
                                              &wrapped_vk, &wrapped_vk_len,
                                              kdf_salt,
                                              &kdf_params, &kdf_params_len,
                                              &folder_file_id);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    char wrapped_vk_hex[VW_GATEWAY_MAX_WRAPPED_VK_BYTES * 2u + 1u];
    char kdf_salt_hex[33];
    char kdf_params_hex[VW_GATEWAY_MAX_KDF_PARAMS_BYTES * 2u + 1u];
    vw_crypto_hex_encode(wrapped_vk, wrapped_vk_len, wrapped_vk_hex);
    vw_crypto_hex_encode(kdf_salt, sizeof(kdf_salt), kdf_salt_hex);
    if (kdf_params_len > 0) {
        vw_crypto_hex_encode(kdf_params, kdf_params_len, kdf_params_hex);
    } else {
        kdf_params_hex[0] = '\0';
    }
    free(wrapped_vk);
    free(kdf_params);

    char *buf = malloc(8192);
    if (buf == NULL) { send_error(conn, 500, "error"); return; }
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, 8192);
    vw_json_write_object_start(&w);
    vw_json_write_key(&w, "wrapped_vk");
    vw_json_write_string(&w, wrapped_vk_hex, strlen(wrapped_vk_hex));
    vw_json_write_key(&w, "kdf_salt");
    vw_json_write_string(&w, kdf_salt_hex, strlen(kdf_salt_hex));
    vw_json_write_key(&w, "kdf_params");
    vw_json_write_string(&w, kdf_params_hex, strlen(kdf_params_hex));
    vw_json_write_key(&w, "folder_file_id");
    vw_json_write_uint(&w, folder_file_id);
    vw_json_write_object_end(&w);
    size_t len = 0;
    vw_json_writer_result(&w, &len);
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
    free(buf);
}

static void write_vault_entry(vw_json_writer_t *w, const vw_vault_entry_t *e) {
    vw_json_write_object_start(w);
    vw_json_write_key(w, "vault_id");
    vw_json_write_uint(w, e->vault_id);
    vw_json_write_key(w, "folder_file_id");
    vw_json_write_uint(w, e->folder_file_id);
    vw_json_write_key(w, "created_at");
    vw_json_write_int(w, e->created_at);
    vw_json_write_object_end(w);
}

static void handle_vault_list(vw_gateway_session_pool_t *pool,
                               const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;

    vw_vault_entry_t *entries = NULL;
    uint32_t count = 0;
    vw_err_t err = vw_client_vault_list(sess, &entries, &count);
    if (err != VW_OK) {
        send_file_op_error(pool, cookie, conn, err);
        return;
    }

    char *buf = malloc(16384);
    if (buf == NULL) { free(entries); send_error(conn, 500, "error"); return; }
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, 16384);
    vw_json_write_array_start(&w);
    for (uint32_t i = 0; i < count; i++) write_vault_entry(&w, &entries[i]);
    vw_json_write_array_end(&w);
    free(entries);

    size_t len = 0;
    if (vw_json_writer_result(&w, &len) != VW_OK) {
        free(buf);
        send_error(conn, 500, "response_too_large");
        return;
    }
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
    free(buf);
}

/* ── Dispatch ─────────────────────────────────────────────────────────────── */

void vw_gateway_dispatch(vw_gateway_session_pool_t *pool,
                          const vw_gateway_server_cfg_t *cfg,
                          const vw_http_request_t *req,
                          vw_http_conn_t *conn) {
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/login") == 0) {
        handle_login(pool, cfg, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/logout") == 0) {
        handle_logout(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/files/list") == 0) {
        handle_file_list(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/files/stat") == 0) {
        handle_file_stat(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/files/mkdir") == 0) {
        handle_file_mkdir(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/files/delete") == 0) {
        handle_file_delete(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/files/move") == 0) {
        handle_file_move(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/versions/list") == 0) {
        handle_version_list(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/versions/restore") == 0) {
        handle_version_restore(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/versions/chunks") == 0) {
        handle_version_chunks(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/chunks/upload") == 0) {
        handle_chunk_upload(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/chunks/download") == 0) {
        handle_chunk_download(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/files/commit") == 0) {
        handle_file_commit(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/shares/grant") == 0) {
        handle_share_grant(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/shares/revoke") == 0) {
        handle_share_revoke(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/shares/list") == 0) {
        handle_share_list(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/links/create") == 0) {
        handle_link_create(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/links/revoke") == 0) {
        handle_link_revoke(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/links/list") == 0) {
        handle_link_list(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/links/access") == 0) {
        handle_link_access(pool, cfg, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/vault/create") == 0) {
        handle_vault_create(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/vault/key_fetch") == 0) {
        handle_vault_key_fetch(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/vault/list") == 0) {
        handle_vault_list(pool, req, conn);
        return;
    }

    send_error(conn, 404, "not_found");
}
