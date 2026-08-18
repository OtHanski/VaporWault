#include "vw_gateway_api.h"
#include "vw_json.h"
#include "../core/vw_crypto.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Remember-me (TASK-165) global state. cfg/store are process-lifetime
 * configuration set once at startup (cfg by every vw_gateway_dispatch()
 * call — it's the same pointer/values every time, main.c never rebuilds
 * it — store by main.c calling vw_gateway_api_set_remember_store() once
 * before the accept loop starts), not per-request state, so a static
 * here avoids threading a `cfg` parameter through all twenty-odd
 * per-endpoint handlers that never otherwise needed it. Safe precisely
 * because this whole module is documented single-threaded-only (see
 * vw_gateway_session.h's own threading note, which applies equally
 * here) — there is no concurrent dispatch() call this could race with.
 */
static const vw_gateway_server_cfg_t *g_server_cfg = NULL;
static vw_gateway_remember_store_t   *g_remember_store = NULL;

void vw_gateway_api_set_remember_store(vw_gateway_remember_store_t *store) {
    g_remember_store = store;
}

#define VW_GATEWAY_COOKIE_NAME "vw_session"
#define VW_GATEWAY_MAX_PASSWORD_BYTES 256u

/*
 * Multi-slot sessions (TASK-164). One browser can hold up to
 * VW_GATEWAY_MAX_SLOTS simultaneously logged-in accounts, each under its
 * own cookie name "vw_session_<slot>" (slot 0 == today's plain
 * "vw_session", so an unmodified browser/frontend that never sends
 * X-Vw-Slot keeps behaving exactly as before this task). A small hard cap
 * — same "mandatory hard cap" philosophy as VW_GATEWAY_MAX_SESSIONS
 * (vw_gateway_session.h's own doc: an unbounded per-browser slot count
 * would let one browser claim an unbounded share of the pool's 256-session
 * hard cap). This is a purely gateway-local, per-request routing concept —
 * the session pool itself stays keyed by cookie VALUE only, with no notion
 * of "slot" (see vw_gateway_session.h).
 *
 * Deliberately still one-process-one-server (ARCHITECTURE.md's "Gateway
 * stays one-process-one-server" decision) — every slot is an account on
 * the *same* server this gateway is configured for. A second, unrelated
 * server gets its own separate gateway deployment/URL; there is no
 * per-slot host/CA-cert field anywhere in this file.
 */
#define VW_GATEWAY_MAX_SLOTS 6u
#define VW_GATEWAY_SLOT_HEADER "X-Vw-Slot"

/* "vw_session_" + up to 1 digit (VW_GATEWAY_MAX_SLOTS - 1 <= 9) + NUL. */
static void slot_cookie_name(unsigned slot, char *out, size_t out_size) {
    snprintf(out, out_size, VW_GATEWAY_COOKIE_NAME "_%u", slot);
}

/*
 * Reads X-Vw-Slot off the request and returns a slot index in
 * [0, VW_GATEWAY_MAX_SLOTS). Absent, non-numeric, or out-of-range values
 * all fall back to slot 0 rather than rejecting the request outright —
 * this header is a routing hint from a trusted-shape browser/frontend,
 * not a security boundary (the cookie value itself, checked in
 * constant time by vw_gateway_session_get, is what actually
 * authenticates), so failing open to "acts like today's single-slot
 * behavior" is the safe default per this task's own acceptance criterion
 * that an absent header must be a complete no-op.
 */
static unsigned resolve_slot(const vw_http_request_t *req) {
    const char *hdr = vw_http_header_get(req, VW_GATEWAY_SLOT_HEADER);
    if (hdr == NULL || hdr[0] < '0' || hdr[0] > '9') return 0;
    char *end = NULL;
    long v = strtol(hdr, &end, 10);
    if (end == hdr || *end != '\0' || v < 0 || (unsigned long)v >= VW_GATEWAY_MAX_SLOTS) return 0;
    return (unsigned)v;
}

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
 * TASK-176: same four network-shaped failure codes vw_sync.c's is_net_err
 * treats as "connection problem, not a real rejection" — the signal this
 * gateway uses to decide a fallback attempt is warranted (never for
 * VW_ERR_AUTH_2FA_REQUIRED/_BAD_CREDS/etc., which mean the primary was
 * reached and answered).
 */
static int is_net_err(vw_err_t err) {
    return err == VW_ERR_NET_CONNECT || err == VW_ERR_NET_CLOSED ||
           err == VW_ERR_NET_TIMEOUT || err == VW_ERR_NET_TLS;
}

static int fallback_configured(const vw_gateway_server_cfg_t *cfg) {
    return cfg->fallback_host != NULL && cfg->fallback_host[0] != '\0';
}

static void build_client_cfg(const vw_gateway_server_cfg_t *cfg, int use_fallback,
                              vw_client_cfg_t *out) {
    memset(out, 0, sizeof(*out));
    out->host             = use_fallback ? cfg->fallback_host : cfg->server_host;
    out->port             = use_fallback ? cfg->fallback_port : cfg->server_port;
    out->cert_verify      = VW_CERT_VERIFY_REQUIRED;
    out->ca_cert_pem_path = use_fallback ? cfg->fallback_ca_cert_pem_path : cfg->ca_cert_pem_path;
}

/*
 * TASK-176: send the "this session is on the fallback right now"
 * rejection for a write endpoint. Called after require_session() already
 * succeeded for `cookie` — an unknown cookie here would mean
 * require_session() itself already sent a 401 and the caller already
 * returned, so this only ever sees a genuinely live session. Returns 1
 * (and has already written the HTTP response) if the caller must stop;
 * 0 if the write may proceed.
 */
static int reject_if_read_only(vw_gateway_session_pool_t *pool, const char *cookie,
                                vw_http_conn_t *conn) {
    int read_only = 0;
    if (vw_gateway_session_is_read_only(pool, cookie, &read_only) == VW_OK && read_only) {
        send_error(conn, 503, "read_only_fallback");
        return 1;
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
/*
 * Attempts to resume a session for cookie (TASK-165's remember-me) when
 * it's absent from the live in-memory pool — a gateway restart, or an
 * idle/capacity eviction of a session whose cookie the browser still
 * has. Returns VW_OK with *out_sess set (and the pool now holding a live
 * entry under this exact cookie again) on success; any other return
 * means "no dice," and the caller should fall through to its own 401.
 *
 * No lock/retry logic needed for the "resume-rotation race" this task's
 * own security note calls out: vw_gateway_dispatch() is only ever called
 * from main.c's single-threaded, one-request-at-a-time accept loop
 * (vw_gateway_session.h's own threading note), so two requests
 * presenting the same stale cookie can never both reach this function
 * concurrently — whichever is handled first either resumes and
 * re-inserts (so a second one takes the ordinary live-session path in
 * require_session() below, never reaching here at all) or fails and
 * evicts the stale on-disk entry (so a second one gets a clean 401 here,
 * not a second resume attempt on an already-consumed single-use token).
 */
static vw_err_t try_resume_and_reinsert(vw_gateway_session_pool_t *pool, const char *cookie,
                                         vw_client_sess_t **out_sess) {
    if (g_remember_store == NULL || g_server_cfg == NULL) return VW_ERR_AUTH_REQUIRED;

    uint8_t token[32];
    char username[VW_MAX_USERNAME_BYTES + 1];
    if (vw_gateway_remember_get(g_remember_store, cookie, token, username, sizeof(username)) != VW_OK) {
        return VW_ERR_AUTH_REQUIRED;
    }

    /* TASK-176: always the primary — a resume token is meaningless
     * against a different server (see this file's fallback-connect
     * comments in handle_login). */
    vw_client_cfg_t client_cfg;
    build_client_cfg(g_server_cfg, 0, &client_cfg);

    vw_client_sess_t *sess = NULL;
    if (vw_client_resume(&client_cfg, token, &sess) != VW_OK) {
        /* Expired/revoked/already-consumed - simple lazy GC, no separate
         * sweep needed (this task's own design note). */
        vw_gateway_remember_remove(g_remember_store, cookie);
        return VW_ERR_AUTH_REQUIRED;
    }

    if (vw_gateway_session_reinsert(pool, cookie, sess, username) != VW_OK) {
        /* Removing the store entry here is correct even though the
         * failure (almost certainly VW_ERR_QUOTA_EXCEEDED - the pool at
         * its 256-session hard cap) has nothing to do with the token's
         * own validity: vw_client_resume() above already succeeded,
         * which per its own doc means the server already rotated past
         * the OLD token we looked up (single-use resumption,
         * docs/PROTOCOL.md §7.1) - so the on-disk copy is dead the
         * instant that call returns VW_OK, regardless of what happens
         * next locally. There is no "keep the old entry for a retry"
         * option; the user just has to log in again, same as any other
         * too_many_sessions case. */
        vw_client_close(sess);
        vw_gateway_remember_remove(g_remember_store, cookie);
        return VW_ERR_AUTH_REQUIRED;
    }

    /* Persist the rotated token immediately - vw_client_resume's own doc:
     * single-use per resume (docs/PROTOCOL.md §7.1), same convention
     * vw_daemon.c's try_connect() already follows ("persist fresh token"
     * right after vw_client_get_token). */
    uint8_t new_token[32];
    vw_client_get_token(sess, new_token);
    vw_gateway_remember_put(g_remember_store, cookie, new_token, username);
    *out_sess = sess;
    return VW_OK;
}

static vw_err_t require_session(vw_gateway_session_pool_t *pool,
                                 const vw_http_request_t *req,
                                 vw_http_conn_t *conn,
                                 vw_client_sess_t **out_sess,
                                 char *out_cookie) {
    char slot_cookie_hdr_name[16];
    slot_cookie_name(resolve_slot(req), slot_cookie_hdr_name, sizeof(slot_cookie_hdr_name));

    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (!get_cookie_value(req, slot_cookie_hdr_name, cookie, sizeof(cookie))) {
        send_error(conn, 401, "auth_required");
        return VW_ERR_AUTH_REQUIRED;
    }
    vw_err_t err = vw_gateway_session_get(pool, cookie, out_sess);
    if (err != VW_OK) {
        err = try_resume_and_reinsert(pool, cookie, out_sess);
    }
    if (err != VW_OK) {
        send_error(conn, 401, "auth_required");
        return VW_ERR_AUTH_REQUIRED;
    }
    if (out_cookie != NULL) {
        memcpy(out_cookie, cookie, sizeof(cookie));
    }
    return VW_OK;
}

/*
 * Shared JSON-body field readers. Defined here (ahead of every endpoint
 * that uses them, including handle_login/handle_logout/handle_link_access
 * below, which is why this pair moved up from where the rest of this
 * file's endpoint-specific helpers live, right before handle_file_list) —
 * a plain forward declaration would work too, but a single definition
 * point is simpler to keep in sync.
 */
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

/*
 * Determines which slot a fresh login/link-access session should occupy.
 * explicit_slot_valid/explicit_slot come from the request's own JSON body
 * "slot" field (present and, per this function's own check, in range) —
 * an explicit, out-of-range value is a caller error (unlike the
 * X-Vw-Slot *header* used by require_session, which fails open to slot 0;
 * here the caller is asserting a specific target, so a bad one should be
 * rejected, not silently reinterpreted). Absent -> "next free slot" for
 * THIS browser: the lowest slot whose cookie is either absent or doesn't
 * map to a currently-live session. Scoped entirely to the calling
 * browser's own Cookie header, so it can never observe (or affect)
 * another browser's sessions. Returns VW_ERR_QUOTA_EXCEEDED if every slot
 * is occupied and none was explicitly requested (a real cap, not a
 * suggestion — see VW_GATEWAY_MAX_SLOTS's own doc above), or
 * VW_ERR_INVALID_ARG for an out-of-range explicit slot.
 */
static vw_err_t resolve_login_slot(vw_gateway_session_pool_t *pool,
                                    const vw_http_request_t *req,
                                    int explicit_slot_valid, unsigned explicit_slot,
                                    unsigned *out_slot) {
    if (explicit_slot_valid) {
        if (explicit_slot >= VW_GATEWAY_MAX_SLOTS) return VW_ERR_INVALID_ARG;
        *out_slot = explicit_slot;
        return VW_OK;
    }
    for (unsigned i = 0; i < VW_GATEWAY_MAX_SLOTS; i++) {
        char name[16];
        slot_cookie_name(i, name, sizeof(name));
        char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
        vw_client_sess_t *dummy;
        if (!get_cookie_value(req, name, cookie, sizeof(cookie)) ||
            vw_gateway_session_get(pool, cookie, &dummy) != VW_OK) {
            *out_slot = i;
            return VW_OK;
        }
    }
    return VW_ERR_QUOTA_EXCEEDED;
}

/*
 * If target_slot's cookie is currently present, removes it from the live
 * pool AND the remember-me store (TASK-165) — otherwise re-authenticating
 * an already-occupied slot (this function's whole reason to exist:
 * resolve_login_slot's explicit-slot path allows exactly that) would
 * orphan the old entries: the pool one until idle-reap, the on-disk one
 * forever (nothing else ever revisits a remember-store entry except a
 * cookie-miss on that exact cookie value, which can't happen again once
 * a NEW cookie takes over the slot). Safe to call unconditionally on
 * both — vw_gateway_session_remove/vw_gateway_remember_remove are both
 * no-ops on an absent/unknown cookie.
 */
static void evict_slot_if_present(vw_gateway_session_pool_t *pool,
                                   const vw_http_request_t *req, unsigned slot) {
    char name[16];
    slot_cookie_name(slot, name, sizeof(name));
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (get_cookie_value(req, name, cookie, sizeof(cookie))) {
        vw_gateway_session_remove(pool, cookie);
        if (g_remember_store != NULL) {
            vw_gateway_remember_remove(g_remember_store, cookie);
        }
    }
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

    /* Multi-slot (TASK-164): resolve BEFORE the network round-trip below,
     * so a full slot set or an invalid explicit slot fails fast without
     * ever contacting the server. */
    uint64_t slot_raw = 0;
    int slot_present = (get_json_uint_field(req, "slot", &slot_raw) == VW_OK);
    unsigned target_slot = 0;
    vw_err_t slot_err = resolve_login_slot(pool, req, slot_present, (unsigned)slot_raw, &target_slot);
    if (slot_err != VW_OK) {
        vw_crypto_secure_zero(password, sizeof(password));
        vw_crypto_secure_zero(otp, sizeof(otp));
        send_error(conn, slot_err == VW_ERR_QUOTA_EXCEEDED ? 507 : 400,
                   slot_err == VW_ERR_QUOTA_EXCEEDED ? "no_free_slot" : "bad_request");
        return;
    }

    /* Remember-me (TASK-165): opt-in at both the operator level
     * (g_remember_store == NULL unless main.c was given --state-dir) and
     * the user level (this field) - absent/false/store-disabled all mean
     * "session-only cookie," never an error. */
    int remember = 0;
    if (vw_json_object_get((const char *)req->body, req->body_len, "remember", &v) == VW_OK &&
        v.kind == VW_JSON_BOOL) {
        remember = v.bool_val ? 1 : 0;
    }
    remember = remember && (g_remember_store != NULL);

    vw_client_cfg_t client_cfg;
    build_client_cfg(cfg, 0, &client_cfg);

    vw_client_sess_t *sess = NULL;
    vw_err_t err = vw_client_connect(&client_cfg, username, username_len,
                                      password, password_len,
                                      login_otp_cb, &otp_ctx, &sess);

    /* TASK-176: the primary is unreachable and a fallback is configured —
     * retry with the SAME already-in-hand credentials against it before
     * giving up. Unlike the daemon (TASK-173), this gateway never needs
     * to retain a derived credential for later: every login already has
     * the raw password in hand for exactly this one retry, so there is
     * nothing to persist. A session created this way is read-only for
     * its entire lifetime (see vw_gateway_session_create's read_only
     * param) — remember-me resume (try_resume_and_reinsert) never
     * attempts a fallback connect at all, since a primary-issued resume
     * token is meaningless against a different server (docs/PROTOCOL.md
     * §7.1); only a fresh login like this one can fail over. */
    int read_only = 0;
    if (is_net_err(err) && fallback_configured(cfg)) {
        vw_client_cfg_t fallback_cfg;
        build_client_cfg(cfg, 1, &fallback_cfg);
        vw_err_t fb_err = vw_client_connect(&fallback_cfg, username, username_len,
                                             password, password_len,
                                             login_otp_cb, &otp_ctx, &sess);
        if (fb_err == VW_OK) { err = VW_OK; read_only = 1; }
    }

    vw_crypto_secure_zero(password, sizeof(password));
    vw_crypto_secure_zero(otp, sizeof(otp));

    if (err == VW_OK) {
        evict_slot_if_present(pool, req, target_slot);
        char cookie_hex[VW_GATEWAY_COOKIE_HEX_LEN + 1];
        if (vw_gateway_session_create(pool, sess, username, read_only, cookie_hex) != VW_OK) {
            vw_client_close(sess);
            send_error(conn, 503, "too_many_sessions");
            return;
        }
        /* TASK-176: never persist a remember-me token issued by the
         * fallback — try_resume_and_reinsert only ever resumes against
         * the primary (see this function's own comment above), so a
         * fallback-issued token would just silently never resume. */
        if (remember && !read_only) {
            uint8_t token[32];
            vw_client_get_token(sess, token);
            /* Best-effort: a failed persist here just means this login
             * won't survive a restart, not that the login itself fails -
             * the live in-memory session created above is unaffected. */
            (void)vw_gateway_remember_put(g_remember_store, cookie_hex, token, username);
        }
        char slot_name[16];
        slot_cookie_name(target_slot, slot_name, sizeof(slot_name));
        char cookie_header[VW_GATEWAY_COOKIE_HEX_LEN + 96];
        /* Max-Age=2592000 (30 days, matching the server's own
         * DEFAULT_SESSION_TTL_SECS, src/server/vw_auth.c) only when
         * remember was actually honored - a session-only cookie for
         * every other case, unchanged from before this task. TASK-176:
         * also session-only when read_only, since the persist above was
         * skipped — a long-lived cookie would promise a durability this
         * login never actually got. */
        if (remember && !read_only) {
            snprintf(cookie_header, sizeof(cookie_header),
                     "%s=%s; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000",
                     slot_name, cookie_hex);
        } else {
            snprintf(cookie_header, sizeof(cookie_header),
                     "%s=%s; Path=/; HttpOnly; Secure; SameSite=Strict",
                     slot_name, cookie_hex);
        }
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
    /* Multi-slot (TASK-164): an explicit body "slot" field says which one
     * to clear; absent (including no body at all — logout never required
     * one before this task) defaults to slot 0, preserving today's
     * behavior for a frontend that hasn't been updated yet. An
     * out-of-range value here just can't match any real slot's cookie
     * name below, so it's harmless to fail open to 0 rather than reject
     * the request — logout has nothing left to protect by being strict. */
    uint64_t slot_raw = 0;
    unsigned slot = 0;
    if (get_json_uint_field(req, "slot", &slot_raw) == VW_OK && slot_raw < VW_GATEWAY_MAX_SLOTS) {
        slot = (unsigned)slot_raw;
    }
    char slot_name[16];
    slot_cookie_name(slot, slot_name, sizeof(slot_name));

    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (get_cookie_value(req, slot_name, cookie, sizeof(cookie))) {
        vw_gateway_session_remove(pool, cookie);
        /* TASK-165: a remembered slot's on-disk entry must go too, or a
         * "logged out" browser would silently resume itself on its very
         * next request (this task's own acceptance criterion). */
        if (g_remember_store != NULL) {
            vw_gateway_remember_remove(g_remember_store, cookie);
        }
    }
    /* Idempotent either way - an unknown/absent cookie is not an error. */
    char clear_header[96];
    snprintf(clear_header, sizeof(clear_header),
             "%s=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0", slot_name);
    send_json_status(conn, 200, "ok", clear_header);
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
        case VW_ERR_VERSION_NOT_FOUND:
            /* Found during TASK-153/144 review: /api/versions/restore with
             * any invalid/foreign version_id (stale UI state, a double
             * click, a version already superseded) is exactly as ordinary
             * as VW_ERR_NOT_FOUND above - same class of gap as
             * VW_ERR_ALREADY_EXISTS/RATE_LIMITED/AUTH_REQUIRED elsewhere in
             * this switch, doesn't warrant eviction. */
            send_error(conn, 404, "version_not_found");
            return;
        case VW_ERR_DIR_NOT_EMPTY:
            send_error(conn, 409, "dir_not_empty");
            return;
        case VW_ERR_ALREADY_EXISTS:
            /* Found via TASK-141 testing: a plain name collision (e.g.
             * mkdir on an existing name) - as ordinary an outcome as
             * VW_ERR_NOT_FOUND above, not a connection-health signal.
             * Same class of gap as VW_ERR_AUTH_REQUIRED below; this one
             * doesn't warrant eviction either. */
            send_error(conn, 409, "already_exists");
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
        case VW_ERR_RATE_LIMITED:
            send_error(conn, 429, "rate_limited");
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
    if (reject_if_read_only(pool, cookie, conn)) return;
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
    if (reject_if_read_only(pool, cookie, conn)) return;
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
    if (reject_if_read_only(pool, cookie, conn)) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    uint64_t file_id = 0, new_parent_dir_id = 0;
    char new_name[256];
    new_name[0] = '\0';

    if (get_json_uint_field(req, "file_id", &file_id) != VW_OK) {
        send_error(conn, 400, "bad_request");
        return;
    }
    (void)get_json_uint_field(req, "new_parent_dir_id", &new_parent_dir_id);
    if (get_json_string_field(req, "new_name", new_name, sizeof(new_name)) != VW_OK) {
        /* Optional field: a decode failure (oversized/malformed value) means
         * treat it as absent, not as whatever partial bytes landed in the
         * buffer — checking new_name[0] below must never see a stale or
         * truncated value from a failed decode. */
        new_name[0] = '\0';
    }

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
    if (reject_if_read_only(pool, cookie, conn)) return;

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

#define VW_GATEWAY_MAX_WRAPPED_VK_BYTES 2048u
#define VW_GATEWAY_MAX_KDF_PARAMS_BYTES 512u

/*
 * Decodes a hex-encoded JSON string field into an opaque byte buffer -
 * shared by every endpoint moving a wrapped-key blob (vault create/
 * key_fetch, TASK-135; an encrypted commit's wrapped_dek, TASK-141)
 * without ever needing to parse its meaning.
 */
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

static void handle_file_commit(vw_gateway_session_pool_t *pool,
                                const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (reject_if_read_only(pool, cookie, conn)) return;
    if (req->body == NULL) { send_error(conn, 400, "bad_request"); return; }

    char path[VW_MAX_PATH_BYTES];
    path[0] = '\0';
    uint64_t file_id = 0;
    char leaf_name[256];
    leaf_name[0] = '\0';
    uint64_t logical_size = 0;

    /* Both are optional fields (one of path/file_id+leaf_name/file_id-alone
     * addresses the target, per the three modes below) — a decode failure
     * must be treated as absent, not as whatever partial bytes a failed
     * decode left behind (see vw_json_string_decode's own doc comment). */
    if (get_json_string_field(req, "path", path, sizeof(path)) != VW_OK) {
        path[0] = '\0';
    }
    (void)get_json_uint_field(req, "file_id", &file_id);
    if (get_json_string_field(req, "leaf_name", leaf_name, sizeof(leaf_name)) != VW_OK) {
        leaf_name[0] = '\0';
    }

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

    /* Optional vault fields (TASK-141) - an encrypted commit's wrapped_dek
     * is this module's usual opaque hex blob, exactly like TASK-135's
     * vault/create wrapped_vk. vault_id absent or 0 means a plaintext
     * commit, matching vw_client_file_commit_raw's own convention. */
    uint64_t vault_id = 0;
    uint8_t wrapped_dek[VW_GATEWAY_MAX_WRAPPED_VK_BYTES];
    size_t wrapped_dek_len = 0;
    (void)get_json_uint_field(req, "vault_id", &vault_id);
    if (vault_id != 0) {
        if (get_json_hex_field(req, "wrapped_dek", wrapped_dek, sizeof(wrapped_dek),
                                &wrapped_dek_len) != VW_OK ||
            wrapped_dek_len == 0) {
            free(hashes);
            send_error(conn, 400, "bad_request");
            return;
        }
    }

    uint64_t out_file_id = 0, out_version_id = 0;
    vw_err_t err = vw_client_file_commit_raw(sess, commit_file_id, name_or_path, name_len,
                                              logical_size, chunk_count, hashes,
                                              vault_id,
                                              vault_id != 0 ? wrapped_dek : NULL,
                                              (uint16_t)wrapped_dek_len,
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
    if (reject_if_read_only(pool, cookie, conn)) return;
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
    if (reject_if_read_only(pool, cookie, conn)) return;
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
    if (reject_if_read_only(pool, cookie, conn)) return;
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
    if (reject_if_read_only(pool, cookie, conn)) return;
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

    /* Multi-slot (TASK-164): same resolution as handle_login, before the
     * network round-trip. A redeemed link is a login-like action from the
     * browser's own perspective (it can coexist with other already-open
     * account slots), so it gets the same "explicit or next free" choice. */
    uint64_t slot_raw = 0;
    int slot_present = (get_json_uint_field(req, "slot", &slot_raw) == VW_OK);
    unsigned target_slot = 0;
    vw_err_t slot_err = resolve_login_slot(pool, req, slot_present, (unsigned)slot_raw, &target_slot);
    if (slot_err != VW_OK) {
        send_error(conn, slot_err == VW_ERR_QUOTA_EXCEEDED ? 507 : 400,
                   slot_err == VW_ERR_QUOTA_EXCEEDED ? "no_free_slot" : "bad_request");
        return;
    }

    vw_client_cfg_t client_cfg;
    build_client_cfg(cfg, 0, &client_cfg);

    vw_client_sess_t *sess = NULL;
    vw_err_t err = vw_client_link_access(&client_cfg, link_token, &sess);

    /* TASK-176: same fallback treatment as handle_login — an anonymous
     * link redemption can fail over too (the resulting session is
     * read-only regardless, same as any other fallback session, so an
     * EDIT-permission link's writes are correctly blocked while degraded
     * either way). */
    int read_only = 0;
    if (is_net_err(err) && fallback_configured(cfg)) {
        vw_client_cfg_t fallback_cfg;
        build_client_cfg(cfg, 1, &fallback_cfg);
        vw_err_t fb_err = vw_client_link_access(&fallback_cfg, link_token, &sess);
        if (fb_err == VW_OK) { err = VW_OK; read_only = 1; }
    }

    if (err != VW_OK) {
        /* Anti-enumeration (vw_client_link_access's own doc): unknown,
         * revoked, and expired tokens are all indistinguishable here too. */
        send_error(conn, 401, "bad_credentials");
        return;
    }

    evict_slot_if_present(pool, req, target_slot);
    char cookie_hex[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    /* No real logged-in username for a link session - see
     * vw_gateway_session_create's own doc on the NULL convention. */
    if (vw_gateway_session_create(pool, sess, NULL, read_only, cookie_hex) != VW_OK) {
        vw_client_close(sess);
        send_error(conn, 503, "too_many_sessions");
        return;
    }
    char slot_name[16];
    slot_cookie_name(target_slot, slot_name, sizeof(slot_name));
    char cookie_header[VW_GATEWAY_COOKIE_HEX_LEN + 96];
    snprintf(cookie_header, sizeof(cookie_header),
             "%s=%s; Path=/; HttpOnly; Secure; SameSite=Strict",
             slot_name, cookie_hex);
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

static void handle_vault_create(vw_gateway_session_pool_t *pool,
                                 const vw_http_request_t *req, vw_http_conn_t *conn) {
    vw_client_sess_t *sess;
    char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
    if (require_session(pool, req, conn, &sess, cookie) != VW_OK) return;
    if (reject_if_read_only(pool, cookie, conn)) return;
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

/*
 * /api/accounts (TASK-164): which slots THIS browser currently has a live
 * session in, and each one's display username. Read entirely off the
 * calling request's own Cookie header (get_cookie_value/
 * vw_gateway_session_get_username below never look at anything but the
 * slot cookie names derived here), so this can never leak another
 * browser's sessions. No require_session() call - by design, an empty
 * result (no slots occupied) is a normal, successful response here, not
 * a 401 - this is exactly how the frontend's "does the browser already
 * have anything to resume" check on page load is meant to work, per this
 * task's own note that the frontend previously always showed the login
 * form even when a still-valid cookie was already present.
 */
static void handle_accounts(vw_gateway_session_pool_t *pool,
                             const vw_http_request_t *req, vw_http_conn_t *conn) {
    char *buf = malloc(2048);
    if (buf == NULL) { send_error(conn, 500, "error"); return; }
    vw_json_writer_t w;
    vw_json_writer_init(&w, buf, 2048);
    vw_json_write_object_start(&w);
    vw_json_write_key(&w, "slots");
    vw_json_write_array_start(&w);

    for (unsigned i = 0; i < VW_GATEWAY_MAX_SLOTS; i++) {
        char name[16];
        slot_cookie_name(i, name, sizeof(name));
        char cookie[VW_GATEWAY_COOKIE_HEX_LEN + 1];
        char username[VW_MAX_USERNAME_BYTES + 1];
        if (!get_cookie_value(req, name, cookie, sizeof(cookie)) ||
            vw_gateway_session_get_username(pool, cookie, username, sizeof(username)) != VW_OK) {
            continue;
        }
        int read_only = 0;
        (void)vw_gateway_session_is_read_only(pool, cookie, &read_only);

        vw_json_write_object_start(&w);
        vw_json_write_key(&w, "slot");
        vw_json_write_uint(&w, i);
        vw_json_write_key(&w, "username");
        /* Empty for a redeemed-public-link session - see
         * vw_gateway_session_create's own doc on the NULL convention. */
        vw_json_write_string(&w, username, strlen(username));
        /* TASK-176: lets the frontend show "read-only fallback" and grey
         * out/explain disabled write actions for this slot, mirroring the
         * daemon/GUI's own conn_mode surfacing (TASK-173/175). */
        vw_json_write_key(&w, "read_only");
        vw_json_write_bool(&w, read_only != 0);
        vw_json_write_object_end(&w);
    }

    vw_json_write_array_end(&w);
    vw_json_write_object_end(&w);
    size_t len = 0;
    vw_json_writer_result(&w, &len);
    vw_http_send_response(conn, 200, "application/json", NULL, buf, (uint32_t)len);
    free(buf);
}

/* ── Dispatch ─────────────────────────────────────────────────────────────── */

void vw_gateway_dispatch(vw_gateway_session_pool_t *pool,
                          const vw_gateway_server_cfg_t *cfg,
                          const vw_http_request_t *req,
                          vw_http_conn_t *conn) {
    g_server_cfg = cfg;

    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/login") == 0) {
        handle_login(pool, cfg, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/logout") == 0) {
        handle_logout(pool, req, conn);
        return;
    }
    if (req->method == VW_HTTP_POST && strcmp(req->path, "/api/accounts") == 0) {
        handle_accounts(pool, req, conn);
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
