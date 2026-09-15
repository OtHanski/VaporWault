#include "vw_update_net.h"
#include "../core/vw_net.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* Bounds shared by every fetch this module ever makes — the manifest is
 * small, an asset archive is larger but still bounded; individual callers
 * pass their own max_body_bytes, these two are purely internal plumbing
 * limits. */
/* Overridable via target_compile_definitions (same convention as
 * VW_ECC_MAX_DATA_SHARDS/VW_OPLOG_SEGMENT_MAX elsewhere in this codebase)
 * so a test target can shrink these to make the timeout-enforcement test
 * fast instead of taking the real 10-20s production values. */
#ifndef VW_UPDATE_CONNECT_TIMEOUT_MS
#define VW_UPDATE_CONNECT_TIMEOUT_MS 10000u
#endif
#ifndef VW_UPDATE_RECV_TIMEOUT_MS
#define VW_UPDATE_RECV_TIMEOUT_MS    20000u
#endif
#define VW_UPDATE_MAX_HEADER_BYTES   8192u   /* status line + all headers */
#define VW_UPDATE_MAX_HOST_LEN       255u
#define VW_UPDATE_MAX_PATH_LEN       2048u
#define VW_UPDATE_READ_CHUNK         4096u
/* Wall-clock cap on one fetch's total read phase (header+body combined),
 * independent of vw_net_recv_partial's own per-call recv timeout. Needed
 * because vw_net_recv_partial can legitimately return VW_OK with got==0
 * on a transient MBEDTLS_ERR_SSL_WANT_READ (an incompletely-assembled TLS
 * record, not "no more data") — see the read loops below — so a peer that
 * trickles bytes just fast enough to keep triggering that path without
 * ever completing a record could otherwise stall this fetch indefinitely
 * even though no single recv() call ever times out. */
#ifndef VW_UPDATE_TOTAL_READ_DEADLINE_SECS
#define VW_UPDATE_TOTAL_READ_DEADLINE_SECS 60
#endif

typedef struct {
    int     status_code;
    long    content_length;          /* -1 = header absent */
    int     chunked;                 /* Transfer-Encoding: chunked seen */
    char    location[VW_UPDATE_MAX_HOST_LEN + VW_UPDATE_MAX_PATH_LEN + 16];
    int     has_location;
} http_head_t;

/* ── small ASCII helpers (no locale-dependent libc case functions) ──────── */

static int ieq_n(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return 1;
}

static const char *skip_ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t')) p++;
    return p;
}

/* ── HTTPS URL parsing (for redirect targets) ────────────────────────────
 * Handles "https://host[:port]/path...". No userinfo, no fragment
 * handling needed — not part of any shape this module's real-world peer
 * (GitHub's release infrastructure) or its test doubles produce.
 * out_port defaults to 443 when the URL has no explicit port. */
static vw_err_t parse_https_url(const char *url,
                                 char *out_host, size_t host_sz,
                                 uint16_t *out_port,
                                 char *out_path, size_t path_sz) {
    static const char prefix[] = "https://";
    size_t plen = sizeof(prefix) - 1;
    if (strncmp(url, prefix, plen) != 0) return VW_ERR_UPDATE_NET;

    const char *host_start = url + plen;
    const char *p = host_start;
    while (*p && *p != '/' && *p != ':') p++;

    size_t host_len = (size_t)(p - host_start);
    if (host_len == 0 || host_len >= host_sz) return VW_ERR_UPDATE_NET;
    memcpy(out_host, host_start, host_len);
    out_host[host_len] = '\0';

    *out_port = 443;
    if (*p == ':') {
        p++;
        unsigned long port = 0;
        int ndigits = 0;
        while (*p >= '0' && *p <= '9' && ndigits < 6) {
            port = port * 10 + (unsigned long)(*p - '0');
            p++; ndigits++;
        }
        if (ndigits == 0 || port == 0 || port > 65535) return VW_ERR_UPDATE_NET;
        *out_port = (uint16_t)port;
    }

    if (*p == '\0') {
        if (path_sz < 2) return VW_ERR_UPDATE_NET;
        out_path[0] = '/';
        out_path[1] = '\0';
        return VW_OK;
    }

    size_t path_len = strlen(p);
    if (path_len >= path_sz) return VW_ERR_UPDATE_NET;
    memcpy(out_path, p, path_len + 1);
    return VW_OK;
}

/* ── Response head parsing ───────────────────────────────────────────────
 * hdr/hdr_len is the raw bytes up to and including the blank line
 * terminating the headers (the "\r\n\r\n"). Never fails on a merely
 * unexpected-but-well-formed header set — absent Content-Length or an
 * unrecognized status is reported via the out struct's fields, decided by
 * the caller, not this parser. */
static vw_err_t parse_response_head(const uint8_t *hdr, size_t hdr_len,
                                     http_head_t *out) {
    memset(out, 0, sizeof(*out));
    out->content_length = -1;

    const char *p   = (const char *)hdr;
    const char *end = (const char *)hdr + hdr_len;

    /* Status line: "HTTP/1.x SP status SP reason CRLF" */
    if (hdr_len < 12 || strncmp(p, "HTTP/1.", 7) != 0) return VW_ERR_UPDATE_NET;
    const char *sp = memchr(p, ' ', (size_t)(end - p));
    if (!sp) return VW_ERR_UPDATE_NET;
    sp = skip_ws(sp, end);
    int code = 0, ndigits = 0;
    while (sp < end && *sp >= '0' && *sp <= '9' && ndigits < 3) {
        code = code * 10 + (*sp - '0');
        sp++; ndigits++;
    }
    if (ndigits != 3) return VW_ERR_UPDATE_NET;
    out->status_code = code;

    const char *line_end = memchr(p, '\n', (size_t)(end - p));
    if (!line_end) return VW_ERR_UPDATE_NET;
    p = line_end + 1;

    /* Header lines until the blank line. */
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) break;
        const char *line = p;
        const char *line_stop = nl;
        if (line_stop > line && line_stop[-1] == '\r') line_stop--;
        p = nl + 1;

        if (line_stop == line) break; /* blank line: end of headers */

        const char *colon = memchr(line, ':', (size_t)(line_stop - line));
        if (!colon) continue; /* malformed header line — ignore, not fatal */

        size_t name_len = (size_t)(colon - line);
        const char *val = skip_ws(colon + 1, line_stop);
        size_t val_len = (size_t)(line_stop - val);

        if (name_len == 14 && ieq_n(line, "content-length", 14)) {
            char numbuf[32];
            if (val_len == 0 || val_len >= sizeof(numbuf)) return VW_ERR_UPDATE_NET;
            memcpy(numbuf, val, val_len);
            numbuf[val_len] = '\0';
            for (size_t i = 0; i < val_len; i++)
                if (numbuf[i] < '0' || numbuf[i] > '9') return VW_ERR_UPDATE_NET;
            out->content_length = atol(numbuf);
            if (out->content_length < 0) return VW_ERR_UPDATE_NET;
        } else if (name_len == 17 && ieq_n(line, "transfer-encoding", 17)) {
            if (val_len >= 7 && ieq_n(val, "chunked", 7))
                out->chunked = 1;
        } else if (name_len == 8 && ieq_n(line, "location", 8)) {
            if (val_len < sizeof(out->location)) {
                memcpy(out->location, val, val_len);
                out->location[val_len] = '\0';
                out->has_location = 1;
            }
        }
    }

    return VW_OK;
}

/*
 * Test-hook seam (same convention as VW_SYNC_TEST_HOOKS/
 * VW_FILE_HANDLERS_TEST_HOOKS elsewhere in this codebase): when compiled
 * with VW_UPDATE_NET_TEST_HOOKS, a test can redirect the connect step
 * away from vw_net_connect_generic()'s real VW_CERT_VERIFY_SYSTEM_STORE
 * path — which needs a real, publicly-trusted certificate and so can't be
 * pointed at a local self-signed test server — toward
 * VW_CERT_VERIFY_NONE against a local server instead, or toward a
 * deliberately-failing/slow connect to exercise the timeout path. This
 * only changes what a *test* binary does; production builds never define
 * VW_UPDATE_NET_TEST_HOOKS and always take the real SYSTEM_STORE path.
 */
#ifdef VW_UPDATE_NET_TEST_HOOKS
static vw_err_t (*g_connect_hook)(const char *host, uint16_t port,
                                   const vw_conn_opts_t *opts,
                                   vw_conn_t **out_conn) = NULL;

void vw_update_net_test_set_connect_hook(
        vw_err_t (*fn)(const char *host, uint16_t port,
                        const vw_conn_opts_t *opts, vw_conn_t **out_conn)) {
    g_connect_hook = fn;
}
#endif

static vw_err_t do_connect_for_fetch(const char *host, uint16_t port,
                                      const vw_conn_opts_t *opts,
                                      vw_conn_t **out_conn) {
#ifdef VW_UPDATE_NET_TEST_HOOKS
    if (g_connect_hook) return g_connect_hook(host, port, opts, out_conn);
#endif
    return vw_net_connect_generic(host, port, VW_CERT_VERIFY_SYSTEM_STORE,
                                   NULL, opts, out_conn);
}

/* ── One fetch attempt: connect, send GET, read+parse the response head,
 * and either (a) return a redirect Location for the caller to follow, or
 * (b) read and return the final body. Does not itself follow redirects —
 * vw_update_https_get's outer loop does that, bounding the count. ─────── */
static vw_err_t fetch_once(const char *host, uint16_t port, const char *path,
                            size_t max_body_bytes,
                            http_head_t *out_head,
                            vw_update_response_t *out_body /* zeroed by caller;
                                                               only filled when
                                                               out_head->status_code
                                                               is a final 2xx */) {
    vw_conn_opts_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.connect_timeout_ms = VW_UPDATE_CONNECT_TIMEOUT_MS; /* bounds the TCP connect */
    /* opts.recv_timeout_ms is deliberately left 0 here: net_connect_impl()
     * ignores it for the handshake (uses its own hardcoded 10s) and would
     * discard it afterward regardless (see the vw_net_conn_set_recv_timeout
     * call and its comment below) — setting it here would be dead code
     * that misleadingly suggests it controls the read-phase timeout. */

    vw_conn_t *conn = NULL;
    vw_err_t err = do_connect_for_fetch(host, port, &opts, &conn);
    if (err != VW_OK) return VW_ERR_UPDATE_NET;

    /* vw_net_connect*()'s opts->recv_timeout_ms only bounds the TLS
     * handshake itself — net_connect_impl() deliberately resets the
     * connection's recv timeout to 0 (unlimited) once the handshake
     * completes (see ARCHITECTURE.md's "vw_net recv timeout" row); every
     * other caller in this codebase re-arms it post-connect via
     * vw_net_conn_set_recv_timeout(), and this is no exception — without
     * this call, the read loops below would block indefinitely on a peer
     * that accepts the connection but never sends a response. */
    err = vw_net_conn_set_recv_timeout(conn, VW_UPDATE_RECV_TIMEOUT_MS);
    if (err != VW_OK) { vw_net_close(conn); return VW_ERR_UPDATE_NET; }

    char req[VW_UPDATE_MAX_PATH_LEN + VW_UPDATE_MAX_HOST_LEN + 128];
    int n = snprintf(req, sizeof(req),
                      "GET %s HTTP/1.1\r\n"
                      "Host: %s\r\n"
                      "User-Agent: VaporWault-update-check/1\r\n"
                      "Connection: close\r\n"
                      "\r\n",
                      path, host);
    if (n <= 0 || (size_t)n >= sizeof(req)) { vw_net_close(conn); return VW_ERR_UPDATE_NET; }

    err = vw_net_send(conn, req, (size_t)n);
    if (err != VW_OK) { vw_net_close(conn); return VW_ERR_UPDATE_NET; }

    /* Read until we have the full header block ("\r\n\r\n"), capped at
     * VW_UPDATE_MAX_HEADER_BYTES. Any body bytes read past the header
     * boundary in the same recv (common — TCP doesn't respect our framing)
     * are kept in spill[]/spill_len for the body-read phase below. */
    uint8_t hdrbuf[VW_UPDATE_MAX_HEADER_BYTES];
    size_t  hdrbuf_len = 0;
    size_t  head_end = 0; /* offset just past "\r\n\r\n"; 0 = not found yet */
    time_t  deadline = time(NULL) + VW_UPDATE_TOTAL_READ_DEADLINE_SECS;

    while (head_end == 0) {
        if (hdrbuf_len >= sizeof(hdrbuf)) { vw_net_close(conn); return VW_ERR_UPDATE_NET; }
        if (time(NULL) >= deadline) { vw_net_close(conn); return VW_ERR_UPDATE_NET; }
        size_t want = sizeof(hdrbuf) - hdrbuf_len;
        size_t got = 0;
        err = vw_net_recv_partial(conn, hdrbuf + hdrbuf_len, want, &got);
        if (err != VW_OK) { vw_net_close(conn); return VW_ERR_UPDATE_NET; }
        if (got == 0) continue; /* VW_OK + 0 bytes == transient WANT_READ,
                                    not EOF (see VW_UPDATE_TOTAL_READ_DEADLINE_SECS
                                    comment above) — try again, bounded by
                                    the wall-clock deadline, not treated as
                                    a connection-closed error */
        hdrbuf_len += got;

        for (size_t i = 3; i < hdrbuf_len; i++) {
            if (hdrbuf[i - 3] == '\r' && hdrbuf[i - 2] == '\n' &&
                hdrbuf[i - 1] == '\r' && hdrbuf[i]     == '\n') {
                head_end = i + 1;
                break;
            }
        }
    }

    err = parse_response_head(hdrbuf, head_end, out_head);
    if (err != VW_OK) { vw_net_close(conn); return err; }

    size_t spill_len = hdrbuf_len - head_end;
    const uint8_t *spill = hdrbuf + head_end;

    int is_redirect = (out_head->status_code == 301 || out_head->status_code == 302 ||
                        out_head->status_code == 307 || out_head->status_code == 308);

    if (is_redirect) {
        vw_net_close(conn); /* Connection: close was sent either way */
        if (!out_head->has_location) return VW_ERR_UPDATE_NET;
        return VW_OK; /* caller inspects out_head->location */
    }

    if (out_head->status_code != 200) { vw_net_close(conn); return VW_ERR_UPDATE_NET; }
    if (out_head->chunked)            { vw_net_close(conn); return VW_ERR_UPDATE_NET; }
    if (out_head->content_length < 0) { vw_net_close(conn); return VW_ERR_UPDATE_NET; }
    if ((size_t)out_head->content_length > max_body_bytes) {
        vw_net_close(conn);
        return VW_ERR_UPDATE_NET; /* rejected before allocating/reading a single body byte */
    }

    size_t body_len = (size_t)out_head->content_length;
    uint8_t *body = NULL;
    if (body_len > 0) {
        body = (uint8_t *)malloc(body_len);
        if (!body) { vw_net_close(conn); return VW_ERR_OOM; }
    }

    size_t filled = 0;
    if (spill_len > 0) {
        size_t take = spill_len < body_len ? spill_len : body_len;
        if (take > 0) memcpy(body, spill, take);
        filled = take;
    }
    while (filled < body_len) {
        if (time(NULL) >= deadline) { free(body); vw_net_close(conn); return VW_ERR_UPDATE_NET; }
        size_t want = body_len - filled;
        if (want > VW_UPDATE_READ_CHUNK) want = VW_UPDATE_READ_CHUNK;
        size_t got = 0;
        err = vw_net_recv_partial(conn, body + filled, want, &got);
        if (err != VW_OK) { free(body); vw_net_close(conn); return VW_ERR_UPDATE_NET; }
        if (got == 0) continue; /* transient WANT_READ, see above — retry */
        filled += got;
    }

    vw_net_close(conn);
    out_body->body     = body;
    out_body->body_len = body_len;
    out_body->body_cap = body_len;
    return VW_OK;
}

vw_err_t vw_update_https_get(const char *host, uint16_t port, const char *path,
                              size_t max_body_bytes,
                              vw_update_response_t *out) {
    if (!host || !path || !out) return VW_ERR_INVALID_ARG;
    memset(out, 0, sizeof(*out));

    char cur_host[VW_UPDATE_MAX_HOST_LEN + 1];
    char cur_path[VW_UPDATE_MAX_PATH_LEN + 1];
    uint16_t cur_port = port;
    if (strlen(host) >= sizeof(cur_host)) return VW_ERR_INVALID_ARG;
    if (strlen(path) >= sizeof(cur_path)) return VW_ERR_INVALID_ARG;
    memcpy(cur_host, host, strlen(host) + 1);
    memcpy(cur_path, path, strlen(path) + 1);

    for (int redirects = 0; redirects <= 1; redirects++) {
        http_head_t head;
        vw_err_t err = fetch_once(cur_host, cur_port, cur_path, max_body_bytes, &head, out);
        if (err != VW_OK) return err;

        int is_redirect = (head.status_code == 301 || head.status_code == 302 ||
                            head.status_code == 307 || head.status_code == 308);
        if (!is_redirect) return VW_OK; /* out is populated */

        if (redirects == 1) return VW_ERR_UPDATE_NET; /* a second redirect — hard fail */

        char next_host[VW_UPDATE_MAX_HOST_LEN + 1];
        char next_path[VW_UPDATE_MAX_PATH_LEN + 1];
        uint16_t next_port;
        if (parse_https_url(head.location, next_host, sizeof(next_host),
                             &next_port, next_path, sizeof(next_path)) != VW_OK)
            return VW_ERR_UPDATE_NET;

        memcpy(cur_host, next_host, strlen(next_host) + 1);
        memcpy(cur_path, next_path, strlen(next_path) + 1);
        cur_port = next_port;
    }

    return VW_ERR_UPDATE_NET; /* unreachable */
}

void vw_update_response_free(vw_update_response_t *r) {
    if (!r) return;
    free(r->body);
    r->body     = NULL;
    r->body_len = 0;
    r->body_cap = 0;
}
