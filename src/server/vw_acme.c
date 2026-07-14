/*
 * vw_acme.c — ACME v2 automatic TLS certificate renewal (RFC 8555).
 *
 * POSIX only.  Windows builds compile to stubs that return VW_OK.
 *
 * Uses mbedTLS directly (not vw_net) because ACME requires plain HTTP/1.1
 * over TLS without the VaporWault ALPN tag or custom framing.
 *
 * Private mbedTLS struct members are accessed via MBEDTLS_ALLOW_PRIVATE_ACCESS
 * for certificate validity-date inspection and EC key coordinate extraction.
 * This is the documented mbedTLS 3.x escape hatch for application code.
 */

/* Must precede mbedTLS includes to unlock struct member access. */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "vw_acme.h"
#include "vw_ddns.h"
#include "../core/vw_fs.h"
#include "../core/vw_crypto.h"

/* ── Platform guard ──────────────────────────────────────────────────────── */

#ifdef _WIN32

/* ── Windows stubs ───────────────────────────────────────────────────────── */

vw_err_t vw_acme_ctx_create(const vw_acme_cfg_t *cfg,
                              const char *cert_pem_path,
                              const char *key_pem_path,
                              vw_acme_ctx_t **out_ctx)
{
    (void)cfg; (void)cert_pem_path; (void)key_pem_path;
    *out_ctx = NULL;
    return VW_OK;
}
void     vw_acme_ctx_destroy(vw_acme_ctx_t *ctx)              { (void)ctx; }
vw_err_t vw_acme_renew_if_needed(vw_acme_ctx_t *ctx,
                                   vw_net_ctx_t *net_ctx)
{ (void)ctx; (void)net_ctx; return VW_OK; }
vw_err_t vw_acme_start(vw_acme_ctx_t *ctx, vw_net_ctx_t *net_ctx)
{ (void)ctx; (void)net_ctx; return VW_OK; }
void     vw_acme_stop(vw_acme_ctx_t *ctx)                     { (void)ctx; }

#else /* POSIX implementation */

#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/asn1write.h>

#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

/* Read a PEM file into a NUL-terminated heap buffer for mbedTLS parsing. */
static int acme_load_pem(const char *path, unsigned char **out, size_t *outlen)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0 || sz > 1024 * 1024) { fclose(f); return -1; }
    rewind(f);
    unsigned char *buf = (unsigned char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz)
    { free(buf); fclose(f); return -1; }
    fclose(f);
    buf[sz] = '\0';
    *out = buf; *outlen = (size_t)sz + 1;
    return 0;
}

/* ── Constants ───────────────────────────────────────────────────────────── */

#define RESP_BUF_SIZE    (65536u)
#define POLL_INTERVAL_S  5
#define POLL_MAX_TRIES   60      /* 5 min total */
#define ACME_LOG_TAG     "ACME"

/* Known system CA bundle paths (tried in order). */
static const char *CA_BUNDLE_PATHS[] = {
    "/etc/ssl/certs/ca-certificates.crt",   /* Debian / Ubuntu */
    "/etc/pki/tls/certs/ca-bundle.crt",     /* RHEL / CentOS   */
    "/etc/ssl/cert.pem",                     /* Alpine / macOS  */
    NULL,
};

/* ── Context ─────────────────────────────────────────────────────────────── */

struct vw_acme_ctx {
    vw_acme_cfg_t            cfg;
    char                     cert_pem_path[512];
    char                     key_pem_path[512];
    mbedtls_pk_context       account_key;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt         ca_certs;
    char                     dir_host[256];          /* host of directory URL */
    char                     url_new_nonce[256];
    char                     url_new_account[256];
    char                     url_new_order[256];
    char                     account_kid[512];       /* empty until registered */
    vw_net_ctx_t            *net_ctx;
    pthread_t                thread;
    pthread_mutex_t          lock;
    int                      shutdown;
    int                      thread_started;
};

/* ── Logging shim ────────────────────────────────────────────────────────── */

static void acme_log(const char *level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void acme_log(const char *level, const char *fmt, ...) {
    fprintf(stderr, "[%s] %s  ", level, ACME_LOG_TAG);
    va_list ap; va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}

/* ── Base64url ───────────────────────────────────────────────────────────── */

static void b64url_convert(char *s) {
    for (; *s; s++) {
        if      (*s == '+') *s = '-';
        else if (*s == '/') *s = '_';
        else if (*s == '=') { *s = '\0'; break; }
    }
}

/* Encode src[0..slen-1] into dst (null-terminated). dst must hold
 * at least ((slen + 2) / 3 * 4 + 1) bytes. Returns 0 on success. */
static int b64url_encode(const uint8_t *src, size_t slen,
                          char *dst, size_t dst_size)
{
    size_t olen;
    int ret = mbedtls_base64_encode((uint8_t *)dst, dst_size, &olen, src, slen);
    if (ret != 0) return ret;
    dst[olen] = '\0';
    b64url_convert(dst);
    return 0;
}

/* ── Minimal JSON string extractor ──────────────────────────────────────── */

/* Find "key":"value" in json.  Returns 0 and writes value into out.
 * The search is intentionally simple: works for well-formed ACME JSON
 * where values do not contain escaped quotes. */
static int json_str(const char *json, const char *key,
                     char *out, size_t out_size)
{
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    const char *e = p;
    while (*e && *e != '"') {
        if (*e == '\\') e++;
        e++;
    }
    size_t len = (size_t)(e - p);
    if (len >= out_size) return -1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

/* Find first occurrence of dns-01 challenge in an authorization JSON body.
 * Extracts its url and token.  Returns 0 on success. */
static int json_find_dns01(const char *json, char *url, size_t url_sz,
                             char *token, size_t tok_sz)
{
    const char *p = json;
    while ((p = strstr(p, "\"dns-01\"")) != NULL) {
        /* Step back to find the start of this challenge object. */
        const char *obj = p;
        while (obj > json && *obj != '{') obj--;
        /* Find the end of this challenge object. */
        int depth = 0;
        const char *end = obj;
        while (*end) {
            if (*end == '{') depth++;
            else if (*end == '}') { depth--; if (depth == 0) { end++; break; } }
            end++;
        }
        size_t len = (size_t)(end - obj);
        char tmp[2048];
        if (len >= sizeof(tmp)) { p++; continue; }
        memcpy(tmp, obj, len);
        tmp[len] = '\0';
        if (json_str(tmp, "url", url, url_sz) == 0 &&
            json_str(tmp, "token", token, tok_sz) == 0)
            return 0;
        p++;
    }
    return -1;
}

/* Find first occurrence of http-01 challenge in an authorization JSON body. */
static int json_find_http01(const char *json, char *url, size_t url_sz,
                              char *token, size_t tok_sz)
{
    const char *p = json;
    while ((p = strstr(p, "\"http-01\"")) != NULL) {
        const char *obj = p;
        while (obj > json && *obj != '{') obj--;
        int depth = 0;
        const char *end = obj;
        while (*end) {
            if (*end == '{') depth++;
            else if (*end == '}') { depth--; if (depth == 0) { end++; break; } }
            end++;
        }
        size_t len = (size_t)(end - obj);
        char tmp[2048];
        if (len >= sizeof(tmp)) { p++; continue; }
        memcpy(tmp, obj, len);
        tmp[len] = '\0';
        if (json_str(tmp, "url", url, url_sz) == 0 &&
            json_str(tmp, "token", token, tok_sz) == 0)
            return 0;
        p++;
    }
    return -1;
}

/* Extract the first URL string from a JSON array value like ["https://..."]. */
static int json_first_array_str(const char *json, const char *key,
                                  char *out, size_t out_size)
{
    char needle[256];
    snprintf(needle, sizeof(needle), "\"%s\":[\"", key);
    const char *p = strstr(json, needle);
    if (!p) return -1;
    p += strlen(needle);
    const char *e = p;
    while (*e && *e != '"') {
        if (*e == '\\') e++;
        e++;
    }
    size_t len = (size_t)(e - p);
    if (len >= out_size) return -1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

/* ── URL utilities ───────────────────────────────────────────────────────── */

static int parse_https_url(const char *url, char *host, size_t host_sz,
                             uint16_t *port, char *path, size_t path_sz)
{
    if (strncmp(url, "https://", 8) != 0) return -1;
    const char *p     = url + 8;
    const char *slash = strchr(p, '/');
    size_t      hlen  = slash ? (size_t)(slash - p) : strlen(p);

    /* Detect optional port in host part. */
    const char *colon = memchr(p, ':', hlen);
    size_t      nhlen = colon ? (size_t)(colon - p) : hlen;
    if (nhlen >= host_sz) return -1;
    memcpy(host, p, nhlen); host[nhlen] = '\0';

    *port = 443;
    if (colon) *port = (uint16_t)strtoul(colon + 1, NULL, 10);

    const char *pp = slash ? slash : "/";
    size_t plen = strlen(pp);
    if (plen >= path_sz) return -1;
    memcpy(path, pp, plen + 1);
    return 0;
}

/* Validate that url is on the same host as ctx->dir_host. */
static int url_same_host(vw_acme_ctx_t *ctx, const char *url)
{
    char host[256]; uint16_t port; char path[1024];
    if (parse_https_url(url, host, sizeof(host), &port, path, sizeof(path)) != 0)
        return 0;
    return strcmp(host, ctx->dir_host) == 0;
}

/* ── HTTPS client ────────────────────────────────────────────────────────── */

typedef struct {
    mbedtls_net_context  net;
    mbedtls_ssl_context  ssl;
    mbedtls_ssl_config   ssl_conf;
} acme_conn_t;

static int acme_connect(vw_acme_ctx_t *ctx, const char *host,
                         uint16_t port, acme_conn_t *c)
{
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

    mbedtls_net_init(&c->net);
    mbedtls_ssl_init(&c->ssl);
    mbedtls_ssl_config_init(&c->ssl_conf);

    int ret;
    if ((ret = mbedtls_net_connect(&c->net, host, portstr,
                                    MBEDTLS_NET_PROTO_TCP)) != 0)
        return ret;
    if ((ret = mbedtls_ssl_config_defaults(&c->ssl_conf,
                                            MBEDTLS_SSL_IS_CLIENT,
                                            MBEDTLS_SSL_TRANSPORT_STREAM,
                                            MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
        return ret;

    mbedtls_ssl_conf_authmode(&c->ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&c->ssl_conf, &ctx->ca_certs, NULL);
    mbedtls_ssl_conf_rng(&c->ssl_conf, mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
    /* Require TLS 1.2+ for ACME (external service, not VaporWault protocol). */
    mbedtls_ssl_conf_min_tls_version(&c->ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);

    if ((ret = mbedtls_ssl_setup(&c->ssl, &c->ssl_conf)) != 0) return ret;
    if ((ret = mbedtls_ssl_set_hostname(&c->ssl, host))   != 0) return ret;

    mbedtls_ssl_set_bio(&c->ssl, &c->net,
                         mbedtls_net_send, mbedtls_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&c->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            return ret;
    }
    return 0;
}

static void acme_disconnect(acme_conn_t *c) {
    mbedtls_ssl_close_notify(&c->ssl);
    mbedtls_net_free(&c->net);
    mbedtls_ssl_free(&c->ssl);
    mbedtls_ssl_config_free(&c->ssl_conf);
}

/*
 * Send an HTTP/1.1 request and read the response.
 * method: "GET", "POST", "HEAD"
 * body/content_type: used for POST; set body=NULL for GET/HEAD
 * Out parameters (all may be NULL if caller doesn't need them):
 *   resp_nonce    : Replay-Nonce header value
 *   resp_location : Location header value
 *   resp_body     : response body (NUL-terminated, truncated to body_sz-1)
 * Returns HTTP status code on success, or -1 on transport/parse error.
 */
static int acme_https(vw_acme_ctx_t *ctx,
                       const char *method, const char *url,
                       const char *content_type, const char *body,
                       char *resp_nonce,    size_t nonce_sz,
                       char *resp_location, size_t loc_sz,
                       char *resp_body,     size_t body_sz)
{
    char host[256]; uint16_t port; char path[1024];
    if (parse_https_url(url, host, sizeof(host), &port, path, sizeof(path)) != 0)
        return -1;

    acme_conn_t c;
    if (acme_connect(ctx, host, port, &c) != 0) return -1;

    /* Build request. */
    char req[RESP_BUF_SIZE];
    int  rlen;
    if (body) {
        rlen = snprintf(req, sizeof(req),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n"
            "%s",
            method, path, host,
            content_type ? content_type : "application/jose+json",
            strlen(body), body);
    } else {
        rlen = snprintf(req, sizeof(req),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            method, path, host);
    }
    if (rlen < 0 || (size_t)rlen >= sizeof(req)) { acme_disconnect(&c); return -1; }

    /* Send. */
    int ret;
    size_t written = 0;
    while (written < (size_t)rlen) {
        ret = mbedtls_ssl_write(&c.ssl,
                                 (const uint8_t *)req + written,
                                 (size_t)rlen - written);
        if (ret <= 0) { acme_disconnect(&c); return -1; }
        written += (size_t)ret;
    }

    /* Receive full response. */
    char *resp = malloc(RESP_BUF_SIZE);
    if (!resp) { acme_disconnect(&c); return -1; }

    size_t total = 0;
    while (total < RESP_BUF_SIZE - 1) {
        ret = mbedtls_ssl_read(&c.ssl, (uint8_t *)resp + total,
                                RESP_BUF_SIZE - 1 - total);
        if (ret == 0 || ret == MBEDTLS_ERR_SSL_CONN_EOF ||
            ret == MBEDTLS_ERR_NET_CONN_RESET)
            break;
        if (ret < 0) { free(resp); acme_disconnect(&c); return -1; }
        total += (size_t)ret;
    }
    resp[total] = '\0';
    acme_disconnect(&c);

    /* Parse status line: "HTTP/1.1 NNN ..." */
    int status = -1;
    if (total > 12 && strncmp(resp, "HTTP/", 5) == 0) {
        const char *sp = strchr(resp, ' ');
        if (sp) status = (int)strtol(sp + 1, NULL, 10);
    }

    /* Extract headers. */
    char *hdr_end = strstr(resp, "\r\n\r\n");
    if (!hdr_end) { free(resp); return status; }
    size_t hdr_len = (size_t)(hdr_end - resp);
    /* NUL-terminate the header block temporarily. */
    char saved = hdr_end[0]; hdr_end[0] = '\0';

    if (resp_nonce && nonce_sz > 0) {
        const char *h = strcasestr(resp, "\r\nReplay-Nonce:");
        if (h) {
            h += 15; /* skip "\r\nReplay-Nonce:" */
            while (*h == ' ') h++;
            const char *e = h; while (*e && *e != '\r' && *e != '\n') e++;
            size_t n = (size_t)(e - h);
            if (n < nonce_sz) { memcpy(resp_nonce, h, n); resp_nonce[n] = '\0'; }
        }
    }
    if (resp_location && loc_sz > 0) {
        const char *h = strcasestr(resp, "\r\nLocation:");
        if (h) {
            h += 11;
            while (*h == ' ') h++;
            const char *e = h; while (*e && *e != '\r' && *e != '\n') e++;
            size_t n = (size_t)(e - h);
            if (n < loc_sz) { memcpy(resp_location, h, n); resp_location[n] = '\0'; }
        }
    }

    /* Find Content-Length. */
    long content_length = -1;
    const char *cl = strcasestr(resp, "\r\nContent-Length:");
    if (cl) content_length = strtol(cl + 17, NULL, 10);

    hdr_end[0] = saved;

    /* Copy body. */
    const char *body_start = hdr_end + 4;
    size_t body_avail = total - hdr_len - 4;
    if (content_length >= 0 && (size_t)content_length < body_avail)
        body_avail = (size_t)content_length;
    if (resp_body && body_sz > 0) {
        size_t copy = body_avail < body_sz - 1 ? body_avail : body_sz - 1;
        memcpy(resp_body, body_start, copy);
        resp_body[copy] = '\0';
    }

    free(resp);
    return status;
}

/* GET request — convenience wrapper. */
static int acme_get(vw_acme_ctx_t *ctx, const char *url,
                     char *nonce, size_t nonce_sz,
                     char *body, size_t body_sz)
{
    return acme_https(ctx, "GET", url, NULL, NULL,
                      nonce, nonce_sz, NULL, 0, body, body_sz);
}

/* ── EC key management ───────────────────────────────────────────────────── */

/* Write key to path with mode 0600.
 *
 * SEC.07 [2026-07-12]: Fixed TOCTOU race.  The previous fopen("wb")+chmod()
 * pattern created the file with umask-dependent permissions (typically 0644)
 * and then restricted them — leaving a window during which the private key was
 * world-readable.  Using open(O_CREAT|O_WRONLY|O_TRUNC|O_NOFOLLOW, 0600)
 * sets the correct mode at creation time, atomically.  O_NOFOLLOW prevents a
 * symlink-race attacker from redirecting the write to an arbitrary target.
 *
 * Zeros the stack PEM buffer on all exit paths (private key material).
 * Returns 0 on success; on write/close failure, removes the partial file. */
static int write_key_pem(mbedtls_pk_context *key, const char *path) {
    uint8_t pem[4096];
    int ret = mbedtls_pk_write_key_pem(key, pem, sizeof(pem));
    if (ret != 0) { memset(pem, 0, sizeof(pem)); return ret; }
    size_t pem_len = strlen((char *)pem);

    /* Create with correct mode atomically — no umask race. */
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) { memset(pem, 0, sizeof(pem)); return -1; }

    size_t done = 0;
    int io_ok = 1;
    while (done < pem_len) {
        ssize_t n = write(fd, pem + done, pem_len - done);
        if (n <= 0) { io_ok = 0; break; }
        done += (size_t)n;
    }
    if (close(fd) != 0) io_ok = 0;
    memset(pem, 0, sizeof(pem)); /* zero private key material before returning */
    if (!io_ok) {
        remove(path); /* clean up partial write before caller can rename it */
        return -1;
    }
    return 0;
}

/* Generate fresh EC P-256 key. */
static int gen_ec_key(vw_acme_ctx_t *ctx, mbedtls_pk_context *key) {
    int ret;
    mbedtls_pk_init(key);
    ret = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) return ret;
    /* mbedtls_pk_ec_rw() is gated by MBEDTLS_ECP_LIGHT which isn't visible
     * with our custom config despite MBEDTLS_ECP_C being set.  Use the
     * deprecated mbedtls_pk_ec() accessor with a const cast — safe because
     * key is a non-const object we own and have just initialised above. */
    return mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                                (mbedtls_ecp_keypair *)mbedtls_pk_ec(key),
                                mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
}

/* Load account key from PEM, or generate one if the file doesn't exist. */
static int account_key_load_or_create(vw_acme_ctx_t *ctx) {
    if (vw_fs_exists(ctx->cfg.account_key)) {
        /* Load existing key from PEM file. */
        void  *buf = NULL; size_t len = 0;
        if (vw_fs_read_file(ctx->cfg.account_key, &buf, &len) != VW_OK)
            return -1;
        int ret = mbedtls_pk_parse_key(&ctx->account_key,
                                        (const uint8_t *)buf, len + 1,
                                        NULL, 0,
                                        mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
        vw_crypto_secure_zero(buf, len);
        free(buf);
        return ret;
    }

    /* Generate and persist a new EC P-256 key. */
    acme_log("INFO", "generating new ACME account key → %s",
             ctx->cfg.account_key);
    int ret = gen_ec_key(ctx, &ctx->account_key);
    if (ret != 0) return ret;
    if (write_key_pem(&ctx->account_key, ctx->cfg.account_key) != 0)
        return -1;
    acme_log("INFO", "ACME account key written");
    return 0;
}

/* Extract uncompressed EC point coordinates from a PK context.
 * x_out[32], y_out[32] are filled on success; returns 0. */
static int ec_pub_coords(mbedtls_pk_context *key,
                          uint8_t x_out[32], uint8_t y_out[32])
{
    uint8_t der[200];
    int len = mbedtls_pk_write_pubkey_der(key, der, sizeof(der));
    if (len < 65) return -1;
    /* DER is written at the END of der[]; the uncompressed point (04||X||Y)
     * is the last 65 bytes of the encoded SubjectPublicKeyInfo. */
    const uint8_t *pt = der + sizeof(der) - 65;
    if (*pt != 0x04) return -1;
    memcpy(x_out, pt + 1,  32);
    memcpy(y_out, pt + 33, 32);
    return 0;
}

/* ── JWK thumbprint ──────────────────────────────────────────────────────── */

/* Compute base64url(SHA-256(JWK_canonical)) for account key.
 * JWK_canonical for P-256: {"crv":"P-256","kty":"EC","x":"<b64u>","y":"<b64u>"}
 * Keys MUST be in lexicographic order for the thumbprint. */
static int jwk_thumbprint(vw_acme_ctx_t *ctx, char *out, size_t out_sz) {
    uint8_t x[32], y[32];
    if (ec_pub_coords(&ctx->account_key, x, y) != 0) return -1;

    char xb[64], yb[64];
    if (b64url_encode(x, 32, xb, sizeof(xb)) != 0) return -1;
    if (b64url_encode(y, 32, yb, sizeof(yb)) != 0) return -1;

    char jwk[512];
    snprintf(jwk, sizeof(jwk),
             "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"%s\",\"y\":\"%s\"}",
             xb, yb);

    uint8_t hash[32];
    if (mbedtls_sha256((const uint8_t *)jwk, strlen(jwk), hash, 0) != 0)
        return -1;
    return b64url_encode(hash, 32, out, out_sz);
}

/* ── JWS signing ─────────────────────────────────────────────────────────── */

/* Convert DER-encoded ECDSA signature to raw R||S (64 bytes for P-256). */
static int ecdsa_der_to_raw(const uint8_t *der, size_t der_len,
                              uint8_t raw[64])
{
    if (der_len < 8 || der[0] != 0x30) return -1;
    size_t off = 2; /* skip SEQUENCE header */
    if (der[off] != 0x02) return -1;
    size_t rlen = der[off + 1]; off += 2;
    const uint8_t *r = der + off; off += rlen;
    if (off >= der_len || der[off] != 0x02) return -1;
    size_t slen = der[off + 1]; off += 2;
    const uint8_t *s = der + off;
    if (rlen > 33 || slen > 33) return -1;

    memset(raw, 0, 64);
    /* R: right-justified into raw[0..31], strip leading 0x00 if present. */
    size_t rcopy = rlen > 32 ? 32 : rlen;
    memcpy(raw + 32 - rcopy, r + (rlen > 32 ? 1 : 0), rcopy);
    /* S: right-justified into raw[32..63]. */
    size_t scopy = slen > 32 ? 32 : slen;
    memcpy(raw + 64 - scopy, s + (slen > 32 ? 1 : 0), scopy);
    return 0;
}

/*
 * Build a JWS in flattened JSON form.
 *
 * If ctx->account_kid is non-empty, the "kid" header member is used.
 * Otherwise the full JWK is embedded (for newAccount).
 *
 * payload == NULL  →  POST-as-GET (empty-string payload in JWS).
 */
static int jws_build(vw_acme_ctx_t *ctx,
                      const char *url,
                      const char *nonce,
                      const char *payload,
                      char *out, size_t out_sz)
{
    /* Build protected header JSON. */
    char hdr_json[1024];
    if (ctx->account_kid[0] != '\0') {
        snprintf(hdr_json, sizeof(hdr_json),
                 "{\"alg\":\"ES256\",\"nonce\":\"%s\",\"url\":\"%s\","
                 "\"kid\":\"%s\"}",
                 nonce, url, ctx->account_kid);
    } else {
        uint8_t x[32], y[32];
        if (ec_pub_coords(&ctx->account_key, x, y) != 0) return -1;
        char xb[64], yb[64];
        b64url_encode(x, 32, xb, sizeof(xb));
        b64url_encode(y, 32, yb, sizeof(yb));
        snprintf(hdr_json, sizeof(hdr_json),
                 "{\"alg\":\"ES256\",\"nonce\":\"%s\",\"url\":\"%s\","
                 "\"jwk\":{\"crv\":\"P-256\",\"kty\":\"EC\","
                 "\"x\":\"%s\",\"y\":\"%s\"}}",
                 nonce, url, xb, yb);
    }

    char hdr_b64[1024], pay_b64[RESP_BUF_SIZE / 4];
    if (b64url_encode((const uint8_t *)hdr_json, strlen(hdr_json),
                      hdr_b64, sizeof(hdr_b64)) != 0) return -1;

    /* POST-as-GET: empty string payload; ordinary POST: base64url(payload). */
    if (!payload || !*payload) {
        pay_b64[0] = '\0';
    } else {
        if (b64url_encode((const uint8_t *)payload, strlen(payload),
                          pay_b64, sizeof(pay_b64)) != 0) return -1;
    }

    /* Signing input: base64url(header) || "." || base64url(payload) */
    char sign_input[RESP_BUF_SIZE / 2];
    snprintf(sign_input, sizeof(sign_input), "%s.%s", hdr_b64, pay_b64);

    uint8_t hash[32];
    if (mbedtls_sha256((const uint8_t *)sign_input, strlen(sign_input),
                       hash, 0) != 0) return -1;

    uint8_t sig_der[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
    size_t  sig_len = 0;
    if (mbedtls_pk_sign(&ctx->account_key, MBEDTLS_MD_SHA256,
                         hash, sizeof(hash),
                         sig_der, sizeof(sig_der), &sig_len,
                         mbedtls_ctr_drbg_random, &ctx->ctr_drbg) != 0)
        return -1;

    uint8_t sig_raw[64];
    if (ecdsa_der_to_raw(sig_der, sig_len, sig_raw) != 0) return -1;

    char sig_b64[128];
    if (b64url_encode(sig_raw, 64, sig_b64, sizeof(sig_b64)) != 0) return -1;

    int n = snprintf(out, out_sz,
                     "{\"protected\":\"%s\",\"payload\":\"%s\","
                     "\"signature\":\"%s\"}",
                     hdr_b64, pay_b64, sig_b64);
    return (n > 0 && (size_t)n < out_sz) ? 0 : -1;
}

/* Get a fresh nonce from ACME and sign a JWS POST.
 * Returns HTTP status or -1 on error. */
static int acme_jws_post(vw_acme_ctx_t *ctx,
                          const char *url, const char *payload_json,
                          char *resp_nonce, size_t nonce_sz,
                          char *resp_location, size_t loc_sz,
                          char *resp_body, size_t body_sz)
{
    /* Fetch a fresh nonce. */
    char nonce[256] = "";
    acme_get(ctx, ctx->url_new_nonce, nonce, sizeof(nonce), NULL, 0);

    char jws[RESP_BUF_SIZE / 2];
    if (jws_build(ctx, url, nonce, payload_json, jws, sizeof(jws)) != 0)
        return -1;

    return acme_https(ctx, "POST", url,
                      "application/jose+json", jws,
                      resp_nonce, nonce_sz,
                      resp_location, loc_sz,
                      resp_body, body_sz);
}

/* ── ACME protocol ───────────────────────────────────────────────────────── */

/* Fetch and cache the ACME directory URLs. */
static vw_err_t acme_get_directory(vw_acme_ctx_t *ctx) {
    char body[RESP_BUF_SIZE];
    int status = acme_get(ctx, ctx->cfg.directory, NULL, 0, body, sizeof(body));
    if (status != 200) {
        acme_log("ERROR", "directory fetch failed (status %d)", status);
        return VW_ERR_IO;
    }
    if (json_str(body, "newNonce",   ctx->url_new_nonce,   sizeof(ctx->url_new_nonce))   != 0 ||
        json_str(body, "newAccount", ctx->url_new_account, sizeof(ctx->url_new_account)) != 0 ||
        json_str(body, "newOrder",   ctx->url_new_order,   sizeof(ctx->url_new_order))   != 0) {
        acme_log("ERROR", "directory JSON missing required URLs");
        return VW_ERR_PROTO_INVALID;
    }
    /* Validate directory URLs are on the expected host (SEC.07). */
    if (!url_same_host(ctx, ctx->url_new_nonce)   ||
        !url_same_host(ctx, ctx->url_new_account) ||
        !url_same_host(ctx, ctx->url_new_order)) {
        acme_log("ERROR", "directory URLs point to unexpected host");
        return VW_ERR_PROTO_INVALID;
    }
    return VW_OK;
}

/* Register or find the existing ACME account.
 * On success, ctx->account_kid is populated. */
static vw_err_t acme_ensure_account(vw_acme_ctx_t *ctx) {
    char payload[512];
    if (ctx->cfg.contact[0] != '\0') {
        snprintf(payload, sizeof(payload),
                 "{\"termsOfServiceAgreed\":true,"
                 "\"contact\":[\"mailto:%s\"]}",
                 ctx->cfg.contact);
    } else {
        snprintf(payload, sizeof(payload),
                 "{\"termsOfServiceAgreed\":true}");
    }

    char location[512] = "";
    char body[RESP_BUF_SIZE];
    char nonce[256] = "";
    int status = acme_jws_post(ctx, ctx->url_new_account, payload,
                                nonce, sizeof(nonce),
                                location, sizeof(location),
                                body, sizeof(body));
    if (status != 200 && status != 201) {
        acme_log("ERROR", "account registration failed (status %d): %.200s",
                 status, body);
        return VW_ERR_IO;
    }
    if (location[0] == '\0') {
        acme_log("ERROR", "account response missing Location header");
        return VW_ERR_IO;
    }
    if (!url_same_host(ctx, location)) {
        acme_log("ERROR", "account KID URL from unexpected host");
        return VW_ERR_PROTO_INVALID;
    }
    snprintf(ctx->account_kid, sizeof(ctx->account_kid), "%s", location);
    return VW_OK;
}

/* Create a new order for ctx->cfg.domain. Returns order URL in order_url. */
static vw_err_t acme_create_order(vw_acme_ctx_t *ctx,
                                   char *order_url, size_t url_sz,
                                   char *finalize_url, size_t fin_sz,
                                   char *authz_url, size_t authz_sz)
{
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"%s\"}]}",
             ctx->cfg.domain);

    char body[RESP_BUF_SIZE], location[512] = "", nonce[256] = "";
    int status = acme_jws_post(ctx, ctx->url_new_order, payload,
                                nonce, sizeof(nonce),
                                location, sizeof(location),
                                body, sizeof(body));
    if (status != 201) {
        acme_log("ERROR", "newOrder failed (status %d): %.200s", status, body);
        return VW_ERR_IO;
    }
    if (!url_same_host(ctx, location)) {
        acme_log("ERROR", "order URL from unexpected host");
        return VW_ERR_PROTO_INVALID;
    }
    snprintf(order_url, url_sz, "%s", location);
    if (json_str(body, "finalize", finalize_url, fin_sz) != 0 ||
        !url_same_host(ctx, finalize_url)) {
        acme_log("ERROR", "order body missing/invalid finalize URL");
        return VW_ERR_IO;
    }
    if (json_first_array_str(body, "authorizations", authz_url, authz_sz) != 0 ||
        !url_same_host(ctx, authz_url)) {
        acme_log("ERROR", "order body missing/invalid authorization URL");
        return VW_ERR_IO;
    }
    return VW_OK;
}

/* Compute keyAuthorization: token + "." + jwk_thumbprint. */
static int keyauth(vw_acme_ctx_t *ctx, const char *token,
                    char *out, size_t out_sz)
{
    char thumb[64];
    if (jwk_thumbprint(ctx, thumb, sizeof(thumb)) != 0) return -1;
    snprintf(out, out_sz, "%s.%s", token, thumb);
    return 0;
}

/* DNS TXT value = base64url(sha256(keyAuth)). */
static int dns_txt_value(vw_acme_ctx_t *ctx, const char *token,
                           char *out, size_t out_sz)
{
    char kauth[512];
    if (keyauth(ctx, token, kauth, sizeof(kauth)) != 0) return -1;
    uint8_t hash[32];
    if (mbedtls_sha256((const uint8_t *)kauth, strlen(kauth), hash, 0) != 0)
        return -1;
    return b64url_encode(hash, 32, out, out_sz);
}

/* Poll an ACME URL (POST-as-GET) until status == "valid" or "invalid".
 * Returns VW_OK on "valid", VW_ERR_IO on "invalid" or timeout. */
static vw_err_t acme_poll_status(vw_acme_ctx_t *ctx, const char *url,
                                   const char *waiting_for)
{
    char body[RESP_BUF_SIZE], nonce[256];
    for (int attempt = 0; attempt < POLL_MAX_TRIES; attempt++) {
        sleep(POLL_INTERVAL_S);
        int status = acme_jws_post(ctx, url, NULL,
                                    nonce, sizeof(nonce),
                                    NULL, 0, body, sizeof(body));
        if (status < 0) return VW_ERR_IO;
        char st[64] = "";
        json_str(body, "status", st, sizeof(st));
        acme_log("DEBUG", "polling %s → status=%s", waiting_for, st);
        if (strcmp(st, "valid") == 0) return VW_OK;
        if (strcmp(st, "invalid") == 0) {
            acme_log("ERROR", "ACME %s became invalid: %.400s",
                     waiting_for, body);
            return VW_ERR_IO;
        }
    }
    acme_log("ERROR", "ACME %s timed out after %d polls", waiting_for,
             POLL_MAX_TRIES);
    return VW_ERR_TIMEOUT;
}

/* ── HTTP-01 challenge provisioning ──────────────────────────────────────── */

/* Validate that the token from ACME is safe to use as a filename.
 * ACME tokens are base64url strings [A-Za-z0-9_-]+.
 * Returns 0 if safe, -1 if not. */
static int token_safe(const char *token) {
    if (!token || !*token) return -1;
    for (const char *p = token; *p; p++) {
        if (!isalnum((unsigned char)*p) && *p != '-' && *p != '_')
            return -1;
    }
    return 0;
}

static vw_err_t http01_write(vw_acme_ctx_t *ctx,
                               const char *http_root,
                               const char *token,
                               const char *kauth,
                               char *file_path, size_t path_sz)
{
    (void)ctx;
    if (token_safe(token) != 0) {
        acme_log("ERROR", "HTTP-01 token contains unsafe characters");
        return VW_ERR_INVALID_ARG;
    }
    /* Build path: <http_root>/.well-known/acme-challenge/<token> */
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/.well-known/acme-challenge", http_root);
    if (vw_fs_ensure_dir(dir) != VW_OK) return VW_ERR_IO;

    {
        size_t dlen = strlen(dir), tlen = strlen(token);
        if (dlen + 1 + tlen + 1 > path_sz) return VW_ERR_INVALID_ARG;
        memcpy(file_path, dir, dlen);
        file_path[dlen] = '/';
        memcpy(file_path + dlen + 1, token, tlen + 1);
    }

    /* Verify the resulting path is strictly under http_root (SEC.07). */
    if (strncmp(file_path, http_root, strlen(http_root)) != 0) {
        acme_log("ERROR", "HTTP-01 path traversal detected");
        return VW_ERR_PERMISSION;
    }

    return vw_fs_atomic_write(file_path, kauth, strlen(kauth));
}

/* ── CSR generation ──────────────────────────────────────────────────────── */

static vw_err_t generate_csr(vw_acme_ctx_t *ctx,
                               mbedtls_pk_context *domain_key,
                               const char *domain,
                               char *csr_b64, size_t csr_sz)
{
    mbedtls_x509write_csr req;
    mbedtls_x509write_csr_init(&req);
    mbedtls_x509write_csr_set_md_alg(&req, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key(&req, domain_key);

    char subject[320];
    snprintf(subject, sizeof(subject), "CN=%s", domain);
    int ret = mbedtls_x509write_csr_set_subject_name(&req, subject);
    if (ret != 0) { mbedtls_x509write_csr_free(&req); return VW_ERR_IO; }

    /* Add SAN extension: SEQUENCE { [2] IA5String <domain> }
     * OID 2.5.29.17 raw bytes: 55 1D 11 */
    size_t dlen = strlen(domain);
    if (dlen > 253) { mbedtls_x509write_csr_free(&req); return VW_ERR_INVALID_ARG; }
    uint8_t san_der[260];
    san_der[0] = 0x30;           /* SEQUENCE */
    san_der[1] = (uint8_t)(2 + dlen);
    san_der[2] = 0x82;           /* dNSName [2] IMPLICIT */
    san_der[3] = (uint8_t)dlen;
    memcpy(san_der + 4, domain, dlen);
    size_t san_len = 4 + dlen;
    const uint8_t san_oid[] = {0x55, 0x1D, 0x11};
    ret = mbedtls_x509write_csr_set_extension(
              &req, (const char *)san_oid, sizeof(san_oid),
              0 /* not critical */, san_der, san_len);
    if (ret != 0) { mbedtls_x509write_csr_free(&req); return VW_ERR_IO; }

    uint8_t csr_der[2048];
    ret = mbedtls_x509write_csr_der(&req, csr_der, sizeof(csr_der),
                                     mbedtls_ctr_drbg_random, &ctx->ctr_drbg);
    mbedtls_x509write_csr_free(&req);
    if (ret < 0) return VW_ERR_IO;

    /* mbedtls writes DER at the END of the buffer; ret = length. */
    const uint8_t *der_start = csr_der + sizeof(csr_der) - (size_t)ret;
    return b64url_encode(der_start, (size_t)ret, csr_b64, csr_sz) == 0
           ? VW_OK : VW_ERR_IO;
}

/* ── Certificate expiry check ────────────────────────────────────────────── */

/* Returns number of days until the cert expires, -1 on error, 0 if expired. */
static int cert_days_remaining(const char *cert_pem_path) {
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    {
        unsigned char *buf = NULL; size_t blen = 0;
        int ret = (acme_load_pem(cert_pem_path, &buf, &blen) == 0)
                  ? mbedtls_x509_crt_parse(&crt, buf, blen) : -1;
        free(buf);
        if (ret != 0) { mbedtls_x509_crt_free(&crt); return -1; }
    }
    struct tm exp_tm;
    memset(&exp_tm, 0, sizeof(exp_tm));
    exp_tm.tm_year = crt.valid_to.year - 1900;
    exp_tm.tm_mon  = crt.valid_to.mon  - 1;
    exp_tm.tm_mday = crt.valid_to.day;
    exp_tm.tm_hour = crt.valid_to.hour;
    exp_tm.tm_min  = crt.valid_to.min;
    exp_tm.tm_sec  = crt.valid_to.sec;
    mbedtls_x509_crt_free(&crt);

    time_t exp = timegm(&exp_tm);
    time_t now = time(NULL);
    if (exp <= now) return 0;
    return (int)((exp - now) / 86400);
}

/* ── Full renewal ────────────────────────────────────────────────────────── */

vw_err_t vw_acme_renew_if_needed(vw_acme_ctx_t *ctx, vw_net_ctx_t *net_ctx)
{
    if (!ctx) return VW_OK;

    /* Check days remaining. */
    int days = cert_days_remaining(ctx->cert_pem_path);
    if (days < 0) {
        acme_log("INFO", "cert not found or unreadable — attempting initial issuance");
    } else if (days > (int)ctx->cfg.renew_days) {
        acme_log("DEBUG", "cert valid for %d days — no renewal needed", days);
        return VW_OK;
    } else {
        acme_log("INFO", "cert expires in %d day(s) — initiating renewal", days);
    }

    /* Fetch ACME directory. */
    vw_err_t rc = acme_get_directory(ctx);
    if (rc != VW_OK) return rc;

    /* Warn loudly in staging mode. */
    if (strstr(ctx->cfg.directory, "staging") != NULL)
        acme_log("WARN", "ACME STAGING MODE — certificate will NOT be trusted");

    /* Register / find account. */
    rc = acme_ensure_account(ctx);
    if (rc != VW_OK) return rc;

    /* Create order. */
    char order_url[512], finalize_url[512], authz_url[512];
    rc = acme_create_order(ctx, order_url, sizeof(order_url),
                            finalize_url, sizeof(finalize_url),
                            authz_url, sizeof(authz_url));
    if (rc != VW_OK) return rc;

    /* Fetch authorization. */
    char authz_body[RESP_BUF_SIZE], nonce[256];
    int status = acme_jws_post(ctx, authz_url, NULL,
                                nonce, sizeof(nonce),
                                NULL, 0, authz_body, sizeof(authz_body));
    if (status < 200 || status >= 300) {
        acme_log("ERROR", "authorization fetch failed (status %d)", status);
        return VW_ERR_IO;
    }

    /* Extract challenge. Prefer DNS-01 if hook is configured. */
    char chal_url[512] = "", token[512] = "";
    int  used_dns01 = 0, used_http01 = 0;
    char http_file_path[1024] = "";

    if (ctx->cfg.dns_hook[0] != '\0' &&
        json_find_dns01(authz_body, chal_url, sizeof(chal_url),
                         token, sizeof(token)) == 0 &&
        url_same_host(ctx, chal_url))
    {
        char dns_val[128];
        if (dns_txt_value(ctx, token, dns_val, sizeof(dns_val)) != 0)
            return VW_ERR_IO;

        char acme_domain[320];
        snprintf(acme_domain, sizeof(acme_domain),
                 "_acme-challenge.%s", ctx->cfg.domain);
        rc = vw_ddns_set(ctx->cfg.dns_hook, acme_domain, dns_val);
        if (rc != VW_OK) {
            acme_log("ERROR", "DNS hook set failed");
            return rc;
        }
        used_dns01 = 1;
        /* Hook is responsible for propagation delay. */

    } else if (ctx->cfg.http_root[0] != '\0' &&
               json_find_http01(authz_body, chal_url, sizeof(chal_url),
                                 token, sizeof(token)) == 0 &&
               url_same_host(ctx, chal_url))
    {
        char kauth[512];
        if (keyauth(ctx, token, kauth, sizeof(kauth)) != 0) return VW_ERR_IO;
        rc = http01_write(ctx, ctx->cfg.http_root, token, kauth,
                           http_file_path, sizeof(http_file_path));
        if (rc != VW_OK) return rc;
        used_http01 = 1;
    } else {
        acme_log("ERROR",
                 "no usable challenge: configure acme_dns_hook or acme_http_root");
        return VW_ERR_INVALID_ARG;
    }

    /* Trigger challenge validation (empty-JSON payload, not POST-as-GET). */
    char resp_body[RESP_BUF_SIZE];
    status = acme_jws_post(ctx, chal_url, "{}",
                            nonce, sizeof(nonce),
                            NULL, 0, resp_body, sizeof(resp_body));
    if (status < 200 || status >= 300) {
        acme_log("ERROR", "challenge trigger failed (status %d): %.200s",
                 status, resp_body);
        rc = VW_ERR_IO;
        goto cleanup_challenge;
    }

    /* Poll for authorization to become valid. */
    rc = acme_poll_status(ctx, authz_url, "authorization");

cleanup_challenge:
    if (used_dns01) {
        char acme_domain[320];
        snprintf(acme_domain, sizeof(acme_domain),
                 "_acme-challenge.%s", ctx->cfg.domain);
        vw_ddns_clear(ctx->cfg.dns_hook, acme_domain);
    }
    if (used_http01 && http_file_path[0] != '\0') {
        vw_fs_delete(http_file_path);
    }
    if (rc != VW_OK) return rc;

    /* Generate fresh domain key + CSR. */
    mbedtls_pk_context domain_key;
    mbedtls_pk_init(&domain_key);
    if (gen_ec_key(ctx, &domain_key) != 0) {
        mbedtls_pk_free(&domain_key);
        return VW_ERR_IO;
    }

    char csr_b64[4096];
    rc = generate_csr(ctx, &domain_key, ctx->cfg.domain,
                      csr_b64, sizeof(csr_b64));
    if (rc != VW_OK) {
        mbedtls_pk_free(&domain_key);
        return rc;
    }

    /* Finalize order with CSR. */
    char finalize_payload[4096 + 64];
    snprintf(finalize_payload, sizeof(finalize_payload),
             "{\"csr\":\"%s\"}", csr_b64);

    status = acme_jws_post(ctx, finalize_url, finalize_payload,
                            nonce, sizeof(nonce),
                            NULL, 0, resp_body, sizeof(resp_body));
    if (status < 200 || status >= 300) {
        acme_log("ERROR", "finalize failed (status %d): %.200s",
                 status, resp_body);
        mbedtls_pk_free(&domain_key);
        return VW_ERR_IO;
    }

    /* Poll order for "valid" status and get certificate URL. */
    rc = acme_poll_status(ctx, order_url, "order");
    if (rc != VW_OK) {
        mbedtls_pk_free(&domain_key);
        return rc;
    }

    /* Fetch finalized order to get certificate URL. */
    status = acme_jws_post(ctx, order_url, NULL,
                            nonce, sizeof(nonce),
                            NULL, 0, resp_body, sizeof(resp_body));
    char cert_url[512] = "";
    if (status < 200 || status >= 300 ||
        json_str(resp_body, "certificate", cert_url, sizeof(cert_url)) != 0 ||
        !url_same_host(ctx, cert_url)) {
        acme_log("ERROR", "cannot extract certificate URL from order");
        mbedtls_pk_free(&domain_key);
        return VW_ERR_IO;
    }

    /* Download certificate chain (POST-as-GET). */
    status = acme_jws_post(ctx, cert_url, NULL,
                            nonce, sizeof(nonce),
                            NULL, 0, resp_body, sizeof(resp_body));
    if (status != 200) {
        acme_log("ERROR", "cert download failed (status %d)", status);
        mbedtls_pk_free(&domain_key);
        return VW_ERR_IO;
    }

    /* Write new key (to .new path first, then rename). */
    char key_new[516], cert_new[516];
    snprintf(key_new,  sizeof(key_new),  "%s.new", ctx->key_pem_path);
    snprintf(cert_new, sizeof(cert_new), "%s.new", ctx->cert_pem_path);

    if (write_key_pem(&domain_key, key_new) != 0) {
        acme_log("ERROR", "cannot write new domain key to %s", key_new);
        mbedtls_pk_free(&domain_key);
        return VW_ERR_IO;
    }
    mbedtls_pk_free(&domain_key);

    /* Write cert chain. */
    rc = vw_fs_atomic_write(cert_new, resp_body, strlen(resp_body));
    if (rc != VW_OK) {
        acme_log("ERROR", "cannot write new cert to %s", cert_new);
        vw_fs_delete(key_new);
        return rc;
    }

    /* Promote new key then new cert. If the cert rename fails, roll back the
     * key so we don't end up with a new key paired with an old certificate. */
    if (vw_fs_rename(key_new, ctx->key_pem_path) != VW_OK) {
        acme_log("ERROR", "cannot rename new key file to %s", ctx->key_pem_path);
        return VW_ERR_IO;
    }
    if (vw_fs_rename(cert_new, ctx->cert_pem_path) != VW_OK) {
        acme_log("ERROR", "cannot rename new cert file to %s; rolling back key",
                 ctx->cert_pem_path);
        /* Best-effort rollback — if this also fails, the server needs a manual fix. */
        vw_fs_rename(ctx->key_pem_path, key_new);
        return VW_ERR_IO;
    }

    acme_log("INFO", "certificate renewed successfully for %s", ctx->cfg.domain);

    /* Hot-swap certificate in the live TLS context. */
    vw_net_ctx_t *nc = net_ctx ? net_ctx : ctx->net_ctx;
    if (nc) {
        if (vw_net_ctx_reload_cert(nc, ctx->cert_pem_path,
                                    ctx->key_pem_path) == VW_OK)
            acme_log("INFO", "TLS certificate hot-swapped");
        else
            acme_log("WARN", "cert reload failed — restart server to apply new cert");
    }
    return VW_OK;
}

/* ── Background renewal thread ───────────────────────────────────────────── */

#define RENEW_CHECK_INTERVAL_S  (12 * 3600)

static void *acme_thread_fn(void *arg) {
    vw_acme_ctx_t *ctx = arg;

    /* First check immediately on startup. */
    vw_acme_renew_if_needed(ctx, NULL);

    int elapsed = 0;
    while (1) {
        sleep(1);
        pthread_mutex_lock(&ctx->lock);
        int stop = ctx->shutdown;
        pthread_mutex_unlock(&ctx->lock);
        if (stop) break;
        if (++elapsed >= RENEW_CHECK_INTERVAL_S) {
            elapsed = 0;
            vw_acme_renew_if_needed(ctx, NULL);
        }
    }
    return NULL;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

vw_err_t vw_acme_ctx_create(const vw_acme_cfg_t *cfg,
                              const char *cert_pem_path,
                              const char *key_pem_path,
                              vw_acme_ctx_t **out_ctx)
{
    *out_ctx = NULL;
    if (!cfg || !cfg->enabled) return VW_OK;

    if (!cfg->domain[0]) {
        acme_log("ERROR", "acme_domain must be set");
        return VW_ERR_INVALID_ARG;
    }

    vw_acme_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return VW_ERR_OOM;

    ctx->cfg = *cfg;
    if (!ctx->cfg.renew_days) ctx->cfg.renew_days = VW_ACME_DEFAULT_RENEW_DAYS;
    snprintf(ctx->cert_pem_path, sizeof(ctx->cert_pem_path), "%s", cert_pem_path);
    snprintf(ctx->key_pem_path,  sizeof(ctx->key_pem_path),  "%s", key_pem_path);

    /* Extract directory host for URL validation. */
    uint16_t dport; char dpath[1024];
    if (parse_https_url(cfg->directory, ctx->dir_host, sizeof(ctx->dir_host),
                         &dport, dpath, sizeof(dpath)) != 0) {
        acme_log("ERROR", "invalid acme_directory URL: %s", cfg->directory);
        free(ctx); return VW_ERR_INVALID_ARG;
    }

    /* Initialise RNG. */
    mbedtls_pk_init(&ctx->account_key);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    const char *pers = "vw_acme";
    if (mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func,
                                &ctx->entropy,
                                (const uint8_t *)pers, strlen(pers)) != 0) {
        acme_log("ERROR", "ctr_drbg seed failed");
        goto fail;
    }

    /* Load system CA bundle. */
    mbedtls_x509_crt_init(&ctx->ca_certs);
    int ca_loaded = 0;
    for (int i = 0; CA_BUNDLE_PATHS[i]; i++) {
        unsigned char *ca_buf = NULL; size_t ca_len = 0;
        int ca_ret = (acme_load_pem(CA_BUNDLE_PATHS[i], &ca_buf, &ca_len) == 0)
                     ? mbedtls_x509_crt_parse(&ctx->ca_certs, ca_buf, ca_len) : -1;
        free(ca_buf);
        if (ca_ret == 0) {
            acme_log("INFO", "CA bundle: %s", CA_BUNDLE_PATHS[i]);
            ca_loaded = 1;
            break;
        }
    }
    if (!ca_loaded) {
        acme_log("ERROR", "no system CA bundle found — ACME disabled");
        goto fail;
    }

    /* Load or generate account key. */
    if (account_key_load_or_create(ctx) != 0) {
        acme_log("ERROR", "account key load/generate failed");
        goto fail;
    }

    pthread_mutex_init(&ctx->lock, NULL);
    *out_ctx = ctx;
    return VW_OK;

fail:
    mbedtls_pk_free(&ctx->account_key);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);
    mbedtls_x509_crt_free(&ctx->ca_certs);
    free(ctx);
    return VW_ERR_IO;
}

void vw_acme_ctx_destroy(vw_acme_ctx_t *ctx) {
    if (!ctx) return;
    vw_acme_stop(ctx);
    mbedtls_pk_free(&ctx->account_key);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_entropy_free(&ctx->entropy);
    mbedtls_x509_crt_free(&ctx->ca_certs);
    pthread_mutex_destroy(&ctx->lock);
    free(ctx);
}

vw_err_t vw_acme_start(vw_acme_ctx_t *ctx, vw_net_ctx_t *net_ctx) {
    if (!ctx) return VW_OK;
    ctx->net_ctx = net_ctx;
    ctx->shutdown = 0;
    if (pthread_create(&ctx->thread, NULL, acme_thread_fn, ctx) != 0) {
        acme_log("ERROR", "failed to start ACME renewal thread");
        return VW_ERR_IO;
    }
    ctx->thread_started = 1;
    return VW_OK;
}

void vw_acme_stop(vw_acme_ctx_t *ctx) {
    if (!ctx || !ctx->thread_started) return;
    pthread_mutex_lock(&ctx->lock);
    ctx->shutdown = 1;
    pthread_mutex_unlock(&ctx->lock);
    pthread_join(ctx->thread, NULL);
    ctx->thread_started = 0;
}

#endif /* _WIN32 */
