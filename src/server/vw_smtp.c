/*
 * vw_smtp.c — Minimal SMTP relay client for VaporWault.
 *
 * Supports plaintext (NONE), STARTTLS, and SMTPS (implicit TLS).
 * Uses mbedTLS for TLS. Thread-safe: each call opens its own connection.
 *
 * RFC references:
 *   RFC 5321 — SMTP
 *   RFC 3207 — STARTTLS
 *   RFC 4616 — AUTH PLAIN
 *   RFC 4648 — Base64
 */

#include "vw_smtp.h"

#include "../core/vw_crypto.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ── Platform-specific socket headers ───────────────────────────────────── */
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
   typedef SOCKET smtp_sock_t;
#  define SMTP_INVALID_SOCK  INVALID_SOCKET
#  define smtp_close(s)      closesocket(s)
#  define smtp_errno()       WSAGetLastError()
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netdb.h>
#  include <unistd.h>
#  include <errno.h>
   typedef int smtp_sock_t;
#  define SMTP_INVALID_SOCK  (-1)
#  define smtp_close(s)      close(s)
#  define smtp_errno()       errno
#endif

/* ── mbedTLS headers ────────────────────────────────────────────────────── */
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"

/* ── Platform atomic shim (MSVC C mode lacks stdatomic) ─────────────────── */
#ifdef _WIN32
static volatile LONG s_smtp_msgid_seq = 0;
#define smtp_msgid_next() ((uint32_t)InterlockedIncrement(&s_smtp_msgid_seq) - 1u)
#else
#include <stdatomic.h>
static _Atomic uint32_t s_smtp_msgid_seq = 0;
#define smtp_msgid_next() atomic_fetch_add_explicit(&s_smtp_msgid_seq, 1u, memory_order_relaxed)
#endif

/* ── PEM file loader (no MBEDTLS_FS_IO required) ────────────────────────── */
static int smtp_load_pem(const char *path, unsigned char **out, size_t *outlen)
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

/* ── Constants ──────────────────────────────────────────────────────────── */
#define SMTP_LINE_BUF    2048
#define SMTP_CMD_BUF     1024
#define SMTP_HOSTNAME_MAX 256
#define SMTP_HDR_BUF     4096   /* enlarged to fit Date + Message-ID headers */

/* ── Module state ───────────────────────────────────────────────────────── */

/* s_smtp_msgid_seq (and smtp_msgid_next macro) defined above. */

/* ── Private helpers ─────────────────────────────────────────────────────── */

/* Write a Message-ID value (with angle brackets) into out[0..out_sz-1].
 * Uses 8 random bytes from vw_crypto_random; falls back to a counter if
 * the RNG is unavailable (e.g. not yet seeded at early startup). */
static void make_message_id(char *out, size_t out_sz,
                             time_t now, const char *host)
{
    static const char hx[] = "0123456789abcdef";
    uint8_t rb[8];
    char rand_hex[17];

    if (vw_crypto_random(rb, sizeof(rb)) == VW_OK) {
        for (int i = 0; i < 8; i++) {
            rand_hex[i * 2]     = hx[(rb[i] >> 4) & 0xf];
            rand_hex[i * 2 + 1] = hx[ rb[i]       & 0xf];
        }
        rand_hex[16] = '\0';
    } else {
        uint32_t seq = smtp_msgid_next();
        (void)snprintf(rand_hex, sizeof(rand_hex), "ctr%013x", (unsigned)seq);
    }

    (void)snprintf(out, out_sz, "<%016llx.%s@%s>",
                   (unsigned long long)(uint64_t)now, rand_hex, host);
}

/* ── Connection abstraction ─────────────────────────────────────────────── */

typedef struct {
    smtp_sock_t          fd;
    mbedtls_ssl_context *ssl;   /* NULL if plain TCP */
} smtp_conn_t;

/* ── Forward declarations ───────────────────────────────────────────────── */

static void set_err(char *buf, size_t sz, const char *fmt, ...);
static int  smtp_conn_read_line(smtp_conn_t *c, char *buf, size_t buf_size);
static int  smtp_conn_write(smtp_conn_t *c, const char *data, size_t len);
static int  smtp_expect(smtp_conn_t *c, int expected_code,
                        char *err_buf, size_t err_sz);
static size_t base64_encode(const uint8_t *src, size_t src_len,
                             char *dst, size_t dst_size);
static vw_err_t smtp_tls_upgrade(smtp_conn_t *c,
                                  mbedtls_ssl_context *ssl,
                                  mbedtls_ssl_config  *conf,
                                  mbedtls_entropy_context *entropy,
                                  mbedtls_ctr_drbg_context *ctr_drbg,
                                  mbedtls_net_context *net,
                                  mbedtls_x509_crt *cacert,
                                  const char *host,
                                  int verify_cert,
                                  const char *ca_cert_path,
                                  char *err_buf, size_t err_sz);
static vw_err_t smtp_do_auth(smtp_conn_t *c,
                              const char *username, const char *password,
                              char *err_buf, size_t err_sz);
static vw_err_t smtp_send_message(smtp_conn_t *c,
                                   const vw_smtp_cfg_t *cfg,
                                   const char *to_addr,
                                   const char *subject,
                                   const char *body_text,
                                   char *err_buf, size_t err_sz);
static vw_err_t smtp_ehlo(smtp_conn_t *c, char *err_buf, size_t err_sz);

/* ── Variadic error helper ──────────────────────────────────────────────── */

static void set_err(char *buf, size_t sz, const char *fmt, ...)
{
    if (!buf || sz == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sz, fmt, ap);
    va_end(ap);
    buf[sz - 1] = '\0';
}

/* Returns 0 if str contains no CR or LF bytes, -1 otherwise. */
static int smtp_no_crlf(const char *str)
{
    for (; *str; str++) {
        if (*str == '\r' || *str == '\n') return -1;
    }
    return 0;
}

/* ── Base64 encoder (RFC 4648) ──────────────────────────────────────────── */

static const char B64_ALPHA[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
 * Encode src into dst as standard base64.
 * dst must have at least ((src_len + 2) / 3) * 4 + 1 bytes.
 * Returns the number of characters written (not including NUL).
 * Returns 0 if dst_size is too small.
 */
static size_t base64_encode(const uint8_t *src, size_t src_len,
                             char *dst, size_t dst_size)
{
    size_t out_len = ((src_len + 2) / 3) * 4;
    if (dst_size < out_len + 1) return 0;

    size_t i = 0, o = 0;
    while (i + 2 < src_len) {
        uint32_t v = ((uint32_t)src[i] << 16)
                   | ((uint32_t)src[i+1] << 8)
                   |  (uint32_t)src[i+2];
        dst[o++] = B64_ALPHA[(v >> 18) & 0x3F];
        dst[o++] = B64_ALPHA[(v >> 12) & 0x3F];
        dst[o++] = B64_ALPHA[(v >>  6) & 0x3F];
        dst[o++] = B64_ALPHA[(v      ) & 0x3F];
        i += 3;
    }
    if (i < src_len) {
        uint32_t v = (uint32_t)src[i] << 16;
        if (i + 1 < src_len) v |= (uint32_t)src[i+1] << 8;
        dst[o++] = B64_ALPHA[(v >> 18) & 0x3F];
        dst[o++] = B64_ALPHA[(v >> 12) & 0x3F];
        dst[o++] = (i + 1 < src_len) ? B64_ALPHA[(v >> 6) & 0x3F] : '=';
        dst[o++] = '=';
    }
    dst[o] = '\0';
    return o;
}

/* ── Low-level I/O ──────────────────────────────────────────────────────── */

/*
 * Read one line (terminated by \n) from the connection into buf.
 * Strips trailing \r\n. Returns the 3-digit SMTP code, or -1 on error.
 * Handles multi-line responses (e.g. "250-...") by consuming all continuation
 * lines and returning the code from the final line.
 */
static int smtp_conn_read_line(smtp_conn_t *c, char *buf, size_t buf_size)
{
    if (buf_size < 4) return -1;

    int final_code = -1;

    for (;;) {
        /* Read byte-by-byte until LF */
        size_t pos = 0;
        for (;;) {
            if (pos >= buf_size - 1) return -1; /* line too long */
            char ch;
            int n;
            if (c->ssl) {
                n = mbedtls_ssl_read(c->ssl, (unsigned char *)&ch, 1);
                if (n <= 0) return -1;
            } else {
#ifdef _WIN32
                n = recv(c->fd, &ch, 1, 0);
#else
                n = (int)recv(c->fd, &ch, 1, 0);
#endif
                if (n <= 0) return -1;
            }
            if (ch == '\n') break;
            if (ch != '\r') buf[pos++] = ch;
        }
        buf[pos] = '\0';

        /* Parse 3-digit code */
        if (pos < 3) return -1;
        int code = 0;
        for (int d = 0; d < 3; d++) {
            if (buf[d] < '0' || buf[d] > '9') return -1;
            code = code * 10 + (buf[d] - '0');
        }
        final_code = code;

        /* If 4th character is '-', this is a continuation line; keep reading */
        if (pos >= 4 && buf[3] == '-') continue;
        break;
    }
    return final_code;
}

/*
 * Write len bytes from data to the connection.
 * Returns 0 on success, -1 on error.
 */
static int smtp_conn_write(smtp_conn_t *c, const char *data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int n;
        if (c->ssl) {
            n = mbedtls_ssl_write(c->ssl,
                                  (const unsigned char *)(data + sent),
                                  len - sent);
            if (n <= 0) return -1;
        } else {
#ifdef _WIN32
            n = send(c->fd, data + sent, (int)(len - sent), 0);
#else
            n = (int)send(c->fd, data + sent, len - sent, 0);
#endif
            if (n <= 0) return -1;
        }
        sent += (size_t)n;
    }
    return 0;
}

/*
 * Read a response line and check the code matches expected_code.
 * Returns 0 on match, -1 on I/O error or unexpected code.
 */
static int smtp_expect(smtp_conn_t *c, int expected_code,
                        char *err_buf, size_t err_sz)
{
    char line[SMTP_LINE_BUF];
    int code = smtp_conn_read_line(c, line, sizeof(line));
    if (code < 0) {
        set_err(err_buf, err_sz, "SMTP: I/O error reading server response");
        return -1;
    }
    if (code != expected_code) {
        set_err(err_buf, err_sz, "SMTP: expected %d, got %d: %s",
                expected_code, code, line);
        return -1;
    }
    return 0;
}

/* ── TLS upgrade ────────────────────────────────────────────────────────── */

/*
 * Wrap the existing raw socket fd in TLS using mbedTLS.
 * On success, c->ssl is set to ssl (caller manages lifetime).
 */
static vw_err_t smtp_tls_upgrade(smtp_conn_t *c,
                                  mbedtls_ssl_context *ssl,
                                  mbedtls_ssl_config  *conf,
                                  mbedtls_entropy_context *entropy,
                                  mbedtls_ctr_drbg_context *ctr_drbg,
                                  mbedtls_net_context *net,
                                  mbedtls_x509_crt *cacert,
                                  const char *host,
                                  int verify_cert,
                                  const char *ca_cert_path,
                                  char *err_buf, size_t err_sz)
{
    int rc;
    const char *pers = "vw_smtp";

    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);
    mbedtls_ssl_config_init(conf);
    mbedtls_ssl_init(ssl);

    rc = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (rc != 0) {
        set_err(err_buf, err_sz, "mbedTLS: ctr_drbg_seed failed (%d)", rc);
        goto fail;
    }

    rc = mbedtls_ssl_config_defaults(conf,
                                     MBEDTLS_SSL_IS_CLIENT,
                                     MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) {
        set_err(err_buf, err_sz, "mbedTLS: ssl_config_defaults failed (%d)", rc);
        goto fail;
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);

    if (verify_cert == 0) {
        /* Advisory: cert verification disabled — relay connection is not MITM-safe.
         * Set smtp_verify_cert=1 with a ca_cert_path in production. */
        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
    } else {
        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        if (!ca_cert_path || ca_cert_path[0] == '\0') {
            set_err(err_buf, err_sz,
                    "SMTP: verify_cert=1 requires ca_cert_path to be set");
            goto fail;
        }
        {
            unsigned char *ca_buf = NULL;
            size_t ca_len = 0;
            if (smtp_load_pem(ca_cert_path, &ca_buf, &ca_len) != 0)
                rc = -1;
            else
                rc = mbedtls_x509_crt_parse(cacert, ca_buf, ca_len);
            free(ca_buf);
        }
        if (rc != 0) {
            set_err(err_buf, err_sz,
                    "mbedTLS: failed to load CA chain from '%s' (%d)",
                    ca_cert_path, rc);
            goto fail;
        }
        mbedtls_ssl_conf_ca_chain(conf, cacert, NULL);
    }

    rc = mbedtls_ssl_setup(ssl, conf);
    if (rc != 0) {
        set_err(err_buf, err_sz, "mbedTLS: ssl_setup failed (%d)", rc);
        goto fail;
    }

    rc = mbedtls_ssl_set_hostname(ssl, host);
    if (rc != 0) {
        set_err(err_buf, err_sz, "mbedTLS: ssl_set_hostname failed (%d)", rc);
        goto fail;
    }

    /* Wrap existing socket — mbedtls_net_context holds the fd */
    net->fd = (int)c->fd;
    mbedtls_ssl_set_bio(ssl, net, mbedtls_net_send, mbedtls_net_recv, NULL);

    /* TLS handshake */
    while ((rc = mbedtls_ssl_handshake(ssl)) != 0) {
        if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
            char mbed_err[128];
            mbedtls_strerror(rc, mbed_err, sizeof(mbed_err));
            set_err(err_buf, err_sz, "mbedTLS: handshake failed (%d): %s",
                    rc, mbed_err);
            goto fail;
        }
    }

    c->ssl = ssl;
    return VW_OK;

fail:
    /* Free all mbedTLS objects on error; cacert lifetime is owned by the caller. */
    mbedtls_ssl_free(ssl);
    mbedtls_ssl_config_free(conf);
    mbedtls_ctr_drbg_free(ctr_drbg);
    mbedtls_entropy_free(entropy);
    return VW_ERR_NET_TLS;
}

/* ── SMTP helpers ───────────────────────────────────────────────────────── */

/* Send EHLO and consume (possibly multi-line) response. */
static vw_err_t smtp_ehlo(smtp_conn_t *c, char *err_buf, size_t err_sz)
{
    char hostname[SMTP_HOSTNAME_MAX];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        /* Fall back to a literal if gethostname fails */
        (void)snprintf(hostname, sizeof(hostname), "localhost");
    }
    hostname[sizeof(hostname) - 1] = '\0';

    char cmd[SMTP_CMD_BUF];
    int n = snprintf(cmd, sizeof(cmd), "EHLO %s\r\n", hostname);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        set_err(err_buf, err_sz, "SMTP: EHLO command too long");
        return VW_ERR_IO;
    }
    if (smtp_conn_write(c, cmd, (size_t)n) != 0) {
        set_err(err_buf, err_sz, "SMTP: write error sending EHLO");
        return VW_ERR_IO;
    }
    if (smtp_expect(c, 250, err_buf, err_sz) != 0) return VW_ERR_IO;
    return VW_OK;
}

/*
 * AUTH exchange. Tries AUTH PLAIN first (RFC 4616); falls back to AUTH LOGIN
 * on 504/534 (mechanism unsupported / too weak). All credential buffers are
 * zeroed on every exit path via a single cleanup label.
 */
static vw_err_t smtp_do_auth(smtp_conn_t *c,
                              const char *username, const char *password,
                              char *err_buf, size_t err_sz)
{
    char     local_user[256];
    char     local_pass[256];
    char     b64_user[348];        /* base64(255) = 340 + padding + NUL */
    char     b64_pass[348];
    char     line[512];
    /* PLAIN token: NUL + user(255) + NUL + pass(255) = 512 bytes max */
    char     plain_token[514];
    char     b64_plain[688];       /* base64(512) = 684 + NUL */
    char     plain_cmd[700];       /* "AUTH PLAIN " + b64(684) + "\r\n" + NUL */
    char     resp[SMTP_LINE_BUF];
    int      n;
    int      code;
    size_t   ul;
    size_t   pl;
    size_t   token_len;
    vw_err_t result = VW_ERR_IO;

    (void)snprintf(local_user, sizeof(local_user), "%s", username);
    (void)snprintf(local_pass, sizeof(local_pass), "%s", password);
    local_user[sizeof(local_user) - 1] = '\0';
    local_pass[sizeof(local_pass) - 1] = '\0';

    ul = strlen(local_user);
    pl = strlen(local_pass);

    /* Precompute base64 for AUTH LOGIN */
    if (base64_encode((const uint8_t *)local_user, ul, b64_user, sizeof(b64_user)) == 0 ||
        base64_encode((const uint8_t *)local_pass, pl, b64_pass, sizeof(b64_pass)) == 0) {
        set_err(err_buf, err_sz, "SMTP: base64 encoding failed");
        goto cleanup;
    }

    /* Build AUTH PLAIN token: NUL + username + NUL + password (RFC 4616) */
    plain_token[0] = '\0';
    memcpy(plain_token + 1, local_user, ul);
    plain_token[1 + ul] = '\0';
    memcpy(plain_token + 2 + ul, local_pass, pl);
    token_len = 2 + ul + pl;
    if (base64_encode((const uint8_t *)plain_token, token_len,
                      b64_plain, sizeof(b64_plain)) == 0) {
        set_err(err_buf, err_sz, "SMTP: base64 encoding failed for AUTH PLAIN");
        goto cleanup;
    }
    memset(plain_token, 0, sizeof(plain_token));

    /* Try AUTH PLAIN (single-step, widely supported on Postfix and cloud relays) */
    n = snprintf(plain_cmd, sizeof(plain_cmd), "AUTH PLAIN %s\r\n", b64_plain);
    memset(b64_plain, 0, sizeof(b64_plain));
    if (n < 0 || (size_t)n >= sizeof(plain_cmd)) {
        set_err(err_buf, err_sz, "SMTP: AUTH PLAIN command too long");
        goto cleanup;
    }
    if (smtp_conn_write(c, plain_cmd, (size_t)n) != 0) {
        set_err(err_buf, err_sz, "SMTP: write error sending AUTH PLAIN");
        memset(plain_cmd, 0, sizeof(plain_cmd));
        goto cleanup;
    }
    memset(plain_cmd, 0, sizeof(plain_cmd));

    code = smtp_conn_read_line(c, resp, sizeof(resp));
    if (code == 235) {
        result = VW_OK;
        goto cleanup;
    }
    if (code != 504 && code != 534) {
        /* 504=unsupported mechanism, 534=mechanism too weak — fall back to LOGIN.
           All other response codes are hard failures. */
        set_err(err_buf, err_sz, "SMTP: AUTH PLAIN rejected (%d): %s", code, resp);
        goto cleanup;
    }

    /* AUTH LOGIN fallback (two-step challenge-response) */
    if (smtp_conn_write(c, "AUTH LOGIN\r\n", 12) != 0) {
        set_err(err_buf, err_sz, "SMTP: write error sending AUTH LOGIN");
        goto cleanup;
    }
    if (smtp_expect(c, 334, err_buf, err_sz) != 0) goto cleanup;

    n = snprintf(line, sizeof(line), "%s\r\n", b64_user);
    if (n < 0 || (size_t)n >= sizeof(line)) {
        set_err(err_buf, err_sz, "SMTP: AUTH username line too long");
        goto cleanup;
    }
    if (smtp_conn_write(c, line, (size_t)n) != 0) {
        set_err(err_buf, err_sz, "SMTP: write error sending username");
        goto cleanup;
    }
    memset(line, 0, sizeof(line));
    if (smtp_expect(c, 334, err_buf, err_sz) != 0) goto cleanup;

    n = snprintf(line, sizeof(line), "%s\r\n", b64_pass);
    if (n < 0 || (size_t)n >= sizeof(line)) {
        set_err(err_buf, err_sz, "SMTP: AUTH password line too long");
        goto cleanup;
    }
    if (smtp_conn_write(c, line, (size_t)n) != 0) {
        set_err(err_buf, err_sz, "SMTP: write error sending password");
        goto cleanup;
    }
    memset(line, 0, sizeof(line));

    if (smtp_expect(c, 235, err_buf, err_sz) == 0)
        result = VW_OK;

cleanup:
    vw_crypto_secure_zero(local_user,  sizeof(local_user));
    vw_crypto_secure_zero(local_pass,  sizeof(local_pass));
    vw_crypto_secure_zero(b64_user,    sizeof(b64_user));
    vw_crypto_secure_zero(b64_pass,    sizeof(b64_pass));
    vw_crypto_secure_zero(line,        sizeof(line));
    vw_crypto_secure_zero(plain_token, sizeof(plain_token));
    vw_crypto_secure_zero(b64_plain,   sizeof(b64_plain));
    vw_crypto_secure_zero(plain_cmd,   sizeof(plain_cmd));
    return result;
}

/*
 * Send the SMTP envelope and DATA body.
 * Applies RFC 5321 dot-stuffing to the body.
 */
static vw_err_t smtp_send_message(smtp_conn_t *c,
                                   const vw_smtp_cfg_t *cfg,
                                   const char *to_addr,
                                   const char *subject,
                                   const char *body_text,
                                   char *err_buf, size_t err_sz)
{
    char cmd[SMTP_CMD_BUF];
    int n;

    /* MAIL FROM */
    n = snprintf(cmd, sizeof(cmd), "MAIL FROM:<%s>\r\n", cfg->from_addr);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        set_err(err_buf, err_sz, "SMTP: MAIL FROM line too long");
        return VW_ERR_IO;
    }
    if (smtp_conn_write(c, cmd, (size_t)n) != 0 ||
        smtp_expect(c, 250, err_buf, err_sz) != 0) return VW_ERR_IO;

    /* RCPT TO */
    n = snprintf(cmd, sizeof(cmd), "RCPT TO:<%s>\r\n", to_addr);
    if (n < 0 || (size_t)n >= sizeof(cmd)) {
        set_err(err_buf, err_sz, "SMTP: RCPT TO line too long");
        return VW_ERR_IO;
    }
    if (smtp_conn_write(c, cmd, (size_t)n) != 0 ||
        smtp_expect(c, 250, err_buf, err_sz) != 0) return VW_ERR_IO;

    /* DATA */
    if (smtp_conn_write(c, "DATA\r\n", 6) != 0 ||
        smtp_expect(c, 354, err_buf, err_sz) != 0) return VW_ERR_IO;

    /* Generate Date: and Message-ID: before building the header block. */
    char date_str[64];
    char msgid_str[16 + 1 + 16 + 1 + 256 + 3]; /* <16hex.16hex@256host> */
    {
        time_t now = time(NULL);
        struct tm tm_utc;
#ifdef _WIN32
        gmtime_s(&tm_utc, &now);
#else
        gmtime_r(&now, &tm_utc);
#endif
        strftime(date_str, sizeof(date_str),
                 "%a, %d %b %Y %H:%M:%S +0000", &tm_utc);
        make_message_id(msgid_str, sizeof(msgid_str), now, cfg->host);
    }

    /* Headers */
    char headers[SMTP_HDR_BUF];
    n = snprintf(headers, sizeof(headers),
                 "From: \"%s\" <%s>\r\n"
                 "To: <%s>\r\n"
                 "Date: %s\r\n"
                 "Message-ID: %s\r\n"
                 "Subject: %s\r\n"
                 "MIME-Version: 1.0\r\n"
                 "Content-Type: text/plain; charset=UTF-8\r\n"
                 "\r\n",
                 cfg->from_name, cfg->from_addr,
                 to_addr,
                 date_str,
                 msgid_str,
                 subject);
    if (n < 0 || (size_t)n >= sizeof(headers)) {
        set_err(err_buf, err_sz, "SMTP: message headers too long");
        return VW_ERR_IO;
    }
    if (smtp_conn_write(c, headers, (size_t)n) != 0) {
        set_err(err_buf, err_sz, "SMTP: write error sending headers");
        return VW_ERR_IO;
    }

    /* Body with dot-stuffing (RFC 5321 section 4.5.2):
     * any line beginning with '.' must be prefixed with another '.'. */
    const char *p = body_text;
    int at_line_start = 1;
    while (*p) {
        if (at_line_start && *p == '.') {
            /* Prepend an extra dot */
            if (smtp_conn_write(c, ".", 1) != 0) {
                set_err(err_buf, err_sz, "SMTP: write error in dot-stuffing");
                return VW_ERR_IO;
            }
        }

        /* Find end of current line */
        const char *end = p;
        while (*end && *end != '\n') end++;

        /* Determine the raw line (may contain \r before \n) */
        size_t line_len = (size_t)(end - p);
        /* Strip trailing \r if present (we will write CRLF ourselves) */
        size_t bare_len = line_len;
        if (bare_len > 0 && p[bare_len - 1] == '\r') bare_len--;

        if (bare_len > 0) {
            if (smtp_conn_write(c, p, bare_len) != 0) {
                set_err(err_buf, err_sz, "SMTP: write error sending body");
                return VW_ERR_IO;
            }
        }
        if (*end == '\n') {
            if (smtp_conn_write(c, "\r\n", 2) != 0) {
                set_err(err_buf, err_sz, "SMTP: write error sending CRLF");
                return VW_ERR_IO;
            }
            p = end + 1;
            at_line_start = 1;
        } else {
            /* Reached end of body without trailing newline */
            if (bare_len > 0) {
                if (smtp_conn_write(c, "\r\n", 2) != 0) {
                    set_err(err_buf, err_sz, "SMTP: write error sending final CRLF");
                    return VW_ERR_IO;
                }
            }
            p = end;
            at_line_start = 0;
        }
    }

    /* End DATA with <CRLF>.<CRLF> */
    if (smtp_conn_write(c, "\r\n.\r\n", 5) != 0 ||
        smtp_expect(c, 250, err_buf, err_sz) != 0) {
        if (err_buf && err_buf[0] == '\0')
            set_err(err_buf, err_sz, "SMTP: error ending DATA");
        return VW_ERR_IO;
    }

    /* QUIT (best-effort, ignore errors) */
    (void)smtp_conn_write(c, "QUIT\r\n", 6);

    return VW_OK;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

vw_err_t vw_smtp_send(const vw_smtp_cfg_t *cfg,
                        const char *to_addr,
                        const char *subject,
                        const char *body_text,
                        char *out_err_msg,
                        size_t err_msg_size)
{
    if (!cfg || !to_addr || !subject || !body_text)
        return VW_ERR_INVALID_ARG;

    if (out_err_msg && err_msg_size > 0) out_err_msg[0] = '\0';

    /* Reject CRLF in all address/header fields before opening any connection. */
    if (smtp_no_crlf(to_addr) != 0 || smtp_no_crlf(subject) != 0 ||
        smtp_no_crlf(cfg->from_name) != 0 || smtp_no_crlf(cfg->from_addr) != 0) {
        set_err(out_err_msg, err_msg_size,
                "SMTP: to_addr, subject, from_name, or from_addr contains CR or LF");
        return VW_ERR_INVALID_ARG;
    }

    /* Declare cacert here so early-return paths can safely free it. */
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt_init(&cacert);

#ifdef _WIN32
    /* Initialise Winsock if not already done. */
    WSADATA wsa;
    (void)WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    /* ── Resolve host and connect ─────────────────────────────── */
    char port_str[8];
    (void)snprintf(port_str, sizeof(port_str), "%u", (unsigned)cfg->port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *res = NULL;
    if (getaddrinfo(cfg->host, port_str, &hints, &res) != 0 || res == NULL) {
        set_err(out_err_msg, err_msg_size,
                "SMTP: cannot resolve host '%s'", cfg->host);
#ifdef _WIN32
        WSACleanup();
#endif
        mbedtls_x509_crt_free(&cacert);
        return VW_ERR_NET_CONNECT;
    }

    smtp_sock_t fd = SMTP_INVALID_SOCK;
    struct addrinfo *ai;
    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd == SMTP_INVALID_SOCK) continue;
        if (connect(fd, ai->ai_addr, (int)ai->ai_addrlen) == 0) break;
        smtp_close(fd);
        fd = SMTP_INVALID_SOCK;
    }
    freeaddrinfo(res);

    if (fd == SMTP_INVALID_SOCK) {
        set_err(out_err_msg, err_msg_size,
                "SMTP: TCP connect to %s:%s failed (errno %d)",
                cfg->host, port_str, smtp_errno());
#ifdef _WIN32
        WSACleanup();
#endif
        mbedtls_x509_crt_free(&cacert);
        return VW_ERR_NET_CONNECT;
    }

    /* 30 s per-operation timeout (covers SMTP command stalls in the 2FA OTP path) */
#ifdef _WIN32
    {
        DWORD tv_ms = 30000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv_ms, sizeof(tv_ms));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv_ms, sizeof(tv_ms));
    }
#else
    {
        struct timeval tv;
        tv.tv_sec  = 30;
        tv.tv_usec = 0;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    }
#endif

    /* ── TLS / non-TLS setup ──────────────────────────────────── */
    smtp_conn_t conn;
    conn.fd  = fd;
    conn.ssl = NULL;

    /* mbedTLS objects — always allocated on the stack; only initialised when needed */
    mbedtls_ssl_context      ssl;
    mbedtls_ssl_config        conf;
    mbedtls_entropy_context   entropy;
    mbedtls_ctr_drbg_context  ctr_drbg;
    mbedtls_net_context       net;
    /* Suppress uninitialised-use warnings by zeroing; init happens in smtp_tls_upgrade */
    memset(&ssl,      0, sizeof(ssl));
    memset(&conf,     0, sizeof(conf));
    memset(&entropy,  0, sizeof(entropy));
    memset(&ctr_drbg, 0, sizeof(ctr_drbg));
    memset(&net,      0, sizeof(net));

    vw_err_t err = VW_OK;

    if (cfg->tls_mode == VW_SMTP_TLS_SMTPS) {
        /* Implicit TLS: upgrade before any SMTP traffic */
        err = smtp_tls_upgrade(&conn, &ssl, &conf, &entropy, &ctr_drbg, &net,
                                &cacert, cfg->host, cfg->verify_cert,
                                cfg->ca_cert_path, out_err_msg, err_msg_size);
        if (err != VW_OK) goto cleanup;
    }

    /* ── Server greeting ──────────────────────────────────────── */
    {
        char line[SMTP_LINE_BUF];
        int code = smtp_conn_read_line(&conn, line, sizeof(line));
        if (code != 220) {
            set_err(out_err_msg, err_msg_size,
                    "SMTP: unexpected greeting (code %d): %s", code, line);
            err = VW_ERR_IO;
            goto cleanup;
        }
    }

    /* ── EHLO ─────────────────────────────────────────────────── */
    err = smtp_ehlo(&conn, out_err_msg, err_msg_size);
    if (err != VW_OK) goto cleanup;

    /* ── STARTTLS upgrade (if requested) ─────────────────────── */
    if (cfg->tls_mode == VW_SMTP_TLS_STARTTLS) {
        if (smtp_conn_write(&conn, "STARTTLS\r\n", 10) != 0 ||
            smtp_expect(&conn, 220, out_err_msg, err_msg_size) != 0) {
            set_err(out_err_msg, err_msg_size,
                    "SMTP: STARTTLS command rejected by server");
            err = VW_ERR_NET_TLS;
            goto cleanup;
        }

        err = smtp_tls_upgrade(&conn, &ssl, &conf, &entropy, &ctr_drbg, &net,
                                &cacert, cfg->host, cfg->verify_cert,
                                cfg->ca_cert_path, out_err_msg, err_msg_size);
        if (err != VW_OK) goto cleanup;

        /* RFC 3207: must re-EHLO after STARTTLS */
        err = smtp_ehlo(&conn, out_err_msg, err_msg_size);
        if (err != VW_OK) goto cleanup;
    }

    /* ── AUTH LOGIN (skip if no username configured) ──────────── */
    if (cfg->username[0] != '\0') {
        err = smtp_do_auth(&conn, cfg->username, cfg->password,
                           out_err_msg, err_msg_size);
        if (err != VW_OK) goto cleanup;
    }

    /* ── Send envelope + message body ────────────────────────── */
    err = smtp_send_message(&conn, cfg, to_addr, subject, body_text,
                            out_err_msg, err_msg_size);

cleanup:
    /* TLS teardown — only when TLS was successfully established */
    if (conn.ssl) {
        (void)mbedtls_ssl_close_notify(conn.ssl);
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        /* net.fd is the same fd we own below; don't let mbedtls close it */
        net.fd = -1;
    }
    /* cacert lifetime must outlast the connection; always free here */
    mbedtls_x509_crt_free(&cacert);

    smtp_close(fd);

#ifdef _WIN32
    WSACleanup();
#endif

    return err;
}

/* ── vw_smtp_validate_cfg ───────────────────────────────────────────────── */

vw_err_t vw_smtp_validate_cfg(const vw_smtp_cfg_t *cfg,
                               char *out_err_msg, size_t err_sz)
{
    if (!cfg) return VW_ERR_INVALID_ARG;

    if (cfg->host[0] == '\0') {
        set_err(out_err_msg, err_sz, "SMTP: host must not be empty");
        return VW_ERR_INVALID_ARG;
    }
    if (cfg->port == 0) {
        set_err(out_err_msg, err_sz, "SMTP: port must not be zero");
        return VW_ERR_INVALID_ARG;
    }
    if ((int)cfg->tls_mode < VW_SMTP_TLS_NONE ||
        (int)cfg->tls_mode > VW_SMTP_TLS_SMTPS) {
        set_err(out_err_msg, err_sz, "SMTP: tls_mode value %d is out of range",
                (int)cfg->tls_mode);
        return VW_ERR_INVALID_ARG;
    }
    if (cfg->verify_cert == 1 && cfg->ca_cert_path[0] == '\0') {
        set_err(out_err_msg, err_sz,
                "SMTP: verify_cert=1 requires ca_cert_path to be set");
        return VW_ERR_INVALID_ARG;
    }
    return VW_OK;
}
