#include "vw_net.h"
#include "vw_crypto.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* mbedTLS */
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

#ifdef _WIN32
#   include <winsock2.h>
#   include <ws2tcpip.h>
#   pragma comment(lib, "ws2_32.lib")
/* Platform shims for recv_timeout_ms atomics (MSVC C mode lacks stdatomic). */
#   define VW_RECV_TIMEOUT_TYPE           volatile LONG
#   define vw_recv_timeout_load(p)        ((uint32_t)InterlockedCompareExchange((volatile LONG *)(p), 0, 0))
#   define vw_recv_timeout_store(p, v)    ((void)InterlockedExchange((volatile LONG *)(p), (LONG)(v)))
#else
#   include <stdatomic.h>
#   include <arpa/inet.h>
#   include <errno.h>
#   include <fcntl.h>
#   include <netdb.h>
#   include <netinet/in.h>
#   include <pthread.h>
#   include <sys/select.h>
#   include <sys/socket.h>
#   include <unistd.h>
#   define VW_RECV_TIMEOUT_TYPE           _Atomic uint32_t
#   define vw_recv_timeout_load(p)        atomic_load_explicit((p), memory_order_relaxed)
#   define vw_recv_timeout_store(p, v)    atomic_store_explicit((p), (v), memory_order_relaxed)
#endif

/* ── TLS configuration constants ─────────────────────────────────────────── */

static const int VW_TLS_CIPHERSUITES[] = {
    MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
    MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,
    0
};

static const char *VW_ALPN_CLIENT[]  = { "vw/1",         NULL };
static const char *VW_ALPN_CLUSTER[] = { "vw-cluster/1", NULL };

/* ── Rate-limit token bucket ─────────────────────────────────────────────── */

typedef struct {
    uint64_t bps;
    uint64_t tokens;
    uint64_t last_refill_ns;
} token_bucket_t;

#ifdef _WIN32
static LARGE_INTEGER s_qpf;
static INIT_ONCE     s_qpf_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK qpf_once_cb(PINIT_ONCE o, PVOID p, PVOID *ctx) {
    (void)o; (void)p; (void)ctx;
    QueryPerformanceFrequency(&s_qpf);
    return TRUE;
}
#endif

static uint64_t now_ns(void) {
#ifdef _WIN32
    InitOnceExecuteOnce(&s_qpf_once, qpf_once_cb, NULL, NULL);
    LARGE_INTEGER cnt;
    QueryPerformanceCounter(&cnt);
    return (uint64_t)cnt.QuadPart * 1000000000ULL / (uint64_t)s_qpf.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static void bucket_consume(token_bucket_t *b, uint64_t bytes) {
    if (b->bps == 0) return;

    uint64_t now     = now_ns();
    uint64_t elapsed = now - b->last_refill_ns;
    b->last_refill_ns = now;

    uint64_t refill = (b->bps * elapsed) / 1000000000ULL;
    b->tokens += refill;
    if (b->tokens > b->bps) b->tokens = b->bps;

    if (b->tokens >= bytes) {
        b->tokens -= bytes;
        return;
    }

    uint64_t deficit = bytes - b->tokens;
    uint64_t wait_ns = (deficit * 1000000000ULL) / b->bps;
    b->tokens = 0;

#ifdef _WIN32
    DWORD ms = (DWORD)((wait_ns + 999999ULL) / 1000000ULL);
    if (ms > 0) Sleep(ms);
#else
    struct timespec ts = {
        .tv_sec  = (time_t)(wait_ns / 1000000000ULL),
        .tv_nsec = (long)(wait_ns % 1000000000ULL)
    };
    nanosleep(&ts, NULL);
#endif
}

/* ── Client-owned TLS state (embedded per client connection) ─────────────── */

typedef struct {
    mbedtls_ssl_config      conf;
    mbedtls_x509_crt        ca_cert;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int                     ca_loaded;
} vw_client_tls_t;

/* ── Connection structure ────────────────────────────────────────────────── */

struct vw_conn {
    mbedtls_ssl_context ssl;
    mbedtls_net_context net;
    token_bucket_t      upload_bucket;
    token_bucket_t      download_bucket;
    char                peer_addr[254];
    VW_RECV_TIMEOUT_TYPE recv_timeout_ms; /* per-connection recv deadline; 0 = none */
    int                 is_client;    /* 1 = owns client_tls; 0 = borrows server conf */
    vw_client_tls_t    *client_tls;  /* non-NULL iff is_client == 1 */
#ifdef _WIN32
    CRITICAL_SECTION    send_cs;
#else
    pthread_mutex_t     send_mu;
#endif
};

/* ── Server context structure ────────────────────────────────────────────── */

struct vw_net_ctx {
    mbedtls_ssl_config      conf;
    mbedtls_x509_crt        cert;
    mbedtls_pk_context      key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_net_context     listen_net;
    const char            **alpn_protos;
#ifdef _WIN32
    SRWLOCK                 cert_rw_lock;
#else
    pthread_rwlock_t        cert_rw_lock;
#endif
};

/* ── Custom bio callbacks ─────────────────────────────────────────────────── */

static int conn_send(void *ctx, const unsigned char *buf, size_t len)
{
    return mbedtls_net_send(&((vw_conn_t *)ctx)->net, buf, len);
}

static int conn_recv(void *ctx, unsigned char *buf, size_t len)
{
    return mbedtls_net_recv(&((vw_conn_t *)ctx)->net, buf, len);
}

/* mbedtls_ssl_read passes ssl->conf->read_timeout here. We ignore that value
 * and use conn->recv_timeout_ms instead so each server connection has its own
 * deadline without touching the shared ssl_config. */
static int conn_recv_timeout(void *ctx, unsigned char *buf, size_t len,
                              uint32_t timeout_ms)
{
    vw_conn_t *conn = (vw_conn_t *)ctx;
    (void)timeout_ms;
    uint32_t tms = vw_recv_timeout_load(&conn->recv_timeout_ms);
    return mbedtls_net_recv_timeout(&conn->net, buf, len, tms);
}

/* ── Non-blocking TCP connect with optional timeout ───────────────────────── */

static int connect_with_timeout(mbedtls_net_context *net,
                                 const char *host, const char *port_str,
                                 uint32_t timeout_ms)
{
    if (timeout_ms == 0)
        return mbedtls_net_connect(net, host, port_str, MBEDTLS_NET_PROTO_TCP);

    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res)
        return MBEDTLS_ERR_NET_UNKNOWN_HOST;

    int connected = 0;
    for (ai = res; ai && !connected; ai = ai->ai_next) {
#ifdef _WIN32
        SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        int r = connect(s, ai->ai_addr, (int)ai->ai_addrlen);
        int in_prog = (r != 0 && WSAGetLastError() == WSAEWOULDBLOCK);
#else
        int s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        int orig_flags = fcntl(s, F_GETFL, 0);
        if (orig_flags < 0 || fcntl(s, F_SETFL, orig_flags | O_NONBLOCK) < 0) {
            close(s); continue;
        }
        int r = connect(s, ai->ai_addr, ai->ai_addrlen);
        int in_prog = (r != 0 && errno == EINPROGRESS);
#endif
        if (r == 0) {
            connected = 1;
        } else if (in_prog) {
            fd_set wfds, efds;
            FD_ZERO(&wfds); FD_SET(s, &wfds);
            FD_ZERO(&efds); FD_SET(s, &efds);
            struct timeval tv;
            tv.tv_sec  = (long)(timeout_ms / 1000);
            tv.tv_usec = (long)((timeout_ms % 1000) * 1000);
            /* nfds is ignored on Windows; use 0 to avoid sign-cast warnings */
#ifdef _WIN32
            int sel = select(0, NULL, &wfds, &efds, &tv);
#else
            int sel = select(s + 1, NULL, &wfds, &efds, &tv);
#endif
            if (sel > 0 && FD_ISSET(s, &wfds)) {
                int err = 0;
                socklen_t elen = sizeof(err);
                if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&err, &elen) == 0 && err == 0)
                    connected = 1;
            }
        }

        if (connected) {
#ifdef _WIN32
            u_long nb_off = 0;
            ioctlsocket(s, FIONBIO, &nb_off);
            net->fd = (int)(intptr_t)s;
#else
            fcntl(s, F_SETFL, orig_flags);
            net->fd = s;
#endif
        } else {
#ifdef _WIN32
            closesocket(s);
#else
            close(s);
#endif
        }
    }
    freeaddrinfo(res);
    return connected ? 0 : MBEDTLS_ERR_NET_CONNECT_FAILED;
}

/* ── Internal helpers ────────────────────────────────────────────────────── */

static vw_err_t configure_ssl_defaults(mbedtls_ssl_config *conf,
                                        mbedtls_ctr_drbg_context *rng,
                                        int endpoint,
                                        const char **alpn_protos) {
    if (mbedtls_ssl_config_defaults(conf, endpoint,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0)
        return VW_ERR_NET_TLS;

    mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_max_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_3);
    mbedtls_ssl_conf_ciphersuites(conf, VW_TLS_CIPHERSUITES);
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, rng);

    if (alpn_protos) {
        if (mbedtls_ssl_conf_alpn_protocols(conf, alpn_protos) != 0)
            return VW_ERR_NET_TLS;
    }
    return VW_OK;
}

/* Read a PEM file into a NUL-terminated heap buffer.
 * mbedTLS PEM parsers require the buffer to be NUL-terminated; len includes it. */
static vw_err_t load_pem_file(const char *path,
                               unsigned char **out_buf, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return VW_ERR_NET_TLS;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return VW_ERR_NET_TLS; }
    long sz = ftell(f);
    if (sz < 0 || sz > 1024 * 1024) { fclose(f); return VW_ERR_NET_TLS; }
    rewind(f);

    unsigned char *buf = (unsigned char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return VW_ERR_OOM; }

    if (sz > 0 && fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f); return VW_ERR_NET_TLS;
    }
    fclose(f);
    buf[sz] = '\0';
    *out_buf = buf;
    *out_len = (size_t)sz + 1; /* length includes NUL for PEM parser */
    return VW_OK;
}

static vw_err_t load_server_cert(vw_net_ctx_t *ctx,
                                  const char *cert_path,
                                  const char *key_path) {
    unsigned char *cert_buf = NULL, *key_buf = NULL;
    size_t cert_len = 0, key_len = 0;
    vw_err_t err = VW_OK;

    if (load_pem_file(cert_path, &cert_buf, &cert_len) != VW_OK ||
        load_pem_file(key_path,  &key_buf,  &key_len)  != VW_OK)
    { err = VW_ERR_NET_TLS; goto done; }

    if (mbedtls_x509_crt_parse(&ctx->cert, cert_buf, cert_len) != 0)
    { err = VW_ERR_NET_TLS; goto done; }
    if (mbedtls_pk_parse_key(&ctx->key, key_buf, key_len, NULL, 0,
                              mbedtls_ctr_drbg_random, &ctx->ctr_drbg) != 0)
    { err = VW_ERR_NET_TLS; goto done; }
    if (mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->cert, &ctx->key) != 0)
    { err = VW_ERR_NET_TLS; goto done; }
done:
    free(cert_buf);
    free(key_buf);
    return err;
}

static vw_err_t vw_net_listen_internal(const char *host, uint16_t port,
                                        const char *cert_pem_path,
                                        const char *key_pem_path,
                                        int is_cluster,
                                        vw_net_ctx_t **out_ctx) {
    vw_net_ctx_t *ctx = (vw_net_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return VW_ERR_OOM;

    mbedtls_ssl_config_init(&ctx->conf);
    mbedtls_x509_crt_init(&ctx->cert);
    mbedtls_pk_init(&ctx->key);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);
    mbedtls_net_init(&ctx->listen_net);
#ifdef _WIN32
    InitializeSRWLock(&ctx->cert_rw_lock);
#else
    pthread_rwlock_init(&ctx->cert_rw_lock, NULL);
#endif
    ctx->alpn_protos = is_cluster ? VW_ALPN_CLUSTER : VW_ALPN_CLIENT;

    static const unsigned char pers[] = "vapourwault_srv_drbg";
    if (mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func,
                               &ctx->entropy, pers, sizeof(pers) - 1) != 0)
        goto fail;

    if (configure_ssl_defaults(&ctx->conf, &ctx->ctr_drbg,
                                MBEDTLS_SSL_IS_SERVER,
                                ctx->alpn_protos) != VW_OK)
        goto fail;

    /* TLS 1.3 session resumption uses PSK tickets (MBEDTLS_SSL_TICKET_C),
     * not the TLS 1.2 session cache — no mbedtls_ssl_conf_session_cache needed. */

    if (load_server_cert(ctx, cert_pem_path, key_pem_path) != VW_OK)
        goto fail;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);
    if (mbedtls_net_bind(&ctx->listen_net, host, port_str,
                          MBEDTLS_NET_PROTO_TCP) != 0)
        goto fail;

    *out_ctx = ctx;
    return VW_OK;

fail:
    mbedtls_ssl_config_free(&ctx->conf);
    mbedtls_x509_crt_free(&ctx->cert);
    mbedtls_pk_free(&ctx->key);
    mbedtls_entropy_free(&ctx->entropy);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_net_free(&ctx->listen_net);
#ifndef _WIN32
    pthread_rwlock_destroy(&ctx->cert_rw_lock);
    /* SRWLOCK (Win32) requires no cleanup */
#endif
    free(ctx);
    return VW_ERR_NET_TLS;
}

/* ── Public server API ───────────────────────────────────────────────────── */

vw_err_t vw_net_listen(const char *host, uint16_t port,
                        const char *cert_pem_path,
                        const char *key_pem_path,
                        vw_net_ctx_t **out_ctx) {
    return vw_net_listen_internal(host, port, cert_pem_path, key_pem_path,
                                  0, out_ctx);
}

vw_err_t vw_net_listen_cluster(const char *host, uint16_t port,
                                const char *cert_pem_path,
                                const char *key_pem_path,
                                vw_net_ctx_t **out_ctx) {
    return vw_net_listen_internal(host, port, cert_pem_path, key_pem_path,
                                  1, out_ctx);
}

vw_err_t vw_net_accept(vw_net_ctx_t *ctx, vw_conn_t **out_conn) {
    vw_conn_t *conn = (vw_conn_t *)calloc(1, sizeof(*conn));
    if (!conn) return VW_ERR_OOM;

    mbedtls_ssl_init(&conn->ssl);
    mbedtls_net_init(&conn->net);
#ifdef _WIN32
    InitializeCriticalSection(&conn->send_cs);
#else
    pthread_mutex_init(&conn->send_mu, NULL);
#endif

    if (mbedtls_net_accept(&ctx->listen_net, &conn->net,
                            NULL, 0, NULL) != 0) {
        mbedtls_ssl_free(&conn->ssl);
        mbedtls_net_free(&conn->net);
#ifdef _WIN32
        DeleteCriticalSection(&conn->send_cs);
#else
        pthread_mutex_destroy(&conn->send_mu);
#endif
        free(conn);
        return VW_ERR_NET_CONNECT;
    }

    /* Capture peer address for logging */
    struct sockaddr_storage sa;
    socklen_t salen = sizeof(sa);
    if (getpeername(conn->net.fd, (struct sockaddr *)&sa, &salen) == 0) {
        if (sa.ss_family == AF_INET)
            inet_ntop(AF_INET,  &((struct sockaddr_in  *)&sa)->sin_addr,
                      conn->peer_addr, sizeof(conn->peer_addr));
        else if (sa.ss_family == AF_INET6)
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&sa)->sin6_addr,
                      conn->peer_addr, sizeof(conn->peer_addr));
    }

    /* Hold cert read lock across ssl_setup + handshake to prevent reload_cert
       from swapping ctx->conf while we are using it. */
#ifdef _WIN32
    AcquireSRWLockShared(&ctx->cert_rw_lock);
#else
    pthread_rwlock_rdlock(&ctx->cert_rw_lock);
#endif

    int accept_diag_step = 1, accept_diag_rc = 0;
    if ((accept_diag_rc = mbedtls_ssl_setup(&conn->ssl, &ctx->conf)) != 0)
        goto fail;
    mbedtls_ssl_set_bio(&conn->ssl, conn,
                        conn_send, conn_recv, conn_recv_timeout);

    accept_diag_step = 2; accept_diag_rc = 0;
    {
        int rc;
        while ((rc = mbedtls_ssl_handshake(&conn->ssl)) != 0) {
            if (rc != MBEDTLS_ERR_SSL_WANT_READ &&
                rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
                accept_diag_rc = rc;
                goto fail;
            }
        }
    }

#ifdef _WIN32
    ReleaseSRWLockShared(&ctx->cert_rw_lock);
#else
    pthread_rwlock_unlock(&ctx->cert_rw_lock);
#endif

    conn->upload_bucket.last_refill_ns   = now_ns();
    conn->download_bucket.last_refill_ns = now_ns();
    *out_conn = conn;
    return VW_OK;

fail:
    {
        char errbuf[256] = "";
        mbedtls_strerror(accept_diag_rc, errbuf, sizeof(errbuf));
        fprintf(stderr,
                "[vw_net] vw_net_accept FAIL step=%d rc=%d (%s)\n",
                accept_diag_step, accept_diag_rc, errbuf);
    }
#ifdef _WIN32
    ReleaseSRWLockShared(&ctx->cert_rw_lock);
#else
    pthread_rwlock_unlock(&ctx->cert_rw_lock);
#endif
    mbedtls_ssl_free(&conn->ssl);
    mbedtls_net_free(&conn->net);
#ifdef _WIN32
    DeleteCriticalSection(&conn->send_cs);
#else
    pthread_mutex_destroy(&conn->send_mu);
#endif
    free(conn);
    return VW_ERR_NET_TLS;
}

void vw_net_ctx_close(vw_net_ctx_t *ctx) {
    if (!ctx) return;
    mbedtls_ssl_config_free(&ctx->conf);
    mbedtls_x509_crt_free(&ctx->cert);
    mbedtls_pk_free(&ctx->key);
    mbedtls_entropy_free(&ctx->entropy);
    mbedtls_ctr_drbg_free(&ctx->ctr_drbg);
    mbedtls_net_free(&ctx->listen_net);
#ifndef _WIN32
    pthread_rwlock_destroy(&ctx->cert_rw_lock);
    /* SRWLOCK (Win32) requires no cleanup */
#endif
    free(ctx);
}

/* ── Public client API ───────────────────────────────────────────────────── */

vw_err_t vw_net_connect(const char *host, uint16_t port,
                         vw_cert_verify_t verify,
                         const char *ca_cert_pem_path,
                         const vw_conn_opts_t *opts,
                         vw_conn_t **out_conn) {
    if (verify == VW_CERT_VERIFY_REQUIRED && !ca_cert_pem_path)
        return VW_ERR_INVALID_ARG;

    vw_conn_t *conn = (vw_conn_t *)calloc(1, sizeof(*conn));
    if (!conn) return VW_ERR_OOM;

    vw_client_tls_t *tls = (vw_client_tls_t *)calloc(1, sizeof(*tls));
    if (!tls) { free(conn); return VW_ERR_OOM; }

    conn->client_tls = tls;
    conn->is_client  = 1;

    mbedtls_ssl_init(&conn->ssl);
    mbedtls_net_init(&conn->net);
    mbedtls_ssl_config_init(&tls->conf);
    mbedtls_x509_crt_init(&tls->ca_cert);
    mbedtls_entropy_init(&tls->entropy);
    mbedtls_ctr_drbg_init(&tls->ctr_drbg);
#ifdef _WIN32
    InitializeCriticalSection(&conn->send_cs);
#else
    pthread_mutex_init(&conn->send_mu, NULL);
#endif

    int diag_step = 0, diag_rc = 0;

    static const unsigned char pers[] = "vapourwault_cli_drbg";
    diag_step = 1;
    if ((diag_rc = mbedtls_ctr_drbg_seed(&tls->ctr_drbg, mbedtls_entropy_func,
                                          &tls->entropy, pers,
                                          sizeof(pers) - 1)) != 0)
        goto fail;

    diag_step = 2;
    if (configure_ssl_defaults(&tls->conf, &tls->ctr_drbg,
                                MBEDTLS_SSL_IS_CLIENT,
                                VW_ALPN_CLIENT) != VW_OK)
        goto fail;

    if (verify == VW_CERT_VERIFY_NONE) {
        mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_NONE);
    } else {
        mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        if (ca_cert_pem_path) {
            unsigned char *ca_buf = NULL;
            size_t ca_len = 0;
            int ca_ret = -1;
            diag_step = 3;
            if (load_pem_file(ca_cert_pem_path, &ca_buf, &ca_len) == VW_OK)
                ca_ret = mbedtls_x509_crt_parse(&tls->ca_cert, ca_buf, ca_len);
            free(ca_buf);
            diag_rc = ca_ret;
            if (ca_ret != 0) goto fail;
            tls->ca_loaded = 1;
            mbedtls_ssl_conf_ca_chain(&tls->conf, &tls->ca_cert, NULL);
        }
    }

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    diag_step = 4;
    uint32_t ctimeout = opts ? opts->connect_timeout_ms : 0;
    if ((diag_rc = connect_with_timeout(&conn->net, host, port_str,
                                         ctimeout)) != 0)
        goto fail;

    if (opts && opts->recv_timeout_ms)
        conn->recv_timeout_ms = opts->recv_timeout_ms;

    diag_step = 5;
    if ((diag_rc = mbedtls_ssl_setup(&conn->ssl, &tls->conf)) != 0) goto fail;
    mbedtls_ssl_set_bio(&conn->ssl, conn,
                        conn_send, conn_recv, conn_recv_timeout);
    mbedtls_ssl_set_hostname(&conn->ssl, host);

    diag_step = 6; diag_rc = 0;
    {
        int rc;
        while ((rc = mbedtls_ssl_handshake(&conn->ssl)) != 0) {
            if (rc != MBEDTLS_ERR_SSL_WANT_READ &&
                rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
                diag_rc = rc;
                goto fail;
            }
        }
    }

    strncpy(conn->peer_addr, host, sizeof(conn->peer_addr) - 1);
    conn->upload_bucket.last_refill_ns   = now_ns();
    conn->download_bucket.last_refill_ns = now_ns();
    if (opts) {
        conn->upload_bucket.bps   = opts->upload_bps;
        conn->download_bucket.bps = opts->download_bps;
    }

    *out_conn = conn;
    return VW_OK;

fail:
    {
        char errbuf[256] = "";
        mbedtls_strerror(diag_rc, errbuf, sizeof(errbuf));
        fprintf(stderr,
                "[vw_net] vw_net_connect FAIL step=%d rc=%d (%s)\n",
                diag_step, diag_rc, errbuf);
    }
    mbedtls_ssl_free(&conn->ssl);
    mbedtls_net_free(&conn->net);
    mbedtls_ssl_config_free(&tls->conf);
    mbedtls_x509_crt_free(&tls->ca_cert);
    mbedtls_entropy_free(&tls->entropy);
    mbedtls_ctr_drbg_free(&tls->ctr_drbg);
    free(tls);
#ifdef _WIN32
    DeleteCriticalSection(&conn->send_cs);
#else
    pthread_mutex_destroy(&conn->send_mu);
#endif
    free(conn);
    return VW_ERR_NET_TLS;
}

/* ── Per-connection send / recv ──────────────────────────────────────────── */

vw_err_t vw_net_send(vw_conn_t *conn, const void *data, size_t len) {
    bucket_consume(&conn->upload_bucket, (uint64_t)len);

    const uint8_t *p = (const uint8_t *)data;
    size_t remaining = len;

#ifdef _WIN32
    EnterCriticalSection(&conn->send_cs);
#else
    pthread_mutex_lock(&conn->send_mu);
#endif

    vw_err_t result = VW_OK;
    while (remaining > 0) {
        int rc = mbedtls_ssl_write(&conn->ssl, p, remaining);
        if (rc > 0) {
            p += rc;
            remaining -= (size_t)rc;
        } else if (rc == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        } else if (rc == 0 || rc == MBEDTLS_ERR_NET_CONN_RESET) {
            result = VW_ERR_NET_CLOSED;
            break;
        } else {
            result = VW_ERR_IO;
            break;
        }
    }

#ifdef _WIN32
    LeaveCriticalSection(&conn->send_cs);
#else
    pthread_mutex_unlock(&conn->send_mu);
#endif
    return result;
}

vw_err_t vw_net_recv(vw_conn_t *conn, void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    size_t remaining = len;

    while (remaining > 0) {
        int rc = mbedtls_ssl_read(&conn->ssl, p, remaining);
        if (rc > 0) {
            bucket_consume(&conn->download_bucket, (uint64_t)rc);
            p += rc;
            remaining -= (size_t)rc;
        } else if (rc == MBEDTLS_ERR_SSL_WANT_READ) {
            continue;
        } else if (rc == MBEDTLS_ERR_SSL_TIMEOUT) {
            return VW_ERR_NET_TIMEOUT;
        } else if (rc == 0 || rc == MBEDTLS_ERR_NET_CONN_RESET) {
            return VW_ERR_NET_CLOSED;
        } else {
            return VW_ERR_IO;
        }
    }
    return VW_OK;
}

vw_err_t vw_net_recv_partial(vw_conn_t *conn, void *buf, size_t buf_size,
                              size_t *out_len) {
    int rc = mbedtls_ssl_read(&conn->ssl, (uint8_t *)buf, buf_size);
    if (rc > 0) {
        bucket_consume(&conn->download_bucket, (uint64_t)rc);
        *out_len = (size_t)rc;
        return VW_OK;
    } else if (rc == MBEDTLS_ERR_SSL_WANT_READ) {
        *out_len = 0;
        return VW_OK;
    } else if (rc == MBEDTLS_ERR_SSL_TIMEOUT) {
        return VW_ERR_NET_TIMEOUT;
    } else if (rc == 0 || rc == MBEDTLS_ERR_NET_CONN_RESET) {
        return VW_ERR_NET_CLOSED;
    }
    return VW_ERR_IO;
}

void vw_net_set_rate_limit(vw_conn_t *conn,
                            uint64_t upload_bps, uint64_t download_bps) {
    conn->upload_bucket.bps   = upload_bps;
    conn->download_bucket.bps = download_bps;
    conn->upload_bucket.tokens   = 0;
    conn->download_bucket.tokens = 0;
    conn->upload_bucket.last_refill_ns   = now_ns();
    conn->download_bucket.last_refill_ns = now_ns();
}

void vw_net_close(vw_conn_t *conn) {
    if (!conn) return;
    mbedtls_ssl_close_notify(&conn->ssl);
    mbedtls_net_free(&conn->net);
    mbedtls_ssl_free(&conn->ssl);
    if (conn->is_client && conn->client_tls) {
        vw_client_tls_t *tls = conn->client_tls;
        mbedtls_ssl_config_free(&tls->conf);
        if (tls->ca_loaded) mbedtls_x509_crt_free(&tls->ca_cert);
        mbedtls_entropy_free(&tls->entropy);
        mbedtls_ctr_drbg_free(&tls->ctr_drbg);
        free(tls);
    }
#ifdef _WIN32
    DeleteCriticalSection(&conn->send_cs);
#else
    pthread_mutex_destroy(&conn->send_mu);
#endif
    free(conn);
}

vw_err_t vw_net_peer_addr(const vw_conn_t *conn, char *out_buf,
                           size_t buf_size) {
    if (!conn || !out_buf || buf_size == 0) return VW_ERR_INVALID_ARG;
    strncpy(out_buf, conn->peer_addr, buf_size - 1);
    out_buf[buf_size - 1] = '\0';
    return VW_OK;
}

const char *vw_net_alpn(const vw_conn_t *conn) {
    return mbedtls_ssl_get_alpn_protocol(&conn->ssl);
}

vw_err_t vw_net_conn_set_recv_timeout(vw_conn_t *conn, uint32_t timeout_ms)
{
    if (!conn) return VW_ERR_INVALID_ARG;
    vw_recv_timeout_store(&conn->recv_timeout_ms, timeout_ms);
    return VW_OK;
}

vw_err_t vw_net_ctx_reload_cert(vw_net_ctx_t *ctx,
                                 const char *cert_pem_path,
                                 const char *key_pem_path) {
    mbedtls_x509_crt         new_cert;
    mbedtls_pk_context        new_key;
    mbedtls_entropy_context   tmp_entropy;
    mbedtls_ctr_drbg_context  tmp_drbg;
    unsigned char            *cert_buf = NULL, *key_buf = NULL;
    size_t                    cert_len = 0, key_len = 0;
    mbedtls_x509_crt_init(&new_cert);
    mbedtls_pk_init(&new_key);
    mbedtls_entropy_init(&tmp_entropy);
    mbedtls_ctr_drbg_init(&tmp_drbg);

    /* Parse outside lock — slow I/O; use a local RNG to avoid racing with
     * concurrent TLS handshakes that hold a shared lock on ctx->ctr_drbg. */
    static const unsigned char pers[] = "vapourwault_reload_drbg";
    if (mbedtls_ctr_drbg_seed(&tmp_drbg, mbedtls_entropy_func,
                               &tmp_entropy, pers, sizeof(pers) - 1) != 0)
        goto fail_parse;
    if (load_pem_file(cert_pem_path, &cert_buf, &cert_len) != VW_OK) goto fail_parse;
    if (load_pem_file(key_pem_path,  &key_buf,  &key_len)  != VW_OK) goto fail_parse;
    if (mbedtls_x509_crt_parse(&new_cert, cert_buf, cert_len) != 0) goto fail_parse;
    if (mbedtls_pk_parse_key(&new_key, key_buf, key_len, NULL, 0,
                              mbedtls_ctr_drbg_random, &tmp_drbg) != 0) goto fail_parse;
    free(cert_buf); cert_buf = NULL;
    free(key_buf);  key_buf  = NULL;
    mbedtls_ctr_drbg_free(&tmp_drbg);
    mbedtls_entropy_free(&tmp_entropy);

#ifdef _WIN32
    AcquireSRWLockExclusive(&ctx->cert_rw_lock);
#else
    pthread_rwlock_wrlock(&ctx->cert_rw_lock);
#endif

    /* Replace cert/key in context */
    mbedtls_x509_crt_free(&ctx->cert);
    mbedtls_pk_free(&ctx->key);
    ctx->cert = new_cert;
    ctx->key  = new_key;

    /*
     * Reinitialise ssl_config to clear the old key_cert linked-list entry
     * (which now points at freed memory). Reconfigure from scratch so
     * conf_own_cert is the sole entry.
     */
    mbedtls_ssl_config_free(&ctx->conf);
    mbedtls_ssl_config_init(&ctx->conf);

    vw_err_t err = configure_ssl_defaults(&ctx->conf, &ctx->ctr_drbg,
                                           MBEDTLS_SSL_IS_SERVER,
                                           ctx->alpn_protos);
    if (err == VW_OK) {
        if (mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->cert, &ctx->key) != 0)
            err = VW_ERR_NET_TLS;
    }

#ifdef _WIN32
    ReleaseSRWLockExclusive(&ctx->cert_rw_lock);
#else
    pthread_rwlock_unlock(&ctx->cert_rw_lock);
#endif
    return err;

fail_parse:
    free(cert_buf);
    free(key_buf);
    mbedtls_x509_crt_free(&new_cert);
    mbedtls_pk_free(&new_key);
    mbedtls_ctr_drbg_free(&tmp_drbg);
    mbedtls_entropy_free(&tmp_entropy);
    return VW_ERR_NET_TLS;
}
