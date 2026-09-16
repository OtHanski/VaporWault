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
#   include <wincrypt.h>   /* TASK-00296: CertOpenStore et al. for
                               load_system_ca_chain() below */
#   pragma comment(lib, "ws2_32.lib")
#   pragma comment(lib, "crypt32.lib")
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
#ifdef _WIN32
    /* TASK-00296: hostname for win32_verify_cert_cb's SSL chain-policy
     * check (VW_CERT_VERIFY_SYSTEM_STORE only) — must outlive the
     * handshake, so it lives here rather than a stack buffer. */
    wchar_t                 hostname_w[256];
#endif
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

#ifdef _WIN32
/*
 * TASK-00296 fix: mbedtls_net_connect() (the timeout_ms==0 path just
 * below) internally calls mbedTLS's own net_prepare(), which lazily calls
 * WSAStartup() on Windows — but the non-blocking branch below talks to
 * raw Winsock (socket/connect/select) directly and never did, relying
 * entirely on WSAStartup having already happened as a side effect of some
 * *other* mbedtls_net_connect() call (or one of the handful of other
 * ad-hoc WSAStartup call sites in this codebase — vw_client_cli.c,
 * vw_ipc.c, vw_smtp.c) earlier in the process. That was always true for
 * every caller before TASK-00296 (this project's own client/server code
 * always passes conn_opts=NULL, i.e. timeout_ms==0, for every connection
 * except the new outbound update-check fetch), but a client auto-update
 * check can legitimately be the very first network call a fresh daemon
 * process ever makes (headless auto-policy, zero configured accounts —
 * see vw_update.c's design), so this branch needs its own guaranteed
 * one-time init rather than depending on load-bearing call-order luck
 * elsewhere in the process. Found via a real DNS-resolution failure
 * (WSANOTINITIALISED) in a from-scratch process during TASK-00296's own
 * manual GitHub-fetch verification — not theoretical.
 */
static INIT_ONCE   s_wsa_once = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK wsa_once_cb(PINIT_ONCE o, PVOID p, PVOID *ctx) {
    (void)o; (void)p; (void)ctx;
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    return TRUE;
}
static void ensure_wsa_started(void) {
    InitOnceExecuteOnce(&s_wsa_once, wsa_once_cb, NULL, NULL);
}
#endif

#ifdef VW_NET_DNS_TEST_HOOK
static int (*g_dns_test_resolver)(const char *, const char *, struct addrinfo **) = NULL;
void vw_net_test_set_dns_resolver(
        int (*fn)(const char *host, const char *port_str, struct addrinfo **out_res)) {
    g_dns_test_resolver = fn;
}
#endif

/*
 * TASK-00305: getaddrinfo() has no timeout of its own — the connect-phase
 * timeout below only ever bounded the TCP connect, not resolution, so a
 * slow or unresponsive resolver could stall a caller for its own internal
 * retry budget (well past a minute in the sandbox that found this). Bound
 * it by running the actual getaddrinfo() call on a detached helper thread
 * and waiting for it with a hard deadline: if the deadline passes first,
 * the wait is abandoned and the orphaned thread frees its own context and
 * result once (if ever) the resolver returns — a rare leaked thread is the
 * accepted cost of a portable hard bound with no new external dependency
 * (this project's existing detached-thread pattern, e.g. vw_cluster.c's
 * per-replica accept threads).
 */
typedef struct {
#ifdef _WIN32
    CRITICAL_SECTION   lock;
    CONDITION_VARIABLE cond;
#else
    pthread_mutex_t lock;
    pthread_cond_t  cond;
#endif
    char *host;
    char *port_str;
    int   done;       /* set once the resolver has returned */
    int   abandoned;  /* set by the waiter if it gave up before done */
    int   gai_rc;
    struct addrinfo *res;
} dns_resolve_ctx_t;

static void dns_resolve_ctx_free(dns_resolve_ctx_t *ctx) {
#ifdef _WIN32
    DeleteCriticalSection(&ctx->lock);
#else
    pthread_cond_destroy(&ctx->cond);
    pthread_mutex_destroy(&ctx->lock);
#endif
    free(ctx->host);
    free(ctx->port_str);
    free(ctx);
}

#ifdef _WIN32
static DWORD WINAPI dns_resolve_thread(LPVOID arg)
#else
static void *dns_resolve_thread(void *arg)
#endif
{
    dns_resolve_ctx_t *ctx = (dns_resolve_ctx_t *)arg;

    struct addrinfo *res = NULL;
    int rc;
#ifdef VW_NET_DNS_TEST_HOOK
    if (g_dns_test_resolver) {
        rc = g_dns_test_resolver(ctx->host, ctx->port_str, &res);
    } else
#endif
    {
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        rc = getaddrinfo(ctx->host, ctx->port_str, &hints, &res);
    }

#ifdef _WIN32
    EnterCriticalSection(&ctx->lock);
#else
    pthread_mutex_lock(&ctx->lock);
#endif
    if (ctx->abandoned) {
#ifdef _WIN32
        LeaveCriticalSection(&ctx->lock);
#else
        pthread_mutex_unlock(&ctx->lock);
#endif
        if (res) freeaddrinfo(res);
        dns_resolve_ctx_free(ctx);
        return 0;
    }
    ctx->gai_rc = rc;
    ctx->res    = res;
    ctx->done   = 1;
#ifdef _WIN32
    WakeConditionVariable(&ctx->cond);
    LeaveCriticalSection(&ctx->lock);
#else
    pthread_cond_signal(&ctx->cond);
    pthread_mutex_unlock(&ctx->lock);
#endif
    return 0;
}

/* Resolve host:port_str with a hard wall-clock bound of timeout_ms. On
 * success returns 0 and *out_res is the resolved list (caller still owns
 * it and must freeaddrinfo() it). On timeout, allocation failure, or
 * resolution failure, returns -1 and *out_res is NULL. */
static int dns_resolve_bounded(const char *host, const char *port_str,
                                uint32_t timeout_ms, struct addrinfo **out_res)
{
    *out_res = NULL;

    dns_resolve_ctx_t *ctx = (dns_resolve_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return -1;
    ctx->host     = strdup(host);
    ctx->port_str = strdup(port_str);
    if (!ctx->host || !ctx->port_str) {
        free(ctx->host); free(ctx->port_str); free(ctx);
        return -1;
    }

#ifdef _WIN32
    InitializeCriticalSection(&ctx->lock);
    InitializeConditionVariable(&ctx->cond);
    HANDLE h = CreateThread(NULL, 0, dns_resolve_thread, ctx, 0, NULL);
    if (!h) { dns_resolve_ctx_free(ctx); return -1; }
    CloseHandle(h); /* detach — result comes back via ctx->lock/cond, not a join */
#else
    pthread_mutex_init(&ctx->lock, NULL);
    pthread_cond_init(&ctx->cond, NULL);
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int spawn_rc = pthread_create(&tid, &attr, dns_resolve_thread, ctx);
    pthread_attr_destroy(&attr);
    if (spawn_rc != 0) { dns_resolve_ctx_free(ctx); return -1; }
#endif

#ifdef _WIN32
    EnterCriticalSection(&ctx->lock);
    uint64_t deadline = now_ns() + (uint64_t)timeout_ms * 1000000ULL;
    while (!ctx->done) {
        uint64_t now = now_ns();
        if (now >= deadline) break;
        DWORD remaining_ms = (DWORD)((deadline - now) / 1000000ULL);
        if (remaining_ms == 0) remaining_ms = 1;
        SleepConditionVariableCS(&ctx->cond, &ctx->lock, remaining_ms);
    }
    if (!ctx->done) {
        ctx->abandoned = 1;
        LeaveCriticalSection(&ctx->lock);
        return -1; /* dns_resolve_thread frees ctx once it eventually returns */
    }
    int gai_rc = ctx->gai_rc;
    struct addrinfo *res = ctx->res;
    LeaveCriticalSection(&ctx->lock);
    dns_resolve_ctx_free(ctx);
#else
    pthread_mutex_lock(&ctx->lock);
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec  += (time_t)(timeout_ms / 1000);
    deadline.tv_nsec += (long)((timeout_ms % 1000) * 1000000L);
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec  += 1;
        deadline.tv_nsec -= 1000000000L;
    }
    int wait_rc = 0;
    while (!ctx->done && wait_rc == 0)
        wait_rc = pthread_cond_timedwait(&ctx->cond, &ctx->lock, &deadline);
    if (!ctx->done) {
        ctx->abandoned = 1;
        pthread_mutex_unlock(&ctx->lock);
        return -1; /* dns_resolve_thread frees ctx once it eventually returns */
    }
    int gai_rc = ctx->gai_rc;
    struct addrinfo *res = ctx->res;
    pthread_mutex_unlock(&ctx->lock);
    dns_resolve_ctx_free(ctx);
#endif

    if (gai_rc != 0 || !res) return -1;
    *out_res = res;
    return 0;
}

static int connect_with_timeout(mbedtls_net_context *net,
                                 const char *host, const char *port_str,
                                 uint32_t timeout_ms)
{
    if (timeout_ms == 0)
        return mbedtls_net_connect(net, host, port_str, MBEDTLS_NET_PROTO_TCP);

#ifdef _WIN32
    ensure_wsa_started();
#endif

    struct addrinfo *res = NULL, *ai;

    if (dns_resolve_bounded(host, port_str, timeout_ms, &res) != 0 || !res)
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
    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, rng);

    if (alpn_protos) {
        if (mbedtls_ssl_conf_alpn_protocols(conf, alpn_protos) != 0)
            return VW_ERR_NET_TLS;
    }
    return VW_OK;
}

#ifndef _WIN32
/*
 * TASK-00296 (Linux/POSIX): load the OS trust store (NOT a project-pinned
 * PEM) into chain, for vw_net_connect_generic()'s
 * VW_CERT_VERIFY_SYSTEM_STORE path — outbound connections to a public,
 * non-VaporWault-controlled host (the client auto-update feature's only
 * current caller). Returns 0 on success, nonzero on failure.
 *
 * Deliberately reads the LIVE OS trust store on every call rather than
 * embedding a fixed, project-pinned root set: a public CDN's chain can
 * rotate roots/intermediates over this key's lifetime, and a hardcoded
 * set would silently bit-rot into hard-to-diagnose update-check failures
 * years later. Same guarantee a browser gets from the OS keeping its own
 * trust store current.
 *
 * Windows does NOT use this function — see win32_verify_cert_cb below for
 * why the same "parse every store cert into one mbedtls_x509_crt chain"
 * strategy doesn't work there.
 */
/* load_pem_file() (defined below, used throughout this file for the
 * server's own cert/key loading) is reused here too — buffer-based, not
 * mbedtls_x509_crt_parse_file(), since this project deliberately avoids
 * requiring MBEDTLS_FS_IO (see vw_smtp.c's own smtp_load_pem for the same
 * convention). Forward-declared since its real definition comes later in
 * this file, after load_system_ca_chain's own callers. */
static vw_err_t load_pem_file(const char *path, unsigned char **out_buf, size_t *out_len);

static int load_system_ca_chain(mbedtls_x509_crt *chain) {
    /* Standard system CA bundle locations across common Linux
     * distributions (Debian/Ubuntu, RHEL/Fedora, Alpine/others) — same
     * approach curl and other minimal C tools use, no new dependency. */
    static const char *candidates[] = {
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    };
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        unsigned char *buf = NULL; size_t buflen = 0;
        if (load_pem_file(candidates[i], &buf, &buflen) != VW_OK) continue;
        int ok = (mbedtls_x509_crt_parse(chain, buf, buflen) >= 0); /* >=0: at least one cert parsed */
        free(buf);
        if (ok) return 0;
    }
    return -1;
}
#endif /* !_WIN32 */

#ifdef _WIN32
/*
 * TASK-00296 (Windows): a fixed, self-signed, VaporWault-internal
 * placeholder certificate — NOT a real CA, never matches any real peer's
 * chain — loaded purely to satisfy mbedTLS's TLS 1.3 client code, which
 * hard-requires a non-empty ca_chain to exist whenever authmode is
 * REQUIRED (independent of whether a verify callback is also registered).
 * See the VW_CERT_VERIFY_SYSTEM_STORE branch below for how the real trust
 * decision is made instead (win32_verify_cert_cb, via Windows' own chain
 * engine) — this placeholder grants no trust by itself.
 */
static const char VW_NET_PLACEHOLDER_CA_PEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBiDCCAS+gAwIBAgIUOw4bN+Qy08iH92/Z1kabLuEvRL8wCgYIKoZIzj0EAwIw\n"
    "GjEYMBYGA1UEAwwPVmFwb3JXYXVsdCBUZXN0MB4XDTI2MDcwNzA5NTkzOVoXDTM2\n"
    "MDcwNDA5NTkzOVowGjEYMBYGA1UEAwwPVmFwb3JXYXVsdCBUZXN0MFkwEwYHKoZI\n"
    "zj0CAQYIKoZIzj0DAQcDQgAEBzR5n+n1kbN6f2goisc6aFUwkdNbxwGqXJ3yO3ra\n"
    "cWQ/eUC+wivPwa0nLByWqF5WcAJgyP/mk38QgzCn9Xd7EaNTMFEwHQYDVR0OBBYE\n"
    "FDZWT/P4PsQJMxNdcpFZSalt59sKMB8GA1UdIwQYMBaAFDZWT/P4PsQJMxNdcpFZ\n"
    "Salt59sKMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgWLzqbWKg\n"
    "aDH/Ml+h9ShTBu1Nk2MDdW0rwKU1xJRKfHUCIDbD63boc0KQ+VV07cNm/fJdXnk5\n"
    "5NO/rLH3Clxrw7G+\n"
    "-----END CERTIFICATE-----\n";

/*
 * TASK-00296 (Windows): verify the peer's certificate against the Windows
 * trust store using Windows' OWN chain-building/verification engine
 * (CertGetCertificateChain + CertVerifyCertificateChainPolicy), instead of
 * enumerating every cert in the "ROOT" store and handing them to mbedTLS's
 * own X.509 engine as a ca_chain.
 *
 * That enumerate-everything approach was tried first and empirically
 * fails: the Windows ROOT store holds a large, heterogeneous mix of CAs
 * accumulated over the OS's lifetime, and mbedTLS's certificate-chain
 * verification walk can hard-abort the ENTIRE handshake — not just skip
 * one unusable anchor — the moment it touches a stored certificate whose
 * signature algorithm its own OID table doesn't recognize
 * (MBEDTLS_ERR_X509_INVALID_ALG "unsupported OID" was reproduced live
 * against a real github.com connection during this task's manual
 * verification pass, immediately after WSAStartup and DNS/connect were
 * fixed — not theoretical). Using Windows' own, natively-maintained
 * verification engine sidesteps this entirely: it never needs to hand
 * mbedTLS a store certificate to parse at all, and is the same class of
 * mechanism other cross-platform tools use to validate TLS peers against
 * the OS store on Windows rather than fighting a foreign X.509 stack.
 *
 * Registered via mbedtls_ssl_conf_verify() instead of
 * mbedtls_ssl_conf_ca_chain() — no ca_chain is configured on Windows at
 * all, so mbedTLS's own internal path-building always marks every
 * candidate untrusted; this callback is the sole source of trust.
 */
static int win32_verify_cert_cb(void *p_vrfy, mbedtls_x509_crt *crt,
                                 int depth, uint32_t *flags) {
    if (depth != 0) {
        /* Only the leaf (depth 0) is evaluated — CertGetCertificateChain
         * builds its own path to a trusted root using Windows' own
         * store/AIA fetching from just the leaf, so intermediate/root
         * certs the peer sent need no separate check here. Clear
         * whatever mbedTLS's own CA-chain-less internal walk set for
         * this depth; the leaf-depth verdict below is authoritative. */
        *flags = 0;
        return 0;
    }

    const wchar_t *hostname_w = (const wchar_t *)p_vrfy;
    int trusted = 0;

    PCCERT_CONTEXT leaf = CertCreateCertificateContext(
        X509_ASN_ENCODING, crt->raw.p, (DWORD)crt->raw.len);
    if (leaf) {
        CERT_CHAIN_PARA chain_para;
        memset(&chain_para, 0, sizeof(chain_para));
        chain_para.cbSize = sizeof(chain_para);

        PCCERT_CHAIN_CONTEXT chain_ctx = NULL;
        BOOL got_chain = CertGetCertificateChain(
            NULL, leaf, NULL, NULL, &chain_para,
            0, /* deliberately no online revocation check — see the
                  function-level comment on why */
            NULL, &chain_ctx);

        if (got_chain && chain_ctx) {
            SSL_EXTRA_CERT_CHAIN_POLICY_PARA extra;
            memset(&extra, 0, sizeof(extra));
            extra.cbSize = sizeof(extra);
            extra.dwAuthType = AUTHTYPE_SERVER;
            extra.pwszServerName = (wchar_t *)hostname_w;

            CERT_CHAIN_POLICY_PARA policy_para;
            memset(&policy_para, 0, sizeof(policy_para));
            policy_para.cbSize = sizeof(policy_para);
            policy_para.pvExtraPolicyPara = &extra;

            CERT_CHAIN_POLICY_STATUS policy_status;
            memset(&policy_status, 0, sizeof(policy_status));
            policy_status.cbSize = sizeof(policy_status);

            if (CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain_ctx,
                                                  &policy_para, &policy_status) &&
                policy_status.dwError == 0) {
                trusted = 1;
            }
            CertFreeCertificateChain(chain_ctx);
        }
        CertFreeCertificateContext(leaf);
    }

    *flags = trusted ? 0 : MBEDTLS_X509_BADCERT_NOT_TRUSTED;
    return 0; /* the callback itself never hard-fails; trust is conveyed via *flags */
}
#endif /* _WIN32 */

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

    /* Finite recv timeout during handshake — prevents deadlock if the client
     * never sends data. Reset to 0 after so data-phase reads are unaffected. */
    vw_recv_timeout_store(&conn->recv_timeout_ms, 10000u);

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
    vw_recv_timeout_store(&conn->recv_timeout_ms, 0u);

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

/*
 * TASK-251: vw_net_accept() (below) calls mbedtls_net_accept() with no
 * timeout — a genuinely blocking accept() on the listening socket. A
 * shutdown request only sets a flag the accept loop checks *after*
 * accept() returns, so with no client actively connecting, the server
 * never notices it should stop at all: confirmed for real, a plain TCP
 * connect to the listen port immediately unblocked an otherwise-stuck
 * shutdown. This closes the listening socket's underlying fd directly
 * (shutdown()+close(), the standard technique for interrupting a peer
 * thread blocked in accept() on that same socket) so the pending
 * mbedtls_net_accept() call fails immediately and the accept loop's
 * existing `if (accept_err == VW_ERR_NET_CONNECT) break;` handles the
 * rest — no new shutdown path needed. Sets ctx->listen_net.fd = -1
 * afterward so the later mbedtls_net_free() (via vw_net_ctx_close(),
 * called once the accept loop has already exited) is a safe no-op for
 * this socket instead of operating on an already-closed fd number.
 */
void vw_net_ctx_interrupt_listener(vw_net_ctx_t *ctx) {
    if (!ctx) return;
    int fd = ctx->listen_net.fd;
    if (fd == -1) return;
#ifdef _WIN32
    shutdown(fd, SD_BOTH);
    closesocket(fd);
#else
    shutdown(fd, SHUT_RDWR);
    close(fd);
#endif
    ctx->listen_net.fd = -1;
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

static vw_err_t net_connect_impl(const char *host, uint16_t port,
                                  vw_cert_verify_t verify,
                                  const char *ca_cert_pem_path,
                                  const vw_conn_opts_t *opts,
                                  const char **alpn_protos,
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
                                alpn_protos) != VW_OK)
        goto fail;
    if (verify == VW_CERT_VERIFY_NONE) {
        mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_NONE);
    } else if (verify == VW_CERT_VERIFY_SYSTEM_STORE) {
        mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        diag_step = 3;
#ifdef _WIN32
        /* mbedTLS's TLS 1.3 client code hard-requires SOME ca_chain
         * object to exist when authmode is REQUIRED — with none
         * configured at all it fails outright ("No CA Chain is set, but
         * required to operate") before win32_verify_cert_cb ever runs.
         * VW_NET_PLACEHOLDER_CA_PEM below is loaded purely to satisfy
         * that structural requirement; it can never actually match a
         * real peer's chain (it's a fixed, VaporWault-internal
         * self-signed test cert, not a real CA), so it grants no trust
         * by itself. The verify callback unconditionally OVERWRITES
         * *flags (not ORs into it) based on Windows' own
         * CertVerifyCertificateChainPolicy verdict — the placeholder's
         * own non-match is irrelevant to the actual trust decision. */
        if ((diag_rc = mbedtls_x509_crt_parse(&tls->ca_cert,
                (const unsigned char *)VW_NET_PLACEHOLDER_CA_PEM,
                sizeof(VW_NET_PLACEHOLDER_CA_PEM))) != 0)
            goto fail;
        tls->ca_loaded = 1;
        mbedtls_ssl_conf_ca_chain(&tls->conf, &tls->ca_cert, NULL);

        if (MultiByteToWideChar(CP_UTF8, 0, host, -1,
                                 tls->hostname_w,
                                 (int)(sizeof(tls->hostname_w) / sizeof(wchar_t))) == 0) {
            diag_rc = -1;
            goto fail;
        }
        mbedtls_ssl_conf_verify(&tls->conf, win32_verify_cert_cb, tls->hostname_w);
#else
        if ((diag_rc = load_system_ca_chain(&tls->ca_cert)) != 0) goto fail;
        tls->ca_loaded = 1;
        mbedtls_ssl_conf_ca_chain(&tls->conf, &tls->ca_cert, NULL);
#endif
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

    /* Set a finite recv timeout so the handshake cannot block indefinitely.
     * conn->recv_timeout_ms starts at 0 (= infinite) which deadlocks if the
     * peer never sends data (e.g. a non-TLS service is listening on the port).
     * Reset to 0 after the handshake so data-phase reads are unaffected. */
    vw_recv_timeout_store(&conn->recv_timeout_ms, 10000u);

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
    vw_recv_timeout_store(&conn->recv_timeout_ms, 0u);

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

vw_err_t vw_net_connect(const char *host, uint16_t port,
                         vw_cert_verify_t verify,
                         const char *ca_cert_pem_path,
                         const vw_conn_opts_t *opts,
                         vw_conn_t **out_conn) {
    return net_connect_impl(host, port, verify, ca_cert_pem_path, opts,
                             VW_ALPN_CLIENT, out_conn);
}

vw_err_t vw_net_connect_generic(const char *host, uint16_t port,
                                 vw_cert_verify_t verify,
                                 const char *ca_cert_pem_path,
                                 const vw_conn_opts_t *opts,
                                 vw_conn_t **out_conn) {
    return net_connect_impl(host, port, verify, ca_cert_pem_path, opts,
                             NULL /* no ALPN */, out_conn);
}

vw_err_t vw_net_connect_cluster(const char *host, uint16_t port,
                                 vw_cert_verify_t verify,
                                 const char *ca_cert_pem_path,
                                 const vw_conn_opts_t *opts,
                                 vw_conn_t **out_conn) {
    return net_connect_impl(host, port, verify, ca_cert_pem_path, opts,
                             VW_ALPN_CLUSTER, out_conn);
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
