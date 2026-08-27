/*
 * vapourwault-web-gateway — entry point (TASK-131/132).
 *
 * A standalone vw/1 client (sibling of vapourwault-daemon, not a bridge
 * over its IPC) that translates HTTP/JSON requests from a browser
 * frontend into wire-protocol calls against the real VaporWault server.
 * See ARCHITECTURE.md's Web gateway module map / TASK-127's design.
 */

#include "vw_http.h"
#include "vw_gateway_session.h"
#include "vw_gateway_remember.h"
#include "vw_gateway_api.h"
#include "../core/vw_crypto.h"
#include "../core/vw_proto.h"
#include "vw_version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void print_usage(const char *prog) {
    printf("Usage: %s --server-host HOST --server-port PORT --ca-cert PATH "
           "[--listen-host HOST] [--listen-port PORT] [--state-dir DIR]\n"
           "       [--fallback-server-host HOST --fallback-server-port PORT "
           "--fallback-ca-cert PATH]\n\n"
           "  --server-host HOST   VaporWault server to connect to (required)\n"
           "  --server-port PORT   VaporWault server TLS port (required)\n"
           "  --ca-cert PATH       CA cert PEM to verify the server's certificate\n"
           "                       (required - this gateway never disables TLS\n"
           "                       verification, per ARCHITECTURE.md)\n"
           "  --listen-host HOST   Address to bind the HTTP listener on\n"
           "                       (default: 127.0.0.1 - loopback only, see\n"
           "                       ARCHITECTURE.md's Gateway listener bind\n"
           "                       address decision)\n"
           "  --listen-port PORT   Port to bind the HTTP listener on (default: 8080)\n"
           "  --state-dir DIR      Enables \"remember me\" logins (TASK-165):\n"
           "                       persists a small on-disk store of resumable\n"
           "                       session tokens for remember=true logins,\n"
           "                       hardened to this process's own user only. \n"
           "                       Omit to disable the feature entirely (a\n"
           "                       remember=true login is then silently\n"
           "                       treated as session-only).\n"
           "  --fallback-server-host HOST  Optional read-only fallback (TASK-176):\n"
           "                       an already cluster-paired replica of the\n"
           "                       primary above. Used automatically, read-only,\n"
           "                       for new logins if the primary is unreachable.\n"
           "                       All three --fallback-* flags are required\n"
           "                       together, or omit all three (default).\n"
           "  --fallback-server-port PORT  Fallback server TLS port\n"
           "  --fallback-ca-cert PATH      CA cert PEM for the fallback - required\n"
           "                       whenever a fallback is configured, never\n"
           "                       optional or defaulted (same rule as --ca-cert)\n",
           prog);
}

int main(int argc, char **argv) {
    const char *server_host = NULL;
    const char *ca_cert = NULL;
    const char *listen_host = "127.0.0.1";
    const char *state_dir = NULL;
    uint16_t server_port = 0;
    uint16_t listen_port = 8080;
    const char *fallback_host = NULL;
    const char *fallback_ca_cert = NULL;
    uint16_t fallback_port = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("vapourwault-web-gateway %s\n", VW_VERSION_STRING);
            return 0;
        } else if (strcmp(argv[i], "--server-host") == 0 && i + 1 < argc) {
            server_host = argv[++i];
        } else if (strcmp(argv[i], "--server-port") == 0 && i + 1 < argc) {
            server_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--ca-cert") == 0 && i + 1 < argc) {
            ca_cert = argv[++i];
        } else if (strcmp(argv[i], "--listen-host") == 0 && i + 1 < argc) {
            listen_host = argv[++i];
        } else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc) {
            listen_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--state-dir") == 0 && i + 1 < argc) {
            state_dir = argv[++i];
        } else if (strcmp(argv[i], "--fallback-server-host") == 0 && i + 1 < argc) {
            fallback_host = argv[++i];
        } else if (strcmp(argv[i], "--fallback-server-port") == 0 && i + 1 < argc) {
            fallback_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--fallback-ca-cert") == 0 && i + 1 < argc) {
            fallback_ca_cert = argv[++i];
        } else {
            fprintf(stderr, "Unknown argument: %s\n\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (server_host == NULL || server_port == 0 || ca_cert == NULL) {
        fprintf(stderr, "--server-host, --server-port, and --ca-cert are all required.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    /* TASK-176: all three fallback flags together, or none — a partial
     * set is a configuration error, never silently treated as "no
     * fallback" (same convention as TASK-174's CLI flags). */
    int fallback_any = (fallback_host != NULL) || (fallback_port != 0) || (fallback_ca_cert != NULL);
    int fallback_all = (fallback_host != NULL) && (fallback_port != 0) && (fallback_ca_cert != NULL);
    if (fallback_any && !fallback_all) {
        fprintf(stderr,
                "--fallback-server-host, --fallback-server-port, and --fallback-ca-cert "
                "must all be given together, or none of them.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    if (vw_crypto_init() != VW_OK) {
        fprintf(stderr, "vw_crypto_init failed\n");
        return 1;
    }

    vw_gateway_session_pool_t *pool = NULL;
    if (vw_gateway_session_pool_create(&pool) != VW_OK) {
        fprintf(stderr, "failed to create session pool\n");
        vw_crypto_cleanup();
        return 1;
    }

    vw_http_ctx_t *ctx = NULL;
    vw_err_t err = vw_http_listen(listen_host, listen_port, &ctx);
    if (err != VW_OK) {
        fprintf(stderr, "failed to listen on %s:%u (err=%d)\n",
                listen_host, (unsigned)listen_port, (int)err);
        vw_gateway_session_pool_destroy(pool);
        vw_crypto_cleanup();
        return 1;
    }

    /* Remember-me (TASK-165) - entirely opt-in; omitting --state-dir
     * leaves the gateway exactly as before this task. */
    vw_gateway_remember_store_t *remember_store = NULL;
    if (state_dir != NULL) {
        if (vw_gateway_remember_open(state_dir, &remember_store) != VW_OK) {
            fprintf(stderr, "failed to open remember-me store at %s\n", state_dir);
            vw_http_ctx_close(ctx);
            vw_gateway_session_pool_destroy(pool);
            vw_crypto_cleanup();
            return 1;
        }
        vw_gateway_api_set_remember_store(remember_store);
    }

    vw_gateway_server_cfg_t server_cfg;
    server_cfg.server_host = server_host;
    server_cfg.server_port = server_port;
    server_cfg.ca_cert_pem_path = ca_cert;
    server_cfg.fallback_host = fallback_host;
    server_cfg.fallback_port = fallback_port;
    server_cfg.fallback_ca_cert_pem_path = fallback_ca_cert;

    char fallback_desc[128];
    fallback_desc[0] = '\0';
    if (fallback_host != NULL) {
        snprintf(fallback_desc, sizeof(fallback_desc),
                 ", read-only fallback %s:%u", fallback_host, (unsigned)fallback_port);
    }
    printf("vapourwault-web-gateway (protocol v%u) listening on %s:%u, "
           "upstream server %s:%u%s%s\n",
           (unsigned)VW_PROTO_VERSION_CURRENT, listen_host, (unsigned)listen_port,
           server_host, (unsigned)server_port,
           remember_store != NULL ? " (remember-me enabled)" : "",
           fallback_desc);

    time_t last_reap = time(NULL);

    for (;;) {
        vw_http_conn_t *conn = NULL;
        if (vw_http_accept(ctx, &conn) != VW_OK) {
            continue;
        }

        vw_http_request_t req;
        if (vw_http_recv_request(conn, &req) == VW_OK) {
            vw_gateway_dispatch(pool, &server_cfg, &req, conn);
            vw_http_request_free(&req);
        }
        vw_http_conn_close(conn);

        time_t now = time(NULL);
        if (now - last_reap >= 60) {
            vw_gateway_session_reap_idle(pool);
            last_reap = now;
        }
    }
    /* No clean-shutdown signal handling in this MVP (matches the accept
     * loop's own scope: single-threaded, one request at a time, runs
     * until killed) - ctx/pool/remember_store/crypto cleanup would be
     * unreachable code after an infinite loop, so it's not written
     * rather than left dead. */
}
