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
#include "vw_gateway_api.h"
#include "../core/vw_crypto.h"
#include "../core/vw_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void print_usage(const char *prog) {
    printf("Usage: %s --server-host HOST --server-port PORT --ca-cert PATH "
           "[--listen-host HOST] [--listen-port PORT]\n\n"
           "  --server-host HOST   VaporWault server to connect to (required)\n"
           "  --server-port PORT   VaporWault server TLS port (required)\n"
           "  --ca-cert PATH       CA cert PEM to verify the server's certificate\n"
           "                       (required - this gateway never disables TLS\n"
           "                       verification, per ARCHITECTURE.md)\n"
           "  --listen-host HOST   Address to bind the HTTP listener on\n"
           "                       (default: 127.0.0.1 - loopback only, see\n"
           "                       ARCHITECTURE.md's Gateway listener bind\n"
           "                       address decision)\n"
           "  --listen-port PORT   Port to bind the HTTP listener on (default: 8080)\n",
           prog);
}

int main(int argc, char **argv) {
    const char *server_host = NULL;
    const char *ca_cert = NULL;
    const char *listen_host = "127.0.0.1";
    uint16_t server_port = 0;
    uint16_t listen_port = 8080;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
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

    vw_gateway_server_cfg_t server_cfg;
    server_cfg.server_host = server_host;
    server_cfg.server_port = server_port;
    server_cfg.ca_cert_pem_path = ca_cert;

    printf("vapourwault-web-gateway (protocol v%u) listening on %s:%u, "
           "upstream server %s:%u\n",
           (unsigned)VW_PROTO_VERSION_CURRENT, listen_host, (unsigned)listen_port,
           server_host, (unsigned)server_port);

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
     * until killed) - ctx/pool/crypto cleanup would be unreachable code
     * after an infinite loop, so it's not written rather than left dead. */
}
