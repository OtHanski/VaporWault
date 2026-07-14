#ifndef VW_ACME_H
#define VW_ACME_H

/*
 * vw_acme — ACME v2 automatic TLS certificate renewal.
 *
 * Implements RFC 8555 (ACME v2) against Let's Encrypt (or any compatible CA).
 * DNS-01 challenge is the primary method; HTTP-01 is a file-write-only fallback
 * (operator must serve the file via their own web server on port 80).
 *
 * When acme_cfg.enabled == 0 this module does nothing; all functions return
 * VW_OK immediately with *out_ctx = NULL.
 *
 * POSIX only for Phase 5.  Windows build compiles to stubs.
 */

#include "../core/vw_proto.h"
#include "../core/vw_net.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Configuration ───────────────────────────────────────────────────────── */

typedef struct {
    int      enabled;              /* 0 = manual PEM, 1 = ACME renewal        */
    char     directory[256];       /* ACME directory URL                       */
    char     contact[256];         /* mailto: address for the account          */
    char     domain[256];          /* domain name to certify                   */
    char     account_key[512];     /* EC P-256 account key PEM path            */
    char     dns_hook[512];        /* DNS-01 hook script path (primary)        */
    char     http_root[512];       /* HTTP-01 challenge file root (fallback)   */
    uint32_t renew_days;           /* renew when fewer than this many days left*/
} vw_acme_cfg_t;

/* ── Default values ──────────────────────────────────────────────────────── */

#define VW_ACME_DEFAULT_DIRECTORY \
    "https://acme-v02.api.letsencrypt.org/directory"
#define VW_ACME_DEFAULT_ACCOUNT_KEY \
    "/etc/vapourwaultd/acme_account.key"
#define VW_ACME_DEFAULT_RENEW_DAYS  30u

/* ── Runtime context ─────────────────────────────────────────────────────── */

typedef struct vw_acme_ctx vw_acme_ctx_t;

/*
 * Create an ACME context.  If cfg->enabled == 0 or the platform is Windows,
 * *out_ctx is set to NULL and VW_OK is returned.
 *
 * cert_pem_path and key_pem_path are the output paths that ACME writes the
 * issued certificate and private key to (same paths as the server's TLS files).
 *
 * Loads or generates the EC P-256 account key.  Does NOT perform any network
 * operation; the first renewal check happens when vw_acme_start is called.
 */
vw_err_t vw_acme_ctx_create(const vw_acme_cfg_t *cfg,
                              const char *cert_pem_path,
                              const char *key_pem_path,
                              vw_acme_ctx_t **out_ctx);

/*
 * Release all resources.  Safe to call with ctx == NULL.
 */
void vw_acme_ctx_destroy(vw_acme_ctx_t *ctx);

/*
 * Perform one renewal check synchronously.
 *   - If the cert at cert_pem_path has more than cfg.renew_days remaining,
 *     returns VW_OK without doing anything.
 *   - Otherwise initiates the full ACME order/challenge/CSR/finalize flow.
 *   - On success writes the new cert and key and calls
 *     vw_net_ctx_reload_cert(net_ctx, ...) to hot-swap the certificate.
 *   - net_ctx may be NULL; cert files are still written but no reload occurs.
 */
vw_err_t vw_acme_renew_if_needed(vw_acme_ctx_t *ctx, vw_net_ctx_t *net_ctx);

/*
 * Start the 12-hour background renewal timer thread.
 * Calls vw_acme_renew_if_needed once immediately, then every 12 hours.
 * net_ctx is stored in ctx and used for hot-swapping; may be NULL.
 * No-op if ctx is NULL (ACME disabled).
 */
vw_err_t vw_acme_start(vw_acme_ctx_t *ctx, vw_net_ctx_t *net_ctx);

/*
 * Stop the background renewal thread and wait for it to exit.
 * No-op if ctx is NULL.
 */
void vw_acme_stop(vw_acme_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* VW_ACME_H */
