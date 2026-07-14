#ifndef VW_SMTP_H
#define VW_SMTP_H

#include "../core/vw_proto.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VW_SMTP_TLS_NONE      = 0,   /* plaintext (port 25) */
    VW_SMTP_TLS_STARTTLS  = 1,   /* STARTTLS upgrade (port 587) */
    VW_SMTP_TLS_SMTPS     = 2,   /* implicit TLS from connect (port 465) */
} vw_smtp_tls_t;

typedef struct {
    char           host[256];
    uint16_t       port;
    char           username[256];
    char           password[256];
    /* from_addr must be a bare addr-spec (user@example.com) with no angle brackets,
     * CR, LF, or whitespace. Validated on every vw_smtp_send call. */
    char           from_addr[256];
    /* from_name must not contain double-quote, backslash, CR, or LF. */
    char           from_name[128];
    vw_smtp_tls_t  tls_mode;
    /* verify_cert=1: TLS peer authentication enabled; ca_cert_path must be set.
     * verify_cert=0: skip verification (testing only). */
    int            verify_cert;
    /* Path to PEM CA bundle used when verify_cert=1. Ignored when verify_cert=0. */
    char           ca_cert_path[256];
} vw_smtp_cfg_t;

/*
 * Validate cfg for obvious misconfiguration errors. Call at server startup
 * before accepting any connections. Returns VW_OK or VW_ERR_INVALID_ARG;
 * out_err_msg (may be NULL; err_sz bytes) receives a human-readable
 * description of the first problem found.
 */
vw_err_t vw_smtp_validate_cfg(const vw_smtp_cfg_t *cfg,
                               char *out_err_msg, size_t err_sz);

/* Send a plain-text email.
 * On error, out_err_msg (may be NULL) receives a human-readable description.
 * Returns VW_ERR_NET_CONNECT if TCP fails, VW_ERR_NET_TLS if TLS fails,
 * VW_ERR_IO if the SMTP server returns a non-2xx response. */
vw_err_t vw_smtp_send(const vw_smtp_cfg_t *cfg,
                        const char *to_addr,
                        const char *subject,
                        const char *body_text,
                        char *out_err_msg,
                        size_t err_msg_size);

#ifdef __cplusplus
}
#endif
#endif /* VW_SMTP_H */
