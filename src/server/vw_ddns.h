#ifndef VW_DDNS_H
#define VW_DDNS_H

/*
 * vw_ddns — DNS-01 TXT record provisioning via a shell hook script.
 *
 * The hook is called as:
 *   <hook_cmd> set   <domain> <keyauth_token>
 *   <hook_cmd> clear <domain>
 *
 * The hook must exit 0 on success.  The server waits for DNS propagation
 * before notifying ACME; the wait duration is the responsibility of the
 * hook (e.g. add a `sleep 30` after the DNS API call).
 *
 * Security: hook_cmd must be an absolute path to an operator-controlled
 * script.  domain and token are validated before being passed to the hook
 * to prevent shell injection from ACME server responses.
 */

#include "../core/vw_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create the _acme-challenge.<domain> TXT record by calling:
 *   hook_cmd set <domain> <token>
 *
 * token is the ACME keyAuthorization value.
 * Returns VW_ERR_INVALID_ARG if any argument is NULL/empty or if
 * domain or token contain characters outside [A-Za-z0-9._-].
 * Returns VW_ERR_IO if the hook exits non-zero.
 */
vw_err_t vw_ddns_set(const char *hook_cmd, const char *domain,
                      const char *token);

/*
 * Remove the _acme-challenge.<domain> TXT record by calling:
 *   hook_cmd clear <domain>
 *
 * Returns VW_ERR_IO if the hook exits non-zero.
 */
vw_err_t vw_ddns_clear(const char *hook_cmd, const char *domain);

#ifdef __cplusplus
}
#endif

#endif /* VW_DDNS_H */
