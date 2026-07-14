/*
 * vw_ddns.c — DNS-01 TXT record provisioning via shell hook.
 */

#include "vw_ddns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Allowed characters in domain labels and ACME tokens (base64url alphabet
 * plus '.', '-').  Prevents shell-injection from ACME server responses. */
static int safe_chars(const char *s) {
    for (; *s; s++) {
        char c = *s;
        if (!isalnum((unsigned char)c) && c != '.' && c != '-' && c != '_')
            return 0;
    }
    return 1;
}

static vw_err_t run_hook(const char *hook_cmd, const char *verb,
                          const char *domain, const char *token)
{
    char cmd[2048];
    int  n;
    if (token)
        n = snprintf(cmd, sizeof(cmd), "%s %s %s %s",
                     hook_cmd, verb, domain, token);
    else
        n = snprintf(cmd, sizeof(cmd), "%s %s %s",
                     hook_cmd, verb, domain);
    if (n < 0 || (size_t)n >= sizeof(cmd)) return VW_ERR_INVALID_ARG;
    return system(cmd) == 0 ? VW_OK : VW_ERR_IO;
}

vw_err_t vw_ddns_set(const char *hook_cmd, const char *domain,
                      const char *token)
{
    if (!hook_cmd || !*hook_cmd || !domain || !*domain || !token || !*token)
        return VW_ERR_INVALID_ARG;
    if (!safe_chars(domain) || !safe_chars(token))
        return VW_ERR_INVALID_ARG;
    return run_hook(hook_cmd, "set", domain, token);
}

vw_err_t vw_ddns_clear(const char *hook_cmd, const char *domain)
{
    if (!hook_cmd || !*hook_cmd || !domain || !*domain)
        return VW_ERR_INVALID_ARG;
    if (!safe_chars(domain))
        return VW_ERR_INVALID_ARG;
    return run_hook(hook_cmd, "clear", domain, NULL);
}
