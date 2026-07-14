#include "vw_auth_provider.h"

#include <stddef.h>
#include <string.h>

#define MAX_PROVIDERS 8u

static const vw_auth_provider_t *g_providers[MAX_PROVIDERS];
static size_t g_provider_count = 0;

vw_err_t vw_auth_provider_register(const vw_auth_provider_t *provider)
{
    size_t i;
    if (!provider || !provider->name) return VW_ERR_INVALID_ARG;
    for (i = 0; i < g_provider_count; i++) {
        if (strcmp(g_providers[i]->name, provider->name) == 0)
            return VW_ERR_INVALID_ARG;
    }
    if (g_provider_count >= MAX_PROVIDERS) return VW_ERR_INVALID_ARG;
    g_providers[g_provider_count++] = provider;
    return VW_OK;
}

const vw_auth_provider_t *vw_auth_provider_get(const char *name)
{
    size_t i;
    if (!name) return NULL;
    for (i = 0; i < g_provider_count; i++) {
        if (strcmp(g_providers[i]->name, name) == 0)
            return g_providers[i];
    }
    return NULL;
}

/* Phase 1 stubs. The email OTP flow lives directly in vw_auth_begin_login. */
static vw_err_t email_otp_generate(const vw_auth_provider_t *self,
                                    uint64_t user_id, const char *to_email,
                                    char **out_challenge)
{
    (void)self; (void)user_id; (void)to_email; (void)out_challenge;
    return VW_ERR_NOT_IMPL;
}

static vw_err_t email_otp_verify(const vw_auth_provider_t *self,
                                  const char *challenge,
                                  const char *response, uint16_t response_len)
{
    (void)self; (void)challenge; (void)response; (void)response_len;
    return VW_ERR_NOT_IMPL;
}

const vw_auth_provider_t vw_auth_email_otp_provider = {
    "email_otp",
    email_otp_generate,
    email_otp_verify,
};
