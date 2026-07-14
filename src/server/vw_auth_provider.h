#ifndef VW_AUTH_PROVIDER_H
#define VW_AUTH_PROVIDER_H

/*
 * vw_auth_provider — abstract 2FA provider interface.
 *
 * Phase 1 uses email OTP generated and delivered directly in vw_auth_begin_login.
 * This interface is scaffolding for Phase 2 extensibility (TOTP apps, SMS, etc.).
 * Providers are registered at server startup with vw_auth_provider_register and
 * looked up by name via vw_auth_provider_get.
 *
 * The email_otp provider is declared as vw_auth_email_otp_provider; its
 * generate_challenge and verify_response stubs return VW_ERR_NOT_IMPL in Phase 1.
 */

#include "../core/vw_proto.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vw_auth_provider {
    const char *name;

    /*
     * Generate and deliver a challenge to the user (e.g. send an OTP email).
     * out_challenge may be NULL in Phase 1 email-OTP; it exists for TOTP
     * providers that need to return a URI or shared secret display string.
     * The caller is responsible for freeing *out_challenge if non-NULL.
     */
    vw_err_t (*generate_challenge)(const struct vw_auth_provider *self,
                                   uint64_t user_id, const char *to_email,
                                   char **out_challenge);

    /*
     * Verify a user's response against the challenge.
     * Returns VW_OK on success, VW_ERR_AUTH_2FA_INVALID otherwise.
     */
    vw_err_t (*verify_response)(const struct vw_auth_provider *self,
                                const char *challenge,
                                const char *response, uint16_t response_len);
} vw_auth_provider_t;

/*
 * Register a provider. Returns VW_ERR_INVALID_ARG if provider is NULL,
 * has no name, a provider with that name is already registered, or the
 * registry is full (max 8 providers).
 */
vw_err_t vw_auth_provider_register(const vw_auth_provider_t *provider);

/*
 * Look up a registered provider by name. Returns NULL if not found.
 */
const vw_auth_provider_t *vw_auth_provider_get(const char *name);

/*
 * Phase 1 email OTP provider. Stubs only — the actual OTP flow lives in
 * vw_auth_begin_login / vw_auth_verify_2fa for Phase 1.
 * Register at startup to satisfy future TASK-011 provider lookups.
 */
extern const vw_auth_provider_t vw_auth_email_otp_provider;

#ifdef __cplusplus
}
#endif

#endif /* VW_AUTH_PROVIDER_H */
