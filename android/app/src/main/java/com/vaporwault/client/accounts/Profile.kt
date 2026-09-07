package com.vaporwault.client.accounts

/**
 * One saved account profile's non-secret metadata. Host/port/username are
 * already known to the user — nothing here needs encryption; only the
 * session/login tokens in [ProfileStore]'s per-profile `.cred` files do.
 */
data class Profile(
    val id: String,
    val label: String,
    val host: String,
    val port: Int,
    val caCertPemPath: String, // "" = VW_CERT_VERIFY_NONE (test only)
    val username: String,
)
