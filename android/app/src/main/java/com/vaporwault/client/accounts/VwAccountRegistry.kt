package com.vaporwault.client.accounts

import android.content.Context
import com.vaporwault.client.VwClient
import java.security.MessageDigest

/**
 * Ties [ProfileStore] and [VwClient] together — the mobile analogue of
 * `vw_daemon.c`'s multi-account model (TASK-227), reimplemented in Kotlin
 * since the daemon's actual C code (fork, round-robin scheduling, IPC
 * dispatch) has no Android equivalent to port. Each profile owns its own
 * independent [VwClient] session handle; there is no shared mutable state
 * between profiles beyond the one AndroidKeyStore master key every
 * profile's credentials happen to be wrapped under ([VwSecureStore] is
 * stateless per call, so that sharing isn't a cross-contamination risk).
 */
class VwAccountRegistry(context: Context) {
    private val store = ProfileStore(context)

    fun listProfiles(): List<Profile> = store.list()

    /**
     * Add a brand-new profile: connect+login with a raw password, then
     * persist the resulting session token and a SHA-256(password) "login
     * token" (never the raw password itself) for future [resume] calls.
     * [password] is zeroed before this returns, regardless of outcome.
     *
     * Returns the new profile and an already-open [VwClient], or null on
     * failure (call [VwClient.lastError] for why).
     */
    fun addProfile(
        label: String,
        host: String,
        port: Int,
        username: String,
        password: ByteArray,
        caCertPemPath: String = "",
        otp: String = "",
    ): Pair<Profile, VwClient>? {
        val client = VwClient.connect(host, port, username, password, caCertPemPath, otp)
        if (client == null) {
            secureZero(password)
            return null
        }

        val loginToken = MessageDigest.getInstance("SHA-256").digest(password)
        secureZero(password)

        val profile = store.create(
            label, host, port, caCertPemPath, username,
            sessionToken = client.token(), loginToken = loginToken, expiresAt = client.expiresAt(),
        )
        secureZero(loginToken)
        return profile to client
    }

    /**
     * Resume a saved profile without ever re-prompting for a password:
     * try [VwClient.resume] with the saved session token first; if that
     * fails (typically the token's natural expiry), fall back to
     * [VwClient.connectWithHash] with the saved login token — the same
     * two-tier fallback the desktop daemon already relies on. Either way,
     * the freshly-issued session token is re-persisted before returning,
     * since a resumed/reconnected token is a fresh single-use replacement
     * (PROTOCOL.md §7.1), never the same bytes handed back.
     *
     * Returns null if the profile doesn't exist, its credentials can't be
     * decrypted, or both the resume and the login-token fallback fail
     * (e.g. the account's password changed server-side) — call
     * [VwClient.lastError] for the last attempt's reason.
     */
    fun resume(profileId: String): VwClient? {
        val profile = store.get(profileId) ?: return null
        val creds = store.readCredentials(profileId) ?: return null

        val client = VwClient.resume(profile.host, profile.port, profile.caCertPemPath, creds.sessionToken)
            ?: VwClient.connectWithHash(
                profile.host, profile.port, profile.username, creds.loginToken, profile.caCertPemPath,
            )

        if (client == null) {
            secureZero(creds.sessionToken)
            secureZero(creds.loginToken)
            return null
        }

        store.writeCredentials(profileId, client.token(), creds.loginToken, client.expiresAt())
        secureZero(creds.sessionToken)
        secureZero(creds.loginToken)
        return client
    }

    fun removeProfile(id: String) = store.remove(id)
}
