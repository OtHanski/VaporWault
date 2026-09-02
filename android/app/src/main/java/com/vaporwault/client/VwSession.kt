package com.vaporwault.client

import com.vaporwault.client.accounts.Profile

/**
 * Holds the currently-active [VwClient] + [Profile] for the life of the
 * app process — a plain singleton, not a persisted or process-surviving
 * concept (the native session handle inside [VwClient] couldn't survive
 * process death anyway; [com.vaporwault.client.accounts.VwAccountRegistry]
 * is what re-establishes a session on a fresh launch via [Profile.id]).
 */
object VwSession {
    var client: VwClient? = null
        private set
    var profile: Profile? = null
        private set

    fun set(client: VwClient, profile: Profile) {
        this.client?.takeIf { it !== client }?.close()
        this.client = client
        this.profile = profile
    }

    fun clear() {
        client?.close()
        client = null
        profile = null
    }
}
