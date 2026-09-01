package com.vaporwault.client

/**
 * Thin 1:1 wrapper over the JNI bridge (vw_jni_bridge.c) — TASK-225 scope
 * only (connect + login). TASK-226 extends this into the full VwClient
 * surface (file ops, sharing, version history, account self-service); this
 * object exists purely to prove the native toolchain end-to-end first.
 */
object VwNative {
    init {
        System.loadLibrary("vaporwault_jni")
    }

    /**
     * Connect to [host]:[port] and authenticate with [username]/[password].
     * [caCertPemPath] may be empty to use VW_CERT_VERIFY_NONE (test only —
     * never for a real deployment; see ARCHITECTURE.md's gateway precedent).
     *
     * Returns a non-zero native session handle on success, or 0 on failure
     * (call [nativeLastError] for the vw_err_t code).
     */
    external fun nativeConnect(
        host: String,
        port: Int,
        caCertPemPath: String,
        username: String,
        password: ByteArray,
    ): Long

    external fun nativeLastError(): Int

    external fun nativeLogout(sessionHandle: Long)
}
