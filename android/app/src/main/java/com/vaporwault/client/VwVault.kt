package com.vaporwault.client

import com.vaporwault.client.accounts.secureZero
import java.nio.CharBuffer
import java.util.Arrays

/**
 * Ergonomic wrapper over an unlocked vault's native handle (TASK-230) — the
 * vault-scoped analogue of [VwClient] for a session. Every method here
 * needs the owning [VwClient] alongside this handle since the underlying
 * `vw_vault_*` C functions take both a `vw_vault_t*` and a
 * `vw_client_sess_t*` (the vault owns the VK; the session does the actual
 * network I/O — see `vw_vault.h`'s header comment for why they're kept
 * separate rather than one function owning both).
 *
 * **Passphrase handling**: every entry point here takes the Encryption
 * Passphrase as a [CharArray], never a [String] — a JVM `String` is
 * interned/immutable and cannot be reliably zeroed, so a secret that ever
 * touches one lingers in memory for an indeterminate time after use. Callers
 * must build the [CharArray] directly from an `EditText`'s `Editable`
 * (`editable.getChars(0, editable.length, chars, 0)`), never via
 * `editable.toString().toCharArray()`, and must zero it themselves after
 * calling into this class — [setup]/[unlock] zero their own UTF-8-encoded
 * copy before returning, but do not and cannot reach back into the caller's
 * original [CharArray].
 */
class VwVault private constructor(vaultHandle: Long, val vaultId: Long) : AutoCloseable {

    private var handleField: Long = vaultHandle
    private val handle: Long
        get() = if (handleField != 0L) handleField
                else error("VwVault method called after close()")

    /** The folder this vault covers — resolved once and cached; a vault's
     * folder never changes for the lifetime of a handle. */
    val folderFileId: Long by lazy { VwNative.nativeVaultFolderFileId(handle) }

    /**
     * Encrypt localPath (a real POSIX path — see `VaultTransferer`, never a
     * `content://` URI directly) and upload it into this vault's folder.
     * fileId == 0 creates a new file named leafName; fileId != 0 uploads a
     * new version of that existing (vault-owned) file.
     */
    fun uploadFile(client: VwClient, fileId: Long, leafName: String, localPath: String): CommitResult? =
        VwNative.nativeVaultUploadFile(handle, client.rawHandle(), fileId, leafName, localPath)
            ?.let { CommitResult(fileId = it[0], versionId = it[1]) }

    /** Download and decrypt fileId's current version into localPath (a real
     * POSIX path the caller then copies to the user's chosen destination).
     * Returns 0 (VW_OK) on success. */
    fun downloadFile(client: VwClient, fileId: Long, localPath: String): Int =
        VwNative.nativeVaultDownloadFile(handle, client.rawHandle(), fileId, localPath)

    /** Zeroes the in-memory VK and frees the native handle. Safe to call
     * more than once; every method above throws after this. */
    override fun close() {
        if (handleField != 0L) {
            VwNative.nativeVaultClose(handleField)
            handleField = 0L
        }
    }

    companion object {
        /**
         * Create a brand-new vault for folderFileId (the caller must own
         * it) under [client]'s session, derived from [passphrase] at the
         * SEC.07-pinned Argon2id floor. Returns the open vault (holding the
         * fresh VK) on success, or null on failure — call [lastError] for
         * why. [passphrase] is zeroed by this call before it returns,
         * regardless of outcome.
         */
        fun setup(client: VwClient, folderFileId: Long, passphrase: CharArray): VwVault? {
            val bytes = charsToUtf8Bytes(passphrase)
            val result = VwNative.nativeVaultSetup(client.rawHandle(), folderFileId, bytes)
            secureZero(bytes)
            return result?.let { VwVault(vaultHandle = it[0], vaultId = it[1]) }
        }

        /**
         * Unlock an existing vault (new-device / new-session case) with
         * [passphrase]. Returns null on failure — including a wrong
         * passphrase, distinguishable via `lastError() ==
         * VwClient.ERR_AUTH_BAD_CREDS`. [passphrase] is zeroed by this call
         * before it returns, regardless of outcome.
         */
        fun unlock(client: VwClient, vaultId: Long, passphrase: CharArray): VwVault? {
            val bytes = charsToUtf8Bytes(passphrase)
            val handle = VwNative.nativeVaultUnlock(client.rawHandle(), vaultId, bytes)
            secureZero(bytes)
            return if (handle != 0L) VwVault(handle, vaultId) else null
        }

        /** vw_err_t code from the most recent failed bridge call **on this
         * thread** — same `_Thread_local` footgun as [VwClient.lastError];
         * see that function's doc comment. Capture it on the calling
         * background thread, never from inside `runOnUiThread`. */
        fun lastError(): Int = VwNative.nativeLastError()

        /**
         * UTF-8-encodes [chars] without ever materializing a [String] —
         * `Charset.encode(CharBuffer)` uses a [java.nio.charset.CharsetEncoder]
         * directly, the standard char[]-to-byte[] idiom for secrets on the
         * JVM. The intermediate [java.nio.ByteBuffer]'s backing array is
         * zeroed after copying out the result; [chars] itself is the
         * caller's responsibility (see this class's doc comment).
         */
        private fun charsToUtf8Bytes(chars: CharArray): ByteArray {
            val encoded = Charsets.UTF_8.encode(CharBuffer.wrap(chars))
            val bytes = ByteArray(encoded.remaining())
            encoded.get(bytes)
            if (encoded.hasArray()) Arrays.fill(encoded.array(), 0)
            return bytes
        }
    }
}
