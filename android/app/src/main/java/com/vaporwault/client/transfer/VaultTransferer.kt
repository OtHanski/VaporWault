package com.vaporwault.client.transfer

import android.content.Context
import android.net.Uri
import com.vaporwault.client.CommitResult
import com.vaporwault.client.VwClient
import com.vaporwault.client.VwVault
import java.io.File

/**
 * Vault-aware counterpart to [FileTransferer] (TASK-230). Unlike the
 * plaintext path, `vw_vault_upload_file`/`_download_file` are single
 * whole-file native calls that take a real POSIX path — they can't be fed
 * a `content://` stream directly the way [FileTransferer] streams chunks
 * one at a time, so this class stages through the app's private cache
 * (`context.cacheDir`, deleted in a `finally` block regardless of outcome)
 * on both sides of the native call. That staged file is plaintext — for an
 * upload it's the same plaintext the user is uploading from (no new
 * exposure); for a download it's the same plaintext the user is about to
 * receive at their chosen destination anyway.
 *
 * No live progress reporting and no mid-transfer cancellation in this
 * first cut — each call is one blocking native call with no callback hook
 * (see `vw_jni_bridge.c`'s `nativeVaultUploadFile` doc for why), a
 * disclosed scope simplification, not an oversight.
 */
class VaultTransferer(private val context: Context, private val client: VwClient, private val vault: VwVault) {

    fun uploadFile(sourceUri: Uri, fileId: Long, leafName: String): CommitResult? {
        val staged = File.createTempFile("vw_vault_up_", ".tmp", context.cacheDir)
        try {
            val copied = context.contentResolver.openInputStream(sourceUri)?.use { input ->
                staged.outputStream().use { output -> input.copyTo(output) }
                true
            } ?: false
            if (!copied) return null
            return vault.uploadFile(client, fileId, leafName, staged.absolutePath)
        } finally {
            staged.delete()
        }
    }

    /** Returns true on success. On failure, call [VwVault.lastError] for why. */
    fun downloadFile(fileId: Long, destUri: Uri): Boolean {
        val staged = File.createTempFile("vw_vault_down_", ".tmp", context.cacheDir)
        try {
            if (vault.downloadFile(client, fileId, staged.absolutePath) != 0) return false
            return context.contentResolver.openOutputStream(destUri)?.use { output ->
                staged.inputStream().use { input -> input.copyTo(output) }
                true
            } ?: false
        } finally {
            staged.delete()
        }
    }
}
