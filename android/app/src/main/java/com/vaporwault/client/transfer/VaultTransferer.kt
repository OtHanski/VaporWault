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
 * one at a time, so [downloadFile] stages through the app's private cache
 * (`context.cacheDir`, deleted in a `finally` block regardless of outcome).
 * That staged file is plaintext — for a download it's the same plaintext
 * the user is about to receive at their chosen destination anyway.
 *
 * [uploadFile] no longer stages its own copy (TASK-246 review) — its sole
 * caller, `FileBrowserActivity`, already stages the picked Uri into a
 * local `file://` one before calling this, specifically so the picked
 * Uri's SAF grant never needs to survive to this call at all. Staging it
 * a second time here would double the I/O and peak cache usage for a file
 * that's already sitting in this app's own cache — so a `file://` source
 * is read directly, and only a non-`file` Uri (kept as a defensive
 * fallback, not expected from the current caller) is copied first.
 *
 * No live progress reporting and no mid-transfer cancellation in this
 * first cut — each call is one blocking native call with no callback hook
 * (see `vw_jni_bridge.c`'s `nativeVaultUploadFile` doc for why), a
 * disclosed scope simplification, not an oversight.
 */
class VaultTransferer(private val context: Context, private val client: VwClient, private val vault: VwVault) {

    fun uploadFile(sourceUri: Uri, fileId: Long, leafName: String): CommitResult? {
        if (sourceUri.scheme == "file") {
            val path = sourceUri.path ?: return null
            return vault.uploadFile(client, fileId, leafName, path)
        }
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
