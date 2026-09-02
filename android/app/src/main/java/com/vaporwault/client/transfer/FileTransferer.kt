package com.vaporwault.client.transfer

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.documentfile.provider.DocumentFile
import com.vaporwault.client.CommitResult
import com.vaporwault.client.VwClient
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.security.MessageDigest

/** Matches src/core/vw_proto.h's VW_CHUNK_SIZE_DEFAULT (4 MiB) — not
 * required to match exactly (a smaller chunk size would still work, just
 * less network-efficient), but there's no reason to pick a different
 * number than the server's own default. */
private const val CHUNK_SIZE = 4 * 1024 * 1024
private const val HASH_BYTES = 32

/** Which of vw_client_file_commit_raw's three modes (see
 * vw_jni_bridge.h's nativeFileCommit doc / VwClient.commitFile) an upload
 * targets. */
sealed class UploadTarget {
    data class NewFile(val virtualPath: String) : UploadTarget()
    data class NewVersion(val fileId: Long) : UploadTarget()
    data class NewInFolder(val folderFileId: Long, val leafName: String) : UploadTarget()
}

data class BatchResult(val succeeded: Int, val failed: Int)

/**
 * Chunked upload/download over [VwClient] + Storage Access Framework
 * [Uri]s (TASK-228). Streams directly between the SAF stream and the
 * network, chunk by chunk, with **no intermediate private-cache file**:
 * the existing chunk-upload-if-missing/chunk-download primitives
 * (TASK-226) already make each chunk resumable server-side (CHUNK_QUERY
 * dedup), so re-reading the same SAF source from the start after an
 * interruption naturally re-skips whatever the server already has — that
 * property doesn't need a local staging copy to get, unlike what the
 * desktop client's own local-path convenience wrappers rely on. This is a
 * deliberate simplification versus TASK-224's original sketch (which
 * assumed staging through the app's private cache dir); the raw
 * chunk-buffer primitives TASK-226 actually built make that
 * staging step unnecessary.
 *
 * Vault/E2EE content is out of scope here — [downloadFile] refuses a
 * version with `vault_id != 0` (TASK-230's job).
 */
class FileTransferer(private val context: Context, private val client: VwClient) {

    /** Uploads [sourceUri] to [target]. [onProgress] reports bytes read
     * from the source so far / total size (-1 total if unknown — SAF
     * doesn't always expose a size). Returns null on any failure — call
     * [VwClient.lastError] for the last native call's reason, though a
     * local read/stream-open failure has no vw_err_t to report. */
    fun uploadFile(sourceUri: Uri, target: UploadTarget, onProgress: (Long, Long) -> Unit): CommitResult? {
        val totalSize = queryUriSize(sourceUri) ?: -1L
        val hashesOut = ByteArrayOutputStream()
        val digest = MessageDigest.getInstance("SHA-256")
        val readBuf = ByteArray(CHUNK_SIZE)
        val directBuf = ByteBuffer.allocateDirect(CHUNK_SIZE)
        var bytesDone = 0L

        val input = context.contentResolver.openInputStream(sourceUri) ?: return null
        input.use {
            while (true) {
                var filled = 0
                while (filled < readBuf.size) {
                    val n = it.read(readBuf, filled, readBuf.size - filled)
                    if (n < 0) break
                    filled += n
                }
                if (filled == 0) break

                directBuf.clear()
                directBuf.put(readBuf, 0, filled)
                // No flip() needed — the native side reads via
                // GetDirectBufferAddress (the raw base address) plus the
                // explicit `filled` length, never Kotlin's position/limit
                // (see VwClient.kt's chunk-method doc, learned the hard
                // way in TASK-226).

                digest.reset()
                digest.update(readBuf, 0, filled)
                val hash = digest.digest()

                if (client.chunkUploadIfMissing(hash, directBuf, filled) != 0) return null
                hashesOut.write(hash)

                bytesDone += filled
                onProgress(bytesDone, totalSize)

                if (filled < readBuf.size) break // short read == end of stream
            }
        }

        val chunkHashes = hashesOut.toByteArray()
        return when (target) {
            is UploadTarget.NewFile -> client.createFile(target.virtualPath, bytesDone, chunkHashes)
            is UploadTarget.NewVersion -> client.commitNewVersion(target.fileId, bytesDone, chunkHashes)
            is UploadTarget.NewInFolder ->
                client.createFileInFolder(target.folderFileId, target.leafName, bytesDone, chunkHashes)
        }
    }

    /** Downloads file_id's current version to [destUri]. Returns false on
     * any failure (including an encrypted version — vault decrypt is
     * TASK-230's job, not this one). */
    fun downloadFile(fileId: Long, destUri: Uri, onProgress: (Long, Long) -> Unit): Boolean {
        val entry = client.statById(fileId) ?: return false
        val chunks = client.versionChunks(entry.versionId) ?: return false
        if (chunks.vaultId != 0L) return false

        val output = context.contentResolver.openOutputStream(destUri) ?: return false
        val directBuf = ByteBuffer.allocateDirect(CHUNK_SIZE)
        var bytesDone = 0L

        output.use {
            for (i in 0 until chunks.chunkCount) {
                val hash = chunks.hashes.copyOfRange(i * HASH_BYTES, (i + 1) * HASH_BYTES)
                val len = client.chunkDownload(hash, directBuf, CHUNK_SIZE)
                if (len < 0) return false

                // rewind(), not flip() — there is no Kotlin-side put() to
                // flip *from* here either; native wrote directly into the
                // buffer's backing memory without moving Kotlin's tracked
                // position, so this just resets position to 0 for get().
                directBuf.rewind()
                val bytes = ByteArray(len)
                directBuf.get(bytes)
                it.write(bytes)

                bytesDone += len
                onProgress(bytesDone, entry.sizeBytes)
            }
        }
        return bytesDone == entry.sizeBytes
    }

    /** Recursively uploads every file under [sourceTreeUri] (a persisted
     * SAF tree) into [destFolderFileId] (an existing, owned or
     * EDIT-shared remote folder), creating matching remote subfolders as
     * they're encountered. A per-file/per-folder failure is counted, not
     * fatal — the walk continues. */
    fun uploadFolder(sourceTreeUri: Uri, destFolderFileId: Long, onProgress: (String, Long, Long) -> Unit): BatchResult {
        val root = DocumentFile.fromTreeUri(context, sourceTreeUri) ?: return BatchResult(0, 0)
        return uploadFolderRecursive(root, destFolderFileId, onProgress)
    }

    private fun uploadFolderRecursive(
        dir: DocumentFile,
        destFolderFileId: Long,
        onProgress: (String, Long, Long) -> Unit,
    ): BatchResult {
        var ok = 0
        var bad = 0
        for (child in dir.listFiles()) {
            val name = child.name ?: continue
            if (child.isDirectory) {
                val subDirId = client.mkdir(destFolderFileId, name)
                if (subDirId == 0L) {
                    bad++
                    continue
                }
                val sub = uploadFolderRecursive(child, subDirId, onProgress)
                ok += sub.succeeded
                bad += sub.failed
            } else {
                val result = uploadFile(child.uri, UploadTarget.NewInFolder(destFolderFileId, name)) { done, total ->
                    onProgress(name, done, total)
                }
                if (result != null) ok++ else bad++
            }
        }
        return BatchResult(ok, bad)
    }

    /** Recursively downloads [remoteDirFileId]'s contents into
     * [destTreeUri] (a persisted SAF tree), creating matching local
     * subfolders as they're encountered. */
    fun downloadFolder(remoteDirFileId: Long, destTreeUri: Uri, onProgress: (String, Long, Long) -> Unit): BatchResult {
        val destDir = DocumentFile.fromTreeUri(context, destTreeUri) ?: return BatchResult(0, 0)
        return downloadFolderRecursive(remoteDirFileId, destDir, onProgress)
    }

    private fun downloadFolderRecursive(
        remoteDirFileId: Long,
        destDir: DocumentFile,
        onProgress: (String, Long, Long) -> Unit,
    ): BatchResult {
        var ok = 0
        var bad = 0
        val entries = client.listFilesById(remoteDirFileId, recursive = false) ?: return BatchResult(0, 0)
        for (entry in entries) {
            if (entry.entryType == 1) {
                val subDir = destDir.createDirectory(entry.name)
                if (subDir == null) {
                    bad++
                    continue
                }
                val sub = downloadFolderRecursive(entry.fileId, subDir, onProgress)
                ok += sub.succeeded
                bad += sub.failed
            } else {
                val destFile = destDir.createFile("application/octet-stream", entry.name)
                if (destFile == null) {
                    bad++
                    continue
                }
                val success = downloadFile(entry.fileId, destFile.uri) { done, total -> onProgress(entry.name, done, total) }
                if (success) ok++ else bad++
            }
        }
        return BatchResult(ok, bad)
    }

    private fun queryUriSize(uri: Uri): Long? {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.SIZE), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val idx = cursor.getColumnIndex(OpenableColumns.SIZE)
                if (idx >= 0 && !cursor.isNull(idx)) return cursor.getLong(idx)
            }
        }
        return null
    }
}
