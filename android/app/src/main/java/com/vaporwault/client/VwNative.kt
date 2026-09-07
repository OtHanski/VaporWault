package com.vaporwault.client

import java.nio.ByteBuffer

/**
 * Raw 1:1 mirror of the JNI bridge (vw_jni_bridge.c/.h) — every `external
 * fun` here corresponds exactly to one `Java_com_vaporwault_client_VwNative_*`
 * export. This object is intentionally low-level (thread-local last-error,
 * sentinel return values, flat encoded byte[] records); [VwClient] is the
 * ergonomic wrapper built on top of it that application code should
 * actually use — see that file's class doc for the failure-sentinel and
 * record-encoding conventions shared across every method here.
 */
object VwNative {
    init {
        System.loadLibrary("vaporwault_jni")
    }

    // ── Session lifecycle ────────────────────────────────────────────────

    external fun nativeConnect(
        host: String,
        port: Int,
        caCertPemPath: String,
        username: String,
        password: ByteArray,
        otp: String,
    ): Long

    external fun nativeConnectWithHash(
        host: String,
        port: Int,
        caCertPemPath: String,
        username: String,
        authToken: ByteArray,
        otp: String,
    ): Long

    external fun nativeSessionResume(
        host: String,
        port: Int,
        caCertPemPath: String,
        savedToken: ByteArray,
    ): Long

    external fun nativeGetToken(sessionHandle: Long): ByteArray
    external fun nativeUserId(sessionHandle: Long): Long
    external fun nativeExpiresAt(sessionHandle: Long): Long
    external fun nativeIsAdmin(sessionHandle: Long): Boolean
    external fun nativeLastError(): Int
    external fun nativeLogout(sessionHandle: Long)

    // ── File operations ──────────────────────────────────────────────────

    external fun nativeFileList(sessionHandle: Long, virtualPath: String, recursive: Boolean): ByteArray?
    external fun nativeFileListById(sessionHandle: Long, dirFileId: Long, recursive: Boolean): ByteArray?
    external fun nativeFileStat(sessionHandle: Long, virtualPath: String): ByteArray?
    external fun nativeFileStatById(sessionHandle: Long, fileId: Long): ByteArray?
    external fun nativeFileDelete(sessionHandle: Long, virtualPath: String): Int
    external fun nativeFileDeleteById(sessionHandle: Long, fileId: Long): Int
    external fun nativeFileMove(sessionHandle: Long, fileId: Long, newParentDirId: Long, newName: String): Int
    external fun nativeFileMkdir(sessionHandle: Long, newParentDirId: Long, name: String): Long

    // ── Chunked transfer primitives ──────────────────────────────────────

    /** `data` must be a direct [ByteBuffer] (see [java.nio.ByteBuffer.allocateDirect]). */
    external fun nativeChunkUploadIfMissing(sessionHandle: Long, hash: ByteArray, data: ByteBuffer, len: Int): Int

    external fun nativeFileCommit(
        sessionHandle: Long,
        fileId: Long,
        nameOrPath: String,
        logicalSize: Long,
        chunkHashes: ByteArray,
        vaultId: Long,
        wrappedDek: ByteArray?,
    ): LongArray?

    external fun nativeVersionChunksRaw(sessionHandle: Long, versionId: Long): ByteArray?

    /** `out` must be a direct [ByteBuffer] at least `outCapacity` bytes. */
    external fun nativeChunkDownloadRaw(sessionHandle: Long, hash: ByteArray, out: ByteBuffer, outCapacity: Int): Int

    // ── Version history ──────────────────────────────────────────────────

    external fun nativeVersionList(sessionHandle: Long, virtualPath: String): ByteArray?
    external fun nativeVersionListById(sessionHandle: Long, fileId: Long): ByteArray?
    external fun nativeVersionRestore(sessionHandle: Long, virtualPath: String, versionId: Long): Int
    external fun nativeVersionRestoreById(sessionHandle: Long, versionId: Long): Int

    // ── Sharing ───────────────────────────────────────────────────────────

    external fun nativeShareGrant(
        sessionHandle: Long, fileId: Long, targetUsername: String, permission: Int, expiresAt: Long,
    ): Long
    external fun nativeShareRevoke(sessionHandle: Long, shareId: Long): Int
    external fun nativeShareList(sessionHandle: Long, mode: Int): ByteArray?

    external fun nativeLinkCreate(
        sessionHandle: Long, fileId: Long, permission: Int, expiresAt: Long, password: String,
    ): ByteArray?
    external fun nativeLinkRevoke(sessionHandle: Long, shareId: Long): Int
    external fun nativeLinkList(sessionHandle: Long, fileIdFilter: Long): ByteArray?

    // ── Account self-service ──────────────────────────────────────────────

    external fun nativeAccountEmailGet(sessionHandle: Long): String?
    external fun nativeAccountEmailSet(sessionHandle: Long, email: String): String?
    external fun nativeAccount2faGet(sessionHandle: Long): Int
    external fun nativeAccount2faSet(sessionHandle: Long, password: ByteArray, enable: Boolean): Int
    external fun nativeNotifyPrefsGet(sessionHandle: Long): Long
    external fun nativeNotifyPrefsSet(sessionHandle: Long, prefs: Long): Long

    // ── Vault ─────────────────────────────────────────────────────────────

    /** `passphrase` is consumed and zeroed native-side before this returns. */
    external fun nativeVaultSetup(sessionHandle: Long, folderFileId: Long, passphrase: ByteArray): LongArray?
    /** `passphrase` is consumed and zeroed native-side before this returns. */
    external fun nativeVaultUnlock(sessionHandle: Long, vaultId: Long, passphrase: ByteArray): Long
    external fun nativeVaultClose(vaultHandle: Long)
    external fun nativeVaultFolderFileId(vaultHandle: Long): Long
    external fun nativeVaultList(sessionHandle: Long): ByteArray?
    external fun nativeVaultUploadFile(
        vaultHandle: Long, sessionHandle: Long, fileId: Long, leafName: String, localPath: String,
    ): LongArray?
    external fun nativeVaultDownloadFile(
        vaultHandle: Long, sessionHandle: Long, fileId: Long, localPath: String,
    ): Int
}
