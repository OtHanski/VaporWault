package com.vaporwault.client

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** One FILE_LIST/_STAT entry (vw_file_entry_t). */
data class FileEntry(
    val entryType: Int,   // 0 = file, 1 = dir (VW_ENTRY_FILE/_DIR)
    val fileId: Long,
    val sizeBytes: Long,
    val mtimeUnix: Long,
    val versionId: Long,  // current HEAD version; 0 if directory
    val vaultId: Long,    // 0 = unencrypted or a directory
    val name: String,     // leaf name only
)

/** One SHARE_LIST entry (vw_share_entry_t) — a user-to-user grant or a
 * public link (share_type discriminates); see [LinkEntry] for the
 * link-specific listing, which never includes the raw token. */
data class ShareEntry(
    val shareId: Long,
    val fileId: Long,
    val name: String,           // shared item's leaf name; display-only
    val shareType: Int,         // 0 = user grant, 1 = public link
    val targetUsername: String, // grants only; empty for links
    val permission: Int,        // vw_perm_t: 0=none,1=view,2=edit,3=owner
    val createdAt: Long,
    val expiresAt: Long,        // 0 = never
    val revoked: Boolean,
)

/** One LINK_LIST entry (vw_link_entry_t). Never includes the raw token —
 * that's only ever returned once, by [VwClient.linkCreate]. */
data class LinkEntry(
    val shareId: Long,
    val fileId: Long,
    val name: String,
    val permission: Int,
    val createdAt: Long,
    val expiresAt: Long,
    val revoked: Boolean,
    val hasPassword: Boolean,
)

/** One VERSION_LIST entry (vw_version_entry_t). */
data class VersionEntry(
    val versionId: Long,
    val createdAt: Long,
    val sizeBytes: Long,
)

/** FILE_COMMIT_ACK result. */
data class CommitResult(val fileId: Long, val versionId: Long)

/** VERSION_CHUNKS result: the version's ordered chunk hash list (32 bytes
 * each, concatenated in [hashes]) plus its vault fields — [vaultId] == 0
 * and [wrappedDek] == null for an unencrypted version. */
data class VersionChunks(
    val chunkCount: Int,
    val vaultId: Long,
    val wrappedDek: ByteArray?,
    val hashes: ByteArray,
)

/** LINK_CREATE result. [token] is the raw 32-byte link token — the only
 * time it is ever available; relay it to the user immediately and never
 * persist it, matching the server's own "never re-display" convention
 * (see vw_client_core.h's vw_client_link_create doc). */
data class LinkCreateResult(val shareId: Long, val token: ByteArray)

/** One VAULT_LIST entry (vw_vault_entry_t). Never includes wrapped-key
 * material — [VwVault.unlock] is the only way to actually open one. */
data class VaultEntry(val vaultId: Long, val folderFileId: Long, val createdAt: Long)

/**
 * Ergonomic wrapper over [VwNative]'s raw JNI bridge — the mobile analogue
 * of desktop's `VwGuiIpc` (src/gui/client/vw_gui_ipc.h) relative to
 * `vw_ipc.h`, except calling straight into linked-in native code rather
 * than over a socket to a separate daemon process (there is no separate
 * daemon on Android; this object *is* the client for one authenticated
 * session).
 *
 * Failure convention, uniform across every method below (matching
 * [VwNative]'s own convention): a fetch-shaped method returns null, an
 * action-shaped method returns a nonzero/negative sentinel appropriate to
 * its type. Call [lastError] immediately after a failure to get the
 * vw_err_t code — it reflects the most recent failed bridge call on the
 * current thread, so don't let another bridge call happen in between if
 * you need it.
 *
 * One instance owns one native session handle; [close]/[logout] frees it.
 * Using any method after that throws [IllegalStateException] rather than
 * risking a use-after-free into native code.
 */
class VwClient private constructor(sessionHandle: Long) : AutoCloseable {

    private var handleField: Long = sessionHandle
    private val handle: Long
        get() = if (handleField != 0L) handleField
                else error("VwClient method called after logout()/close()")

    companion object {
        /**
         * Connect and authenticate. [caCertPemPath] empty = VW_CERT_VERIFY_NONE
         * (test only). [otp] empty on the first attempt; if the account has
         * 2FA enabled this returns null with [lastError] ==
         * `VW_ERR_AUTH_2FA_REQUIRED` (301) — prompt the user and call
         * [connect] again with the same arguments plus the code.
         */
        fun connect(
            host: String,
            port: Int,
            username: String,
            password: ByteArray,
            caCertPemPath: String = "",
            otp: String = "",
        ): VwClient? {
            val handle = VwNative.nativeConnect(host, port, caCertPemPath, username, password, otp)
            return if (handle != 0L) VwClient(handle) else null
        }

        /**
         * Reconnect using an already-derived auth_token (SHA-256(password))
         * instead of a raw password — never re-prompts the user. This is
         * how a saved "login token" (see the `accounts` package, TASK-227)
         * resumes a profile when [resume] fails, typically because the
         * session token naturally expired — the same two-tier fallback the
         * desktop daemon's own read-only-fallback connect already relies
         * on. [authToken] must be exactly 32 bytes.
         */
        fun connectWithHash(
            host: String,
            port: Int,
            username: String,
            authToken: ByteArray,
            caCertPemPath: String = "",
            otp: String = "",
        ): VwClient? {
            val handle = VwNative.nativeConnectWithHash(host, port, caCertPemPath, username, authToken, otp)
            return if (handle != 0L) VwClient(handle) else null
        }

        /** Resume a previously-saved session token (single-use — see
         * [VwClient.token]'s doc for what to do with the result). */
        fun resume(host: String, port: Int, caCertPemPath: String, savedToken: ByteArray): VwClient? {
            val handle = VwNative.nativeSessionResume(host, port, caCertPemPath, savedToken)
            return if (handle != 0L) VwClient(handle) else null
        }

        /**
         * vw_err_t code from the most recent failed bridge call **on this
         * thread** — the native slot behind this is `_Thread_local`. Call
         * it on the same background thread that made the failing call,
         * *before* posting to `runOnUiThread`/the main thread — calling it
         * from inside `runOnUiThread` silently reads the main thread's own
         * (untouched, always-`VW_OK`) slot instead and reports `0`
         * regardless of what actually failed. Hit repeatedly across this
         * codebase (`LoginActivity`, `VaultActivity`, `AccountActivity`) —
         * always capture into a `val` on the calling thread first:
         * `val lastError = if (result == null) VwClient.lastError() else 0`
         * then reference that `val` inside `runOnUiThread`.
         */
        fun lastError(): Int = VwNative.nativeLastError()

        const val ERR_AUTH_BAD_CREDS = 300
        const val ERR_AUTH_2FA_REQUIRED = 301
    }

    /** Send AUTH_LOGOUT and free the native session. Safe to call more than
     * once; subsequent calls (and [close]) are then no-ops. */
    fun logout() {
        if (handleField == 0L) return
        VwNative.nativeLogout(handleField)
        handleField = 0L
    }

    override fun close() = logout()

    // ── Session accessors ────────────────────────────────────────────────

    /** Current session token (32 bytes) — persist this after [connect]/
     * [resume] so a future session can call [resume] instead of
     * re-prompting for a password. */
    fun token(): ByteArray = VwNative.nativeGetToken(handle)
    fun userId(): Long = VwNative.nativeUserId(handle)
    fun expiresAt(): Long = VwNative.nativeExpiresAt(handle)
    fun isAdmin(): Boolean = VwNative.nativeIsAdmin(handle)

    // ── File operations ──────────────────────────────────────────────────

    fun listFiles(virtualPath: String, recursive: Boolean = false): List<FileEntry>? =
        VwNative.nativeFileList(handle, virtualPath, recursive)?.let(::decodeFileEntries)

    /** Works for a folder the caller doesn't own but has at least VIEW
     * access to (a share grant) — [listFiles] can't reach that. */
    fun listFilesById(dirFileId: Long, recursive: Boolean = false): List<FileEntry>? =
        VwNative.nativeFileListById(handle, dirFileId, recursive)?.let(::decodeFileEntries)

    fun stat(virtualPath: String): FileEntry? =
        VwNative.nativeFileStat(handle, virtualPath)?.let { leBuffer(it).readFileEntry() }

    fun statById(fileId: Long): FileEntry? =
        VwNative.nativeFileStatById(handle, fileId)?.let { leBuffer(it).readFileEntry() }

    /** Returns vw_err_t (0 = success); VW_ERR_DIR_NOT_EMPTY for a non-empty directory. */
    fun deleteFile(virtualPath: String): Int = VwNative.nativeFileDelete(handle, virtualPath)
    fun deleteFileById(fileId: Long): Int = VwNative.nativeFileDeleteById(handle, fileId)

    /** newParentDirId == 0 means "move to owner's own root"; newName empty keeps the current name. */
    fun moveFile(fileId: Long, newParentDirId: Long, newName: String = ""): Int =
        VwNative.nativeFileMove(handle, fileId, newParentDirId, newName)

    /** newParentDirId == 0 means caller's own root. Returns the new directory's file_id, or 0 on failure. */
    fun mkdir(newParentDirId: Long, name: String): Long = VwNative.nativeFileMkdir(handle, newParentDirId, name)

    // ── Chunked transfer ─────────────────────────────────────────────────
    // Native reads/writes these direct buffers via GetDirectBufferAddress
    // (the raw base address) plus an explicit length — it never reads or
    // advances position()/limit(). Don't flip() a buffer expecting native
    // writes to have moved its position the way a Kotlin-side put() would;
    // there is nothing for flip() to flip to, and doing so leaves an
    // empty [position, limit) region and a BufferUnderflowException on
    // the next get() (found the hard way testing this task's own
    // round-trip smoke test).

    /** `data` must be a direct [ByteBuffer] holding at least `len` chunk
     * bytes. Returns vw_err_t. */
    fun chunkUploadIfMissing(hash: ByteArray, data: ByteBuffer, len: Int): Int =
        VwNative.nativeChunkUploadIfMissing(handle, hash, data, len)

    /** Create a NEW file at an owned virtual path. */
    fun createFile(virtualPath: String, logicalSize: Long, chunkHashes: ByteArray): CommitResult? =
        commitFile(fileId = 0, nameOrPath = virtualPath, logicalSize, chunkHashes)

    /** Commit a new version of an existing file in place. */
    fun commitNewVersion(fileId: Long, logicalSize: Long, chunkHashes: ByteArray): CommitResult? =
        commitFile(fileId, nameOrPath = "", logicalSize, chunkHashes)

    /** Create a new file named [leafName] inside [folderFileId] (which the
     * caller has at least EDIT on — owned or shared). */
    fun createFileInFolder(
        folderFileId: Long, leafName: String, logicalSize: Long, chunkHashes: ByteArray,
    ): CommitResult? = commitFile(fileId = folderFileId, nameOrPath = leafName, logicalSize, chunkHashes)

    /** The general FILE_COMMIT primitive all three convenience methods
     * above call — see vw_jni_bridge.h's nativeFileCommit doc for exactly
     * how file_id/nameOrPath together select which of the three modes
     * applies. vaultId != 0 requires a non-null wrappedDek (TASK-230). */
    fun commitFile(
        fileId: Long,
        nameOrPath: String,
        logicalSize: Long,
        chunkHashes: ByteArray,
        vaultId: Long = 0,
        wrappedDek: ByteArray? = null,
    ): CommitResult? {
        val result = VwNative.nativeFileCommit(
            handle, fileId, nameOrPath, logicalSize, chunkHashes, vaultId, wrappedDek,
        )
        return result?.let { CommitResult(fileId = it[0], versionId = it[1]) }
    }

    fun versionChunks(versionId: Long): VersionChunks? =
        VwNative.nativeVersionChunksRaw(handle, versionId)?.let(::decodeVersionChunks)

    /** `out` must be a direct [ByteBuffer] at least `outCapacity` bytes.
     * Returns the actual byte count written, or -1 on failure. */
    fun chunkDownload(hash: ByteArray, out: ByteBuffer, outCapacity: Int): Int =
        VwNative.nativeChunkDownloadRaw(handle, hash, out, outCapacity)

    // ── Version history ──────────────────────────────────────────────────

    fun listVersions(virtualPath: String): List<VersionEntry>? =
        VwNative.nativeVersionList(handle, virtualPath)?.let(::decodeVersionEntries)

    /** Works for a file the caller doesn't own (a grant target) — [listVersions] can't. */
    fun listVersionsById(fileId: Long): List<VersionEntry>? =
        VwNative.nativeVersionListById(handle, fileId)?.let(::decodeVersionEntries)

    fun restoreVersion(virtualPath: String, versionId: Long): Int =
        VwNative.nativeVersionRestore(handle, virtualPath, versionId)

    fun restoreVersionById(versionId: Long): Int =
        VwNative.nativeVersionRestoreById(handle, versionId)

    // ── Sharing ───────────────────────────────────────────────────────────

    /** permission is a vw_perm_t (0=none,1=view,2=edit,3=owner); expiresAt == 0 means never.
     * Returns the new share_id, or 0 on failure. */
    fun shareGrant(fileId: Long, targetUsername: String, permission: Int, expiresAt: Long = 0): Long =
        VwNative.nativeShareGrant(handle, fileId, targetUsername, permission, expiresAt)

    /** Returns vw_err_t; VW_ERR_PERMISSION if the caller isn't the share's creator. */
    fun shareRevoke(shareId: Long): Int = VwNative.nativeShareRevoke(handle, shareId)

    /** mode: 0 = grants I created, 1 = grants granted to me. */
    fun listShares(mode: Int): List<ShareEntry>? = VwNative.nativeShareList(handle, mode)?.let(::decodeShareEntries)

    /** password empty = none. See [LinkCreateResult]'s doc — the token is
     * never obtainable again after this call returns. */
    fun linkCreate(fileId: Long, permission: Int, expiresAt: Long = 0, password: String = ""): LinkCreateResult? =
        VwNative.nativeLinkCreate(handle, fileId, permission, expiresAt, password)?.let(::decodeLinkCreateResult)

    fun linkRevoke(shareId: Long): Int = VwNative.nativeLinkRevoke(handle, shareId)

    /** fileIdFilter == 0 lists all of them. */
    fun listLinks(fileIdFilter: Long = 0): List<LinkEntry>? =
        VwNative.nativeLinkList(handle, fileIdFilter)?.let(::decodeLinkEntries)

    // ── Account self-service ──────────────────────────────────────────────

    /** Returns the address ("" = none on file), or null on failure. */
    fun getEmail(): String? = VwNative.nativeAccountEmailGet(handle)

    /** email == "" clears it. Returns the stored value on success. */
    fun setEmail(email: String): String? = VwNative.nativeAccountEmailSet(handle, email)

    /** Returns 0 (disabled), 1 (enabled), or -1 on failure. */
    fun get2fa(): Int = VwNative.nativeAccount2faGet(handle)

    /** Requires re-proving the current password — a security-sensitive
     * toggle, not a preference. Returns 0/1 on success, -1 on failure. */
    fun set2fa(password: ByteArray, enable: Boolean): Int = VwNative.nativeAccount2faSet(handle, password, enable)

    /** Returns the VW_NOTIFY_* bitmask, or -1 on failure. */
    fun getNotifyPrefs(): Long = VwNative.nativeNotifyPrefsGet(handle)

    /** Replaces the COMPLETE bitmask, not a per-bit toggle — call
     * [getNotifyPrefs] first, flip the bit locally, then pass the full
     * result here. Returns the stored value on success, or -1 on failure. */
    fun setNotifyPrefs(prefs: Long): Long = VwNative.nativeNotifyPrefsSet(handle, prefs)

    // ── Vault ────────────────────────────────────────────────────────────

    /** Vaults owned by the caller — never includes wrapped-key material;
     * use [VwVault.unlock] to actually open one. */
    fun listVaults(): List<VaultEntry>? =
        VwNative.nativeVaultList(handle)?.let(::decodeVaultEntries)

    /** This session's raw handle, needed by [VwVault]'s static factory
     * methods (which — like [VwClient]'s own — take a session handle
     * directly rather than a [VwClient] instance, matching [VwNative]'s
     * shape one level up). */
    internal fun rawHandle(): Long = handle
}

// ── Record decoding ──────────────────────────────────────────────────────
// Mirrors vw_jni_bridge.c's write_<type>() functions field-for-field — see
// that file's header comment for the shared little-endian, u32-count-
// prefixed record-array convention.

private fun leBuffer(bytes: ByteArray): ByteBuffer =
    ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)

private fun ByteBuffer.readLenString(): String {
    val len = short.toInt() and 0xFFFF
    val bytes = ByteArray(len)
    get(bytes)
    return String(bytes, Charsets.UTF_8)
}

private fun ByteBuffer.readFileEntry(): FileEntry {
    val entryType = get().toInt() and 0xFF
    val fileId = long
    val sizeBytes = long
    val mtimeUnix = long
    val versionId = long
    val vaultId = long
    val name = readLenString()
    return FileEntry(entryType, fileId, sizeBytes, mtimeUnix, versionId, vaultId, name)
}

private fun ByteBuffer.readShareEntry(): ShareEntry {
    val shareId = long
    val fileId = long
    val name = readLenString()
    val shareType = get().toInt() and 0xFF
    val targetUsername = readLenString()
    val permission = get().toInt() and 0xFF
    val createdAt = long
    val expiresAt = long
    val revoked = get() != 0.toByte()
    return ShareEntry(shareId, fileId, name, shareType, targetUsername, permission, createdAt, expiresAt, revoked)
}

private fun ByteBuffer.readLinkEntry(): LinkEntry {
    val shareId = long
    val fileId = long
    val name = readLenString()
    val permission = get().toInt() and 0xFF
    val createdAt = long
    val expiresAt = long
    val revoked = get() != 0.toByte()
    val hasPassword = get() != 0.toByte()
    return LinkEntry(shareId, fileId, name, permission, createdAt, expiresAt, revoked, hasPassword)
}

private fun ByteBuffer.readVersionEntry(): VersionEntry =
    VersionEntry(versionId = long, createdAt = long, sizeBytes = long)

private fun ByteBuffer.readVaultEntry(): VaultEntry =
    VaultEntry(vaultId = long, folderFileId = long, createdAt = long)

private fun decodeFileEntries(bytes: ByteArray): List<FileEntry> {
    val buf = leBuffer(bytes)
    val count = buf.int
    return List(count) { buf.readFileEntry() }
}

private fun decodeShareEntries(bytes: ByteArray): List<ShareEntry> {
    val buf = leBuffer(bytes)
    val count = buf.int
    return List(count) { buf.readShareEntry() }
}

private fun decodeLinkEntries(bytes: ByteArray): List<LinkEntry> {
    val buf = leBuffer(bytes)
    val count = buf.int
    return List(count) { buf.readLinkEntry() }
}

private fun decodeVersionEntries(bytes: ByteArray): List<VersionEntry> {
    val buf = leBuffer(bytes)
    val count = buf.int
    return List(count) { buf.readVersionEntry() }
}

private fun decodeVaultEntries(bytes: ByteArray): List<VaultEntry> {
    val buf = leBuffer(bytes)
    val count = buf.int
    return List(count) { buf.readVaultEntry() }
}

private fun decodeVersionChunks(bytes: ByteArray): VersionChunks {
    val buf = leBuffer(bytes)
    val chunkCount = buf.int
    val vaultId = buf.long
    val dekLen = buf.short.toInt() and 0xFFFF
    val wrappedDek = if (dekLen > 0) ByteArray(dekLen).also { buf.get(it) } else null
    val hashes = ByteArray(chunkCount * 32).also { buf.get(it) }
    return VersionChunks(chunkCount, vaultId, wrappedDek, hashes)
}

private fun decodeLinkCreateResult(bytes: ByteArray): LinkCreateResult {
    val buf = leBuffer(bytes)
    val shareId = buf.long
    val token = ByteArray(32).also { buf.get(it) }
    return LinkCreateResult(shareId, token)
}
